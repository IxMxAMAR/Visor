"""
Injects EFI files into a raw FAT32 disk image without mtools/WSL.
Parses FAT32 structures directly and writes files to free clusters.
"""
import struct, os, sys, math, time
from pathlib import Path

IMG = Path("tests/samples/samples/bochs_disk.img")
BUILD = Path("target/x86_64-unknown-uefi/debug")

INJECT = [
    BUILD / "uefi_hv.efi",
    BUILD / "check_hv_vendor.efi",
    Path("tests/startup.nsh"),
]

# ── FAT32 helpers ──────────────────────────────────────────────────────────

def read_bpb(data):
    """Parse FAT32 BPB from the first 512 bytes."""
    bpb = {}
    bpb['bytes_per_sec']   = struct.unpack_from('<H', data, 11)[0]
    bpb['sec_per_cluster'] = struct.unpack_from('<B', data, 13)[0]
    bpb['reserved_secs']   = struct.unpack_from('<H', data, 14)[0]
    bpb['num_fats']        = struct.unpack_from('<B', data, 16)[0]
    bpb['total_secs']      = struct.unpack_from('<I', data, 32)[0]
    bpb['secs_per_fat']    = struct.unpack_from('<I', data, 36)[0]
    bpb['root_cluster']    = struct.unpack_from('<I', data, 44)[0]
    bps = bpb['bytes_per_sec']
    spc = bpb['sec_per_cluster']
    bpb['cluster_size']    = bps * spc
    bpb['fat_offset']      = bpb['reserved_secs'] * bps
    bpb['data_offset']     = (bpb['reserved_secs'] + bpb['num_fats'] * bpb['secs_per_fat']) * bps
    return bpb

def cluster_offset(bpb, cluster):
    return bpb['data_offset'] + (cluster - 2) * bpb['cluster_size']

def read_fat32_entry(data, bpb, cluster):
    off = bpb['fat_offset'] + cluster * 4
    return struct.unpack_from('<I', data, off)[0] & 0x0FFFFFFF

def write_fat32_entry(data, bpb, cluster, value):
    off = bpb['fat_offset'] + cluster * 4
    existing = struct.unpack_from('<I', data, off)[0] & 0xF0000000
    struct.pack_into('<I', data, off, existing | (value & 0x0FFFFFFF))
    # Mirror to second FAT
    off2 = off + bpb['secs_per_fat'] * bpb['bytes_per_sec']
    existing2 = struct.unpack_from('<I', data, off2)[0] & 0xF0000000
    struct.pack_into('<I', data, off2, existing2 | (value & 0x0FFFFFFF))

def find_free_clusters(data, bpb, count):
    """Returns list of `count` free cluster numbers."""
    total = (bpb['total_secs'] * bpb['bytes_per_sec'] - bpb['data_offset']) // bpb['cluster_size'] + 2
    found = []
    for c in range(2, total):
        if read_fat32_entry(data, bpb, c) == 0:
            found.append(c)
            if len(found) == count:
                return found
    return found

def allocate_chain(data, bpb, size):
    """Allocates a cluster chain for `size` bytes. Returns first cluster."""
    n = math.ceil(size / bpb['cluster_size']) if size > 0 else 1
    clusters = find_free_clusters(data, bpb, n)
    if len(clusters) < n:
        raise RuntimeError("Not enough free clusters")
    for i, c in enumerate(clusters):
        next_c = clusters[i + 1] if i + 1 < len(clusters) else 0x0FFFFFFF
        write_fat32_entry(data, bpb, c, next_c)
    return clusters[0], clusters

def write_file_data(data, bpb, clusters, file_bytes):
    cs = bpb['cluster_size']
    for i, c in enumerate(clusters):
        off = cluster_offset(bpb, c)
        chunk = file_bytes[i * cs : (i + 1) * cs]
        data[off : off + len(chunk)] = chunk

def fat_name_83(name):
    """Convert filename to 8.3 FAT format (uppercase, space-padded)."""
    name = name.upper()
    if '.' in name:
        base, ext = name.rsplit('.', 1)
    else:
        base, ext = name, ''
    base = (base + '        ')[:8]
    ext  = (ext  + '   ')[:3]
    return (base + ext).encode('ascii')

def make_dir_entry(name83, cluster, size, attr=0x20):
    """Build a 32-byte FAT directory entry."""
    now = time.localtime()
    date = ((now.tm_year - 1980) << 9) | (now.tm_mon << 5) | now.tm_mday
    tim  = (now.tm_hour << 11) | (now.tm_min << 5) | (now.tm_sec // 2)
    hi   = (cluster >> 16) & 0xFFFF
    lo   = cluster & 0xFFFF
    entry = bytearray(32)
    entry[0:11]   = name83
    entry[11]     = attr
    struct.pack_into('<H', entry, 20, hi)        # cluster high
    struct.pack_into('<H', entry, 22, tim)        # write time
    struct.pack_into('<H', entry, 24, date)       # write date
    struct.pack_into('<H', entry, 26, lo)         # cluster low
    struct.pack_into('<I', entry, 28, size)       # file size
    return bytes(entry)

def lfn_checksum(name83):
    """Compute LFN checksum from the 11-byte 8.3 name."""
    chk = 0
    for c in name83:
        chk = ((chk >> 1) | ((chk & 1) << 7)) & 0xFF
        chk = (chk + c) & 0xFF
    return chk

def make_lfn_entries(long_name, name83):
    """
    Build the LFN directory entries (attribute=0x0F) that precede the 8.3 entry.
    Returns bytes containing all LFN entries in the correct order (first→last).
    """
    # Pad name to multiple of 13 UTF-16 chars, terminated with 0x0000 then 0xFFFF.
    chars = list(long_name.encode('utf-16-le'))
    chars += [0x00, 0x00]          # null terminator
    while len(chars) // 2 % 13 != 0:
        chars += [0xFF, 0xFF]      # pad with 0xFFFF

    num_entries = len(chars) // 2 // 13
    chk = lfn_checksum(name83)
    entries = []

    for seq in range(1, num_entries + 1):
        chunk = chars[(seq - 1) * 13 * 2 : seq * 13 * 2]
        e = bytearray(32)
        ord_flag = seq | (0x40 if seq == num_entries else 0)
        e[0]  = ord_flag
        e[11] = 0x0F          # LFN attribute
        e[13] = chk
        # Slots: chars 0-4 at bytes 1-10, chars 5-10 at 14-25, chars 11-12 at 28-31
        for i in range(5):
            struct.pack_into('<H', e, 1 + i*2, struct.unpack_from('<H', bytes(chunk), i*2)[0])
        for i in range(6):
            struct.pack_into('<H', e, 14 + i*2, struct.unpack_from('<H', bytes(chunk), (5+i)*2)[0])
        for i in range(2):
            struct.pack_into('<H', e, 28 + i*2, struct.unpack_from('<H', bytes(chunk), (11+i)*2)[0])
        entries.append(bytes(e))

    # LFN entries are stored last→first in the directory.
    entries.reverse()
    return b''.join(entries)

def find_or_free_slot(data, bpb, root_cluster, name83, lfn_count):
    """
    Finds a contiguous run of (lfn_count + 1) free/deleted slots in the root
    directory for LFN entries + the 8.3 entry. Also checks for an existing 8.3
    entry to overwrite. Returns (first_slot_offset, found_existing).
    """
    cluster = root_cluster
    while cluster < 0x0FFFFFF8:
        off = cluster_offset(bpb, cluster)
        entries_per_cluster = bpb['cluster_size'] // 32
        run_start = None
        run_len   = 0

        for i in range(entries_per_cluster):
            entry_off  = off + i * 32
            first      = data[entry_off]
            entry_name = bytes(data[entry_off : entry_off + 11])

            if entry_name == name83 and first not in (0x00, 0xE5):
                return entry_off, True    # existing 8.3 entry — overwrite in place

            if first == 0x00 or first == 0xE5:
                if run_start is None:
                    run_start = entry_off
                run_len += 1
                if run_len >= lfn_count + 1:
                    return run_start, False
            else:
                run_start = None
                run_len   = 0

        cluster = read_fat32_entry(data, bpb, cluster)
    raise RuntimeError("Root directory full")

# ── Main ───────────────────────────────────────────────────────────────────

def inject():
    if not IMG.exists():
        print(f"ERROR: disk image not found: {IMG}")
        sys.exit(1)

    data = bytearray(IMG.read_bytes())
    bpb  = read_bpb(data)
    print(f"FAT32: {bpb['bytes_per_sec']}B/sec, {bpb['sec_per_cluster']} sec/cluster, "
          f"cluster={bpb['cluster_size']}B, root@cluster{bpb['root_cluster']}")

    for src in INJECT:
        if not src.exists():
            print(f"  SKIP (not found): {src}")
            continue

        file_bytes = src.read_bytes()
        name83     = fat_name_83(src.name)
        lfn_data   = make_lfn_entries(src.name, name83)
        lfn_count  = len(lfn_data) // 32

        # Find slots: lfn_count LFN slots + 1 for the 8.3 entry.
        slot_off, existing = find_or_free_slot(
            data, bpb, bpb['root_cluster'], name83, lfn_count)

        if existing:
            # Reuse the 8.3 slot; write LFN entries in the slots before it.
            old_lo    = struct.unpack_from('<H', data, slot_off + 26)[0]
            old_hi    = struct.unpack_from('<H', data, slot_off + 20)[0]
            old_start = (old_hi << 16) | old_lo
            c = old_start
            while 2 <= c < 0x0FFFFFF8:
                nxt = read_fat32_entry(data, bpb, c)
                write_fat32_entry(data, bpb, c, 0)
                c = nxt
            lfn_start = slot_off - lfn_count * 32
        else:
            lfn_start = slot_off
            slot_off  = lfn_start + lfn_count * 32

        first_cluster, clusters = allocate_chain(data, bpb, len(file_bytes))
        write_file_data(data, bpb, clusters, file_bytes)

        if lfn_count > 0 and lfn_start >= 0:
            data[lfn_start : lfn_start + len(lfn_data)] = lfn_data

        entry = make_dir_entry(name83, first_cluster, len(file_bytes))
        data[slot_off : slot_off + 32] = entry

        print(f"  OK {src.name:40s} {len(file_bytes):>9,} bytes @ cluster {first_cluster} (LFN={lfn_count})")

    IMG.write_bytes(data)
    print(f"\nDisk image updated: {IMG}")

if __name__ == "__main__":
    os.chdir(Path(__file__).parent)
    inject()
