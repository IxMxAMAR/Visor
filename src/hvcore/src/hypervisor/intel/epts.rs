//! EPT (Extended Page Table) structures, identity mapping, and hook engine.

use alloc::{boxed::Box, vec::Vec};
use core::ptr::addr_of;

use x86::bits64::paging::{BASE_PAGE_SHIFT, BASE_PAGE_SIZE, LARGE_PAGE_SIZE};

use crate::hypervisor::{
    intel::mtrr::MemoryType,
    platform_ops,
    support::{Page, zeroed_box},
};

use super::mtrr::Mtrr;

// ─── Static identity-mapped EPT structures ─────────────────────────────────

#[repr(C, align(4096))]
pub(crate) struct Epts {
    pml4: Pml4,
    pdpt: Pdpt,
    pd: [Pd; 512],
    pt: Pt,
}

impl Epts {
    pub(crate) fn build_identity(&mut self) {
        let mtrr = Mtrr::new();
        log::trace!("{mtrr:#x?}");
        log::trace!("Initializing EPTs");

        let ops = platform_ops::get();

        let mut pa = 0u64;

        self.pml4.0.entries[0].set_readable(true);
        self.pml4.0.entries[0].set_writable(true);
        self.pml4.0.entries[0].set_executable(true);
        self.pml4.0.entries[0].set_pfn(ops.pa(addr_of!(self.pdpt) as _) >> BASE_PAGE_SHIFT);
        for (i, pdpte) in self.pdpt.0.entries.iter_mut().enumerate() {
            pdpte.set_readable(true);
            pdpte.set_writable(true);
            pdpte.set_executable(true);
            pdpte.set_pfn(ops.pa(addr_of!(self.pd[i]) as _) >> BASE_PAGE_SHIFT);
            for pde in &mut self.pd[i].0.entries {
                if pa == 0 {
                    // First 2MB is managed by 4KB EPT PTs so MTRR memory types
                    // are properly reflected into the EPT memory types.
                    pde.set_readable(true);
                    pde.set_writable(true);
                    pde.set_executable(true);
                    pde.set_pfn(ops.pa(addr_of!(self.pt) as _) >> BASE_PAGE_SHIFT);
                    for pte in &mut self.pt.0.entries {
                        let memory_type =
                            mtrr.find(pa..pa + BASE_PAGE_SIZE as u64)
                                .unwrap_or_else(|| {
                                    panic!("Could not resolve a memory type for {pa:#x?}")
                                });
                        pte.set_readable(true);
                        pte.set_writable(true);
                        pte.set_executable(true);
                        pte.set_memory_type(memory_type as u64);
                        pte.set_pfn(pa >> BASE_PAGE_SHIFT);
                        pa += BASE_PAGE_SIZE as u64;
                    }
                } else {
                    // For the rest of GPAs, use 2MB large page EPTs.
                    let memory_type = mtrr
                        .find(pa..pa + LARGE_PAGE_SIZE as u64)
                        .unwrap_or_else(|| panic!("Could not resolve a memory type for {pa:#x?}"));
                    pde.set_readable(true);
                    pde.set_writable(true);
                    pde.set_executable(true);
                    pde.set_memory_type(memory_type as u64);
                    pde.set_large(true);
                    pde.set_pfn(pa >> BASE_PAGE_SHIFT);
                    pa += LARGE_PAGE_SIZE as u64;
                }
            }
        }
    }

    /// Returns an EPT pointer for this EPT.
    pub(crate) fn eptp(&self) -> EptPointer {
        let mut eptp = EptPointer::default();
        let ept_pml4_pa = platform_ops::get().pa(addr_of!(*self) as *const _);
        eptp.set_pfn(ept_pml4_pa >> BASE_PAGE_SHIFT);

        // Write-back memory type for accessing EPT paging structures.
        // See: 29.3.7.1 Memory Type Used for Accessing EPT Paging Structures
        eptp.set_memory_type(MemoryType::WriteBack as _);

        // Page-walk length of 4.
        // See: Table 25-9. Format of Extended-Page-Table Pointer
        eptp.set_page_levels_minus_one(3);
        eptp
    }
}

// ─── EPT Manager: dynamic hook engine ──────────────────────────────────────

/// Owns the identity-mapped EPT and supports page-level hooks for stealth.
pub(crate) struct EptManager {
    epts: Box<Epts>,
    /// Extra 4KB page tables produced by splitting 2MB large pages.
    /// Each entry is (pdpt_idx, pd_idx, page_table).
    split_pts: Vec<(usize, usize, Box<Pt>)>,
    /// Zero-filled dummy page returned to scanners reading hidden GPAs.
    dummy_page: Box<Page>,
}

impl EptManager {
    pub(crate) fn new() -> Self {
        let mut epts = zeroed_box::<Epts>();
        epts.build_identity();
        Self {
            epts,
            split_pts: Vec::new(),
            dummy_page: zeroed_box::<Page>(),
        }
    }

    /// Returns the EPT pointer to pass into the VMCS `EPTP` field.
    pub(crate) fn eptp(&self) -> EptPointer {
        self.epts.eptp()
    }

    /// Splits the 2MB large page containing `gpa` into 512 identity-mapped
    /// 4KB entries. Idempotent — calling again on an already-split region is
    /// a no-op.
    pub(crate) fn split_large_page(&mut self, gpa: u64) {
        let pdpt_idx = ((gpa >> 30) & 0x1ff) as usize;
        let pd_idx   = ((gpa >> 21) & 0x1ff) as usize;

        // The first 2MB is already tracked at 4KB granularity in `self.epts.pt`.
        if pdpt_idx == 0 && pd_idx == 0 {
            return;
        }

        // Already split?
        if self.split_pts.iter().any(|(p, d, _)| *p == pdpt_idx && *d == pd_idx) {
            return;
        }

        let pde = &self.epts.pd[pdpt_idx].0.entries[pd_idx];
        assert!(pde.large(), "split_large_page called on a non-large PDE at pdpt={pdpt_idx} pd={pd_idx}");

        let base_pa     = pde.pfn() << BASE_PAGE_SHIFT;
        let memory_type = pde.memory_type();

        let ops = platform_ops::get();
        let mut new_pt = zeroed_box::<Pt>();
        for (i, pte) in new_pt.0.entries.iter_mut().enumerate() {
            pte.set_readable(true);
            pte.set_writable(true);
            pte.set_executable(true);
            pte.set_memory_type(memory_type);
            pte.set_pfn((base_pa + i as u64 * BASE_PAGE_SIZE as u64) >> BASE_PAGE_SHIFT);
        }

        let new_pt_pa = ops.pa(addr_of!(*new_pt) as *const _);

        // Update the PDE to point to the new 4KB page table.
        let pde = &mut self.epts.pd[pdpt_idx].0.entries[pd_idx];
        pde.set_large(false);
        pde.set_pfn(new_pt_pa >> BASE_PAGE_SHIFT);

        self.split_pts.push((pdpt_idx, pd_idx, new_pt));
        // SAFETY: all EPT modifications must be followed by INVEPT.
        invept_global();
    }

    /// Remaps the 4KB EPT entry for `gpa` to the dummy (all-zeros) page.
    ///
    /// Scanners reading this GPA see harmless zeros. The page is readable but
    /// not writable or executable, so any execution attempt from that GPA will
    /// trigger an EPT violation that we handle in `handle_violation`.
    pub(crate) fn remap_page_to_dummy(&mut self, gpa: u64) {
        self.split_large_page(gpa);
        let dummy_pa = platform_ops::get().pa(addr_of!(*self.dummy_page) as *const _);
        let pte = self.get_pte_mut(gpa).expect("PTE not found after split");
        pte.set_readable(true);
        pte.set_writable(false);
        pte.set_executable(false);
        pte.set_pfn(dummy_pa >> BASE_PAGE_SHIFT);
        invept_global();
    }

    /// Marks the 4KB EPT entry for `gpa` as fully non-present.
    ///
    /// Any guest access triggers an EPT violation. Handle in `handle_violation`.
    /// Reserved for the dual-view hiding strategy in phase 2.
    #[expect(dead_code)]
    pub(crate) fn hide_page(&mut self, gpa: u64) {
        self.split_large_page(gpa);
        let pte = self.get_pte_mut(gpa).expect("PTE not found after split");
        pte.set_readable(false);
        pte.set_writable(false);
        pte.set_executable(false);
        invept_global();
    }

    /// Restores the EPT entry for `gpa` to a standard identity mapping
    /// (GPA == HPA, full permissions).
    pub(crate) fn restore_page(&mut self, gpa: u64) {
        self.split_large_page(gpa);
        let pte = self.get_pte_mut(gpa).expect("PTE not found after split");
        pte.set_readable(true);
        pte.set_writable(true);
        pte.set_executable(true);
        pte.set_pfn(gpa >> BASE_PAGE_SHIFT);
        invept_global();
    }

    /// Called from the EPT violation VMEXIT handler.
    ///
    /// Current strategy: restore the faulting page so the guest re-executes
    /// successfully. Phase 2 will add dual-view hiding with MTF re-protection.
    pub(crate) fn handle_violation(&mut self, gpa: u64) {
        let page_gpa = gpa & !0xfff_u64;
        log::debug!("EPT violation @ GPA {page_gpa:#x} — restoring identity mapping");
        self.restore_page(page_gpa);
    }

    /// Returns a mutable reference to the 4KB PTE covering `gpa`.
    /// The caller must ensure the containing 2MB region has been split first.
    fn get_pte_mut(&mut self, gpa: u64) -> Option<&mut Entry> {
        let pdpt_idx = ((gpa >> 30) & 0x1ff) as usize;
        let pd_idx   = ((gpa >> 21) & 0x1ff) as usize;
        let pt_idx   = ((gpa >> 12) & 0x1ff) as usize;

        if pdpt_idx == 0 && pd_idx == 0 {
            return Some(&mut self.epts.pt.0.entries[pt_idx]);
        }

        self.split_pts
            .iter_mut()
            .find(|(p, d, _)| *p == pdpt_idx && *d == pd_idx)
            .map(|(_, _, pt)| &mut pt.0.entries[pt_idx])
    }
}

// ─── INVEPT ────────────────────────────────────────────────────────────────

/// 16-byte descriptor required by the INVEPT instruction.
/// For type 2 (all-context), the descriptor content is ignored by the CPU.
#[repr(C)]
struct InveptDescriptor {
    eptp:     u64,
    reserved: u64,
}

/// Issues INVEPT type 2 (global context), invalidating all EPT-derived TLB
/// entries across all EPTP contexts on the current logical processor.
pub(crate) fn invept_global() {
    let desc = InveptDescriptor { eptp: 0, reserved: 0 };
    // SAFETY: INVEPT is safe to call at any privilege level in VMX root.
    unsafe {
        core::arch::asm!(
            "invept {typ}, [{desc}]",
            typ  = in(reg) 2u64,
            desc = in(reg) addr_of!(desc),
            options(nostack, preserves_flags),
        );
    }
}

// ─── Bitfield types ────────────────────────────────────────────────────────

bitfield::bitfield! {
    /// A 64-bit VMCS field value describing where to find and how to walk EPTs.
    // See: 25.6.11 Extended-Page-Table Pointer (EPTP)
    // See: Table 25-9. Format of Extended-Page-Table Pointer
    #[derive(Clone, Copy, Default)]
    pub struct EptPointer(u64);
    impl Debug;
    memory_type,           set_memory_type:           2, 0;
    page_levels_minus_one, set_page_levels_minus_one: 5, 3;
    enable_access_dirty,   set_enable_access_dirty:   6;
    enable_sss,            set_enable_sss:             7;
    pfn,                   set_pfn:                   51, 12;
}

#[derive(Debug, Clone, Copy)]
struct Pml4(Table);

#[derive(Debug, Clone, Copy)]
struct Pdpt(Table);

#[derive(Debug, Clone, Copy)]
struct Pd(Table);

#[derive(Debug, Clone, Copy)]
struct Pt(Table);

#[derive(Debug, Clone, Copy)]
#[repr(C, align(4096))]
struct Table {
    entries: [Entry; 512],
}

bitfield::bitfield! {
    /// Figure 29-1. Formats of EPTP and EPT Paging-Structure Entries
    #[derive(Clone, Copy)]
    struct Entry(u64);
    impl Debug;
    readable,    set_readable:    0;
    writable,    set_writable:    1;
    executable,  set_executable:  2;
    memory_type, set_memory_type: 5, 3;
    large,       set_large:       7;
    pfn,         set_pfn:         51, 12;
}
