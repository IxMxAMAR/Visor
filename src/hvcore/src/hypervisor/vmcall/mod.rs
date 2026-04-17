//! VMCALL subsystem: hypercall dispatch and supporting utilities.
//!
//! The ring-0 driver communicates with the hypervisor through `VMCALL`.
//! Codes are defined in `VmcallCode` and dispatched by `dispatch()`.

/// VMCALL codes understood by the hypervisor.
/// The driver places the code in `RAX` before issuing `VMCALL`.
#[repr(u64)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum VmcallCode {
    /// Liveness check — returns `VISOR_ALIVE` magic.
    Ping          = 0,
    /// Returns the hypervisor interface version.
    GetVersion    = 1,
    /// Hides the page at the guest physical address in `arg1` (remap→dummy).
    HidePage      = 2,
    /// Restores identity mapping for the GPA in `arg1`.
    UnhidePage    = 3,
    /// Unknown / unsupported code.
    Unknown       = u64::MAX,
}

impl From<u64> for VmcallCode {
    fn from(v: u64) -> Self {
        match v {
            0 => Self::Ping,
            1 => Self::GetVersion,
            2 => Self::HidePage,
            3 => Self::UnhidePage,
            _ => Self::Unknown,
        }
    }
}

/// Magic value returned by `VMCALL_PING` so the driver can confirm the
/// hypervisor is loaded and responding.
pub(crate) const VISOR_ALIVE: u64 = 0xDEAD_C0DE_CAFE_BABE;

/// Current interface version, incremented on breaking changes.
pub(crate) const VISOR_VERSION: u64 = 1;

/// Dispatches a VMCALL from the guest.
///
/// Called from `host::handle_vmcall` in VMX-root.
/// Returns the value to write back into `RAX`.
pub(crate) fn dispatch(code: u64, arg1: u64, _arg2: u64, _arg3: u64) -> u64 {
    match VmcallCode::from(code) {
        VmcallCode::Ping => {
            log::debug!("VMCALL: Ping");
            VISOR_ALIVE
        }

        VmcallCode::GetVersion => {
            log::debug!("VMCALL: GetVersion");
            VISOR_VERSION
        }

        VmcallCode::HidePage => {
            log::debug!("VMCALL: HidePage GPA={arg1:#x}");
            crate::hypervisor::intel::hide_page_hypercall(arg1);
            0
        }

        VmcallCode::UnhidePage => {
            log::debug!("VMCALL: UnhidePage GPA={arg1:#x}");
            crate::hypervisor::intel::unhide_page_hypercall(arg1);
            0
        }

        VmcallCode::Unknown => {
            log::warn!("VMCALL: unknown code {code:#x}");
            u64::MAX
        }
    }
}
