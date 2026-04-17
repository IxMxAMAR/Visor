//! This module implements Intel VT-x based virtualization. Code comments refer
//! to Intel® 64 and IA-32 Architectures Software Developer Manuals revision 84 at
//! <https://intel.com/sdm>.

use super::host::Architecture;

mod epts;
mod guest;
mod mtrr;
mod vmx;

pub(crate) use guest::{handle_ept_violation, hide_page_hypercall, unhide_page_hypercall};

/// The Intel processor implements VMX as a virtualization extension.
pub(crate) struct Intel;

impl Architecture for Intel {
    type VirtualizationExtension = vmx::Vmx;
    type Guest = guest::VmxGuest;
}
