//! ObRegisterCallbacks pre-operation callback for self-protection (T1562.001).
//!
//! Strips dangerous access rights from any handle opened against the SENTINEL
//! agent process, preventing:
//!   - PROCESS_TERMINATE        — kill the agent
//!   - PROCESS_VM_WRITE         — inject shellcode
//!   - PROCESS_VM_OPERATION     — cross-process memory operations
//!   - PROCESS_SUSPEND_RESUME   — freeze the agent

use core::{
    ffi::c_void,
    sync::atomic::Ordering,
};

use wdk_sys::{ntddk::*, types::*};

use super::PROTECTED_PID;

// ---------------------------------------------------------------------------
// ObRegisterCallbacks types not fully exposed by wdk-sys
// ---------------------------------------------------------------------------

/// OB_PRE_OPERATION_INFORMATION — passed to the pre-op callback.
/// We declare only the fields we access; the rest are opaque.
#[repr(C)]
pub struct OB_PRE_OPERATION_INFORMATION {
    /// The type of operation (OB_OPERATION_HANDLE_CREATE = 1, etc.)
    pub operation: u32,
    /// Flags (OB_PRE_OPERATION_INFORMATION_FLAG_*).
    pub flags: u32,
    /// The target kernel object (cast to PEPROCESS for process type).
    pub object: *mut c_void,
    /// The type of `Object`.
    pub object_type: *mut c_void,
    /// Union: parameters for create/duplicate. We treat it as a pointer to the
    /// create-handle parameters structure.
    pub parameters: *mut OB_PRE_CREATE_HANDLE_INFORMATION,
    /// Reserved — unused.
    pub call_context: *mut c_void,
    /// Reserved.
    pub object_create_info: *mut c_void,
    /// Reserved.
    pub extra_information: *mut c_void,
}

/// OB_PRE_CREATE_HANDLE_INFORMATION — embedded in OB_PRE_OPERATION_INFORMATION.
#[repr(C)]
pub struct OB_PRE_CREATE_HANDLE_INFORMATION {
    /// Access mask requested by the caller.
    pub desired_access: u32,
    /// Original access mask before any callback stripping.
    pub original_desired_access: u32,
}

/// OB_PREOP_CALLBACK_STATUS return code.
#[repr(u32)]
pub enum OB_PREOP_CALLBACK_STATUS {
    OB_PREOP_SUCCESS = 0,
}

// ---------------------------------------------------------------------------
// Access mask bits to strip from handles targeting the protected process
// ---------------------------------------------------------------------------

/// Access rights that would allow an attacker to kill or inject into SENTINEL.
const STRIP_ACCESS: u32 =
    0x0001   // PROCESS_TERMINATE
    | 0x0020 // PROCESS_VM_OPERATION
    | 0x0008 // PROCESS_VM_WRITE
    | 0x0800 // PROCESS_SUSPEND_RESUME
    ;

// ---------------------------------------------------------------------------
// The pre-operation callback
// ---------------------------------------------------------------------------

/// ObCallbacks pre-operation routine.
///
/// Called before a handle to a process object is created or duplicated.
/// Strips dangerous access bits if the target process is the protected PID.
///
/// # Safety
/// Called by the kernel at IRQL <= APC_LEVEL.
pub unsafe extern "system" fn ob_pre_operation_callback(
    _context: *mut c_void,
    info: *mut OB_PRE_OPERATION_INFORMATION,
) -> OB_PREOP_CALLBACK_STATUS {
    if info.is_null() {
        return OB_PREOP_CALLBACK_STATUS::OB_PREOP_SUCCESS;
    }

    let info_ref = &*info;

    // Retrieve the target process ID.
    let target_pid = PsGetProcessId(info_ref.object as PEPROCESS) as u32;

    let protected_pid = PROTECTED_PID.load(Ordering::Relaxed);

    // 0 means no process is currently being protected.
    if protected_pid == 0 || target_pid != protected_pid {
        return OB_PREOP_CALLBACK_STATUS::OB_PREOP_SUCCESS;
    }

    // Strip dangerous access rights.
    if !info_ref.parameters.is_null() {
        let params = &mut *info_ref.parameters;
        params.desired_access &= !STRIP_ACCESS;
    }

    OB_PREOP_CALLBACK_STATUS::OB_PREOP_SUCCESS
}
