//! C5 — ObRegisterCallbacks self-protection (T1562.001).
//!
//! Registers a kernel object callback on the process object type so that any
//! attempt to open a handle to the ARQENOR agent process with dangerous rights
//! (terminate, inject, suspend) has those rights stripped in the pre-op callback.
//!
//! # Design
//! - `PROTECTED_PID` is a process-global atomic set by `DriverEntry` to the
//!   agent's PID once the usermode agent connects via the IPC port.
//! - The callback inspects every new or duplicated process handle and strips
//!   PROCESS_TERMINATE | PROCESS_VM_WRITE | PROCESS_VM_OPERATION |
//!   PROCESS_SUSPEND_RESUME when the target matches `PROTECTED_PID`.

pub mod callbacks;

use core::{
    ffi::c_void,
    sync::atomic::{AtomicU32, Ordering},
};

use wdk_sys::{ntddk::*, types::*, NTSTATUS, STATUS_SUCCESS};

use callbacks::{
    ob_pre_operation_callback,
    OB_PRE_OPERATION_INFORMATION,
    OB_PREOP_CALLBACK_STATUS,
};

// ---------------------------------------------------------------------------
// Global protected PID — shared with callbacks module
// ---------------------------------------------------------------------------

/// PID of the ARQENOR usermode agent to protect. 0 = no protection active.
/// Set by `DriverEntry` after the agent's PID becomes known via IPC connect.
pub static PROTECTED_PID: AtomicU32 = AtomicU32::new(0);

// ---------------------------------------------------------------------------
// PsProcessType — kernel-exported global symbol
// ---------------------------------------------------------------------------

extern "C" {
    /// Pointer to the kernel's process object type descriptor.
    /// Used as the `ObjectType` in OB_OPERATION_REGISTRATION.
    static PsProcessType: *mut POBJECT_TYPE;
}

// ---------------------------------------------------------------------------
// ObRegisterCallbacks types
// ---------------------------------------------------------------------------

/// OB_OPERATION values.
const OB_OPERATION_HANDLE_CREATE: u32 = 0x00000001;
const OB_OPERATION_HANDLE_DUPLICATE: u32 = 0x00000002;

/// Function pointer type for OB pre-operation callbacks.
type POB_PRE_OPERATION_CALLBACK = unsafe extern "system" fn(
    registration_context: *mut c_void,
    operation_information: *mut OB_PRE_OPERATION_INFORMATION,
) -> OB_PREOP_CALLBACK_STATUS;

/// Function pointer type for OB post-operation callbacks.
type POB_POST_OPERATION_CALLBACK =
    unsafe extern "system" fn(registration_context: *mut c_void, operation_information: *mut c_void);

/// OB_OPERATION_REGISTRATION — describes one object type to intercept.
#[repr(C)]
struct OB_OPERATION_REGISTRATION {
    object_type: *mut *mut c_void, // POBJECT_TYPE*
    operations: u32,
    pre_operation: POB_PRE_OPERATION_CALLBACK,
    post_operation: Option<POB_POST_OPERATION_CALLBACK>,
}

unsafe impl Sync for OB_OPERATION_REGISTRATION {}
unsafe impl Send for OB_OPERATION_REGISTRATION {}

/// OB_CALLBACK_REGISTRATION — top-level registration struct.
#[repr(C)]
struct OB_CALLBACK_REGISTRATION {
    version: u16,
    operation_registration_count: u16,
    altitude: UNICODE_STRING,
    registration_context: *mut c_void,
    operation_registration: *const OB_OPERATION_REGISTRATION,
}

unsafe impl Sync for OB_CALLBACK_REGISTRATION {}
unsafe impl Send for OB_CALLBACK_REGISTRATION {}

/// Current supported version for OB_CALLBACK_REGISTRATION.
const OB_FLT_REGISTRATION_VERSION: u16 = 0x0100;

// ---------------------------------------------------------------------------
// Altitude string for ObRegisterCallbacks
// ---------------------------------------------------------------------------

/// UTF-16 altitude string "370010".
static OB_ALTITUDE_WIDE: [u16; 6] = [
    b'3' as u16, b'7' as u16, b'0' as u16, b'0' as u16, b'1' as u16, b'0' as u16,
];

// ---------------------------------------------------------------------------
// ObRegisterCallbacks / ObUnRegisterCallbacks FFI
// ---------------------------------------------------------------------------

#[link(name = "ntoskrnl")]
extern "system" {
    fn ObRegisterCallbacks(
        registration: *const OB_CALLBACK_REGISTRATION,
        registration_handle: *mut *mut c_void,
    ) -> NTSTATUS;

    fn ObUnRegisterCallbacks(registration_handle: *mut c_void);
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Token representing an active ObRegisterCallbacks registration.
pub struct ProtectionModule {
    pub registration_handle: *mut c_void,
}

// SAFETY: kernel handles are not thread-local; we control all access via
// DriverState which is not shared across threads in normal driver operation.
unsafe impl Send for ProtectionModule {}

impl ProtectionModule {
    /// Register the ObCallbacks self-protection.
    ///
    /// `protected_pid` should be a pointer to the `PROTECTED_PID` atomic,
    /// or null to defer until the agent connects.
    ///
    /// # Safety
    /// Must be called at IRQL == PASSIVE_LEVEL.
    pub unsafe fn register(
        _protected_pid: *const AtomicU32,
    ) -> Result<Self, NTSTATUS> {
        // Build the operation registration array on the stack.
        // We capture PsProcessType here so the pointer is valid for the
        // lifetime of the registration.
        let op_reg = OB_OPERATION_REGISTRATION {
            // SAFETY: PsProcessType is a kernel-exported symbol valid for
            // the entire lifetime of the OS.
            object_type: PsProcessType as *mut *mut c_void,
            operations: OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE,
            pre_operation: ob_pre_operation_callback,
            post_operation: None,
        };

        // Allocate op_reg in non-paged memory so the pointer remains valid
        // after this function returns. We use ExAllocatePool2 (Win10+) with
        // our pool tag.
        //
        // POOL_FLAG_NON_PAGED = 0x40
        const POOL_FLAG_NON_PAGED: u64 = 0x40;
        const POOL_TAG: u32 = u32::from_le_bytes(*b"SNTL");

        let op_reg_ptr = ExAllocatePool2(
            POOL_FLAG_NON_PAGED,
            core::mem::size_of::<OB_OPERATION_REGISTRATION>() as u64,
            POOL_TAG,
        ) as *mut OB_OPERATION_REGISTRATION;

        if op_reg_ptr.is_null() {
            return Err(0xC000009Au32 as NTSTATUS); // STATUS_INSUFFICIENT_RESOURCES
        }
        core::ptr::write(op_reg_ptr, op_reg);

        let altitude_us = UNICODE_STRING {
            Length: (OB_ALTITUDE_WIDE.len() * 2) as u16,
            MaximumLength: (OB_ALTITUDE_WIDE.len() * 2) as u16,
            Buffer: OB_ALTITUDE_WIDE.as_ptr() as *mut u16,
        };

        let cb_reg = OB_CALLBACK_REGISTRATION {
            version: OB_FLT_REGISTRATION_VERSION,
            operation_registration_count: 1,
            altitude: altitude_us,
            registration_context: core::ptr::null_mut(),
            operation_registration: op_reg_ptr,
        };

        let mut registration_handle: *mut c_void = core::ptr::null_mut();
        let status = ObRegisterCallbacks(&cb_reg, &mut registration_handle);

        // Free the temporary op_reg allocation — ObRegisterCallbacks copies
        // the registration data internally.
        ExFreePoolWithTag(op_reg_ptr as *mut c_void, POOL_TAG);

        if status != STATUS_SUCCESS {
            return Err(status);
        }

        Ok(ProtectionModule { registration_handle })
    }

    /// Unregister the ObCallbacks and reset the protected PID.
    ///
    /// # Safety
    /// Must be called at IRQL == PASSIVE_LEVEL.
    pub unsafe fn unregister(&self) {
        PROTECTED_PID.store(0, Ordering::Release);
        ObUnRegisterCallbacks(self.registration_handle);
    }
}
