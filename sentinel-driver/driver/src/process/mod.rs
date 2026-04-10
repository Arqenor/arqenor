//! C4 — Process notify callbacks (T1059, T1055).
//!
//! Registers `process_notify_callback` with `PsSetCreateProcessNotifyRoutineEx`
//! to receive a notification for every process creation and termination
//! system-wide, including the image path and command line from the kernel's
//! own bookkeeping (not spoofable by usermode).

pub mod callbacks;

use wdk_sys::{ntddk::*, types::*, NTSTATUS, STATUS_SUCCESS};

use callbacks::{process_notify_callback, PS_CREATE_NOTIFY_INFO};

// ---------------------------------------------------------------------------
// PsSetCreateProcessNotifyRoutineEx FFI
// ---------------------------------------------------------------------------

/// Function pointer type accepted by PsSetCreateProcessNotifyRoutineEx.
type PCREATE_PROCESS_NOTIFY_ROUTINE_EX = unsafe extern "system" fn(
    process: PEPROCESS,
    process_id: HANDLE,
    create_info: *mut PS_CREATE_NOTIFY_INFO,
);

#[link(name = "ntoskrnl")]
extern "system" {
    /// Register or remove a process-creation notify routine (extended version).
    ///
    /// Pass `remove = FALSE` (0) to register, `TRUE` (1) to unregister.
    fn PsSetCreateProcessNotifyRoutineEx(
        notify_routine: PCREATE_PROCESS_NOTIFY_ROUTINE_EX,
        remove: u8,
    ) -> NTSTATUS;
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Token representing a registered `PsSetCreateProcessNotifyRoutineEx` callback.
pub struct ProcessModule;

impl ProcessModule {
    /// Register the process-creation notify routine.
    ///
    /// # Safety
    /// Must be called at IRQL == PASSIVE_LEVEL.
    /// The image must be signed or running under test-signing — the kernel
    /// validates the digital signature before accepting the registration.
    pub unsafe fn register() -> Result<Self, NTSTATUS> {
        let status = PsSetCreateProcessNotifyRoutineEx(process_notify_callback, 0 /* FALSE */);
        if status != STATUS_SUCCESS {
            return Err(status);
        }
        Ok(ProcessModule)
    }

    /// Unregister the process-creation notify routine.
    ///
    /// The kernel waits for any pending callback invocations to complete before
    /// returning.
    ///
    /// # Safety
    /// Must be called at IRQL == PASSIVE_LEVEL.
    pub unsafe fn unregister(&self) {
        // Ignore return value — the only error is if the routine wasn't
        // registered, which can't happen given our ownership model.
        let _ = PsSetCreateProcessNotifyRoutineEx(process_notify_callback, 1 /* TRUE */);
    }
}
