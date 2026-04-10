//! Process creation/termination callback for PsSetCreateProcessNotifyRoutineEx.
//!
//! Fires for every process start and exit system-wide. Emits:
//!   - `KernelEvent::ProcessCreate` with image path, command line, parent PID,
//!     and creating thread ID.
//!   - `KernelEvent::ProcessTerminate` with PID and timestamp.
//!
//! MITRE coverage: T1059 (cmd execution), T1055 (injection visible via
//! unexpected parent relationships).

use core::ffi::c_void;

use wdk_sys::{ntddk::*, types::*, HANDLE};

use crate::ipc;
use arqenor_driver_common::KernelEvent;

// ---------------------------------------------------------------------------
// PS_CREATE_NOTIFY_INFO — wdk-sys may not expose all fields we need.
// We redeclare it with the fields we actually access.
// ---------------------------------------------------------------------------

/// Subset of PS_CREATE_NOTIFY_INFO that we need.
/// Layout must match ntddk.h; unused trailing fields are covered by padding.
#[repr(C)]
pub struct PS_CREATE_NOTIFY_INFO {
    pub size: usize,
    /// Packed flags (see ntddk.h).
    pub flags: u32,
    /// Parent process ID.
    pub parent_process_id: HANDLE,
    /// Creating thread's client ID.
    pub creating_thread_id: CLIENT_ID,
    /// FILE_OBJECT for the image — may be null.
    pub file_object: *mut c_void,
    /// Image file name as a UNICODE_STRING pointer — may be null.
    pub image_file_name: *mut UNICODE_STRING,
    /// Command line as a UNICODE_STRING pointer — may be null for system processes.
    pub command_line: *mut UNICODE_STRING,
    /// Process creation status (output).
    pub creation_status: i32,
}

/// Kernel CLIENT_ID: process ID + thread ID.
#[repr(C)]
pub struct CLIENT_ID {
    pub unique_process: HANDLE,
    pub unique_thread: HANDLE,
}

// ---------------------------------------------------------------------------
// Helper: copy UNICODE_STRING into a fixed-size u16 array
// ---------------------------------------------------------------------------

/// Copy up to `N - 1` UTF-16 code units from a UNICODE_STRING pointer.
/// Null-terminates the result.
///
/// # Safety
/// `us` must be null or point to a valid UNICODE_STRING.
unsafe fn copy_us<const N: usize>(us: *const UNICODE_STRING) -> ([u16; N], usize) {
    let mut out = [0u16; N];
    if us.is_null() || (*us).Buffer.is_null() {
        return (out, 0);
    }
    let len_chars = ((*us).Length as usize) / 2;
    let copy_chars = len_chars.min(N - 1);
    core::ptr::copy_nonoverlapping((*us).Buffer, out.as_mut_ptr(), copy_chars);
    (out, copy_chars)
}

// ---------------------------------------------------------------------------
// The notify callback
// ---------------------------------------------------------------------------

/// Process creation/termination notify routine.
///
/// # Safety
/// Called by the kernel at PASSIVE_LEVEL for process create, or at or below
/// APC_LEVEL for process terminate.
///
/// `create_info` is non-null for creation; null for termination.
pub unsafe extern "system" fn process_notify_callback(
    _process: PEPROCESS,
    process_id: HANDLE,
    create_info: *mut PS_CREATE_NOTIFY_INFO,
) {
    if create_info.is_null() {
        // ---- Process termination ----
        let event = KernelEvent::ProcessTerminate {
            pid: process_id as u32,
            timestamp: KeQueryInterruptTime() as u64,
        };
        let _ = ipc::send_event(&event);
    } else {
        // ---- Process creation ----
        let info = &*create_info;

        let (image_path, image_path_len) = copy_us::<512>(info.image_file_name as *const UNICODE_STRING);

        // CommandLine is null for many system/driver processes — handle gracefully.
        let (cmdline, cmdline_len) = if info.command_line.is_null() {
            ([0u16; 1024], 0usize)
        } else {
            copy_us::<1024>(info.command_line as *const UNICODE_STRING)
        };

        let ppid = info.parent_process_id as u32;
        let tid  = info.creating_thread_id.unique_thread as u32;

        let event = KernelEvent::ProcessCreate {
            pid: process_id as u32,
            ppid,
            creating_tid: tid,
            image_path,
            image_path_len: image_path_len as u16,
            cmdline,
            cmdline_len: cmdline_len as u16,
            timestamp: KeQueryInterruptTime() as u64,
        };
        let _ = ipc::send_event(&event);
    }
}
