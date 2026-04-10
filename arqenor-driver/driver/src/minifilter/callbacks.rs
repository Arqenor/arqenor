//! Minifilter pre-operation callbacks for file system interception.
//!
//! Three operations are monitored:
//!   - IRP_MJ_CREATE   — file open/create (new file creation, executable open)
//!   - IRP_MJ_WRITE    — file write (data tampering)
//!   - IRP_MJ_SET_INFORMATION — rename / delete (T1565, T1005)
//!
//! All callbacks are monitoring-only: they always return
//! `FLT_PREOP_SUCCESS_NO_CALLBACK` and never modify the I/O parameters.

use core::ffi::c_void;

use wdk_sys::{ntddk::*, types::*, NTSTATUS, STATUS_SUCCESS};

use crate::ipc;
use arqenor_driver_common::KernelEvent;

// ---------------------------------------------------------------------------
// wdk-sys does not yet expose fltkernel types. We declare the minimal subsets
// needed here as opaque pointer aliases.  Everything the callbacks touch is
// accessed through raw pointers with explicit field-offset arithmetic, keeping
// us independent of exact struct layout differences across WDK versions.
// ---------------------------------------------------------------------------

/// Opaque FLT_CALLBACK_DATA pointer (fltkernel.h: _FLT_CALLBACK_DATA).
pub type FLT_CALLBACK_DATA = c_void;

/// Opaque FLT_RELATED_OBJECTS pointer (fltkernel.h: _FLT_RELATED_OBJECTS).
pub type FLT_RELATED_OBJECTS = c_void;

/// Opaque FLT_FILE_NAME_INFORMATION pointer.
pub type FLT_FILE_NAME_INFORMATION = c_void;

/// Opaque PFLT_FILTER pointer (registered filter handle).
pub type PFLT_FILTER = *mut c_void;

/// Return value for pre-op callbacks.
#[repr(u32)]
pub enum FLT_PREOP_CALLBACK_STATUS {
    /// I/O continues; no post-op callback requested.
    FLT_PREOP_SUCCESS_NO_CALLBACK = 0,
    /// I/O continues; post-op callback requested.
    FLT_PREOP_SUCCESS_WITH_CALLBACK = 1,
    /// Callback completed the I/O request.
    FLT_PREOP_COMPLETE = 2,
    /// Pass the request down without further inspection.
    FLT_PREOP_SYNCHRONIZE = 3,
    /// Disallow fast-I/O.
    FLT_PREOP_DISALLOW_FASTIO = 4,
}

// FLT_FILE_NAME_* option flags
const FLT_FILE_NAME_NORMALIZED: u32 = 0x01;
const FLT_FILE_NAME_QUERY_DEFAULT: u32 = 0x00;
const FLT_FILE_NAME_OPTIONS: u32 = FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT;

// IRP major function codes used in the FLT_REGISTRATION callback table.
pub const IRP_MJ_CREATE: u8 = 0x00;
pub const IRP_MJ_WRITE: u8 = 0x04;
pub const IRP_MJ_SET_INFORMATION: u8 = 0x06;
pub const IRP_MJ_OPERATION_END: u8 = 0x80;

// IRQL thresholds
const PASSIVE_LEVEL: u8 = 0;
const APC_LEVEL: u8 = 1;

// Pool tag: b"SNTL" in little-endian u32
const POOL_TAG: u32 = u32::from_le_bytes(*b"SNTL");

// ---------------------------------------------------------------------------
// fltkernel FFI — forward declarations
// ---------------------------------------------------------------------------

#[link(name = "fltmgr")]
extern "system" {
    fn FltGetFileNameInformation(
        data: *mut FLT_CALLBACK_DATA,
        name_options: u32,
        file_name_information: *mut *mut FLT_FILE_NAME_INFORMATION,
    ) -> NTSTATUS;

    fn FltParseFileNameInformation(
        file_name_information: *mut FLT_FILE_NAME_INFORMATION,
    ) -> NTSTATUS;

    fn FltReleaseFileNameInformation(file_name_information: *mut FLT_FILE_NAME_INFORMATION);
}

// ---------------------------------------------------------------------------
// Monitored path patterns (hardcoded, phase-1)
// ---------------------------------------------------------------------------

/// Monitored directory prefixes (UTF-16 encoded at compile time via macros).
/// We compare against the normalized path returned by FltGetFileNameInformation.
static MONITORED_DIRS: &[&str] = &[
    "\\Windows\\System32\\",
    "\\Windows\\SysWOW64\\",
    "\\Windows\\System32\\drivers\\",
    "\\Users\\",     // user-profile writes are high-signal for cred theft
    "\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\",
];

/// Monitored file extensions (lowercase comparison).
static MONITORED_EXTENSIONS: &[&[u8]] = &[
    b".exe", b".dll", b".sys", b".ps1", b".bat", b".cmd", b".vbs",
    b".hta", b".js",  b".lnk", b".inf",
];

// ---------------------------------------------------------------------------
// Helper: extract a UTF-16 path from FLT_FILE_NAME_INFORMATION and copy it
// into a fixed-size u16 array. Returns the number of u16 code units copied.
// ---------------------------------------------------------------------------

/// Copy up to `N` UTF-16 code units from a kernel UNICODE_STRING into a
/// fixed-size array.  Truncates silently — the last element is always 0.
///
/// # Safety
/// `us` must point to a valid, initialized UNICODE_STRING.
unsafe fn copy_unicode_string<const N: usize>(us: *const UNICODE_STRING) -> ([u16; N], usize) {
    let mut out = [0u16; N];
    if us.is_null() || (*us).Buffer.is_null() {
        return (out, 0);
    }
    let len_chars = ((*us).Length as usize) / 2;
    let copy_chars = len_chars.min(N - 1); // leave room for null terminator
    core::ptr::copy_nonoverlapping((*us).Buffer, out.as_mut_ptr(), copy_chars);
    (out, copy_chars)
}

/// Naive ASCII-case-folded extension check on a UTF-16 path.
///
/// Converts the tail of `path` to lowercase ASCII and matches against the
/// byte patterns in `MONITORED_EXTENSIONS`.  Non-ASCII characters are left
/// as-is and will not match the ASCII extension patterns.
fn path_has_monitored_extension(path: &[u16]) -> bool {
    // Find last dot
    let dot_pos = match path.iter().rposition(|&c| c == b'.' as u16) {
        Some(p) => p,
        None => return false,
    };
    let ext_slice = &path[dot_pos..];
    let mut ext_buf = [0u8; 8];
    let copy_len = ext_slice.len().min(ext_buf.len());
    for (i, &wc) in ext_slice[..copy_len].iter().enumerate() {
        // ASCII tolower
        let byte = if wc < 0x80 { (wc as u8).to_ascii_lowercase() } else { 0xFF };
        ext_buf[i] = byte;
    }
    let ext_bytes = &ext_buf[..copy_len];
    MONITORED_EXTENSIONS.iter().any(|&m| m == ext_bytes)
}

/// Check if the path contains any monitored directory prefix.
///
/// Both `path_lower` and monitored dirs are compared in ASCII-lowercase.
/// This is sufficient because Windows paths in System32 etc. are ASCII.
fn path_has_monitored_dir(path_wide: &[u16]) -> bool {
    // Convert to a small ASCII scratch buffer for fast comparison.
    // For paths > 512 chars we only look at the first 512.
    let mut ascii_buf = [0u8; 512];
    let len = path_wide.len().min(ascii_buf.len());
    for (i, &wc) in path_wide[..len].iter().enumerate() {
        ascii_buf[i] = if wc < 0x80 { (wc as u8).to_ascii_lowercase() } else { b'?' };
    }
    let ascii = &ascii_buf[..len];

    for dir in MONITORED_DIRS {
        let dir_bytes = dir.as_bytes();
        // Simple substring search — path may start with a volume prefix.
        if ascii.windows(dir_bytes.len()).any(|w| {
            w.iter().zip(dir_bytes.iter()).all(|(&a, &b)| a == b.to_ascii_lowercase())
        }) {
            return true;
        }
    }
    false
}

/// Returns true if the normalized path should be reported as a telemetry event.
fn should_monitor(path_chars: &[u16]) -> bool {
    path_has_monitored_extension(path_chars) || path_has_monitored_dir(path_chars)
}

// ---------------------------------------------------------------------------
// Pre-Create callback
// ---------------------------------------------------------------------------

/// Pre-operation callback for IRP_MJ_CREATE.
///
/// Fires when any process opens or creates a file. We only report creates that
/// touch monitored paths (System32, executable extensions, etc.).
///
/// # IRQL
/// Filter Manager guarantees IRQL <= APC_LEVEL for pre-create.
pub unsafe extern "system" fn pre_create_callback(
    data: *mut FLT_CALLBACK_DATA,
    flt_objects: *const FLT_RELATED_OBJECTS,
    _completion_context: *mut *mut c_void,
) -> FLT_PREOP_CALLBACK_STATUS {
    let _ = flt_objects; // not used in monitoring path

    // IRQL guard — FltGetFileNameInformation requires <= APC_LEVEL
    if KeGetCurrentIrql() > APC_LEVEL {
        return FLT_PREOP_CALLBACK_STATUS::FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    let mut name_info: *mut FLT_FILE_NAME_INFORMATION = core::ptr::null_mut();
    let status = FltGetFileNameInformation(data, FLT_FILE_NAME_OPTIONS, &mut name_info);
    if status != STATUS_SUCCESS || name_info.is_null() {
        return FLT_PREOP_CALLBACK_STATUS::FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    // Parse the name info so the Name field is populated.
    let _ = FltParseFileNameInformation(name_info);

    // SAFETY: name_info points to a valid FLT_FILE_NAME_INFORMATION.
    // The Name field is a UNICODE_STRING at a known offset.
    // FLT_FILE_NAME_INFORMATION layout (simplified):
    //   UNICODE_STRING Name;  // offset 0
    let name_us = name_info as *const UNICODE_STRING;
    let (path_buf, path_len) = copy_unicode_string::<512>(name_us);

    if path_len > 0 && should_monitor(&path_buf[..path_len]) {
        let event = KernelEvent::FileCreate {
            path: path_buf,
            path_len: path_len as u16,
            pid: PsGetCurrentProcessId() as u32,
            timestamp: KeQueryInterruptTime() as u64,
        };
        // Non-fatal — if send fails we continue I/O normally.
        let _ = ipc::send_event(&event);
    }

    FltReleaseFileNameInformation(name_info);
    FLT_PREOP_CALLBACK_STATUS::FLT_PREOP_SUCCESS_NO_CALLBACK
}

// ---------------------------------------------------------------------------
// Pre-Write callback
// ---------------------------------------------------------------------------

/// Pre-operation callback for IRP_MJ_WRITE.
///
/// Fires when data is written to a file. Reported only for monitored paths.
///
/// # IRQL
/// Write IRPs can arrive at DISPATCH_LEVEL from paging I/O — we bail early
/// in that case because FltGetFileNameInformation requires <= APC_LEVEL.
pub unsafe extern "system" fn pre_write_callback(
    data: *mut FLT_CALLBACK_DATA,
    flt_objects: *const FLT_RELATED_OBJECTS,
    _completion_context: *mut *mut c_void,
) -> FLT_PREOP_CALLBACK_STATUS {
    let _ = flt_objects;

    // Must be <= APC_LEVEL to call FltGetFileNameInformation.
    if KeGetCurrentIrql() > APC_LEVEL {
        return FLT_PREOP_CALLBACK_STATUS::FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    let mut name_info: *mut FLT_FILE_NAME_INFORMATION = core::ptr::null_mut();
    let status = FltGetFileNameInformation(data, FLT_FILE_NAME_OPTIONS, &mut name_info);
    if status != STATUS_SUCCESS || name_info.is_null() {
        return FLT_PREOP_CALLBACK_STATUS::FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    let _ = FltParseFileNameInformation(name_info);

    let name_us = name_info as *const UNICODE_STRING;
    let (path_buf, path_len) = copy_unicode_string::<512>(name_us);

    if path_len > 0 && should_monitor(&path_buf[..path_len]) {
        let event = KernelEvent::FileWrite {
            path: path_buf,
            path_len: path_len as u16,
            pid: PsGetCurrentProcessId() as u32,
            timestamp: KeQueryInterruptTime() as u64,
        };
        let _ = ipc::send_event(&event);
    }

    FltReleaseFileNameInformation(name_info);
    FLT_PREOP_CALLBACK_STATUS::FLT_PREOP_SUCCESS_NO_CALLBACK
}

// ---------------------------------------------------------------------------
// Pre-SetInformation callback (rename / delete)
// ---------------------------------------------------------------------------

/// Pre-operation callback for IRP_MJ_SET_INFORMATION.
///
/// Covers file renames (FileRenameInformation) and pending deletes
/// (FileDispositionInformation), both relevant to T1565 (data manipulation).
///
/// # IRQL
/// SetInformation arrives at PASSIVE_LEVEL for user-mode initiated I/O.
pub unsafe extern "system" fn pre_set_info_callback(
    data: *mut FLT_CALLBACK_DATA,
    flt_objects: *const FLT_RELATED_OBJECTS,
    _completion_context: *mut *mut c_void,
) -> FLT_PREOP_CALLBACK_STATUS {
    let _ = flt_objects;

    if KeGetCurrentIrql() > APC_LEVEL {
        return FLT_PREOP_CALLBACK_STATUS::FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    let mut name_info: *mut FLT_FILE_NAME_INFORMATION = core::ptr::null_mut();
    let status = FltGetFileNameInformation(data, FLT_FILE_NAME_OPTIONS, &mut name_info);
    if status != STATUS_SUCCESS || name_info.is_null() {
        return FLT_PREOP_CALLBACK_STATUS::FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    let _ = FltParseFileNameInformation(name_info);

    let name_us = name_info as *const UNICODE_STRING;
    let (path_buf, path_len) = copy_unicode_string::<512>(name_us);

    if path_len > 0 && should_monitor(&path_buf[..path_len]) {
        let event = KernelEvent::FileRename {
            path: path_buf,
            path_len: path_len as u16,
            pid: PsGetCurrentProcessId() as u32,
            timestamp: KeQueryInterruptTime() as u64,
        };
        let _ = ipc::send_event(&event);
    }

    FltReleaseFileNameInformation(name_info);
    FLT_PREOP_CALLBACK_STATUS::FLT_PREOP_SUCCESS_NO_CALLBACK
}
