//! Registry callback routine for CmRegisterCallbackEx.
//!
//! Monitors pre-operation registry events on high-value keys used for
//! persistence (T1547.001), defence evasion (T1112), and hijacking
//! (Image File Execution Options).
//!
//! The callback is monitoring-only: it always returns STATUS_SUCCESS so that
//! the registry operation proceeds normally.

use core::ffi::c_void;

use wdk_sys::{ntddk::*, types::*, NTSTATUS, STATUS_SUCCESS};

use crate::ipc;
use sentinel_driver_common::KernelEvent;

// ---------------------------------------------------------------------------
// REG_NOTIFY_CLASS — kernel enum for the type of registry operation.
// Only the values we dispatch on are listed.
// ---------------------------------------------------------------------------

/// Registry notification class codes passed as `argument1` to the callback.
#[repr(i32)]
#[allow(non_camel_case_types, dead_code)]
enum REG_NOTIFY_CLASS {
    RegNtPreDeleteKey          = 0,
    RegNtPreSetValueKey        = 1,
    RegNtPreDeleteValueKey     = 2,
    RegNtPreSetInformationKey  = 3,
    RegNtPreRenameKey          = 4,
    RegNtPreEnumerateKey       = 5,
    RegNtPreEnumerateValueKey  = 6,
    RegNtPreQueryKey           = 7,
    RegNtPreQueryValueKey      = 8,
    RegNtPreQueryMultipleValueKey = 9,
    RegNtPreCreateKey          = 10,
    RegNtPostCreateKey         = 11,
    RegNtPreOpenKey            = 12,
    RegNtPostOpenKey           = 13,
    RegNtPreCreateKeyEx        = 26,
    RegNtPostCreateKeyEx       = 27,
}

// ---------------------------------------------------------------------------
// Kernel structures for registry callback argument2
// (declared here because wdk-sys doesn't expose all registry info structs)
// ---------------------------------------------------------------------------

/// Minimal view of REG_SET_VALUE_KEY_INFORMATION.
/// Full struct has more fields; we only need Object and ValueName.
#[repr(C)]
struct REG_SET_VALUE_KEY_INFORMATION {
    object: *mut c_void,        // Registry key object (PVOID)
    value_name: *mut UNICODE_STRING,
    title_index: u32,
    type_: u32,
    data: *mut c_void,
    data_size: u32,
    call_context: *mut c_void,
    object_context: *mut c_void,
    reserved: *mut c_void,
}

/// Minimal view of REG_CREATE_KEY_INFORMATION / REG_PRE_CREATE_KEY_INFORMATION.
#[repr(C)]
struct REG_CREATE_KEY_INFORMATION {
    complete_name: *mut UNICODE_STRING,
    root_object: *mut c_void,
    object: *mut c_void,
    options: u32,
    disposition: *mut u32,
    create_options: *mut c_void,
    result_object: *mut *mut c_void,
    call_context: *mut c_void,
    root_object_context: *mut c_void,
    transaction: *mut c_void,
}

/// Minimal view of REG_DELETE_KEY_INFORMATION.
#[repr(C)]
struct REG_DELETE_KEY_INFORMATION {
    object: *mut c_void,
    call_context: *mut c_void,
    object_context: *mut c_void,
    reserved: *mut c_void,
}

// ---------------------------------------------------------------------------
// CmCallbackGetKeyObjectIDEx FFI
// ---------------------------------------------------------------------------

#[link(name = "ntoskrnl")]
extern "system" {
    /// Obtain the registry path for a key object.
    /// Returns an allocated UNICODE_STRING — caller must free with
    /// CmCallbackReleaseKeyObjectIDEx.
    fn CmCallbackGetKeyObjectIDEx(
        cookie: *mut i64,
        object: *mut c_void,
        object_id: *mut u64,
        object_name: *mut *mut UNICODE_STRING,
        flags: u32,
    ) -> NTSTATUS;

    fn CmCallbackReleaseKeyObjectIDEx(object_name: *mut UNICODE_STRING);
}

// ---------------------------------------------------------------------------
// Monitored key path prefixes
// ---------------------------------------------------------------------------

/// ASCII-lowercased key path prefixes that are high-value for persistence /
/// defence evasion monitoring.
static MONITORED_KEY_PREFIXES: &[&str] = &[
    "\\registry\\machine\\software\\microsoft\\windows\\currentversion\\run",
    "\\registry\\machine\\software\\microsoft\\windows nt\\currentversion\\winlogon",
    "\\registry\\machine\\system\\currentcontrolset\\services",
    "\\registry\\machine\\software\\microsoft\\windows nt\\currentversion\\image file execution options",
    "\\registry\\machine\\software\\classes\\ms-settings",
];

/// Returns true if `path` (ASCII-lowercased) starts with any monitored prefix.
fn is_monitored_key(path_wide: &[u16]) -> bool {
    // Convert to ASCII lowercase scratch buffer (first 512 chars max).
    let mut ascii = [0u8; 512];
    let len = path_wide.len().min(ascii.len());
    for (i, &wc) in path_wide[..len].iter().enumerate() {
        ascii[i] = if wc < 0x80 { (wc as u8).to_ascii_lowercase() } else { b'?' };
    }
    let path_bytes = &ascii[..len];

    for prefix in MONITORED_KEY_PREFIXES {
        let p = prefix.as_bytes();
        if path_bytes.len() >= p.len() && &path_bytes[..p.len()] == p {
            return true;
        }
    }
    false
}

// ---------------------------------------------------------------------------
// Helper: copy UNICODE_STRING into a fixed-size u16 array
// ---------------------------------------------------------------------------

/// # Safety: `us` must point to a valid, initialized UNICODE_STRING.
unsafe fn copy_unicode_string_512(us: *const UNICODE_STRING) -> ([u16; 512], usize) {
    let mut out = [0u16; 512];
    if us.is_null() || (*us).Buffer.is_null() {
        return (out, 0);
    }
    let len_chars = ((*us).Length as usize) / 2;
    let copy_chars = len_chars.min(511);
    core::ptr::copy_nonoverlapping((*us).Buffer, out.as_mut_ptr(), copy_chars);
    (out, copy_chars)
}

// ---------------------------------------------------------------------------
// Get key path from an object pointer
// ---------------------------------------------------------------------------

/// Resolve a registry object pointer to its full path.
///
/// Returns `None` if `CmCallbackGetKeyObjectIDEx` fails or the path is empty.
///
/// # Safety
/// `cookie` must be the callback cookie from `CmRegisterCallbackEx`.
/// `object` must be a valid registry key object pointer.
unsafe fn get_key_path(
    cookie: &mut i64,
    object: *mut c_void,
) -> Option<([u16; 512], usize)> {
    let mut name_ptr: *mut UNICODE_STRING = core::ptr::null_mut();
    let status =
        CmCallbackGetKeyObjectIDEx(cookie as *mut i64, object, core::ptr::null_mut(), &mut name_ptr, 0);

    if status != STATUS_SUCCESS || name_ptr.is_null() {
        return None;
    }

    let result = copy_unicode_string_512(name_ptr);
    CmCallbackReleaseKeyObjectIDEx(name_ptr);

    if result.1 == 0 { None } else { Some(result) }
}

// ---------------------------------------------------------------------------
// The registry callback routine
// ---------------------------------------------------------------------------

/// Main registry pre-operation callback.
///
/// `context` carries the `RegistryModule` pointer (cast from `*mut c_void`).
/// `argument1` is the `REG_NOTIFY_CLASS` cast to `*mut c_void` (usize).
/// `argument2` is the operation-specific info struct pointer.
///
/// # Safety
/// Called by the kernel at PASSIVE_LEVEL or APC_LEVEL.
pub unsafe extern "system" fn registry_callback_routine(
    context: *mut c_void,
    argument1: *mut c_void,
    argument2: *mut c_void,
) -> NTSTATUS {
    // Retrieve the callback cookie stored in RegistryModule.
    // context is *mut RegistryModule — we only need the cookie field.
    // Since we can't import RegistryModule here (circular module issue), we
    // store the cookie at a well-known offset (first field, i64).
    let cookie_ptr = context as *mut i64;
    if cookie_ptr.is_null() {
        return STATUS_SUCCESS;
    }
    let cookie_val = *cookie_ptr;

    let notify_class = argument1 as i32;

    match notify_class {
        // RegNtPreSetValueKey = 1
        1 => {
            let info = argument2 as *mut REG_SET_VALUE_KEY_INFORMATION;
            if info.is_null() {
                return STATUS_SUCCESS;
            }
            let object = (*info).object;
            let mut cookie = cookie_val;
            if let Some((key_path, key_len)) = get_key_path(&mut cookie, object) {
                if is_monitored_key(&key_path[..key_len]) {
                    // Get value name
                    let (val_name, val_len) =
                        copy_unicode_string_512((*info).value_name as *const UNICODE_STRING);

                    let event = KernelEvent::RegistrySetValue {
                        key_path,
                        key_path_len: key_len as u16,
                        value_name: val_name,
                        value_name_len: val_len as u16,
                        data_type: (*info).type_,
                        pid: PsGetCurrentProcessId() as u32,
                        timestamp: KeQueryInterruptTime() as u64,
                    };
                    let _ = ipc::send_event(&event);
                }
            }
        }

        // RegNtPreCreateKey = 10  or  RegNtPreCreateKeyEx = 26
        10 | 26 => {
            let info = argument2 as *mut REG_CREATE_KEY_INFORMATION;
            if info.is_null() {
                return STATUS_SUCCESS;
            }
            let (key_path, key_len) =
                copy_unicode_string_512((*info).complete_name as *const UNICODE_STRING);

            if key_len > 0 && is_monitored_key(&key_path[..key_len]) {
                let event = KernelEvent::RegistryCreateKey {
                    key_path,
                    key_path_len: key_len as u16,
                    pid: PsGetCurrentProcessId() as u32,
                    timestamp: KeQueryInterruptTime() as u64,
                };
                let _ = ipc::send_event(&event);
            }
        }

        // RegNtPreDeleteKey = 0
        0 => {
            let info = argument2 as *mut REG_DELETE_KEY_INFORMATION;
            if info.is_null() {
                return STATUS_SUCCESS;
            }
            let object = (*info).object;
            let mut cookie = cookie_val;
            if let Some((key_path, key_len)) = get_key_path(&mut cookie, object) {
                if is_monitored_key(&key_path[..key_len]) {
                    let event = KernelEvent::RegistryDeleteKey {
                        key_path,
                        key_path_len: key_len as u16,
                        pid: PsGetCurrentProcessId() as u32,
                        timestamp: KeQueryInterruptTime() as u64,
                    };
                    let _ = ipc::send_event(&event);
                }
            }
        }

        _ => {
            // Not an operation we care about — pass through.
        }
    }

    STATUS_SUCCESS
}
