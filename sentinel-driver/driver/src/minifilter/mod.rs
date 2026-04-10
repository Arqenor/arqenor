//! C2 — File system minifilter for FIM at kernel level (T1565, T1005).
//!
//! Registers a minifilter with Filter Manager at altitude 370010.
//! Three IRP major functions are intercepted in pre-op:
//!   - IRP_MJ_CREATE        (file creation / open)
//!   - IRP_MJ_WRITE         (file data write)
//!   - IRP_MJ_SET_INFORMATION (rename, delete)
//!
//! All callbacks are monitoring-only: I/O is never blocked or modified.

pub mod callbacks;

use core::ffi::c_void;

use wdk_sys::{
    ntddk::*,
    types::*,
    DRIVER_OBJECT, NTSTATUS, STATUS_SUCCESS,
};

use callbacks::{
    pre_create_callback,
    pre_set_info_callback,
    pre_write_callback,
    FLT_PREOP_CALLBACK_STATUS,
    IRP_MJ_CREATE,
    IRP_MJ_OPERATION_END,
    IRP_MJ_SET_INFORMATION,
    IRP_MJ_WRITE,
    PFLT_FILTER,
};

// ---------------------------------------------------------------------------
// fltkernel FFI
// ---------------------------------------------------------------------------

/// Function pointer type for a pre-operation callback.
type PFN_FLT_PRE_OPERATION_CALLBACK = unsafe extern "system" fn(
    data: *mut callbacks::FLT_CALLBACK_DATA,
    flt_objects: *const callbacks::FLT_RELATED_OBJECTS,
    completion_context: *mut *mut c_void,
) -> FLT_PREOP_CALLBACK_STATUS;

/// One entry in the FLT_OPERATION_REGISTRATION array.
#[repr(C)]
struct FLT_OPERATION_REGISTRATION {
    major_function: u8,
    flags: u32,
    pre_operation: Option<PFN_FLT_PRE_OPERATION_CALLBACK>,
    post_operation: *const c_void, // NULL — no post-op needed
    reserved1: *const c_void,
}

// Safety: the static registration array contains only function pointers and
// integer constants — it is Send + Sync at the kernel level.
unsafe impl Sync for FLT_OPERATION_REGISTRATION {}
unsafe impl Send for FLT_OPERATION_REGISTRATION {}

/// The complete FLT_REGISTRATION structure passed to FltRegisterFilter.
///
/// Field layout must match fltkernel.h exactly.  Fields not used by a
/// monitoring-only filter are set to NULL / 0.
#[repr(C)]
struct FLT_REGISTRATION {
    size: u16,
    version: u16,
    flags: u32,
    context_registration: *const c_void,
    operation_registration: *const FLT_OPERATION_REGISTRATION,
    filter_unload_callback: *const c_void,
    instance_setup_callback: *const c_void,
    instance_query_teardown_callback: *const c_void,
    instance_teardown_start_callback: *const c_void,
    instance_teardown_complete_callback: *const c_void,
    generate_file_name_callback: *const c_void,
    normalize_name_component_callback: *const c_void,
    normalize_context_cleanup_callback: *const c_void,
    transaction_notification_callback: *const c_void,
    normalize_name_component_ex_callback: *const c_void,
    section_notification_callback: *const c_void,
}

unsafe impl Sync for FLT_REGISTRATION {}
unsafe impl Send for FLT_REGISTRATION {}

// FLT_REGISTRATION version for Windows 10+.
const FLT_REGISTRATION_VERSION: u16 = 0x0203;

// FLT_REGISTRATION flags — none needed for a monitoring filter.
const FLTFL_REGISTRATION_DO_NOT_SUPPORT_SERVICE_STOP: u32 = 0x00000004;

// ---------------------------------------------------------------------------
// Static registration tables
// ---------------------------------------------------------------------------

/// The callback table. Terminated by an entry with IRP_MJ_OPERATION_END.
static OPERATION_REGISTRATION: [FLT_OPERATION_REGISTRATION; 4] = [
    FLT_OPERATION_REGISTRATION {
        major_function: IRP_MJ_CREATE,
        flags: 0,
        pre_operation: Some(pre_create_callback),
        post_operation: core::ptr::null(),
        reserved1: core::ptr::null(),
    },
    FLT_OPERATION_REGISTRATION {
        major_function: IRP_MJ_WRITE,
        flags: 0,
        pre_operation: Some(pre_write_callback),
        post_operation: core::ptr::null(),
        reserved1: core::ptr::null(),
    },
    FLT_OPERATION_REGISTRATION {
        major_function: IRP_MJ_SET_INFORMATION,
        flags: 0,
        pre_operation: Some(pre_set_info_callback),
        post_operation: core::ptr::null(),
        reserved1: core::ptr::null(),
    },
    // Terminator — must be last.
    FLT_OPERATION_REGISTRATION {
        major_function: IRP_MJ_OPERATION_END,
        flags: 0,
        pre_operation: None,
        post_operation: core::ptr::null(),
        reserved1: core::ptr::null(),
    },
];

static FILTER_REGISTRATION: FLT_REGISTRATION = FLT_REGISTRATION {
    size: core::mem::size_of::<FLT_REGISTRATION>() as u16,
    version: FLT_REGISTRATION_VERSION,
    flags: FLTFL_REGISTRATION_DO_NOT_SUPPORT_SERVICE_STOP,
    context_registration: core::ptr::null(),
    operation_registration: OPERATION_REGISTRATION.as_ptr(),
    filter_unload_callback: core::ptr::null(),
    instance_setup_callback: core::ptr::null(),
    instance_query_teardown_callback: core::ptr::null(),
    instance_teardown_start_callback: core::ptr::null(),
    instance_teardown_complete_callback: core::ptr::null(),
    generate_file_name_callback: core::ptr::null(),
    normalize_name_component_callback: core::ptr::null(),
    normalize_context_cleanup_callback: core::ptr::null(),
    transaction_notification_callback: core::ptr::null(),
    normalize_name_component_ex_callback: core::ptr::null(),
    section_notification_callback: core::ptr::null(),
};

// ---------------------------------------------------------------------------
// fltmgr.sys imports
// ---------------------------------------------------------------------------

#[link(name = "fltmgr")]
extern "system" {
    fn FltRegisterFilter(
        driver: *mut DRIVER_OBJECT,
        registration: *const FLT_REGISTRATION,
        ret_filter: *mut PFLT_FILTER,
    ) -> NTSTATUS;

    fn FltStartFiltering(filter: PFLT_FILTER) -> NTSTATUS;

    fn FltUnregisterFilter(filter: PFLT_FILTER);
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Token representing a successfully registered minifilter.
///
/// Call `unregister` from DriverUnload to tear down cleanly.
pub struct MinifilterModule {
    pub filter_handle: PFLT_FILTER,
}

impl MinifilterModule {
    /// Register the SENTINEL minifilter with Filter Manager and start filtering.
    ///
    /// # Safety
    /// Must be called at IRQL == PASSIVE_LEVEL during DriverEntry.
    /// `driver` must be the `DriverObject` passed to DriverEntry.
    pub unsafe fn register(driver: *mut DRIVER_OBJECT) -> Result<Self, NTSTATUS> {
        let mut filter_handle: PFLT_FILTER = core::ptr::null_mut();

        let status = FltRegisterFilter(
            driver,
            &FILTER_REGISTRATION,
            &mut filter_handle,
        );
        if status != STATUS_SUCCESS {
            return Err(status);
        }

        let status = FltStartFiltering(filter_handle);
        if status != STATUS_SUCCESS {
            FltUnregisterFilter(filter_handle);
            return Err(status);
        }

        Ok(MinifilterModule { filter_handle })
    }

    /// Unregister the minifilter.  Must be called before returning from
    /// DriverUnload.  Blocks until all in-flight callbacks have completed.
    ///
    /// # Safety
    /// Must be called at IRQL == PASSIVE_LEVEL.
    pub unsafe fn unregister(self) {
        FltUnregisterFilter(self.filter_handle);
    }
}
