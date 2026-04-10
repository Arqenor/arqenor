//! C3 — Registry callbacks (T1112, T1547.001).
//!
//! Uses `CmRegisterCallbackEx` with altitude "370010" to intercept registry
//! pre-operations on persistence and defence-evasion key paths.

pub mod callbacks;

use core::ffi::c_void;

use wdk_sys::{
    ntddk::*,
    types::*,
    DRIVER_OBJECT, NTSTATUS, STATUS_SUCCESS,
};

use callbacks::registry_callback_routine;

// ---------------------------------------------------------------------------
// CmRegisterCallbackEx / CmUnRegisterCallback FFI
// ---------------------------------------------------------------------------

#[link(name = "ntoskrnl")]
extern "system" {
    /// Register a registry change notification callback.
    ///
    /// The `altitude` UNICODE_STRING distinguishes this registration when
    /// multiple callbacks are registered at the same altitude.
    fn CmRegisterCallbackEx(
        function: unsafe extern "system" fn(
            context: *mut c_void,
            argument1: *mut c_void,
            argument2: *mut c_void,
        ) -> NTSTATUS,
        altitude: *const UNICODE_STRING,
        driver: *mut DRIVER_OBJECT,
        context: *mut c_void,
        cookie: *mut i64,
        reserved: *mut c_void,
    ) -> NTSTATUS;

    /// Unregister a previously registered registry callback.
    fn CmUnRegisterCallback(cookie: i64) -> NTSTATUS;
}

// ---------------------------------------------------------------------------
// Altitude string — must be kept alive for the lifetime of the registration.
// ---------------------------------------------------------------------------

/// UTF-16 encoded altitude string "370010".
static ALTITUDE_WIDE: &[u16] = &[
    b'3' as u16, b'7' as u16, b'0' as u16, b'0' as u16, b'1' as u16, b'0' as u16,
];

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Token representing an active `CmRegisterCallbackEx` registration.
///
/// The `cookie` field is the **first field** (offset 0) in this struct so that
/// `registry_callback_routine` can retrieve it by casting the context pointer
/// to `*mut i64`.
pub struct RegistryModule {
    /// The opaque cookie returned by `CmRegisterCallbackEx`.
    pub cookie: i64,
}

impl RegistryModule {
    /// Register the registry callback.
    ///
    /// Passes `self` (as a raw pointer) as the `context` argument so the
    /// callback can recover the cookie for `CmCallbackGetKeyObjectIDEx`.
    ///
    /// # Safety
    /// Must be called at IRQL == PASSIVE_LEVEL during DriverEntry.
    pub unsafe fn register(driver: *mut DRIVER_OBJECT) -> Result<Self, NTSTATUS> {
        let mut module = RegistryModule { cookie: 0 };

        let altitude = UNICODE_STRING {
            Length: (ALTITUDE_WIDE.len() * 2) as u16,
            MaximumLength: (ALTITUDE_WIDE.len() * 2) as u16,
            Buffer: ALTITUDE_WIDE.as_ptr() as *mut u16,
        };

        // Pass a pointer to the module's cookie field as context.
        // The callback reads this to call CmCallbackGetKeyObjectIDEx.
        // NOTE: after this call returns, `module` must not be moved until
        // CmUnRegisterCallback is called — enforced by ownership in DriverState.
        let status = CmRegisterCallbackEx(
            registry_callback_routine,
            &altitude,
            driver,
            &mut module.cookie as *mut i64 as *mut c_void,
            &mut module.cookie,
            core::ptr::null_mut(),
        );

        if status != STATUS_SUCCESS {
            return Err(status);
        }

        Ok(module)
    }

    /// Unregister the registry callback.
    ///
    /// Blocks until any in-flight invocations of `registry_callback_routine`
    /// have completed (kernel guarantee from `CmUnRegisterCallback`).
    ///
    /// # Safety
    /// Must be called at IRQL == PASSIVE_LEVEL.
    pub unsafe fn unregister(&self) {
        let _ = CmUnRegisterCallback(self.cookie);
    }
}
