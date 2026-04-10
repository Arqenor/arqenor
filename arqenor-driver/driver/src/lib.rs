//! ARQENOR kernel driver — main entry point.
//!
//! Architecture:
//!   - Minifilter (altitude 370010): file system telemetry (FIM)
//!   - CmRegisterCallbackEx: registry persistence/evasion telemetry
//!   - PsSetCreateProcessNotifyRoutineEx: process creation/termination telemetry
//!   - ObRegisterCallbacks: self-protection against handle-based attacks
//!   - FltCreateCommunicationPort: IPC channel to the ARQENOR usermode agent
//!
//! All subsystems are initialised in `DriverEntry` and torn down in reverse
//! order by `driver_unload`. Any failure during init triggers a partial cleanup
//! and returns the failing NTSTATUS.

#![no_std]
#![no_main]
// `alloc` is required for the WDK allocator integration.
extern crate alloc;

mod alloc_impl;
mod ipc;
mod minifilter;
mod panic_impl;
mod process;
mod protection;
mod registry;

use core::{
    ffi::c_void,
    ptr,
    sync::atomic::{AtomicPtr, AtomicU32, Ordering},
};

use wdk_sys::{
    ntddk::*,
    types::*,
    DRIVER_OBJECT, NTSTATUS,
    STATUS_SUCCESS, STATUS_FAILED_DRIVER_ENTRY,
};

use wdk_alloc::WdkAllocator;

use ipc::IpcPort;
use minifilter::MinifilterModule;
use process::ProcessModule;
use protection::ProtectionModule;
use registry::RegistryModule;

// ---------------------------------------------------------------------------
// Global allocator — must live in non-paged pool
// ---------------------------------------------------------------------------

// NOTE: alloc_impl.rs declares #[global_allocator] — do NOT repeat it here.
// The declaration in alloc_impl.rs is the single source of truth.
use alloc_impl::ALLOCATOR as _; // ensure the module is compiled

// ---------------------------------------------------------------------------
// Pool tag and allocation helpers
// ---------------------------------------------------------------------------

/// Non-paged pool tag: ASCII "SNTL" in little-endian form.
const POOL_TAG: u32 = u32::from_le_bytes(*b"SNTL");

/// `POOL_FLAG_NON_PAGED_NX` — executable bit clear, non-paged.
const POOL_FLAG_NON_PAGED_NX: u64 = 0x40;

// ---------------------------------------------------------------------------
// Driver state
// ---------------------------------------------------------------------------

/// All long-lived kernel handles owned by this driver, allocated on the
/// non-paged heap so they survive after DriverEntry returns.
///
/// Fields are in init order; unload tears them down in reverse.
///
/// # Safety
/// This struct is `#[repr(C)]` and zero-initialised. It is accessed only
/// from `DriverEntry` / `driver_unload` which are serialised by the OS.
/// The `protected_pid` field may be written from the IPC connect callback
/// at any IRQL <= APC_LEVEL, hence the AtomicU32.
#[repr(C)]
pub struct DriverState {
    /// Registered minifilter handle (PFLT_FILTER).
    pub filter_handle: *mut c_void,
    /// IPC server port handle.
    pub ipc_port: *mut c_void,
    /// Registry callback cookie (opaque i64 from CmRegisterCallbackEx).
    pub registry_cookie: i64,
    /// ObCallbacks registration handle.
    pub ob_registration_handle: *mut c_void,
    /// PID of the ARQENOR usermode agent being protected. 0 = inactive.
    pub protected_pid: AtomicU32,
    /// Flags indicating which subsystems have been successfully initialised.
    /// Bit 0 = minifilter, bit 1 = ipc, bit 2 = registry,
    /// bit 3 = process notify, bit 4 = ob callbacks.
    pub init_flags: u32,
}

/// Bitmask constants for `DriverState::init_flags`.
const INIT_MINIFILTER: u32 = 1 << 0;
const INIT_IPC:        u32 = 1 << 1;
const INIT_REGISTRY:   u32 = 1 << 2;
const INIT_PROCESS:    u32 = 1 << 3;
const INIT_PROTECTION: u32 = 1 << 4;

/// Global pointer to the `DriverState` allocation.
/// Null until `DriverEntry` succeeds; set back to null after `driver_unload`.
///
/// Uses `AtomicPtr` for interior mutability without UB.
static DRIVER_STATE: AtomicPtr<DriverState> = AtomicPtr::new(ptr::null_mut());

// ---------------------------------------------------------------------------
// DriverEntry
// ---------------------------------------------------------------------------

/// Kernel entry point — called once by the OS at driver load time.
///
/// # Safety
/// Called by the Windows kernel at IRQL == PASSIVE_LEVEL.
/// `driver_object` is valid for the lifetime of the driver.
/// `registry_path` is valid only for the duration of this call.
#[no_mangle]
pub unsafe extern "system" fn DriverEntry(
    driver_object: *mut DRIVER_OBJECT,
    _registry_path: *mut UNICODE_STRING,
) -> NTSTATUS {
    // Allocate DriverState on the non-paged heap.
    let state_ptr = ExAllocatePool2(
        POOL_FLAG_NON_PAGED_NX,
        core::mem::size_of::<DriverState>() as u64,
        POOL_TAG,
    ) as *mut DriverState;

    if state_ptr.is_null() {
        return STATUS_FAILED_DRIVER_ENTRY;
    }

    // Zero-initialise (ExAllocatePool2 already zeros, but be explicit).
    core::ptr::write(state_ptr, core::mem::zeroed::<DriverState>());
    let state = &mut *state_ptr;

    // ---- 1. Register minifilter ----------------------------------------
    let minifilter = match MinifilterModule::register(driver_object) {
        Ok(m) => m,
        Err(status) => {
            cleanup_partial(state_ptr);
            return status;
        }
    };
    state.filter_handle = minifilter.filter_handle;
    state.init_flags |= INIT_MINIFILTER;

    // ---- 2. Create IPC port (requires the filter handle) ---------------
    match IpcPort::create(state.filter_handle) {
        Ok(port) => {
            state.ipc_port = port.server_port;
            // Don't drop port — we move the raw handle into state above.
            // Prevent the destructor from running via core::mem::forget.
            core::mem::forget(port);
            state.init_flags |= INIT_IPC;
        }
        Err(status) => {
            cleanup_partial(state_ptr);
            return status;
        }
    }

    // ---- 3. Register registry callback ---------------------------------
    let reg_module = match RegistryModule::register(driver_object) {
        Ok(m) => m,
        Err(status) => {
            cleanup_partial(state_ptr);
            return status;
        }
    };
    state.registry_cookie = reg_module.cookie;
    core::mem::forget(reg_module);
    state.init_flags |= INIT_REGISTRY;

    // ---- 4. Register process notify callback ---------------------------
    let _proc_module = match ProcessModule::register() {
        Ok(m) => m,
        Err(status) => {
            cleanup_partial(state_ptr);
            return status;
        }
    };
    core::mem::forget(_proc_module);
    state.init_flags |= INIT_PROCESS;

    // ---- 5. Register ObCallbacks self-protection ----------------------
    let prot_module = match ProtectionModule::register(&state.protected_pid) {
        Ok(m) => m,
        Err(status) => {
            cleanup_partial(state_ptr);
            return status;
        }
    };
    state.ob_registration_handle = prot_module.registration_handle;
    core::mem::forget(prot_module);
    state.init_flags |= INIT_PROTECTION;

    // ---- Publish state & install unload routine ----------------------
    DRIVER_STATE.store(state_ptr, Ordering::Release);
    (*driver_object).DriverUnload = Some(driver_unload);

    STATUS_SUCCESS
}

// ---------------------------------------------------------------------------
// DriverUnload
// ---------------------------------------------------------------------------

/// Called by the OS when the driver is being unloaded.
///
/// Tears down all subsystems in reverse init order:
///   ObCallbacks → ProcessNotify → RegCallbacks → IPC port → Minifilter
///
/// # Safety
/// Called by the Windows kernel at IRQL == PASSIVE_LEVEL.
unsafe extern "system" fn driver_unload(_driver_object: *mut DRIVER_OBJECT) {
    let state_ptr = DRIVER_STATE.swap(ptr::null_mut(), Ordering::AcqRel);
    if state_ptr.is_null() {
        return;
    }

    let state = &mut *state_ptr;

    // ---- 5. Unregister ObCallbacks (reverse order) --------------------
    if state.init_flags & INIT_PROTECTION != 0 {
        let prot = ProtectionModule {
            registration_handle: state.ob_registration_handle,
        };
        prot.unregister();
    }

    // ---- 4. Unregister process notify ---------------------------------
    if state.init_flags & INIT_PROCESS != 0 {
        let proc_mod = ProcessModule;
        proc_mod.unregister();
    }

    // ---- 3. Unregister registry callback ------------------------------
    if state.init_flags & INIT_REGISTRY != 0 {
        let reg_mod = RegistryModule {
            cookie: state.registry_cookie,
        };
        reg_mod.unregister();
    }

    // ---- 2. Close IPC port --------------------------------------------
    if state.init_flags & INIT_IPC != 0 {
        let port = IpcPort {
            server_port: state.ipc_port,
        };
        port.close();
    }

    // ---- 1. Unregister minifilter (must be last filter-related op) ----
    if state.init_flags & INIT_MINIFILTER != 0 {
        let mf = MinifilterModule {
            filter_handle: state.filter_handle,
        };
        mf.unregister();
    }

    // ---- Free the DriverState allocation ------------------------------
    ExFreePoolWithTag(state_ptr as *mut c_void, POOL_TAG);
}

// ---------------------------------------------------------------------------
// Partial cleanup helper
// ---------------------------------------------------------------------------

/// Tear down any subsystems that were successfully initialised before the
/// failing subsystem.  Called only from `DriverEntry` on error paths.
///
/// # Safety
/// `state_ptr` must point to a valid, partially-initialised `DriverState`.
unsafe fn cleanup_partial(state_ptr: *mut DriverState) {
    if state_ptr.is_null() {
        return;
    }

    let state = &mut *state_ptr;

    // Tear down in reverse init order, checking each flag.

    if state.init_flags & INIT_PROTECTION != 0 {
        let prot = ProtectionModule {
            registration_handle: state.ob_registration_handle,
        };
        prot.unregister();
    }

    if state.init_flags & INIT_PROCESS != 0 {
        let proc_mod = ProcessModule;
        proc_mod.unregister();
    }

    if state.init_flags & INIT_REGISTRY != 0 {
        let reg_mod = RegistryModule {
            cookie: state.registry_cookie,
        };
        reg_mod.unregister();
    }

    if state.init_flags & INIT_IPC != 0 {
        let port = IpcPort {
            server_port: state.ipc_port,
        };
        port.close();
    }

    if state.init_flags & INIT_MINIFILTER != 0 {
        let mf = MinifilterModule {
            filter_handle: state.filter_handle,
        };
        mf.unregister();
    }

    ExFreePoolWithTag(state_ptr as *mut c_void, POOL_TAG);
}
