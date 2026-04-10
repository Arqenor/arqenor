//! IPC module — Filter Manager communication port (`\ArqenorPort`).
//!
//! The kernel driver acts as the **server**; the usermode agent connects as the
//! client. Once connected the kernel side calls `FltSendMessage` to push
//! `KernelEvent` blobs to usermode without waiting for a reply.
//!
//! # Thread-safety
//! `CLIENT_PORT` is set in the connect callback and cleared in the disconnect
//! callback. Both callbacks are serialised by Filter Manager, but `send_event`
//! may race with disconnect. We use an `AtomicPtr` to snapshot the port handle
//! before use and tolerate a null snapshot (event dropped silently).

pub mod messages;

use core::{
    ffi::c_void,
    sync::atomic::{AtomicPtr, Ordering},
};

use messages::{EventBuffer, KernelEvent};

use wdk_sys::{
    ntddk::*,
    types::*,
    NTSTATUS, STATUS_SUCCESS,
};

// ---------------------------------------------------------------------------
// fltkernel.h types not (yet) in wdk-sys — declared as opaque C enums so the
// compiler gives them distinct types while keeping their ABI as `*mut c_void`.
// ---------------------------------------------------------------------------

/// Opaque handle to a registered minifilter filter object (PFLT_FILTER).
pub type PFLT_FILTER = *mut c_void;

/// Opaque handle to a Filter Manager communication port (PFLT_PORT).
pub type PFLT_PORT = *mut c_void;

/// Opaque handle to a Filter Manager callback data block (PFLT_CALLBACK_DATA).
pub type PFLT_CALLBACK_DATA = *mut c_void;

// ---------------------------------------------------------------------------
// fltkernel FFI — functions not exposed via wdk-sys safe wrappers
// ---------------------------------------------------------------------------

#[link(name = "fltmgr")]
extern "system" {
    /// Create a kernel-side communication port that usermode can connect to.
    ///
    /// Signature mirrors `FltCreateCommunicationPort` from fltkernel.h.
    fn FltCreateCommunicationPort(
        filter: PFLT_FILTER,
        server_port: *mut PFLT_PORT,
        object_attributes: *mut OBJECT_ATTRIBUTES,
        server_port_cookie: *mut c_void,
        connect_notify: unsafe extern "system" fn(
            client_port: PFLT_PORT,
            server_port_cookie: *mut c_void,
            connection_context: *mut c_void,
            size_of_context: u32,
            connection_port_cookie: *mut *mut c_void,
        ) -> NTSTATUS,
        disconnect_notify: unsafe extern "system" fn(connection_port_cookie: *mut c_void),
        message_notify: unsafe extern "system" fn(
            port_cookie: *mut c_void,
            input_buffer: *mut c_void,
            input_buffer_length: u32,
            output_buffer: *mut c_void,
            output_buffer_length: u32,
            return_output_buffer_length: *mut u32,
        ) -> NTSTATUS,
        max_connections: i32,
    ) -> NTSTATUS;

    /// Close (delete) the kernel-side server communication port.
    fn FltCloseCommunicationPort(server_port: PFLT_PORT);

    /// Send a message from kernel to usermode via a communication port.
    fn FltSendMessage(
        filter: PFLT_FILTER,
        client_port: *mut PFLT_PORT,
        sender_buffer: *mut c_void,
        sender_buffer_length: u32,
        reply_buffer: *mut c_void,
        reply_length: *mut u32,
        timeout: *mut i64,
    ) -> NTSTATUS;
}

// ---------------------------------------------------------------------------
// Port name — `\ArqenorPort` as a static UTF-16 literal
// ---------------------------------------------------------------------------

/// UTF-16 encoded port name. Null terminator not needed for UNICODE_STRING.
static PORT_NAME_WIDE: &[u16] = &[
    b'\\' as u16,
    b'S' as u16, b'e' as u16, b'n' as u16, b't' as u16, b'i' as u16,
    b'n' as u16, b'e' as u16, b'l' as u16,
    b'P' as u16, b'o' as u16, b'r' as u16, b't' as u16,
];

// ---------------------------------------------------------------------------
// Global state
// ---------------------------------------------------------------------------

/// The active client port connection. Null when no usermode client is connected.
static CLIENT_PORT: AtomicPtr<c_void> = AtomicPtr::new(core::ptr::null_mut());

/// The server port handle retained for cleanup.
static SERVER_PORT: AtomicPtr<c_void> = AtomicPtr::new(core::ptr::null_mut());

/// The filter handle needed by FltSendMessage.
static FILTER_HANDLE: AtomicPtr<c_void> = AtomicPtr::new(core::ptr::null_mut());

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Opaque token representing an active IPC port.
///
/// Drop (via `close()`) to tear down the server port.
pub struct IpcPort {
    pub server_port: PFLT_PORT,
}

impl IpcPort {
    /// Create the kernel-side Filter Manager communication port.
    ///
    /// Must be called after the minifilter has been registered (we need the
    /// `filter` handle). The port allows at most one simultaneous client
    /// connection (the ARQENOR usermode agent).
    ///
    /// # Safety
    /// Must be called at IRQL == PASSIVE_LEVEL.
    /// `filter` must be a valid, registered minifilter handle.
    pub unsafe fn create(filter: PFLT_FILTER) -> Result<Self, NTSTATUS> {
        debug_assert!(
            KeGetCurrentIrql() == 0, // PASSIVE_LEVEL
            "IpcPort::create must be called at PASSIVE_LEVEL"
        );

        // Store filter handle so send_event can use it without a parameter.
        FILTER_HANDLE.store(filter, Ordering::Release);

        // Build UNICODE_STRING for the port name.
        let mut port_name = UNICODE_STRING {
            Length: (PORT_NAME_WIDE.len() * 2) as u16,
            MaximumLength: (PORT_NAME_WIDE.len() * 2) as u16,
            Buffer: PORT_NAME_WIDE.as_ptr() as *mut u16,
        };

        // Build OBJECT_ATTRIBUTES — allow any process to connect (ACL = null).
        let mut obj_attr: OBJECT_ATTRIBUTES = core::mem::zeroed();
        InitializeObjectAttributes(
            &mut obj_attr,
            &mut port_name,
            OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE,
            core::ptr::null_mut(),
            core::ptr::null_mut(),
        );

        let mut server_port: PFLT_PORT = core::ptr::null_mut();

        let status = FltCreateCommunicationPort(
            filter,
            &mut server_port,
            &mut obj_attr,
            core::ptr::null_mut(), // server_port_cookie
            connect_notify,
            disconnect_notify,
            message_notify,
            1, // max one client at a time
        );

        if status != STATUS_SUCCESS {
            return Err(status);
        }

        SERVER_PORT.store(server_port, Ordering::Release);
        Ok(Self { server_port })
    }

    /// Close the server communication port.
    ///
    /// # Safety
    /// Must be called at IRQL == PASSIVE_LEVEL.
    pub unsafe fn close(self) {
        FltCloseCommunicationPort(self.server_port);
        SERVER_PORT.store(core::ptr::null_mut(), Ordering::Release);
        FILTER_HANDLE.store(core::ptr::null_mut(), Ordering::Release);
    }
}

// ---------------------------------------------------------------------------
// Send path
// ---------------------------------------------------------------------------

/// Send a `KernelEvent` to the connected usermode agent.
///
/// Returns `Ok(())` on success, or `Err(NTSTATUS)` if no client is connected
/// or `FltSendMessage` fails. The event is dropped silently when no client is
/// present — we never block the calling thread.
///
/// # Safety
/// Safe to call at IRQL <= APC_LEVEL. Uses a 0-timeout so it never blocks.
pub unsafe fn send_event(event: &KernelEvent) -> Result<(), NTSTATUS> {
    let client_port = CLIENT_PORT.load(Ordering::Acquire);
    if client_port.is_null() {
        // No agent connected — silently drop.
        return Ok(());
    }

    let filter = FILTER_HANDLE.load(Ordering::Acquire);
    if filter.is_null() {
        return Ok(());
    }

    let mut buf = EventBuffer::from_event(event);
    // Zero timeout: non-blocking send. If the usermode queue is full, we drop.
    let mut timeout: i64 = 0;

    let status = FltSendMessage(
        filter,
        &mut (client_port as PFLT_PORT),
        buf.data.as_mut_ptr() as *mut c_void,
        buf.used,
        core::ptr::null_mut(), // no reply expected
        core::ptr::null_mut(),
        &mut timeout,
    );

    // STATUS_TIMEOUT means the queue was full — not a hard error for telemetry.
    if status == STATUS_SUCCESS || status == 0x00000102u32 as i32
    /* STATUS_TIMEOUT */
    {
        Ok(())
    } else {
        Err(status)
    }
}

// ---------------------------------------------------------------------------
// Filter Manager callbacks
// ---------------------------------------------------------------------------

/// Called by Filter Manager when a usermode client connects.
unsafe extern "system" fn connect_notify(
    client_port: PFLT_PORT,
    _server_port_cookie: *mut c_void,
    _connection_context: *mut c_void,
    _size_of_context: u32,
    _connection_port_cookie: *mut *mut c_void,
) -> NTSTATUS {
    // Only one client is allowed (max_connections = 1 in create).
    CLIENT_PORT.store(client_port, Ordering::Release);
    STATUS_SUCCESS
}

/// Called by Filter Manager when the usermode client disconnects.
unsafe extern "system" fn disconnect_notify(_connection_port_cookie: *mut c_void) {
    CLIENT_PORT.store(core::ptr::null_mut(), Ordering::Release);
}

/// Called by Filter Manager when the usermode client sends a message to kernel.
///
/// ARQENOR is push-only (kernel → user), so we don't expect inbound messages.
/// Return `STATUS_NOT_SUPPORTED` to indicate nothing was processed.
unsafe extern "system" fn message_notify(
    _port_cookie: *mut c_void,
    _input_buffer: *mut c_void,
    _input_buffer_length: u32,
    _output_buffer: *mut c_void,
    _output_buffer_length: u32,
    _return_output_buffer_length: *mut u32,
) -> NTSTATUS {
    0xC00000BBu32 as NTSTATUS // STATUS_NOT_SUPPORTED
}
