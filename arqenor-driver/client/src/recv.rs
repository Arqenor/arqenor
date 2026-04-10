//! Blocking receiver + async stream wrapper for the ARQENOR filter port.

use std::mem;
use std::sync::Arc;

use tracing::{debug, error, warn};
use windows::{
    core::w,
    Win32::Foundation::{CloseHandle, ERROR_FILE_NOT_FOUND, HANDLE},
    Win32::Storage::InstallableFileSystems::{
        FilterConnectCommunicationPort, FilterGetMessage, FILTER_MESSAGE_HEADER,
    },
};

use arqenor_driver_common::{KernelEvent, KernelMessage};

use crate::error::ClientError;

// ── Wire layout ───────────────────────────────────────────────────────────────

/// Buffer that FilterGetMessage writes into.
///
/// FilterGetMessage prepends a `FILTER_MESSAGE_HEADER` before the payload
/// that the kernel driver sent. So the receive buffer must be:
///
///   [FILTER_MESSAGE_HEADER (8 bytes)] [KernelMessage]
///
/// We use a single packed struct to ensure contiguous layout.
#[repr(C)]
struct RecvBuffer {
    /// Prepended by FilterGetMessage; NOT sent by the driver.
    flt_header: FILTER_MESSAGE_HEADER,
    /// The actual message sent by the driver via FltSendMessage.
    message: KernelMessage,
}

// ── DriverClient ──────────────────────────────────────────────────────────────

/// Connected client to the ARQENOR kernel driver's filter communication port.
///
/// The handle is cheaply cloneable via `Arc` so it can be moved into the
/// `spawn_blocking` thread used by [`into_event_stream`].
pub struct DriverClient {
    port: Arc<PortHandle>,
}

/// `HANDLE` wrapper that closes the port on drop.
struct PortHandle(HANDLE);

impl Drop for PortHandle {
    fn drop(&mut self) {
        // SAFETY: We own the handle and are the last reference.
        unsafe {
            let _ = CloseHandle(self.0);
        }
    }
}

// SAFETY: HANDLE is effectively a pointer-sized integer; the filter port
// handle is valid to use from any thread.
unsafe impl Send for PortHandle {}
unsafe impl Sync for PortHandle {}

impl DriverClient {
    /// Connect to the `\ArqenorPort` filter communication port.
    ///
    /// Fails with [`ClientError::DriverNotLoaded`] if the driver is not
    /// running (FilterConnectCommunicationPort returns ERROR_FILE_NOT_FOUND
    /// when the port does not exist).
    pub fn connect() -> Result<Self, ClientError> {
        // SAFETY: FFI call; w!() produces a valid null-terminated wide string.
        let handle = unsafe {
            FilterConnectCommunicationPort(
                w!(r"\ArqenorPort"),
                0,
                None,        // no context
                0,
                None,        // no security attributes
            )
        };

        match handle {
            Ok(h) => {
                debug!("Connected to \\ArqenorPort (handle = {h:?})");
                Ok(Self {
                    port: Arc::new(PortHandle(h)),
                })
            }
            Err(e) => {
                if e.code() == windows::core::HRESULT::from(ERROR_FILE_NOT_FOUND) {
                    Err(ClientError::DriverNotLoaded)
                } else {
                    Err(ClientError::ConnectionFailed(e))
                }
            }
        }
    }

    /// Receive the next event from the kernel driver (blocking).
    ///
    /// Allocates a [`RecvBuffer`] on the stack and calls `FilterGetMessage`.
    /// The call blocks until the driver sends a message or the port is closed.
    pub fn recv_blocking(&self) -> Result<KernelEvent, ClientError> {
        // Zero-init the entire buffer (required: FILTER_MESSAGE_HEADER fields
        // must be zeroed before calling FilterGetMessage).
        let mut buf = unsafe { mem::zeroed::<RecvBuffer>() };
        let buf_size = mem::size_of::<RecvBuffer>() as u32;

        // SAFETY:
        // - `self.port.0` is a valid filter port handle.
        // - `buf` is correctly sized and aligned for the receive operation.
        // - `None` for the OVERLAPPED means synchronous (blocking) receive.
        let result = unsafe {
            FilterGetMessage(
                self.port.0,
                &mut buf.flt_header,
                buf_size,
                None, // synchronous
            )
        };

        if let Err(e) = result {
            let code = e.code().0 as u32;
            error!("FilterGetMessage failed: HRESULT {code:#010x}");
            return Err(ClientError::ReceiveError(code));
        }

        // Validate the message size field written by our driver.
        let reported_size = buf.message.header.size as usize;
        let expected_min = mem::size_of::<KernelMessage>();
        if reported_size < expected_min {
            warn!(
                reported_size,
                expected_min,
                "KernelMessage header.size too small — discarding"
            );
            return Err(ClientError::InvalidMessage);
        }

        // SAFETY: `buf.message.event` is fully initialised by FilterGetMessage.
        // The union variant is determined at runtime by `event.kind`.
        let event = unsafe { mem::transmute_copy::<KernelEvent, KernelEvent>(&buf.message.event) };

        Ok(event)
    }

    /// Convert into an async stream of events.
    ///
    /// Each call to the underlying [`recv_blocking`] is executed on Tokio's
    /// blocking thread pool (`spawn_blocking`), keeping the async executor free.
    ///
    /// The stream ends if the port handle is closed or an unrecoverable error
    /// occurs. Transient errors are yielded as `Err` items so the caller can
    /// decide whether to retry.
    pub fn into_event_stream(
        self,
    ) -> impl tokio_stream::Stream<Item = Result<KernelEvent, ClientError>> {
        let port = self.port;

        // Use an async_stream-style approach via tokio + channels.
        let (tx, rx) = tokio::sync::mpsc::channel::<Result<KernelEvent, ClientError>>(64);

        tokio::task::spawn_blocking(move || {
            // Rebuild a lightweight DriverClient wrapper around the shared Arc.
            let client = DriverClient {
                port: Arc::clone(&port),
            };

            loop {
                let result = client.recv_blocking();

                let is_fatal = match &result {
                    // A ReceiveError with STATUS_PORT_DISCONNECTED (0xC000_0332)
                    // means the driver was unloaded — stop the loop.
                    Err(ClientError::ReceiveError(code)) => {
                        const STATUS_PORT_DISCONNECTED: u32 = 0xC000_0332;
                        const STATUS_CANCELLED: u32 = 0xC000_0120;
                        matches!(*code, STATUS_PORT_DISCONNECTED | STATUS_CANCELLED)
                    }
                    _ => false,
                };

                if tx.blocking_send(result).is_err() {
                    // Receiver dropped — shut down quietly.
                    break;
                }

                if is_fatal {
                    debug!("Filter port disconnected — stopping recv loop");
                    break;
                }
            }
        });

        tokio_stream::wrappers::ReceiverStream::new(rx)
    }
}
