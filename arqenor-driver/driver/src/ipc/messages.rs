//! Kernel-side IPC message types.
//!
//! Re-exports `KernelEvent` from `arqenor-driver-common` and provides a
//! fixed-size serialization wrapper suitable for `FltSendMessage`, which
//! cannot use heap-allocated dynamically-sized buffers at IRQL > PASSIVE.

use arqenor_driver_common::KernelEvent;

/// Maximum serialized size of any `KernelEvent` variant.
///
/// FltSendMessage requires a fixed-size output buffer known at call time.
/// All variants must fit within this bound; the common crate enforces this
/// via its own `MAX_EVENT_SIZE` constant which we re-assert here.
pub const MAX_SERIALIZED_EVENT_BYTES: usize = arqenor_driver_common::MAX_EVENT_SIZE;

/// A fixed-size byte buffer that holds one serialized `KernelEvent`.
///
/// The layout on the wire is the raw memory of `KernelEvent` — the usermode
/// agent reads it with the same `#[repr(C)]` definition from the common crate.
/// No length prefix is needed because `FltSendMessage` carries the byte count
/// separately via `SenderBufferLength`.
#[repr(C)]
pub struct EventBuffer {
    pub data: [u8; MAX_SERIALIZED_EVENT_BYTES],
    pub used: u32, // number of valid bytes in `data`
}

impl EventBuffer {
    /// Serialize `event` into a stack-allocated `EventBuffer`.
    ///
    /// Uses a plain `memcopy` of the `#[repr(C)]` struct — no heap allocation,
    /// safe to call at IRQL <= DISPATCH_LEVEL.
    #[inline]
    pub fn from_event(event: &KernelEvent) -> Self {
        // Safety: KernelEvent is repr(C) and plain-old-data. We copy its bytes
        // into a zeroed backing buffer. The size is bounded at compile time.
        let event_size = core::mem::size_of::<KernelEvent>();
        debug_assert!(event_size <= MAX_SERIALIZED_EVENT_BYTES);

        let mut buf = Self {
            data: [0u8; MAX_SERIALIZED_EVENT_BYTES],
            used: event_size as u32,
        };

        // SAFETY: src and dst are non-overlapping, both valid for their sizes.
        unsafe {
            core::ptr::copy_nonoverlapping(
                event as *const KernelEvent as *const u8,
                buf.data.as_mut_ptr(),
                event_size,
            );
        }

        buf
    }
}

pub use arqenor_driver_common::KernelEvent;
