#![no_std]

// Allow std-dependent derives when building for userspace
#[cfg(feature = "std")]
extern crate std;

// ── Size constants (buffer lengths in u16 elements) ───────────────────────────

/// Maximum length of NT image paths stored in process create events.
pub const MAX_PATH_CHARS: usize = 256;
/// Maximum command-line length.
pub const MAX_CMDLINE_CHARS: usize = 512;
/// Maximum registry key path length.
pub const MAX_REG_PATH_CHARS: usize = 256;
/// Maximum registry value name length.
pub const MAX_REG_VALUE_CHARS: usize = 128;
/// Maximum file path length for file events (source and destination).
pub const MAX_FILE_PATH_CHARS: usize = 256;

// ── Size derivation (all in bytes) ───────────────────────────────────────────
//
//  ProcessCreateEvent:
//    pid(4) + ppid(4) + creating_pid(4) + _pad(4) + timestamp(8)
//    + image_path([u16;256] = 512) + cmdline([u16;512] = 1024)
//    = 24 + 512 + 1024 = 1560  ← largest variant
//
//  ProcessTerminateEvent:
//    pid(4) + _pad(4) + timestamp(8) = 16
//
//  FileEvent:
//    pid(4) + _pad(4) + timestamp(8)
//    + path([u16;256] = 512) + new_path([u16;256] = 512)
//    = 16 + 1024 = 1040
//
//  RegistryEvent:
//    pid(4) + _pad(4) + timestamp(8)
//    + key_path([u16;256] = 512) + value_name([u16;128] = 256)
//    = 16 + 768 = 784
//
//  All variants are padded to PAYLOAD_SIZE = 1560 via the union's _pad field.

/// Byte size every `KernelEventPayload` variant must occupy.
pub const PAYLOAD_SIZE: usize = 1560;

/// Discriminant for all kernel events.
/// Must fit in a u32 for C ABI compatibility.
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KernelEventKind {
    ProcessCreate     = 1,
    ProcessTerminate  = 2,
    FileCreate        = 3,
    FileWrite         = 4,
    FileRename        = 5,
    FileDelete        = 6,
    RegistrySetValue  = 7,
    RegistryCreateKey = 8,
    RegistryDeleteKey = 9,
}

/// Fixed-size envelope sent over the FltSendMessage / FilterGetMessage channel.
/// The `kind` discriminant selects which union variant is active.
///
/// Fixed-size layout is required because FltSendMessage copies a contiguous
/// buffer — variable-length messages require multiple round trips.
#[repr(C)]
pub struct KernelEvent {
    pub kind:    KernelEventKind,
    /// Explicit padding to align `payload` to 8 bytes.
    pub padding: [u8; 4],
    pub payload: KernelEventPayload,
}

/// Union of all event payloads. The active variant is determined by
/// `KernelEvent.kind`. The `_pad` field forces every variant to occupy
/// exactly `PAYLOAD_SIZE` bytes so `KernelEvent` is a fixed-size struct
/// suitable for a single `FltSendMessage` call.
#[repr(C)]
pub union KernelEventPayload {
    pub process_create:    ProcessCreateEvent,
    pub process_terminate: ProcessTerminateEvent,
    pub file:              FileEvent,
    pub registry:          RegistryEvent,
    /// Padding: guarantees the union is exactly PAYLOAD_SIZE bytes.
    _pad: [u8; PAYLOAD_SIZE],
}

// ── Process events ────────────────────────────────────────────────────────────

/// Emitted when a new process is created (PsSetCreateProcessNotifyRoutineEx).
/// ATT&CK: T1059, T1106, T1203, T1055 (parent-child anomaly correlation)
///
/// Layout: 1560 bytes.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct ProcessCreateEvent {
    /// PID of the new process.
    pub pid:          u32,
    /// Parent PID (from PS_CREATE_NOTIFY_INFO.ParentProcessId).
    pub ppid:         u32,
    /// Creating thread's TID PID (may differ from ppid for injection detection).
    pub creating_pid: u32,
    pub _pad:         u32,
    /// Kernel monotonic timestamp in 100ns intervals (KeQuerySystemTime).
    pub timestamp:    u64,
    /// NT path of the image (e.g. \Device\HarddiskVolume3\Windows\System32\cmd.exe).
    /// UTF-16LE, null-terminated, zero-padded.
    pub image_path:   [u16; MAX_PATH_CHARS],   // 256 × 2 = 512 bytes
    /// Command line arguments, UTF-16LE. May be all-zero if unavailable.
    pub cmdline:      [u16; MAX_CMDLINE_CHARS], // 512 × 2 = 1024 bytes
    // Total: 4+4+4+4+8 + 512 + 1024 = 1560 bytes
}

/// Emitted when a process exits (create_info == NULL in notify callback).
///
/// Layout: 16 bytes (padded to PAYLOAD_SIZE by the union).
#[repr(C)]
#[derive(Clone, Copy)]
pub struct ProcessTerminateEvent {
    pub pid:       u32,
    pub _pad:      u32,
    pub timestamp: u64,
}

// ── File events ───────────────────────────────────────────────────────────────

/// Emitted by the minifilter for file create, write, rename, and delete.
/// ATT&CK: T1565.001, T1005, T1027, T1486
///
/// Layout: 1040 bytes (padded to PAYLOAD_SIZE by the union).
#[repr(C)]
#[derive(Clone, Copy)]
pub struct FileEvent {
    pub pid:       u32,
    pub _pad:      u32,
    pub timestamp: u64,
    /// Full normalized NT path of the target file.
    pub path:      [u16; MAX_FILE_PATH_CHARS], // 256 × 2 = 512 bytes
    /// For renames: new path. For other operations: zero-filled.
    pub new_path:  [u16; MAX_FILE_PATH_CHARS], // 256 × 2 = 512 bytes
    // Total: 4+4+8 + 512 + 512 = 1040 bytes
}

// ── Registry events ───────────────────────────────────────────────────────────

/// Emitted by CmRegisterCallbackEx for key/value operations.
/// ATT&CK: T1112, T1547.001, T1574.011
///
/// Layout: 784 bytes (padded to PAYLOAD_SIZE by the union).
#[repr(C)]
#[derive(Clone, Copy)]
pub struct RegistryEvent {
    pub pid:        u32,
    pub _pad:       u32,
    pub timestamp:  u64,
    /// Full registry key path (e.g. \Registry\Machine\SOFTWARE\...).
    pub key_path:   [u16; MAX_REG_PATH_CHARS],   // 256 × 2 = 512 bytes
    /// Value name (for SetValue events). Zero for key-level events.
    pub value_name: [u16; MAX_REG_VALUE_CHARS],  // 128 × 2 = 256 bytes
    // Total: 4+4+8 + 512 + 256 = 784 bytes
}

// ── IPC message header for FilterGetMessage ───────────────────────────────────

/// Header prepended to every message sent via FltSendMessage.
/// FilterGetMessage on the userspace side receives this struct.
#[repr(C)]
pub struct MessageHeader {
    /// Total message size in bytes (header + event).
    pub size:     u32,
    /// Sequence number for ordering / loss detection.
    pub sequence: u32,
}

/// Full message as seen by FilterGetMessage on the userspace side.
#[repr(C)]
pub struct KernelMessage {
    pub header: MessageHeader,
    pub event:  KernelEvent,
}

// ── Compile-time size assertions ──────────────────────────────────────────────

const _ASSERT_PROCESS_CREATE_SIZE: () = assert!(
    core::mem::size_of::<ProcessCreateEvent>() == PAYLOAD_SIZE,
    "ProcessCreateEvent must be exactly PAYLOAD_SIZE bytes"
);

const _ASSERT_PAYLOAD_SIZE: () = assert!(
    core::mem::size_of::<KernelEventPayload>() == PAYLOAD_SIZE,
    "KernelEventPayload must be exactly PAYLOAD_SIZE bytes"
);

const _ASSERT_PROCESS_TERMINATE_FITS: () = assert!(
    core::mem::size_of::<ProcessTerminateEvent>() <= PAYLOAD_SIZE,
    "ProcessTerminateEvent exceeds PAYLOAD_SIZE"
);

const _ASSERT_FILE_EVENT_FITS: () = assert!(
    core::mem::size_of::<FileEvent>() <= PAYLOAD_SIZE,
    "FileEvent exceeds PAYLOAD_SIZE"
);

const _ASSERT_REGISTRY_EVENT_FITS: () = assert!(
    core::mem::size_of::<RegistryEvent>() <= PAYLOAD_SIZE,
    "RegistryEvent exceeds PAYLOAD_SIZE"
);

// ── Helper: copy a UNICODE_STRING slice into a fixed [u16; N] buffer ──────────

/// Copy up to `dst.len() - 1` UTF-16 code units from `src` into `dst`,
/// then null-terminate. Used by kernel-side callbacks to fill event path fields
/// from a `UNICODE_STRING`.
#[inline]
pub fn copy_unicode(src: &[u16], dst: &mut [u16]) {
    let len = src.len().min(dst.len().saturating_sub(1));
    dst[..len].copy_from_slice(&src[..len]);
    dst[len] = 0;
}
