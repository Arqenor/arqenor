//! Shared event types between eBPF C probes and the Rust userspace loader.
//!
//! All `repr(C)` structs mirror their counterparts in the `.bpf.c` probe files
//! and are consumed directly from BPF ring buffers — field order and sizes must
//! stay in sync with the C definitions.

use serde::Serialize;

// ── High-level tagged event (emitted to the detection pipeline) ──────────────

/// Discriminant for events produced by the eBPF agent.
#[derive(Debug, Clone, Serialize)]
pub enum EbpfEventKind {
    /// B2 — Process execution via execve/execveat (T1059)
    ProcessExec,
    /// B3 — Anonymous RWX mmap (shellcode injection) (T1055)
    MemoryRwxMap,
    /// B3 — ptrace attach to a foreign process (T1055.008)
    PtraceAttach,
    /// B4 — Write to /etc/ld.so.preload (T1574.006)
    LdPreloadWrite,
    /// B4 — Write to /etc/cron.d/ or /etc/crontab (T1053.003)
    CronWrite,
    /// B5 — commit_creds escalation to uid 0 (T1068)
    CommitCredsEscalation,
    /// B6 — Kernel module loaded via insmod/modprobe (T1014)
    KernelModuleLoad,
}

/// Generic event forwarded from the eBPF loader to the detection pipeline.
///
/// All probe-specific data is normalised into this struct so that downstream
/// detectors do not need to know which probe produced the event.
#[derive(Debug, Clone, Serialize)]
pub struct EbpfEvent {
    /// Event category.
    pub kind: EbpfEventKind,
    /// PID of the process that triggered the event.
    pub pid: u32,
    /// Parent PID.
    pub ppid: u32,
    /// Effective UID of the triggering process.
    pub uid: u32,
    /// Process name (up to 16 bytes, kernel `comm` field).
    pub comm: String,
    /// Path or file name associated with the event, if applicable.
    pub filename: Option<String>,
    /// Extra context (argv[0], mmap flags, ptrace request code, …).
    pub extra: Option<String>,
    /// Kernel monotonic timestamp from `bpf_ktime_get_ns()`.
    pub timestamp_ns: u64,
}

// ── repr(C) structs — must mirror the C structs in each .bpf.c file ─────────

/// Mirrors `struct execve_event` in `execve.bpf.c`.
/// Emitted from the `sys_enter_execve` tracepoint (B2).
#[repr(C)]
pub struct ExecveEvent {
    pub pid:      u32,
    pub ppid:     u32,
    pub uid:      u32,
    pub comm:     [u8; 16],
    pub filename: [u8; 256],
    pub argv0:    [u8; 128],
    pub ts_ns:    u64,
}

/// Mirrors `struct mmap_event` in `memory.bpf.c`.
/// Emitted from the `do_mmap` kprobe when prot == RWX and mapping is anonymous (B3).
#[repr(C)]
pub struct MmapEvent {
    pub pid:   u32,
    pub ppid:  u32,
    pub uid:   u32,
    pub comm:  [u8; 16],
    pub addr:  u64,
    pub len:   u64,
    pub prot:  u32, // PROT_READ | PROT_WRITE | PROT_EXEC
    pub flags: u32,
    pub ts_ns: u64,
}

/// Mirrors `struct ptrace_event` in `memory.bpf.c`.
/// Emitted from the `sys_enter_ptrace` tracepoint when attaching to a foreign PID (B3).
#[repr(C)]
pub struct PtraceEvent {
    pub pid:        u32,
    pub ppid:       u32,
    pub uid:        u32,
    pub comm:       [u8; 16],
    pub request:    u64, // PTRACE_ATTACH, PTRACE_PEEKDATA, …
    pub target_pid: u64,
    pub ts_ns:      u64,
}

/// Mirrors `struct creds_event` in `privesc.bpf.c`.
/// Emitted from the `commit_creds` kprobe on uid → 0 transitions (B5).
#[repr(C)]
pub struct CredsEvent {
    pub pid:     u32,
    pub ppid:    u32,
    pub old_uid: u32,
    pub new_uid: u32,
    pub comm:    [u8; 16],
    pub ts_ns:   u64,
}

/// Mirrors `struct module_event` in `rootkit.bpf.c`.
/// Emitted from the `do_init_module` kprobe on every insmod/modprobe (B6).
#[repr(C)]
pub struct ModuleEvent {
    pub pid:   u32,
    pub comm:  [u8; 16],
    pub name:  [u8; 64],
    pub ts_ns: u64,
}

/// Mirrors `struct file_write_event` in `persistence.bpf.c`.
/// Emitted from the `sys_enter_openat` tracepoint for sensitive paths (B4).
#[repr(C)]
pub struct FileWriteEvent {
    pub pid:      u32,
    pub ppid:     u32,
    pub uid:      u32,
    pub comm:     [u8; 16],
    pub filename: [u8; 256],
    pub ts_ns:    u64,
}
