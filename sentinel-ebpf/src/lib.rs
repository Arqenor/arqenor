//! sentinel-ebpf — Linux eBPF kernel telemetry agent.
//!
//! Provides real-time kernel-level detection via eBPF tracepoints and kprobes:
//!
//!   - **B2** — `execve`/`execveat` tracepoint → process execution (T1059)
//!   - **B3** — `do_mmap` kprobe (RWX anonymous pages) + `sys_enter_ptrace`
//!              tracepoint → memory injection (T1055, T1055.008)
//!   - **B4** — `sys_enter_openat` tracepoint on `/etc/ld.so.preload` and
//!              `/etc/cron*` → persistence (T1574.006, T1053.003)
//!   - **B5** — `commit_creds` kprobe → uid 0 escalation (T1068)
//!   - **B6** — `do_init_module` kprobe → kernel module load / rootkit (T1014)
//!
//! # Privileges
//!
//! Loading eBPF programs requires **`CAP_BPF`** (Linux 5.8+) or root.
//! The agent will return an error at startup if the capability is absent.
//!
//! # Platform
//!
//! This crate is **Linux-only**. On other targets the public surface is reduced
//! to the shared [`events`] module (event types are still usable for IPC /
//! serialisation).

pub mod events;

#[cfg(target_os = "linux")]
pub mod loader;

/// Re-export the agent entry-point on Linux.
#[cfg(target_os = "linux")]
pub use loader::linux::EbpfAgent;

/// Re-export the generic event type for use by downstream crates on all platforms.
pub use events::EbpfEvent;
