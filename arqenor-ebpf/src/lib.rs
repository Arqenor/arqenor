//! arqenor-ebpf — Linux eBPF kernel telemetry agent.
//!
//! Provides real-time kernel-level detection via eBPF tracepoints and kprobes:
//!
//!   - **B2** — `execve`/`execveat` tracepoint → process execution (T1059)
//!   - **B3** — `do_mmap` kprobe (RWX anonymous pages) + `sys_enter_ptrace`
//!     tracepoint → memory injection (T1055, T1055.008)
//!   - **B4** — `sys_enter_openat` tracepoint on `/etc/ld.so.preload` and
//!     `/etc/cron*` → persistence (T1574.006, T1053.003)
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

// Loader has two implementations selected by `build.rs`:
//
// - `loader.rs` — real `libbpf-rs` skeleton load + attach. Compiled when the
//   build script could find BTF + bpftool and successfully generated the
//   per-probe `.skel.rs` files in `OUT_DIR`.
// - `loader_stub.rs` — no-op API-compatible stub. Compiled when build.rs is
//   invoked with `SKIP_EBPF=1` (CI runners that lack BTF). Exposes the same
//   `loader::linux::EbpfAgent` symbol so downstream crates need no `cfg`.
//
// `build.rs` emits the `ebpf_stubs` cfg via `cargo:rustc-cfg=ebpf_stubs`
// (and declares it via `cargo:rustc-check-cfg` to avoid rustc 1.80+ warnings).

#[cfg(all(target_os = "linux", not(ebpf_stubs)))]
pub mod loader;

#[cfg(all(target_os = "linux", ebpf_stubs))]
#[path = "loader_stub.rs"]
pub mod loader;

/// Re-export the agent entry-point on Linux.
#[cfg(target_os = "linux")]
pub use loader::linux::EbpfAgent;

/// Re-export the generic event type for use by downstream crates on all platforms.
pub use events::EbpfEvent;
