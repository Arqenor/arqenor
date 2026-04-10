//! eBPF program loader (Linux only).
//!
//! Uses `libbpf-rs` to load and attach eBPF programs compiled from the C probes
//! in `src/probes/`. Once attached, ring buffer callbacks forward kernel events
//! to a bounded `tokio::sync::mpsc` channel consumed by the detection pipeline.
//!
//! # Usage
//!
//! ```rust,ignore
//! let (agent, mut rx) = EbpfAgent::start()?;
//! while let Some(event) = rx.recv().await {
//!     // forward to detection engine …
//! }
//! ```

#[cfg(target_os = "linux")]
pub mod linux {
    use std::sync::Arc;
    use anyhow::{Context, Result};
    use tokio::sync::mpsc;

    use crate::events::{
        EbpfEvent, EbpfEventKind,
        ExecveEvent, MmapEvent, PtraceEvent,
        CredsEvent, ModuleEvent, FileWriteEvent,
    };

    // ── Generated skeletons (produced by build.rs via libbpf-cargo) ──────────
    //
    // These includes are commented out because the skeletons are generated at
    // build time on a Linux host. Un-comment and adjust the module names once
    // the build has run at least once on Linux.
    //
    // include!(concat!(env!("OUT_DIR"), "/execve.skel.rs"));
    // include!(concat!(env!("OUT_DIR"), "/memory.skel.rs"));
    // include!(concat!(env!("OUT_DIR"), "/persistence.skel.rs"));
    // include!(concat!(env!("OUT_DIR"), "/privesc.skel.rs"));
    // include!(concat!(env!("OUT_DIR"), "/rootkit.skel.rs"));

    // ── Agent ─────────────────────────────────────────────────────────────────

    /// Owns all loaded eBPF programs and their kernel attachment links.
    ///
    /// Dropping this struct detaches all probes from the kernel.
    pub struct EbpfAgent {
        /// Keeping the links alive keeps the programs attached.
        _links: Vec<libbpf_rs::Link>,
    }

    impl EbpfAgent {
        /// Load and attach all eBPF probes, then start draining ring buffers.
        ///
        /// Returns `(Self, Receiver<EbpfEvent>)`. The caller must drive the
        /// receiver — events are dropped when the channel is full.
        ///
        /// # Errors
        ///
        /// Returns an error if the process lacks `CAP_BPF` / root, or if any
        /// probe fails to load (missing BTF, kernel too old, …).
        pub fn start() -> Result<(Self, mpsc::Receiver<EbpfEvent>)> {
            let (tx, rx) = mpsc::channel::<EbpfEvent>(4096);
            let _tx = Arc::new(tx);

            let links: Vec<libbpf_rs::Link> = Vec::new();

            // ── Phase 2 TODO: load each skeleton and attach programs ──────────
            //
            // Pattern for every probe (shown for execve):
            //
            //   let mut skel = ExecveSkelBuilder::default()
            //       .open()
            //       .context("open execve skeleton")?
            //       .load()
            //       .context("load execve skeleton")?;
            //
            //   let link = skel
            //       .progs_mut()
            //       .handle_execve()
            //       .attach_tracepoint("syscalls", "sys_enter_execve")
            //       .context("attach execve tracepoint")?;
            //   links.push(link);
            //
            //   // Spawn ring-buffer drain task
            //   let tx_clone = Arc::clone(&_tx);
            //   let map_fd  = skel.maps().execve_events().as_fd();
            //   tokio::task::spawn_blocking(move || {
            //       drain_execve(map_fd, tx_clone);
            //   });
            //
            // Repeat for memory, persistence, privesc, rootkit.
            // ─────────────────────────────────────────────────────────────────

            tracing::info!(
                probes = links.len(),
                "eBPF agent started — probes attached"
            );

            Ok((Self { _links: links }, rx))
        }
    }

    // ── Ring buffer drain helpers ─────────────────────────────────────────────

    /// Convert a null-terminated C byte slice to an owned `String`.
    ///
    /// Stops at the first `NUL` byte; falls back to lossy UTF-8 for non-ASCII
    /// kernel strings (e.g. filenames with non-UTF bytes).
    pub fn cstr_to_string(bytes: &[u8]) -> String {
        let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
        String::from_utf8_lossy(&bytes[..end]).into_owned()
    }

    /// Construct an [`EbpfEvent`] from a raw [`ExecveEvent`] ring-buffer sample.
    pub fn execve_to_event(raw: &ExecveEvent) -> EbpfEvent {
        EbpfEvent {
            kind:         EbpfEventKind::ProcessExec,
            pid:          raw.pid,
            ppid:         raw.ppid,
            uid:          raw.uid,
            comm:         cstr_to_string(&raw.comm),
            filename:     Some(cstr_to_string(&raw.filename)),
            extra:        Some(cstr_to_string(&raw.argv0)),
            timestamp_ns: raw.ts_ns,
        }
    }

    /// Construct an [`EbpfEvent`] from a raw [`MmapEvent`] ring-buffer sample.
    pub fn mmap_to_event(raw: &MmapEvent) -> EbpfEvent {
        EbpfEvent {
            kind:         EbpfEventKind::MemoryRwxMap,
            pid:          raw.pid,
            ppid:         raw.ppid,
            uid:          raw.uid,
            comm:         cstr_to_string(&raw.comm),
            filename:     None,
            extra:        Some(format!(
                "addr=0x{:x} len={} prot=0x{:x} flags=0x{:x}",
                raw.addr, raw.len, raw.prot, raw.flags
            )),
            timestamp_ns: raw.ts_ns,
        }
    }

    /// Construct an [`EbpfEvent`] from a raw [`PtraceEvent`] ring-buffer sample.
    pub fn ptrace_to_event(raw: &PtraceEvent) -> EbpfEvent {
        EbpfEvent {
            kind:         EbpfEventKind::PtraceAttach,
            pid:          raw.pid,
            ppid:         raw.ppid,
            uid:          raw.uid,
            comm:         cstr_to_string(&raw.comm),
            filename:     None,
            extra:        Some(format!(
                "request={} target_pid={}",
                raw.request, raw.target_pid
            )),
            timestamp_ns: raw.ts_ns,
        }
    }

    /// Construct an [`EbpfEvent`] from a raw [`CredsEvent`] ring-buffer sample.
    pub fn creds_to_event(raw: &CredsEvent) -> EbpfEvent {
        EbpfEvent {
            kind:         EbpfEventKind::CommitCredsEscalation,
            pid:          raw.pid,
            ppid:         raw.ppid,
            uid:          raw.old_uid,
            comm:         cstr_to_string(&raw.comm),
            filename:     None,
            extra:        Some(format!(
                "old_uid={} new_uid={}",
                raw.old_uid, raw.new_uid
            )),
            timestamp_ns: raw.ts_ns,
        }
    }

    /// Construct an [`EbpfEvent`] from a raw [`ModuleEvent`] ring-buffer sample.
    pub fn module_to_event(raw: &ModuleEvent) -> EbpfEvent {
        EbpfEvent {
            kind:         EbpfEventKind::KernelModuleLoad,
            pid:          raw.pid,
            ppid:         0, // not captured in this probe
            uid:          0, // not captured in this probe
            comm:         cstr_to_string(&raw.comm),
            filename:     Some(cstr_to_string(&raw.name)),
            extra:        None,
            timestamp_ns: raw.ts_ns,
        }
    }

    /// Construct an [`EbpfEvent`] from a raw [`FileWriteEvent`] ring-buffer sample.
    ///
    /// The event kind is inferred from the filename prefix:
    /// `/etc/ld` → [`EbpfEventKind::LdPreloadWrite`],
    /// `/etc/cr` → [`EbpfEventKind::CronWrite`].
    pub fn file_write_to_event(raw: &FileWriteEvent) -> EbpfEvent {
        let filename = cstr_to_string(&raw.filename);

        let kind = if filename.starts_with("/etc/ld") {
            EbpfEventKind::LdPreloadWrite
        } else {
            EbpfEventKind::CronWrite
        };

        EbpfEvent {
            kind,
            pid:          raw.pid,
            ppid:         raw.ppid,
            uid:          raw.uid,
            comm:         cstr_to_string(&raw.comm),
            filename:     Some(filename),
            extra:        None,
            timestamp_ns: raw.ts_ns,
        }
    }
}
