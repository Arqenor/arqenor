//! eBPF program loader (Linux only).
//!
//! Uses [`libbpf-rs`](https://docs.rs/libbpf-rs/0.24/libbpf_rs/) to load and
//! attach the eBPF programs compiled from the C probes in `src/probes/`. Once
//! attached, ring-buffer callbacks decode raw kernel samples into [`EbpfEvent`]
//! values and forward them on a bounded `tokio::sync::mpsc` channel consumed
//! by the detection pipeline.
//!
//! # Usage
//!
//! ```rust,ignore
//! let (agent, mut rx) = EbpfAgent::start()?;
//! while let Some(event) = rx.recv().await {
//!     // forward to detection engine …
//! }
//! ```
//!
//! # Privileges
//!
//! Loading eBPF programs requires `CAP_BPF` (Linux 5.8+) or root. Older
//! kernels still need full `CAP_SYS_ADMIN`. The agent surfaces that as
//! [`EbpfLoadError::SkelLoad`] (libbpf maps EPERM to a load failure).
//!
//! # Failure model
//!
//! `EbpfAgent::start` is *best-effort*: each probe is loaded independently
//! and a failure on one probe (missing kprobe symbol on the running kernel,
//! verifier rejection, …) is logged via `tracing::warn!` and skipped — the
//! agent still returns successfully with whatever subset of probes attached
//! cleanly. If **every** probe fails, the call still succeeds with an empty
//! `links` vector and an open (but never-fed) receiver; callers that want a
//! hard failure should check `agent.attached_probes()`.

#[cfg(target_os = "linux")]
pub mod linux {
    use std::mem::MaybeUninit;
    use std::sync::Arc;
    use std::time::Duration;

    use libbpf_rs::skel::{OpenSkel, Skel, SkelBuilder};
    use libbpf_rs::{OpenObject, RingBufferBuilder};
    use thiserror::Error;
    use tokio::sync::mpsc;

    use crate::events::{
        CredsEvent, EbpfEvent, ExecveEvent, FileWriteEvent, MmapEvent, ModuleEvent, PtraceEvent,
    };

    // ── Generated skeletons ───────────────────────────────────────────────
    //
    // `libbpf-cargo`'s `SkeletonBuilder::build_and_generate` emits a Rust file
    // per probe under `$OUT_DIR`. Each file declares a top-level module that
    // exposes `<Probe>SkelBuilder`, `Open<Probe>Skel`, `<Probe>Skel` and a
    // generated `<Probe>Maps` accessor. We pull them in here so they are
    // visible to the loader code below.
    //
    // The `include!` directive embeds the file as if it were typed inline,
    // so the generated `mod execve_bpf { … }` becomes a sibling of the rest
    // of this module's items.
    //
    // NOTE — this only compiles on Linux *after* `build.rs` has run at least
    // once. If you see "file not found", run `cargo build` to trigger the
    // build script.

    #[allow(
        clippy::all,
        dead_code,
        non_camel_case_types,
        non_snake_case,
        non_upper_case_globals,
        unused_imports,
        unused_qualifications
    )]
    mod skel_execve {
        include!(concat!(env!("OUT_DIR"), "/execve.skel.rs"));
    }
    #[allow(
        clippy::all,
        dead_code,
        non_camel_case_types,
        non_snake_case,
        non_upper_case_globals,
        unused_imports,
        unused_qualifications
    )]
    mod skel_memory {
        include!(concat!(env!("OUT_DIR"), "/memory.skel.rs"));
    }
    #[allow(
        clippy::all,
        dead_code,
        non_camel_case_types,
        non_snake_case,
        non_upper_case_globals,
        unused_imports,
        unused_qualifications
    )]
    mod skel_persistence {
        include!(concat!(env!("OUT_DIR"), "/persistence.skel.rs"));
    }
    #[allow(
        clippy::all,
        dead_code,
        non_camel_case_types,
        non_snake_case,
        non_upper_case_globals,
        unused_imports,
        unused_qualifications
    )]
    mod skel_privesc {
        include!(concat!(env!("OUT_DIR"), "/privesc.skel.rs"));
    }
    #[allow(
        clippy::all,
        dead_code,
        non_camel_case_types,
        non_snake_case,
        non_upper_case_globals,
        unused_imports,
        unused_qualifications
    )]
    mod skel_rootkit {
        include!(concat!(env!("OUT_DIR"), "/rootkit.skel.rs"));
    }

    use skel_execve::*;
    use skel_memory::*;
    use skel_persistence::*;
    use skel_privesc::*;
    use skel_rootkit::*;

    // ── Errors ────────────────────────────────────────────────────────────

    /// Errors returned by [`EbpfAgent::start`].
    #[derive(Debug, Error)]
    pub enum EbpfLoadError {
        #[error("failed to open eBPF skeleton for probe `{probe}`: {source}")]
        SkelOpen {
            probe: &'static str,
            #[source]
            source: libbpf_rs::Error,
        },
        #[error(
            "failed to load eBPF skeleton for probe `{probe}` \
             (missing CAP_BPF/CAP_SYS_ADMIN, kernel too old, or verifier rejection?): {source}"
        )]
        SkelLoad {
            probe: &'static str,
            #[source]
            source: libbpf_rs::Error,
        },
        #[error("failed to attach eBPF program `{prog}` (probe `{probe}`): {source}")]
        Attach {
            probe: &'static str,
            prog: &'static str,
            #[source]
            source: libbpf_rs::Error,
        },
        #[error("failed to build ring buffer for probe `{probe}`: {source}")]
        RingBuffer {
            probe: &'static str,
            #[source]
            source: libbpf_rs::Error,
        },
    }

    // ── Agent ─────────────────────────────────────────────────────────────

    /// Tracks which eBPF probes were successfully attached.
    ///
    /// Programs and their auto-attached `Link`s live inside the leaked
    /// skeletons (see the per-probe attach helpers). This struct exists only
    /// to expose the count of live probes to callers that want to assert at
    /// least one probe is running.
    ///
    /// Dropping this struct does **not** detach the probes — the leaked
    /// skeletons keep them attached for the lifetime of the process. That is
    /// intentional for a long-lived security agent.
    pub struct EbpfAgent {
        /// Number of probes that successfully loaded *and* attached.
        attached_probes: usize,
    }

    impl EbpfAgent {
        /// Number of probes that successfully attached.
        pub fn attached_probes(&self) -> usize {
            self.attached_probes
        }

        /// Load and attach all eBPF probes, then start draining ring buffers.
        ///
        /// Returns `(Self, Receiver<EbpfEvent>)`. The caller must drive the
        /// receiver — events are dropped silently when the channel is full
        /// (back-pressure on the kernel side is preferred over blocking the
        /// drain task).
        ///
        /// Probes are loaded best-effort: an error on one probe is logged and
        /// skipped rather than aborting the whole agent. See module-level docs.
        pub fn start() -> Result<(Self, mpsc::Receiver<EbpfEvent>), EbpfLoadError> {
            let (tx, rx) = mpsc::channel::<EbpfEvent>(4096);
            let tx = Arc::new(tx);

            let mut attached: usize = 0;

            // ── B2 — execve / execveat ────────────────────────────────────
            match attach_execve(Arc::clone(&tx)) {
                Ok(()) => {
                    attached += 1;
                    tracing::info!("eBPF probe attached: execve");
                }
                Err(e) => tracing::warn!(error = %e, "eBPF probe failed: execve — skipping"),
            }

            // ── B3 — do_mmap (RWX) + ptrace ──────────────────────────────
            match attach_memory(Arc::clone(&tx)) {
                Ok(()) => {
                    attached += 1;
                    tracing::info!("eBPF probe attached: memory");
                }
                Err(e) => tracing::warn!(error = %e, "eBPF probe failed: memory — skipping"),
            }

            // ── B4 — sys_enter_openat on /etc/ld* and /etc/cr* ───────────
            match attach_persistence(Arc::clone(&tx)) {
                Ok(()) => {
                    attached += 1;
                    tracing::info!("eBPF probe attached: persistence");
                }
                Err(e) => {
                    tracing::warn!(error = %e, "eBPF probe failed: persistence — skipping")
                }
            }

            // ── B5 — commit_creds (uid → 0) ──────────────────────────────
            match attach_privesc(Arc::clone(&tx)) {
                Ok(()) => {
                    attached += 1;
                    tracing::info!("eBPF probe attached: privesc");
                }
                Err(e) => tracing::warn!(error = %e, "eBPF probe failed: privesc — skipping"),
            }

            // ── B6 — do_init_module ──────────────────────────────────────
            match attach_rootkit(Arc::clone(&tx)) {
                Ok(()) => {
                    attached += 1;
                    tracing::info!("eBPF probe attached: rootkit");
                }
                Err(e) => tracing::warn!(error = %e, "eBPF probe failed: rootkit — skipping"),
            }

            tracing::info!(probes_attached = attached, "eBPF agent started");

            Ok((
                Self {
                    attached_probes: attached,
                },
                rx,
            ))
        }
    }

    // ── Internal: send-or-warn helper ─────────────────────────────────────
    //
    // `try_send` is non-blocking and returns Err(Full) when the bounded
    // channel is saturated. Silently dropping kernel events is exactly the
    // failure mode an attacker would benefit from, so we warn loudly.
    // `tracing` rate-limiting is the user's responsibility via subscriber
    // config — we surface the signal honestly.
    fn try_send_event(probe: &'static str, tx: &mpsc::Sender<EbpfEvent>, event: EbpfEvent) {
        match tx.try_send(event) {
            Ok(()) => {}
            Err(mpsc::error::TrySendError::Full(_)) => {
                tracing::warn!(probe, "eBPF event dropped — channel full");
            }
            Err(mpsc::error::TrySendError::Closed(_)) => {
                // Receiver gone: caller has shut down the consumer. Stop
                // logging — every subsequent event will hit this branch.
                tracing::debug!(probe, "eBPF event dropped — receiver closed");
            }
        }
    }

    // ── Per-probe attach helpers ──────────────────────────────────────────
    //
    // Each helper:
    //   1. Allocates a `MaybeUninit<OpenObject>` on the heap and leaks it so
    //      the skeleton's `'obj` lifetime is `'static`. In libbpf-rs 0.24
    //      `SkelBuilder::open(&mut MaybeUninit<OpenObject>)` ties the skel's
    //      lifetime to the OpenObject — leaking the OpenObject is what makes
    //      the subsequent `Box::leak(skel)` sound.
    //   2. Loads the skeleton (returning typed errors).
    //   3. Auto-attaches every program declared in the skeleton via its
    //      `SEC()` annotation (`Skel::attach()` honours all of them).
    //   4. Builds a `RingBufferBuilder` over the probe's ring map(s) using
    //      direct field access (`skel.maps.<name>` — libbpf-cargo 0.24 emits
    //      `pub maps: <Probe>Maps`, not a method).
    //   5. Leaks the loaded skeleton with `Box::leak` so the auto-attached
    //      links stay alive for the lifetime of the process — `Skel::attach`
    //      stores `Link`s inside the skeleton itself.
    //   6. Spawns a `tokio::task::spawn_blocking` drain task that polls the
    //      ring buffer and forwards decoded events on `tx`.

    /// Attach the B2 execve / execveat probes.
    fn attach_execve(tx: Arc<mpsc::Sender<EbpfEvent>>) -> Result<(), EbpfLoadError> {
        let open_object: &'static mut MaybeUninit<OpenObject> =
            Box::leak(Box::new(MaybeUninit::uninit()));

        let open_skel = ExecveSkelBuilder::default()
            .open(open_object)
            .map_err(|source| EbpfLoadError::SkelOpen {
                probe: "execve",
                source,
            })?;
        let mut skel = open_skel.load().map_err(|source| EbpfLoadError::SkelLoad {
            probe: "execve",
            source,
        })?;

        // Auto-attach `handle_execve` + `handle_execveat` via SEC() annotations.
        skel.attach().map_err(|source| EbpfLoadError::Attach {
            probe: "execve",
            prog: "*",
            source,
        })?;

        let tx_drain = Arc::clone(&tx);
        let mut rb = RingBufferBuilder::new();
        rb.add(&skel.maps.execve_events, move |data: &[u8]| {
            if let Some(raw) = parse_sample::<ExecveEvent>(data) {
                try_send_event("execve", &tx_drain, super::execve_to_event(&raw));
            }
            0
        })
        .map_err(|source| EbpfLoadError::RingBuffer {
            probe: "execve",
            source,
        })?;
        let rb = rb.build().map_err(|source| EbpfLoadError::RingBuffer {
            probe: "execve",
            source,
        })?;

        // Skel owns the auto-attached links — keep it alive for the process
        // lifetime. open_object is already 'static (leaked above).
        let _skel: &'static mut ExecveSkel<'static> = Box::leak(Box::new(skel));

        tokio::task::spawn_blocking(move || drain_ring_buffer("execve", rb));

        Ok(())
    }

    /// Attach the B3 memory probes (do_mmap RWX + sys_enter_ptrace).
    fn attach_memory(tx: Arc<mpsc::Sender<EbpfEvent>>) -> Result<(), EbpfLoadError> {
        let open_object: &'static mut MaybeUninit<OpenObject> =
            Box::leak(Box::new(MaybeUninit::uninit()));

        let open_skel = MemorySkelBuilder::default()
            .open(open_object)
            .map_err(|source| EbpfLoadError::SkelOpen {
                probe: "memory",
                source,
            })?;
        let mut skel = open_skel.load().map_err(|source| EbpfLoadError::SkelLoad {
            probe: "memory",
            source,
        })?;

        skel.attach().map_err(|source| EbpfLoadError::Attach {
            probe: "memory",
            prog: "*",
            source,
        })?;

        let mut rb = RingBufferBuilder::new();
        let tx_mmap = Arc::clone(&tx);
        rb.add(&skel.maps.mmap_events, move |data: &[u8]| {
            if let Some(raw) = parse_sample::<MmapEvent>(data) {
                try_send_event("memory", &tx_mmap, super::mmap_to_event(&raw));
            }
            0
        })
        .map_err(|source| EbpfLoadError::RingBuffer {
            probe: "memory",
            source,
        })?;
        let tx_ptrace = Arc::clone(&tx);
        rb.add(&skel.maps.ptrace_events, move |data: &[u8]| {
            if let Some(raw) = parse_sample::<PtraceEvent>(data) {
                try_send_event("memory", &tx_ptrace, super::ptrace_to_event(&raw));
            }
            0
        })
        .map_err(|source| EbpfLoadError::RingBuffer {
            probe: "memory",
            source,
        })?;
        let rb = rb.build().map_err(|source| EbpfLoadError::RingBuffer {
            probe: "memory",
            source,
        })?;

        let _skel: &'static mut MemorySkel<'static> = Box::leak(Box::new(skel));

        tokio::task::spawn_blocking(move || drain_ring_buffer("memory", rb));

        Ok(())
    }

    /// Attach the B4 persistence probe (sys_enter_openat).
    fn attach_persistence(tx: Arc<mpsc::Sender<EbpfEvent>>) -> Result<(), EbpfLoadError> {
        let open_object: &'static mut MaybeUninit<OpenObject> =
            Box::leak(Box::new(MaybeUninit::uninit()));

        let open_skel = PersistenceSkelBuilder::default()
            .open(open_object)
            .map_err(|source| EbpfLoadError::SkelOpen {
                probe: "persistence",
                source,
            })?;
        let mut skel = open_skel.load().map_err(|source| EbpfLoadError::SkelLoad {
            probe: "persistence",
            source,
        })?;

        skel.attach().map_err(|source| EbpfLoadError::Attach {
            probe: "persistence",
            prog: "*",
            source,
        })?;

        let mut rb = RingBufferBuilder::new();
        let tx_drain = Arc::clone(&tx);
        rb.add(&skel.maps.file_write_events, move |data: &[u8]| {
            if let Some(raw) = parse_sample::<FileWriteEvent>(data) {
                try_send_event("persistence", &tx_drain, super::file_write_to_event(&raw));
            }
            0
        })
        .map_err(|source| EbpfLoadError::RingBuffer {
            probe: "persistence",
            source,
        })?;
        let rb = rb.build().map_err(|source| EbpfLoadError::RingBuffer {
            probe: "persistence",
            source,
        })?;

        let _skel: &'static mut PersistenceSkel<'static> = Box::leak(Box::new(skel));

        tokio::task::spawn_blocking(move || drain_ring_buffer("persistence", rb));

        Ok(())
    }

    /// Attach the B5 privesc probe (commit_creds).
    fn attach_privesc(tx: Arc<mpsc::Sender<EbpfEvent>>) -> Result<(), EbpfLoadError> {
        let open_object: &'static mut MaybeUninit<OpenObject> =
            Box::leak(Box::new(MaybeUninit::uninit()));

        let open_skel = PrivescSkelBuilder::default()
            .open(open_object)
            .map_err(|source| EbpfLoadError::SkelOpen {
                probe: "privesc",
                source,
            })?;
        let mut skel = open_skel.load().map_err(|source| EbpfLoadError::SkelLoad {
            probe: "privesc",
            source,
        })?;

        skel.attach().map_err(|source| EbpfLoadError::Attach {
            probe: "privesc",
            prog: "commit_creds",
            source,
        })?;

        let mut rb = RingBufferBuilder::new();
        let tx_drain = Arc::clone(&tx);
        rb.add(&skel.maps.creds_events, move |data: &[u8]| {
            if let Some(raw) = parse_sample::<CredsEvent>(data) {
                try_send_event("privesc", &tx_drain, super::creds_to_event(&raw));
            }
            0
        })
        .map_err(|source| EbpfLoadError::RingBuffer {
            probe: "privesc",
            source,
        })?;
        let rb = rb.build().map_err(|source| EbpfLoadError::RingBuffer {
            probe: "privesc",
            source,
        })?;

        let _skel: &'static mut PrivescSkel<'static> = Box::leak(Box::new(skel));

        tokio::task::spawn_blocking(move || drain_ring_buffer("privesc", rb));

        Ok(())
    }

    /// Attach the B6 rootkit probe (do_init_module).
    fn attach_rootkit(tx: Arc<mpsc::Sender<EbpfEvent>>) -> Result<(), EbpfLoadError> {
        let open_object: &'static mut MaybeUninit<OpenObject> =
            Box::leak(Box::new(MaybeUninit::uninit()));

        let open_skel = RootkitSkelBuilder::default()
            .open(open_object)
            .map_err(|source| EbpfLoadError::SkelOpen {
                probe: "rootkit",
                source,
            })?;
        let mut skel = open_skel.load().map_err(|source| EbpfLoadError::SkelLoad {
            probe: "rootkit",
            source,
        })?;

        skel.attach().map_err(|source| EbpfLoadError::Attach {
            probe: "rootkit",
            prog: "do_init_module",
            source,
        })?;

        let mut rb = RingBufferBuilder::new();
        let tx_drain = Arc::clone(&tx);
        rb.add(&skel.maps.module_events, move |data: &[u8]| {
            if let Some(raw) = parse_sample::<ModuleEvent>(data) {
                try_send_event("rootkit", &tx_drain, super::module_to_event(&raw));
            }
            0
        })
        .map_err(|source| EbpfLoadError::RingBuffer {
            probe: "rootkit",
            source,
        })?;
        let rb = rb.build().map_err(|source| EbpfLoadError::RingBuffer {
            probe: "rootkit",
            source,
        })?;

        let _skel: &'static mut RootkitSkel<'static> = Box::leak(Box::new(skel));

        tokio::task::spawn_blocking(move || drain_ring_buffer("rootkit", rb));

        Ok(())
    }

    // ── Ring buffer drain ─────────────────────────────────────────────────

    /// Loop on a [`libbpf_rs::RingBuffer`] until it errors out (typically
    /// when the underlying skeleton has been dropped at agent shutdown).
    ///
    /// Polls every 200 ms with a generous timeout — kernel callbacks fire
    /// inside `poll`, so latency is bounded by that interval.
    fn drain_ring_buffer(probe: &'static str, rb: libbpf_rs::RingBuffer<'static>) {
        loop {
            match rb.poll(Duration::from_millis(200)) {
                Ok(()) => continue,
                Err(e) => {
                    tracing::warn!(probe, error = %e, "eBPF ring buffer poll failed — drain task exiting");
                    break;
                }
            }
        }
    }

    /// Decode a raw ring-buffer sample into a `repr(C)` event struct.
    ///
    /// Returns `None` if the sample is too short. The sample is copied via
    /// `read_unaligned` so we don't rely on the ring-buffer slice being
    /// suitably aligned for `T`.
    ///
    /// # Safety
    ///
    /// The eBPF probe writes a `T`-shaped record into the ring buffer (each
    /// `*.bpf.c` declares the same `repr(C)` layout as `T` in `events.rs`).
    /// We trust libbpf to deliver complete records — the only check we add
    /// is the length test below.
    fn parse_sample<T: Copy>(data: &[u8]) -> Option<T> {
        if data.len() < std::mem::size_of::<T>() {
            tracing::trace!(
                expected = std::mem::size_of::<T>(),
                got = data.len(),
                "ring buffer sample too short — dropping"
            );
            return None;
        }
        // SAFETY: probes emit aligned records of size `size_of::<T>()`. We
        // copy unaligned to avoid undefined behaviour if libbpf hands us a
        // slice that is not naturally aligned for `T`.
        Some(unsafe { std::ptr::read_unaligned(data.as_ptr() as *const T) })
    }

    // ── Tests ─────────────────────────────────────────────────────────────

    #[cfg(test)]
    mod tests {
        use super::*;

        /// Compile-time check: `EbpfAgent::start` must return the documented
        /// `(EbpfAgent, Receiver<EbpfEvent>)` tuple. We assign the return to
        /// a fully qualified type so the compiler enforces the contract.
        #[test]
        fn start_returns_agent_and_receiver_type() {
            // We don't actually call `start()` here — that requires CAP_BPF
            // and a Linux kernel with BTF. The point of this test is purely
            // to make the function signature load-bearing in the type
            // system: if someone changes it (e.g. drops the receiver), this
            // file fails to compile.
            fn _assert_signature(
            ) -> fn() -> Result<(EbpfAgent, mpsc::Receiver<EbpfEvent>), EbpfLoadError> {
                EbpfAgent::start
            }
            let _ = _assert_signature;
        }

        #[test]
        fn parse_sample_rejects_short_buffer() {
            #[repr(C)]
            #[derive(Copy, Clone)]
            struct Big {
                _a: [u8; 64],
            }
            let buf = vec![0u8; 16];
            assert!(parse_sample::<Big>(&buf).is_none());
        }
    }
}

// ── Cross-platform helpers (also compiled on non-Linux) ─────────────────────

/// Convert a null-terminated C byte slice to an owned `String`.
///
/// Stops at the first `NUL` byte; falls back to lossy UTF-8 for non-ASCII
/// kernel strings (e.g. filenames with non-UTF bytes).
pub fn cstr_to_string(bytes: &[u8]) -> String {
    let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
    String::from_utf8_lossy(&bytes[..end]).into_owned()
}

use crate::events::{
    CredsEvent, EbpfEvent, EbpfEventKind, ExecveEvent, FileWriteEvent, MmapEvent, ModuleEvent,
    PtraceEvent,
};

/// Construct an [`EbpfEvent`] from a raw [`ExecveEvent`] ring-buffer sample.
pub fn execve_to_event(raw: &ExecveEvent) -> EbpfEvent {
    EbpfEvent {
        kind: EbpfEventKind::ProcessExec,
        pid: raw.pid,
        ppid: raw.ppid,
        uid: raw.uid,
        comm: cstr_to_string(&raw.comm),
        filename: Some(cstr_to_string(&raw.filename)),
        extra: Some(cstr_to_string(&raw.argv0)),
        timestamp_ns: raw.ts_ns,
    }
}

/// Construct an [`EbpfEvent`] from a raw [`MmapEvent`] ring-buffer sample.
pub fn mmap_to_event(raw: &MmapEvent) -> EbpfEvent {
    EbpfEvent {
        kind: EbpfEventKind::MemoryRwxMap,
        pid: raw.pid,
        ppid: raw.ppid,
        uid: raw.uid,
        comm: cstr_to_string(&raw.comm),
        filename: None,
        extra: Some(format!(
            "addr=0x{:x} len={} prot=0x{:x} flags=0x{:x}",
            raw.addr, raw.len, raw.prot, raw.flags
        )),
        timestamp_ns: raw.ts_ns,
    }
}

/// Construct an [`EbpfEvent`] from a raw [`PtraceEvent`] ring-buffer sample.
pub fn ptrace_to_event(raw: &PtraceEvent) -> EbpfEvent {
    EbpfEvent {
        kind: EbpfEventKind::PtraceAttach,
        pid: raw.pid,
        ppid: raw.ppid,
        uid: raw.uid,
        comm: cstr_to_string(&raw.comm),
        filename: None,
        extra: Some(format!(
            "request={} target_pid={}",
            raw.request, raw.target_pid
        )),
        timestamp_ns: raw.ts_ns,
    }
}

/// Construct an [`EbpfEvent`] from a raw [`CredsEvent`] ring-buffer sample.
pub fn creds_to_event(raw: &CredsEvent) -> EbpfEvent {
    EbpfEvent {
        kind: EbpfEventKind::CommitCredsEscalation,
        pid: raw.pid,
        ppid: raw.ppid,
        uid: raw.old_uid,
        comm: cstr_to_string(&raw.comm),
        filename: None,
        extra: Some(format!("old_uid={} new_uid={}", raw.old_uid, raw.new_uid)),
        timestamp_ns: raw.ts_ns,
    }
}

/// Construct an [`EbpfEvent`] from a raw [`ModuleEvent`] ring-buffer sample.
pub fn module_to_event(raw: &ModuleEvent) -> EbpfEvent {
    EbpfEvent {
        kind: EbpfEventKind::KernelModuleLoad,
        pid: raw.pid,
        ppid: 0, // not captured in this probe
        uid: 0,  // not captured in this probe
        comm: cstr_to_string(&raw.comm),
        filename: Some(cstr_to_string(&raw.name)),
        extra: None,
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
        pid: raw.pid,
        ppid: raw.ppid,
        uid: raw.uid,
        comm: cstr_to_string(&raw.comm),
        filename: Some(filename),
        extra: None,
        timestamp_ns: raw.ts_ns,
    }
}

#[cfg(test)]
mod converter_tests {
    use super::*;

    #[test]
    fn cstr_to_string_stops_at_nul() {
        let buf = b"hello\0world\0\0\0";
        assert_eq!(cstr_to_string(buf), "hello");
    }

    #[test]
    fn cstr_to_string_handles_no_nul() {
        let buf = b"abc";
        assert_eq!(cstr_to_string(buf), "abc");
    }
}
