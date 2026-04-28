//! Stub eBPF loader — drop-in replacement for [`crate::loader`] when the build
//! script ran with `SKIP_EBPF=1` (typically a CI runner that lacks BTF or
//! `bpftool`).
//!
//! The public API mirrors the real loader exactly (`linux::EbpfAgent`,
//! `linux::EbpfLoadError`, `EbpfAgent::start`, `EbpfAgent::attached_probes`)
//! so downstream crates need no `cfg` of their own. `start()` returns an
//! agent with zero attached probes and an open-but-never-fed receiver; the
//! caller's existing "0 probes ⇒ telemetry disabled" branch handles it.

#[cfg(target_os = "linux")]
pub mod linux {
    use std::sync::atomic::{AtomicU64, Ordering};

    use thiserror::Error;
    use tokio::sync::mpsc;

    use crate::events::EbpfEvent;

    /// Always 0 in stub mode — kept for symbol parity with the real
    /// loader so downstream metrics code can read it unconditionally.
    pub static EBPF_DROPPED_EVENTS: AtomicU64 = AtomicU64::new(0);

    /// Mirror of `loader::linux::ebpf_dropped_events_total`. Always 0
    /// in stub mode (no events are produced, so none can be dropped).
    pub fn ebpf_dropped_events_total() -> u64 {
        EBPF_DROPPED_EVENTS.load(Ordering::Relaxed)
    }

    /// Errors returned by [`EbpfAgent::start`].
    ///
    /// Kept variant-compatible with the real loader so downstream `match`
    /// expressions on the error type compile under either build mode.
    /// Never instantiated in stub mode.
    #[derive(Debug, Error)]
    pub enum EbpfLoadError {
        #[error("failed to open eBPF skeleton for probe `{probe}`: {source}")]
        SkelOpen {
            probe: &'static str,
            #[source]
            source: libbpf_rs::Error,
        },
        #[error("failed to load eBPF skeleton for probe `{probe}`: {source}")]
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
        /// Mirror of `loader::linux::EbpfLoadError::NoProbesAttached`.
        /// The stub never returns this variant (it always returns Ok with
        /// 0 attached probes — that is the explicit stub contract,
        /// distinct from a runtime failure on a real loader).
        #[error(
            "eBPF agent attached 0 probes — kernel may lack BTF or process \
             lacks CAP_BPF/CAP_SYS_ADMIN"
        )]
        NoProbesAttached,
    }

    /// Stub agent — exists so the type signature matches the real loader.
    pub struct EbpfAgent {
        attached_probes: usize,
    }

    impl EbpfAgent {
        /// Always returns 0 in stub mode.
        pub fn attached_probes(&self) -> usize {
            self.attached_probes
        }

        /// Returns an inert agent and a receiver that will never receive
        /// any events. Logs a warning so operators understand why no
        /// kernel telemetry is reaching the pipeline.
        pub fn start() -> Result<(Self, mpsc::Receiver<EbpfEvent>), EbpfLoadError> {
            tracing::warn!(
                "eBPF compiled in stub mode (SKIP_EBPF=1) — no probes will attach. \
                 Rebuild on a host with BTF + bpftool + libbpf-dev to enable kernel telemetry."
            );
            let (_tx, rx) = mpsc::channel::<EbpfEvent>(1);
            Ok((Self { attached_probes: 0 }, rx))
        }
    }
}
