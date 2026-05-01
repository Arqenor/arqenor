//! Bridge module — maps Linux eBPF kernel telemetry into pipeline [`Alert`]s.
//!
//! Historically the conversion lived in `arqenor-cli` and bypassed
//! [`crate::pipeline::DetectionPipeline`] entirely (events were dropped onto
//! the external `scan_alerts` lane). That short-circuited the SIGMA matcher,
//! IOC checks and correlation engine. This module factors the mapping out so
//! the pipeline can ingest [`EbpfEvent`]s natively (see
//! [`crate::pipeline::DetectionPipeline::with_ebpf`]).
//!
//! `arqenor-ebpf` is gated to `cfg(target_os = "linux")` in `Cargo.toml`. To
//! keep the pipeline `tokio::select!` branch cross-platform (the macro does
//! not accept `#[cfg]` on individual branches), [`EbpfEvent`] is re-exported
//! on Linux and shimmed as a zero-variant enum elsewhere — every match
//! against it is then trivially exhaustive on non-Linux targets.

use crate::models::alert::Alert;

#[cfg(target_os = "linux")]
use crate::models::alert::Severity;
#[cfg(target_os = "linux")]
use chrono::Utc;
#[cfg(target_os = "linux")]
use std::collections::HashMap;
#[cfg(target_os = "linux")]
use uuid::Uuid;

/// Kernel event re-exported from `arqenor-ebpf` on Linux. On other targets,
/// the type is a zero-variant placeholder so a [`Receiver<EbpfEvent>`] field
/// can exist in the pipeline without conditional compilation.
#[cfg(target_os = "linux")]
pub use arqenor_ebpf::events::EbpfEvent;

#[cfg(not(target_os = "linux"))]
pub enum EbpfEvent {}

#[cfg(target_os = "linux")]
use arqenor_ebpf::events::EbpfEventKind;

/// Convert an [`EbpfEvent`] into an [`Alert`] suitable for the detection
/// pipeline.
///
/// Returns `None` for event kinds that are observability-only and would flood
/// the alert stream on a busy host (currently: `EbpfEventKind::ProcessExec`).
/// The execve probe is loaded for future correlation rules; surfacing every
/// `execve` as an alert is left for a follow-up change that introduces a real
/// suspicious-process classifier on top.
///
/// On non-Linux targets, [`EbpfEvent`] is uninhabited and this function is
/// statically unreachable — the `match evt {}` is exhaustive.
#[cfg(not(target_os = "linux"))]
pub fn ebpf_event_to_alert(evt: EbpfEvent) -> Option<Alert> {
    match evt {}
}

#[cfg(target_os = "linux")]
pub fn ebpf_event_to_alert(evt: EbpfEvent) -> Option<Alert> {
    let (kind, attack_id, severity, message, rule_id) = match evt.kind {
        // Observability-only — would flood on any active workstation.
        EbpfEventKind::ProcessExec => return None,
        EbpfEventKind::MemoryRwxMap => (
            "ebpf_rwx_map",
            "T1055",
            Severity::High,
            format!("RWX memory mapping by {} (PID {})", evt.comm, evt.pid),
            "SENT-EBPF-MMAP",
        ),
        EbpfEventKind::PtraceAttach => (
            "ebpf_ptrace_attach",
            "T1055.008",
            Severity::High,
            format!(
                "ptrace attach by {} (PID {}) — possible code injection",
                evt.comm, evt.pid
            ),
            "SENT-EBPF-PTRACE",
        ),
        EbpfEventKind::CommitCredsEscalation => (
            "ebpf_creds_escalation",
            "T1068",
            Severity::Critical,
            format!("credentials escalation by {} (PID {})", evt.comm, evt.pid),
            "SENT-EBPF-CREDS",
        ),
        EbpfEventKind::KernelModuleLoad => (
            "ebpf_kernel_module_load",
            "T1014",
            Severity::High,
            format!(
                "kernel module loaded by {}: {}",
                evt.comm,
                evt.filename.as_deref().unwrap_or("?")
            ),
            "SENT-EBPF-KMOD",
        ),
        EbpfEventKind::LdPreloadWrite => (
            "ebpf_ld_preload_write",
            "T1574.006",
            Severity::Critical,
            format!(
                "/etc/ld.so.preload written by {} (PID {})",
                evt.comm, evt.pid
            ),
            "SENT-EBPF-LDPRELD",
        ),
        EbpfEventKind::CronWrite => (
            "ebpf_cron_write",
            "T1053.003",
            Severity::Medium,
            format!(
                "cron file modified by {} (PID {}): {}",
                evt.comm,
                evt.pid,
                evt.filename.as_deref().unwrap_or("?")
            ),
            "SENT-EBPF-CRON",
        ),
    };

    let mut metadata = HashMap::new();
    metadata.insert("pid".into(), evt.pid.to_string());
    metadata.insert("ppid".into(), evt.ppid.to_string());
    metadata.insert("uid".into(), evt.uid.to_string());
    metadata.insert("comm".into(), evt.comm);
    if let Some(filename) = evt.filename {
        metadata.insert("filename".into(), filename);
    }
    if let Some(extra) = evt.extra {
        metadata.insert("extra".into(), extra);
    }
    metadata.insert("source".into(), "ebpf".into());

    Some(Alert {
        id: Uuid::new_v4(),
        severity,
        kind: kind.into(),
        message,
        occurred_at: Utc::now(),
        metadata,
        rule_id: Some(rule_id.into()),
        attack_id: Some(attack_id.into()),
    })
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;

    fn mk_event(kind: EbpfEventKind, comm: &str) -> EbpfEvent {
        EbpfEvent {
            kind,
            pid: 4242,
            ppid: 1,
            uid: 0,
            comm: comm.into(),
            filename: Some("/tmp/payload".into()),
            extra: None,
            timestamp_ns: 0,
        }
    }

    #[test]
    fn process_exec_is_dropped() {
        let evt = mk_event(EbpfEventKind::ProcessExec, "bash");
        assert!(ebpf_event_to_alert(evt).is_none());
    }

    #[test]
    fn rwx_map_is_high_severity() {
        let evt = mk_event(EbpfEventKind::MemoryRwxMap, "evil");
        let alert = ebpf_event_to_alert(evt).expect("alert produced");
        assert_eq!(alert.severity, Severity::High);
        assert_eq!(alert.kind, "ebpf_rwx_map");
        assert_eq!(alert.attack_id.as_deref(), Some("T1055"));
        assert_eq!(
            alert.metadata.get("source").map(String::as_str),
            Some("ebpf")
        );
        assert_eq!(alert.metadata.get("pid").map(String::as_str), Some("4242"));
    }

    #[test]
    fn creds_escalation_is_critical() {
        let evt = mk_event(EbpfEventKind::CommitCredsEscalation, "su");
        let alert = ebpf_event_to_alert(evt).expect("alert produced");
        assert_eq!(alert.severity, Severity::Critical);
        assert_eq!(alert.attack_id.as_deref(), Some("T1068"));
    }

    #[test]
    fn ld_preload_write_is_critical() {
        let evt = mk_event(EbpfEventKind::LdPreloadWrite, "tee");
        let alert = ebpf_event_to_alert(evt).expect("alert produced");
        assert_eq!(alert.severity, Severity::Critical);
        assert_eq!(alert.kind, "ebpf_ld_preload_write");
    }
}
