//! ETW → Alert bridge (Phase 2 — A3).
//!
//! Consumes [`EtwEvent`]s from the `etw_consumer` channel, applies detection
//! rules, and emits [`Alert`]s for high-value event IDs.
//!
//! ## Alert rules
//!
//! | Rule ID  | Provider data1 | Event ID | ATT&CK      | Severity |
//! |----------|----------------|----------|-------------|----------|
//! | ETW-1001 | A0C1853B (PS)  | 4104     | T1059.001   | High     |
//! | ETW-1002 | 54849625 (Sec) | 4698     | T1053.005   | High     |
//! | ETW-1003 | 54849625 (Sec) | 4702     | T1053.005   | Medium   |
//! | ETW-1004 | 54849625 (Sec) | 4720     | T1136       | High     |
//! | ETW-1005 | 54849625 (Sec) | 4732     | T1078       | High     |
//! | ETW-1006 | 1418EF04 (WMI) | 5861     | T1047       | High     |
//! | ETW-1007 | DE7B24EA (Sched)| 106     | T1053.005   | Medium   |
//! | ETW-1008 | 70EB4F03 (Reg) | 1       | T1112       | Low      |
//! | ETW-1009 | 70EB4F03 (Reg) | 3       | T1112       | Low      |

use std::sync::mpsc::{Receiver, SyncSender};

use chrono::Utc;
use sentinel_core::models::alert::{Alert, Severity};
use uuid::Uuid;

use super::etw_consumer::EtwEvent;

// ── Alert specification ───────────────────────────────────────────────────────

struct AlertSpec {
    severity:  Severity,
    rule_id:   &'static str,
    attack_id: &'static str,
    kind:      &'static str,
}

/// Apply detection rules to a single ETW event.
///
/// Returns `Some(AlertSpec)` for high-value event IDs that warrant an alert;
/// `None` for informational or noisy events (process start/stop, DNS queries…).
fn classify(event: &EtwEvent) -> Option<AlertSpec> {
    // Match on the first 8 hex chars of the provider GUID (data1 field).
    // The format string uses uppercase `{:08X}`, so this is always uppercase.
    let tag = event.provider_guid.get(1..9)?;

    match (tag, event.event_id) {
        // ── PowerShell script-block (T1059.001) ───────────────────────────────
        // Event 4104 = script block logged *after* PS decodes obfuscation.
        // Even a benign-looking script block is worth recording — obfuscated
        // loaders, stagers, and living-off-the-land scripts all appear here.
        ("A0C1853B", 4104) => Some(AlertSpec {
            severity:  Severity::High,
            rule_id:   "ETW-1001",
            attack_id: "T1059.001",
            kind:      "PowerShell ScriptBlock Execution",
        }),

        // ── Scheduled task created (T1053.005) ───────────────────────────────
        ("54849625", 4698) => Some(AlertSpec {
            severity:  Severity::High,
            rule_id:   "ETW-1002",
            attack_id: "T1053.005",
            kind:      "Scheduled Task Created",
        }),

        // ── Scheduled task modified (T1053.005) ──────────────────────────────
        ("54849625", 4702) => Some(AlertSpec {
            severity:  Severity::Medium,
            rule_id:   "ETW-1003",
            attack_id: "T1053.005",
            kind:      "Scheduled Task Modified",
        }),

        // ── User account created (T1136) ──────────────────────────────────────
        ("54849625", 4720) => Some(AlertSpec {
            severity:  Severity::High,
            rule_id:   "ETW-1004",
            attack_id: "T1136",
            kind:      "User Account Created",
        }),

        // ── User added to local group (T1078) ────────────────────────────────
        ("54849625", 4732) => Some(AlertSpec {
            severity:  Severity::High,
            rule_id:   "ETW-1005",
            attack_id: "T1078",
            kind:      "User Added to Local Security Group",
        }),

        // ── WMI event consumer created (T1047) ───────────────────────────────
        // Event 5861 fires when a WMI subscription is registered — a classic
        // persistence mechanism. Almost always malicious outside vendor tooling.
        ("1418EF04", 5861) => Some(AlertSpec {
            severity:  Severity::High,
            rule_id:   "ETW-1006",
            attack_id: "T1047",
            kind:      "WMI Event Consumer Registered",
        }),

        // ── Scheduled task launched (T1053.005) ──────────────────────────────
        ("DE7B24EA", 106) => Some(AlertSpec {
            severity:  Severity::Medium,
            rule_id:   "ETW-1007",
            attack_id: "T1053.005",
            kind:      "Scheduled Task Launched",
        }),

        // ── Kernel-Registry : modification clé Run/RunOnce (T1547.001) ───────────────
        // On ne peut pas filtrer sur le nom de clé sans TDH parsing, mais toute
        // modification de registre kernel-level mérite un log Medium.
        ("70EB4F03", 1) => Some(AlertSpec {
            severity:  Severity::Low,
            rule_id:   "ETW-1008",
            attack_id: "T1112",
            kind:      "Registry Key Created (Kernel)",
        }),
        ("70EB4F03", 3) => Some(AlertSpec {
            severity:  Severity::Low,
            rule_id:   "ETW-1009",
            attack_id: "T1112",
            kind:      "Registry Value Set (Kernel)",
        }),

        // Everything else (process start/stop, DNS, image load, network, file…)
        // is not converted to an alert here — too noisy without TDH content parsing.
        _ => None,
    }
}

/// Build an [`Alert`] from a matched event + spec.
fn build_alert(event: &EtwEvent, spec: AlertSpec) -> Alert {
    let mut metadata = std::collections::HashMap::new();
    metadata.insert("pid".into(), event.pid.to_string());
    metadata.insert("tid".into(), event.tid.to_string());
    metadata.insert("event_id".into(), event.event_id.to_string());
    metadata.insert("provider".into(), event.provider_guid.clone());
    metadata.insert("etw_description".into(), event.description.to_string());

    Alert {
        id:          Uuid::new_v4(),
        severity:    spec.severity,
        kind:        spec.kind.to_string(),
        message:     format!(
            "{} — PID {} (ETW {})",
            spec.kind, event.pid, event.event_id,
        ),
        occurred_at: Utc::now(),
        metadata,
        rule_id:     Some(spec.rule_id.to_string()),
        attack_id:   Some(spec.attack_id.to_string()),
    }
}

// ── EtwMonitor ────────────────────────────────────────────────────────────────

/// Consumes [`EtwEvent`]s from the ETW consumer channel, applies detection
/// rules, and forwards matching [`Alert`]s to `alert_tx`.
///
/// Run this on a dedicated thread via [`EtwMonitor::run_blocking`] — the call
/// blocks until the ETW consumer drops its sender (i.e. the session stops).
pub struct EtwMonitor {
    event_rx: Receiver<EtwEvent>,
}

impl EtwMonitor {
    pub fn new(event_rx: Receiver<EtwEvent>) -> Self {
        Self { event_rx }
    }

    /// Block the calling thread, draining [`EtwEvent`]s and emitting
    /// [`Alert`]s.  Returns when the ETW session is stopped (channel closes).
    pub fn run_blocking(self, alert_tx: SyncSender<Alert>) {
        for event in &self.event_rx {
            if let Some(spec) = classify(&event) {
                let alert = build_alert(&event, spec);
                tracing::debug!(
                    rule_id = %alert.rule_id.as_deref().unwrap_or(""),
                    pid     = event.pid,
                    event_id = event.event_id,
                    "ETW alert emitted",
                );
                // Non-blocking: if the alert consumer is lagging, drop rather
                // than stall the ETW dispatch chain.
                if alert_tx.try_send(alert).is_err() {
                    tracing::warn!("alert channel full — ETW alert dropped");
                }
            }
        }
        tracing::info!("EtwMonitor: event channel closed, exiting");
    }
}
