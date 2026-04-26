//! ETW → Alert bridge (Phase 2 — A3).
//!
//! Consumes [`EtwEvent`]s from the `etw_consumer` channel, applies detection
//! rules, and emits [`Alert`]s for high-value event IDs.
//!
//! ## Alert rules
//!
//! | Rule ID  | Provider data1  | Event ID | ATT&CK    | Severity |
//! |----------|-----------------|----------|-----------|----------|
//! | ETW-1001 | A0C1853B (PS)   | 4104     | T1059.001 | High     |
//! | ETW-1002 | 54849625 (Sec)  | 4698     | T1053.005 | High     |
//! | ETW-1003 | 54849625 (Sec)  | 4702     | T1053.005 | Medium   |
//! | ETW-1004 | 54849625 (Sec)  | 4720     | T1136     | High     |
//! | ETW-1005 | 54849625 (Sec)  | 4732     | T1078     | High     |
//! | ETW-1006 | 1418EF04 (WMI)  | 5861     | T1047     | High     |
//! | ETW-1007 | DE7B24EA (Sched)| 106      | T1053.005 | Medium   |
//! | ETW-1008 | 70EB4F03 (Reg)  | 1        | T1112     | Low      |
//! | ETW-1009 | 70EB4F03 (Reg)  | 3        | T1112     | Low      |
//! | ETW-1010 | EDD08927 (File) | 12       | T1555.003 | Med/High |
//!
//! ETW-1010 inspects the `FileName` property of Kernel-File create events and
//! fires when it matches a known credential store (Chrome / Edge / Firefox /
//! KeePass / SSH / AWS / GCP / Azure). Severity follows
//! [`super::cred_paths::CredStoreKind::severity`]. The rule does **not** yet
//! suppress legit-browser openers — that allowlist is a downstream pipeline
//! concern (`DetectionPipeline::run`).

use std::sync::mpsc::{Receiver, SyncSender};

use arqenor_core::models::alert::{Alert, Severity};
use chrono::Utc;
use uuid::Uuid;

use super::cred_paths::{match_credential_path, CredStoreKind};
use super::etw_consumer::EtwEvent;

// ── Alert specification ───────────────────────────────────────────────────────

struct AlertSpec {
    severity: Severity,
    rule_id: &'static str,
    attack_id: &'static str,
    kind: &'static str,
}

/// Result of classifying a single [`EtwEvent`].
enum Classified {
    /// Static (provider, event_id) → fixed alert spec.
    Static(AlertSpec),
    /// Kernel-File event whose `FileName` property matched a credential store.
    /// Carries the matched kind and the path so they can be embedded in the
    /// alert metadata.
    CredAccess { kind: CredStoreKind, path: String },
}

/// Apply detection rules to a single ETW event.
///
/// Returns `Some` for high-value events that warrant an alert; `None` for
/// informational or noisy events (process start/stop, DNS queries, file
/// opens that are not credential stores…).
fn classify(event: &EtwEvent) -> Option<Classified> {
    // Match on the first 8 hex chars of the provider GUID (data1 field).
    // The format string uses uppercase `{:08X}`, so this is always uppercase.
    let tag = event.provider_guid.get(1..9)?;

    // ── Kernel-File: credential-store access (T1555.003 / T1552.001) ─────
    // Event 12 is the file-create / file-open opcode. Only fire when the
    // FileName property points at a known credential store — anything else
    // would flood the alert stream.
    if (tag, event.event_id) == ("EDD08927", 12) {
        if let Some(path) = lookup_property_ci(&event.properties, "FileName") {
            if let Some(kind) = match_credential_path(path) {
                return Some(Classified::CredAccess {
                    kind,
                    path: path.to_string(),
                });
            }
        }
        return None;
    }

    let spec = match (tag, event.event_id) {
        // ── PowerShell script-block (T1059.001) ───────────────────────────────
        // Event 4104 = script block logged *after* PS decodes obfuscation.
        // Even a benign-looking script block is worth recording — obfuscated
        // loaders, stagers, and living-off-the-land scripts all appear here.
        ("A0C1853B", 4104) => Some(AlertSpec {
            severity: Severity::High,
            rule_id: "ETW-1001",
            attack_id: "T1059.001",
            kind: "PowerShell ScriptBlock Execution",
        }),

        // ── Scheduled task created (T1053.005) ───────────────────────────────
        ("54849625", 4698) => Some(AlertSpec {
            severity: Severity::High,
            rule_id: "ETW-1002",
            attack_id: "T1053.005",
            kind: "Scheduled Task Created",
        }),

        // ── Scheduled task modified (T1053.005) ──────────────────────────────
        ("54849625", 4702) => Some(AlertSpec {
            severity: Severity::Medium,
            rule_id: "ETW-1003",
            attack_id: "T1053.005",
            kind: "Scheduled Task Modified",
        }),

        // ── User account created (T1136) ──────────────────────────────────────
        ("54849625", 4720) => Some(AlertSpec {
            severity: Severity::High,
            rule_id: "ETW-1004",
            attack_id: "T1136",
            kind: "User Account Created",
        }),

        // ── User added to local group (T1078) ────────────────────────────────
        ("54849625", 4732) => Some(AlertSpec {
            severity: Severity::High,
            rule_id: "ETW-1005",
            attack_id: "T1078",
            kind: "User Added to Local Security Group",
        }),

        // ── WMI event consumer created (T1047) ───────────────────────────────
        // Event 5861 fires when a WMI subscription is registered — a classic
        // persistence mechanism. Almost always malicious outside vendor tooling.
        ("1418EF04", 5861) => Some(AlertSpec {
            severity: Severity::High,
            rule_id: "ETW-1006",
            attack_id: "T1047",
            kind: "WMI Event Consumer Registered",
        }),

        // ── Scheduled task launched (T1053.005) ──────────────────────────────
        ("DE7B24EA", 106) => Some(AlertSpec {
            severity: Severity::Medium,
            rule_id: "ETW-1007",
            attack_id: "T1053.005",
            kind: "Scheduled Task Launched",
        }),

        // ── Kernel-Registry : modification clé Run/RunOnce (T1547.001) ───────────────
        // On ne peut pas filtrer sur le nom de clé sans TDH parsing, mais toute
        // modification de registre kernel-level mérite un log Medium.
        ("70EB4F03", 1) => Some(AlertSpec {
            severity: Severity::Low,
            rule_id: "ETW-1008",
            attack_id: "T1112",
            kind: "Registry Key Created (Kernel)",
        }),
        ("70EB4F03", 3) => Some(AlertSpec {
            severity: Severity::Low,
            rule_id: "ETW-1009",
            attack_id: "T1112",
            kind: "Registry Value Set (Kernel)",
        }),

        // Everything else (process start/stop, DNS, image load, network, file…)
        // is not converted to an alert here — too noisy without TDH content parsing.
        _ => None,
    };
    spec.map(Classified::Static)
}

/// Look up `key` in `props` ignoring case — TDH-decoded property names are
/// usually `FileName` but we don't want a single capitalisation drift to
/// silently disable detection.
fn lookup_property_ci<'a>(
    props: &'a std::collections::HashMap<String, String>,
    key: &str,
) -> Option<&'a str> {
    props
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case(key))
        .map(|(_, v)| v.as_str())
}

/// Build an [`Alert`] from a matched event + classification.
fn build_alert(event: &EtwEvent, classified: Classified) -> Alert {
    let mut metadata = std::collections::HashMap::new();
    metadata.insert("pid".into(), event.pid.to_string());
    metadata.insert("tid".into(), event.tid.to_string());
    metadata.insert("event_id".into(), event.event_id.to_string());
    metadata.insert("provider".into(), event.provider_guid.clone());
    metadata.insert("etw_description".into(), event.description.to_string());

    match classified {
        Classified::Static(spec) => Alert {
            id: Uuid::new_v4(),
            severity: spec.severity,
            kind: spec.kind.to_string(),
            message: format!("{} — PID {} (ETW {})", spec.kind, event.pid, event.event_id,),
            occurred_at: Utc::now(),
            metadata,
            rule_id: Some(spec.rule_id.to_string()),
            attack_id: Some(spec.attack_id.to_string()),
        },
        Classified::CredAccess { kind, path } => {
            metadata.insert("cred_store".into(), kind.label().to_string());
            metadata.insert("file_path".into(), path.clone());
            Alert {
                id: Uuid::new_v4(),
                severity: kind.severity(),
                kind: "BrowserCredAccess".to_string(),
                message: format!(
                    "Credential-store file opened: {} ({}) — PID {}",
                    path,
                    kind.label(),
                    event.pid,
                ),
                occurred_at: Utc::now(),
                metadata,
                rule_id: Some("ETW-1010".to_string()),
                attack_id: Some(kind.attack_id().to_string()),
            }
        }
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn synth_event(
        provider_guid: &str,
        event_id: u16,
        properties: HashMap<String, String>,
    ) -> EtwEvent {
        EtwEvent {
            provider_guid: provider_guid.to_string(),
            event_id,
            pid: 4321,
            tid: 1,
            timestamp: 0,
            level: 0,
            opcode: 0,
            task: 0,
            keyword: 0,
            user_data: Vec::new(),
            description: "synthetic",
            properties,
        }
    }

    /// A Kernel-File create event whose `FileName` is Chrome's Login Data must
    /// produce a `BrowserCredAccess` alert with kind/path metadata populated.
    #[test]
    fn kernel_file_chrome_login_data_emits_cred_access_alert() {
        let mut props = HashMap::new();
        props.insert(
            "FileName".into(),
            r"\Device\HarddiskVolume3\Users\alice\AppData\Local\Google\Chrome\User Data\Default\Login Data"
                .into(),
        );
        let ev = synth_event("{EDD08927-9CC4-4E65-B970-C2560FB5C289}", 12, props);

        let classified = classify(&ev).expect("must classify as cred access");
        let alert = build_alert(&ev, classified);

        assert_eq!(alert.kind, "BrowserCredAccess");
        assert_eq!(alert.severity, Severity::Medium); // browser → Medium
        assert_eq!(alert.attack_id.as_deref(), Some("T1555.003"));
        assert_eq!(alert.rule_id.as_deref(), Some("ETW-1010"));
        assert_eq!(
            alert.metadata.get("cred_store").map(String::as_str),
            Some("Chrome")
        );
        assert!(alert
            .metadata
            .get("file_path")
            .map(|p| p.contains("Login Data"))
            .unwrap_or(false));
    }

    /// SSH private keys are higher-signal than browser stores — severity bumps
    /// to High.
    #[test]
    fn kernel_file_ssh_key_emits_high_severity_alert() {
        let mut props = HashMap::new();
        props.insert("FileName".into(), r"C:\Users\bob\.ssh\id_ed25519".into());
        let ev = synth_event("{EDD08927-9CC4-4E65-B970-C2560FB5C289}", 12, props);
        let alert = build_alert(&ev, classify(&ev).unwrap());

        assert_eq!(alert.severity, Severity::High);
        assert_eq!(alert.attack_id.as_deref(), Some("T1552.001"));
        assert_eq!(
            alert.metadata.get("cred_store").map(String::as_str),
            Some("SSH")
        );
    }

    /// A Kernel-File event for a non-credential path must not produce an alert.
    #[test]
    fn kernel_file_unrelated_path_is_silent() {
        let mut props = HashMap::new();
        props.insert(
            "FileName".into(),
            r"C:\Users\carol\Documents\report.docx".into(),
        );
        let ev = synth_event("{EDD08927-9CC4-4E65-B970-C2560FB5C289}", 12, props);
        assert!(classify(&ev).is_none());
    }

    /// A Kernel-File event with no `FileName` property (e.g. TDH parse failed
    /// because the caller is non-admin) must not panic and must return None.
    #[test]
    fn kernel_file_without_filename_property_is_silent() {
        let ev = synth_event("{EDD08927-9CC4-4E65-B970-C2560FB5C289}", 12, HashMap::new());
        assert!(classify(&ev).is_none());
    }

    /// Property lookup is case-insensitive — `filename` must work the same as
    /// `FileName`.
    #[test]
    fn property_lookup_is_case_insensitive() {
        let mut props = HashMap::new();
        props.insert(
            "filename".into(),
            r"C:\Users\dave\Documents\Vault.kdbx".into(),
        );
        let ev = synth_event("{EDD08927-9CC4-4E65-B970-C2560FB5C289}", 12, props);
        assert!(matches!(
            classify(&ev),
            Some(Classified::CredAccess {
                kind: CredStoreKind::KeePassDb,
                ..
            }),
        ));
    }

    /// Existing static rules must still classify correctly after the refactor.
    #[test]
    fn powershell_event_4104_still_classifies_as_static() {
        let ev = synth_event(
            "{A0C1853B-5C40-4B15-8766-3CF1C58F985A}",
            4104,
            HashMap::new(),
        );
        let alert = build_alert(&ev, classify(&ev).unwrap());
        assert_eq!(alert.kind, "PowerShell ScriptBlock Execution");
        assert_eq!(alert.rule_id.as_deref(), Some("ETW-1001"));
    }
}
