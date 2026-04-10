//! Phase 3 — Real-time detection pipeline.
//!
//! Consumes process events and file events from platform monitors,
//! evaluates detection rules, and emits alerts on an output channel.
//!
//! ```text
//! ┌──────────────┐    ┌──────────────┐
//! │ ProcessWatch │    │   FIM Watch  │
//! └──────┬───────┘    └──────┬───────┘
//!        │  ProcessEvent     │  FileEvent
//!        ▼                   ▼
//!   ┌────────────────────────────────┐
//!   │       DetectionPipeline        │
//!   │  • LOLBin / process rules      │
//!   │  • File-path rules             │
//!   │  • Persistence diff (periodic) │
//!   └────────────────┬───────────────┘
//!                    │ Alert
//!                    ▼
//!            ┌──────────────┐
//!            │  alert_tx    │ → store / TUI / gRPC
//!            └──────────────┘
//! ```

use crate::{
    models::{
        alert::{Alert, Severity},
        file_event::{FileEvent, FileEventKind},
        process::{ProcessEvent, ProcessEventKind},
    },
    rules::{self, engine, DetectionRule, Pattern},
};
use chrono::Utc;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use tokio::sync::mpsc::{Receiver, Sender};
use uuid::Uuid;

// ── File-path rule ──────────────────────────────────────────────────────────

/// A file-path based detection rule.
#[derive(Debug, Clone)]
pub struct SensitivePathRule {
    pub id:        &'static str,
    pub pattern:   Pattern,
    pub severity:  Severity,
    pub attack_id: &'static str,
    pub title:     &'static str,
}

/// File-path rules that ship out of the box.
fn default_sensitive_path_rules() -> Vec<SensitivePathRule> {
    vec![
        // Windows
        SensitivePathRule {
            id: "SENT-F001", attack_id: "T1547.001",
            severity: Severity::High,
            title: "File Dropped in Startup Folder",
            pattern: Pattern::new("*\\Startup\\*"),
        },
        SensitivePathRule {
            id: "SENT-F002", attack_id: "T1565.001",
            severity: Severity::Critical,
            title: "Hosts File Modified",
            pattern: Pattern::new("*\\drivers\\etc\\hosts"),
        },
        SensitivePathRule {
            id: "SENT-F003", attack_id: "T1003",
            severity: Severity::Critical,
            title: "LSASS Dump File Detected",
            pattern: Pattern::new("*lsass*.dmp"),
        },
        SensitivePathRule {
            id: "SENT-F004", attack_id: "T1059.001",
            severity: Severity::High,
            title: "PowerShell Profile Modified",
            pattern: Pattern::new("*\\WindowsPowerShell\\*profile.ps1"),
        },
        // Linux
        SensitivePathRule {
            id: "SENT-F010", attack_id: "T1556",
            severity: Severity::Critical,
            title: "Shadow File Modified",
            pattern: Pattern::new("*/etc/shadow"),
        },
        SensitivePathRule {
            id: "SENT-F011", attack_id: "T1098",
            severity: Severity::High,
            title: "Sudoers Modified",
            pattern: Pattern::new("*/etc/sudoers*"),
        },
        SensitivePathRule {
            id: "SENT-F012", attack_id: "T1098.004",
            severity: Severity::High,
            title: "SSH Authorized Keys Modified",
            pattern: Pattern::new("*/.ssh/authorized_keys"),
        },
        SensitivePathRule {
            id: "SENT-F013", attack_id: "T1543.002",
            severity: Severity::High,
            title: "Systemd Unit Created/Modified",
            pattern: Pattern::new("*/systemd/system/*.service"),
        },
        SensitivePathRule {
            id: "SENT-F014", attack_id: "T1053.003",
            severity: Severity::Medium,
            title: "Cron File Modified",
            pattern: Pattern::new("*/cron*"),
        },
    ]
}

// ── Pipeline config ─────────────────────────────────────────────────────────

/// Configuration for the detection pipeline.
pub struct PipelineConfig {
    /// Process-based detection rules (LOLBin, suspicious process names, …).
    pub rules: Vec<DetectionRule>,
    /// File-path patterns that generate alerts on creation/modification.
    pub sensitive_paths: Vec<SensitivePathRule>,
}

impl Default for PipelineConfig {
    fn default() -> Self {
        Self {
            rules: rules::lolbin::built_in_rules(),
            sensitive_paths: default_sensitive_path_rules(),
        }
    }
}

// ── Pipeline stats ──────────────────────────────────────────────────────────

/// Thread-safe counters for observability.
#[derive(Debug, Default)]
pub struct PipelineStats {
    pub process_events: AtomicU64,
    pub file_events:    AtomicU64,
    pub alerts_fired:   AtomicU64,
}

impl PipelineStats {
    pub fn snapshot(&self) -> PipelineStatsSnapshot {
        PipelineStatsSnapshot {
            process_events: self.process_events.load(Ordering::Relaxed),
            file_events:    self.file_events.load(Ordering::Relaxed),
            alerts_fired:   self.alerts_fired.load(Ordering::Relaxed),
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct PipelineStatsSnapshot {
    pub process_events: u64,
    pub file_events:    u64,
    pub alerts_fired:   u64,
}

// ── Detection pipeline ──────────────────────────────────────────────────────

/// Real-time detection pipeline.
///
/// Construct with [`DetectionPipeline::new`], then [`DetectionPipeline::run`]
/// inside a `tokio::spawn`.  The pipeline exits when all input channels are
/// closed or `alert_tx` is dropped.
pub struct DetectionPipeline {
    config:     PipelineConfig,
    process_rx: Receiver<ProcessEvent>,
    file_rx:    Receiver<FileEvent>,
    alert_tx:   Sender<Alert>,
    stats:      Arc<PipelineStats>,
}

impl DetectionPipeline {
    pub fn new(
        config:     PipelineConfig,
        process_rx: Receiver<ProcessEvent>,
        file_rx:    Receiver<FileEvent>,
        alert_tx:   Sender<Alert>,
    ) -> Self {
        Self {
            config,
            process_rx,
            file_rx,
            alert_tx,
            stats: Arc::new(PipelineStats::default()),
        }
    }

    /// Shared handle to pipeline statistics (can be cloned before `run()`).
    pub fn stats(&self) -> Arc<PipelineStats> {
        Arc::clone(&self.stats)
    }

    /// Run the pipeline until all input channels close.
    pub async fn run(mut self) {
        loop {
            tokio::select! {
                msg = self.process_rx.recv() => match msg {
                    Some(evt) => {
                        self.stats.process_events.fetch_add(1, Ordering::Relaxed);
                        if !self.handle_process_event(&evt).await {
                            break;
                        }
                    }
                    None => {
                        // Process channel closed — drain file channel then exit
                        self.drain_file_events().await;
                        break;
                    }
                },
                msg = self.file_rx.recv() => match msg {
                    Some(evt) => {
                        self.stats.file_events.fetch_add(1, Ordering::Relaxed);
                        if !self.handle_file_event(&evt).await {
                            break;
                        }
                    }
                    None => {
                        // File channel closed — drain process channel then exit
                        self.drain_process_events().await;
                        break;
                    }
                },
            }
        }

        let snap = self.stats.snapshot();
        tracing::info!(
            process_events = snap.process_events,
            file_events    = snap.file_events,
            alerts_fired   = snap.alerts_fired,
            "detection pipeline stopped"
        );
    }

    /// Returns `false` if alert_tx is closed (caller should break).
    async fn handle_process_event(&self, evt: &ProcessEvent) -> bool {
        if !matches!(evt.kind, ProcessEventKind::Created) {
            return true;
        }

        let engine_evt = engine::ProcessEvent {
            pid:          evt.process.pid,
            image:        evt.process.exe_path.clone().unwrap_or_default(),
            name:         evt.process.name.clone(),
            cmdline:      evt.process.cmdline.clone().unwrap_or_default(),
            parent_image: None, // Phase 4: parent correlation via process tree cache
        };

        for alert in engine::evaluate_all(&self.config.rules, &engine_evt) {
            self.stats.alerts_fired.fetch_add(1, Ordering::Relaxed);
            if self.alert_tx.send(alert).await.is_err() {
                return false;
            }
        }
        true
    }

    /// Returns `false` if alert_tx is closed (caller should break).
    async fn handle_file_event(&self, evt: &FileEvent) -> bool {
        // Skip deletions for path-based alerting (covered by FIM baseline).
        if matches!(evt.kind, FileEventKind::Deleted) {
            return true;
        }

        let kind_str = match evt.kind {
            FileEventKind::Created  => "created",
            FileEventKind::Modified => "modified",
            FileEventKind::Renamed  => "renamed",
            FileEventKind::Deleted  => "deleted",
        };

        for rule in &self.config.sensitive_paths {
            if rule.pattern.matches(&evt.path) {
                self.stats.alerts_fired.fetch_add(1, Ordering::Relaxed);

                let mut metadata = HashMap::new();
                metadata.insert("path".into(), evt.path.clone());
                metadata.insert("action".into(), kind_str.into());
                if let Some(ref hash) = evt.sha256 {
                    metadata.insert("sha256".into(), hash.clone());
                }

                let alert = Alert {
                    id:          Uuid::new_v4(),
                    severity:    rule.severity.clone(),
                    kind:        "file_rule".into(),
                    message:     format!("{} — {} ({})", rule.title, evt.path, kind_str),
                    occurred_at: Utc::now(),
                    metadata,
                    rule_id:     Some(rule.id.into()),
                    attack_id:   Some(rule.attack_id.into()),
                };

                if self.alert_tx.send(alert).await.is_err() {
                    return false;
                }
            }
        }
        true
    }

    /// Drain remaining process events after the file channel has closed.
    async fn drain_process_events(&mut self) {
        while let Some(evt) = self.process_rx.recv().await {
            self.stats.process_events.fetch_add(1, Ordering::Relaxed);
            if !self.handle_process_event(&evt).await {
                return;
            }
        }
    }

    /// Drain remaining file events after the process channel has closed.
    async fn drain_file_events(&mut self) {
        while let Some(evt) = self.file_rx.recv().await {
            self.stats.file_events.fetch_add(1, Ordering::Relaxed);
            if !self.handle_file_event(&evt).await {
                return;
            }
        }
    }
}

// ── Convenience builder (legacy compat) ─────────────────────────────────────

/// Simplified builder that matches the Phase 2 `DetectionEngine` API.
///
/// Prefer [`DetectionPipeline`] for full control.
pub struct DetectionEngine {
    rules: Vec<DetectionRule>,
}

impl DetectionEngine {
    pub fn new(rules: Vec<DetectionRule>) -> Self {
        Self { rules }
    }

    /// Spawn the pipeline and return a handle to its stats.
    pub fn run(
        self,
        process_rx: Receiver<ProcessEvent>,
        fim_rx: Receiver<FileEvent>,
        alert_tx: Sender<Alert>,
    ) -> Arc<PipelineStats> {
        let config = PipelineConfig {
            rules: self.rules,
            sensitive_paths: default_sensitive_path_rules(),
        };
        let pipeline = DetectionPipeline::new(config, process_rx, fim_rx, alert_tx);
        let stats = pipeline.stats();
        tokio::spawn(pipeline.run());
        stats
    }
}
