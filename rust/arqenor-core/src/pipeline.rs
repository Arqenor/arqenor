//! Phase 3 — Real-time detection pipeline.
//!
//! Consumes process events, file events, and connection events from platform
//! monitors, evaluates detection rules, and emits alerts on an output channel.
//!
//! ```text
//! ┌──────────────┐  ┌──────────────┐  ┌──────────────┐
//! │ ProcessWatch │  │   FIM Watch  │  │  ConnWatch   │
//! └──────┬───────┘  └──────┬───────┘  └──────┬───────┘
//!        │ ProcessEvent    │ FileEvent        │ ConnectionInfo
//!        ▼                 ▼                  ▼
//!   ┌──────────────────────────────────────────────┐
//!   │             DetectionPipeline                │
//!   │  • LOLBin / process rules                    │
//!   │  • File-path rules                           │
//!   │  • Persistence diff (periodic)               │
//!   │  • C2 beaconing analysis (periodic)          │
//!   │  • DNS tunneling / DGA detection (periodic)  │
//!   └────────────────────┬─────────────────────────┘
//!                        │ Alert
//!                        ▼
//!                ┌──────────────┐
//!                │  alert_tx    │ → store / TUI / gRPC
//!                └──────────────┘
//! ```

use crate::{
    correlation::CorrelationEngine,
    ioc::{checker::IocChecker, IocDatabase},
    models::{
        alert::{sanitize_metadata_value, Alert, Severity},
        connection::ConnectionInfo,
        file_event::{FileEvent, FileEventKind},
        incident::Incident,
        network::{FlowKey, FlowRecord},
        process::{ProcessEvent, ProcessEventKind},
    },
    rules::{
        self, engine,
        sigma::{self, EventFields, SigmaRule},
        DetectionRule, Pattern,
    },
};
use chrono::Utc;
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::mpsc::{self, Receiver, Sender};
use tokio::sync::RwLock;
use uuid::Uuid;

// ── File-path rule ──────────────────────────────────────────────────────────

/// A file-path based detection rule.
#[derive(Debug, Clone)]
pub struct SensitivePathRule {
    pub id: &'static str,
    pub pattern: Pattern,
    pub severity: Severity,
    pub attack_id: &'static str,
    pub title: &'static str,
}

/// File-path rules that ship out of the box.
fn default_sensitive_path_rules() -> Vec<SensitivePathRule> {
    vec![
        // Windows
        SensitivePathRule {
            id: "SENT-F001",
            attack_id: "T1547.001",
            severity: Severity::High,
            title: "File Dropped in Startup Folder",
            pattern: Pattern::new("*\\Startup\\*"),
        },
        SensitivePathRule {
            id: "SENT-F002",
            attack_id: "T1565.001",
            severity: Severity::Critical,
            title: "Hosts File Modified",
            pattern: Pattern::new("*\\drivers\\etc\\hosts"),
        },
        SensitivePathRule {
            id: "SENT-F003",
            attack_id: "T1003",
            severity: Severity::Critical,
            title: "LSASS Dump File Detected",
            pattern: Pattern::new("*lsass*.dmp"),
        },
        SensitivePathRule {
            id: "SENT-F004",
            attack_id: "T1059.001",
            severity: Severity::High,
            title: "PowerShell Profile Modified",
            pattern: Pattern::new("*\\WindowsPowerShell\\*profile.ps1"),
        },
        // Linux
        SensitivePathRule {
            id: "SENT-F010",
            attack_id: "T1556",
            severity: Severity::Critical,
            title: "Shadow File Modified",
            pattern: Pattern::new("*/etc/shadow"),
        },
        SensitivePathRule {
            id: "SENT-F011",
            attack_id: "T1098",
            severity: Severity::High,
            title: "Sudoers Modified",
            pattern: Pattern::new("*/etc/sudoers*"),
        },
        SensitivePathRule {
            id: "SENT-F012",
            attack_id: "T1098.004",
            severity: Severity::High,
            title: "SSH Authorized Keys Modified",
            pattern: Pattern::new("*/.ssh/authorized_keys"),
        },
        SensitivePathRule {
            id: "SENT-F013",
            attack_id: "T1543.002",
            severity: Severity::High,
            title: "Systemd Unit Created/Modified",
            pattern: Pattern::new("*/systemd/system/*.service"),
        },
        SensitivePathRule {
            id: "SENT-F014",
            attack_id: "T1053.003",
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
    /// SIGMA rules for process/file/network event evaluation.
    pub sigma_rules: Vec<SigmaRule>,
    /// Shared IOC database for threat-intelligence lookups.
    pub ioc_db: Option<Arc<RwLock<IocDatabase>>>,
}

impl Default for PipelineConfig {
    fn default() -> Self {
        Self {
            rules: rules::lolbin::built_in_rules(),
            sensitive_paths: default_sensitive_path_rules(),
            sigma_rules: Vec::new(),
            ioc_db: None,
        }
    }
}

// ── Pipeline stats ──────────────────────────────────────────────────────────

/// Thread-safe counters for observability.
#[derive(Debug, Default)]
pub struct PipelineStats {
    pub process_events: AtomicU64,
    pub file_events: AtomicU64,
    pub conn_events: AtomicU64,
    pub alerts_fired: AtomicU64,
}

impl PipelineStats {
    pub fn snapshot(&self) -> PipelineStatsSnapshot {
        PipelineStatsSnapshot {
            process_events: self.process_events.load(Ordering::Relaxed),
            file_events: self.file_events.load(Ordering::Relaxed),
            conn_events: self.conn_events.load(Ordering::Relaxed),
            alerts_fired: self.alerts_fired.load(Ordering::Relaxed),
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct PipelineStatsSnapshot {
    pub process_events: u64,
    pub file_events: u64,
    pub conn_events: u64,
    pub alerts_fired: u64,
}

// ── Detection pipeline ──────────────────────────────────────────────────────

/// Real-time detection pipeline.
///
/// Construct with [`DetectionPipeline::new`], then [`DetectionPipeline::run`]
/// inside a `tokio::spawn`.  The pipeline exits when all input channels are
/// closed or `alert_tx` is dropped.
pub struct DetectionPipeline {
    config: PipelineConfig,
    process_rx: Receiver<ProcessEvent>,
    file_rx: Receiver<FileEvent>,
    conn_rx: Receiver<ConnectionInfo>,
    /// Receives externally-generated alerts (e.g. from host scan tasks).
    scan_rx: Receiver<Alert>,
    alert_tx: Sender<Alert>,
    incident_tx: Option<Sender<Incident>>,
    stats: Arc<PipelineStats>,
    correlation: Mutex<CorrelationEngine>,
}

impl DetectionPipeline {
    pub fn new(
        config: PipelineConfig,
        process_rx: Receiver<ProcessEvent>,
        file_rx: Receiver<FileEvent>,
        alert_tx: Sender<Alert>,
    ) -> Self {
        // Create dummy channels for optional inputs.
        let (_dummy_conn, conn_rx) = mpsc::channel::<ConnectionInfo>(1);
        drop(_dummy_conn);
        let (_dummy_scan, scan_rx) = mpsc::channel::<Alert>(1);
        drop(_dummy_scan);

        Self {
            config,
            process_rx,
            file_rx,
            conn_rx,
            scan_rx,
            alert_tx,
            incident_tx: None,
            stats: Arc::new(PipelineStats::default()),
            correlation: Mutex::new(CorrelationEngine::new()),
        }
    }

    /// Create a pipeline with an additional connection event stream for
    /// network-based detection (C2 beaconing, DNS tunneling, DGA).
    pub fn with_connections(
        config: PipelineConfig,
        process_rx: Receiver<ProcessEvent>,
        file_rx: Receiver<FileEvent>,
        conn_rx: Receiver<ConnectionInfo>,
        alert_tx: Sender<Alert>,
    ) -> Self {
        let (_dummy_scan, scan_rx) = mpsc::channel::<Alert>(1);
        drop(_dummy_scan);

        Self {
            config,
            process_rx,
            file_rx,
            conn_rx,
            scan_rx,
            alert_tx,
            incident_tx: None,
            stats: Arc::new(PipelineStats::default()),
            correlation: Mutex::new(CorrelationEngine::new()),
        }
    }

    /// Set an optional channel to receive correlated incidents.
    pub fn with_incident_channel(mut self, tx: Sender<Incident>) -> Self {
        self.incident_tx = Some(tx);
        self
    }

    /// Set a channel for externally-generated alerts (e.g. from host scan
    /// tasks like memory scanning, ntdll hook detection, BYOVD).  These
    /// alerts are fed through correlation and emitted on `alert_tx`.
    pub fn with_scan_alerts(mut self, rx: Receiver<Alert>) -> Self {
        self.scan_rx = rx;
        self
    }

    /// Shared handle to pipeline statistics (can be cloned before `run()`).
    pub fn stats(&self) -> Arc<PipelineStats> {
        Arc::clone(&self.stats)
    }

    /// Run the pipeline until all input channels close.
    pub async fn run(mut self) {
        // Flow table for accumulating connection data between analysis ticks.
        let mut flow_table: HashMap<FlowKey, FlowRecord> = HashMap::new();

        // Periodic network analysis interval (every 60 s).
        let mut analysis_interval = tokio::time::interval(Duration::from_secs(60));
        analysis_interval.tick().await; // skip the first immediate tick

        // Track which input channels are still open.
        let mut process_open = true;
        let mut file_open = true;
        let mut conn_open = true;
        let mut scan_open = true;

        loop {
            // Exit when all event channels have closed.
            if !process_open && !file_open && !conn_open && !scan_open {
                break;
            }

            tokio::select! {
                msg = self.process_rx.recv(), if process_open => match msg {
                    Some(evt) => {
                        self.stats.process_events.fetch_add(1, Ordering::Relaxed);
                        if !self.handle_process_event(&evt).await {
                            break;
                        }
                    }
                    None => {
                        process_open = false;
                    }
                },
                msg = self.file_rx.recv(), if file_open => match msg {
                    Some(evt) => {
                        self.stats.file_events.fetch_add(1, Ordering::Relaxed);
                        if !self.handle_file_event(&evt).await {
                            break;
                        }
                    }
                    None => {
                        file_open = false;
                    }
                },
                msg = self.conn_rx.recv(), if conn_open => match msg {
                    Some(conn) => {
                        self.stats.conn_events.fetch_add(1, Ordering::Relaxed);
                        if !self.handle_connection_event(&conn, &mut flow_table).await {
                            break;
                        }
                    }
                    None => {
                        conn_open = false;
                    }
                },
                // External scan alerts (memory, ntdll, BYOVD, etc.)
                msg = self.scan_rx.recv(), if scan_open => match msg {
                    Some(alert) => {
                        if !self.emit_alert(alert).await {
                            break;
                        }
                    }
                    None => {
                        scan_open = false;
                    }
                },
                _ = analysis_interval.tick() => {
                    self.run_network_analysis(&mut flow_table).await;
                    self.flush_correlation().await;
                }
            }
        }

        // Run final analysis on any remaining flow data.
        if !flow_table.is_empty() {
            self.run_network_analysis(&mut flow_table).await;
        }
        self.flush_correlation().await;

        let snap = self.stats.snapshot();
        tracing::info!(
            process_events = snap.process_events,
            file_events = snap.file_events,
            conn_events = snap.conn_events,
            alerts_fired = snap.alerts_fired,
            "detection pipeline stopped"
        );
    }

    /// Returns `false` if alert_tx is closed (caller should break).
    async fn handle_process_event(&self, evt: &ProcessEvent) -> bool {
        if !matches!(evt.kind, ProcessEventKind::Created) {
            return true;
        }

        let image = evt.process.exe_path.clone().unwrap_or_default();
        let cmdline = evt.process.cmdline.clone().unwrap_or_default();

        // ── LOLBin / built-in rules ────────────────────────────────────
        let engine_evt = engine::ProcessEvent {
            pid: evt.process.pid,
            image: image.clone(),
            name: evt.process.name.clone(),
            cmdline: cmdline.clone(),
            parent_image: None,
        };

        for alert in engine::evaluate_all(&self.config.rules, &engine_evt) {
            if !self.emit_alert(alert).await {
                return false;
            }
        }

        // ── SIGMA rules ────────────────────────────────────────────────
        if !self.config.sigma_rules.is_empty() {
            let fields = process_event_to_sigma_fields(evt);
            for rule in &self.config.sigma_rules {
                // Only evaluate process_creation rules against process events.
                let category = rule.logsource.category.as_deref().unwrap_or("");
                if category != "process_creation" && !category.is_empty() {
                    continue;
                }
                if sigma::evaluate(rule, &fields) {
                    let alert = sigma_match_to_alert(rule, &fields);
                    if !self.emit_alert(alert).await {
                        return false;
                    }
                }
            }
        }

        // ── IOC check on process image hash ────────────────────────────
        if let Some(ref sha256) = evt.process.sha256 {
            if let Some(ref ioc_db) = self.config.ioc_db {
                let db = ioc_db.read().await;
                let checker = IocChecker::new(&db);
                if let Some(alert) = checker.check_file_hash(sha256, &image) {
                    if !self.emit_alert(alert).await {
                        return false;
                    }
                }
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
            FileEventKind::Created => "created",
            FileEventKind::Modified => "modified",
            FileEventKind::Renamed => "renamed",
            FileEventKind::Deleted => "deleted",
        };

        // ── Sensitive path rules ───────────────────────────────────────
        for rule in &self.config.sensitive_paths {
            if rule.pattern.matches(&evt.path) {
                let mut metadata = HashMap::new();
                metadata.insert("path".into(), evt.path.clone());
                metadata.insert("action".into(), kind_str.into());
                if let Some(ref hash) = evt.sha256 {
                    metadata.insert("sha256".into(), hash.clone());
                }

                let alert = Alert {
                    id: Uuid::new_v4(),
                    severity: rule.severity.clone(),
                    kind: "file_rule".into(),
                    message: format!("{} — {} ({})", rule.title, evt.path, kind_str),
                    occurred_at: Utc::now(),
                    metadata,
                    rule_id: Some(rule.id.into()),
                    attack_id: Some(rule.attack_id.into()),
                };

                if !self.emit_alert(alert).await {
                    return false;
                }
            }
        }

        // ── SIGMA file_event rules ─────────────────────────────────────
        if !self.config.sigma_rules.is_empty() {
            let fields = file_event_to_sigma_fields(evt);
            for rule in &self.config.sigma_rules {
                let category = rule.logsource.category.as_deref().unwrap_or("");
                if category != "file_event" && !category.is_empty() {
                    continue;
                }
                if category.is_empty() {
                    continue; // don't evaluate uncategorized rules against file events
                }
                if sigma::evaluate(rule, &fields) {
                    let alert = sigma_match_to_alert(rule, &fields);
                    if !self.emit_alert(alert).await {
                        return false;
                    }
                }
            }
        }

        // ── IOC hash check ─────────────────────────────────────────────
        if let Some(ref sha256) = evt.sha256 {
            if let Some(ref ioc_db) = self.config.ioc_db {
                let db = ioc_db.read().await;
                let checker = IocChecker::new(&db);
                if let Some(alert) = checker.check_file_hash(sha256, &evt.path) {
                    if !self.emit_alert(alert).await {
                        return false;
                    }
                }
            }
        }

        true
    }

    /// Drain remaining process events after the file channel has closed.
    #[allow(dead_code)]
    async fn drain_process_events(&mut self) {
        while let Some(evt) = self.process_rx.recv().await {
            self.stats.process_events.fetch_add(1, Ordering::Relaxed);
            if !self.handle_process_event(&evt).await {
                return;
            }
        }
    }

    /// Drain remaining file events after the process channel has closed.
    #[allow(dead_code)]
    async fn drain_file_events(&mut self) {
        while let Some(evt) = self.file_rx.recv().await {
            self.stats.file_events.fetch_add(1, Ordering::Relaxed);
            if !self.handle_file_event(&evt).await {
                return;
            }
        }
    }

    // ── Alert emission + correlation ──────────────────────────────────────

    /// Acquire the correlation engine mutex, recovering gracefully from a
    /// poisoned lock.
    ///
    /// Mutex poisoning means a previous holder panicked mid-update — internal
    /// state may be inconsistent. For a security-monitoring pipeline,
    /// hard-crashing every subsequent thread is worse than continuing with
    /// possibly-stale correlation: the engine is window/HashMap based and
    /// tolerates missing entries. We log once per poisoned access and proceed.
    fn correlation_guard(&self) -> std::sync::MutexGuard<'_, CorrelationEngine> {
        self.correlation.lock().unwrap_or_else(|poisoned| {
            tracing::warn!(
                "correlation mutex was poisoned by a previous panic; \
                 continuing with possibly inconsistent state"
            );
            poisoned.into_inner()
        })
    }

    /// Send an alert on the output channel and ingest it into the correlation
    /// engine.  Returns `false` if the alert channel is closed.
    ///
    /// CORR-INJECT: metadata values are sanitised at the pipeline boundary
    /// before the alert reaches *any* downstream sink (correlation,
    /// `alert_tx`, gRPC stream, SSE). This is the single chokepoint at which
    /// untrusted-source content (process command lines, file paths, IOC
    /// payloads) is forced to be safe for line-oriented protocols. The
    /// correlation engine repeats the scrub defensively on its own boundary.
    async fn emit_alert(&self, mut alert: Alert) -> bool {
        self.stats.alerts_fired.fetch_add(1, Ordering::Relaxed);

        for value in alert.metadata.values_mut() {
            if value.chars().any(|c| c.is_control() && c != '\t') {
                *value = sanitize_metadata_value(value);
            }
        }

        // Ingest into correlation engine.
        let escalated_incident = {
            let mut corr = self.correlation_guard();
            corr.ingest(alert.clone()).cloned()
        };

        // If correlation detected a severity escalation, emit the incident.
        if let Some(incident) = escalated_incident {
            if let Some(ref tx) = self.incident_tx {
                let _ = tx.send(incident).await;
            }
        }

        self.alert_tx.send(alert).await.is_ok()
    }

    /// Flush stale incidents from the correlation engine and emit them.
    async fn flush_correlation(&self) {
        let flushed = {
            let mut corr = self.correlation_guard();
            corr.flush_stale()
        };

        if let Some(ref tx) = self.incident_tx {
            for incident in flushed {
                let _ = tx.send(incident).await;
            }
        }
    }

    /// Return a snapshot of active incidents from the correlation engine.
    pub fn active_incidents(&self) -> Vec<Incident> {
        let corr = self.correlation_guard();
        corr.active_incidents().into_iter().cloned().collect()
    }

    // ── Network / connection handling ───────────────────────────────────────

    /// Parse an address string ("ip:port", "[ipv6]:port", or bare "ip") into
    /// its IP and port components.
    fn parse_addr(s: &str) -> Option<(IpAddr, u16)> {
        // Try SocketAddr first (handles ip:port and [ipv6]:port).
        if let Ok(sa) = s.parse::<std::net::SocketAddr>() {
            return Some((sa.ip(), sa.port()));
        }
        // Fall back to bare IP address (port 0).
        s.parse::<IpAddr>().ok().map(|ip| (ip, 0))
    }

    /// Upsert a connection event into the flow table and check IOCs.
    ///
    /// Returns `false` if alert_tx is closed (caller should break).
    async fn handle_connection_event(
        &self,
        conn: &ConnectionInfo,
        flow_table: &mut HashMap<FlowKey, FlowRecord>,
    ) -> bool {
        let remote_str = match conn.remote_addr.as_deref() {
            Some(r) if !r.is_empty() => r,
            _ => return true, // skip listen / local-only
        };

        let (src_ip, _src_port) = match Self::parse_addr(&conn.local_addr) {
            Some(v) => v,
            None => return true,
        };
        let (dst_ip, dst_port) = match Self::parse_addr(remote_str) {
            Some(v) => v,
            None => return true,
        };

        let key = FlowKey {
            src_ip,
            dst_ip,
            dst_port,
            proto: conn.proto.to_string(),
        };

        let now = Utc::now();

        flow_table
            .entry(key.clone())
            .and_modify(|rec| {
                rec.last_seen = now;
                rec.conn_count += 1;
                rec.timestamps.push(now);
            })
            .or_insert_with(|| FlowRecord {
                key,
                pid: conn.pid,
                first_seen: now,
                last_seen: now,
                conn_count: 1,
                timestamps: vec![now],
            });

        // ── IOC IP check ───────────────────────────────────────────────
        if let Some(ref ioc_db) = self.config.ioc_db {
            let db = ioc_db.read().await;
            let checker = IocChecker::new(&db);
            if let Some(mut alert) = checker.check_connection(dst_ip, dst_port) {
                alert.metadata.insert("pid".into(), conn.pid.to_string());
                if !self.emit_alert(alert).await {
                    return false;
                }
            }
        }

        true
    }

    /// Periodic network analysis: beacon detection (and future DNS analysis).
    ///
    /// Drains the flow table, runs scoring functions, and emits alerts for
    /// flows that exceed the beacon threshold.
    ///
    /// When `rules::network` becomes available the pipeline will delegate to
    /// `analyze_beaconing` / `beacon_alerts`. Until then a lightweight
    /// coefficient-of-variation check is used inline.
    async fn run_network_analysis(&self, flow_table: &mut HashMap<FlowKey, FlowRecord>) {
        if flow_table.is_empty() {
            return;
        }

        let flows: Vec<FlowRecord> = flow_table.drain().map(|(_, v)| v).collect();

        tracing::debug!(
            flow_count = flows.len(),
            "running periodic network analysis"
        );

        // ── Beacon analysis ────────────────────────────────────────────
        for flow in &flows {
            if flow.timestamps.len() < 4 {
                continue; // not enough data points
            }

            // Compute inter-arrival intervals in milliseconds.
            let mut sorted_ts = flow.timestamps.clone();
            sorted_ts.sort();
            let intervals: Vec<f64> = sorted_ts
                .windows(2)
                .filter_map(|pair| {
                    let delta = (pair[1] - pair[0]).num_milliseconds() as f64;
                    if delta > 0.0 {
                        Some(delta)
                    } else {
                        None
                    }
                })
                .collect();

            if intervals.is_empty() {
                continue;
            }

            let n = intervals.len() as f64;
            let mean = intervals.iter().sum::<f64>() / n;
            if mean == 0.0 {
                continue;
            }

            let variance = intervals.iter().map(|v| (v - mean).powi(2)).sum::<f64>() / n;
            let stddev = variance.sqrt();
            let cv = stddev / mean; // coefficient of variation

            // Low CV → very regular interval → likely beaconing.
            // Score: 1.0 - cv, clamped to [0, 1].
            let score = (1.0 - cv).clamp(0.0, 1.0);

            if score >= 0.7 {
                let severity = if score >= 0.9 {
                    Severity::Critical
                } else if score >= 0.8 {
                    Severity::High
                } else {
                    Severity::Medium
                };

                let mut metadata = HashMap::new();
                metadata.insert("src_ip".into(), flow.key.src_ip.to_string());
                metadata.insert("dst_ip".into(), flow.key.dst_ip.to_string());
                metadata.insert("dst_port".into(), flow.key.dst_port.to_string());
                metadata.insert("proto".into(), flow.key.proto.clone());
                metadata.insert("conn_count".into(), flow.conn_count.to_string());
                metadata.insert("beacon_score".into(), format!("{score:.3}"));
                metadata.insert("interval_mean_ms".into(), format!("{mean:.1}"));
                metadata.insert("interval_stddev_ms".into(), format!("{stddev:.1}"));
                metadata.insert("pid".into(), flow.pid.to_string());

                let alert = Alert {
                    id: Uuid::new_v4(),
                    severity,
                    kind: "network_beacon".into(),
                    message: format!(
                        "Possible C2 beaconing: {} → {}:{} ({}) — \
                         score {:.2}, {} connections, mean interval {:.0} ms",
                        flow.key.src_ip,
                        flow.key.dst_ip,
                        flow.key.dst_port,
                        flow.key.proto,
                        score,
                        flow.conn_count,
                        mean,
                    ),
                    occurred_at: Utc::now(),
                    metadata,
                    rule_id: Some("SENT-N001".into()),
                    attack_id: Some("T1071.001".into()),
                };

                if !self.emit_alert(alert).await {
                    return; // alert channel closed
                }
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
    sigma_rules: Vec<SigmaRule>,
    ioc_db: Option<Arc<RwLock<IocDatabase>>>,
}

impl DetectionEngine {
    pub fn new(rules: Vec<DetectionRule>) -> Self {
        Self {
            rules,
            sigma_rules: Vec::new(),
            ioc_db: None,
        }
    }

    /// Add SIGMA rules to the engine.
    pub fn with_sigma_rules(mut self, rules: Vec<SigmaRule>) -> Self {
        self.sigma_rules = rules;
        self
    }

    /// Attach an IOC database for threat-intelligence lookups.
    pub fn with_ioc_db(mut self, db: Arc<RwLock<IocDatabase>>) -> Self {
        self.ioc_db = Some(db);
        self
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
            sigma_rules: self.sigma_rules,
            ioc_db: self.ioc_db,
        };
        let pipeline = DetectionPipeline::new(config, process_rx, fim_rx, alert_tx);
        let stats = pipeline.stats();
        tokio::spawn(pipeline.run());
        stats
    }
}

// ── SIGMA field converters ─────────────────────────────────────────────────

/// Convert a [`ProcessEvent`] to SIGMA-compatible [`EventFields`].
fn process_event_to_sigma_fields(evt: &ProcessEvent) -> EventFields {
    let mut fields = EventFields::new();
    fields.insert("pid".into(), evt.process.pid.to_string());
    fields.insert("ppid".into(), evt.process.ppid.to_string());
    if let Some(ref path) = evt.process.exe_path {
        fields.insert("image_path".into(), path.clone());
    }
    fields.insert("name".into(), evt.process.name.clone());
    if let Some(ref cmd) = evt.process.cmdline {
        fields.insert("cmdline".into(), cmd.clone());
    }
    if let Some(ref user) = evt.process.user {
        fields.insert("user".into(), user.clone());
    }
    if let Some(ref sha) = evt.process.sha256 {
        fields.insert("sha256".into(), sha.clone());
    }
    fields
}

/// Convert a [`FileEvent`] to SIGMA-compatible [`EventFields`].
fn file_event_to_sigma_fields(evt: &FileEvent) -> EventFields {
    let mut fields = EventFields::new();
    fields.insert("file_path".into(), evt.path.clone());
    fields.insert(
        "event_type".into(),
        match evt.kind {
            FileEventKind::Created => "created".into(),
            FileEventKind::Modified => "modified".into(),
            FileEventKind::Renamed => "renamed".into(),
            FileEventKind::Deleted => "deleted".into(),
        },
    );
    if let Some(ref sha) = evt.sha256 {
        fields.insert("sha256".into(), sha.clone());
    }
    fields
}

/// Build an [`Alert`] from a matched SIGMA rule.
fn sigma_match_to_alert(rule: &SigmaRule, fields: &EventFields) -> Alert {
    let attack_id = rule.attack_ids.first().cloned();
    let mut metadata: HashMap<String, String> = fields.clone();
    metadata.insert("sigma_rule_id".into(), rule.id.clone());
    metadata.insert("sigma_title".into(), rule.title.clone());
    if let Some(ref desc) = rule.description {
        metadata.insert("sigma_description".into(), desc.clone());
    }

    Alert {
        id: Uuid::new_v4(),
        severity: rule.level.to_severity(),
        kind: "sigma_match".into(),
        message: format!("SIGMA: {}", rule.title),
        occurred_at: Utc::now(),
        metadata,
        rule_id: Some(rule.id.clone()),
        attack_id,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::panic::{catch_unwind, AssertUnwindSafe};

    /// A poisoned correlation mutex must not bring down the pipeline.
    /// Both `active_incidents` and the internal `correlation_guard` recover
    /// the inner state instead of panicking.
    #[test]
    fn correlation_guard_recovers_from_poison() {
        let (_proc_tx, proc_rx) = mpsc::channel::<ProcessEvent>(1);
        let (_file_tx, file_rx) = mpsc::channel::<FileEvent>(1);
        let (alert_tx, _alert_rx) = mpsc::channel::<Alert>(1);
        let pipeline =
            DetectionPipeline::new(PipelineConfig::default(), proc_rx, file_rx, alert_tx);

        // Poison the mutex by panicking while holding the lock.
        let _ = catch_unwind(AssertUnwindSafe(|| {
            let _g = pipeline.correlation.lock().unwrap();
            panic!("intentional panic to poison the correlation mutex");
        }));
        assert!(pipeline.correlation.is_poisoned());

        // active_incidents must not panic on a poisoned mutex.
        let incidents = pipeline.active_incidents();
        assert!(incidents.is_empty());

        // Direct guard helper must also recover.
        let _g = pipeline.correlation_guard();
    }
}
