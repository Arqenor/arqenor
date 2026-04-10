//! Alert correlation engine.
//!
//! Groups related alerts into scored incidents, reducing noise and surfacing
//! real attacks.  Alerts are correlated primarily by PID (or parent chain)
//! within a sliding time window.

use std::collections::HashMap;

use chrono::{Duration, Utc};
use uuid::Uuid;

use crate::models::alert::{Alert, Severity};
use crate::models::incident::Incident;

// ── Constants ────────────────────────────────────────────────────────────────

/// Time window for correlating alerts into an incident (5 minutes).
const CORRELATION_WINDOW_SECS: i64 = 5 * 60;

const CRITICAL_THRESHOLD: u32 = 100;
const HIGH_THRESHOLD: u32 = 60;
const MEDIUM_THRESHOLD: u32 = 30;

/// How long completed incidents are retained (24 hours).
const COMPLETED_RETENTION_SECS: i64 = 24 * 60 * 60;

// ── Scoring ──────────────────────────────────────────────────────────────────

fn alert_score(alert: &Alert) -> u32 {
    let base = match alert.severity {
        Severity::Critical => 50,
        Severity::High     => 30,
        Severity::Medium   => 15,
        Severity::Low      => 5,
        Severity::Info     => 1,
    };

    let multiplier = match alert.attack_id.as_deref() {
        Some(id) if id.starts_with("T1003") => 3, // Credential access
        Some(id) if id.starts_with("T1055") => 2, // Process injection
        Some(id) if id.starts_with("T1547") => 2, // Persistence + execution
        _ => 1,
    };

    base * multiplier
}

fn severity_from_score(score: u32) -> Severity {
    if score >= CRITICAL_THRESHOLD {
        Severity::Critical
    } else if score >= HIGH_THRESHOLD {
        Severity::High
    } else if score >= MEDIUM_THRESHOLD {
        Severity::Medium
    } else {
        Severity::Low
    }
}

// ── Summary generation ───────────────────────────────────────────────────────

fn build_summary(incident: &Incident) -> String {
    let pid_part = match incident.pid {
        Some(pid) => {
            let proc_name = incident
                .alerts
                .iter()
                .find_map(|a| a.metadata.get("image").or_else(|| a.metadata.get("name")))
                .map(|s| s.as_str())
                .unwrap_or("unknown");
            format!("Process {} (PID {})", proc_name, pid)
        }
        None => "Non-process activity".to_string(),
    };

    let count = incident.alerts.len();
    let span = incident.last_seen - incident.first_seen;
    let span_str = if span.num_seconds() < 60 {
        format!("{}s", span.num_seconds())
    } else {
        format!("{}m", span.num_minutes())
    };

    // Collect unique attack descriptions.
    let mut descs: Vec<String> = Vec::new();
    let mut seen: Vec<String> = Vec::new();
    for alert in &incident.alerts {
        let key = alert.attack_id.clone().unwrap_or_default();
        if !seen.contains(&key) {
            seen.push(key);
            let attack_part = alert
                .attack_id
                .as_deref()
                .map(|id| format!(" ({})", id))
                .unwrap_or_default();
            descs.push(format!("{}{}", alert.message, attack_part));
        }
    }
    let truncated = descs.len() > 5;
    descs.truncate(5);

    let sev_label = match incident.severity {
        Severity::Critical => "CRITICAL",
        Severity::High     => "HIGH",
        Severity::Medium   => "MEDIUM",
        Severity::Low      => "LOW",
        Severity::Info     => "INFO",
    };

    let mut s = format!(
        "{} triggered {} alert{} in {}: {}",
        pid_part,
        count,
        if count == 1 { "" } else { "s" },
        span_str,
        descs.join(", "),
    );
    if truncated {
        s.push_str(", ...");
    }
    s.push_str(&format!(". Incident score: {} ({}).", incident.score, sev_label));
    s
}

// ── Helpers ──────────────────────────────────────────────────────────────────

fn extract_pid(alert: &Alert) -> Option<u32> {
    alert.metadata.get("pid").and_then(|v| v.parse().ok())
}

fn extract_ppid(alert: &Alert) -> Option<u32> {
    alert.metadata.get("ppid").and_then(|v| v.parse().ok())
}

fn orphan_key(alert: &Alert) -> u64 {
    use std::hash::{Hash, Hasher};
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    alert.attack_id.hash(&mut hasher);
    if let Some(ip) = alert.metadata.get("dst_ip") {
        ip.hash(&mut hasher);
    }
    if let Some(domain) = alert.metadata.get("domain") {
        domain.hash(&mut hasher);
    }
    hasher.finish()
}

// ── CorrelationEngine ────────────────────────────────────────────────────────

/// Maintains active incidents, evaluates new alerts, and flushes stale ones.
///
/// Thread safety: wrap in `Arc<Mutex<CorrelationEngine>>` at the call site.
pub struct CorrelationEngine {
    active:    HashMap<u32, Incident>,
    orphan:    HashMap<u64, Incident>,
    pid_alias: HashMap<u32, u32>,
    completed: Vec<Incident>,
    retention: Duration,
}

impl CorrelationEngine {
    pub fn new() -> Self {
        Self {
            active:    HashMap::new(),
            orphan:    HashMap::new(),
            pid_alias: HashMap::new(),
            completed: Vec::new(),
            retention: Duration::seconds(COMPLETED_RETENTION_SECS),
        }
    }

    fn resolve_pid(&self, pid: u32) -> u32 {
        self.pid_alias.get(&pid).copied().unwrap_or(pid)
    }

    /// Ingest a new alert.  Returns the incident if severity escalated.
    pub fn ingest(&mut self, alert: Alert) -> Option<&Incident> {
        let now = Utc::now();
        let pid = extract_pid(&alert);
        let ppid = extract_ppid(&alert);

        match pid {
            Some(raw_pid) => {
                // Parent-child aliasing.
                let canonical = if let Some(pp) = ppid {
                    if self.active.contains_key(&pp) || self.pid_alias.contains_key(&pp) {
                        let parent = self.resolve_pid(pp);
                        self.pid_alias.insert(raw_pid, parent);
                        parent
                    } else {
                        self.resolve_pid(raw_pid)
                    }
                } else {
                    self.resolve_pid(raw_pid)
                };

                let points = alert_score(&alert);

                if let Some(incident) = self.active.get_mut(&canonical) {
                    let old_sev = incident.severity.clone();
                    incident.score += points;
                    incident.last_seen = now;
                    if let Some(ref aid) = alert.attack_id {
                        if !incident.attack_ids.contains(aid) {
                            incident.attack_ids.push(aid.clone());
                        }
                    }
                    incident.alerts.push(alert);
                    incident.severity = severity_from_score(incident.score);
                    incident.summary = build_summary(incident);
                    return if old_sev != incident.severity {
                        self.active.get(&canonical)
                    } else {
                        None
                    };
                }

                // New incident.
                let attack_ids: Vec<String> = alert.attack_id.iter().cloned().collect();
                let severity = severity_from_score(points);
                let mut incident = Incident {
                    id: Uuid::new_v4(),
                    score: points,
                    severity,
                    attack_ids,
                    alerts: vec![alert],
                    summary: String::new(),
                    pid: Some(canonical),
                    first_seen: now,
                    last_seen: now,
                    is_closed: false,
                };
                incident.summary = build_summary(&incident);
                self.active.insert(canonical, incident);
                self.active.get(&canonical)
            }
            None => {
                let key = orphan_key(&alert);
                let points = alert_score(&alert);

                if let Some(incident) = self.orphan.get_mut(&key) {
                    let old_sev = incident.severity.clone();
                    incident.score += points;
                    incident.last_seen = now;
                    if let Some(ref aid) = alert.attack_id {
                        if !incident.attack_ids.contains(aid) {
                            incident.attack_ids.push(aid.clone());
                        }
                    }
                    incident.alerts.push(alert);
                    incident.severity = severity_from_score(incident.score);
                    incident.summary = build_summary(incident);
                    return if old_sev != incident.severity {
                        self.orphan.get(&key)
                    } else {
                        None
                    };
                }

                let attack_ids: Vec<String> = alert.attack_id.iter().cloned().collect();
                let severity = severity_from_score(points);
                let mut incident = Incident {
                    id: Uuid::new_v4(),
                    score: points,
                    severity,
                    attack_ids,
                    alerts: vec![alert],
                    summary: String::new(),
                    pid: None,
                    first_seen: now,
                    last_seen: now,
                    is_closed: false,
                };
                incident.summary = build_summary(&incident);
                self.orphan.insert(key, incident);
                self.orphan.get(&key)
            }
        }
    }

    /// Close stale incidents and return the newly closed ones.
    pub fn flush_stale(&mut self) -> Vec<Incident> {
        let now = Utc::now();
        let window = Duration::seconds(CORRELATION_WINDOW_SECS);
        let mut flushed = Vec::new();

        let stale_pids: Vec<u32> = self
            .active
            .iter()
            .filter(|(_, inc)| now - inc.last_seen > window)
            .map(|(pid, _)| *pid)
            .collect();

        for pid in stale_pids {
            if let Some(mut inc) = self.active.remove(&pid) {
                inc.is_closed = true;
                flushed.push(inc);
            }
            self.pid_alias.retain(|_, v| *v != pid);
        }

        let stale_orphans: Vec<u64> = self
            .orphan
            .iter()
            .filter(|(_, inc)| now - inc.last_seen > window)
            .map(|(key, _)| *key)
            .collect();

        for key in stale_orphans {
            if let Some(mut inc) = self.orphan.remove(&key) {
                inc.is_closed = true;
                flushed.push(inc);
            }
        }

        self.completed.extend(flushed.clone());
        self.completed.retain(|inc| now - inc.last_seen < self.retention);

        flushed
    }

    /// All active (open) incidents.
    pub fn active_incidents(&self) -> Vec<&Incident> {
        self.active.values().chain(self.orphan.values()).collect()
    }

    /// Completed incidents (retained for 24h).
    pub fn completed_incidents(&self) -> &[Incident] {
        &self.completed
    }
}

impl Default for CorrelationEngine {
    fn default() -> Self { Self::new() }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_alert(severity: Severity, attack_id: Option<&str>, pid: Option<u32>) -> Alert {
        let mut metadata = HashMap::new();
        if let Some(p) = pid {
            metadata.insert("pid".to_string(), p.to_string());
        }
        Alert {
            id: Uuid::new_v4(),
            severity,
            kind: "test".into(),
            message: "test alert".into(),
            occurred_at: Utc::now(),
            metadata,
            rule_id: Some("TEST-001".into()),
            attack_id: attack_id.map(String::from),
        }
    }

    #[test]
    fn single_alert_creates_incident() {
        let mut engine = CorrelationEngine::new();
        let result = engine.ingest(make_alert(Severity::High, Some("T1059.001"), Some(1234)));
        assert!(result.is_some());
        assert_eq!(engine.active_incidents().len(), 1);
    }

    #[test]
    fn same_pid_correlates() {
        let mut engine = CorrelationEngine::new();
        engine.ingest(make_alert(Severity::Medium, Some("T1059.001"), Some(100)));
        engine.ingest(make_alert(Severity::Medium, Some("T1053.005"), Some(100)));
        let incidents = engine.active_incidents();
        assert_eq!(incidents.len(), 1);
        assert_eq!(incidents[0].alerts.len(), 2);
    }

    #[test]
    fn different_pid_separates() {
        let mut engine = CorrelationEngine::new();
        engine.ingest(make_alert(Severity::Low, None, Some(100)));
        engine.ingest(make_alert(Severity::Low, None, Some(200)));
        assert_eq!(engine.active_incidents().len(), 2);
    }

    #[test]
    fn credential_access_scores_high() {
        let mut engine = CorrelationEngine::new();
        // T1003 Critical: 50 * 3 = 150 → CRITICAL
        let result = engine.ingest(make_alert(Severity::Critical, Some("T1003.001"), Some(42)));
        let inc = result.unwrap();
        assert_eq!(inc.score, 150);
        assert_eq!(inc.severity, Severity::Critical);
    }

    #[test]
    fn parent_child_correlation() {
        let mut engine = CorrelationEngine::new();
        engine.ingest(make_alert(Severity::Medium, Some("T1059"), Some(10)));
        let mut child = make_alert(Severity::High, Some("T1055.001"), Some(20));
        child.metadata.insert("ppid".into(), "10".into());
        engine.ingest(child);
        let incidents = engine.active_incidents();
        assert_eq!(incidents.len(), 1);
        assert_eq!(incidents[0].alerts.len(), 2);
    }

    #[test]
    fn score_accumulates() {
        let mut engine = CorrelationEngine::new();
        engine.ingest(make_alert(Severity::Medium, None, Some(5)));
        engine.ingest(make_alert(Severity::Medium, None, Some(5)));
        let inc = &engine.active_incidents()[0];
        assert_eq!(inc.score, 30);
        assert_eq!(inc.severity, Severity::Medium);
    }
}
