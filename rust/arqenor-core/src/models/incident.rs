//! Incident model — a group of correlated alerts forming an attack chain.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::alert::{Alert, Severity};

/// An incident is a group of correlated alerts that together indicate
/// a likely attack chain.  Single low-severity alerts rarely warrant
/// investigation; a cluster of them does.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Incident {
    pub id:         Uuid,
    pub score:      u32,
    pub severity:   Severity,
    /// Deduplicated MITRE ATT&CK IDs across all alerts in this incident.
    pub attack_ids: Vec<String>,
    pub alerts:     Vec<Alert>,
    /// Human-readable narrative summarising the incident.
    pub summary:    String,
    /// Primary process ID (if the incident was correlated by PID).
    pub pid:        Option<u32>,
    pub first_seen: DateTime<Utc>,
    pub last_seen:  DateTime<Utc>,
    pub is_closed:  bool,
}
