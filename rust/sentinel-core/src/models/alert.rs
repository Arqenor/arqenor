use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Alert {
    pub id:          Uuid,
    pub severity:    Severity,
    pub kind:        String,
    pub message:     String,
    pub occurred_at: DateTime<Utc>,
    pub metadata:    HashMap<String, String>,
    pub rule_id:     Option<String>,
    pub attack_id:   Option<String>,
}
