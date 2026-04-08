use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessInfo {
    pub pid:            u32,
    pub ppid:           u32,
    pub name:           String,
    pub exe_path:       Option<String>,
    pub cmdline:        Option<String>,
    pub user:           Option<String>,
    pub sha256:         Option<String>,
    pub started_at:     Option<DateTime<Utc>>,
    pub loaded_modules: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ProcessEventKind {
    Created,
    Terminated,
    Modified,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessEvent {
    pub id:         Uuid,
    pub kind:       ProcessEventKind,
    pub process:    ProcessInfo,
    pub event_time: DateTime<Utc>,
}
