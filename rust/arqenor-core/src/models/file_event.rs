use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum FileEventKind {
    Created,
    Modified,
    Deleted,
    Renamed,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileEvent {
    pub id:         Uuid,
    pub kind:       FileEventKind,
    pub path:       String,
    pub sha256:     Option<String>,
    pub size:       Option<u64>,
    pub event_time: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileHash {
    pub sha256: String,
    pub size:   u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanConfig {
    pub recursive:          bool,
    pub include_extensions: Vec<String>,
    pub max_size_bytes:     Option<u64>,
    pub compute_hash:       bool,
}
