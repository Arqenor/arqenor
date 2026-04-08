use async_trait::async_trait;
use tokio::sync::mpsc::Sender;

use crate::{
    error::SentinelError,
    models::file_event::{FileEvent, FileHash, ScanConfig},
};

#[async_trait]
pub trait FsScanner: Send + Sync {
    /// Recursively scan `root`, emitting a `FileEvent` per file found.
    async fn scan_path(
        &self,
        root: &std::path::Path,
        config: &ScanConfig,
    ) -> Result<Vec<FileEvent>, SentinelError>;

    /// Hash a single file (BLAKE3 or SHA-256 depending on impl).
    async fn hash_file(&self, path: &std::path::Path) -> Result<FileHash, SentinelError>;

    /// Watch `root` for real-time filesystem changes.
    async fn watch_path(
        &self,
        root: &std::path::Path,
        tx: Sender<FileEvent>,
    ) -> Result<(), SentinelError>;
}
