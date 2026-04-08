use async_trait::async_trait;
use chrono::Utc;
use hex::encode;
use sentinel_core::{
    error::SentinelError,
    models::file_event::{FileEvent, FileEventKind, FileHash, ScanConfig},
    traits::fs_scanner::FsScanner,
};
use sha2::{Digest, Sha256};
use std::{fs, path::Path};
use tokio::sync::mpsc::Sender;
use uuid::Uuid;
use walkdir::WalkDir;

pub struct WindowsFsScanner;

impl WindowsFsScanner {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl FsScanner for WindowsFsScanner {
    async fn scan_path(
        &self,
        root: &Path,
        config: &ScanConfig,
    ) -> Result<Vec<FileEvent>, SentinelError> {
        let mut events = Vec::new();
        let walker = WalkDir::new(root).follow_links(false);
        let walker = if config.recursive { walker } else { walker.max_depth(1) };

        for entry in walker.into_iter().filter_map(|e| e.ok()) {
            let path = entry.path();
            if !path.is_file() {
                continue;
            }

            if let Some(ref exts) = Some(&config.include_extensions) {
                if !exts.is_empty() {
                    let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");
                    if !exts.iter().any(|e| e == ext) {
                        continue;
                    }
                }
            }

            let meta = fs::metadata(path).ok();
            let size = meta.map(|m| m.len());

            if let Some(max) = config.max_size_bytes {
                if size.unwrap_or(0) > max {
                    continue;
                }
            }

            let sha256 = if config.compute_hash {
                self.hash_file(path).await.ok().map(|h| h.sha256)
            } else {
                None
            };

            events.push(FileEvent {
                id:         Uuid::new_v4(),
                kind:       FileEventKind::Created,
                path:       path.to_string_lossy().into_owned(),
                sha256,
                size,
                event_time: Utc::now(),
            });
        }

        Ok(events)
    }

    async fn hash_file(&self, path: &Path) -> Result<FileHash, SentinelError> {
        let bytes = fs::read(path)?;
        let size  = bytes.len() as u64;
        let hash  = encode(Sha256::digest(&bytes));
        Ok(FileHash { sha256: hash, size })
    }

    async fn watch_path(&self, _root: &Path, _tx: Sender<FileEvent>) -> Result<(), SentinelError> {
        // TODO: ReadDirectoryChangesW — Phase 2
        Err(SentinelError::NotSupported)
    }
}
