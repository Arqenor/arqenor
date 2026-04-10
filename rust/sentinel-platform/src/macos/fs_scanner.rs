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

use super::esf_dispatcher::EsfDispatcher;
use super::esf_monitor::EsfRawEvent;

pub struct MacosFsScanner;

impl MacosFsScanner {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl FsScanner for MacosFsScanner {
    async fn scan_path(&self, root: &Path, config: &ScanConfig) -> Result<Vec<FileEvent>, SentinelError> {
        let mut events = Vec::new();
        let walker = WalkDir::new(root).follow_links(false);
        let walker = if config.recursive { walker } else { walker.max_depth(1) };

        for entry in walker.into_iter().filter_map(|e| e.ok()) {
            let path = entry.path();
            if !path.is_file() { continue; }
            let size = fs::metadata(path).ok().map(|m| m.len());
            if let Some(max) = config.max_size_bytes {
                if size.unwrap_or(0) > max { continue; }
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
        Ok(FileHash { sha256: encode(Sha256::digest(&bytes)), size })
    }

    /// Watch `root` for filesystem changes via the macOS Endpoint Security Framework.
    ///
    /// Registers a file-event sender with the global `EsfDispatcher` and spawns
    /// a task that converts raw ESF events into `FileEvent` values, filtering to
    /// only paths under `root`. The loop exits when the downstream `tx` channel
    /// is dropped.
    async fn watch_path(&self, root: &Path, tx: Sender<FileEvent>) -> Result<(), SentinelError> {
        let (esf_tx, mut esf_rx) = tokio::sync::mpsc::channel::<EsfRawEvent>(2048);

        {
            let dispatcher = EsfDispatcher::global();
            let mut guard = dispatcher.lock().map_err(|e| {
                SentinelError::Platform(format!("EsfDispatcher lock poisoned: {e}"))
            })?;
            guard.set_file_sender(esf_tx);
            guard.start();
        }

        let root_prefix = root.to_string_lossy().into_owned();

        tokio::spawn(async move {
            while let Some(raw) = esf_rx.recv().await {
                let file_event = match raw {
                    EsfRawEvent::FileCreate { ref path, .. } if path.starts_with(&root_prefix) => {
                        FileEvent {
                            id:         Uuid::new_v4(),
                            kind:       FileEventKind::Created,
                            path:       path.clone(),
                            sha256:     None,
                            size:       None,
                            event_time: Utc::now(),
                        }
                    }
                    EsfRawEvent::FileWrite { ref path, .. } if path.starts_with(&root_prefix) => {
                        FileEvent {
                            id:         Uuid::new_v4(),
                            kind:       FileEventKind::Modified,
                            path:       path.clone(),
                            sha256:     None,
                            size:       None,
                            event_time: Utc::now(),
                        }
                    }
                    EsfRawEvent::FileDelete { ref path, .. } if path.starts_with(&root_prefix) => {
                        FileEvent {
                            id:         Uuid::new_v4(),
                            kind:       FileEventKind::Deleted,
                            path:       path.clone(),
                            sha256:     None,
                            size:       None,
                            event_time: Utc::now(),
                        }
                    }
                    EsfRawEvent::FileRename { ref new_path, .. } if new_path.starts_with(&root_prefix) => {
                        FileEvent {
                            id:         Uuid::new_v4(),
                            kind:       FileEventKind::Renamed,
                            path:       new_path.clone(),
                            sha256:     None,
                            size:       None,
                            event_time: Utc::now(),
                        }
                    }
                    EsfRawEvent::FileChmod { ref path, .. } if path.starts_with(&root_prefix) => {
                        FileEvent {
                            id:         Uuid::new_v4(),
                            kind:       FileEventKind::Modified,
                            path:       path.clone(),
                            sha256:     None,
                            size:       None,
                            event_time: Utc::now(),
                        }
                    }
                    EsfRawEvent::FileChown { ref path, .. } if path.starts_with(&root_prefix) => {
                        FileEvent {
                            id:         Uuid::new_v4(),
                            kind:       FileEventKind::Modified,
                            path:       path.clone(),
                            sha256:     None,
                            size:       None,
                            event_time: Utc::now(),
                        }
                    }
                    // Non-file variants or paths outside the watched root.
                    _ => continue,
                };

                if tx.send(file_event).await.is_err() {
                    break;
                }
            }
        });

        Ok(())
    }
}
