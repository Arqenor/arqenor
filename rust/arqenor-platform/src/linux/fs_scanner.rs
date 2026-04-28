use arqenor_core::{
    error::ArqenorError,
    models::file_event::{FileEvent, FileEventKind, FileHash, ScanConfig},
    traits::fs_scanner::FsScanner,
};
use async_trait::async_trait;
use chrono::Utc;
use hex::encode;
use inotify::{EventMask, Inotify, WatchMask};
use std::{
    fs,
    path::{Path, PathBuf},
};
use tokio::sync::mpsc::Sender;
use uuid::Uuid;
use walkdir::WalkDir;

use crate::hash::{sha256_file_streaming, DEFAULT_MAX_HASH_SIZE};
use crate::path_validate::ensure_no_reparse_strict;

pub struct LinuxFsScanner;

impl LinuxFsScanner {
    pub fn new() -> Self {
        Self
    }
}

impl Default for LinuxFsScanner {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl FsScanner for LinuxFsScanner {
    async fn scan_path(
        &self,
        root: &Path,
        config: &ScanConfig,
    ) -> Result<Vec<FileEvent>, ArqenorError> {
        let mut events = Vec::new();
        let walker = WalkDir::new(root).follow_links(false);
        let walker = if config.recursive {
            walker
        } else {
            walker.max_depth(1)
        };

        for entry in walker.into_iter().filter_map(|e| e.ok()) {
            let path = entry.path();
            if !path.is_file() {
                continue;
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
                id: Uuid::new_v4(),
                kind: FileEventKind::Created,
                path: path.to_string_lossy().into_owned(),
                sha256,
                size,
                event_time: Utc::now(),
            });
        }
        Ok(events)
    }

    async fn hash_file(&self, path: &Path) -> Result<FileHash, ArqenorError> {
        // Pre-streaming this used `fs::read` followed by `Sha256::digest` —
        // both required holding the entire file in memory. We now stream
        // 64 KiB chunks through the digest and bail on files above the
        // platform-wide size cap.
        let size = fs::metadata(path)?.len();
        let digest = sha256_file_streaming(path, DEFAULT_MAX_HASH_SIZE)
            .map_err(|e| ArqenorError::Platform(format!("hash_file({}): {e}", path.display())))?;
        Ok(FileHash {
            sha256: encode(digest),
            size,
        })
    }

    /// Watch `root` for filesystem changes using Linux inotify.
    ///
    /// Spawns a blocking thread that loops on `read_events_blocking`.
    /// Events are streamed to `tx`; the loop exits when `tx` is dropped or
    /// the watch descriptor becomes invalid.
    async fn watch_path(&self, root: &Path, tx: Sender<FileEvent>) -> Result<(), ArqenorError> {
        // Reject symlinks/world-writable components before adding an inotify
        // watch — a non-root user could otherwise swap a path component for
        // a symlink between resolution and watch registration and quietly
        // observe (or hide) events on a directory the agent thinks it owns.
        ensure_no_reparse_strict(root).map_err(|e| {
            ArqenorError::Platform(format!("refusing to watch '{}': {e}", root.display()))
        })?;

        let root = root.to_owned();
        tokio::task::spawn_blocking(move || inotify_watch_loop(root, tx));
        Ok(())
    }
}

// ── inotify blocking loop ────────────────────────────────────────────────────

fn inotify_watch_loop(root: PathBuf, tx: Sender<FileEvent>) {
    let mut inotify = match Inotify::init() {
        Ok(i) => i,
        Err(_) => return,
    };

    if inotify
        .watches()
        .add(
            &root,
            WatchMask::CREATE
                | WatchMask::DELETE
                | WatchMask::MODIFY
                | WatchMask::CLOSE_WRITE
                | WatchMask::MOVED_TO
                | WatchMask::MOVED_FROM,
        )
        .is_err()
    {
        return;
    }

    let mut buf = [0u8; 8192];

    loop {
        let events = match inotify.read_events_blocking(&mut buf) {
            Ok(e) => e,
            Err(_) => break,
        };

        for event in events {
            let name = match event.name {
                Some(n) => n,
                None => continue, // directory-level event with no filename
            };

            let kind = if event.mask.contains(EventMask::CREATE)
                || event.mask.contains(EventMask::MOVED_TO)
            {
                FileEventKind::Created
            } else if event.mask.contains(EventMask::DELETE)
                || event.mask.contains(EventMask::MOVED_FROM)
            {
                FileEventKind::Deleted
            } else if event.mask.contains(EventMask::MODIFY)
                || event.mask.contains(EventMask::CLOSE_WRITE)
            {
                FileEventKind::Modified
            } else {
                continue;
            };

            let file_event = FileEvent {
                id: Uuid::new_v4(),
                kind,
                path: root.join(name).to_string_lossy().into_owned(),
                sha256: None,
                size: None,
                event_time: Utc::now(),
            };

            if tx.blocking_send(file_event).is_err() {
                return;
            }
        }
    }
}
