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

use windows::Win32::Foundation::CloseHandle;
use windows::Win32::Storage::FileSystem::{
    CreateFileW, ReadDirectoryChangesW,
    FILE_FLAG_BACKUP_SEMANTICS, FILE_NOTIFY_CHANGE_DIR_NAME, FILE_NOTIFY_CHANGE_FILE_NAME,
    FILE_NOTIFY_CHANGE_LAST_WRITE, FILE_NOTIFY_CHANGE_SECURITY, FILE_SHARE_DELETE,
    FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING,
};
use windows::core::PCWSTR;

// FILE_ACTION_* constants from winnt.h (not re-exported by windows-rs as named constants)
const FILE_ACTION_ADDED:            u32 = 1;
const FILE_ACTION_REMOVED:          u32 = 2;
const FILE_ACTION_MODIFIED:         u32 = 3;
const FILE_ACTION_RENAMED_OLD_NAME: u32 = 4;
const FILE_ACTION_RENAMED_NEW_NAME: u32 = 5;

// Minimum byte offset of FILE_NOTIFY_INFORMATION.FileName
//   NextEntryOffset(4) + Action(4) + FileNameLength(4) = 12
const FNI_HEADER_BYTES: usize = 12;

/// Walk a raw byte buffer returned by `ReadDirectoryChangesW` and extract
/// (action, filename) pairs from the linked `FILE_NOTIFY_INFORMATION` chain.
///
/// # Safety
/// `buf` must have been filled by a successful `ReadDirectoryChangesW` call
/// and `bytes_returned` must not exceed `buf.len() * 4`.
unsafe fn parse_notify_buf(buf: &[u32], bytes_returned: u32) -> Vec<(u32, String)> {
    let mut results = Vec::new();
    let bytes = bytes_returned as usize;
    if bytes < FNI_HEADER_BYTES {
        return results;
    }

    // View the DWORD-aligned buffer as raw bytes for portable field access
    let base = buf.as_ptr() as *const u8;
    let mut offset: usize = 0;

    loop {
        if offset + FNI_HEADER_BYTES > bytes {
            break;
        }

        // Read the three fixed DWORD fields at the current offset.
        // Safety: offset is always a multiple of 4 (guaranteed by NextEntryOffset docs)
        // and the buffer is DWORD-aligned.
        let next_entry  = *(base.add(offset)     as *const u32); // NextEntryOffset
        let action      = *(base.add(offset + 4) as *const u32); // Action
        let fname_bytes = *(base.add(offset + 8) as *const u32); // FileNameLength (bytes)

        let name_start = offset + FNI_HEADER_BYTES;
        let name_end   = name_start + fname_bytes as usize;
        if name_end > bytes {
            break;
        }

        // FileName is encoded as UTF-16LE (no null terminator — length is explicit)
        let name_u16 = std::slice::from_raw_parts(
            base.add(name_start) as *const u16,
            fname_bytes as usize / 2,
        );
        results.push((action, String::from_utf16_lossy(name_u16)));

        if next_entry == 0 {
            break;
        }
        offset += next_entry as usize;
    }
    results
}

pub struct WindowsFsScanner;

impl WindowsFsScanner {
    pub fn new() -> Self {
        Self
    }
}

impl Default for WindowsFsScanner {
    fn default() -> Self {
        Self::new()
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

            if let Some(exts) = Some(&config.include_extensions) {
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

    /// Watch `root` for filesystem changes using `ReadDirectoryChangesW`.
    ///
    /// Spawns a blocking thread that loops synchronously on the Win32 call.
    /// Events are streamed to `tx`; the loop exits when `tx` is dropped or
    /// the directory is removed.
    async fn watch_path(
        &self,
        root: &Path,
        tx: Sender<FileEvent>,
    ) -> Result<(), SentinelError> {
        use std::os::windows::ffi::OsStrExt;

        let root = root.to_owned();

        // Null-terminate the path for PCWSTR
        let path_w: Vec<u16> = root
            .as_os_str()
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();

        // Open the directory handle before moving into spawn_blocking
        // so callers get an error immediately if the path is invalid.
        let dir_handle = unsafe {
            CreateFileW(
                PCWSTR::from_raw(path_w.as_ptr()),
                0x0000_0001_u32,                                  // FILE_LIST_DIRECTORY
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                None,
                OPEN_EXISTING,
                FILE_FLAG_BACKUP_SEMANTICS,
                None,
            )
            .map_err(|e| SentinelError::Platform(e.to_string()))?
        };

        tokio::task::spawn_blocking(move || {
            // 16 KB DWORD-aligned buffer (u32 guarantees 4-byte alignment)
            let mut buf = vec![0u32; 4096];
            let buf_bytes = (buf.len() * std::mem::size_of::<u32>()) as u32;
            let notify_filter = FILE_NOTIFY_CHANGE_FILE_NAME
                | FILE_NOTIFY_CHANGE_DIR_NAME
                | FILE_NOTIFY_CHANGE_LAST_WRITE
                | FILE_NOTIFY_CHANGE_SECURITY;

            loop {
                let mut bytes_returned: u32 = 0;

                // Synchronous (blocking) call — no OVERLAPPED, no completion routine
                let ok = unsafe {
                    ReadDirectoryChangesW(
                        dir_handle,
                        buf.as_mut_ptr() as *mut _,
                        buf_bytes,
                        true,          // bWatchSubtree
                        notify_filter,
                        Some(&mut bytes_returned),
                        None,          // lpOverlapped
                        None,          // lpCompletionRoutine
                    )
                    .is_ok()
                };

                if !ok || bytes_returned == 0 {
                    // Directory was removed or handle became invalid
                    break;
                }

                let events = unsafe { parse_notify_buf(&buf, bytes_returned) };

                for (action, rel_name) in events {
                    let kind = match action {
                        FILE_ACTION_ADDED            => FileEventKind::Created,
                        FILE_ACTION_REMOVED          => FileEventKind::Deleted,
                        FILE_ACTION_MODIFIED         => FileEventKind::Modified,
                        FILE_ACTION_RENAMED_OLD_NAME
                        | FILE_ACTION_RENAMED_NEW_NAME => FileEventKind::Renamed,
                        _                            => continue,
                    };

                    let full_path = root.join(&rel_name).to_string_lossy().into_owned();
                    let event = FileEvent {
                        id:         Uuid::new_v4(),
                        kind,
                        path:       full_path,
                        sha256:     None,
                        size:       None,
                        event_time: Utc::now(),
                    };

                    if tx.blocking_send(event).is_err() {
                        // Receiver was dropped — stop watching
                        unsafe { let _ = CloseHandle(dir_handle); }
                        return;
                    }
                }
            }

            unsafe { let _ = CloseHandle(dir_handle); }
        });

        Ok(())
    }
}
