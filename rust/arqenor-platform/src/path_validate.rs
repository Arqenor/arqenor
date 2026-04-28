//! Watch-root validation helpers.
//!
//! On Windows, a non-elevated user can plant a junction (or another reparse
//! point) inside a directory the agent is later asked to monitor — the
//! `CreateFileW(... FILE_FLAG_BACKUP_SEMANTICS)` call would happily follow the
//! redirection and end up scanning whatever the attacker pointed at. The same
//! class of trick exists on Linux (symlink swap, TOCTOU between resolution
//! and `inotify_add_watch`).
//!
//! [`ensure_no_reparse`] rejects any path whose components contain a symlink,
//! Windows reparse point, or junction, so the caller only ever observes the
//! real, on-disk root.

use std::path::Path;

/// Returned when [`ensure_no_reparse`] refuses to validate a path.
#[derive(Debug, thiserror::Error)]
pub enum PathValidateError {
    #[error("path component is a symlink: {0}")]
    Symlink(String),
    #[error("path component is a reparse point: {0}")]
    ReparsePoint(String),
    #[error("path component is world-writable: {0}")]
    WorldWritable(String),
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

/// Return `Err` if `path` (or any of its parent components, walked from the
/// root downwards) is a symlink, junction, or reparse point.
///
/// Used to refuse watching paths that could be redirected by a non-privileged
/// user before the agent's `CreateFileW` / `inotify_add_watch` call.
pub fn ensure_no_reparse(path: &Path) -> Result<(), PathValidateError> {
    let mut current = std::path::PathBuf::new();
    for component in path.components() {
        current.push(component);

        let meta = match std::fs::symlink_metadata(&current) {
            Ok(m) => m,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                // Component does not exist yet — nothing to redirect.
                continue;
            }
            Err(e) => return Err(PathValidateError::Io(e)),
        };

        if meta.file_type().is_symlink() {
            return Err(PathValidateError::Symlink(current.display().to_string()));
        }

        #[cfg(windows)]
        {
            use std::os::windows::fs::MetadataExt;
            // Win32 `FILE_ATTRIBUTE_REPARSE_POINT` — covers junctions, mount
            // points, and any other reparse type we don't want to follow.
            const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
            if meta.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
                return Err(PathValidateError::ReparsePoint(
                    current.display().to_string(),
                ));
            }
        }
    }
    Ok(())
}

/// Linux-specific extension: in addition to [`ensure_no_reparse`], reject
/// world-writable components unless they're well-known system "sticky"
/// directories. Used as a defence-in-depth check before adding an inotify
/// watch on a user-supplied path.
#[cfg(target_os = "linux")]
pub fn ensure_no_reparse_strict(path: &Path) -> Result<(), PathValidateError> {
    use std::os::unix::fs::PermissionsExt;

    ensure_no_reparse(path)?;

    // Sticky-bit directories like /tmp are legitimately world-writable.
    const STICKY_ALLOWLIST: &[&str] = &["/tmp", "/var/tmp", "/dev/shm"];

    let mut current = std::path::PathBuf::new();
    for component in path.components() {
        current.push(component);

        let meta = match std::fs::symlink_metadata(&current) {
            Ok(m) => m,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
            Err(e) => return Err(PathValidateError::Io(e)),
        };

        let mode = meta.permissions().mode();
        if mode & 0o002 != 0 {
            let path_str = current.to_string_lossy();
            let allowed = STICKY_ALLOWLIST
                .iter()
                .any(|allowed| path_str.starts_with(allowed));
            // The sticky bit (0o1000) on a directory mitigates world-writable
            // for the deletion semantics we care about here.
            let sticky = mode & 0o1000 != 0;
            if !allowed && !sticky {
                return Err(PathValidateError::WorldWritable(
                    current.display().to_string(),
                ));
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_normal_directory() {
        // Use the system temp dir — guaranteed to exist and not be a reparse
        // point (sticky on Linux but tested separately).
        let dir = std::env::temp_dir();
        ensure_no_reparse(&dir).expect("temp dir must validate");
    }

    #[test]
    fn missing_path_is_ok() {
        // Non-existent path is treated as valid (callers will fail later when
        // they actually open it).
        let dir = std::env::temp_dir().join("arqenor-nonexistent-component-xyz");
        ensure_no_reparse(&dir).expect("missing path must validate as no-op");
    }

    #[cfg(unix)]
    #[test]
    fn rejects_unix_symlink() {
        use std::os::unix::fs::symlink;
        let tmp = std::env::temp_dir();
        let target = tmp.join(format!("arqenor-symlink-target-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&target).expect("create target");
        let link = tmp.join(format!("arqenor-symlink-{}", uuid::Uuid::new_v4()));
        symlink(&target, &link).expect("create symlink");

        let err = ensure_no_reparse(&link).expect_err("symlink must be rejected");
        assert!(matches!(err, PathValidateError::Symlink(_)), "got {err:?}");

        let _ = std::fs::remove_file(&link);
        let _ = std::fs::remove_dir(&target);
    }
}
