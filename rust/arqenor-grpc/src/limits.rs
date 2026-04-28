//! Server-side input validation, quotas and metadata sanitization for the
//! gRPC boundary.
//!
//! Addresses three findings of the 2026-04 security audit:
//! - **GRPC-PATH**: caller-supplied `root_path` must be canonicalized and
//!   constrained to a configured allowlist before any FS traversal.
//! - **GRPC-MAXSIZE**: caller-supplied `max_size_bytes` must be capped by a
//!   server-side maximum to bound hashing cost.
//! - **GRPC-METADATA**: stringly-typed `Alert.metadata` values originating
//!   from cmdlines, file paths or 3rd-party IOC feeds must be neutralised
//!   before crossing the gRPC boundary (log injection, XSS in downstream
//!   SSE consumers, control-character poisoning).
//!
//! Keep this module free of platform-specific code.

use std::path::{Path, PathBuf};

use tonic::Status;

/// Hard upper bound for `ScanRequest.max_size_bytes`. Files larger than this
/// are never hashed by the server, regardless of what the client requests.
///
/// 10 GiB is generous enough to cover legitimate forensic captures (memory
/// dumps, packet captures) while preventing a single malicious request from
/// pinning a streaming hasher on `/dev/zero` or equivalent.
pub const SERVER_MAX_FILE: u64 = 10 * 1024 * 1024 * 1024;

/// Built-in filesystem-scan allowlist used when no configuration source
/// supplies one. Mirrors the safe-by-default roots the auditor recommended
/// in finding GRPC-PATH.
///
/// Used as a fallback by [`load_allowed_roots`] when `configs/arqenor.toml`
/// is missing, malformed, or its `[scan].fs_roots` is empty.
pub fn builtin_allowed_roots() -> Vec<PathBuf> {
    #[cfg(target_os = "windows")]
    {
        vec![
            PathBuf::from(r"C:\Users"),
            PathBuf::from(r"C:\Windows\System32"),
        ]
    }
    #[cfg(not(target_os = "windows"))]
    {
        vec![PathBuf::from("/home"), PathBuf::from("/var/log")]
    }
}

/// Resolve the active scan-root allowlist by consulting `arqenor-core`'s
/// config loader, falling back to [`builtin_allowed_roots`] if the config
/// is unreadable or specifies no roots.
pub fn load_allowed_roots() -> Vec<PathBuf> {
    match arqenor_core::config::Config::load() {
        Ok(cfg) if !cfg.scan.fs_roots.is_empty() => cfg.scan.fs_roots,
        Ok(_) => {
            tracing::info!("config has no [scan].fs_roots — using built-in defaults");
            builtin_allowed_roots()
        }
        Err(e) => {
            tracing::warn!(
                error = %e,
                "could not load configs/arqenor.toml — using built-in scan-root defaults"
            );
            builtin_allowed_roots()
        }
    }
}

/// An allowlist of canonicalized filesystem roots that callers may scan.
///
/// Roots that fail to canonicalize at construction time (e.g. they don't
/// exist on this host) are silently dropped — the resulting list is the
/// intersection of the configured set with what is actually reachable.
#[derive(Debug, Clone)]
pub struct AllowedRoots {
    canonical: Vec<PathBuf>,
}

impl AllowedRoots {
    /// Build a new allowlist by canonicalizing each input root.
    pub fn new<I, P>(roots: I) -> Self
    where
        I: IntoIterator<Item = P>,
        P: AsRef<Path>,
    {
        let canonical = roots
            .into_iter()
            .filter_map(|p| match std::fs::canonicalize(p.as_ref()) {
                Ok(c) => Some(c),
                Err(e) => {
                    tracing::warn!(
                        path = %p.as_ref().display(),
                        error = %e,
                        "scan-root allowlist entry could not be canonicalized; dropping"
                    );
                    None
                }
            })
            .collect();
        Self { canonical }
    }

    /// True when no root could be canonicalized — every request will be
    /// rejected. Useful for an early `bail!`-style log at startup.
    pub fn is_empty(&self) -> bool {
        self.canonical.is_empty()
    }

    /// Validate that `requested` (a caller-supplied path) canonicalizes to a
    /// location inside one of the allowed roots. Returns the canonicalized
    /// path on success, an appropriate `Status` on failure.
    pub fn validate(&self, requested: &str) -> Result<PathBuf, Status> {
        if requested.trim().is_empty() {
            return Err(Status::invalid_argument("root_path must not be empty"));
        }

        let canonical = std::fs::canonicalize(requested)
            .map_err(|e| Status::invalid_argument(format!("invalid root_path: {e}")))?;

        if self
            .canonical
            .iter()
            .any(|allowed| canonical.starts_with(allowed))
        {
            Ok(canonical)
        } else {
            Err(Status::permission_denied("root_path outside allowed roots"))
        }
    }
}

/// Resolve the effective `max_size_bytes` for a `ScanRequest`.
///
/// - `0` is treated as "use server default" and mapped to [`SERVER_MAX_FILE`].
/// - Values above [`SERVER_MAX_FILE`] are rejected with
///   `Status::invalid_argument`.
pub fn resolve_max_size_bytes(requested: u64) -> Result<u64, Status> {
    if requested == 0 {
        return Ok(SERVER_MAX_FILE);
    }
    if requested > SERVER_MAX_FILE {
        return Err(Status::invalid_argument(
            "max_size_bytes exceeds server limit",
        ));
    }
    Ok(requested)
}

/// Strip control characters (`< 0x20`, plus `0x7F`) from a metadata value
/// before it crosses the gRPC boundary.
///
/// This is a defense-in-depth backstop. The same sanitization also happens
/// at the point of `Alert.metadata` insertion in `arqenor-core` — we still
/// run it here because `host_analyzer.rs` builds proto `Alert`s from
/// non-`Alert` sources too (e.g. raw process events).
///
/// Delegates to the canonical helper in `arqenor-core` so both layers stay
/// in sync.
#[inline]
pub fn sanitize_meta_value(s: &str) -> String {
    arqenor_core::models::alert::sanitize_metadata_value(s)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolve_max_size_zero_maps_to_server_default() {
        assert_eq!(resolve_max_size_bytes(0).unwrap(), SERVER_MAX_FILE);
    }

    #[test]
    fn resolve_max_size_under_limit_passes() {
        assert_eq!(resolve_max_size_bytes(1024).unwrap(), 1024);
    }

    #[test]
    fn resolve_max_size_over_limit_rejected() {
        let err = resolve_max_size_bytes(SERVER_MAX_FILE + 1).unwrap_err();
        assert_eq!(err.code(), tonic::Code::InvalidArgument);
    }

    #[test]
    fn sanitize_strips_newlines_and_controls() {
        // Core's sanitizer preserves `\t` (legitimate column separator in
        // log lines) but neutralises every other control char.
        let raw = "user\nSEVERITY=critical\r\x07tail";
        let cleaned = sanitize_meta_value(raw);
        assert!(!cleaned.contains('\n'));
        assert!(!cleaned.contains('\r'));
        assert!(!cleaned.contains('\x07'));
        assert_eq!(cleaned.len(), raw.len()); // 1:1 char replacement
    }

    #[test]
    fn sanitize_preserves_printable_ascii_and_unicode() {
        let raw = "C:\\Users\\é\\file.exe --flag=Ω";
        assert_eq!(sanitize_meta_value(raw), raw);
    }

    #[test]
    fn allowlist_rejects_empty_path() {
        let allow = AllowedRoots::new(Vec::<&str>::new());
        let err = allow.validate("").unwrap_err();
        assert_eq!(err.code(), tonic::Code::InvalidArgument);
    }

    #[test]
    fn allowlist_rejects_path_outside_root() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let allow = AllowedRoots::new([tmp.path()]);

        // Create a sibling dir that is NOT under the allowed root.
        let sibling = tempfile::tempdir().expect("sibling tempdir");
        let err = allow
            .validate(sibling.path().to_str().expect("utf8"))
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::PermissionDenied);
    }

    #[test]
    fn allowlist_accepts_path_inside_root() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let allow = AllowedRoots::new([tmp.path()]);

        let nested = tmp.path().join("sub");
        std::fs::create_dir_all(&nested).expect("mkdir nested");
        let canonical = allow
            .validate(nested.to_str().expect("utf8"))
            .expect("nested path under allowed root must validate");
        assert!(canonical.starts_with(std::fs::canonicalize(tmp.path()).unwrap()));
    }
}
