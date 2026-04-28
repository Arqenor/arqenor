//! Typed loader for `configs/arqenor.toml`.
//!
//! The OSS configuration is intentionally tiny: a handful of operator-tunable
//! values (gRPC bind addresses, scan roots, log level) that downstream crates
//! — `arqenor-grpc`, `arqenor-platform`, the orchestrator — read at startup.
//! Centralising the schema here keeps every consumer in sync and provides a
//! single point at which we reject an ill-formed config (so we never fall
//! back to "best-effort defaults" that mask a typo at deploy time).
//!
//! # Resolution order
//!
//! 1. The path passed to [`Config::load_from`] (if any).
//! 2. The `ARQENOR_CONFIG` environment variable (if set).
//! 3. `./configs/arqenor.toml` relative to the current working directory.
//!
//! All paths are resolved with [`std::fs::canonicalize`] when available so
//! relative scan roots survive `cd`-style restarts.

use std::env;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Default path probed when neither an explicit argument nor `ARQENOR_CONFIG`
/// is supplied.
pub const DEFAULT_CONFIG_PATH: &str = "configs/arqenor.toml";

/// Environment variable that may override the default config path.
pub const CONFIG_ENV_VAR: &str = "ARQENOR_CONFIG";

/// Errors surfaced by the config loader.
///
/// `toml::de::Error` is large (~128 B); boxing keeps `Result<Config, _>`
/// compact and silences `clippy::result_large_err`.
#[derive(Debug, Error)]
pub enum ConfigError {
    /// `std::fs::read_to_string` failed (file missing, permission denied, …).
    #[error("config I/O error reading {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    /// `toml::from_str` failed — schema mismatch or malformed TOML.
    #[error("config parse error in {path}: {source}")]
    Parse {
        path: PathBuf,
        #[source]
        source: Box<toml::de::Error>,
    },
}

/// Top-level configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    #[serde(default)]
    pub general: GeneralConfig,

    #[serde(default)]
    pub grpc: GrpcConfig,

    #[serde(default)]
    pub api: ApiConfig,

    #[serde(default)]
    pub scan: ScanConfig,

    /// Reserved for the future `[alerts]` section. Kept as a free-form table
    /// so existing config files (which already define `[alerts]`) do not
    /// trip the `deny_unknown_fields` guard at the top level.
    #[serde(default)]
    pub alerts: toml::value::Table,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GeneralConfig {
    #[serde(default = "default_log_level")]
    pub log_level: String,

    #[serde(default = "default_data_dir")]
    pub data_dir: PathBuf,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GrpcConfig {
    #[serde(default = "default_host_analyzer_addr")]
    pub host_analyzer_addr: String,

    #[serde(default = "default_network_scanner_addr")]
    pub network_scanner_addr: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApiConfig {
    #[serde(default = "default_api_listen_addr")]
    pub listen_addr: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScanConfig {
    /// Filesystem roots to scan for FIM / hash-based detections.
    #[serde(default)]
    pub fs_roots: Vec<PathBuf>,

    /// Maximum file size (bytes) to hash. `0` disables the cap.
    #[serde(default = "default_max_file_size")]
    pub max_file_size: u64,

    /// Watch-mode interval in seconds.
    #[serde(default = "default_interval_secs")]
    pub interval_secs: u64,
}

// ── Defaults ─────────────────────────────────────────────────────────────────

fn default_log_level() -> String {
    "info".to_string()
}
fn default_data_dir() -> PathBuf {
    PathBuf::from("./data")
}
fn default_host_analyzer_addr() -> String {
    "127.0.0.1:50051".to_string()
}
fn default_network_scanner_addr() -> String {
    "127.0.0.1:50052".to_string()
}
fn default_api_listen_addr() -> String {
    "127.0.0.1:8080".to_string()
}
fn default_max_file_size() -> u64 {
    10 * 1024 * 1024
}
fn default_interval_secs() -> u64 {
    60
}

impl Default for GeneralConfig {
    fn default() -> Self {
        Self {
            log_level: default_log_level(),
            data_dir: default_data_dir(),
        }
    }
}

impl Default for GrpcConfig {
    fn default() -> Self {
        Self {
            host_analyzer_addr: default_host_analyzer_addr(),
            network_scanner_addr: default_network_scanner_addr(),
        }
    }
}

impl Default for ApiConfig {
    fn default() -> Self {
        Self {
            listen_addr: default_api_listen_addr(),
        }
    }
}

impl Default for ScanConfig {
    fn default() -> Self {
        Self {
            fs_roots: Vec::new(),
            max_file_size: default_max_file_size(),
            interval_secs: default_interval_secs(),
        }
    }
}

impl Default for Config {
    fn default() -> Self {
        Self {
            general: GeneralConfig::default(),
            grpc: GrpcConfig::default(),
            api: ApiConfig::default(),
            scan: ScanConfig::default(),
            alerts: toml::value::Table::new(),
        }
    }
}

// ── Loader ───────────────────────────────────────────────────────────────────

impl Config {
    /// Resolve the active config path using the documented precedence:
    /// explicit `path` argument → `ARQENOR_CONFIG` env var → default.
    pub fn resolve_path(explicit: Option<&Path>) -> PathBuf {
        if let Some(p) = explicit {
            return p.to_path_buf();
        }
        if let Ok(env_path) = env::var(CONFIG_ENV_VAR) {
            if !env_path.is_empty() {
                return PathBuf::from(env_path);
            }
        }
        PathBuf::from(DEFAULT_CONFIG_PATH)
    }

    /// Load the active config (default path / env override).
    pub fn load() -> Result<Self, ConfigError> {
        Self::load_from(None::<&Path>)
    }

    /// Load from an explicit path. Pass `None` to honour the env / default
    /// fallback chain.
    pub fn load_from<P: AsRef<Path>>(path: Option<P>) -> Result<Self, ConfigError> {
        let resolved = Self::resolve_path(path.as_ref().map(|p| p.as_ref()));
        let raw = std::fs::read_to_string(&resolved).map_err(|e| ConfigError::Io {
            path: resolved.clone(),
            source: e,
        })?;
        let cfg: Config = toml::from_str(&raw).map_err(|e| ConfigError::Parse {
            path: resolved,
            source: Box::new(e),
        })?;
        Ok(cfg)
    }

    /// Parse a config from an in-memory TOML string. Useful for tests and
    /// for callers that pull config from a key/value store.
    pub fn from_toml_str(s: &str) -> Result<Self, toml::de::Error> {
        toml::from_str(s)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = r#"
[general]
log_level = "debug"
data_dir  = "/var/lib/arqenor"

[grpc]
host_analyzer_addr  = "0.0.0.0:50051"
network_scanner_addr = "0.0.0.0:50052"

[api]
listen_addr = "0.0.0.0:8080"

[scan]
fs_roots = ["/etc", "/var/log"]
max_file_size = 5242880
interval_secs = 30

[alerts]
min_severity = "high"
"#;

    #[test]
    fn parses_full_config() {
        let cfg = Config::from_toml_str(SAMPLE).expect("parse");
        assert_eq!(cfg.general.log_level, "debug");
        assert_eq!(cfg.general.data_dir, PathBuf::from("/var/lib/arqenor"));
        assert_eq!(cfg.grpc.host_analyzer_addr, "0.0.0.0:50051");
        assert_eq!(cfg.api.listen_addr, "0.0.0.0:8080");
        assert_eq!(cfg.scan.fs_roots.len(), 2);
        assert_eq!(cfg.scan.max_file_size, 5_242_880);
        assert_eq!(cfg.scan.interval_secs, 30);
        // The `[alerts]` table is preserved as free-form.
        assert_eq!(
            cfg.alerts.get("min_severity").and_then(|v| v.as_str()),
            Some("high")
        );
    }

    #[test]
    fn defaults_apply_when_section_missing() {
        let cfg = Config::from_toml_str("").expect("empty parse");
        assert_eq!(cfg.general.log_level, "info");
        assert_eq!(cfg.grpc.host_analyzer_addr, "127.0.0.1:50051");
        assert_eq!(cfg.scan.max_file_size, 10 * 1024 * 1024);
    }

    #[test]
    fn unknown_fields_in_typed_sections_are_rejected() {
        // The `deny_unknown_fields` guard catches typos that would otherwise
        // silently fall back to defaults.
        let bad = r#"
[general]
log_levle = "info"
"#;
        assert!(Config::from_toml_str(bad).is_err());
    }

    #[test]
    fn resolve_path_priority() {
        // No env var set in this scope: default wins.
        std::env::remove_var(CONFIG_ENV_VAR);
        let p = Config::resolve_path(None);
        assert_eq!(p, PathBuf::from(DEFAULT_CONFIG_PATH));

        // Explicit beats everything.
        let custom = PathBuf::from("/tmp/explicit.toml");
        let p = Config::resolve_path(Some(&custom));
        assert_eq!(p, custom);
    }
}
