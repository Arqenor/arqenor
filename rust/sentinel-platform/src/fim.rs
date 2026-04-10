use std::collections::HashMap;
use std::path::{Path, PathBuf};
use sha2::{Digest, Sha256};
use uuid::Uuid;
use sentinel_core::models::alert::{Alert, Severity};

// ---------------------------------------------------------------------------
// F1 — Baseline storage
// ---------------------------------------------------------------------------

pub struct FimBaseline {
    pub entries: HashMap<PathBuf, [u8; 32]>,
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

fn sha256_file(path: &Path) -> Option<[u8; 32]> {
    let bytes = std::fs::read(path).ok()?;
    let hash = Sha256::digest(&bytes);
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&hash);
    Some(arr)
}

fn make_alert(severity: Severity, path: &Path, reason: &str, attack_id: &str) -> Alert {
    let mut metadata = HashMap::new();
    metadata.insert("path".into(), path.to_string_lossy().into_owned());
    metadata.insert("reason".into(), reason.into());
    Alert {
        id:          Uuid::new_v4(),
        severity,
        kind:        "FIM".into(),
        message:     format!("[FIM] {} — {}", reason, path.display()),
        occurred_at: chrono::Utc::now(),
        metadata,
        rule_id:     Some("SENT-FIM".into()),
        attack_id:   Some(attack_id.into()),
    }
}

// ---------------------------------------------------------------------------
// F2 — Build baseline
// ---------------------------------------------------------------------------

pub fn build_baseline(paths: &[PathBuf]) -> FimBaseline {
    let mut entries = HashMap::new();
    for path in paths {
        if path.is_dir() {
            // Walk directory and hash every regular file inside
            if let Ok(walker) = walkdir::WalkDir::new(path)
                .follow_links(false)
                .into_iter()
                .collect::<Result<Vec<_>, _>>()
                .map(|v| v.into_iter())
            {
                for entry in walker {
                    let p = entry.path().to_path_buf();
                    if p.is_file() {
                        if let Some(hash) = sha256_file(&p) {
                            entries.insert(p, hash);
                        }
                    }
                }
            } else {
                // Partial walk — iterate tolerating errors
                for e in walkdir::WalkDir::new(path).follow_links(false).into_iter().flatten() {
                    let p = e.path().to_path_buf();
                    if p.is_file() {
                        if let Some(hash) = sha256_file(&p) {
                            entries.insert(p, hash);
                        }
                    }
                }
            }
        } else if path.is_file() {
            if let Some(hash) = sha256_file(path) {
                entries.insert(path.clone(), hash);
            }
        }
        // If path doesn't exist yet we just skip it — it'll appear as Created later
    }
    FimBaseline { entries }
}

// ---------------------------------------------------------------------------
// F3 — Check baseline and return alerts
// ---------------------------------------------------------------------------

pub struct FimAlert {
    pub path:   PathBuf,
    pub reason: FimAlertReason,
    pub alert:  Alert,
}

pub enum FimAlertReason {
    Modified,
    Deleted,
    Created,
}

pub fn check_baseline(baseline: &FimBaseline, watch_paths: &[PathBuf]) -> Vec<FimAlert> {
    let mut alerts = Vec::new();

    // --- Re-check every file already in the baseline ---
    for (path, &original_hash) in &baseline.entries {
        if !path.exists() {
            alerts.push(FimAlert {
                alert:  make_alert(Severity::Critical, path, "File deleted", "T1485"),
                path:   path.clone(),
                reason: FimAlertReason::Deleted,
            });
        } else if let Some(current_hash) = sha256_file(path) {
            if current_hash != original_hash {
                alerts.push(FimAlert {
                    alert:  make_alert(Severity::High, path, "File modified", "T1565.001"),
                    path:   path.clone(),
                    reason: FimAlertReason::Modified,
                });
            }
        }
        // If we can't read it now but it existed at baseline, skip (permission
        // issue; don't false-positive as deleted).
    }

    // --- Scan watch_paths for newly created files not present in baseline ---
    for watch_path in watch_paths {
        if watch_path.is_dir() {
            for e in walkdir::WalkDir::new(watch_path).follow_links(false).into_iter().flatten() {
                let p = e.path().to_path_buf();
                if p.is_file() && !baseline.entries.contains_key(&p) {
                    alerts.push(FimAlert {
                        alert:  make_alert(Severity::High, &p, "New file created", "T1036"),
                        path:   p.clone(),
                        reason: FimAlertReason::Created,
                    });
                }
            }
        } else {
            // Single-file watch path
            if watch_path.is_file() && !baseline.entries.contains_key(watch_path) {
                alerts.push(FimAlert {
                    alert:  make_alert(
                        Severity::High,
                        watch_path,
                        "New file created",
                        "T1036",
                    ),
                    path:   watch_path.clone(),
                    reason: FimAlertReason::Created,
                });
            }
        }
    }

    alerts
}

// ---------------------------------------------------------------------------
// F4 — Critical Windows paths
// ---------------------------------------------------------------------------

#[cfg(target_os = "windows")]
pub fn windows_critical_paths() -> Vec<PathBuf> {
    let sysroot = std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".to_string());
    vec![
        PathBuf::from(format!(r"{}\System32\lsass.exe", sysroot)),
        PathBuf::from(format!(r"{}\System32\ntdll.dll", sysroot)),
        PathBuf::from(format!(r"{}\System32\winlogon.exe", sysroot)),
        PathBuf::from(format!(r"{}\System32\drivers\etc\hosts", sysroot)),
        PathBuf::from(format!(r"{}\System32\sethc.exe", sysroot)),
        PathBuf::from(format!(r"{}\System32\utilman.exe", sysroot)),
    ]
}

// ---------------------------------------------------------------------------
// F5 — Critical Linux paths
// ---------------------------------------------------------------------------

#[cfg(target_os = "linux")]
pub fn linux_critical_paths() -> Vec<PathBuf> {
    vec![
        PathBuf::from("/etc/passwd"),
        PathBuf::from("/etc/shadow"),
        PathBuf::from("/etc/sudoers"),
        PathBuf::from("/etc/ssh/sshd_config"),
        PathBuf::from("/bin/su"),
        PathBuf::from("/usr/bin/sudo"),
    ]
}

// ---------------------------------------------------------------------------
// F6 — Critical macOS paths
// ---------------------------------------------------------------------------

#[cfg(target_os = "macos")]
pub fn macos_critical_paths() -> Vec<PathBuf> {
    let home = std::env::var("HOME").unwrap_or_else(|_| "/var/root".to_string());
    vec![
        PathBuf::from("/etc/hosts"),
        PathBuf::from("/etc/sudoers"),
        PathBuf::from("/etc/pam.d"),
        PathBuf::from("/etc/ssh/sshd_config"),
        PathBuf::from("/Library/LaunchDaemons"),
        PathBuf::from("/Library/LaunchAgents"),
        PathBuf::from("/Library/Security/SecurityAgentPlugins"),
        PathBuf::from(format!("{}/Library/LaunchAgents", home)),
        PathBuf::from("/usr/local/bin"),
    ]
}

// ---------------------------------------------------------------------------
// FimMonitor — public façade
// ---------------------------------------------------------------------------

pub struct FimMonitor {
    baseline: Option<FimBaseline>,
    paths:    Vec<PathBuf>,
}

impl FimMonitor {
    pub fn new() -> Self {
        Self { baseline: None, paths: Vec::new() }
    }

    pub fn with_paths(paths: Vec<PathBuf>) -> Self {
        Self { baseline: None, paths }
    }

    /// Build the initial baseline (call once at startup).
    pub fn init_baseline(&mut self) {
        self.baseline = Some(build_baseline(&self.paths));
    }

    /// Check for changes since the baseline was built. Returns alerts.
    pub fn check(&self) -> Vec<FimAlert> {
        match &self.baseline {
            Some(b) => check_baseline(b, &self.paths),
            None    => Vec::new(),
        }
    }

    /// Rebuild baseline (call after confirming changes are legitimate).
    pub fn rebuild_baseline(&mut self) {
        self.baseline = Some(build_baseline(&self.paths));
    }
}

impl Default for FimMonitor {
    fn default() -> Self {
        Self::new()
    }
}
