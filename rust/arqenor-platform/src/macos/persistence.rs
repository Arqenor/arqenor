use async_trait::async_trait;
use arqenor_core::{
    error::ArqenorError,
    models::persistence::{PersistenceEntry, PersistenceKind},
    traits::persistence::PersistenceDetector,
};
use std::{fs, path::Path};

#[cfg(target_os = "macos")]
use std::os::unix::fs::PermissionsExt;

pub struct MacosPersistenceDetector;

impl MacosPersistenceDetector {
    pub fn new() -> Self {
        Self
    }
}

// ── constants ────────────────────────────────────────────────────────────────

const LAUNCH_DIRS: &[(&str, PersistenceKind)] = &[
    ("/Library/LaunchDaemons",        PersistenceKind::LaunchDaemon),
    ("/Library/LaunchAgents",         PersistenceKind::LaunchAgent),
    ("/System/Library/LaunchDaemons", PersistenceKind::LaunchDaemon),
    ("/System/Library/LaunchAgents",  PersistenceKind::LaunchAgent),
];

/// Authorization-plugin bundles shipped with macOS or common Apple frameworks.
const KNOWN_AUTH_PLUGINS: &[&str] = &[
    "PKINITMechanism.bundle",
    "DiskUnlock.bundle",
    "CryptoTokenKit.bundle",
];

const PERIODIC_DIRS: &[&str] = &[
    "/etc/periodic/daily",
    "/etc/periodic/weekly",
    "/etc/periodic/monthly",
];

// ── helpers ──────────────────────────────────────────────────────────────────

fn user_launch_dirs() -> Vec<(String, PersistenceKind)> {
    if let Ok(home) = std::env::var("HOME") {
        vec![(
            format!("{}/Library/LaunchAgents", home),
            PersistenceKind::LaunchAgent,
        )]
    } else {
        vec![]
    }
}

/// Parse a macOS property-list file and extract the command that would be
/// executed.  Prefers `ProgramArguments` (array form); falls back to `Program`
/// (single-string form).
fn parse_plist_command(path: &Path) -> String {
    let val: plist::Value = match plist::from_file(path) {
        Ok(v) => v,
        Err(_) => return String::new(),
    };
    let dict = match val.as_dictionary() {
        Some(d) => d,
        None => return String::new(),
    };
    // ProgramArguments = ["/usr/bin/something", "--flag"]
    if let Some(args) = dict.get("ProgramArguments").and_then(|v| v.as_array()) {
        let cmd: Vec<&str> = args.iter().filter_map(|a| a.as_string()).collect();
        if !cmd.is_empty() {
            return cmd.join(" ");
        }
    }
    // Program = "/usr/bin/something"
    dict.get("Program")
        .and_then(|v| v.as_string())
        .unwrap_or("")
        .to_owned()
}

/// Extract scheduling / lifecycle context flags from a plist dict and return a
/// human-readable suffix string such as `" [RunAtLoad, KeepAlive]"`.
fn plist_context_flags(path: &Path) -> String {
    let val: plist::Value = match plist::from_file(path) {
        Ok(v) => v,
        Err(_) => return String::new(),
    };
    let dict = match val.as_dictionary() {
        Some(d) => d,
        None => return String::new(),
    };

    let mut flags: Vec<String> = Vec::new();

    if let Some(v) = dict.get("RunAtLoad").and_then(|v| v.as_boolean()) {
        if v {
            flags.push("RunAtLoad".into());
        }
    }
    if let Some(v) = dict.get("KeepAlive") {
        match v.as_boolean() {
            Some(true) => flags.push("KeepAlive".into()),
            _ => {
                // KeepAlive can also be a dict of conditions
                if v.as_dictionary().is_some() {
                    flags.push("KeepAlive(conditional)".into());
                }
            }
        }
    }
    if let Some(interval) = dict.get("StartInterval").and_then(|v| v.as_signed_integer()) {
        flags.push(format!("StartInterval={interval}s"));
    }

    if flags.is_empty() {
        String::new()
    } else {
        format!(" [{}]", flags.join(", "))
    }
}

// ── Launch Daemons / Agents  (ATT&CK T1543.004 / T1543.001) ─────────────────

/// Scan system and user LaunchDaemons / LaunchAgents directories.
/// For each `.plist` found, parse the binary/XML plist to extract the actual
/// command and scheduling flags, enriching the entry far beyond the filename.
fn detect_launch_items(entries: &mut Vec<PersistenceEntry>) {
    let static_dirs: Vec<(&str, &PersistenceKind)> =
        LAUNCH_DIRS.iter().map(|(p, k)| (*p, k)).collect();

    let user_dirs = user_launch_dirs();
    let dynamic_dirs: Vec<(&str, &PersistenceKind)> =
        user_dirs.iter().map(|(p, k)| (p.as_str(), k)).collect();

    for (dir, kind) in static_dirs.into_iter().chain(dynamic_dirs) {
        let path = Path::new(dir);
        if !path.exists() {
            continue;
        }
        let rd = match fs::read_dir(path) {
            Ok(r) => r,
            Err(_) => continue,
        };
        for entry in rd.filter_map(|e| e.ok()) {
            let file_name = entry.file_name().to_string_lossy().into_owned();
            if !file_name.ends_with(".plist") {
                continue;
            }

            let file_path = entry.path();
            let command = parse_plist_command(&file_path);
            let context = plist_context_flags(&file_path);
            let display_name = format!("{file_name}{context}");

            entries.push(PersistenceEntry {
                kind:     kind.clone(),
                name:     display_name,
                command,
                location: file_path.to_string_lossy().into_owned(),
                is_new:   false,
            });
        }
    }
}

// ── Login Items / BTM  (ATT&CK T1547.015) ───────────────────────────────────

/// Detect macOS Background Task Management (BTM) login items and disabled
/// launch services.
///
/// ATT&CK T1547.015 — Boot or Logon Autostart Execution: Login Items.
///
/// The `backgrounditems.btm` file is a binary plist that tracks app-registered
/// login items.  Full parsing of the nested `LSSharedFileList` structure is
/// non-trivial, so we flag the file's existence and last-modification time as a
/// starting point for manual triage.
///
/// Additionally, `/var/db/com.apple.xpc.launchd/disabled.*.plist` files list
/// services that the user or system has explicitly disabled — useful context
/// when correlating which launch items are active.
fn detect_login_items(entries: &mut Vec<PersistenceEntry>) {
    // ── backgrounditems.btm ──
    if let Ok(home) = std::env::var("HOME") {
        let btm_path = format!(
            "{}/Library/Application Support/com.apple.backgroundtaskmanagementagent/backgrounditems.btm",
            home
        );
        let btm = Path::new(&btm_path);
        if btm.exists() {
            let mod_time = fs::metadata(btm)
                .and_then(|m| m.modified())
                .map(|t| {
                    let elapsed = t.elapsed().unwrap_or_default();
                    format!("modified {}s ago", elapsed.as_secs())
                })
                .unwrap_or_else(|_| "modification time unavailable".into());

            entries.push(PersistenceEntry {
                kind:     PersistenceKind::Unknown("LoginItem".into()),
                name:     format!("backgrounditems.btm ({mod_time})"),
                command:  String::new(),
                location: btm_path,
                is_new:   false,
            });
        }
    }

    // ── disabled.*.plist in /var/db/com.apple.xpc.launchd/ ──
    let disabled_dir = Path::new("/var/db/com.apple.xpc.launchd");
    if disabled_dir.exists() {
        if let Ok(rd) = fs::read_dir(disabled_dir) {
            for de in rd.filter_map(|e| e.ok()) {
                let name = de.file_name().to_string_lossy().into_owned();
                if name.starts_with("disabled.") && name.ends_with(".plist") {
                    entries.push(PersistenceEntry {
                        kind:     PersistenceKind::Unknown("LoginItem".into()),
                        name:     format!("disabled-services: {name}"),
                        command:  String::new(),
                        location: de.path().to_string_lossy().into_owned(),
                        is_new:   false,
                    });
                }
            }
        }
    }
}

// ── Cron Tabs  (ATT&CK T1053.003) ───────────────────────────────────────────

/// Detect per-user crontab files and the system-wide `/etc/crontab`.
///
/// ATT&CK T1053.003 — Scheduled Task/Job: Cron.
///
/// On macOS the per-user crontab spool lives under `/usr/lib/cron/tabs/`
/// (or `/var/at/tabs/` on some versions).  Each file is named after the user.
fn detect_cron_tabs(entries: &mut Vec<PersistenceEntry>) {
    const CRON_SPOOL_DIRS: &[&str] = &[
        "/usr/lib/cron/tabs",
        "/var/at/tabs",
    ];

    for spool in CRON_SPOOL_DIRS {
        let spool_path = Path::new(spool);
        if !spool_path.exists() {
            continue;
        }
        if let Ok(rd) = fs::read_dir(spool_path) {
            for de in rd.filter_map(|e| e.ok()) {
                let username = de.file_name().to_string_lossy().into_owned();
                let content = fs::read_to_string(de.path()).unwrap_or_default();
                let line_count = content
                    .lines()
                    .filter(|l| {
                        let trimmed = l.trim();
                        !trimmed.is_empty() && !trimmed.starts_with('#')
                    })
                    .count();

                entries.push(PersistenceEntry {
                    kind:     PersistenceKind::Cron,
                    name:     format!("crontab user={username} ({line_count} entries)"),
                    command:  String::new(),
                    location: de.path().to_string_lossy().into_owned(),
                    is_new:   false,
                });
            }
        }
    }

    // /etc/crontab — system-wide
    let etc_crontab = Path::new("/etc/crontab");
    if etc_crontab.exists() {
        let content = fs::read_to_string(etc_crontab).unwrap_or_default();
        let line_count = content
            .lines()
            .filter(|l| {
                let trimmed = l.trim();
                !trimmed.is_empty() && !trimmed.starts_with('#')
            })
            .count();

        entries.push(PersistenceEntry {
            kind:     PersistenceKind::Cron,
            name:     format!("/etc/crontab ({line_count} entries)"),
            command:  String::new(),
            location: "/etc/crontab".into(),
            is_new:   false,
        });
    }
}

// ── Authorization Plugins  (ATT&CK T1547.002) ───────────────────────────────

/// Detect non-default macOS Authorization (SecurityAgent) plug-in bundles.
///
/// ATT&CK T1547.002 — Boot or Logon Autostart Execution: Authentication Package.
///
/// Bundles in `/Library/Security/SecurityAgentPlugins/` that are not in the
/// known-good list are flagged.  Malicious plug-ins execute code during the
/// authentication flow (e.g. at login or on screen-unlock).
fn detect_authorization_plugins(entries: &mut Vec<PersistenceEntry>) {
    let plugins_dir = Path::new("/Library/Security/SecurityAgentPlugins");
    if !plugins_dir.exists() {
        return;
    }
    let rd = match fs::read_dir(plugins_dir) {
        Ok(r) => r,
        Err(_) => return,
    };

    for de in rd.filter_map(|e| e.ok()) {
        let name = de.file_name().to_string_lossy().into_owned();
        if !name.ends_with(".bundle") {
            continue;
        }
        if KNOWN_AUTH_PLUGINS.contains(&name.as_str()) {
            continue;
        }

        entries.push(PersistenceEntry {
            kind:     PersistenceKind::Unknown("AuthorizationPlugin".into()),
            name:     name,
            command:  String::new(),
            location: de.path().to_string_lossy().into_owned(),
            is_new:   false,
        });
    }
}

// ── Periodic Scripts  (ATT&CK T1053.003) ────────────────────────────────────

/// Detect executable scripts in `/etc/periodic/{daily,weekly,monthly}`.
///
/// ATT&CK T1053.003 — Scheduled Task/Job: Cron.
///
/// macOS runs `periodic(8)` via a LaunchDaemon, which in turn sources every
/// executable file in these directories.  Dropping a script here provides
/// reliable recurring execution.
fn detect_periodic_scripts(entries: &mut Vec<PersistenceEntry>) {
    for dir in PERIODIC_DIRS {
        let path = Path::new(dir);
        if !path.exists() {
            continue;
        }
        let rd = match fs::read_dir(path) {
            Ok(r) => r,
            Err(_) => continue,
        };

        for de in rd.filter_map(|e| e.ok()) {
            let file_path = de.path();

            // Only flag files that are executable
            #[cfg(target_os = "macos")]
            {
                if let Ok(meta) = fs::metadata(&file_path) {
                    let mode = meta.permissions().mode();
                    if mode & 0o111 == 0 {
                        continue; // not executable
                    }
                } else {
                    continue;
                }
            }

            // On non-macOS (compile gate) accept everything — this code will
            // never actually run there, but keeps the module compilable for
            // tests / CI on Linux.
            #[cfg(not(target_os = "macos"))]
            {
                if let Ok(meta) = fs::metadata(&file_path) {
                    if !meta.is_file() {
                        continue;
                    }
                } else {
                    continue;
                }
            }

            let file_name = de.file_name().to_string_lossy().into_owned();
            let period = Path::new(dir)
                .file_name()
                .map(|s| s.to_string_lossy().into_owned())
                .unwrap_or_default();

            entries.push(PersistenceEntry {
                kind:     PersistenceKind::Cron,
                name:     format!("periodic/{period}: {file_name}"),
                command:  String::new(),
                location: file_path.to_string_lossy().into_owned(),
                is_new:   false,
            });
        }
    }
}

// ── DYLD Injection  (ATT&CK T1574.004) ──────────────────────────────────────

/// Detect DYLD_INSERT_LIBRARIES-based dylib injection.
///
/// ATT&CK T1574.004 — Hijack Execution Flow: Dylib Hijacking.
///
/// Checks:
/// 1. The `DYLD_INSERT_LIBRARIES` environment variable (analogous to Linux
///    `LD_PRELOAD`).
/// 2. `/etc/launchd.conf`, which can set environment variables (including
///    DYLD_ vars) for every process spawned by launchd — a system-wide
///    persistence vector.
fn detect_dylib_hijacking(entries: &mut Vec<PersistenceEntry>) {
    // ── env var ──
    if let Ok(val) = std::env::var("DYLD_INSERT_LIBRARIES") {
        if !val.is_empty() {
            entries.push(PersistenceEntry {
                kind:     PersistenceKind::Unknown("DylibHijack".into()),
                name:     "DYLD_INSERT_LIBRARIES".into(),
                command:  val,
                location: "environment".into(),
                is_new:   false,
            });
        }
    }

    // ── /etc/launchd.conf ──
    let launchd_conf = Path::new("/etc/launchd.conf");
    if launchd_conf.exists() {
        let content = fs::read_to_string(launchd_conf).unwrap_or_default();
        for line in content.lines() {
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }
            // Flag any line that references a DYLD_ variable
            if trimmed.contains("DYLD_") {
                entries.push(PersistenceEntry {
                    kind:     PersistenceKind::Unknown("DylibHijack".into()),
                    name:     format!("launchd.conf DYLD entry"),
                    command:  trimmed.to_owned(),
                    location: "/etc/launchd.conf".into(),
                    is_new:   false,
                });
            }
        }
    }
}

// ── trait impl ───────────────────────────────────────────────────────────────

#[async_trait]
impl PersistenceDetector for MacosPersistenceDetector {
    async fn detect(&self) -> Result<Vec<PersistenceEntry>, ArqenorError> {
        let mut entries = Vec::new();

        detect_launch_items(&mut entries);           // LaunchDaemons/Agents — T1543.004
        detect_login_items(&mut entries);            // BTM login items      — T1547.015
        detect_cron_tabs(&mut entries);              // crontab files        — T1053.003
        detect_authorization_plugins(&mut entries);  // SecurityAgent plugins — T1547.002
        detect_periodic_scripts(&mut entries);       // periodic(8) scripts  — T1053.003
        detect_dylib_hijacking(&mut entries);        // DYLD injection       — T1574.004

        Ok(entries)
    }

    async fn diff_baseline(
        &self,
        baseline: &[PersistenceEntry],
    ) -> Result<Vec<PersistenceEntry>, ArqenorError> {
        let current = self.detect().await?;
        Ok(current
            .into_iter()
            .filter(|e| !baseline.iter().any(|b| b.name == e.name && b.location == e.location))
            .map(|mut e| {
                e.is_new = true;
                e
            })
            .collect())
    }
}
