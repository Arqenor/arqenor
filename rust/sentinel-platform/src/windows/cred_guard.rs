// ── Section E: Credential Theft Detection ────────────────────────────────────
//
// Implements Phase-1 credential-theft and ransomware-signal detection for
// Windows hosts.  All functions are gated on #[cfg(windows)].

use chrono::Utc;
use std::collections::HashMap;
use uuid::Uuid;

use sentinel_core::models::alert::{Alert, Severity};

// ── Helper ────────────────────────────────────────────────────────────────────

fn make_alert(
    severity: Severity,
    kind: &str,
    message: String,
    attack_id: &str,
    meta: HashMap<String, String>,
) -> Alert {
    Alert {
        id:          Uuid::new_v4(),
        severity,
        kind:        kind.to_string(),
        message,
        occurred_at: Utc::now(),
        metadata:    meta,
        rule_id:     None,
        attack_id:   Some(attack_id.to_string()),
    }
}

// ── E1 — LSASS Handle Scan (T1003.001) ───────────────────────────────────────
//
// Full handle enumeration via NtQuerySystemInformation (SystemHandleInformation)
// is Phase-2+ complexity: it requires an undocumented NT syscall, a variable-
// length output buffer, and per-handle OpenProcess/DuplicateHandle cycles that
// need SE_DEBUG_PRIVILEGE.
//
// For Phase 1 we detect the *processes* most likely to be performing LSASS
// memory reads by cross-referencing the running process list against a set of
// known credential-dumping binaries (see E2) and a path-based heuristic below.

#[cfg(windows)]
pub fn scan_lsass_handles(sys: &sysinfo::System) -> Vec<Alert> {
    // TODO Phase-2: implement via NtQuerySystemInformation / SystemHandleInformation.
    // Requires SE_DEBUG_PRIVILEGE and iterating every system handle to find ones
    // targeting the lsass.exe process object with PROCESS_VM_READ access.
    let _ = sys; // parameter accepted so the public API is stable
    Vec::new()
}

// ── E2 — Known Credential-Dumping Tools (T1003.001 / T1003) ──────────────────

const CRED_DUMP_NAMES: &[&str] = &[
    "mimikatz.exe",
    "procdump.exe",
    "procdump64.exe",
    "nanodump.exe",
    "wce.exe",
    "pwdump.exe",
    "pwdump7.exe",
    "fgdump.exe",
    "gsecdump.exe",
    "safetykatz.exe",
    "sharpdump.exe",
    "crackmapexec.exe",
];

const CRED_DUMP_CMDLINE_TOKENS: &[&str] = &[
    "sekurlsa",
    "lsadump",
    "dcsync",
    "logonpasswords",
];

#[cfg(windows)]
pub fn detect_cred_tools(sys: &sysinfo::System) -> Vec<Alert> {
    let mut alerts = Vec::new();

    for (_pid, process) in sys.processes() {
        let name_lc = process.name().to_lowercase();
        let cmdline  = process.cmd().join(" ");
        let cmdline_lc = cmdline.to_lowercase();

        let name_hit = CRED_DUMP_NAMES
            .iter()
            .any(|&known| name_lc == known.to_lowercase());

        let cmd_hit = CRED_DUMP_CMDLINE_TOKENS
            .iter()
            .any(|&token| cmdline_lc.contains(token));

        if name_hit || cmd_hit {
            let pid_val = usize::from(*_pid) as u32;
            let exe = process
                .exe()
                .map(|p| p.to_string_lossy().into_owned())
                .unwrap_or_else(|| "<unknown>".to_string());

            let reason = if name_hit {
                format!("Process name matches known credential dumping tool: {}", process.name())
            } else {
                format!(
                    "Process cmdline contains credential dumping keyword: {}",
                    cmdline
                        .split_whitespace()
                        .find(|tok| {
                            CRED_DUMP_CMDLINE_TOKENS
                                .iter()
                                .any(|&k| tok.to_lowercase().contains(k))
                        })
                        .unwrap_or("<unknown token>")
                )
            };

            let mut meta = HashMap::new();
            meta.insert("pid".to_string(),      pid_val.to_string());
            meta.insert("process_name".to_string(), process.name().to_string());
            meta.insert("exe_path".to_string(), exe);
            meta.insert("cmdline".to_string(),  cmdline);

            alerts.push(make_alert(
                Severity::Critical,
                "CredentialDumper",
                reason,
                "T1003.001",
                meta,
            ));
        }
    }

    alerts
}

// ── E3 — SAM / SYSTEM / SECURITY Hive Dump (T1003.002) ───────────────────────
//
// Attackers dump the SAM hive offline with commands such as:
//   reg save HKLM\SAM C:\temp\sam.hive
// Detect these by inspecting the cmdline of every running process.

const SAM_DUMP_PATTERNS: &[&str] = &[
    r"save HKLM\SAM",
    r"save HKLM\SYSTEM",
    r"save HKLM\SECURITY",
    // case-insensitive variants handled below
    r"save hklm\sam",
    r"save hklm\system",
    r"save hklm\security",
];

#[cfg(windows)]
pub fn detect_sam_dump(sys: &sysinfo::System) -> Vec<Alert> {
    let mut alerts = Vec::new();

    for (_pid, process) in sys.processes() {
        let cmdline    = process.cmd().join(" ");
        let cmdline_lc = cmdline.to_lowercase();

        let hit = SAM_DUMP_PATTERNS
            .iter()
            .any(|&pat| cmdline_lc.contains(&pat.to_lowercase()));

        if hit {
            let pid_val = usize::from(*_pid) as u32;
            let mut meta = HashMap::new();
            meta.insert("pid".to_string(),      pid_val.to_string());
            meta.insert("process_name".to_string(), process.name().to_string());
            meta.insert("cmdline".to_string(),  cmdline.clone());

            alerts.push(make_alert(
                Severity::High,
                "SamHiveDump",
                format!("SAM/SYSTEM/SECURITY hive dump detected via cmdline: {}", cmdline),
                "T1003.002",
                meta,
            ));
        }
    }

    alerts
}

// ── E4 — Browser Credential Access (T1555.003) ────────────────────────────────
//
// Detecting direct access to browser credential stores (e.g. Chrome's
// `Login Data` SQLite file) requires file-open event telemetry.  On Windows
// this is available via ETW (the Microsoft-Windows-Kernel-File provider) or a
// minifilter driver — neither of which is available in a user-mode Phase-1
// agent without a kernel component.
//
// TODO Phase-2: subscribe to the Microsoft-Windows-Kernel-File ETW provider
//              and raise an alert when a non-browser process opens known
//              browser credential paths.

pub fn detect_browser_cred_access() -> Vec<Alert> {
    // Stub — requires ETW or minifilter driver for file-open event monitoring.
    Vec::new()
}

// ── E5 — Ransomware Pre-encryption Signals (T1490) ────────────────────────────
//
// Ransomware families destroy backups and shadow copies before encrypting.
// Detect the most common command patterns in running process cmdlines.

#[derive(Clone)]
struct RansomPattern {
    process_token: &'static str,
    cmdline_token: &'static str,
    severity:      Severity,
    description:   &'static str,
}

const RANSOM_PATTERNS: &[RansomPattern] = &[
    RansomPattern {
        process_token: "vssadmin",
        cmdline_token: "delete shadows",
        severity:      Severity::Critical,
        description:   "VSS shadow copy deletion — common ransomware pre-encryption step",
    },
    RansomPattern {
        process_token: "bcdedit",
        cmdline_token: "recoveryenabled",
        severity:      Severity::Critical,
        description:   "Boot recovery disabled via bcdedit — common ransomware pre-encryption step",
    },
    RansomPattern {
        process_token: "wbadmin",
        cmdline_token: "delete systemstatebackup",
        severity:      Severity::Critical,
        description:   "System state backup deletion via wbadmin",
    },
    RansomPattern {
        process_token: "wmic",
        cmdline_token: "shadowcopy delete",
        severity:      Severity::Critical,
        description:   "VSS shadow copy deletion via WMIC",
    },
    RansomPattern {
        process_token: "cipher",
        cmdline_token: "/w:",
        severity:      Severity::High,
        description:   "cipher /w: free-space wipe — potential ransomware evidence destruction",
    },
];

#[cfg(windows)]
pub fn detect_ransomware_signals(sys: &sysinfo::System) -> Vec<Alert> {
    let mut alerts = Vec::new();

    for (_pid, process) in sys.processes() {
        let name_lc    = process.name().to_lowercase();
        let cmdline    = process.cmd().join(" ");
        let cmdline_lc = cmdline.to_lowercase();

        for pattern in RANSOM_PATTERNS {
            if name_lc.contains(pattern.process_token)
                && cmdline_lc.contains(pattern.cmdline_token)
            {
                let pid_val = usize::from(*_pid) as u32;
                let mut meta = HashMap::new();
                meta.insert("pid".to_string(),          pid_val.to_string());
                meta.insert("process_name".to_string(), process.name().to_string());
                meta.insert("cmdline".to_string(),      cmdline.clone());

                alerts.push(make_alert(
                    pattern.severity.clone(),
                    "RansomwareSignal",
                    pattern.description.to_string(),
                    "T1490",
                    meta,
                ));

                // One alert per process per pattern is sufficient.
                break;
            }
        }
    }

    alerts
}

// ── E6 — AMSI Bypass Detection (T1562.001) ────────────────────────────────────
//
// Checks whether the `AmsiScanBuffer` function in the in-process copy of
// amsi.dll has been patched (e.g. with `mov eax, 0x80070057; ret` — the classic
// AMSI bypass written by Matt Graeber et al.).
//
// If amsi.dll is not loaded in this process the check is silently skipped and
// an empty Vec is returned.
//
// The expected 7-byte prologue for AmsiScanBuffer on Windows 10/11 x64 is:
//   4C 8B DC       mov r11, rsp
//   49 89 5B 08    mov [r11+08], rbx
// If the first bytes differ the function has been patched.

#[cfg(windows)]
pub fn check_amsi_integrity() -> Vec<Alert> {
    // Declare the two WinAPI functions we need directly so we don't depend on
    // a `LibraryLoader` windows-crate feature that isn't in the workspace
    // feature list.
    #[link(name = "kernel32")]
    extern "system" {
        fn GetModuleHandleA(lpModuleName: *const u8) -> *mut std::ffi::c_void;
        fn GetProcAddress(
            hModule: *mut std::ffi::c_void,
            lpProcName: *const u8,
        ) -> *mut std::ffi::c_void;
    }

    // Expected x64 function prologue for AmsiScanBuffer (Windows 10/11 21H2+).
    // Bytes: mov r11,rsp | mov [r11+08],rbx
    const EXPECTED: [u8; 7] = [0x4C, 0x8B, 0xDC, 0x49, 0x89, 0x5B, 0x08];

    unsafe {
        let module_name = b"amsi.dll\0";
        let hmod = GetModuleHandleA(module_name.as_ptr());
        if hmod.is_null() {
            // amsi.dll is not loaded in this process — nothing to check.
            return Vec::new();
        }

        let proc_name = b"AmsiScanBuffer\0";
        let fn_ptr = GetProcAddress(hmod, proc_name.as_ptr());
        if fn_ptr.is_null() {
            // Shouldn't happen if the module is loaded, but handle gracefully.
            return Vec::new();
        }

        // Read the first 7 bytes of the function.
        let actual: &[u8] = std::slice::from_raw_parts(fn_ptr as *const u8, EXPECTED.len());

        if actual != EXPECTED {
            let expected_hex = EXPECTED
                .iter()
                .map(|b| format!("{:02X}", b))
                .collect::<Vec<_>>()
                .join(" ");
            let actual_hex = actual
                .iter()
                .map(|b| format!("{:02X}", b))
                .collect::<Vec<_>>()
                .join(" ");

            let mut meta = HashMap::new();
            meta.insert("expected_bytes".to_string(), expected_hex);
            meta.insert("actual_bytes".to_string(),   actual_hex);
            meta.insert(
                "fn_address".to_string(),
                format!("{:#018x}", fn_ptr as usize),
            );

            return vec![make_alert(
                Severity::Critical,
                "AmsiBypass",
                format!(
                    "AmsiScanBuffer prologue patched — AMSI bypass detected. \
                     Expected: {} | Got: {}",
                    meta["expected_bytes"], meta["actual_bytes"]
                ),
                "T1562.001",
                meta,
            )];
        }
    }

    Vec::new()
}

// ── Public Struct ─────────────────────────────────────────────────────────────

pub struct CredGuard;

impl CredGuard {
    pub fn new() -> Self {
        Self
    }

    pub fn scan(&self) -> Vec<Alert> {
        let mut sys = sysinfo::System::new_all();
        sys.refresh_all();

        let mut alerts = Vec::new();

        #[cfg(windows)]
        {
            alerts.extend(scan_lsass_handles(&sys));
            alerts.extend(detect_cred_tools(&sys));
            alerts.extend(detect_sam_dump(&sys));
            alerts.extend(detect_browser_cred_access());
            alerts.extend(detect_ransomware_signals(&sys));
            alerts.extend(check_amsi_integrity());
        }

        alerts
    }
}

impl Default for CredGuard {
    fn default() -> Self {
        Self::new()
    }
}
