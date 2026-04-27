// ── Section E: Credential Theft Detection ────────────────────────────────────
//
// Implements Phase-1 credential-theft and ransomware-signal detection for
// Windows hosts.  All functions are gated on #[cfg(windows)].

use chrono::Utc;
use std::collections::HashMap;
use uuid::Uuid;

use arqenor_core::models::alert::{Alert, Severity};

// ── Helper ────────────────────────────────────────────────────────────────────

fn make_alert(
    severity: Severity,
    kind: &str,
    message: String,
    attack_id: &str,
    meta: HashMap<String, String>,
) -> Alert {
    Alert {
        id: Uuid::new_v4(),
        severity,
        kind: kind.to_string(),
        message,
        occurred_at: Utc::now(),
        metadata: meta,
        rule_id: None,
        attack_id: Some(attack_id.to_string()),
    }
}

/// Join a `sysinfo::Process` command line into a single display string.
///
/// `sysinfo` 0.31+ returns `&[OsString]` from `Process::cmd()`, so we lossily
/// convert each argument and join with spaces.
#[cfg(windows)]
fn join_cmd(process: &sysinfo::Process) -> String {
    process
        .cmd()
        .iter()
        .map(|arg| arg.to_string_lossy().into_owned())
        .collect::<Vec<_>>()
        .join(" ")
}

// ── E1 — LSASS Handle Scan (T1003.001) ───────────────────────────────────────
//
// Detects userspace processes holding open handles to `lsass.exe` with an
// access mask that allows credential extraction (PROCESS_VM_READ /
// PROCESS_VM_OPERATION / PROCESS_DUP_HANDLE — the canonical mimikatz /
// nanodump / pypykatz combo).
//
// Pipeline:
//   1. Resolve `lsass.exe`'s PID from `sysinfo`.
//   2. Open lsass with `PROCESS_QUERY_LIMITED_INFORMATION` (no privilege
//      escalation needed, but on hardened hosts even this can fail — we
//      degrade to an empty result rather than panic).
//   3. Snapshot the global handle table via
//      `NtQuerySystemInformation(SystemExtendedHandleInformation)`, retrying
//      with an exponentially-growing buffer on `STATUS_INFO_LENGTH_MISMATCH`.
//   4. Locate the entry whose holder is us and whose `HandleValue` matches the
//      lsass handle we just opened — the `Object` pointer in that entry is
//      lsass's kernel object address.
//   5. Iterate every entry; alert when `Object == lsass_object`, the holder is
//      neither us nor lsass itself, the granted access mask includes a
//      credential-dumping right, and the holder's image name is not on the
//      allowlist of trusted system / EDR processes.
//
// Privileges:
//   - `NtQuerySystemInformation` requires no special right but truncates
//     entries the caller has no right to see.  Without `SE_DEBUG_PRIVILEGE`
//     we still see all *user-mode* holders, which is the population that
//     matters for detecting offensive tooling.
//
// Alerts carry the holder's PID + image name + decoded access mask in
// metadata so downstream rules can correlate against process-creation events.

#[cfg(windows)]
mod handle_scan {
    use std::ffi::c_void;

    pub(super) const PROCESS_VM_READ: u32 = 0x0010;
    pub(super) const PROCESS_VM_OPERATION: u32 = 0x0008;
    pub(super) const PROCESS_DUP_HANDLE: u32 = 0x0040;
    /// `OpenProcess` with this right is what mimikatz / nanodump request.
    pub(super) const DANGEROUS_ACCESS_MASK: u32 =
        PROCESS_VM_READ | PROCESS_VM_OPERATION | PROCESS_DUP_HANDLE;

    const SYSTEM_EXTENDED_HANDLE_INFORMATION: u32 = 64;
    const STATUS_SUCCESS: i32 = 0;
    /// `STATUS_INFO_LENGTH_MISMATCH` (0xC0000004) — buffer was too small.
    const STATUS_INFO_LENGTH_MISMATCH: i32 = 0xC000_0004u32 as i32;

    /// `PROCESS_QUERY_LIMITED_INFORMATION` — minimal right that still lets us
    /// `OpenProcess` lsass under a non-elevated token on most hosts.
    const PROCESS_QUERY_LIMITED_INFORMATION: u32 = 0x1000;

    /// Mirror of `SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX` (winternl.h).
    /// 40 bytes on x64; we use `read_unaligned` so misaligned buffers are safe.
    #[repr(C)]
    #[derive(Clone, Copy)]
    struct SystemHandleTableEntryInfoEx {
        object: *mut c_void,
        unique_process_id: usize,
        handle_value: usize,
        granted_access: u32,
        creator_back_trace_index: u16,
        object_type_index: u16,
        handle_attributes: u32,
        reserved: u32,
    }

    #[link(name = "ntdll")]
    extern "system" {
        fn NtQuerySystemInformation(
            system_information_class: u32,
            system_information: *mut c_void,
            system_information_length: u32,
            return_length: *mut u32,
        ) -> i32;
    }

    #[link(name = "kernel32")]
    extern "system" {
        fn GetCurrentProcessId() -> u32;
        fn OpenProcess(desired_access: u32, inherit_handle: i32, process_id: u32) -> *mut c_void;
        fn CloseHandle(h: *mut c_void) -> i32;
        fn QueryFullProcessImageNameW(
            h: *mut c_void,
            flags: u32,
            buf: *mut u16,
            size: *mut u32,
        ) -> i32;
        fn GetProcessTimes(
            h: *mut c_void,
            creation: *mut FileTime,
            exit: *mut FileTime,
            kernel: *mut FileTime,
            user: *mut FileTime,
        ) -> i32;
    }

    /// Win32 `FILETIME` mirrored locally so we don't need a `windows` crate
    /// import inside the inner module.
    #[repr(C)]
    #[derive(Clone, Copy, Default)]
    pub(super) struct FileTime {
        low: u32,
        high: u32,
    }

    impl FileTime {
        fn as_u64(self) -> u64 {
            ((self.high as u64) << 32) | (self.low as u64)
        }
    }

    /// Snapshot of identity bits we capture *at handle-enumeration time* so
    /// we can later detect PID reuse before correlating an entry with a
    /// `sysinfo` lookup.
    #[derive(Debug, Clone, Default)]
    pub(super) struct ProcessIdentity {
        pub exe_path: Option<String>,
        /// `FILETIME` from `GetProcessTimes` (CreationTime). 0 if unknown.
        pub creation_time: u64,
    }

    /// One handle-table entry, projected to the bits we care about.
    ///
    /// Carries a snapshot of the holder's identity captured at enumeration
    /// time — we re-read these values when we go to alert and refuse to
    /// emit if the PID has been recycled into a different process.
    #[derive(Debug, Clone)]
    pub(super) struct HandleEntry {
        pub object: usize,
        pub holder_pid: u32,
        pub handle_value: usize,
        pub granted_access: u32,
        pub identity: ProcessIdentity,
    }

    /// Snapshot the global handle table.  Returns an empty `Vec` if the
    /// syscall fails — callers must treat that as "no result" rather than
    /// "no holders".
    pub(super) fn enumerate_system_handles() -> Vec<HandleEntry> {
        // 1 MiB initial; double on STATUS_INFO_LENGTH_MISMATCH up to 256 MiB.
        let mut buf_size: usize = 1024 * 1024;
        const MAX_BUF: usize = 256 * 1024 * 1024;

        loop {
            let mut buf: Vec<u8> = vec![0u8; buf_size];
            let mut return_length: u32 = 0;
            // SAFETY: buf is a contiguous u8 array of known length `buf_size`,
            // ntdll writes at most `buf_size` bytes into it.
            let status = unsafe {
                NtQuerySystemInformation(
                    SYSTEM_EXTENDED_HANDLE_INFORMATION,
                    buf.as_mut_ptr() as *mut c_void,
                    buf_size as u32,
                    &mut return_length,
                )
            };

            if status == STATUS_INFO_LENGTH_MISMATCH {
                if buf_size >= MAX_BUF {
                    return Vec::new();
                }
                buf_size = (buf_size * 2).min(MAX_BUF);
                continue;
            }
            if status != STATUS_SUCCESS {
                return Vec::new();
            }

            return parse_handle_table(&buf[..return_length as usize]);
        }
    }

    /// Decode a `SYSTEM_HANDLE_INFORMATION_EX` byte buffer into our entries.
    /// All reads are unaligned because the buffer is `Vec<u8>`-allocated.
    ///
    /// Captures a per-PID identity snapshot (exe path + creation time) so
    /// downstream lookups can reject any entry whose PID has been recycled
    /// before the alert is emitted (TOCTOU defence).
    fn parse_handle_table(buf: &[u8]) -> Vec<HandleEntry> {
        let usize_sz = std::mem::size_of::<usize>();
        let header_sz = 2 * usize_sz; // NumberOfHandles + Reserved
        if buf.len() < header_sz {
            return Vec::new();
        }
        // SAFETY: read at offset 0; bounds verified above.
        let raw_count = unsafe { std::ptr::read_unaligned(buf.as_ptr() as *const usize) };

        let entry_sz = std::mem::size_of::<SystemHandleTableEntryInfoEx>();
        let entries_avail = (buf.len() - header_sz) / entry_sz;
        let count = raw_count.min(entries_avail);

        // Memoise per-PID identity so we don't re-open the same process
        // dozens of times (handle tables on busy hosts have lots of
        // duplication on a handful of PIDs).
        let mut identity_cache: std::collections::HashMap<u32, ProcessIdentity> =
            std::collections::HashMap::new();

        let mut out = Vec::with_capacity(count);
        for i in 0..count {
            let offset = header_sz + i * entry_sz;
            // SAFETY: offset + entry_sz <= buf.len() by construction.
            let entry: SystemHandleTableEntryInfoEx =
                unsafe { std::ptr::read_unaligned(buf.as_ptr().add(offset) as *const _) };
            let pid = entry.unique_process_id as u32;
            let identity = identity_cache
                .entry(pid)
                .or_insert_with(|| capture_process_identity(pid))
                .clone();
            out.push(HandleEntry {
                object: entry.object as usize,
                holder_pid: pid,
                handle_value: entry.handle_value,
                granted_access: entry.granted_access,
                identity,
            });
        }
        out
    }

    /// Capture exe path + creation time for `pid` via
    /// `OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION)` — the minimal access
    /// right that works under non-elevated tokens and against most PPL
    /// processes. Failures (PPL with denied access, kernel pids) yield an
    /// empty identity rather than panicking.
    pub(super) fn capture_process_identity(pid: u32) -> ProcessIdentity {
        if pid == 0 {
            return ProcessIdentity::default();
        }
        // SAFETY: pid is a u32; OpenProcess returns null on failure.
        let h = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
        if h.is_null() {
            return ProcessIdentity::default();
        }

        let exe_path = {
            let mut buf = [0u16; 1024];
            let mut size = buf.len() as u32;
            // SAFETY: handle is valid; buf and size are correctly sized.
            let ok = unsafe {
                QueryFullProcessImageNameW(h, 0, buf.as_mut_ptr(), &mut size as *mut u32)
            };
            if ok != 0 && size > 0 && (size as usize) <= buf.len() {
                Some(String::from_utf16_lossy(&buf[..size as usize]))
            } else {
                None
            }
        };

        let creation_time = {
            let mut creation = FileTime::default();
            let mut exit = FileTime::default();
            let mut kernel = FileTime::default();
            let mut user = FileTime::default();
            // SAFETY: handle is valid; pointers refer to local stack values.
            let ok = unsafe {
                GetProcessTimes(
                    h,
                    &mut creation as *mut _,
                    &mut exit as *mut _,
                    &mut kernel as *mut _,
                    &mut user as *mut _,
                )
            };
            if ok != 0 {
                creation.as_u64()
            } else {
                0
            }
        };

        // SAFETY: handle came from OpenProcess and we close it exactly once.
        unsafe {
            let _ = CloseHandle(h);
        }

        ProcessIdentity {
            exe_path,
            creation_time,
        }
    }

    /// RAII guard for a Win32 handle so we close it on every exit path.
    pub(super) struct Handle(*mut c_void);

    impl Handle {
        pub(super) fn current_pid() -> u32 {
            // SAFETY: GetCurrentProcessId is documented to never fail.
            unsafe { GetCurrentProcessId() }
        }

        pub(super) fn open_for_query(pid: u32) -> Option<Self> {
            // SAFETY: pid is a u32; OpenProcess returns null on failure.
            let h = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
            if h.is_null() {
                None
            } else {
                Some(Self(h))
            }
        }

        pub(super) fn raw(&self) -> usize {
            self.0 as usize
        }
    }

    impl Drop for Handle {
        fn drop(&mut self) {
            if !self.0.is_null() {
                // SAFETY: handle came from OpenProcess and has not been closed.
                unsafe {
                    let _ = CloseHandle(self.0);
                }
            }
        }
    }
}

/// True iff `access_mask` grants any right that is sufficient on its own to
/// extract credentials from lsass (read memory, write memory, or duplicate
/// handles into a less-privileged process).
fn is_dangerous_lsass_access(access_mask: u32) -> bool {
    access_mask & handle_scan::DANGEROUS_ACCESS_MASK != 0
}

/// Trusted system / security holders that legitimately keep handles open to
/// lsass.exe.  Names are matched case-insensitively against
/// `Process::name()` (basename only — full-path allowlisting is a follow-up
/// once a config plumbing story exists).
const LSASS_HANDLE_HOLDER_ALLOWLIST: &[&str] = &[
    // Kernel-side / session bootstrap
    "system",
    "smss.exe",
    "csrss.exe",
    "wininit.exe",
    "services.exe",
    "winlogon.exe",
    // SCM-spawned long-lived hosts
    "svchost.exe",
    "lsm.exe",
    // First-party Windows security stack
    "msmpeng.exe",
    "mssense.exe",
    "securityhealthservice.exe",
    "smartscreen.exe",
    // Common third-party EDR/AV vendor binaries (extend via config)
    "sophosfs.exe",
    "sophosfilescanner.exe",
    "cylancesvc.exe",
    "csagent.exe",
    "sentinelagent.exe",
    "elasticedr.exe",
    "carbonblack.exe",
    "tsenstrap.exe",
    "tanium.exe",
];

fn is_lsass_holder_allowlisted(holder_name: &str) -> bool {
    let lower = holder_name.to_lowercase();
    LSASS_HANDLE_HOLDER_ALLOWLIST
        .iter()
        .any(|&entry| entry == lower)
}

#[cfg(windows)]
pub fn scan_lsass_handles(sys: &sysinfo::System) -> Vec<Alert> {
    use sysinfo::Pid;

    let lsass_pid: u32 = match sys.processes().iter().find_map(|(pid, p)| {
        let name = p.name().to_string_lossy();
        if name.eq_ignore_ascii_case("lsass.exe") {
            Some(usize::from(*pid) as u32)
        } else {
            None
        }
    }) {
        Some(p) => p,
        None => return Vec::new(),
    };

    let lsass_handle = match handle_scan::Handle::open_for_query(lsass_pid) {
        Some(h) => h,
        None => return Vec::new(),
    };
    let our_pid = handle_scan::Handle::current_pid();

    let entries = handle_scan::enumerate_system_handles();
    if entries.is_empty() {
        return Vec::new();
    }

    // Step 1 — find our own row to learn lsass's kernel object pointer.
    let lsass_object = match entries
        .iter()
        .find(|e| e.holder_pid == our_pid && e.handle_value == lsass_handle.raw())
    {
        Some(e) => e.object,
        // We hold a handle to lsass but couldn't find ourselves in the table:
        // the snapshot was taken before our OpenProcess landed, or PPL
        // filtering is in play.  Either way we cannot reliably correlate.
        None => return Vec::new(),
    };

    // Step 2 — flag every other holder of the same kernel object.
    let mut alerts = Vec::new();
    for entry in &entries {
        if entry.object != lsass_object {
            continue;
        }
        if entry.holder_pid == our_pid || entry.holder_pid == lsass_pid {
            continue;
        }
        if !is_dangerous_lsass_access(entry.granted_access) {
            continue;
        }

        // TOCTOU defence: re-capture the holder's identity *now* and refuse
        // to alert if the PID has been recycled (different exe path, or
        // different creation timestamp, between enumeration and lookup).
        let current_identity = handle_scan::capture_process_identity(entry.holder_pid);
        let captured = &entry.identity;
        let pid_recycled = match (captured.creation_time, current_identity.creation_time) {
            // Both timestamps known and disagree → almost certainly reuse.
            (a, b) if a != 0 && b != 0 && a != b => true,
            // One side missing — fall back to exe-path comparison when we
            // have one.
            _ => matches!(
                (&captured.exe_path, &current_identity.exe_path),
                (Some(a), Some(b)) if !a.eq_ignore_ascii_case(b)
            ),
        };
        if pid_recycled {
            tracing::warn!(
                target = "cred_guard",
                pid = entry.holder_pid,
                "skipping LSASS handle holder — PID was reused between enumeration and lookup"
            );
            continue;
        }

        let holder_name = sys
            .process(Pid::from(entry.holder_pid as usize))
            .map(|p| p.name().to_string_lossy().into_owned())
            .unwrap_or_else(|| "<unknown>".to_string());

        if is_lsass_holder_allowlisted(&holder_name) {
            continue;
        }

        let exe_path = sys
            .process(Pid::from(entry.holder_pid as usize))
            .and_then(|p| p.exe().map(|e| e.to_string_lossy().into_owned()))
            // Fall back to the path we captured at enumeration time, which
            // is correct-by-construction even if `sysinfo` later loses the
            // PID between snapshots.
            .or_else(|| captured.exe_path.clone())
            .unwrap_or_else(|| "<unknown>".to_string());

        let mut meta = HashMap::new();
        meta.insert("pid".to_string(), entry.holder_pid.to_string());
        meta.insert("process_name".to_string(), holder_name.clone());
        meta.insert("exe_path".to_string(), exe_path);
        meta.insert(
            "granted_access".to_string(),
            format!("{:#010x}", entry.granted_access),
        );
        meta.insert("target".to_string(), "lsass.exe".to_string());
        meta.insert("target_pid".to_string(), lsass_pid.to_string());

        alerts.push(make_alert(
            Severity::Critical,
            "LsassHandleHeld",
            format!(
                "Process '{}' (PID {}) holds an open handle to lsass.exe with \
                 credential-dumping access (mask {:#x})",
                holder_name, entry.holder_pid, entry.granted_access
            ),
            "T1003.001",
            meta,
        ));
    }

    alerts
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

const CRED_DUMP_CMDLINE_TOKENS: &[&str] = &["sekurlsa", "lsadump", "dcsync", "logonpasswords"];

#[cfg(windows)]
pub fn detect_cred_tools(sys: &sysinfo::System) -> Vec<Alert> {
    let mut alerts = Vec::new();

    for (_pid, process) in sys.processes() {
        let name = process.name().to_string_lossy().into_owned();
        let name_lc = name.to_lowercase();
        let cmdline = join_cmd(process);
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
                format!("Process name matches known credential dumping tool: {name}")
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
            meta.insert("pid".to_string(), pid_val.to_string());
            meta.insert("process_name".to_string(), name);
            meta.insert("exe_path".to_string(), exe);
            meta.insert("cmdline".to_string(), cmdline);

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
        let cmdline = join_cmd(process);
        let cmdline_lc = cmdline.to_lowercase();

        let hit = SAM_DUMP_PATTERNS
            .iter()
            .any(|&pat| cmdline_lc.contains(&pat.to_lowercase()));

        if hit {
            let pid_val = usize::from(*_pid) as u32;
            let mut meta = HashMap::new();
            meta.insert("pid".to_string(), pid_val.to_string());
            meta.insert(
                "process_name".to_string(),
                process.name().to_string_lossy().into_owned(),
            );
            meta.insert("cmdline".to_string(), cmdline.clone());

            alerts.push(make_alert(
                Severity::High,
                "SamHiveDump",
                format!(
                    "SAM/SYSTEM/SECURITY hive dump detected via cmdline: {}",
                    cmdline
                ),
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
    severity: Severity,
    description: &'static str,
}

const RANSOM_PATTERNS: &[RansomPattern] = &[
    RansomPattern {
        process_token: "vssadmin",
        cmdline_token: "delete shadows",
        severity: Severity::Critical,
        description: "VSS shadow copy deletion — common ransomware pre-encryption step",
    },
    RansomPattern {
        process_token: "bcdedit",
        cmdline_token: "recoveryenabled",
        severity: Severity::Critical,
        description: "Boot recovery disabled via bcdedit — common ransomware pre-encryption step",
    },
    RansomPattern {
        process_token: "wbadmin",
        cmdline_token: "delete systemstatebackup",
        severity: Severity::Critical,
        description: "System state backup deletion via wbadmin",
    },
    RansomPattern {
        process_token: "wmic",
        cmdline_token: "shadowcopy delete",
        severity: Severity::Critical,
        description: "VSS shadow copy deletion via WMIC",
    },
    RansomPattern {
        process_token: "cipher",
        cmdline_token: "/w:",
        severity: Severity::High,
        description: "cipher /w: free-space wipe — potential ransomware evidence destruction",
    },
];

#[cfg(windows)]
pub fn detect_ransomware_signals(sys: &sysinfo::System) -> Vec<Alert> {
    let mut alerts = Vec::new();

    for (_pid, process) in sys.processes() {
        let name = process.name().to_string_lossy().into_owned();
        let name_lc = name.to_lowercase();
        let cmdline = join_cmd(process);
        let cmdline_lc = cmdline.to_lowercase();

        for pattern in RANSOM_PATTERNS {
            if name_lc.contains(pattern.process_token) && cmdline_lc.contains(pattern.cmdline_token)
            {
                let pid_val = usize::from(*_pid) as u32;
                let mut meta = HashMap::new();
                meta.insert("pid".to_string(), pid_val.to_string());
                meta.insert("process_name".to_string(), name.clone());
                meta.insert("cmdline".to_string(), cmdline.clone());

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
            meta.insert("actual_bytes".to_string(), actual_hex);
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

#[cfg(all(test, windows))]
mod tests {
    use super::*;

    /// Mimikatz-class access masks must be flagged.
    #[test]
    fn dangerous_access_masks_are_flagged() {
        // Just PROCESS_VM_READ (0x10).
        assert!(is_dangerous_lsass_access(0x0010));
        // Mimikatz: PROCESS_QUERY_INFORMATION | PROCESS_VM_READ — VM_READ
        // is the smoking gun.
        assert!(is_dangerous_lsass_access(0x0410));
        // Nanodump-style: PROCESS_DUP_HANDLE alone.
        assert!(is_dangerous_lsass_access(0x0040));
        // VM_OPERATION (used to set memory writable before dumping).
        assert!(is_dangerous_lsass_access(0x0008));
    }

    /// Bare introspection rights must NOT trigger the detector — those are
    /// what every Task Manager / Process Explorer holds against lsass.
    #[test]
    fn benign_access_masks_are_not_flagged() {
        // PROCESS_QUERY_LIMITED_INFORMATION alone.
        assert!(!is_dangerous_lsass_access(0x1000));
        // PROCESS_QUERY_INFORMATION alone (no VM_READ).
        assert!(!is_dangerous_lsass_access(0x0400));
        // SYNCHRONIZE alone.
        assert!(!is_dangerous_lsass_access(0x0010_0000));
        // Empty mask.
        assert!(!is_dangerous_lsass_access(0));
    }

    /// The allowlist must match case-insensitively, basename-only.
    #[test]
    fn allowlist_is_case_insensitive() {
        assert!(is_lsass_holder_allowlisted("svchost.exe"));
        assert!(is_lsass_holder_allowlisted("SVCHOST.EXE"));
        assert!(is_lsass_holder_allowlisted("Svchost.Exe"));
        assert!(is_lsass_holder_allowlisted("MsMpEng.exe"));
        assert!(!is_lsass_holder_allowlisted("mimikatz.exe"));
        assert!(!is_lsass_holder_allowlisted("nanodump.exe"));
        assert!(!is_lsass_holder_allowlisted(""));
    }

    /// `scan_lsass_handles` must never panic on a host where we have only an
    /// unprivileged token — it should return an empty `Vec` and let the rest
    /// of CredGuard's checks proceed.
    #[test]
    fn scan_lsass_handles_does_not_panic() {
        let mut sys = sysinfo::System::new_all();
        sys.refresh_all();
        let _alerts = scan_lsass_handles(&sys);
    }
}
