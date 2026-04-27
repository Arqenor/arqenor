# Phase 1 — Detection Engine + LOTL Rules
> Target: Q2 2026 | Priority: CRITICAL | Effort: Medium

## Why This Phase First

84% of severe breaches in 2025 used LOTL (Living off the Land) techniques.
Attackers abuse tools already present on the system: PowerShell, certutil, mshta,
WMI, schtasks — they leave almost no traditional IOC.

Detection requires **behavioral rules on top of existing telemetry**, not new
kernel capabilities. This is high-impact, achievable without a kernel driver.

---

## 1.1 — Expanded Persistence Detection

### What to Add (Windows)

| Technique | ATT&CK ID | Detection Method | Priority |
|-----------|-----------|-----------------|----------|
| WMI Event Subscriptions | T1546.003 | Query `__EventFilter`, `__EventConsumer`, `FilterToConsumerBinding` via WMI | P0 |
| COM Hijacking (HKCU) | T1546.015 | Watch `HKCU\Software\Classes\CLSID\*` for new InprocServer32 | P0 |
| DLL Sideloading | T1574.002 | Check running processes for DLLs loaded from user-writable dirs | P0 |
| BITS Jobs | T1197 | Enumerate `BitsAdmin /list` or COM BITS interface | P1 |
| AppInit_DLLs | T1546.010 | Read `HKLM\Software\Microsoft\Windows NT\CurrentVersion\Windows\AppInit_DLLs` | P1 |
| Boot/Logon via Image File Execution Options | T1546.012 | `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options` | P1 |
| Accessibility Features hijack | T1546.008 | Hash `sethc.exe`, `utilman.exe`, `osk.exe` against known-good | P1 |
| Print Monitor / LSA provider | T1547.010 / T1547.002 | Registry keys under `HKLM\SYSTEM\CurrentControlSet\Control\Print\Monitors` | P2 |
| Netsh Helper DLL | T1546.007 | `HKLM\SYSTEM\CurrentControlSet\Services\NetSh` | P2 |

### What to Add (Linux)

| Technique | ATT&CK ID | Detection Method |
|-----------|-----------|-----------------|
| Systemd timers | T1053.006 | Scan `/etc/systemd/system/*.timer` for new entries |
| LD_PRELOAD abuse | T1574.006 | Monitor `/etc/ld.so.preload`; alert if non-empty or changed |
| LKM (kernel module) | T1014 | Watch `/proc/modules` for non-whitelisted modules |
| SSH authorized_keys changes | T1098.004 | FIM on `~/.ssh/authorized_keys` for all users |
| PAM module injection | T1556.003 | Hash and monitor `/etc/pam.d/` and `/lib/security/*.so` |
| `.bashrc` / `.profile` modification | T1546.004 | FIM on all user shell profiles |
| Git hooks | T1059 | Scan `.git/hooks/` in known repos for executable scripts |
| Udev rules | T1546 | Monitor `/etc/udev/rules.d/` for new entries |

### What to Add (macOS)

| Technique | ATT&CK ID | Detection Method |
|-----------|-----------|-----------------|
| Login Items | T1547.015 | `sfltool dumpbtm` or parse `backgroundtaskmanagementagent` DB |
| Cron jobs | T1053.003 | `crontab -l` for all users |
| Periodic scripts | T1053 | Monitor `/etc/periodic/daily`, `/weekly`, `/monthly` |
| Dylib hijacking | T1574.004 | Check `@rpath`/`@loader_path` in new executables |
| Spotlight importer plugins | T1546 | Monitor `~/Library/Spotlight/` for new `.mdimporter` bundles |

### Implementation in Rust

```rust
// arqenor-platform/src/windows/persistence_detector.rs additions:

pub async fn detect_wmi_subscriptions() -> Vec<PersistenceEntry> {
    // Use windows-rs COM to query WMI:
    // SELECT * FROM __EventFilter
    // SELECT * FROM __EventConsumer  
    // SELECT * FROM __FilterToConsumerBinding
    // Any non-empty result = persistence
}

pub async fn detect_com_hijacking() -> Vec<PersistenceEntry> {
    // Enumerate HKCU\Software\Classes\CLSID\*\InprocServer32
    // Any entry here that also exists in HKLM = potential hijack
    // (HKCU takes precedence over HKLM for COM loading)
}

pub async fn detect_dll_sideloading() -> Vec<PersistenceEntry> {
    // For each running process, enumerate loaded DLLs
    // Flag any DLL loaded from: %TEMP%, %APPDATA%, user home, Downloads
    // that has the same name as a known system DLL
}
```

---

## 1.2 — LOTL / LOLBin Detection Rules

### Rule Engine Design

ARQENOR needs a **rule engine** that matches process creation events against
patterns. Format: compatible with SIGMA (the industry-standard open detection rule format).

```rust
// arqenor-core/src/rules/mod.rs

pub struct DetectionRule {
    pub id:          String,       // e.g. "SENT-1001"
    pub attack_id:   String,       // e.g. "T1059.001"
    pub severity:    Severity,
    pub title:       String,
    pub condition:   RuleCondition,
}

pub enum RuleCondition {
    ProcessCreate {
        image:   Option<Pattern>,     // e.g. "*\\powershell.exe"
        cmdline: Option<Pattern>,     // e.g. "*-EncodedCommand*"
        parent:  Option<Pattern>,     // e.g. "*\\winword.exe"
    },
    FileCreate {
        path:      Pattern,
        extension: Option<String>,
    },
    RegistrySet {
        key:   Pattern,
        value: Option<Pattern>,
    },
}
```

### LOLBin Rules to Implement (Top Priority)

| Rule ID | Title | ATT&CK | Condition |
|---------|-------|--------|-----------|
| SENT-1001 | PowerShell Encoded Command | T1059.001 | `powershell.exe` + `-EncodedCommand` or `-Enc` in cmdline |
| SENT-1002 | PowerShell Download Cradle | T1059.001 | `powershell.exe` + `(Net.WebClient\|Invoke-WebRequest\|iwr\|wget)` in cmdline |
| SENT-1003 | Certutil Decode / Download | T1140 | `certutil.exe` + `-decode` or `-urlcache` in cmdline |
| SENT-1004 | MSHTA Remote Execution | T1218.005 | `mshta.exe` with `http://` or `https://` in cmdline |
| SENT-1005 | Regsvr32 COM Scriptlet | T1218.010 | `regsvr32.exe` + `/s` + `/u` + `scrobj.dll` or remote URL |
| SENT-1006 | Rundll32 Remote | T1218.011 | `rundll32.exe` + URL in cmdline |
| SENT-1007 | BITSAdmin Transfer | T1197 | `bitsadmin.exe` + `/transfer` |
| SENT-1008 | WMI Process Spawn | T1047 | `wmiprvse.exe` spawning `cmd.exe`, `powershell.exe`, `cscript.exe` |
| SENT-1009 | Office Spawning Shell | T1204.002 | `winword.exe`, `excel.exe`, `powerpnt.exe` spawning `cmd.exe`, `powershell.exe`, `wscript.exe` |
| SENT-1010 | Schtasks Remote Create | T1053.005 | `schtasks.exe` + `/create` + `/s \\` (remote) |
| SENT-1011 | PsExec-like Lateral Movement | T1021.002 | `\\ADMIN$` or `\\IPC$` path + file copy + service creation in sequence |
| SENT-1012 | VSS Delete Pre-Ransomware | T1490 | `vssadmin.exe delete shadows` or `wmic shadowcopy delete` |
| SENT-1013 | WMIC Spawning Shell | T1047 | `wmic.exe` with `process call create` + shell binary |
| SENT-1014 | InstallUtil Execution | T1218.004 | `installutil.exe` with `/logfile=` or user-writable path |
| SENT-1015 | Suspicious Parent-Child | T1059 | Known system processes (svchost, spoolsv) spawning interactive shells |

### AMSI Bypass Detection

```rust
// Detect AmsiScanBuffer patch — T1562.001
// Compare the first bytes of AmsiScanBuffer in memory against the known-good bytes
// If patched (typically: mov eax, 0x80070057; ret), alert immediately

pub fn check_amsi_integrity() -> Option<Alert> {
    // Load amsi.dll via LoadLibrary
    // GetProcAddress("AmsiScanBuffer")
    // Read first 5 bytes
    // Compare against: 4C 8B DC 49 89 5B (known-good prologue)
    // Mismatch → AMSI patched → CRITICAL alert
}
```

---

## 1.3 — Credential Theft Detection (TA0006)

### LSASS Access Monitoring

The #1 credential dumping technique (T1003.001) is reading LSASS process memory.
Detection without ETW kernel hooks: poll `OpenProcess` handle table periodically.

```rust
// Check every 30s: which processes have PROCESS_VM_READ handle to lsass.exe
// Windows API: NtQuerySystemInformation(SystemHandleInformation)
// Any non-system process (not lsass.exe, not csrss.exe, not system) = CRITICAL alert
```

Rules:
- `mimikatz.exe` or `procdump.exe` in process list = CRITICAL
- Any process with handle to LSASS + `PROCESS_VM_READ` rights = CRITICAL (T1003.001)
- `sekurlsa`, `lsadump` in command line of any process = CRITICAL
- `reg.exe save HKLM\SAM` = HIGH (T1003.002 SAM database dump)
- Browser `Login Data` / `Cookies` accessed by non-browser process = HIGH (T1555.003)

### Shadow Copy / Backup Deletion

Pre-ransomware signal — almost always done before encryption:
```
vssadmin.exe delete shadows /all
wmic shadowcopy delete
bcdedit.exe /set {default} recoveryenabled No
wbadmin.exe DELETE SYSTEMSTATEBACKUP
```
Any of these = CRITICAL pre-ransomware alert.

---

## 1.4 — File Integrity Monitoring (FIM)

Baseline + continuous hash monitoring of critical paths:

**Windows critical paths:**
```
C:\Windows\System32\lsass.exe
C:\Windows\System32\ntdll.dll
C:\Windows\System32\kernel32.dll
C:\Windows\System32\winlogon.exe
C:\Windows\System32\csrss.exe
C:\Windows\System32\svchost.exe
%SystemRoot%\System32\drivers\etc\hosts
```

**Linux critical paths:**
```
/etc/passwd, /etc/shadow, /etc/sudoers
/etc/ssh/sshd_config
/bin/su, /bin/sudo, /usr/bin/passwd
/lib/x86_64-linux-gnu/libc.so.6 (watch for LD_PRELOAD rootkits)
/proc/modules (kernel modules)
```

Implementation: SHA-256 hash on startup, re-check every 60s, alert on mismatch.

---

## 1.5 — Process Scoring Improvements

Current scoring is simplistic (path-based). Upgrade to multi-factor scoring:

| Factor | Score | Rationale |
|--------|-------|-----------|
| Executable in TEMP/APPDATA | +5 | Malware drops to writable dirs |
| System process name from non-system path | +8 | Process masquerading |
| No digital signature | +3 | Legitimate software is usually signed |
| High entropy PE name (8+ random chars) | +2 | Random name = packed/malware |
| Parent is browser/office | +3 | Unusual spawning |
| Unsigned DLL loaded by signed process | +2 | DLL sideloading |
| Parent PID not matching known service | +2 | Orphaned process |
| Running from network share | +4 | PsExec-style lateral movement |
| Hollow process (no PE on disk) | +10 | Process hollowing T1055.012 |

```rust
// Add to arqenor-core/src/models/process.rs:
pub struct ProcessScore {
    pub total:    u8,
    pub factors:  Vec<ScoreFactor>,  // for explainability
}

pub struct ScoreFactor {
    pub name:        &'static str,
    pub points:      u8,
    pub attack_id:   Option<&'static str>,
}
```

---

## Deliverables / Crates Affected

| Crate | Changes |
|-------|---------|
| `arqenor-core` | Add `rules/` module, `ScoreFactor`, `Alert` model with ATT&CK ID |
| `arqenor-platform` | Expand persistence detector (WMI, COM, BITS, DLL sideload) |
| `arqenor-platform` | Add `lsass_guard` module (handle table scan) |
| `arqenor-platform` | Add `fim` module (file integrity monitoring) |
| `arqenor-tui` | Show ATT&CK IDs in process/persistence tabs |
| `arqenor-desktop` | Alerts tab, ATT&CK technique badges |

## Estimated ATT&CK Coverage After Phase 1

+40 techniques covered across:
- TA0002 Execution (LOLBins: T1059.001, T1218.*)  
- TA0003 Persistence (WMI, COM, BITS, DLL sideload)  
- TA0005 Defense Evasion (AMSI bypass, masquerading)  
- TA0006 Credential Access (LSASS, SAM, browser creds)  
- TA0007 Discovery (net enumeration patterns)  
- TA0040 Impact (shadow copy deletion)  

---

## Hardening notes (2026-04-27 security audit pass)

- **FIM SHA-256 streaming.** All disk hashing in this phase (`fim`, `byovd`, `cred_guard`, `fs_scanner` Win/Lin/macOS, `persistence_advanced`) now goes through `arqenor-platform/src/hash.rs` (default 512 MiB cap). Replaces the previous `std::fs::read()` pattern that loaded files entirely in RAM.
- **Symlink / reparse-point validation.** Watch roots are checked through `path_validate::ensure_no_reparse` before `CreateFileW` (Windows) and `inotify::add` (Linux) to prevent a non-privileged user redirecting the FIM session.
- **Cred-guard PID recycling defence.** `windows/cred_guard.rs` captures `ProcessIdentity { exe_path, creation_time }` at handle-table enumeration and re-checks at lookup time, dropping the entry when the PID has been recycled.
