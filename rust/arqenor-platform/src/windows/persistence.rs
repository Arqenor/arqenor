use arqenor_core::{
    error::ArqenorError,
    models::persistence::{PersistenceEntry, PersistenceKind},
    traits::persistence::PersistenceDetector,
};
use async_trait::async_trait;
use std::path::PathBuf;

#[cfg(windows)]
use winreg::{
    enums::{HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE, KEY_READ},
    RegKey,
};

#[cfg(windows)]
use sha2::{Digest, Sha256};

pub struct WindowsPersistenceDetector;

impl WindowsPersistenceDetector {
    pub fn new() -> Self {
        Self
    }
}

impl Default for WindowsPersistenceDetector {
    fn default() -> Self {
        Self::new()
    }
}

// ── Registry Run keys ─────────────────────────────────────────────────────────

const RUN_KEYS: &[(&str, &str)] = &[
    ("HKLM", r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"),
    ("HKLM", r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"),
    ("HKCU", r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"),
    ("HKCU", r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"),
];

#[cfg(windows)]
fn enum_run_keys() -> Vec<PersistenceEntry> {
    let mut entries = Vec::new();
    for (hive_name, subkey) in RUN_KEYS {
        let hive = match *hive_name {
            "HKLM" => RegKey::predef(HKEY_LOCAL_MACHINE),
            "HKCU" => RegKey::predef(HKEY_CURRENT_USER),
            _ => continue,
        };
        let key = match hive.open_subkey(subkey) {
            Ok(k) => k,
            Err(_) => continue,
        };
        for (name, value) in key.enum_values().filter_map(|r| r.ok()) {
            entries.push(PersistenceEntry {
                kind: PersistenceKind::RegistryRun,
                name,
                command: value.to_string(),
                location: format!("{}\\{}", hive_name, subkey),
                is_new: false,
            });
        }
    }
    entries
}

// ── Windows Services ──────────────────────────────────────────────────────────
//
// Read from HKLM\SYSTEM\CurrentControlSet\Services.
// Filter to user-mode services only (Type & 0x10 or Type & 0x20):
//   0x01 = KernelDriver, 0x02 = FileSystemDriver, 0x04 = Adapter, 0x08 = Recognizer
//   0x10 = Win32OwnProcess, 0x20 = Win32ShareProcess, 0x100 = InteractiveProcess

#[cfg(windows)]
fn enum_services() -> Vec<PersistenceEntry> {
    let mut entries = Vec::new();
    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
    let services = match hklm.open_subkey_with_flags(r"SYSTEM\CurrentControlSet\Services", KEY_READ)
    {
        Ok(k) => k,
        Err(_) => return entries,
    };

    for svc_name in services.enum_keys().filter_map(|r| r.ok()) {
        let svc_key = match services.open_subkey(&svc_name) {
            Ok(k) => k,
            Err(_) => continue,
        };

        // Only user-mode processes (Win32OwnProcess | Win32ShareProcess)
        let svc_type: u32 = svc_key.get_value("Type").unwrap_or(0);
        if svc_type & 0x30 == 0 {
            continue;
        }

        let image_path: String = match svc_key.get_value::<String, _>("ImagePath") {
            Ok(p) if !p.is_empty() => expand_env_str(&p),
            _ => continue,
        };

        let display_name: String = svc_key
            .get_value("DisplayName")
            .unwrap_or_else(|_| svc_name.clone());

        entries.push(PersistenceEntry {
            kind: PersistenceKind::WindowsService,
            name: display_name,
            command: image_path,
            location: format!(r"HKLM\SYSTEM\CurrentControlSet\Services\{}", svc_name),
            is_new: false,
        });
    }
    entries
}

// ── Scheduled Tasks ───────────────────────────────────────────────────────────
//
// Enumerate task paths from the registry TaskCache\Tree (doesn't require COM).
// For each task, attempt to read the command from the XML file in System32\Tasks.

#[cfg(windows)]
fn enum_scheduled_tasks() -> Vec<PersistenceEntry> {
    let mut entries = Vec::new();
    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
    let tree = match hklm.open_subkey_with_flags(
        r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree",
        KEY_READ,
    ) {
        Ok(k) => k,
        Err(_) => return entries,
    };
    collect_tasks(&tree, "", &mut entries);
    entries
}

#[cfg(windows)]
fn collect_tasks(key: &RegKey, path: &str, out: &mut Vec<PersistenceEntry>) {
    // A key that has an "Id" value is a task leaf node.
    if key.get_value::<String, _>("Id").is_ok() {
        let task_name = path.rsplit('\\').next().unwrap_or(path).to_string();
        let task_path = if path.is_empty() {
            "\\".to_string()
        } else {
            format!("\\{}", path)
        };
        let command = task_cmd_from_xml(&task_path).unwrap_or_default();
        out.push(PersistenceEntry {
            kind: PersistenceKind::ScheduledTask,
            name: task_name,
            command,
            location: format!("Scheduled Tasks: {}", task_path),
            is_new: false,
        });
        return;
    }

    // Recurse into folder subkeys
    for subkey_name in key.enum_keys().filter_map(|r| r.ok()) {
        if let Ok(subkey) = key.open_subkey_with_flags(&subkey_name, KEY_READ) {
            let child_path = if path.is_empty() {
                subkey_name.clone()
            } else {
                format!("{}\\{}", path, subkey_name)
            };
            collect_tasks(&subkey, &child_path, out);
        }
    }
}

/// Read the task XML file from `%SystemRoot%\System32\Tasks\<task_path>` and
/// extract the command from the first `<Exec>` action's `<Command>` + `<Arguments>`.
fn task_cmd_from_xml(task_path: &str) -> Option<String> {
    let sys_root = std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".to_string());
    let rel = task_path
        .trim_start_matches('\\')
        .replace('\\', std::path::MAIN_SEPARATOR_STR);
    let xml_path: PathBuf = [sys_root.as_str(), "System32", "Tasks", rel.as_str()]
        .iter()
        .collect();

    let content = std::fs::read_to_string(&xml_path).ok()?;
    let command = extract_xml_tag(&content, "Command")?;
    let args = extract_xml_tag(&content, "Arguments")
        .map(|a| format!(" {}", a))
        .unwrap_or_default();

    Some(format!("{}{}", expand_env_str(&command), args))
}

/// Minimal tag extractor — sufficient for well-formed Windows task XML.
fn extract_xml_tag(xml: &str, tag: &str) -> Option<String> {
    let open = format!("<{}>", tag);
    let close = format!("</{}>", tag);
    let start = xml.find(&open)? + open.len();
    let end = xml[start..].find(&close)?;
    let value = xml[start..start + end].trim().to_string();
    if value.is_empty() {
        None
    } else {
        Some(value)
    }
}

// ── Environment variable expansion ───────────────────────────────────────────
//
// Service ImagePath and task commands often contain %SystemRoot% etc.
// On Windows, std::env::var is case-insensitive.

fn expand_env_str(s: &str) -> String {
    if !s.contains('%') {
        return s.to_string();
    }
    let mut out = String::with_capacity(s.len() + 32);
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        if c != '%' {
            out.push(c);
            continue;
        }
        // Collect up to the closing %
        let var: String = chars.by_ref().take_while(|&ch| ch != '%').collect();
        if var.is_empty() {
            out.push('%');
        } else if let Ok(val) = std::env::var(&var) {
            out.push_str(&val);
        } else {
            // Preserve unknown variable
            out.push('%');
            out.push_str(&var);
            out.push('%');
        }
    }
    out
}

// ── B1: WMI Event Subscriptions (T1546.003) ───────────────────────────────────
//
// Uses wmic.exe CLI to avoid COM initialisation complexity.
// Queries __EventFilter and __EventConsumer from the subscription namespace.

#[cfg(windows)]
fn enum_wmi_subscriptions() -> Vec<PersistenceEntry> {
    let mut entries = Vec::new();

    let queries: &[(&str, &str, &str)] = &[
        (r"\\root\subscription", "__EventFilter", "EventFilter"),
        (r"\\root\subscription", "__EventConsumer", "EventConsumer"),
    ];

    for (namespace, class, label) in queries {
        let output = std::process::Command::new("wmic")
            .args([
                "/namespace",
                namespace,
                "PATH",
                class,
                "GET",
                "Name",
                "/format:list",
            ])
            .output();

        let stdout = match output {
            Ok(o) => String::from_utf8_lossy(&o.stdout).to_string(),
            Err(_) => continue,
        };

        for line in stdout.lines() {
            let line = line.trim();
            if let Some(name) = line.strip_prefix("Name=") {
                let name = name.trim().to_string();
                if name.is_empty() {
                    continue;
                }
                entries.push(PersistenceEntry {
                    kind: PersistenceKind::WmiSubscription,
                    name: name.clone(),
                    command: format!("{} subscription: {}", label, name),
                    location: format!(r"WMI\root\subscription\{}", class),
                    is_new: false,
                });
            }
        }
    }

    entries
}

// ── B2: COM Hijacking HKCU (T1546.015) ────────────────────────────────────────
//
// Enumerate HKCU\Software\Classes\CLSID\*\InprocServer32.
// Flag if the same CLSID also exists in HKLM (HKCU override = hijack) or
// if the DLL path is outside System32.

#[cfg(windows)]
fn enum_com_hijacking() -> Vec<PersistenceEntry> {
    let mut entries = Vec::new();

    let hkcu = RegKey::predef(HKEY_CURRENT_USER);
    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);

    let clsid_key = match hkcu.open_subkey_with_flags(r"Software\Classes\CLSID", KEY_READ) {
        Ok(k) => k,
        Err(_) => return entries,
    };

    for clsid in clsid_key.enum_keys().filter_map(|r| r.ok()) {
        let inproc_path = format!(r"{}\InprocServer32", clsid);
        let inproc = match clsid_key.open_subkey_with_flags(&inproc_path, KEY_READ) {
            Ok(k) => k,
            Err(_) => continue,
        };

        let dll_path: String = inproc.get_value("").unwrap_or_default();
        if dll_path.is_empty() {
            continue;
        }

        // Flag if HKLM has the same CLSID (HKCU overrides it = potential hijack)
        let hklm_path = format!(r"Software\Classes\CLSID\{}", clsid);
        let in_hklm = hklm.open_subkey(&hklm_path).is_ok();

        // Also flag if DLL not in System32
        let in_system32 = dll_path.to_lowercase().contains("system32");

        if in_hklm || !in_system32 {
            let location = format!(r"HKCU\Software\Classes\CLSID\{}\InprocServer32", clsid);
            entries.push(PersistenceEntry {
                kind: PersistenceKind::ComHijacking,
                name: clsid.clone(),
                command: dll_path,
                location,
                is_new: false,
            });
        }
    }

    entries
}

// ── B3: DLL Sideloading (T1574.002) ───────────────────────────────────────────
//
// Walks every running process whose handle we can open with
// `PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ`, lists its loaded
// modules via `EnumProcessModules`, and flags any DLL whose full path is
// rooted under a *user-writable* location (Temp, AppData, Downloads, …).
//
// The safe-root list short-circuits the suspicious-root check, so DLLs under
// `%SystemRoot%`, `%ProgramFiles%`, `%ProgramFiles(x86)%`, the Windows Store
// staging area, and `%ProgramData%\Microsoft\Windows\` are never reported even
// when one of those happens to be technically writable.
//
// Protected processes (PPL, antimalware, certain system services) reject
// `OpenProcess` and are silently skipped — this mirrors what every other
// userspace EDR has to live with.

#[cfg(windows)]
fn enum_dll_sideloading() -> Vec<PersistenceEntry> {
    use windows::Win32::Foundation::CloseHandle;
    use windows::Win32::System::Threading::{
        OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_VM_READ,
    };

    let pids = enum_process_pids();
    if pids.is_empty() {
        return Vec::new();
    }

    let safe_roots = build_safe_dll_roots();
    let suspicious_roots = build_suspicious_dll_roots();
    if suspicious_roots.is_empty() {
        // No env vars resolved — nothing we can usefully classify.
        return Vec::new();
    }

    let mut entries = Vec::new();
    // Bound the work: even on a busy host this is comfortably above the real
    // ceiling (~300 procs × ~80 modules) and keeps a single misbehaving target
    // from monopolising the scan.
    const MAX_ENTRIES: usize = 8_192;

    for pid in pids {
        if pid == 0 || entries.len() >= MAX_ENTRIES {
            continue;
        }

        // SAFETY: PID is a u32 from EnumProcesses; OpenProcess returns either
        // an invalid handle (we skip) or a valid one we close below.
        let handle = unsafe {
            OpenProcess(
                PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ,
                false,
                pid,
            )
        };
        let handle = match handle {
            Ok(h) if !h.is_invalid() => h,
            _ => continue,
        };

        // First module is the EXE itself; we record it for the host context
        // and skip it from the sideloading check (an EXE in %TEMP% is a
        // separate detection — typically already caught by Run keys / tasks).
        let modules = enum_process_modules(handle);
        let host_path = modules
            .first()
            .map(|h| get_module_filename_w(handle, *h))
            .unwrap_or_default();
        let host_name = basename(&host_path);

        for module in modules.iter().skip(1) {
            if entries.len() >= MAX_ENTRIES {
                break;
            }
            let dll_path = get_module_filename_w(handle, *module);
            if dll_path.is_empty() {
                continue;
            }
            if !is_suspicious_dll_path(&dll_path, &safe_roots, &suspicious_roots) {
                continue;
            }
            entries.push(PersistenceEntry {
                kind: PersistenceKind::DllSideloading,
                name: basename(&dll_path),
                command: dll_path,
                location: format!("PID {} ({})", pid, host_name),
                is_new: false,
            });
        }

        // SAFETY: handle came from a successful OpenProcess above.
        unsafe {
            let _ = CloseHandle(handle);
        }
    }

    entries
}

/// Enumerate live PIDs via `EnumProcesses`, growing the buffer until it stops
/// reporting the full needed-size match (which signals a possible truncation).
#[cfg(windows)]
fn enum_process_pids() -> Vec<u32> {
    use windows::Win32::System::ProcessStatus::EnumProcesses;

    let mut capacity: usize = 1024;
    loop {
        let mut buf: Vec<u32> = vec![0; capacity];
        let mut bytes_returned: u32 = 0;
        let bytes_in_buf = (buf.len() * std::mem::size_of::<u32>()) as u32;

        // SAFETY: buf is contiguous u32 storage of known size.
        let ok = unsafe { EnumProcesses(buf.as_mut_ptr(), bytes_in_buf, &mut bytes_returned) };
        if ok.is_err() {
            return Vec::new();
        }
        if bytes_returned >= bytes_in_buf && capacity < 32_768 {
            // Buffer was likely full — grow and retry.
            capacity *= 2;
            continue;
        }
        let count = bytes_returned as usize / std::mem::size_of::<u32>();
        buf.truncate(count);
        return buf;
    }
}

/// Enumerate the loaded module handles for `process`. Returns the EXE handle
/// first (mirrors what `EnumProcessModules` itself documents), followed by
/// each loaded DLL. An empty vec means the call failed (access denied, etc.).
#[cfg(windows)]
fn enum_process_modules(
    process: windows::Win32::Foundation::HANDLE,
) -> Vec<windows::Win32::Foundation::HMODULE> {
    use windows::Win32::Foundation::HMODULE;
    use windows::Win32::System::ProcessStatus::EnumProcessModules;

    let mut capacity: usize = 256;
    loop {
        let mut buf: Vec<HMODULE> = vec![HMODULE::default(); capacity];
        let mut needed: u32 = 0;
        let bytes_in_buf = (buf.len() * std::mem::size_of::<HMODULE>()) as u32;

        // SAFETY: buf is correctly sized.
        let ok =
            unsafe { EnumProcessModules(process, buf.as_mut_ptr(), bytes_in_buf, &mut needed) };
        if ok.is_err() {
            return Vec::new();
        }
        if needed > bytes_in_buf && capacity < 4_096 {
            capacity = (needed as usize / std::mem::size_of::<HMODULE>()).next_power_of_two();
            continue;
        }
        let count = (needed as usize / std::mem::size_of::<HMODULE>()).min(buf.len());
        buf.truncate(count);
        return buf;
    }
}

/// Resolve a module handle to its full filesystem path via
/// `GetModuleFileNameExW`. Returns an empty string on failure.
#[cfg(windows)]
fn get_module_filename_w(
    process: windows::Win32::Foundation::HANDLE,
    module: windows::Win32::Foundation::HMODULE,
) -> String {
    use windows::Win32::System::ProcessStatus::GetModuleFileNameExW;

    // 32 KiB covers \\?\ long paths comfortably; no second probe call needed.
    let mut buf = [0u16; 32_768];
    // SAFETY: buf is contiguous u16 storage; len is correctly typed for the API.
    let len = unsafe { GetModuleFileNameExW(Some(process), Some(module), &mut buf) };
    if len == 0 {
        String::new()
    } else {
        String::from_utf16_lossy(&buf[..len as usize])
    }
}

#[cfg(windows)]
fn build_suspicious_dll_roots() -> Vec<String> {
    let mut out = Vec::new();
    push_env_path(&mut out, "TEMP");
    push_env_path(&mut out, "LOCALAPPDATA");
    push_env_path(&mut out, "APPDATA");
    push_env_path(&mut out, "PUBLIC");
    if let Ok(profile) = std::env::var("USERPROFILE") {
        out.push(format!("{}\\Downloads", profile.trim_end_matches('\\')));
        out.push(format!("{}\\Desktop", profile.trim_end_matches('\\')));
        out.push(format!("{}\\Documents", profile.trim_end_matches('\\')));
    }
    out.iter_mut().for_each(|p| *p = p.to_lowercase());
    out
}

#[cfg(windows)]
fn build_safe_dll_roots() -> Vec<String> {
    let mut out = Vec::new();
    push_env_path(&mut out, "SystemRoot"); // C:\Windows — covers System32 / SysWOW64 / Temp
    push_env_path(&mut out, "ProgramFiles");
    push_env_path(&mut out, "ProgramFiles(x86)");
    push_env_path(&mut out, "ProgramW6432");
    if let Ok(local) = std::env::var("LOCALAPPDATA") {
        // Windows Store apps + WinGet stage DLLs from inside %LOCALAPPDATA% but
        // are first-party trusted — keep these out of the "suspicious" bucket.
        out.push(format!(
            "{}\\Microsoft\\WindowsApps",
            local.trim_end_matches('\\')
        ));
        out.push(format!(
            "{}\\Microsoft\\WinGet",
            local.trim_end_matches('\\')
        ));
    }
    if let Ok(pdata) = std::env::var("ProgramData") {
        out.push(format!(
            "{}\\Microsoft\\Windows",
            pdata.trim_end_matches('\\')
        ));
    }
    out.iter_mut().for_each(|p| *p = p.to_lowercase());
    out
}

#[cfg(windows)]
fn push_env_path(out: &mut Vec<String>, name: &str) {
    if let Ok(val) = std::env::var(name) {
        let trimmed = val.trim_end_matches('\\').to_string();
        if !trimmed.is_empty() {
            out.push(trimmed);
        }
    }
}

/// Pure policy: is `dll_path` rooted under a user-writable directory that is
/// **not** also a known safe staging area?  Inputs are expected lowercased on
/// the root side; this function lowercases the DLL path for comparison.
fn is_suspicious_dll_path(
    dll_path: &str,
    safe_roots: &[String],
    suspicious_roots: &[String],
) -> bool {
    let lower = dll_path.to_lowercase();
    if safe_roots
        .iter()
        .any(|r| !r.is_empty() && lower.starts_with(r))
    {
        return false;
    }
    suspicious_roots
        .iter()
        .any(|r| !r.is_empty() && lower.starts_with(r))
}

fn basename(path: &str) -> String {
    path.rsplit_once('\\')
        .map(|(_, n)| n.to_string())
        .unwrap_or_else(|| path.to_string())
}

// ── B4: BITS Jobs (T1197) ─────────────────────────────────────────────────────
//
// Runs `bitsadmin /list /allusers /verbose` and parses the output for job
// names and remote URLs that look suspicious (external URLs or Temp/AppData).

#[cfg(windows)]
fn enum_bits_jobs() -> Vec<PersistenceEntry> {
    let mut entries = Vec::new();

    let output = match std::process::Command::new("bitsadmin")
        .args(["/list", "/allusers", "/verbose"])
        .output()
    {
        Ok(o) => o,
        Err(_) => return entries,
    };

    let stdout = String::from_utf8_lossy(&output.stdout).to_string();

    let mut current_job: Option<String> = None;

    for line in stdout.lines() {
        let line = line.trim();

        // Lines like: "DISPLAY: My Job Name"
        if let Some(name) = line.strip_prefix("DISPLAY:") {
            current_job = Some(name.trim().to_string());
            continue;
        }

        // Lines containing the remote URL or local path
        if line.starts_with("REMOTE NAME:") || line.starts_with("Remote Name:") {
            let url = line
                .split_once(':')
                .map(|x| x.1.trim().to_string())
                .unwrap_or_default();

            if url.is_empty() {
                continue;
            }

            let is_suspicious = url.starts_with("http://")
                || url.starts_with("https://")
                || url.starts_with("ftp://")
                || url.to_lowercase().contains("\\temp\\")
                || url.to_lowercase().contains("\\appdata\\");

            if is_suspicious {
                let job_name = current_job.clone().unwrap_or_else(|| "Unknown".to_string());
                entries.push(PersistenceEntry {
                    kind: PersistenceKind::BitsJob,
                    name: job_name,
                    command: url,
                    location: "BITS Jobs".to_string(),
                    is_new: false,
                });
            }
        }
    }

    entries
}

// ── B5: AppInit_DLLs (T1546.010) ──────────────────────────────────────────────
//
// Any non-empty AppInit_DLLs value means DLLs are injected into every
// user-mode process that links against User32.dll — high-severity finding.

#[cfg(windows)]
fn enum_appinit_dlls() -> Vec<PersistenceEntry> {
    let mut entries = Vec::new();
    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);

    let paths = &[
        r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows",
        r"SOFTWARE\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Windows",
    ];

    for reg_path in paths {
        let key = match hklm.open_subkey_with_flags(reg_path, KEY_READ) {
            Ok(k) => k,
            Err(_) => continue,
        };

        let value: String = key.get_value("AppInit_DLLs").unwrap_or_default();
        if value.trim().is_empty() {
            continue;
        }

        entries.push(PersistenceEntry {
            kind: PersistenceKind::AppInitDll,
            name: "AppInit_DLLs".to_string(),
            command: value,
            location: format!(r"HKLM\{}", reg_path),
            is_new: false,
        });
    }

    entries
}

// ── B6: Image File Execution Options Hijack (T1546.012) ───────────────────────
//
// Any executable subkey under IFEO with a "Debugger" value is a debugger
// hijack — launching that exe actually runs the debugger binary instead.

#[cfg(windows)]
fn enum_ifeo_hijacks() -> Vec<PersistenceEntry> {
    let mut entries = Vec::new();
    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);

    let ifeo = match hklm.open_subkey_with_flags(
        r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options",
        KEY_READ,
    ) {
        Ok(k) => k,
        Err(_) => return entries,
    };

    for exe_name in ifeo.enum_keys().filter_map(|r| r.ok()) {
        let exe_key = match ifeo.open_subkey_with_flags(&exe_name, KEY_READ) {
            Ok(k) => k,
            Err(_) => continue,
        };

        let debugger: String = match exe_key.get_value("Debugger") {
            Ok(v) => v,
            Err(_) => continue,
        };

        if debugger.trim().is_empty() {
            continue;
        }

        entries.push(PersistenceEntry {
            kind:     PersistenceKind::IfeoHijack,
            name:     exe_name.clone(),
            command:  debugger,
            location: format!(
                r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\{}",
                exe_name
            ),
            is_new:   false,
        });
    }

    entries
}

// ── B7: Accessibility Features Hijack (T1546.008) ────────────────────────────
//
// Checks key accessibility executables for signs of replacement:
//   - file size < 50 KB (normal binaries are 100 KB – 1 MB+)
// Also records the SHA-256 hash in the `command` field for manual review.

#[cfg(windows)]
fn enum_accessibility_files() -> Vec<PersistenceEntry> {
    let mut entries = Vec::new();

    let sys_root = std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".to_string());

    let targets = &[
        "sethc.exe",
        "utilman.exe",
        "osk.exe",
        "narrator.exe",
        "magnify.exe",
    ];

    for &target in targets {
        let path = PathBuf::from(format!(r"{}\System32\{}", sys_root, target));

        let metadata = match std::fs::metadata(&path) {
            Ok(m) => m,
            Err(_) => continue,
        };

        let size = metadata.len();

        // Compute SHA-256 for the command field (manual review baseline)
        let hash = std::fs::read(&path)
            .ok()
            .map(|bytes| {
                let mut hasher = Sha256::new();
                hasher.update(&bytes);
                format!("sha256:{}", hex::encode(hasher.finalize()))
            })
            .unwrap_or_else(|| "sha256:unreadable".to_string());

        // Flag if suspiciously small (potential replacement with stub/cmd.exe hardlink)
        if size < 50_000 {
            entries.push(PersistenceEntry {
                kind: PersistenceKind::AccessibilityHijack,
                name: target.to_string(),
                command: format!("size={}B {}", size, hash),
                location: path.to_string_lossy().to_string(),
                is_new: false,
            });
        }
    }

    entries
}

// ── B8: Print Monitor / LSA Provider (T1547.010 / T1547.002) ─────────────────

const LSA_KNOWN_GOOD: &[&str] = &[
    "msv1_0", "kerberos", "wdigest", "tspkg", "pku2u", "cloudap", "livessp",
];

#[cfg(windows)]
fn enum_print_monitors() -> Vec<PersistenceEntry> {
    let mut entries = Vec::new();
    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);

    // ── Print Monitors ────────────────────────────────────────────────────
    let monitors_key =
        hklm.open_subkey_with_flags(r"SYSTEM\CurrentControlSet\Control\Print\Monitors", KEY_READ);

    if let Ok(monitors) = monitors_key {
        for monitor_name in monitors.enum_keys().filter_map(|r| r.ok()) {
            let mk = match monitors.open_subkey_with_flags(&monitor_name, KEY_READ) {
                Ok(k) => k,
                Err(_) => continue,
            };
            let dll: String = mk.get_value("Driver").unwrap_or_default();
            if dll.trim().is_empty() {
                continue;
            }
            let is_ms =
                dll.to_lowercase().contains("microsoft") || dll.to_lowercase().contains("system32");
            if !is_ms {
                entries.push(PersistenceEntry {
                    kind: PersistenceKind::PrintMonitor,
                    name: monitor_name.clone(),
                    command: dll,
                    location: format!(
                        r"HKLM\SYSTEM\CurrentControlSet\Control\Print\Monitors\{}",
                        monitor_name
                    ),
                    is_new: false,
                });
            }
        }
    }

    // ── LSA Authentication Packages ───────────────────────────────────────
    let lsa_key = hklm.open_subkey_with_flags(r"SYSTEM\CurrentControlSet\Control\Lsa", KEY_READ);

    if let Ok(lsa) = lsa_key {
        // Authentication Packages is REG_MULTI_SZ
        let packages: Vec<String> = lsa.get_value("Authentication Packages").unwrap_or_default();

        for pkg in packages {
            let pkg = pkg.trim().to_string();
            if pkg.is_empty() {
                continue;
            }
            let known = LSA_KNOWN_GOOD
                .iter()
                .any(|&g| pkg.to_lowercase() == g.to_lowercase());
            let is_ms = pkg.to_lowercase().contains("microsoft");
            if !known && !is_ms {
                entries.push(PersistenceEntry {
                    kind: PersistenceKind::LsaProvider,
                    name: pkg.clone(),
                    command: pkg,
                    location: r"HKLM\SYSTEM\CurrentControlSet\Control\Lsa".to_string(),
                    is_new: false,
                });
            }
        }
    }

    entries
}

// ── B10: Active Setup (T1547.014) ────────────────────────────────────────────
//
// HKLM\SOFTWARE\Microsoft\Active Setup\Installed Components and
// HKCU\SOFTWARE\Microsoft\Active Setup\Installed Components
// Each subkey with a "StubPath" value runs that command once per new user logon.
// Legitimate software uses this for per-user initialization; malware abuses it
// for low-noise persistence (runs exactly once per user, hard to spot).

#[cfg(windows)]
fn enum_active_setup() -> Vec<PersistenceEntry> {
    let mut entries = Vec::new();

    let hives: &[(&str, winreg::HKEY)] =
        &[("HKLM", HKEY_LOCAL_MACHINE), ("HKCU", HKEY_CURRENT_USER)];

    for (hive_name, hive) in hives {
        let root = RegKey::predef(*hive);
        let components = match root.open_subkey_with_flags(
            r"SOFTWARE\Microsoft\Active Setup\Installed Components",
            KEY_READ,
        ) {
            Ok(k) => k,
            Err(_) => continue,
        };

        for component_id in components.enum_keys().filter_map(|r| r.ok()) {
            let comp_key = match components.open_subkey_with_flags(&component_id, KEY_READ) {
                Ok(k) => k,
                Err(_) => continue,
            };

            let stub_path: String = match comp_key.get_value("StubPath") {
                Ok(v) => v,
                Err(_) => continue, // no StubPath = not a persistence entry
            };
            if stub_path.trim().is_empty() {
                continue;
            }

            // Display name is the default value ("") — fall back to component GUID
            let name: String = comp_key
                .get_value("")
                .unwrap_or_else(|_| component_id.clone());

            entries.push(PersistenceEntry {
                kind: PersistenceKind::ActiveSetup,
                name,
                command: expand_env_str(&stub_path),
                location: format!(
                    r"{}\SOFTWARE\Microsoft\Active Setup\Installed Components\{}",
                    hive_name, component_id
                ),
                is_new: false,
            });
        }
    }

    entries
}

// ── B9: Netsh Helper DLL (T1546.007) ──────────────────────────────────────────
//
// Enumerate HKLM\SOFTWARE\Microsoft\NetSh values. Each value points to a
// helper DLL; flag any not residing in System32.

#[cfg(windows)]
fn enum_netsh_helpers() -> Vec<PersistenceEntry> {
    let mut entries = Vec::new();
    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);

    let netsh = match hklm.open_subkey_with_flags(r"SOFTWARE\Microsoft\NetSh", KEY_READ) {
        Ok(k) => k,
        Err(_) => return entries,
    };

    for (name, value) in netsh.enum_values().filter_map(|r| r.ok()) {
        let dll_path = value.to_string();
        if dll_path.trim().is_empty() {
            continue;
        }
        // Flag if NOT in System32 (case-insensitive)
        if !dll_path.to_lowercase().contains("system32") {
            entries.push(PersistenceEntry {
                kind: PersistenceKind::NetshHelper,
                name,
                command: dll_path,
                location: r"HKLM\SOFTWARE\Microsoft\NetSh".to_string(),
                is_new: false,
            });
        }
    }

    entries
}

// ── Trait implementation ──────────────────────────────────────────────────────

#[async_trait]
impl PersistenceDetector for WindowsPersistenceDetector {
    async fn detect(&self) -> Result<Vec<PersistenceEntry>, ArqenorError> {
        // All three sources run synchronously on the calling thread.
        // They're fast enough (registry reads + file I/O) that spawn_blocking
        // is unnecessary for Phase 1; revisit if detect() shows up in profiles.
        let mut entries = Vec::new();

        #[cfg(windows)]
        {
            entries.extend(enum_run_keys());
            entries.extend(enum_services());
            entries.extend(enum_scheduled_tasks());
            entries.extend(enum_wmi_subscriptions());
            entries.extend(enum_com_hijacking());
            entries.extend(enum_dll_sideloading());
            entries.extend(enum_active_setup());
            entries.extend(enum_bits_jobs());
            entries.extend(enum_appinit_dlls());
            entries.extend(enum_ifeo_hijacks());
            entries.extend(enum_accessibility_files());
            entries.extend(enum_print_monitors());
            entries.extend(enum_netsh_helpers());
        }

        Ok(entries)
    }

    async fn diff_baseline(
        &self,
        baseline: &[PersistenceEntry],
    ) -> Result<Vec<PersistenceEntry>, ArqenorError> {
        let current = self.detect().await?;
        let new_entries = current
            .into_iter()
            .filter(|e| {
                !baseline
                    .iter()
                    .any(|b| b.name == e.name && b.location == e.location)
            })
            .map(|mut e| {
                e.is_new = true;
                e
            })
            .collect();
        Ok(new_entries)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lc(s: &str) -> String {
        s.to_lowercase()
    }

    /// A DLL loaded from a user-writable location with no overriding safe
    /// prefix is suspicious.
    #[test]
    fn dll_in_temp_is_suspicious() {
        let safe = vec![lc(r"C:\Windows"), lc(r"C:\Program Files")];
        let suspect = vec![
            lc(r"C:\Users\alice\AppData\Local\Temp"),
            lc(r"C:\Users\alice\AppData\Local"),
        ];
        assert!(is_suspicious_dll_path(
            r"C:\Users\Alice\AppData\Local\Temp\evil.dll",
            &safe,
            &suspect,
        ));
    }

    /// Anything under `%SystemRoot%` is trusted, even sub-paths that happen to
    /// match a writable folder (e.g. `C:\Windows\Temp` is technically in the
    /// `TEMP` lineage but is a system-owned staging area).
    #[test]
    fn dll_under_system_root_is_safe() {
        let safe = vec![lc(r"C:\Windows")];
        let suspect = vec![lc(r"C:\Windows\Temp"), lc(r"C:\Users\bob\AppData\Local")];
        assert!(!is_suspicious_dll_path(
            r"C:\Windows\System32\kernel32.dll",
            &safe,
            &suspect,
        ));
        assert!(!is_suspicious_dll_path(
            r"C:\Windows\Temp\spooler.dll",
            &safe,
            &suspect,
        ));
    }

    /// Microsoft Store / WinGet stage their binaries under `%LOCALAPPDATA%`
    /// but should be treated as trusted — the safe-root check must short-
    /// circuit the suspicious-root match.
    #[test]
    fn windowsapps_under_localappdata_is_safe() {
        let local = r"C:\Users\carol\AppData\Local";
        let safe = vec![format!("{}\\microsoft\\windowsapps", lc(local))];
        let suspect = vec![lc(local)];
        assert!(!is_suspicious_dll_path(
            r"C:\Users\carol\AppData\Local\Microsoft\WindowsApps\foo.dll",
            &safe,
            &suspect,
        ));
        // But a sibling path under LocalAppData should still trip.
        assert!(is_suspicious_dll_path(
            r"C:\Users\carol\AppData\Local\NotMicrosoft\bad.dll",
            &safe,
            &suspect,
        ));
    }

    /// A DLL outside both buckets (e.g. on a non-system drive) is not flagged.
    #[test]
    fn dll_outside_known_roots_is_not_flagged() {
        let safe = vec![lc(r"C:\Windows"), lc(r"C:\Program Files")];
        let suspect = vec![lc(r"C:\Users\dave\AppData\Local\Temp")];
        assert!(!is_suspicious_dll_path(
            r"D:\dev\target\debug\my_app.dll",
            &safe,
            &suspect,
        ));
    }

    /// Empty roots must never produce a false positive.
    #[test]
    fn empty_roots_never_flag() {
        assert!(!is_suspicious_dll_path(
            r"C:\Users\eve\AppData\Local\Temp\x.dll",
            &[],
            &[],
        ));
    }

    /// `basename` strips Windows-style paths down to the file name.
    #[test]
    fn basename_extracts_filename() {
        assert_eq!(basename(r"C:\Windows\System32\ntdll.dll"), "ntdll.dll");
        assert_eq!(basename("ntdll.dll"), "ntdll.dll");
        assert_eq!(basename(""), "");
    }
}
