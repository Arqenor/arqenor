use async_trait::async_trait;
use arqenor_core::{
    error::ArqenorError,
    models::process::{ProcessEvent, ProcessInfo},
    traits::process_monitor::ProcessMonitor,
};
use sysinfo::{ProcessRefreshKind, RefreshKind, System};
use tokio::sync::mpsc::Sender;
use windows::Win32::Foundation::CloseHandle;
use windows::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Module32FirstW, Module32NextW, MODULEENTRY32W,
    TH32CS_SNAPMODULE, TH32CS_SNAPMODULE32,
};
use windows::Win32::System::EventLog::{EvtClose, EvtNext, EvtRender, EvtSubscribe, EVT_HANDLE};
use windows::Win32::System::Threading::{
    CreateEventW, OpenProcess, QueryFullProcessImageNameW,
    WaitForSingleObject, PROCESS_QUERY_LIMITED_INFORMATION,
};
use windows::core::{PCWSTR, PWSTR};

pub struct WindowsProcessMonitor;

impl WindowsProcessMonitor {
    pub fn new() -> Self {
        Self
    }
}

impl Default for WindowsProcessMonitor {
    fn default() -> Self {
        Self::new()
    }
}

/// Fallback exe path resolution using QueryFullProcessImageNameW.
/// Works with PROCESS_QUERY_LIMITED_INFORMATION — less restrictive than
/// what sysinfo uses internally (PROCESS_QUERY_INFORMATION | PROCESS_VM_READ).
fn win32_exe_path(pid: u32) -> Option<String> {
    unsafe {
        let handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid).ok()?;
        let mut buf = [0u16; 1024];
        let mut size = 1024u32;
        let ok = QueryFullProcessImageNameW(
            handle,
            Default::default(), // PROCESS_NAME_WIN32 = 0
            PWSTR(buf.as_mut_ptr()),
            &mut size,
        )
        .is_ok();
        let _ = CloseHandle(handle);
        if ok && size > 0 {
            Some(String::from_utf16_lossy(&buf[..size as usize]))
        } else {
            None
        }
    }
}

/// Enumerate all modules (EXE + DLLs) loaded in the given process.
///
/// Uses `CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32)`
/// so 32-bit modules inside a 64-bit process are also captured.
/// Returns an empty Vec on any error (access denied, protected process, etc.).
fn enum_modules(pid: u32) -> Vec<String> {
    let mut modules = Vec::new();
    unsafe {
        let snapshot = match CreateToolhelp32Snapshot(
            TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32,
            pid,
        ) {
            Ok(h) => h,
            Err(_) => return modules,
        };

        let mut entry = MODULEENTRY32W {
            dwSize: std::mem::size_of::<MODULEENTRY32W>() as u32,
            ..Default::default()
        };

        if Module32FirstW(snapshot, &mut entry).is_ok() {
            loop {
                // szExePath is [u16; 260], null-terminated
                let len = entry
                    .szExePath
                    .iter()
                    .position(|&c| c == 0)
                    .unwrap_or(entry.szExePath.len());
                let path = String::from_utf16_lossy(&entry.szExePath[..len]);
                if !path.is_empty() {
                    modules.push(path);
                }
                if Module32NextW(snapshot, &mut entry).is_err() {
                    break;
                }
            }
        }
        let _ = CloseHandle(snapshot);
    }
    modules
}

fn build_process_info(p: &sysinfo::Process) -> ProcessInfo {
    let pid = usize::from(p.pid()) as u32;
    let exe_path = p.exe()
        .map(|e| e.to_string_lossy().into_owned())
        .filter(|s| !s.is_empty())
        .or_else(|| win32_exe_path(pid));

    ProcessInfo {
        pid,
        ppid:           p.parent().map(|x| usize::from(x) as u32).unwrap_or(0),
        name:           p.name().to_string(),
        exe_path,
        cmdline:        Some(p.cmd().join(" ")),
        user:           None,
        sha256:         None,
        started_at:     None,
        loaded_modules: vec![],
    }
}

#[async_trait]
impl ProcessMonitor for WindowsProcessMonitor {
    async fn snapshot(&self) -> Result<Vec<ProcessInfo>, ArqenorError> {
        let mut sys = System::new_with_specifics(
            RefreshKind::new().with_processes(ProcessRefreshKind::everything()),
        );
        sys.refresh_all();
        Ok(sys.processes().values().map(build_process_info).collect())
    }

    /// Stream real-time process creation (Event 4688) and termination (4689)
    /// from the Windows Security event log via `EvtSubscribe`.
    ///
    /// Requires: administrator rights + "Audit Process Creation" policy enabled.
    /// Returns `Ok(())` immediately; events flow through `tx` in the background.
    async fn watch(&self, tx: Sender<ProcessEvent>) -> Result<(), ArqenorError> {
        tokio::task::spawn_blocking(move || evt_watch_loop(tx));
        Ok(())
    }

    /// Returns full process info with `loaded_modules` populated via
    /// `CreateToolhelp32Snapshot` + `Module32FirstW`/`Module32NextW`.
    async fn enrich(&self, pid: u32) -> Result<ProcessInfo, ArqenorError> {
        let mut sys = System::new_with_specifics(
            RefreshKind::new().with_processes(ProcessRefreshKind::everything()),
        );
        sys.refresh_all();
        let sysinfo_pid = sysinfo::Pid::from(pid as usize);
        let mut info = sys
            .process(sysinfo_pid)
            .map(build_process_info)
            .ok_or_else(|| ArqenorError::Platform(format!("pid {pid} not found")))?;

        info.loaded_modules = enum_modules(pid);
        Ok(info)
    }
}

// ── Phase 2: EvtSubscribe-based process event streaming ──────────────────────

/// Blocking loop: subscribes to Windows Security log events 4688 (process
/// create) and 4689 (process terminate), renders each as XML, parses the
/// relevant fields, and sends `ProcessEvent`s on `tx`.
///
/// Runs inside `tokio::task::spawn_blocking` — never call from async context.
fn evt_watch_loop(tx: Sender<ProcessEvent>) {
    // Encode string literals as null-terminated UTF-16 slices for PCWSTR
    let channel: Vec<u16> = "Security\0".encode_utf16().collect();
    let query: Vec<u16> =
        "*[System[(EventID=4688) or (EventID=4689)]]\0".encode_utf16().collect();

    unsafe {
        // Signal event: EvtSubscribe will set this when new events arrive
        let signal = match CreateEventW(None, false, false, None) {
            Ok(h) => h,
            Err(_) => return,
        };

        // Subscribe to future Security log events (signal-based, no callback)
        let sub = match EvtSubscribe(
            EVT_HANDLE(0),                     // local session
            signal,                            // signal handle
            PCWSTR::from_raw(channel.as_ptr()),
            PCWSTR::from_raw(query.as_ptr()),
            EVT_HANDLE(0),                     // no bookmark
            None,                              // no context
            None,                              // no callback
            1u32,                              // EvtSubscribeToFutureEvents
        ) {
            Ok(h) => h,
            Err(_) => {
                let _ = CloseHandle(signal);
                return;
            }
        };

        let mut batch = [0isize; 32];
        let mut render_buf: Vec<u16> = vec![0u16; 8192];

        loop {
            // Wait up to 500 ms for new events, then check if channel closed
            WaitForSingleObject(signal, 500);

            if tx.is_closed() {
                break;
            }

            // Drain all queued events (EvtNext with timeout=0 → poll only)
            'drain: loop {
                let mut returned = 0u32;
                if EvtNext(
                    sub,
                    &mut batch,  // events: &mut [isize]
                    0,           // timeout ms — non-blocking poll
                    0,           // flags — reserved
                    &mut returned,
                )
                .is_err()
                {
                    break 'drain; // ERROR_NO_MORE_ITEMS or channel error
                }

                for i in 0..returned as usize {
                    let evt_handle = EVT_HANDLE(batch[i]);
                    if let Some(evt) = render_event(evt_handle, &mut render_buf) {
                        if tx.blocking_send(evt).is_err() {
                            // Receiver dropped — close remaining handles and exit
                            for j in i..returned as usize {
                                let _ = EvtClose(EVT_HANDLE(batch[j]));
                            }
                            let _ = EvtClose(sub);
                            let _ = CloseHandle(signal);
                            return;
                        }
                    }
                    let _ = EvtClose(evt_handle);
                }
            }
        }

        let _ = EvtClose(sub);
        let _ = CloseHandle(signal);
    }
}

/// Render one EVT_HANDLE to XML, then parse out a `ProcessEvent`.
/// Resizes the buffer if the initial allocation is too small.
unsafe fn render_event(handle: EVT_HANDLE, buf: &mut Vec<u16>) -> Option<ProcessEvent> {
    use chrono::Utc;
    use arqenor_core::models::process::{ProcessEventKind, ProcessInfo};
    use uuid::Uuid;

    let mut used = 0u32;
    let mut prop_count = 0u32;

    // First try with the pre-allocated buffer
    let render_ok = EvtRender(
        EVT_HANDLE(0),
        handle,
        1u32, // EvtRenderEventXml
        (buf.len() * 2) as u32,
        Some(buf.as_mut_ptr() as *mut _),
        &mut used,
        &mut prop_count,
    );

    if render_ok.is_err() {
        if used == 0 {
            return None;
        }
        // Buffer too small — resize and retry
        buf.resize((used / 2 + 1) as usize, 0);
        EvtRender(
            EVT_HANDLE(0),
            handle,
            1u32,
            (buf.len() * 2) as u32,
            Some(buf.as_mut_ptr() as *mut _),
            &mut used,
            &mut prop_count,
        )
        .ok()?;
    }

    // used is in bytes; last char is null terminator → strip it
    let char_count = (used / 2).saturating_sub(1) as usize;
    let xml = String::from_utf16_lossy(&buf[..char_count]);

    let event_id: u32 = extract_evt_system(&xml, "EventID")?.parse().ok()?;
    let kind = match event_id {
        4688 => ProcessEventKind::Created,
        4689 => ProcessEventKind::Terminated,
        _    => return None,
    };

    let (pid, ppid, name, exe_path, cmdline) = match event_id {
        4688 => {
            let new_pid  = parse_hex_pid(&extract_evt_data(&xml, "NewProcessId").unwrap_or_default());
            let par_pid  = parse_hex_pid(&extract_evt_data(&xml, "ProcessId").unwrap_or_default());
            let exe      = extract_evt_data(&xml, "NewProcessName");
            let cmd      = extract_evt_data(&xml, "CommandLine");
            let basename = exe.as_deref()
                .and_then(|p| p.rsplit(['\\', '/']).next())
                .unwrap_or_default()
                .to_owned();
            (new_pid, par_pid, basename, exe, cmd)
        }
        4689 => {
            let pid     = parse_hex_pid(&extract_evt_data(&xml, "ProcessId").unwrap_or_default());
            let exe     = extract_evt_data(&xml, "ProcessName");
            let basename = exe.as_deref()
                .and_then(|p| p.rsplit(['\\', '/']).next())
                .unwrap_or_default()
                .to_owned();
            (pid, 0, basename, exe, None)
        }
        _ => return None,
    };

    Some(ProcessEvent {
        id: Uuid::new_v4(),
        kind,
        process: ProcessInfo {
            pid,
            ppid,
            name,
            exe_path,
            cmdline,
            user: None,
            sha256: None,
            started_at: None,
            loaded_modules: vec![],
        },
        event_time: Utc::now(),
    })
}

/// Extract a value from a `<Tag>value</Tag>` element in the System section.
fn extract_evt_system<'a>(xml: &'a str, tag: &str) -> Option<&'a str> {
    let open  = format!("<{tag}>");
    let close = format!("</{tag}>");
    let start = xml.find(&open)? + open.len();
    let end   = xml[start..].find(close.as_str())?;
    Some(&xml[start..start + end])
}

/// Extract the text content from `<Data Name='name'>text</Data>`.
fn extract_evt_data(xml: &str, name: &str) -> Option<String> {
    let needle = format!("Name='{name}'>");
    let start  = xml.find(&needle)? + needle.len();
    let end    = xml[start..].find("</Data>")?;
    let value  = xml[start..start + end].trim().to_string();
    if value.is_empty() { None } else { Some(value) }
}

/// Parse a hex PID string like `"0x1a2b"` or `"6699"` into a `u32`.
fn parse_hex_pid(s: &str) -> u32 {
    let s = s.trim();
    if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        u32::from_str_radix(hex, 16).unwrap_or(0)
    } else {
        s.parse().unwrap_or(0)
    }
}
