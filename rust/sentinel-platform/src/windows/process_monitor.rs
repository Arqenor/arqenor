use async_trait::async_trait;
use sentinel_core::{
    error::SentinelError,
    models::process::{ProcessEvent, ProcessInfo},
    traits::process_monitor::ProcessMonitor,
};
use sysinfo::{ProcessRefreshKind, RefreshKind, System};
use tokio::sync::mpsc::Sender;
use windows::Win32::Foundation::CloseHandle;
use windows::Win32::System::Threading::{OpenProcess, QueryFullProcessImageNameW, PROCESS_QUERY_LIMITED_INFORMATION};
use windows::core::PWSTR;

pub struct WindowsProcessMonitor;

impl WindowsProcessMonitor {
    pub fn new() -> Self {
        Self
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
    async fn snapshot(&self) -> Result<Vec<ProcessInfo>, SentinelError> {
        let mut sys = System::new_with_specifics(
            RefreshKind::new().with_processes(ProcessRefreshKind::everything()),
        );
        sys.refresh_all();
        Ok(sys.processes().values().map(build_process_info).collect())
    }

    async fn watch(&self, _tx: Sender<ProcessEvent>) -> Result<(), SentinelError> {
        // TODO Phase 2: ETW session via windows-rs StartTrace / ProcessTrace
        Err(SentinelError::NotSupported)
    }

    async fn enrich(&self, pid: u32) -> Result<ProcessInfo, SentinelError> {
        // TODO Phase 2: CreateToolhelp32Snapshot + Module32First for loaded DLLs
        let mut sys = System::new_with_specifics(
            RefreshKind::new().with_processes(ProcessRefreshKind::everything()),
        );
        sys.refresh_all();
        let sysinfo_pid = sysinfo::Pid::from(pid as usize);
        sys.process(sysinfo_pid)
            .map(build_process_info)
            .ok_or_else(|| SentinelError::Platform(format!("pid {pid} not found")))
    }
}
