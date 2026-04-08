use async_trait::async_trait;
use sentinel_core::{
    error::SentinelError,
    models::process::{ProcessEvent, ProcessInfo},
    traits::process_monitor::ProcessMonitor,
};
use sysinfo::{ProcessRefreshKind, RefreshKind, System};
use tokio::sync::mpsc::Sender;

pub struct WindowsProcessMonitor;

impl WindowsProcessMonitor {
    pub fn new() -> Self {
        Self
    }
}

fn build_process_info(p: &sysinfo::Process) -> ProcessInfo {
    ProcessInfo {
        pid:            usize::from(p.pid()) as u32,
        ppid:           p.parent().map(|x| usize::from(x) as u32).unwrap_or(0),
        name:           p.name().to_string(),
        exe_path:       p.exe().map(|e| e.to_string_lossy().into_owned()),
        cmdline:        Some(p.cmd().join(" ")),
        user:           None, // TODO: WinAPI enrichment Phase 2
        sha256:         None, // TODO: hash exe Phase 2
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
