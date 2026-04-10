use async_trait::async_trait;
use chrono::Utc;
use arqenor_core::{
    error::ArqenorError,
    models::process::{ProcessEvent, ProcessEventKind, ProcessInfo},
    traits::process_monitor::ProcessMonitor,
};
use std::{collections::HashSet, time::Duration};
use sysinfo::{ProcessRefreshKind, RefreshKind, System};
use tokio::{sync::mpsc::Sender, time};
use uuid::Uuid;

pub struct LinuxProcessMonitor;

impl LinuxProcessMonitor {
    pub fn new() -> Self {
        Self
    }
}

impl Default for LinuxProcessMonitor {
    fn default() -> Self {
        Self::new()
    }
}

/// Fallback: read /proc/<pid>/exe symlink directly.
/// Works for any process we have permission to access.
fn proc_exe_path(pid: u32) -> Option<String> {
    std::fs::read_link(format!("/proc/{pid}/exe"))
        .ok()
        .map(|p| p.to_string_lossy().into_owned())
}

/// Read /proc/<pid>/maps and return deduplicated shared library (.so) paths.
fn read_proc_maps(pid: u32) -> Vec<String> {
    let content = match std::fs::read_to_string(format!("/proc/{pid}/maps")) {
        Ok(c) => c,
        Err(_) => return Vec::new(),
    };
    let mut seen = HashSet::new();
    let mut libs = Vec::new();
    for line in content.lines() {
        // /proc/<pid>/maps columns: addr perms offset dev inode [path]
        let path_part = match line.split_whitespace().nth(5) {
            Some(p) => p,
            None => continue,
        };
        if !path_part.starts_with('/') {
            continue; // anonymous, [vdso], [heap], etc.
        }
        let lower = path_part.to_ascii_lowercase();
        if !lower.contains(".so") {
            continue;
        }
        if seen.insert(path_part.to_owned()) {
            libs.push(path_part.to_owned());
        }
    }
    libs
}

fn build_process_info(p: &sysinfo::Process) -> ProcessInfo {
    let pid = usize::from(p.pid()) as u32;
    let exe_path = p.exe()
        .map(|e| e.to_string_lossy().into_owned())
        .filter(|s| !s.is_empty())
        .or_else(|| proc_exe_path(pid));

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

/// Minimal stub for a PID that no longer appears in /proc (termination event).
fn stub_process_info(pid: u32) -> ProcessInfo {
    ProcessInfo {
        pid,
        ppid:           0,
        name:           String::new(),
        exe_path:       None,
        cmdline:        None,
        user:           None,
        sha256:         None,
        started_at:     None,
        loaded_modules: vec![],
    }
}

#[async_trait]
impl ProcessMonitor for LinuxProcessMonitor {
    async fn snapshot(&self) -> Result<Vec<ProcessInfo>, ArqenorError> {
        let mut sys = System::new_with_specifics(
            RefreshKind::new().with_processes(ProcessRefreshKind::everything()),
        );
        sys.refresh_all();
        Ok(sys.processes().values().map(build_process_info).collect())
    }

    /// Watch for process creation and termination by polling /proc at 500 ms intervals.
    ///
    /// Spawns an async task that diffs the PID set between polls and emits
    /// `Created`/`Terminated` events.  Pre-existing processes at startup are
    /// not reported.  Exits when `tx` is dropped.
    async fn watch(&self, tx: Sender<ProcessEvent>) -> Result<(), ArqenorError> {
        tokio::spawn(async move { proc_watch_loop(tx).await });
        Ok(())
    }

    /// Returns full process info with `loaded_modules` populated from `/proc/<pid>/maps`.
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

        info.loaded_modules = read_proc_maps(pid);
        Ok(info)
    }
}

// ── /proc polling loop ───────────────────────────────────────────────────────

async fn proc_watch_loop(tx: Sender<ProcessEvent>) {
    let mut sys = System::new_with_specifics(
        RefreshKind::new().with_processes(ProcessRefreshKind::everything()),
    );
    sys.refresh_all();

    // Seed the initial PID set — pre-existing processes do not generate events.
    let mut prev_pids: HashSet<u32> = sys
        .processes()
        .keys()
        .map(|pid| usize::from(*pid) as u32)
        .collect();

    let mut interval = time::interval(Duration::from_millis(500));
    interval.tick().await; // discard the immediate first tick

    loop {
        interval.tick().await;

        sys.refresh_processes(ProcessRefreshKind::everything());

        let current_pids: HashSet<u32> = sys
            .processes()
            .keys()
            .map(|pid| usize::from(*pid) as u32)
            .collect();

        // New PIDs → Created events
        for &pid in current_pids.difference(&prev_pids) {
            let info = sys
                .process(sysinfo::Pid::from(pid as usize))
                .map(build_process_info)
                .unwrap_or_else(|| stub_process_info(pid));

            let evt = ProcessEvent {
                id:         Uuid::new_v4(),
                kind:       ProcessEventKind::Created,
                process:    info,
                event_time: Utc::now(),
            };
            if tx.send(evt).await.is_err() {
                return;
            }
        }

        // Gone PIDs → Terminated events
        for &pid in prev_pids.difference(&current_pids) {
            let evt = ProcessEvent {
                id:         Uuid::new_v4(),
                kind:       ProcessEventKind::Terminated,
                process:    stub_process_info(pid),
                event_time: Utc::now(),
            };
            if tx.send(evt).await.is_err() {
                return;
            }
        }

        prev_pids = current_pids;
    }
}
