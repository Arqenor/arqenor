use arqenor_core::{
    error::ArqenorError,
    models::process::{ProcessEvent, ProcessEventKind, ProcessInfo},
    traits::process_monitor::ProcessMonitor,
};
use async_trait::async_trait;
use chrono::Utc;
use sysinfo::{ProcessRefreshKind, RefreshKind, System};
use tokio::sync::mpsc::Sender;
use uuid::Uuid;

use super::esf_dispatcher::EsfDispatcher;
use super::esf_monitor::EsfRawEvent;

pub struct MacosProcessMonitor;

impl MacosProcessMonitor {
    pub fn new() -> Self {
        Self
    }
}

fn build_process_info(p: &sysinfo::Process) -> ProcessInfo {
    // sysinfo on macOS uses proc_pidpath internally — the best available API.
    // Filter empty strings so we consistently get None instead of Some("").
    let exe_path = p
        .exe()
        .map(|e| e.to_string_lossy().into_owned())
        .filter(|s| !s.is_empty());

    ProcessInfo {
        pid: usize::from(p.pid()) as u32,
        ppid: p.parent().map(|x| usize::from(x) as u32).unwrap_or(0),
        name: p.name().to_string(),
        exe_path,
        cmdline: Some(p.cmd().join(" ")),
        user: None,
        sha256: None,
        started_at: None,
        loaded_modules: vec![],
    }
}

/// Build a minimal ProcessInfo from ESF exec data.
fn esf_exec_process_info(pid: u32, ppid: u32, path: String, args: Vec<String>) -> ProcessInfo {
    let name = path.rsplit('/').next().unwrap_or(&path).to_string();

    ProcessInfo {
        pid,
        ppid,
        name,
        exe_path: Some(path),
        cmdline: Some(args.join(" ")),
        user: None,
        sha256: None,
        started_at: None,
        loaded_modules: vec![],
    }
}

/// Minimal stub for a PID that has exited (termination event).
fn stub_process_info(pid: u32) -> ProcessInfo {
    ProcessInfo {
        pid,
        ppid: 0,
        name: String::new(),
        exe_path: None,
        cmdline: None,
        user: None,
        sha256: None,
        started_at: None,
        loaded_modules: vec![],
    }
}

#[async_trait]
impl ProcessMonitor for MacosProcessMonitor {
    async fn snapshot(&self) -> Result<Vec<ProcessInfo>, ArqenorError> {
        let mut sys = System::new_with_specifics(
            RefreshKind::new().with_processes(ProcessRefreshKind::everything()),
        );
        sys.refresh_all();
        Ok(sys.processes().values().map(build_process_info).collect())
    }

    /// Stream live process events via the macOS Endpoint Security Framework.
    ///
    /// Registers a process-event sender with the global `EsfDispatcher` and
    /// spawns a task that converts raw ESF events into `ProcessEvent` values.
    /// The loop exits when the downstream `tx` channel is dropped.
    async fn watch(&self, tx: Sender<ProcessEvent>) -> Result<(), ArqenorError> {
        let (esf_tx, mut esf_rx) = tokio::sync::mpsc::channel::<EsfRawEvent>(2048);

        {
            let dispatcher = EsfDispatcher::global();
            let mut guard = dispatcher
                .lock()
                .map_err(|e| ArqenorError::Platform(format!("EsfDispatcher lock poisoned: {e}")))?;
            guard.set_process_sender(esf_tx);
            guard.start();
        }

        tokio::spawn(async move {
            while let Some(raw) = esf_rx.recv().await {
                let event = match raw {
                    EsfRawEvent::ProcessExec {
                        pid,
                        ppid,
                        path,
                        args,
                        ..
                    } => ProcessEvent {
                        id: Uuid::new_v4(),
                        kind: ProcessEventKind::Created,
                        process: esf_exec_process_info(pid, ppid, path, args),
                        event_time: Utc::now(),
                    },
                    EsfRawEvent::ProcessExit { pid } => ProcessEvent {
                        id: Uuid::new_v4(),
                        kind: ProcessEventKind::Terminated,
                        process: stub_process_info(pid),
                        event_time: Utc::now(),
                    },
                    // ProcessFork is redundant — we will receive the exec event
                    // for the child process. All other variants are not
                    // process-related.
                    _ => continue,
                };

                if tx.send(event).await.is_err() {
                    break;
                }
            }
        });

        Ok(())
    }

    async fn enrich(&self, pid: u32) -> Result<ProcessInfo, ArqenorError> {
        let mut sys = System::new_with_specifics(
            RefreshKind::new().with_processes(ProcessRefreshKind::everything()),
        );
        sys.refresh_all();
        let sysinfo_pid = sysinfo::Pid::from(pid as usize);
        sys.process(sysinfo_pid)
            .map(build_process_info)
            .ok_or_else(|| ArqenorError::Platform(format!("pid {pid} not found")))
    }
}
