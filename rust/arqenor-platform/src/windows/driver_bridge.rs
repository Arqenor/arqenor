//! Bridge between the ARQENOR kernel driver and the detection pipeline.
//!
//! Connects to the `\ArqenorPort` filter communication port, receives
//! `KernelEvent`s (process, file, registry) and converts them into the
//! standard `ProcessEvent` / `FileEvent` / `Alert` types consumed by the
//! `DetectionPipeline`.
//!
//! Requires the `kernel-driver` cargo feature and a loaded `arqenor_driver.sys`.
//!
//! # Architecture
//! ```text
//! arqenor_driver.sys (kernel)
//!   │ FltSendMessage
//!   ▼
//! FilterGetMessage (client crate, spawn_blocking)
//!   │ KernelEvent stream
//!   ▼
//! DriverBridge (this module)
//!   ├──► ProcessEvent  → proc_tx  → DetectionPipeline
//!   ├──► FileEvent     → fim_tx   → DetectionPipeline
//!   └──► Alert (registry persistence) → alert_tx
//! ```

use chrono::Utc;
use arqenor_core::{
    error::ArqenorError,
    models::{
        alert::{Alert, Severity},
        file_event::{FileEvent, FileEventKind},
        process::{ProcessEvent, ProcessEventKind, ProcessInfo},
    },
};
use arqenor_driver_client::DriverClient;
use arqenor_driver_common::KernelEventKind;
use std::collections::HashMap;
use tokio::sync::mpsc::Sender;
use tokio_stream::StreamExt;
use tracing::{debug, info, warn};
use uuid::Uuid;

/// Configuration for the driver bridge.
pub struct DriverBridgeConfig {
    /// If set, file events outside these path prefixes are dropped.
    /// Empty = accept all file events.
    pub file_path_prefixes: Vec<String>,
}

impl Default for DriverBridgeConfig {
    fn default() -> Self {
        Self {
            file_path_prefixes: Vec::new(),
        }
    }
}

/// Senders for the three event types produced by the bridge.
pub struct DriverBridgeSenders {
    pub process_tx: Sender<ProcessEvent>,
    pub file_tx:    Sender<FileEvent>,
    pub alert_tx:   Sender<Alert>,
}

/// Connect to the kernel driver and start streaming events.
///
/// Returns `Ok(())` immediately after spawning the background stream consumer.
/// Fails if the driver is not loaded.
pub async fn start_driver_bridge(
    config:  DriverBridgeConfig,
    senders: DriverBridgeSenders,
) -> Result<(), ArqenorError> {
    let client = DriverClient::connect()
        .map_err(|e| ArqenorError::Platform(format!("driver connect: {e}")))?;

    info!("Connected to ARQENOR kernel driver (\\ArqenorPort)");

    let mut stream = client.into_event_stream();

    tokio::spawn(async move {
        let prefixes = config.file_path_prefixes;
        let mut event_count: u64 = 0;

        while let Some(result) = stream.next().await {
            let event = match result {
                Ok(e) => e,
                Err(e) => {
                    warn!("driver event error: {e}");
                    continue;
                }
            };

            event_count += 1;

            match event.kind {
                KernelEventKind::ProcessCreate => {
                    let payload = unsafe { &event.payload.process_create };
                    let image = utf16_to_string(&payload.image_path);
                    let cmdline = utf16_to_string(&payload.cmdline);
                    let name = image
                        .rsplit('\\')
                        .next()
                        .unwrap_or("")
                        .to_owned();

                    let proc_event = ProcessEvent {
                        id:         Uuid::new_v4(),
                        kind:       ProcessEventKind::Created,
                        process:    ProcessInfo {
                            pid:            payload.pid,
                            ppid:           payload.ppid,
                            name,
                            exe_path:       Some(nt_path_to_dos(&image)),
                            cmdline:        if cmdline.is_empty() { None } else { Some(cmdline) },
                            user:           None,
                            sha256:         None,
                            started_at:     None,
                            loaded_modules: vec![],
                        },
                        event_time: Utc::now(),
                    };

                    if senders.process_tx.send(proc_event).await.is_err() {
                        debug!("process_tx closed — stopping driver bridge");
                        break;
                    }
                }

                KernelEventKind::ProcessTerminate => {
                    let payload = unsafe { &event.payload.process_terminate };
                    let proc_event = ProcessEvent {
                        id:         Uuid::new_v4(),
                        kind:       ProcessEventKind::Terminated,
                        process:    ProcessInfo {
                            pid:  payload.pid,
                            ppid: 0,
                            name: String::new(),
                            exe_path: None,
                            cmdline: None,
                            user: None,
                            sha256: None,
                            started_at: None,
                            loaded_modules: vec![],
                        },
                        event_time: Utc::now(),
                    };

                    if senders.process_tx.send(proc_event).await.is_err() {
                        break;
                    }
                }

                KernelEventKind::FileCreate
                | KernelEventKind::FileWrite
                | KernelEventKind::FileRename
                | KernelEventKind::FileDelete => {
                    let payload = unsafe { &event.payload.file };
                    let path = nt_path_to_dos(&utf16_to_string(&payload.path));

                    // Filter by prefix if configured.
                    if !prefixes.is_empty()
                        && !prefixes.iter().any(|p| path.starts_with(p.as_str()))
                    {
                        continue;
                    }

                    let kind = match event.kind {
                        KernelEventKind::FileCreate => FileEventKind::Created,
                        KernelEventKind::FileWrite  => FileEventKind::Modified,
                        KernelEventKind::FileDelete => FileEventKind::Deleted,
                        KernelEventKind::FileRename => FileEventKind::Renamed,
                        _ => unreachable!(),
                    };

                    let file_event = FileEvent {
                        id:         Uuid::new_v4(),
                        kind,
                        path,
                        sha256:     None,
                        size:       None,
                        event_time: Utc::now(),
                    };

                    if senders.file_tx.send(file_event).await.is_err() {
                        break;
                    }
                }

                KernelEventKind::RegistrySetValue
                | KernelEventKind::RegistryCreateKey
                | KernelEventKind::RegistryDeleteKey => {
                    let payload = unsafe { &event.payload.registry };
                    let key_path = utf16_to_string(&payload.key_path);
                    let value_name = utf16_to_string(&payload.value_name);

                    // Flag known persistence registry paths.
                    let is_persistence = is_persistence_registry_path(&key_path);
                    if !is_persistence {
                        continue;
                    }

                    let action = match event.kind {
                        KernelEventKind::RegistrySetValue  => "SetValue",
                        KernelEventKind::RegistryCreateKey => "CreateKey",
                        KernelEventKind::RegistryDeleteKey => "DeleteKey",
                        _ => unreachable!(),
                    };

                    let mut metadata = HashMap::new();
                    metadata.insert("key_path".into(), key_path.clone());
                    metadata.insert("action".into(), action.into());
                    metadata.insert("pid".into(), payload.pid.to_string());
                    if !value_name.is_empty() {
                        metadata.insert("value_name".into(), value_name);
                    }

                    let alert = Alert {
                        id:          Uuid::new_v4(),
                        severity:    Severity::High,
                        kind:        "registry_persistence".into(),
                        message:     format!(
                            "Registry persistence: {action} on {}",
                            key_path
                        ),
                        occurred_at: Utc::now(),
                        metadata,
                        rule_id:     Some("SENT-K001".into()),
                        attack_id:   Some("T1547.001".into()),
                    };

                    if senders.alert_tx.send(alert).await.is_err() {
                        break;
                    }
                }
            }
        }

        info!(event_count, "driver bridge stopped");
    });

    Ok(())
}

// ── Helpers ──────────────────────────────────────────────────────────────────

/// Convert a null-terminated UTF-16LE buffer to a Rust String.
fn utf16_to_string(buf: &[u16]) -> String {
    let len = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
    String::from_utf16_lossy(&buf[..len])
}

/// Convert NT device paths to DOS paths.
/// `\Device\HarddiskVolume3\Windows\System32\cmd.exe` → `C:\Windows\System32\cmd.exe`
///
/// Tries a simple prefix replacement for common volumes.
/// Falls back to returning the original path if no mapping found.
fn nt_path_to_dos(nt_path: &str) -> String {
    // Common prefix — this covers 90%+ of cases on typical installs.
    // A full implementation would use QueryDosDevice to build a complete map.
    if let Some(rest) = nt_path.strip_prefix("\\Device\\HarddiskVolume") {
        // rest = "3\Windows\..." — strip the volume number
        if let Some(idx) = rest.find('\\') {
            return format!("C:{}", &rest[idx..]);
        }
    }
    if let Some(rest) = nt_path.strip_prefix("\\??\\") {
        return rest.to_owned();
    }
    nt_path.to_owned()
}

/// Check if a registry key path is a known persistence location.
fn is_persistence_registry_path(key: &str) -> bool {
    let lower = key.to_lowercase();
    const PERSISTENCE_KEYS: &[&str] = &[
        "\\currentversion\\run",
        "\\currentversion\\runonce",
        "\\currentversion\\runservices",
        "\\currentversion\\explorer\\shell folders",
        "\\currentversion\\winlogon",
        "\\currentversion\\windows\\appinit_dlls",
        "\\currentversion\\image file execution options",
        "\\currentcontrolset\\services",
        "\\currentcontrolset\\control\\print\\monitors",
        "\\currentcontrolset\\control\\lsa",
        "\\currentcontrolset\\control\\networkprovider",
        "\\currentcontrolset\\services\\netsh",
        "\\active setup\\installed components",
        "\\classes\\clsid",
        "\\environment",
    ];
    PERSISTENCE_KEYS.iter().any(|pat| lower.contains(pat))
}
