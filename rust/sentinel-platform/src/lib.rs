#[cfg(target_os = "windows")]
pub mod windows;
#[cfg(target_os = "linux")]
pub mod linux;
#[cfg(target_os = "macos")]
pub mod macos;

pub mod fim;

// Fail at compile time on unsupported platforms.
#[cfg(not(any(target_os = "windows", target_os = "linux", target_os = "macos")))]
compile_error!("SENTINEL: unsupported platform (only windows / linux / macos)");

use sentinel_core::traits::{
    connection_monitor::ConnectionMonitor,
    fs_scanner::FsScanner,
    persistence::PersistenceDetector,
    process_monitor::ProcessMonitor,
};

pub fn new_connection_monitor() -> Box<dyn ConnectionMonitor> {
    cfg_if::cfg_if! {
        if #[cfg(target_os = "windows")] {
            Box::new(windows::connections::WindowsConnectionMonitor::new())
        } else if #[cfg(target_os = "linux")] {
            Box::new(linux::connections::LinuxConnectionMonitor::new())
        } else {
            Box::new(macos::connections::MacosConnectionMonitor::new())
        }
    }
}

/// Enrich a set of connections with Windows Firewall block status for
/// lateral-movement ports.  On non-Windows or when the `firewall-check`
/// feature is disabled this is a no-op.
pub fn enrich_firewall_status(connections: &mut [sentinel_core::models::connection::ConnectionInfo]) {
    #[cfg(all(target_os = "windows", feature = "firewall-check"))]
    {
        use sentinel_core::models::connection::{ConnState, LATERAL_MOVEMENT_PORTS};

        // Collect the set of LISTEN ports that need a firewall check.
        let listen_ports: Vec<u16> = connections
            .iter()
            .filter(|c| c.state == ConnState::Listen)
            .filter_map(sentinel_core::models::connection::local_port)
            .filter(|p| LATERAL_MOVEMENT_PORTS.contains(p))
            .collect::<std::collections::HashSet<_>>()
            .into_iter()
            .collect();

        if listen_ports.is_empty() {
            return;
        }

        match windows::firewall::query_firewall_block_status(&listen_ports) {
            Ok(statuses) => {
                for conn in connections.iter_mut() {
                    if conn.state != ConnState::Listen {
                        continue;
                    }
                    let port = match sentinel_core::models::connection::local_port(conn) {
                        Some(p) => p,
                        None => continue,
                    };
                    if let Some(status) = statuses.iter().find(|s| s.port == port) {
                        conn.firewall_blocked = Some(status.blocked);
                    }
                }
            }
            Err(e) => {
                tracing::warn!("firewall query failed: {e}");
            }
        }
    }

    // Suppress unused-variable warning on non-Windows / feature-disabled builds.
    #[cfg(not(all(target_os = "windows", feature = "firewall-check")))]
    let _ = connections;
}

pub fn new_process_monitor() -> Box<dyn ProcessMonitor> {
    cfg_if::cfg_if! {
        if #[cfg(target_os = "windows")] {
            Box::new(windows::process_monitor::WindowsProcessMonitor::new())
        } else if #[cfg(target_os = "linux")] {
            Box::new(linux::process_monitor::LinuxProcessMonitor::new())
        } else {
            Box::new(macos::process_monitor::MacosProcessMonitor::new())
        }
    }
}

pub fn new_fs_scanner() -> Box<dyn FsScanner> {
    cfg_if::cfg_if! {
        if #[cfg(target_os = "windows")] {
            Box::new(windows::fs_scanner::WindowsFsScanner::new())
        } else if #[cfg(target_os = "linux")] {
            Box::new(linux::fs_scanner::LinuxFsScanner::new())
        } else {
            Box::new(macos::fs_scanner::MacosFsScanner::new())
        }
    }
}

pub fn new_persistence_detector() -> Box<dyn PersistenceDetector> {
    cfg_if::cfg_if! {
        if #[cfg(target_os = "windows")] {
            Box::new(windows::persistence::WindowsPersistenceDetector::new())
        } else if #[cfg(target_os = "linux")] {
            Box::new(linux::persistence::LinuxPersistenceDetector::new())
        } else {
            Box::new(macos::persistence::MacosPersistenceDetector::new())
        }
    }
}

#[cfg(target_os = "windows")]
pub fn new_cred_guard() -> windows::cred_guard::CredGuard {
    windows::cred_guard::CredGuard::new()
}

/// Create an [`EtwMonitor`] wired to an existing ETW event receiver.
///
/// Spawn the returned monitor on a dedicated thread:
/// ```rust,ignore
/// let (consumer, event_rx) = new_etw_consumer()?;
/// let monitor = new_etw_monitor(event_rx);
/// std::thread::spawn(move || monitor.run_blocking(alert_tx));
/// ```
#[cfg(target_os = "windows")]
pub fn new_etw_monitor(
    event_rx: std::sync::mpsc::Receiver<windows::etw_consumer::EtwEvent>,
) -> windows::etw_monitor::EtwMonitor {
    windows::etw_monitor::EtwMonitor::new(event_rx)
}

/// Start a Windows ETW real-time consumer session.
///
/// Returns `(EtwConsumer, Receiver<EtwEvent>)` on success.  Requires
/// Administrator rights or `SeSystemProfilePrivilege`.
#[cfg(target_os = "windows")]
pub fn new_etw_consumer() -> Result<
    (
        windows::etw_consumer::EtwConsumer,
        std::sync::mpsc::Receiver<windows::etw_consumer::EtwEvent>,
    ),
    sentinel_core::error::SentinelError,
> {
    windows::etw_consumer::EtwConsumer::start()
}

/// Start the kernel driver bridge (Windows only, `kernel-driver` feature).
///
/// Connects to `\SentinelPort` and streams kernel events into the standard
/// `ProcessEvent` / `FileEvent` / `Alert` channels consumed by the detection
/// pipeline.  Fails if the driver is not loaded.
///
/// ```rust,ignore
/// let senders = DriverBridgeSenders { process_tx, file_tx, alert_tx };
/// start_driver_bridge(DriverBridgeConfig::default(), senders).await?;
/// ```
#[cfg(all(target_os = "windows", feature = "kernel-driver"))]
pub async fn start_driver_bridge(
    config:  windows::driver_bridge::DriverBridgeConfig,
    senders: windows::driver_bridge::DriverBridgeSenders,
) -> Result<(), sentinel_core::error::SentinelError> {
    windows::driver_bridge::start_driver_bridge(config, senders).await
}

pub fn new_fim_monitor() -> fim::FimMonitor {
    #[cfg(target_os = "windows")]
    let paths = fim::windows_critical_paths();

    #[cfg(target_os = "linux")]
    let paths = fim::linux_critical_paths();

    #[cfg(target_os = "macos")]
    let paths = fim::macos_critical_paths();

    #[cfg(not(any(target_os = "windows", target_os = "linux", target_os = "macos")))]
    let paths = Vec::new();

    fim::FimMonitor::with_paths(paths)
}
