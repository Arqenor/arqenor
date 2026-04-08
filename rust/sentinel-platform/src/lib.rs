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

pub fn new_fim_monitor() -> fim::FimMonitor {
    #[cfg(target_os = "windows")]
    let paths = fim::windows_critical_paths();

    #[cfg(target_os = "linux")]
    let paths = fim::linux_critical_paths();

    #[cfg(not(any(target_os = "windows", target_os = "linux")))]
    let paths = Vec::new();

    fim::FimMonitor::with_paths(paths)
}
