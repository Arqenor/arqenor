use anyhow::Result;
use clap::Args;
use arqenor_core::{
    ioc::{feeds, IocDatabase},
    models::alert::{Alert, Severity},
    models::connection::ConnectionInfo,
    pipeline::{DetectionPipeline, PipelineConfig},
    rules::sigma,
    traits::connection_monitor::spawn_polling_watch,
};
use arqenor_platform::{new_connection_monitor, new_fs_scanner, new_process_monitor};
use arqenor_store::SqliteStore;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::{mpsc, RwLock};
use tracing::warn;

/// Default connection polling interval in milliseconds (5 seconds).
const CONN_POLL_INTERVAL_MS: u64 = 5_000;

#[derive(Args)]
pub struct WatchArgs {
    /// Directory to monitor for file-integrity changes.
    /// Defaults to C:\Windows\System32 on Windows, /etc on Linux.
    #[arg(long)]
    pub watch_path: Option<PathBuf>,

    /// SQLite database for alert persistence.
    #[arg(long, default_value = "arqenor.db")]
    pub db: PathBuf,

    /// Directory containing SIGMA YAML rules.
    #[arg(long)]
    pub sigma_dir: Option<PathBuf>,

    /// Disable IOC threat-intelligence feed loading.
    #[arg(long)]
    pub no_ioc: bool,

}

pub async fn run(args: WatchArgs) -> Result<()> {
    let mut config = PipelineConfig::default();
    let watch_path = args.watch_path.unwrap_or_else(platform_default_path);

    // ── Load SIGMA rules ────────────────────────────────────────────────────
    if let Some(ref dir) = args.sigma_dir {
        config.sigma_rules = sigma::load_sigma_rules_from_dir(dir);
    }
    let n_sigma = config.sigma_rules.len();

    // ── IOC threat-intelligence feeds ───────────────────────────────────────
    let ioc_db = if !args.no_ioc {
        let db = Arc::new(RwLock::new(IocDatabase::new()));
        // Initial feed load (best-effort, non-blocking on failure).
        {
            let mut guard = db.write().await;
            let loaded = feeds::refresh_all_feeds(&mut guard).await;
            if loaded > 0 {
                println!("  IOC feeds: {loaded} indicators loaded");
            } else {
                warn!("IOC feed load returned 0 indicators (offline or error)");
            }
        }
        // Background refresh every 4 hours.
        feeds::spawn_feed_refresh_loop(Arc::clone(&db), std::time::Duration::from_secs(4 * 3600));
        config.ioc_db = Some(Arc::clone(&db));
        Some(db)
    } else {
        None
    };

    let n_rules  = config.rules.len();
    let n_file   = config.sensitive_paths.len();
    let n_ioc    = if let Some(ref db) = ioc_db {
        db.read().await.stats().total
    } else {
        0
    };

    // ── Channels ─────────────────────────────────────────────────────────────
    let (proc_tx, proc_rx)       = mpsc::channel(512);
    let (fim_tx, fim_rx)         = mpsc::channel(512);
    let (conn_tx, conn_rx)       = mpsc::channel::<ConnectionInfo>(512);
    let (alert_tx, mut alert_rx) = mpsc::channel::<Alert>(256);

    // ── Start platform watchers (non-fatal if unsupported) ───────────────────
    //
    if let Err(e) = new_process_monitor().watch(proc_tx).await {
        warn!("process watcher unavailable: {e}");
    }
    if let Err(e) = new_fs_scanner().watch_path(&watch_path, fim_tx).await {
        warn!("FIM watcher unavailable: {e}");
    }

    // ── Start connection monitor (non-fatal if unsupported) ─────────────────
    {
        let conn_monitor = new_connection_monitor();
        match conn_monitor.watch(conn_tx.clone(), CONN_POLL_INTERVAL_MS).await {
            Ok(()) => {
                tracing::info!("connection monitor: platform watch active");
            }
            Err(arqenor_core::error::ArqenorError::NotSupported) => {
                // Fall back to the generic polling implementation.
                let fallback_monitor = new_connection_monitor();
                spawn_polling_watch(fallback_monitor, conn_tx, CONN_POLL_INTERVAL_MS);
                tracing::info!(
                    "connection monitor: polling fallback ({}ms)",
                    CONN_POLL_INTERVAL_MS,
                );
            }
            Err(e) => {
                warn!("connection monitor unavailable: {e}");
            }
        }
    }

    // ── Host scan channel (platform modules push alerts here) ──────────────
    let (scan_tx, scan_rx) = mpsc::channel::<Alert>(256);

    // ── Start detection pipeline (with connection stream) ─────────────────────
    let pipeline = DetectionPipeline::with_connections(config, proc_rx, fim_rx, conn_rx, alert_tx)
        .with_scan_alerts(scan_rx);
    let stats    = pipeline.stats();
    tokio::spawn(pipeline.run());

    // ── Periodic host scans (Windows: memory, ntdll hooks, BYOVD) ────────
    #[cfg(target_os = "windows")]
    {
        tokio::spawn(run_windows_host_scans(scan_tx));
    }
    #[cfg(not(target_os = "windows"))]
    drop(scan_tx);

    // ── DB writer thread ──────────────────────────────────────────────────────
    let db_path = args.db.clone();
    let (db_tx, db_rx) = std::sync::mpsc::sync_channel::<Alert>(256);
    std::thread::spawn(move || {
        match SqliteStore::open(&db_path) {
            Ok(store) => {
                while let Ok(alert) = db_rx.recv() {
                    if let Err(e) = store.insert_alert(&alert) {
                        warn!("db write error: {e}");
                    }
                }
            }
            Err(e) => warn!("failed to open alert store: {e}"),
        }
    });

    // ── Periodic stats ───────────────────────────────────────────────────────
    let stats_for_ticker = stats.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(60));
        interval.tick().await; // skip immediate first tick
        loop {
            interval.tick().await;
            let s = stats_for_ticker.snapshot();
            eprintln!(
                "[stats] proc:{} file:{} conn:{} alerts:{}",
                s.process_events, s.file_events, s.conn_events, s.alerts_fired,
            );
        }
    });

    // ── Alert consumer ────────────────────────────────────────────────────────
    println!(
        "ARQENOR watch — {n_rules} LOLBin, {n_sigma} SIGMA, {n_file} file rules, {n_ioc} IOCs | FIM: {} | conn: polling {}ms | db: {}",
        watch_path.display(),
        CONN_POLL_INTERVAL_MS,
        args.db.display(),
    );
    println!("Press Ctrl-C to stop.\n{}\n", "─".repeat(72));

    while let Some(alert) = alert_rx.recv().await {
        print_alert(&alert);
        let _ = db_tx.send(alert);
    }

    let snap = stats.snapshot();
    println!("\n{}", "─".repeat(72));
    println!(
        "Session: {} process events, {} file events, {} conn events, {} alerts",
        snap.process_events, snap.file_events, snap.conn_events, snap.alerts_fired,
    );

    Ok(())
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn platform_default_path() -> PathBuf {
    #[cfg(target_os = "windows")]
    { PathBuf::from(r"C:\Windows\System32") }
    #[cfg(target_os = "linux")]
    { PathBuf::from("/etc") }
    #[cfg(not(any(target_os = "windows", target_os = "linux")))]
    { PathBuf::from("/etc") }
}

fn severity_tag(s: &Severity) -> &'static str {
    match s {
        Severity::Info     => "INFO",
        Severity::Low      => "LOW ",
        Severity::Medium   => "MED ",
        Severity::High     => "HIGH",
        Severity::Critical => "CRIT",
    }
}

fn print_alert(a: &Alert) {
    println!(
        "[{}] {} | {} | {} | {}",
        severity_tag(&a.severity),
        a.occurred_at.format("%H:%M:%S"),
        a.kind,
        a.message,
        a.attack_id.as_deref().unwrap_or("-"),
    );
}

// ── Windows host scans ──────────────────────────────────────────────────────

/// Periodically run memory scans, ntdll hook checks, and BYOVD detection,
/// pushing any resulting alerts into the pipeline via `scan_tx`.
#[cfg(target_os = "windows")]
async fn run_windows_host_scans(
    scan_tx: mpsc::Sender<Alert>,
) {
    use chrono::Utc;
    use arqenor_core::models::alert::Severity as Sev;
    use arqenor_platform::windows::{byovd, memory_scan, ntdll_check};
    use std::collections::HashMap;
    use uuid::Uuid;

    let mut interval = tokio::time::interval(std::time::Duration::from_secs(300));
    interval.tick().await; // skip first immediate tick

    loop {
        interval.tick().await;
        tracing::debug!("running periodic Windows host scans");

        // ── BYOVD ──────────────────────────────────────────────────────
        if let Ok(alerts) = tokio::task::spawn_blocking(byovd::scan_byovd).await {
            for ba in alerts {
                let mut meta = HashMap::new();
                meta.insert("driver_name".into(), ba.driver.name.clone());
                meta.insert("driver_path".into(), ba.driver.path.clone());
                meta.insert("driver_sha256".into(), ba.driver.sha256.clone());
                meta.insert("vuln_name".into(), ba.vuln_name.clone());
                if let Some(ref cve) = ba.cve {
                    meta.insert("cve".into(), cve.clone());
                }
                let alert = Alert {
                    id: Uuid::new_v4(),
                    severity: Sev::Critical,
                    kind: "vulnerable_driver".into(),
                    message: format!(
                        "BYOVD: vulnerable driver loaded — {} ({})",
                        ba.vuln_name,
                        ba.cve.as_deref().unwrap_or("no CVE"),
                    ),
                    occurred_at: Utc::now(),
                    metadata: meta,
                    rule_id: Some("SENT-DRV-001".into()),
                    attack_id: Some("T1068".into()),
                };
                if scan_tx.send(alert).await.is_err() { return; }
            }
        }

        // ── ntdll hooks ────────────────────────────────────────────────
        if let Ok(results) = tokio::task::spawn_blocking(ntdll_check::check_ntdll_hooks).await {
            for hook in results {
                if !hook.is_hooked { continue; }
                let hook_type_str = hook.hook_type.as_ref()
                    .map(|h| format!("{:?}", h))
                    .unwrap_or_else(|| "Unknown".into());
                let mut meta = HashMap::new();
                meta.insert("function".into(), hook.function_name.clone());
                meta.insert("hook_type".into(), hook_type_str.clone());
                let alert = Alert {
                    id: Uuid::new_v4(),
                    severity: Sev::High,
                    kind: "ntdll_hook".into(),
                    message: format!("ntdll hook detected: {} ({})", hook.function_name, hook_type_str),
                    occurred_at: Utc::now(),
                    metadata: meta,
                    rule_id: Some("SENT-MEM-001".into()),
                    attack_id: Some("T1562.001".into()),
                };
                if scan_tx.send(alert).await.is_err() { return; }
            }
        }

        // ── Memory scan (VAD + hollowing) ──────────────────────────────
        if let Ok(results) = tokio::task::spawn_blocking(memory_scan::scan_all_processes).await {
            for result in results {
                for anomaly in &result.suspicious {
                    let (msg, attack_id) = match anomaly {
                        memory_scan::MemoryAnomaly::AnonymousExecutable { base, size, .. } => (
                            format!("Anonymous executable memory in PID {} ({}) at {:#x} ({} bytes)",
                                result.pid, result.image_path, base, size),
                            "T1055",
                        ),
                        memory_scan::MemoryAnomaly::ProcessHollowing { base, disk_path, mismatch } => (
                            format!("Process hollowing in PID {} ({}) at {:#x}: {} ({})",
                                result.pid, result.image_path, base, mismatch, disk_path),
                            "T1055.012",
                        ),
                        memory_scan::MemoryAnomaly::ExecutableHeap { base, size } => (
                            format!("Executable heap in PID {} ({}) at {:#x} ({} bytes)",
                                result.pid, result.image_path, base, size),
                            "T1055",
                        ),
                    };
                    let mut meta = HashMap::new();
                    meta.insert("pid".into(), result.pid.to_string());
                    meta.insert("image_path".into(), result.image_path.clone());
                    let alert = Alert {
                        id: Uuid::new_v4(),
                        severity: Sev::High,
                        kind: "memory_anomaly".into(),
                        message: msg,
                        occurred_at: Utc::now(),
                        metadata: meta,
                        rule_id: Some("SENT-MEM-002".into()),
                        attack_id: Some(attack_id.into()),
                    };
                    if scan_tx.send(alert).await.is_err() { return; }
                }
            }
        }

    }
}
