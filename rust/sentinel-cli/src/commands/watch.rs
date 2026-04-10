use anyhow::Result;
use clap::Args;
use sentinel_core::{
    models::alert::{Alert, Severity},
    pipeline::{DetectionPipeline, PipelineConfig},
};
use sentinel_platform::{new_fs_scanner, new_process_monitor};
use sentinel_store::SqliteStore;
use std::path::PathBuf;
use tokio::sync::mpsc;
use tracing::warn;

#[derive(Args)]
pub struct WatchArgs {
    /// Directory to monitor for file-integrity changes.
    /// Defaults to C:\Windows\System32 on Windows, /etc on Linux.
    #[arg(long)]
    pub watch_path: Option<PathBuf>,

    /// SQLite database for alert persistence.
    #[arg(long, default_value = "sentinel.db")]
    pub db: PathBuf,
}

pub async fn run(args: WatchArgs) -> Result<()> {
    let config   = PipelineConfig::default();
    let n_rules  = config.rules.len();
    let n_file   = config.sensitive_paths.len();
    let watch_path = args.watch_path.unwrap_or_else(platform_default_path);

    // ── Channels ─────────────────────────────────────────────────────────────
    let (proc_tx, proc_rx)       = mpsc::channel(512);
    let (fim_tx, fim_rx)         = mpsc::channel(512);
    let (alert_tx, mut alert_rx) = mpsc::channel::<Alert>(256);

    // ── Start platform watchers (non-fatal if unsupported) ───────────────────
    //
    // On Windows with the kernel-driver feature, the driver bridge provides
    // kernel-level process + file telemetry that supersedes the usermode
    // watchers (EvtSubscribe / ReadDirectoryChangesW). If the driver is loaded,
    // we use it; otherwise fall back to the standard watchers.
    #[cfg(all(target_os = "windows", feature = "kernel-driver"))]
    let driver_active = {
        use sentinel_platform::windows::driver_bridge::{DriverBridgeConfig, DriverBridgeSenders};
        let senders = DriverBridgeSenders {
            process_tx: proc_tx.clone(),
            file_tx:    fim_tx.clone(),
            alert_tx:   alert_tx.clone(),
        };
        match sentinel_platform::start_driver_bridge(DriverBridgeConfig::default(), senders).await {
            Ok(()) => {
                println!("  kernel driver: connected (\\SentinelPort)");
                true
            }
            Err(e) => {
                warn!("kernel driver unavailable: {e} — falling back to usermode");
                false
            }
        }
    };
    #[cfg(not(all(target_os = "windows", feature = "kernel-driver")))]
    let driver_active = false;

    if !driver_active {
        if let Err(e) = new_process_monitor().watch(proc_tx).await {
            warn!("process watcher unavailable: {e}");
        }
        if let Err(e) = new_fs_scanner().watch_path(&watch_path, fim_tx).await {
            warn!("FIM watcher unavailable: {e}");
        }
    }

    // ── Start detection pipeline ──────────────────────────────────────────────
    let pipeline = DetectionPipeline::new(config, proc_rx, fim_rx, alert_tx);
    let stats    = pipeline.stats();
    tokio::spawn(pipeline.run());

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
                "[stats] proc:{} file:{} alerts:{}",
                s.process_events, s.file_events, s.alerts_fired,
            );
        }
    });

    // ── Alert consumer ────────────────────────────────────────────────────────
    println!(
        "SENTINEL watch — {n_rules} process rules, {n_file} file rules | FIM: {} | db: {}",
        watch_path.display(),
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
        "Session: {} process events, {} file events, {} alerts",
        snap.process_events, snap.file_events, snap.alerts_fired,
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
