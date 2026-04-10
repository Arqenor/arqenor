use anyhow::Result;
use clap::Args;
use sentinel_core::{
    ioc::{feeds, IocDatabase},
    models::alert::{Alert, Severity},
    models::connection::ConnectionInfo,
    pipeline::{DetectionPipeline, PipelineConfig},
    rules::sigma,
    traits::connection_monitor::spawn_polling_watch,
};
use sentinel_platform::{new_connection_monitor, new_fs_scanner, new_process_monitor};
use sentinel_store::SqliteStore;
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
    #[arg(long, default_value = "sentinel.db")]
    pub db: PathBuf,

    /// Directory containing SIGMA YAML rules.
    #[arg(long)]
    pub sigma_dir: Option<PathBuf>,

    /// Disable IOC threat-intelligence feed loading.
    #[arg(long)]
    pub no_ioc: bool,

    /// Directory containing custom YARA rule files (.yar/.yara).
    /// Built-in rules are always loaded; custom rules supplement them.
    #[cfg(feature = "yara")]
    #[arg(long)]
    pub yara_dir: Option<PathBuf>,
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

    // ── Start connection monitor (non-fatal if unsupported) ─────────────────
    {
        let conn_monitor = new_connection_monitor();
        match conn_monitor.watch(conn_tx.clone(), CONN_POLL_INTERVAL_MS).await {
            Ok(()) => {
                tracing::info!("connection monitor: platform watch active");
            }
            Err(sentinel_core::error::SentinelError::NotSupported) => {
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

    // ── Periodic host scans (Windows: memory, ntdll hooks, BYOVD, YARA) ──
    #[cfg(target_os = "windows")]
    {
        #[cfg(feature = "yara")]
        let yara_dir = args.yara_dir.clone();
        #[cfg(feature = "yara")]
        tokio::spawn(run_windows_host_scans(scan_tx, yara_dir));
        #[cfg(not(feature = "yara"))]
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
        "SENTINEL watch — {n_rules} LOLBin, {n_sigma} SIGMA, {n_file} file rules, {n_ioc} IOCs | FIM: {} | conn: polling {}ms | db: {}",
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

/// Periodically run memory scans, ntdll hook checks, BYOVD detection, and
/// YARA memory scanning, pushing any resulting alerts into the pipeline via
/// `scan_tx`.
#[cfg(target_os = "windows")]
async fn run_windows_host_scans(
    scan_tx: mpsc::Sender<Alert>,
    #[cfg(feature = "yara")] yara_dir: Option<PathBuf>,
) {
    use chrono::Utc;
    use sentinel_core::models::alert::Severity as Sev;
    use sentinel_platform::windows::{byovd, memory_scan, ntdll_check};
    use std::collections::HashMap;
    use uuid::Uuid;

    // ── Compile YARA rules once at startup ──────────────────────────────
    #[cfg(feature = "yara")]
    let yara_scanner = {
        use sentinel_platform::windows::{yara_rules, yara_scan};
        // Start with built-in rules.
        let mut scanner = match yara_scan::YaraScanner::from_source(yara_rules::EMBEDDED_RULES) {
            Ok(s) => {
                tracing::info!("YARA: built-in rules compiled successfully");
                Some(s)
            }
            Err(e) => {
                warn!("YARA: failed to compile built-in rules: {e}");
                None
            }
        };
        // If a custom rules directory was provided, try to load from there instead
        // (custom dir includes all rules, overriding built-in).
        if let Some(ref dir) = yara_dir {
            match yara_scan::YaraScanner::from_rules_dir(dir) {
                Ok(s) => {
                    tracing::info!(dir = %dir.display(), "YARA: loaded custom rules");
                    scanner = Some(s);
                }
                Err(e) => {
                    warn!(dir = %dir.display(), error = %e, "YARA: failed to load custom rules, using built-in only");
                }
            }
        }
        scanner.map(std::sync::Arc::new)
    };

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

        // ── YARA memory scan ──────────────────────────────────────────
        #[cfg(feature = "yara")]
        if let Some(ref scanner) = yara_scanner {
            // YaraScanner::scan_all does CPU-heavy work; run it on the
            // blocking pool.  Arc clone is cheap -- only the refcount bumps.
            let sc = std::sync::Arc::clone(scanner);
            let results = tokio::task::spawn_blocking(move || sc.scan_all()).await;
            if let Ok(results) = results {
                for result in results {
                    for m in &result.matches {
                        let mut meta = HashMap::new();
                        meta.insert("pid".into(), m.pid.to_string());
                        meta.insert("image_path".into(), result.image_path.clone());
                        meta.insert("rule_name".into(), m.rule_name.clone());
                        meta.insert("region_base".into(), format!("0x{:x}", m.region_base));
                        meta.insert("region_size".into(), m.region_size.to_string());
                        if !m.rule_tags.is_empty() {
                            meta.insert("rule_tags".into(), m.rule_tags.join(", "));
                        }

                        let severity = match m.severity.as_deref() {
                            Some(s) if s.contains("critical") => Sev::Critical,
                            Some(s) if s.contains("high") => Sev::High,
                            Some(s) if s.contains("medium") => Sev::Medium,
                            Some(s) if s.contains("low") => Sev::Low,
                            _ => Sev::Critical,
                        };

                        let alert = Alert {
                            id: Uuid::new_v4(),
                            severity,
                            kind: "yara_match".into(),
                            message: format!(
                                "YARA: {} in PID {} ({}) at 0x{:x}",
                                m.rule_name, m.pid, result.image_path, m.region_base,
                            ),
                            occurred_at: Utc::now(),
                            metadata: meta,
                            rule_id: Some(m.rule_name.clone()),
                            attack_id: m.attack_id.clone(),
                        };
                        if scan_tx.send(alert).await.is_err() { return; }
                    }
                }
            }
        }
    }
}
