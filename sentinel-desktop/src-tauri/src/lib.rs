mod network;

use network::PreviousScan;
use sentinel_core::models::{alert::Alert, persistence::PersistenceEntry, process::{ProcessInfo, ProcessScore, ScoreFactor}};
use sentinel_platform::{new_persistence_detector, new_process_monitor};
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, sync::Mutex};
use tauri::{Emitter, Manager, State};

// ── App state ─────────────────────────────────────────────────────────────────

#[derive(Default)]
pub struct AppState {
    /// IP → open ports from the last completed scan (used for diff/new-host detection)
    pub previous_scan: Mutex<PreviousScan>,
}

// ── Process scoring ───────────────────────────────────────────────────────────

fn looks_random(name: &str) -> bool {
    let stem: String = name.chars().take_while(|&c| c != '.').collect();
    if stem.len() < 8 { return false; }
    let vowels = stem.chars().filter(|c| "aeiouAEIOU".contains(*c)).count();
    let ratio = vowels as f32 / stem.len() as f32;
    ratio < 0.1
}

// "No path" alone is not a reliable signal. Windows PPL processes
// (Defender, LsaIso, most hardware driver services) intentionally
// refuse QueryFullProcessImageNameW even from an admin process.
// Real malware runs from disk and will have a path; it can't hide
// behind PPL without a Microsoft-signed certificate.
// Score only what we can actually observe.
fn score_process(p: &ProcessInfo, all_procs: &[ProcessInfo]) -> ProcessScore {
    let mut factors: Vec<ScoreFactor> = Vec::new();

    if let Some(path) = &p.exe_path {
        let low = path.to_lowercase();

        // G1 — Temp directory
        if low.contains("\\temp\\") || low.contains("\\appdata\\local\\temp") {
            factors.push(ScoreFactor {
                name:      "Executes from temp directory".to_string(),
                points:    5,
                attack_id: Some("T1036.005".to_string()),
            });
        }

        // G2 — System process masquerading from unexpected path
        let sys = [
            "svchost.exe", "lsass.exe", "csrss.exe", "winlogon.exe",
            "wininit.exe", "services.exe", "spoolsv.exe", "explorer.exe",
        ];
        if sys.iter().any(|&s| p.name.to_lowercase() == s)
            && !low.contains("\\windows\\system32\\")
            && !low.contains("\\windows\\syswow64\\")
        {
            factors.push(ScoreFactor {
                name:      "System process masquerading from unexpected path".to_string(),
                points:    8,
                attack_id: Some("T1036.005".to_string()),
            });
        }

        // G3 — Executable from unsigned-path location
        if !low.contains("c:\\windows\\") && !low.contains("c:\\program files") {
            factors.push(ScoreFactor {
                name:      "Executable from unsigned-path location".to_string(),
                points:    3,
                attack_id: Some("T1553.002".to_string()),
            });
        }

        // G6 — Executable from network share (UNC path)
        if path.starts_with("\\\\") {
            factors.push(ScoreFactor {
                name:      "Executes from network share (PsExec-style)".to_string(),
                points:    4,
                attack_id: Some("T1021.002".to_string()),
            });
        }
    }

    // G4 — High-entropy filename
    if looks_random(&p.name) {
        factors.push(ScoreFactor {
            name:      "High-entropy process name (possible random malware dropper)".to_string(),
            points:    2,
            attack_id: None,
        });
    }

    // G5 — Spawned by browser or Office application
    let browser_office = [
        "chrome.exe", "firefox.exe", "msedge.exe", "brave.exe", "opera.exe",
        "safari.exe", "WINWORD.EXE", "EXCEL.EXE", "POWERPNT.EXE",
        "outlook.exe", "iexplore.exe",
    ];
    if let Some(parent) = all_procs.iter().find(|pp| pp.pid == p.ppid) {
        if browser_office.iter().any(|&b| parent.name.eq_ignore_ascii_case(b)) {
            factors.push(ScoreFactor {
                name:      "Spawned by browser or Office application".to_string(),
                points:    3,
                attack_id: Some("T1566.001".to_string()),
            });
        }
    }

    let total: u8 = factors.iter().map(|f| f.points).fold(0u8, |acc, p| acc.saturating_add(p));
    ProcessScore { total, factors }
}

fn risk_from_score(score: u8) -> &'static str {
    match score {
        0     => "Normal",
        1     => "Low",
        2..=3 => "Medium",
        4..=7 => "High",
        _     => "Critical",
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessRow {
    pub info:    ProcessInfo,
    pub risk:    String,
    pub score:   u8,
    pub factors: Vec<ScoreFactor>,
}

// ── Commands ──────────────────────────────────────────────────────────────────

#[tauri::command]
async fn get_processes() -> Result<Vec<ProcessRow>, String> {
    let monitor = new_process_monitor();
    let raw = monitor.snapshot().await.map_err(|e| e.to_string())?;
    let mut rows: Vec<ProcessRow> = raw.iter().map(|p| {
        let ps = score_process(p, &raw);
        ProcessRow { info: p.clone(), risk: risk_from_score(ps.total).to_string(), score: ps.total, factors: ps.factors }
    }).collect();
    rows.sort_by(|a, b| b.score.cmp(&a.score).then(a.info.name.cmp(&b.info.name)));
    Ok(rows)
}

#[tauri::command]
async fn get_persistence() -> Result<Vec<PersistenceEntry>, String> {
    let detector = new_persistence_detector();
    detector.detect().await.map_err(|e| e.to_string())
}

#[tauri::command]
async fn get_vpn_status() -> Result<Option<network::VpnInfo>, String> {
    let monitor = new_process_monitor();
    let procs = monitor.snapshot().await.map_err(|e| e.to_string())?;
    let names: Vec<String> = procs.into_iter().map(|p| p.name).collect();
    Ok(network::detect_vpn(&names))
}

/// Starts a subnet scan with anomaly detection.
/// Emits:
///   "network-host"       — each host found (HostInfo JSON)
///   "network-scan-done"  — scan complete, no payload
/// Returns the subnet label, e.g. "192.168.1.x/24".
#[tauri::command]
async fn start_network_scan(
    app:   tauri::AppHandle,
    state: State<'_, AppState>,
) -> Result<String, String> {
    let subnets = network::get_lan_subnets();
    let base = subnets.into_iter().next()
        .ok_or_else(|| "No LAN subnet detected".to_string())?;

    let label = format!("{}.{}.{}.x/24", base[0], base[1], base[2]);

    // Snapshot previous scan for diff
    let previous: PreviousScan = state.previous_scan
        .lock()
        .map(|g| g.clone())
        .unwrap_or_default();

    tokio::spawn(async move {
        let mut rx = network::scan_subnet(base, previous);
        let mut new_scan: HashMap<String, Vec<u16>> = HashMap::new();

        while let Some(host) = rx.recv().await {
            new_scan.insert(host.ip.clone(), host.ports.clone());
            let _ = app.emit("network-host", &host);
        }

        let _ = app.emit("network-scan-done", ());

        // Store completed scan in state
        app.state::<AppState>()
            .previous_scan
            .lock()
            .map(|mut g| { *g = new_scan; })
            .ok();
    });

    Ok(label)
}

#[tauri::command]
async fn get_alerts() -> Result<Vec<Alert>, String> {
    // TODO: integrate with CredGuard, FIM, LOLBin engine
    // For now return empty — real alerts come from background scan
    Ok(Vec::new())
}

// ── App entry point ───────────────────────────────────────────────────────────

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .manage(AppState::default())
        .plugin(tauri_plugin_shell::init())
        .invoke_handler(tauri::generate_handler![
            get_processes,
            get_persistence,
            get_vpn_status,
            start_network_scan,
            get_alerts,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
