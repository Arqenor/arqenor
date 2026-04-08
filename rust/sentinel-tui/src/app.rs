use crate::network::{self, HostInfo, HostRisk, VpnInfo};
use anyhow::Result;
use sentinel_core::models::{persistence::PersistenceEntry, process::ProcessInfo};
use sentinel_platform::{new_persistence_detector, new_process_monitor};
use std::time::{Duration, Instant};
use tokio::sync::mpsc::Receiver;

const NET_RESCAN_INTERVAL: Duration = Duration::from_secs(300); // 5 min

// ─── Tabs ──────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tab {
    Processes,
    Persistence,
    Network,
}

impl Tab {
    pub fn next(self) -> Self {
        match self {
            Self::Processes   => Self::Persistence,
            Self::Persistence => Self::Network,
            Self::Network     => Self::Processes,
        }
    }
    pub fn prev(self) -> Self {
        match self {
            Self::Processes   => Self::Network,
            Self::Persistence => Self::Processes,
            Self::Network     => Self::Persistence,
        }
    }
}

// ─── Risk levels ───────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RiskLevel {
    Normal,
    Low,
    Medium,
    High,
    Critical,
}

impl RiskLevel {
    pub fn label(&self) -> &'static str {
        match self {
            Self::Normal   => "  --  ",
            Self::Low      => " LOW  ",
            Self::Medium   => " MED  ",
            Self::High     => " HIGH ",
            Self::Critical => " CRIT ",
        }
    }
}

// ─── Process row ───────────────────────────────────────────────────────────────

#[derive(Clone)]
pub struct ProcessRow {
    pub info:  ProcessInfo,
    pub risk:  RiskLevel,
    pub score: u8,
}

// ─── Network state ─────────────────────────────────────────────────────────────

pub enum ScanState {
    Idle,
    Scanning { rx: Receiver<HostInfo>, started: Instant },
    Done,
}

pub struct NetworkState {
    pub hosts:         Vec<HostInfo>,
    #[allow(dead_code)]
    pub subnets:       Vec<[u8; 3]>,  // all detected LAN subnets (future: multi-subnet scan)
    pub active_subnet: Option<[u8; 3]>,
    pub scan_state:   ScanState,
    pub last_scan:    Option<Instant>,
}

impl NetworkState {
    fn new() -> Self {
        let subnets = network::get_lan_subnets();
        let active  = subnets.first().copied();
        Self {
            hosts:          vec![],
            subnets,
            active_subnet:  active,
            scan_state:     ScanState::Idle,
            last_scan:      None,
        }
    }

    pub fn start_scan(&mut self) {
        if let Some(base) = self.active_subnet {
            self.hosts.clear();
            let rx = network::scan_subnet(base);
            self.scan_state = ScanState::Scanning { rx, started: Instant::now() };
            self.last_scan  = Some(Instant::now());
        }
    }

    /// Should we kick off a new scan? (auto-rescan every 5 min)
    pub fn should_rescan(&self) -> bool {
        match &self.scan_state {
            ScanState::Idle | ScanState::Done => {
                match self.last_scan {
                    None       => true, // never scanned → scan immediately
                    Some(t)    => t.elapsed() >= NET_RESCAN_INTERVAL,
                }
            }
            ScanState::Scanning { .. } => false,
        }
    }

    /// Poll the channel — call every frame while scanning.
    pub fn poll(&mut self) {
        let done = match &mut self.scan_state {
            ScanState::Scanning { rx, .. } => {
                loop {
                    match rx.try_recv() {
                        Ok(host) => { self.hosts.push(host); }
                        Err(tokio::sync::mpsc::error::TryRecvError::Empty)        => break false,
                        Err(tokio::sync::mpsc::error::TryRecvError::Disconnected) => break true,
                    }
                }
            }
            _ => false,
        };
        if done {
            self.hosts.sort_by(|a, b| {
                risk_ord(&b.risk).cmp(&risk_ord(&a.risk)).then(a.ip.cmp(&b.ip))
            });
            self.scan_state = ScanState::Done;
        }
    }

    pub fn subnet_label(&self) -> String {
        match self.active_subnet {
            Some(b) => format!("{}.{}.{}.x/24", b[0], b[1], b[2]),
            None    => "no LAN detected".into(),
        }
    }

    pub fn status_line(&self) -> String {
        match &self.scan_state {
            ScanState::Idle => "—".into(),
            ScanState::Scanning { started, .. } => {
                format!("scanning {}  {}s  {} up",
                    self.subnet_label(), started.elapsed().as_secs(), self.hosts.len())
            }
            ScanState::Done => {
                let age = self.last_scan
                    .map(|t| format!("{}s ago", t.elapsed().as_secs()))
                    .unwrap_or_default();
                format!("{} hosts  last scan {}", self.hosts.len(), age)
            }
        }
    }
}

fn risk_ord(r: &HostRisk) -> u8 {
    match r {
        HostRisk::High   => 3,
        HostRisk::Medium => 2,
        HostRisk::Low    => 1,
        HostRisk::Normal => 0,
    }
}

// ─── Process scoring ───────────────────────────────────────────────────────────

const KNOWN_KERNEL: &[&str] = &[
    "System", "Idle", "Memory Compression", "Secure System",
    "Registry", "smss.exe", "vmmemWSL",
];

fn score_process(p: &ProcessInfo) -> u8 {
    let mut score: u8 = 0;
    match &p.exe_path {
        None => {
            let name = p.name.to_lowercase();
            if !KNOWN_KERNEL.iter().any(|k| k.to_lowercase() == name) {
                score += 2;
            }
        }
        Some(path) => {
            let low = path.to_lowercase();
            if low.contains("\\temp\\") || low.contains("\\appdata\\local\\temp") {
                score += 5;
            } else if low.contains("\\appdata\\roaming\\") {
                score += 1;
            }
            let sys = ["svchost.exe", "lsass.exe", "csrss.exe", "winlogon.exe", "wininit.exe"];
            for s in sys {
                if p.name.to_lowercase() == s
                    && !low.contains("\\windows\\system32\\")
                    && !low.contains("\\windows\\syswow64\\")
                {
                    score += 8;
                }
            }
        }
    }
    if p.ppid == 0 && p.pid > 4 { score += 1; }
    score
}

fn risk_from_score(score: u8) -> RiskLevel {
    match score {
        0     => RiskLevel::Normal,
        1     => RiskLevel::Low,
        2..=3 => RiskLevel::Medium,
        4..=7 => RiskLevel::High,
        _     => RiskLevel::Critical,
    }
}

// ─── App ───────────────────────────────────────────────────────────────────────

pub struct App {
    pub tab:          Tab,
    pub processes:    Vec<ProcessRow>,
    pub persistence:  Vec<PersistenceEntry>,
    pub net:          NetworkState,
    pub vpn:          Option<VpnInfo>,
    pub selected:     usize,
    pub filter:       String,
    pub filter_mode:  bool,
    pub last_refresh: Instant,
}

impl App {
    pub async fn new() -> Result<Self> {
        let mut app = Self {
            tab:          Tab::Processes,
            processes:    vec![],
            persistence:  vec![],
            net:          NetworkState::new(),
            vpn:          None,
            selected:     0,
            filter:       String::new(),
            filter_mode:  false,
            last_refresh: Instant::now(),
        };
        app.refresh().await?;
        Ok(app)
    }

    pub async fn refresh(&mut self) -> Result<()> {
        let monitor = new_process_monitor();
        let raw     = monitor.snapshot().await.unwrap_or_default();
        let mut rows: Vec<ProcessRow> = raw.into_iter().map(|p| {
            let score = score_process(&p);
            ProcessRow { info: p, risk: risk_from_score(score), score }
        }).collect();
        rows.sort_by(|a, b| b.score.cmp(&a.score).then(a.info.name.cmp(&b.info.name)));
        self.processes = rows;

        let detector  = new_persistence_detector();
        self.persistence = detector.detect().await.unwrap_or_default();
        self.last_refresh = Instant::now();

        // Detect VPN from process names
        let proc_names: Vec<String> = self.processes.iter()
            .map(|r| r.info.name.clone())
            .collect();
        self.vpn = network::detect_vpn(&proc_names);

        Ok(())
    }

    pub fn tick(&mut self) {
        // Always poll the network channel (results come in even when on another tab)
        self.net.poll();
        // Auto-start / auto-rescan
        if self.net.should_rescan() {
            self.net.start_scan();
        }
    }

    pub fn filtered_processes(&self) -> Vec<&ProcessRow> {
        if self.filter.is_empty() {
            return self.processes.iter().collect();
        }
        let q = self.filter.to_lowercase();
        self.processes.iter().filter(|r| {
            r.info.name.to_lowercase().contains(&q)
                || r.info.exe_path.as_deref().unwrap_or("").to_lowercase().contains(&q)
                || r.info.pid.to_string().contains(&q)
        }).collect()
    }

    pub fn counts(&self) -> (usize, usize, usize, usize) {
        let crit = self.processes.iter().filter(|r| r.risk == RiskLevel::Critical).count();
        let high = self.processes.iter().filter(|r| r.risk == RiskLevel::High).count();
        let med  = self.processes.iter().filter(|r| r.risk == RiskLevel::Medium).count();
        let low  = self.processes.iter().filter(|r| r.risk == RiskLevel::Low).count();
        (crit, high, med, low)
    }

    pub fn current_list_len(&self) -> usize {
        match self.tab {
            Tab::Processes   => self.filtered_processes().len(),
            Tab::Persistence => self.persistence.len(),
            Tab::Network     => self.net.hosts.len(),
        }
    }

    pub fn next(&mut self) {
        let len = self.current_list_len();
        if len > 0 { self.selected = (self.selected + 1).min(len - 1); }
    }
    pub fn prev(&mut self) {
        self.selected = self.selected.saturating_sub(1);
    }
    pub fn switch_tab(&mut self, tab: Tab) {
        self.tab      = tab;
        self.selected = 0;
    }
}
