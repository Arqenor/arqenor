use crate::network::{self, HostInfo, HostRisk, VpnInfo};
use anyhow::Result;
use ratatui::widgets::TableState;
use sentinel_core::models::{connection::ConnectionInfo, persistence::PersistenceEntry, process::{ProcessInfo, ProcessScore, ScoreFactor}};
use sentinel_platform::{new_connection_monitor, new_persistence_detector, new_process_monitor};
use std::collections::HashSet;
use std::time::{Duration, Instant};
use tokio::sync::mpsc::Receiver;

const NET_RESCAN_INTERVAL: Duration = Duration::from_secs(300); // 5 min

// ─── Sort ──────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SortCol { Risk, Pid, Name, Path }

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SortDir { Desc, Asc }

// ─── Tabs ──────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tab {
    Processes,
    Persistence,
    Network,
    Connections,
}

impl Tab {
    pub fn next(self) -> Self {
        match self {
            Self::Processes   => Self::Persistence,
            Self::Persistence => Self::Network,
            Self::Network     => Self::Connections,
            Self::Connections => Self::Processes,
        }
    }
    pub fn prev(self) -> Self {
        match self {
            Self::Processes   => Self::Connections,
            Self::Persistence => Self::Processes,
            Self::Network     => Self::Persistence,
            Self::Connections => Self::Network,
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
    pub info:    ProcessInfo,
    pub risk:    RiskLevel,
    pub score:   u8,
    #[allow(dead_code)]
    pub factors: Vec<ScoreFactor>,
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

fn looks_random(name: &str) -> bool {
    let stem: String = name.chars().take_while(|&c| c != '.').collect();
    if stem.len() < 8 { return false; }
    let vowels = stem.chars().filter(|c| "aeiouAEIOU".contains(*c)).count();
    let ratio = vowels as f32 / stem.len() as f32;
    ratio < 0.1
}

fn score_process(p: &ProcessInfo, all_procs: &[ProcessInfo]) -> ProcessScore {
    let mut factors: Vec<ScoreFactor> = Vec::new();

    match &p.exe_path {
        None => {
            // No exe_path — not scored here (PPL / kernel processes)
        }
        Some(path) => {
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

fn risk_from_score(score: u8) -> RiskLevel {
    match score {
        0     => RiskLevel::Normal,
        1     => RiskLevel::Low,
        2..=3 => RiskLevel::Medium,
        4..=7 => RiskLevel::High,
        _     => RiskLevel::Critical,
    }
}

// ─── Filter helpers ────────────────────────────────────────────────────────────

fn matches_filter(r: &ProcessRow, filter: &str) -> bool {
    if filter.is_empty() { return true; }
    for term in filter.split_whitespace() {
        if term.starts_with("risk:") {
            let level = &term[5..];
            let matches = match level {
                "crit" | "critical" => r.risk == RiskLevel::Critical,
                "high"              => r.risk == RiskLevel::High,
                "med" | "medium"    => r.risk == RiskLevel::Medium,
                "low"               => r.risk == RiskLevel::Low,
                _                   => false,
            };
            if !matches { return false; }
        } else if term.starts_with("pid:") {
            let expr = &term[4..];
            if let Some(val) = expr.strip_prefix('>') {
                if let Ok(n) = val.parse::<u32>() {
                    if r.info.pid <= n { return false; }
                }
            } else if let Ok(n) = expr.parse::<u32>() {
                if r.info.pid != n { return false; }
            }
        } else {
            let q = term.to_lowercase();
            if !r.info.name.to_lowercase().contains(&q)
                && !r.info.exe_path.as_deref().unwrap_or("").to_lowercase().contains(&q)
                && !r.info.pid.to_string().contains(&q)
            {
                return false;
            }
        }
    }
    true
}

// ─── App ───────────────────────────────────────────────────────────────────────

/// A process row annotated with its depth in the parent-child tree.
pub struct TreeRow<'a> {
    pub row:     &'a ProcessRow,
    pub depth:   usize,
    pub is_last: bool,   // true if last child of its parent (for └ vs ├)
}

pub struct App {
    pub tab:           Tab,
    pub processes:     Vec<ProcessRow>,
    pub persistence:   Vec<PersistenceEntry>,
    pub connections:   Vec<ConnectionInfo>,
    pub net:           NetworkState,
    pub vpn:           Option<VpnInfo>,
    pub selected:      usize,
    pub proc_state:    TableState,
    pub conn_state:    TableState,
    pub filter:        String,
    pub filter_mode:   bool,
    pub detail_open:   bool,
    pub last_refresh:  Instant,
    pub sort_col:      SortCol,
    pub sort_dir:      SortDir,
    pub new_pids:      HashSet<u32>,   // PIDs that appeared since last refresh
    pub baseline:      HashSet<u32>,   // PIDs/names marked as known-good
    pub action_menu:   bool,
    pub action_result: Option<String>, // feedback message shown after action
    pub tree_mode:     bool,
    pub hide_loopback: bool,
}

impl App {
    pub async fn new() -> Result<Self> {
        let mut proc_state = TableState::default();
        proc_state.select(Some(0));
        let mut app = Self {
            tab:           Tab::Processes,
            processes:     vec![],
            persistence:   vec![],
            connections:   vec![],
            net:           NetworkState::new(),
            vpn:           None,
            selected:      0,
            proc_state,
            conn_state:    TableState::default(),
            filter:        String::new(),
            filter_mode:   false,
            detail_open:   false,
            last_refresh:  Instant::now(),
            sort_col:      SortCol::Risk,
            sort_dir:      SortDir::Desc,
            new_pids:      HashSet::new(),
            baseline:      HashSet::new(),
            action_menu:   false,
            action_result: None,
            tree_mode:     false,
            hide_loopback: false,
        };
        app.refresh().await?;
        Ok(app)
    }

    pub async fn refresh(&mut self) -> Result<()> {
        let prev_pids: HashSet<u32> = self.processes.iter().map(|r| r.info.pid).collect();

        let monitor = new_process_monitor();
        let raw     = monitor.snapshot().await.unwrap_or_default();
        let mut rows: Vec<ProcessRow> = raw.iter().map(|p| {
            let ps = score_process(p, &raw);
            ProcessRow { info: p.clone(), risk: risk_from_score(ps.total), score: ps.total, factors: ps.factors }
        }).collect();
        rows.sort_by(|a, b| b.score.cmp(&a.score).then(a.info.name.cmp(&b.info.name)));
        self.processes = rows;

        self.new_pids = if prev_pids.is_empty() {
            HashSet::new()
        } else {
            self.processes.iter()
                .map(|r| r.info.pid)
                .filter(|pid| !prev_pids.contains(pid))
                .collect()
        };

        let detector  = new_persistence_detector();
        self.persistence = detector.detect().await.unwrap_or_default();

        let conn_monitor = new_connection_monitor();
        self.connections = conn_monitor.snapshot().await.unwrap_or_default();

        // Drop IPv6 LISTEN entries that have an IPv4 counterpart (same pid+port)
        // e.g. keep 0.0.0.0:445 and drop [::]:445 for the same PID
        let ipv4_listen_keys: HashSet<(u32, u16)> = self.connections.iter()
            .filter(|c| c.state == sentinel_core::models::connection::ConnState::Listen
                     && !c.local_addr.starts_with('['))
            .filter_map(|c| {
                c.local_addr.rsplit(':').next()
                    .and_then(|p| p.parse::<u16>().ok())
                    .map(|port| (c.pid, port))
            })
            .collect();
        self.connections.retain(|c| {
            if c.state != sentinel_core::models::connection::ConnState::Listen
                || !c.local_addr.starts_with('[') {
                return true;
            }
            let port = c.local_addr.rsplit(':').next()
                .and_then(|p| p.trim_end_matches(']').parse::<u16>().ok())
                .unwrap_or(0);
            !ipv4_listen_keys.contains(&(c.pid, port))
        });

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

    pub fn filtered_connections(&self) -> Vec<&ConnectionInfo> {
        self.connections.iter().filter(|c| {
            if self.hide_loopback {
                let local_loop  = c.local_addr.starts_with("127.") || c.local_addr.starts_with("[::1]");
                let remote_loop = c.remote_addr.as_deref()
                    .map(|r| r.starts_with("127.") || r.starts_with("[::1]"))
                    .unwrap_or(false);
                if local_loop || remote_loop { return false; }
            }
            if !self.filter.is_empty() {
                let q = self.filter.to_lowercase();
                let name_ok = self.processes.iter()
                    .find(|p| p.info.pid == c.pid)
                    .map(|p| p.info.name.to_lowercase().contains(&q))
                    .unwrap_or(false);
                let addr_ok = c.local_addr.to_lowercase().contains(&q)
                    || c.remote_addr.as_deref().unwrap_or("").to_lowercase().contains(&q)
                    || c.state.to_string().to_lowercase().contains(&q);
                if !name_ok && !addr_ok { return false; }
            }
            true
        }).collect()
    }

    pub fn filtered_processes(&self) -> Vec<&ProcessRow> {
        let filter = self.filter.trim();
        let mut result: Vec<&ProcessRow> = self.processes.iter()
            .filter(|r| matches_filter(r, filter))
            .collect();

        // Re-sort whenever the sort column differs from the default (Risk Desc),
        // or when a filter is active (which can change the set requiring a stable sort).
        let need_sort = self.sort_col != SortCol::Risk
            || self.sort_dir != SortDir::Desc
            || !filter.is_empty();

        if need_sort {
            match (self.sort_col, self.sort_dir) {
                (SortCol::Risk, SortDir::Desc) => result.sort_by(|a, b| b.score.cmp(&a.score).then(a.info.name.cmp(&b.info.name))),
                (SortCol::Risk, SortDir::Asc)  => result.sort_by(|a, b| a.score.cmp(&b.score).then(a.info.name.cmp(&b.info.name))),
                (SortCol::Pid,  SortDir::Desc) => result.sort_by(|a, b| b.info.pid.cmp(&a.info.pid)),
                (SortCol::Pid,  SortDir::Asc)  => result.sort_by(|a, b| a.info.pid.cmp(&b.info.pid)),
                (SortCol::Name, SortDir::Desc) => result.sort_by(|a, b| b.info.name.cmp(&a.info.name)),
                (SortCol::Name, SortDir::Asc)  => result.sort_by(|a, b| a.info.name.cmp(&b.info.name)),
                (SortCol::Path, SortDir::Desc) => result.sort_by(|a, b| b.info.exe_path.cmp(&a.info.exe_path)),
                (SortCol::Path, SortDir::Asc)  => result.sort_by(|a, b| a.info.exe_path.cmp(&b.info.exe_path)),
            }
        }

        result
    }

    pub fn tree_rows(&self) -> Vec<TreeRow<'_>> {
        use std::collections::HashMap;

        let procs = self.filtered_processes();

        // Build pid → index map
        let pid_to_idx: HashMap<u32, usize> = procs.iter()
            .enumerate()
            .map(|(i, r)| (r.info.pid, i))
            .collect();

        // Build children map: parent_pid → [child_indices]
        let mut children: HashMap<u32, Vec<usize>> = HashMap::new();
        let mut roots: Vec<usize> = Vec::new();

        for (i, r) in procs.iter().enumerate() {
            let ppid = r.info.ppid;
            if ppid == 0 || ppid == r.info.pid || !pid_to_idx.contains_key(&ppid) {
                roots.push(i);
            } else {
                children.entry(ppid).or_default().push(i);
            }
        }

        // DFS traversal to build ordered TreeRow list
        fn dfs<'a>(
            idx:      usize,
            depth:    usize,
            is_last:  bool,
            procs:    &[&'a ProcessRow],
            children: &HashMap<u32, Vec<usize>>,
            result:   &mut Vec<TreeRow<'a>>,
        ) {
            let row = procs[idx];
            result.push(TreeRow { row, depth, is_last });
            if let Some(kids) = children.get(&row.info.pid) {
                let n = kids.len();
                for (k, &kid_idx) in kids.iter().enumerate() {
                    dfs(kid_idx, depth + 1, k == n - 1, procs, children, result);
                }
            }
        }

        let mut result: Vec<TreeRow<'_>> = Vec::with_capacity(procs.len());
        let n = roots.len();
        for (i, &root_idx) in roots.iter().enumerate() {
            dfs(root_idx, 0, i == n - 1, &procs, &children, &mut result);
        }

        result
    }

    pub fn toggle_sort(&mut self, col: SortCol) {
        if self.sort_col == col {
            self.sort_dir = match self.sort_dir {
                SortDir::Desc => SortDir::Asc,
                SortDir::Asc  => SortDir::Desc,
            };
        } else {
            self.sort_col = col;
            self.sort_dir = SortDir::Desc;
        }
        self.selected = 0;
        self.proc_state.select(Some(0));
    }

    pub fn selected_process(&self) -> Option<&ProcessRow> {
        self.filtered_processes().into_iter().nth(self.selected)
    }

    pub fn toggle_baseline(&mut self) {
        if let Some(proc) = self.selected_process() {
            let pid = proc.info.pid;
            if self.baseline.contains(&pid) {
                self.baseline.remove(&pid);
            } else {
                self.baseline.insert(pid);
            }
        }
    }

    pub fn counts(&self) -> (usize, usize, usize, usize) {
        let crit = self.processes.iter().filter(|r| r.risk == RiskLevel::Critical).count();
        let high = self.processes.iter().filter(|r| r.risk == RiskLevel::High).count();
        let med  = self.processes.iter().filter(|r| r.risk == RiskLevel::Medium).count();
        let low  = self.processes.iter().filter(|r| r.risk == RiskLevel::Low).count();
        (crit, high, med, low)
    }

    pub fn kill_selected(&mut self) {
        if let Some(proc) = self.selected_process() {
            let pid = proc.info.pid;
            #[cfg(target_os = "windows")]
            {
                use std::process::Command;
                let status = Command::new("taskkill")
                    .args(["/PID", &pid.to_string(), "/F"])
                    .output();
                self.action_result = Some(match status {
                    Ok(o) if o.status.success() => format!("Killed PID {pid}"),
                    Ok(o) => format!("Kill failed: {}", String::from_utf8_lossy(&o.stderr).trim()),
                    Err(e) => format!("Kill error: {e}"),
                });
            }
            #[cfg(not(target_os = "windows"))]
            {
                use std::process::Command;
                let status = Command::new("kill")
                    .args(["-9", &pid.to_string()])
                    .output();
                self.action_result = Some(match status {
                    Ok(o) if o.status.success() => format!("Killed PID {pid}"),
                    Ok(o) => format!("Kill failed: {}", String::from_utf8_lossy(&o.stderr).trim()),
                    Err(e) => format!("Kill error: {e}"),
                });
            }
            self.action_menu = false;
        }
    }

    pub fn hash_selected(&mut self) {
        if let Some(proc) = self.selected_process() {
            if let Some(ref path) = proc.info.exe_path.clone() {
                self.action_result = Some(format!("SHA256: run `sha256sum {path}`"));
            } else {
                self.action_result = Some("No path available".to_string());
            }
            self.action_menu = false;
        }
    }

    pub fn copy_path_selected(&mut self) {
        if let Some(proc) = self.selected_process() {
            if let Some(ref path) = proc.info.exe_path.clone() {
                #[cfg(target_os = "windows")]
                {
                    use std::io::Write;
                    use std::process::{Command, Stdio};
                    let mut child = Command::new("clip")
                        .stdin(Stdio::piped())
                        .spawn()
                        .ok();
                    if let Some(ref mut c) = child {
                        if let Some(ref mut stdin) = c.stdin.take() {
                            let _ = stdin.write_all(path.as_bytes());
                        }
                        self.action_result = Some(format!("Copied: {path}"));
                    } else {
                        self.action_result = Some(format!("Clipboard unavailable: {path}"));
                    }
                }
                #[cfg(target_os = "macos")]
                {
                    use std::io::Write;
                    use std::process::{Command, Stdio};
                    let mut child = Command::new("pbcopy").stdin(Stdio::piped()).spawn().ok();
                    if let Some(ref mut c) = child {
                        if let Some(ref mut stdin) = c.stdin.take() {
                            let _ = stdin.write_all(path.as_bytes());
                        }
                        self.action_result = Some(format!("Copied: {path}"));
                    } else {
                        self.action_result = Some(format!("Clipboard unavailable: {path}"));
                    }
                }
                #[cfg(target_os = "linux")]
                {
                    use std::io::Write;
                    use std::process::{Command, Stdio};
                    let tool = if Command::new("which").arg("xclip").output().map(|o| o.status.success()).unwrap_or(false) {
                        Some(("xclip", vec!["-selection", "clipboard"]))
                    } else if Command::new("which").arg("xsel").output().map(|o| o.status.success()).unwrap_or(false) {
                        Some(("xsel", vec!["--clipboard", "--input"]))
                    } else {
                        None
                    };
                    if let Some((cmd, args)) = tool {
                        let mut child = Command::new(cmd).args(args).stdin(Stdio::piped()).spawn().ok();
                        if let Some(ref mut c) = child {
                            if let Some(ref mut stdin) = c.stdin.take() {
                                let _ = stdin.write_all(path.as_bytes());
                            }
                            self.action_result = Some(format!("Copied: {path}"));
                        }
                    } else {
                        self.action_result = Some(format!("No clipboard tool (install xclip): {path}"));
                    }
                }
            } else {
                self.action_result = Some("No path available".to_string());
            }
            self.action_menu = false;
        }
    }

    pub fn current_list_len(&self) -> usize {
        match self.tab {
            Tab::Processes   => self.filtered_processes().len(),
            Tab::Persistence => self.persistence.len(),
            Tab::Network     => self.net.hosts.len(),
            Tab::Connections => self.filtered_connections().len(),
        }
    }

    pub fn next(&mut self) {
        let len = self.current_list_len();
        if len > 0 {
            self.selected = (self.selected + 1).min(len - 1);
            match self.tab {
                Tab::Processes   => self.proc_state.select(Some(self.selected)),
                Tab::Connections => self.conn_state.select(Some(self.selected)),
                _ => {}
            }
        }
    }
    pub fn prev(&mut self) {
        self.selected = self.selected.saturating_sub(1);
        match self.tab {
            Tab::Processes   => self.proc_state.select(Some(self.selected)),
            Tab::Connections => self.conn_state.select(Some(self.selected)),
            _ => {}
        }
    }
    pub fn switch_tab(&mut self, tab: Tab) {
        self.tab      = tab;
        self.selected = 0;
        self.conn_state.select(Some(0));
        self.proc_state.select(Some(0));
    }
}
