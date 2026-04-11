use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    time::Duration,
};
use tokio::net::TcpStream;

// ─── VPN detection ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct VpnInfo {
    pub name: String,   // "Mullvad", "NordVPN", etc.
    pub tunnel: String, // detected tunnel IP or interface name
}

const VPN_PROCESSES: &[(&str, &str)] = &[
    ("mullvad-daemon.exe", "Mullvad VPN"),
    ("mullvad", "Mullvad VPN"),
    ("nordvpnd", "NordVPN"),
    ("nordvpn.exe", "NordVPN"),
    ("openvpn.exe", "OpenVPN"),
    ("openvpn", "OpenVPN"),
    ("wireguard.exe", "WireGuard"),
    ("wg-quick", "WireGuard"),
    ("expressvpn", "ExpressVPN"),
    ("expressvpnd", "ExpressVPN"),
    ("protonvpn", "ProtonVPN"),
    ("surfshark", "Surfshark"),
];

/// Detect active VPN by checking running process names.
pub fn detect_vpn(processes: &[String]) -> Option<VpnInfo> {
    for proc_name in processes {
        let lower = proc_name.to_lowercase();
        for (pattern, label) in VPN_PROCESSES {
            if lower.contains(pattern) {
                // Try to find the tunnel IP
                let tunnel = get_vpn_tunnel_ip().unwrap_or_else(|| "connected".into());
                return Some(VpnInfo {
                    name: label.to_string(),
                    tunnel,
                });
            }
        }
    }
    None
}

/// Find the VPN tunnel IP by looking for known VPN IP ranges on interfaces.
fn get_vpn_tunnel_ip() -> Option<String> {
    let ifaces = if_addrs::get_if_addrs().ok()?;
    for iface in &ifaces {
        if let if_addrs::IfAddr::V4(v4) = &iface.addr {
            let o = v4.ip.octets();
            // Mullvad: 10.64–127.x.x
            if o[0] == 10 && (64..=127).contains(&o[1]) {
                return Some(format!("{}", v4.ip));
            }
            // WireGuard common: 10.0.0.x with /32
            if o[0] == 10 && o[1] == 0 && o[2] == 0 {
                return Some(format!("{}", v4.ip));
            }
        }
        // Check interface name for tun/wg
        let name = iface.name.to_lowercase();
        if name.starts_with("tun") || name.starts_with("wg") || name.contains("mullvad") {
            if let if_addrs::IfAddr::V4(v4) = &iface.addr {
                return Some(format!("{}", v4.ip));
            }
        }
    }
    None
}

// Ports scanned on each live host
const SCAN_PORTS: &[u16] = &[
    21, 22, 23, 25, 53, 80, 110, 135, 139, 443, 445, 1433, 3306, 3389, 5900, 8080, 8443,
];

// Ports tried in parallel to decide if a host is alive
const ALIVE_PORTS: &[u16] = &[80, 22, 443, 3389, 445, 135, 53, 8080, 8443, 23];

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HostRisk {
    Normal,
    Low,
    Medium,
    High,
}

impl HostRisk {
    pub fn label(&self) -> &'static str {
        match self {
            Self::High => " HIGH ",
            Self::Medium => " MED  ",
            Self::Low => " LOW  ",
            Self::Normal => "  --  ",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OsGuess {
    Windows,
    Linux,
    Router,
    Unknown,
}

impl OsGuess {
    pub fn label(&self) -> &'static str {
        match self {
            Self::Windows => "Windows",
            Self::Linux => "Linux  ",
            Self::Router => "Router ",
            Self::Unknown => "       ",
        }
    }
}

fn guess_os(ports: &[u16]) -> OsGuess {
    let has = |p: u16| ports.contains(&p);
    if has(135) || has(139) || has(445) || has(3389) {
        OsGuess::Windows
    } else if has(22) && !has(80) && !has(443) {
        OsGuess::Linux
    } else if has(80) && has(443) && !has(22) && !has(135) {
        OsGuess::Router
    } else if has(22) {
        OsGuess::Linux
    } else {
        OsGuess::Unknown
    }
}

#[derive(Debug, Clone)]
pub struct HostInfo {
    pub ip: Ipv4Addr,
    pub ports: Vec<u16>,
    pub risk: HostRisk,
    pub os: OsGuess,
}

fn assess_risk(ports: &[u16]) -> HostRisk {
    if ports.contains(&23) || ports.contains(&5900) {
        HostRisk::High // Telnet / VNC
    } else if ports.contains(&445) || ports.contains(&3389) || ports.contains(&1433) {
        HostRisk::Medium // SMB, RDP, SQL
    } else if ports.contains(&135) || ports.contains(&139) || ports.contains(&21) {
        HostRisk::Low
    } else {
        HostRisk::Normal
    }
}

// ─── Interface detection ────────────────────────────────────────────────────────

/// Returns all detected LAN subnets, sorted: 192.168.x first, then others.
/// Filters out loopback, link-local, and known VPN ranges.
pub fn get_lan_subnets() -> Vec<[u8; 3]> {
    let mut subnets: Vec<[u8; 3]> = Vec::new();

    if let Ok(ifaces) = if_addrs::get_if_addrs() {
        for iface in ifaces {
            if iface.is_loopback() {
                continue;
            }
            if let if_addrs::IfAddr::V4(v4) = iface.addr {
                let ip = v4.ip;
                if let Some(base) = private_lan_base(ip) {
                    if !subnets.contains(&base) {
                        subnets.push(base);
                    }
                }
            }
        }
    }

    // Prefer 192.168.x.x → most likely to be the real home/office LAN
    subnets.sort_by_key(|s| if s[0] == 192 && s[1] == 168 { 0u8 } else { 1u8 });
    subnets
}

/// Returns the /24 base if the IP is a private LAN address.
/// Excludes link-local (169.254.x.x) and common VPN exit ranges.
fn private_lan_base(ip: Ipv4Addr) -> Option<[u8; 3]> {
    let o = ip.octets();
    // 192.168.x.x — home/office LAN
    if o[0] == 192 && o[1] == 168 {
        return Some([o[0], o[1], o[2]]);
    }
    // 172.16–31.x.x — corporate
    if o[0] == 172 && (16..=31).contains(&o[1]) {
        return Some([o[0], o[1], o[2]]);
    }
    // 10.x.x.x — but skip common VPN tunnel ranges:
    //   Mullvad:  10.64–127.x.x
    //   NordVPN:  10.5.0.x / 10.8.0.x
    //   WireGuard: 10.0.0.x with /32 mask
    if o[0] == 10 {
        // Skip known VPN ranges
        if (64..=127).contains(&o[1]) {
            return None;
        } // Mullvad
        if o[1] == 5 || o[1] == 8 {
            return None;
        } // NordVPN common
        return Some([o[0], o[1], o[2]]);
    }
    None
}

// ─── Host scanning ─────────────────────────────────────────────────────────────

/// Check if a host is alive by trying ALIVE_PORTS in parallel.
async fn is_alive(ip: Ipv4Addr) -> bool {
    let handles: Vec<_> = ALIVE_PORTS
        .iter()
        .map(|&port| {
            tokio::spawn(async move {
                let addr = SocketAddr::new(IpAddr::V4(ip), port);
                tokio::time::timeout(Duration::from_millis(500), TcpStream::connect(addr))
                    .await
                    .map(|r| r.is_ok())
                    .unwrap_or(false)
            })
        })
        .collect();

    for h in handles {
        if let Ok(true) = h.await {
            return true;
        }
    }
    false
}

/// Scan all SCAN_PORTS on a confirmed-alive host.
async fn scan_ports(ip: Ipv4Addr) -> Vec<u16> {
    let handles: Vec<_> = SCAN_PORTS
        .iter()
        .map(|&port| {
            tokio::spawn(async move {
                let addr = SocketAddr::new(IpAddr::V4(ip), port);
                let ok = tokio::time::timeout(Duration::from_millis(400), TcpStream::connect(addr))
                    .await
                    .map(|r| r.is_ok())
                    .unwrap_or(false);
                (port, ok)
            })
        })
        .collect();

    let mut open = Vec::new();
    for h in handles {
        if let Ok((port, true)) = h.await {
            open.push(port);
        }
    }
    open.sort();
    open
}

/// Full host scan: alive check then port scan. Returns None if host is down.
pub async fn scan_host(ip: Ipv4Addr) -> Option<HostInfo> {
    if !is_alive(ip).await {
        return None;
    }
    let ports = scan_ports(ip).await;
    let risk = assess_risk(&ports);
    let os = guess_os(&ports);
    Some(HostInfo {
        ip,
        ports,
        risk,
        os,
    })
}

/// Scan a full /24 subnet. Results are streamed via the returned channel.
/// All 254 hosts are probed concurrently (tokio handles the actual parallelism).
pub fn scan_subnet(base: [u8; 3]) -> tokio::sync::mpsc::Receiver<HostInfo> {
    let (tx, rx) = tokio::sync::mpsc::channel(128);

    tokio::spawn(async move {
        let mut join_set = tokio::task::JoinSet::new();

        for last in 1u8..=254 {
            let ip = Ipv4Addr::new(base[0], base[1], base[2], last);
            let tx2 = tx.clone();
            join_set.spawn(async move {
                if let Some(host) = scan_host(ip).await {
                    let _ = tx2.send(host).await;
                }
            });
        }

        // Wait for all probes to finish
        while join_set.join_next().await.is_some() {}
        // tx drops here → channel closes → receiver sees Disconnected
    });

    rx
}
