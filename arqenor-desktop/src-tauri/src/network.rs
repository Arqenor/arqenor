use std::{
    collections::HashMap,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    time::Duration,
};
use serde::{Deserialize, Serialize};
use tokio::net::TcpStream;

// ── Port lists ────────────────────────────────────────────────────────────────

const ALIVE_PORTS: &[u16] = &[80, 22, 443, 3389, 445, 135, 53, 8080, 8443, 23, 21];
const SCAN_PORTS:  &[u16] = &[
    21, 22, 23, 25, 53, 80, 110, 135, 139, 443, 445,
    1433, 3306, 3389, 5900, 8080, 8443,
];

// ── VPN detection ─────────────────────────────────────────────────────────────

const VPN_PROCESSES: &[(&str, &str)] = &[
    ("mullvad-daemon", "Mullvad VPN"),
    ("mullvad",        "Mullvad VPN"),
    ("nordvpnd",       "NordVPN"),
    ("nordvpn",        "NordVPN"),
    ("openvpn",        "OpenVPN"),
    ("wireguard",      "WireGuard"),
    ("wg-quick",       "WireGuard"),
    ("expressvpn",     "ExpressVPN"),
    ("protonvpn",      "ProtonVPN"),
    ("surfshark",      "Surfshark"),
];

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VpnInfo {
    pub name:   String,
    pub tunnel: String,
}

pub fn detect_vpn(proc_names: &[String]) -> Option<VpnInfo> {
    for name in proc_names {
        let lower = name.to_lowercase();
        for (pat, label) in VPN_PROCESSES {
            if lower.contains(pat) {
                let tunnel = get_vpn_tunnel_ip().unwrap_or_else(|| "connected".into());
                return Some(VpnInfo { name: label.to_string(), tunnel });
            }
        }
    }
    None
}

fn get_vpn_tunnel_ip() -> Option<String> {
    let ifaces = if_addrs::get_if_addrs().ok()?;
    for iface in &ifaces {
        if let if_addrs::IfAddr::V4(v4) = &iface.addr {
            let o = v4.ip.octets();
            if o[0] == 10 && (64..=127).contains(&o[1]) { return Some(v4.ip.to_string()); }
            if o[0] == 10 && o[1] == 0 && o[2] == 0 { return Some(v4.ip.to_string()); }
        }
        let n = iface.name.to_lowercase();
        if n.starts_with("tun") || n.starts_with("wg") || n.contains("mullvad") {
            if let if_addrs::IfAddr::V4(v4) = &iface.addr { return Some(v4.ip.to_string()); }
        }
    }
    None
}

// ── Subnet helpers ────────────────────────────────────────────────────────────

pub fn get_lan_subnets() -> Vec<[u8; 3]> {
    let mut subnets: Vec<[u8; 3]> = Vec::new();
    if let Ok(ifaces) = if_addrs::get_if_addrs() {
        for iface in ifaces {
            if iface.is_loopback() { continue; }
            if let if_addrs::IfAddr::V4(v4) = iface.addr {
                if let Some(base) = private_lan_base(v4.ip) {
                    if !subnets.contains(&base) { subnets.push(base); }
                }
            }
        }
    }
    subnets.sort_by_key(|s| if s[0] == 192 && s[1] == 168 { 0u8 } else { 1u8 });
    subnets
}

fn private_lan_base(ip: Ipv4Addr) -> Option<[u8; 3]> {
    let o = ip.octets();
    if o[0] == 192 && o[1] == 168 { return Some([o[0], o[1], o[2]]); }
    if o[0] == 172 && (16..=31).contains(&o[1]) { return Some([o[0], o[1], o[2]]); }
    if o[0] == 10 {
        if (64..=127).contains(&o[1]) || o[1] == 5 || o[1] == 8 { return None; }
        return Some([o[0], o[1], o[2]]);
    }
    None
}

// ── Host info ─────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum HostRisk { Normal, Low, Medium, High }

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum OsGuess { Windows, Linux, Router, Unknown }

/// A single anomaly found on a host.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Anomaly {
    pub severity: String,   // "high" | "medium" | "info"
    pub message:  String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HostInfo {
    pub ip:        String,
    pub hostname:  Option<String>,
    pub ports:     Vec<u16>,
    pub risk:      HostRisk,
    pub os:        OsGuess,
    pub is_new:    bool,             // not seen in previous scan
    pub anomalies: Vec<Anomaly>,
}

// ── Previous scan state (for diff / new-host detection) ───────────────────────

/// Snapshot of a previous scan: IP → sorted open ports.
pub type PreviousScan = HashMap<String, Vec<u16>>;

// ── TCP probing ───────────────────────────────────────────────────────────────

async fn is_alive(ip: Ipv4Addr) -> bool {
    let handles: Vec<_> = ALIVE_PORTS.iter().map(|&port| {
        tokio::spawn(async move {
            let addr = SocketAddr::new(IpAddr::V4(ip), port);
            tokio::time::timeout(Duration::from_millis(500), TcpStream::connect(addr))
                .await.map(|r| r.is_ok()).unwrap_or(false)
        })
    }).collect();
    for h in handles {
        if let Ok(true) = h.await { return true; }
    }
    false
}

async fn scan_ports(ip: Ipv4Addr) -> Vec<u16> {
    let handles: Vec<_> = SCAN_PORTS.iter().map(|&port| {
        tokio::spawn(async move {
            let addr = SocketAddr::new(IpAddr::V4(ip), port);
            let ok = tokio::time::timeout(Duration::from_millis(400), TcpStream::connect(addr))
                .await.map(|r| r.is_ok()).unwrap_or(false);
            (port, ok)
        })
    }).collect();
    let mut open = Vec::new();
    for h in handles { if let Ok((p, true)) = h.await { open.push(p); } }
    open.sort();
    open
}

// ── OS fingerprinting ─────────────────────────────────────────────────────────

fn guess_os(ports: &[u16]) -> OsGuess {
    let has = |p: u16| ports.contains(&p);
    if has(135) || has(139) || has(445) || has(3389) { OsGuess::Windows }
    else if has(22) && !has(80) && !has(443)         { OsGuess::Linux   }
    else if has(80) && has(443) && !has(22) && !has(135) { OsGuess::Router }
    else if has(22)                                  { OsGuess::Linux   }
    else                                             { OsGuess::Unknown }
}

// ── Risk + anomaly assessment ─────────────────────────────────────────────────

fn assess(ports: &[u16], os: &OsGuess, is_new: bool, prev_ports: Option<&Vec<u16>>) -> (HostRisk, Vec<Anomaly>) {
    let mut anomalies: Vec<Anomaly> = Vec::new();
    let has = |p: u16| ports.contains(&p);

    // ── New host ──
    if is_new {
        anomalies.push(Anomaly {
            severity: "high".into(),
            message:  "New device — not seen in previous scan".into(),
        });
    }

    // ── Changed ports ──
    if let Some(prev) = prev_ports {
        if !is_new {
            let added:   Vec<u16> = ports.iter().filter(|p| !prev.contains(p)).copied().collect();
            let removed: Vec<u16> = prev.iter().filter(|p| !ports.contains(p)).copied().collect();
            if !added.is_empty() {
                anomalies.push(Anomaly {
                    severity: "medium".into(),
                    message:  format!("New open ports since last scan: {}", fmt_ports(&added)),
                });
            }
            if !removed.is_empty() {
                anomalies.push(Anomaly {
                    severity: "info".into(),
                    message:  format!("Ports closed since last scan: {}", fmt_ports(&removed)),
                });
            }
        }
    }

    // ── Dangerous services ──
    if has(23) {
        anomalies.push(Anomaly { severity: "high".into(),
            message: "Telnet (port 23) — unencrypted remote access".into() });
    }
    if has(5900) {
        anomalies.push(Anomaly { severity: "high".into(),
            message: "VNC (port 5900) — remote desktop exposed".into() });
    }
    if has(21) {
        anomalies.push(Anomaly { severity: "medium".into(),
            message: "FTP (port 21) — unencrypted file transfer".into() });
    }
    if has(1433) {
        anomalies.push(Anomaly { severity: "medium".into(),
            message: "MSSQL (port 1433) — database exposed on LAN".into() });
    }
    if has(3306) {
        anomalies.push(Anomaly { severity: "medium".into(),
            message: "MySQL (port 3306) — database exposed on LAN".into() });
    }

    // ── Multiple management protocols ──
    let mgmt: Vec<&str> = [
        (3389u16, "RDP"), (5900, "VNC"), (22, "SSH"),
    ].iter().filter(|(p, _)| has(*p)).map(|(_, s)| *s).collect();
    if mgmt.len() >= 2 {
        anomalies.push(Anomaly { severity: "medium".into(),
            message: format!("Multiple remote access methods open: {}", mgmt.join(", ")) });
    }

    // ── Unexpected service for detected OS ──
    if *os == OsGuess::Windows && has(22) {
        anomalies.push(Anomaly { severity: "medium".into(),
            message: "SSH (port 22) on Windows host — unusual, verify intent".into() });
    }
    if *os == OsGuess::Router && has(3389) {
        anomalies.push(Anomaly { severity: "high".into(),
            message: "RDP (port 3389) on router/switch — highly suspicious".into() });
    }
    if *os == OsGuess::Router && has(23) {
        anomalies.push(Anomaly { severity: "high".into(),
            message: "Telnet on router — configuration interface exposed unencrypted".into() });
    }

    // ── Many open ports ──
    if ports.len() > 6 {
        anomalies.push(Anomaly { severity: "medium".into(),
            message: format!("{} open ports — large attack surface", ports.len()) });
    }

    // ── Derive HostRisk from anomalies ──
    let risk = if anomalies.iter().any(|a| a.severity == "high") {
        HostRisk::High
    } else if has(445) || has(3389) || anomalies.iter().any(|a| a.severity == "medium") {
        HostRisk::Medium
    } else if has(135) || has(139) {
        HostRisk::Low
    } else {
        HostRisk::Normal
    };

    (risk, anomalies)
}

fn fmt_ports(ports: &[u16]) -> String {
    ports.iter().map(|p| p.to_string()).collect::<Vec<_>>().join(", ")
}

// ── Hostname resolution ───────────────────────────────────────────────────────

async fn resolve_hostname(ip: Ipv4Addr) -> Option<String> {
    let addr = IpAddr::V4(ip);
    tokio::task::spawn_blocking(move || {
        dns_lookup::lookup_addr(&addr).ok().and_then(|h| {
            // Skip if it's just the IP address echoed back
            if h == ip.to_string() || h.is_empty() { None } else { Some(h) }
        })
    }).await.ok().flatten()
}

// ── Full host scan ────────────────────────────────────────────────────────────

pub async fn scan_host(ip: Ipv4Addr, prev: Option<&Vec<u16>>) -> Option<HostInfo> {
    if !is_alive(ip).await { return None; }

    // Run port scan + hostname resolution in parallel
    let (ports, hostname) = tokio::join!(
        scan_ports(ip),
        resolve_hostname(ip),
    );

    let os     = guess_os(&ports);
    let is_new = prev.is_none();
    let (risk, anomalies) = assess(&ports, &os, is_new, prev);

    Some(HostInfo { ip: ip.to_string(), hostname, ports, risk, os, is_new, anomalies })
}

pub fn scan_subnet(
    base:          [u8; 3],
    previous_scan: PreviousScan,
) -> tokio::sync::mpsc::Receiver<HostInfo> {
    let (tx, rx) = tokio::sync::mpsc::channel(128);

    tokio::spawn(async move {
        let mut join_set = tokio::task::JoinSet::new();

        for last in 1u8..=254 {
            let ip   = Ipv4Addr::new(base[0], base[1], base[2], last);
            let tx2  = tx.clone();
            let prev = previous_scan.get(&ip.to_string()).cloned();

            join_set.spawn(async move {
                if let Some(host) = scan_host(ip, prev.as_ref()).await {
                    let _ = tx2.send(host).await;
                }
            });
        }

        while join_set.join_next().await.is_some() {}
        // tx drops → channel closes
    });

    rx
}
