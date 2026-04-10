// Linux connection monitor — reads /proc/net/tcp[6] and /proc/net/udp[6],
// then resolves PIDs by matching socket inodes against /proc/<pid>/fd/ symlinks.

use async_trait::async_trait;
use std::collections::HashMap;
use std::fs;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::path::Path;

use sentinel_core::{
    error::SentinelError,
    models::connection::{ConnState, ConnectionInfo, Proto},
    traits::connection_monitor::ConnectionMonitor,
};

pub struct LinuxConnectionMonitor;

impl LinuxConnectionMonitor {
    pub fn new() -> Self {
        Self
    }
}

// ── inode → PID map ─────────────────────────────────────────────────────────

/// Walk /proc/<pid>/fd/ and build a map from socket inode → pid.
fn build_inode_pid_map() -> HashMap<u64, u32> {
    let mut map = HashMap::new();

    let proc_dir = match fs::read_dir("/proc") {
        Ok(d) => d,
        Err(_) => return map,
    };

    for entry in proc_dir.flatten() {
        let fname = entry.file_name();
        let fname = fname.to_string_lossy();
        let pid: u32 = match fname.parse() {
            Ok(p) => p,
            Err(_) => continue, // not a numeric PID directory
        };

        let fd_path = format!("/proc/{pid}/fd");
        let fd_dir = match fs::read_dir(&fd_path) {
            Ok(d) => d,
            Err(_) => continue, // process may have already exited
        };

        for fd_entry in fd_dir.flatten() {
            let link_path = fd_entry.path();
            if let Ok(target) = fs::read_link(&link_path) {
                let target_str = target.to_string_lossy();
                // Socket entries look like: socket:[<inode>]
                if let Some(inode_str) = target_str.strip_prefix("socket:[").and_then(|s| s.strip_suffix(']')) {
                    if let Ok(inode) = inode_str.parse::<u64>() {
                        map.insert(inode, pid);
                    }
                }
            }
        }
    }

    map
}

// ── /proc/net/tcp format parsing ─────────────────────────────────────────────

/// Convert a little-endian hex IPv4 address:port pair from /proc/net/tcp.
/// Example: "0F02000A:1F90" → "10.0.2.15:8080"
fn parse_ipv4_addr(hex: &str) -> Option<String> {
    let (addr_hex, port_hex) = hex.split_once(':')?;
    let addr_u32 = u32::from_str_radix(addr_hex, 16).ok()?;
    let port     = u16::from_str_radix(port_hex,  16).ok()?;
    // /proc/net/tcp stores the address in host byte order (little-endian on x86).
    let ip = Ipv4Addr::from(u32::from_be(addr_u32.swap_bytes()));
    Some(format!("{ip}:{port}"))
}

/// Convert a little-endian hex IPv6 address:port pair from /proc/net/tcp6.
fn parse_ipv6_addr(hex: &str) -> Option<String> {
    let (addr_hex, port_hex) = hex.split_once(':')?;
    let port = u16::from_str_radix(port_hex, 16).ok()?;

    if addr_hex.len() != 32 {
        return None;
    }

    // Each 8-char chunk is a 32-bit word in host byte order.
    let mut octets = [0u8; 16];
    for (i, chunk) in addr_hex.as_bytes().chunks(8).enumerate() {
        let word_hex = std::str::from_utf8(chunk).ok()?;
        let word = u32::from_str_radix(word_hex, 16).ok()?;
        let bytes = word.to_ne_bytes(); // host byte order
        octets[i * 4..(i + 1) * 4].copy_from_slice(&bytes);
    }

    let ip = Ipv6Addr::from(octets);
    Some(format!("[{ip}]:{port}"))
}

/// Parse tcp state code (hex) into ConnState.
fn tcp_state(hex_code: &str) -> ConnState {
    match hex_code {
        "01" => ConnState::Established,
        "0A" => ConnState::Listen,
        "06" => ConnState::TimeWait,
        "08" => ConnState::CloseWait,
        other => ConnState::Other(format!("0x{other}")),
    }
}

// ── generic /proc/net/{tcp,udp} parser ───────────────────────────────────────

struct RawEntry {
    local_addr:  String,
    remote_addr: String,
    state:       ConnState,
    inode:       u64,
    is_udp:      bool,
}

fn parse_proc_net(path: &Path, is_ipv6: bool, is_udp: bool) -> Vec<RawEntry> {
    let content = match fs::read_to_string(path) {
        Ok(c) => c,
        Err(_) => return vec![],
    };

    let mut entries = Vec::new();

    for line in content.lines().skip(1) {
        // Columns: sl local_address rem_address st tx_queue:rx_queue tr:tm->when retrnsmt uid timeout inode ...
        let cols: Vec<&str> = line.split_whitespace().collect();
        if cols.len() < 10 {
            continue;
        }

        let local_raw  = cols[1];
        let remote_raw = cols[2];
        let state_raw  = cols[3];
        let inode: u64 = match cols[9].parse() {
            Ok(i) => i,
            Err(_) => continue,
        };

        let parse_addr = if is_ipv6 { parse_ipv6_addr } else { parse_ipv4_addr };

        let local_addr  = match parse_addr(local_raw)  { Some(a) => a, None => continue };
        let remote_addr = match parse_addr(remote_raw) { Some(a) => a, None => continue };

        let state = if is_udp {
            ConnState::Other("STATELESS".into())
        } else {
            tcp_state(state_raw)
        };

        entries.push(RawEntry {
            local_addr,
            remote_addr,
            state,
            inode,
            is_udp,
        });
    }

    entries
}

// ── merge and resolve ─────────────────────────────────────────────────────────

fn collect_connections(inode_map: &HashMap<u64, u32>) -> Vec<ConnectionInfo> {
    let sources: &[(&str, bool, bool)] = &[
        ("/proc/net/tcp",  false, false),
        ("/proc/net/tcp6", true,  false),
        ("/proc/net/udp",  false, true),
        ("/proc/net/udp6", true,  true),
    ];

    let mut result = Vec::new();

    for &(path, is_ipv6, is_udp) in sources {
        let entries = parse_proc_net(Path::new(path), is_ipv6, is_udp);
        for e in entries {
            let pid = *inode_map.get(&e.inode).unwrap_or(&0);
            let proto = if e.is_udp { Proto::Udp } else { Proto::Tcp };

            // Treat "0.0.0.0:0" / "[::]0" as no remote.
            let remote_addr = if e.remote_addr.ends_with(":0")
                || e.remote_addr == "[::]:0"
            {
                None
            } else {
                Some(e.remote_addr)
            };

            result.push(ConnectionInfo {
                pid,
                proto,
                local_addr: e.local_addr,
                remote_addr,
                state: e.state,
                firewall_blocked: None,
            });
        }
    }

    result
}

#[async_trait]
impl ConnectionMonitor for LinuxConnectionMonitor {
    async fn snapshot(&self) -> Result<Vec<ConnectionInfo>, SentinelError> {
        // Building the inode→PID map is the only expensive part; do it once.
        let inode_map = build_inode_pid_map();
        Ok(collect_connections(&inode_map))
    }
}
