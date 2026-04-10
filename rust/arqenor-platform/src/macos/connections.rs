// macOS connection monitor — parses `lsof -i -n -P -w` output.
// No extra crates needed; lsof ships with every macOS install.

use async_trait::async_trait;
use std::process::Command;

use arqenor_core::{
    error::ArqenorError,
    models::connection::{ConnState, ConnectionInfo, Proto},
    traits::connection_monitor::ConnectionMonitor,
};

pub struct MacosConnectionMonitor;

impl MacosConnectionMonitor {
    pub fn new() -> Self {
        Self
    }
}

// ── lsof line parser ─────────────────────────────────────────────────────────
//
// `lsof -i -n -P -w` produces lines like:
//   COMMAND   PID   USER   FD   TYPE  DEVICE  SIZE/OFF  NODE  NAME
//   rapportd  395   user   13u  IPv4  0x...   0t0       TCP   127.0.0.1:49376->127.0.0.1:49377 (ESTABLISHED)
//   rapportd  395   user   15u  IPv6  0x...   0t0       TCP   *:7000 (LISTEN)
//   sharingd  432   user   22u  IPv4  0x...   0t0       UDP   *:5353
//
// We skip the header line (starts with "COMMAND").

fn parse_lsof_line(line: &str) -> Option<ConnectionInfo> {
    let cols: Vec<&str> = line.split_whitespace().collect();

    // Minimum: COMMAND PID USER FD TYPE DEVICE SIZE NODE NAME
    if cols.len() < 9 {
        return None;
    }

    if cols[0] == "COMMAND" {
        return None; // header
    }

    let pid: u32 = cols[1].parse().ok()?;

    // TYPE column (cols[4]) is IPv4 / IPv6; skip others (unix sockets, etc.)
    match cols[4] {
        "IPv4" | "IPv6" => {}
        _ => return None,
    }

    // cols[7] is TCP/UDP
    let proto = match cols[7].to_uppercase().as_str() {
        "TCP" => Proto::Tcp,
        "UDP" => Proto::Udp,
        _ => return None,
    };

    // NAME field (cols[8]) holds the address and optional state:
    //   "127.0.0.1:49376->127.0.0.1:49377 (ESTABLISHED)"
    //   "*:7000 (LISTEN)"
    //   "*:5353"
    let name = cols[8];

    // Strip optional " (STATE)" suffix — it may appear as a separate token.
    // Collect everything from col[8] onward as the full name string.
    let full_name: String = cols[8..].join(" ");

    // Extract state from parenthesis if present.
    let (addr_part, state_str) = if let Some(paren_start) = full_name.find('(') {
        let addr = full_name[..paren_start].trim();
        let state = full_name[paren_start + 1..].trim_end_matches(')').trim();
        (addr, state.to_owned())
    } else {
        (full_name.trim(), String::new())
    };

    let state = match proto {
        Proto::Udp => ConnState::Other("STATELESS".into()),
        Proto::Tcp => match state_str.to_uppercase().as_str() {
            "LISTEN"      => ConnState::Listen,
            "ESTABLISHED" => ConnState::Established,
            "TIME_WAIT"   => ConnState::TimeWait,
            "CLOSE_WAIT"  => ConnState::CloseWait,
            ""            => ConnState::Other("UNKNOWN".into()),
            other         => ConnState::Other(other.to_owned()),
        },
    };

    // Split "local->remote" or just "local".
    let (local_addr, remote_addr) = if let Some((l, r)) = addr_part.split_once("->") {
        // Replace lsof's wildcard "*" with "0.0.0.0".
        let local  = l.replace('*', "0.0.0.0");
        let remote = r.replace('*', "0.0.0.0");
        (local, Some(remote))
    } else {
        let local = addr_part.replace('*', "0.0.0.0");
        (local, None)
    };

    // Suppress unused variable warning for `name`.
    let _ = name;

    Some(ConnectionInfo {
        pid,
        proto,
        local_addr,
        remote_addr,
        state,
        firewall_blocked: None,
    })
}

#[async_trait]
impl ConnectionMonitor for MacosConnectionMonitor {
    async fn snapshot(&self) -> Result<Vec<ConnectionInfo>, ArqenorError> {
        let output = Command::new("lsof")
            .args(["-i", "-n", "-P", "-w"])
            .output()
            .map_err(|e| ArqenorError::Platform(format!("lsof failed: {e}")))?;

        let text = String::from_utf8_lossy(&output.stdout);
        let connections = text
            .lines()
            .filter_map(parse_lsof_line)
            .collect();

        Ok(connections)
    }
}
