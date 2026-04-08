// Windows connection monitor — uses `netstat -ano` because the workspace's
// windows crate feature list does not include Win32_NetworkManagement_IpHelper.

use async_trait::async_trait;
use std::process::Command;

use sentinel_core::{
    error::SentinelError,
    models::connection::{ConnState, ConnectionInfo, Proto},
    traits::connection_monitor::ConnectionMonitor,
};

pub struct WindowsConnectionMonitor;

impl WindowsConnectionMonitor {
    pub fn new() -> Self {
        Self
    }
}

/// Parse one `netstat -ano` line into a `ConnectionInfo`.
///
/// Expected formats (active connections):
///   TCP    0.0.0.0:135            0.0.0.0:0              LISTENING       956
///   TCP    192.168.1.5:50222      93.184.216.34:443      ESTABLISHED     4512
///   UDP    0.0.0.0:5353           *:*                                    3684
fn parse_netstat_line(line: &str) -> Option<ConnectionInfo> {
    let mut cols = line.split_whitespace();

    let proto_str = cols.next()?;
    let proto = match proto_str.to_uppercase().as_str() {
        "TCP" | "TCP6" => Proto::Tcp,
        "UDP" | "UDP6" => Proto::Udp,
        _ => return None,
    };

    let local_addr  = cols.next()?.to_owned();
    let remote_raw  = cols.next()?;

    // For TCP the next field is state; for UDP it's the PID.
    let (state, pid) = match proto {
        Proto::Tcp => {
            let state_str = cols.next()?;
            let pid_str   = cols.next()?;
            let pid: u32 = pid_str.parse().ok()?;
            let state = parse_tcp_state(state_str);
            (state, pid)
        }
        Proto::Udp => {
            let pid_str = cols.next()?;
            let pid: u32 = pid_str.parse().ok()?;
            (ConnState::Other("STATELESS".into()), pid)
        }
    };

    let remote_addr = match remote_raw {
        "*:*" | "0.0.0.0:*" | "[::]:*" | "" => None,
        s => Some(s.to_owned()),
    };

    Some(ConnectionInfo {
        pid,
        proto,
        local_addr,
        remote_addr,
        state,
    })
}

fn parse_tcp_state(s: &str) -> ConnState {
    match s.to_uppercase().as_str() {
        "LISTENING"    => ConnState::Listen,
        "ESTABLISHED"  => ConnState::Established,
        "TIME_WAIT"    => ConnState::TimeWait,
        "CLOSE_WAIT"   => ConnState::CloseWait,
        other          => ConnState::Other(other.to_owned()),
    }
}

#[async_trait]
impl ConnectionMonitor for WindowsConnectionMonitor {
    async fn snapshot(&self) -> Result<Vec<ConnectionInfo>, SentinelError> {
        let output = Command::new("netstat")
            .args(["-ano"])
            .output()
            .map_err(|e| SentinelError::Platform(format!("netstat failed: {e}")))?;

        let text = String::from_utf8_lossy(&output.stdout);
        let connections = text
            .lines()
            .filter_map(parse_netstat_line)
            .collect();

        Ok(connections)
    }
}
