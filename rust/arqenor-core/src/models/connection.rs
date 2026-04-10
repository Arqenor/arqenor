use std::fmt;

#[derive(Debug, Clone)]
pub struct ConnectionInfo {
    pub pid:         u32,
    pub proto:       Proto,
    pub local_addr:  String,
    pub remote_addr: Option<String>, // None for LISTEN / unconnected UDP
    pub state:       ConnState,
    /// `Some(true)` when an active inbound Block firewall rule covers the local
    /// port.  `None` means the firewall state was not queried (unsupported
    /// platform, feature disabled, or insufficient privileges).
    pub firewall_blocked: Option<bool>,
}

/// Ports that represent high-value lateral-movement attack surface when
/// exposed on 0.0.0.0 without a firewall block rule.
pub const LATERAL_MOVEMENT_PORTS: &[u16] = &[
    445,  // SMB
    139,  // NetBIOS Session
    135,  // MS-RPC Endpoint Mapper
    3389, // RDP
    5985, // WinRM HTTP
];

/// Determine the risk severity of a LISTEN connection, factoring in firewall
/// state.  Returns `None` for connections that don't match any high-risk
/// heuristic.
pub fn listen_risk_severity(conn: &ConnectionInfo) -> Option<ListenRisk> {
    if conn.state != ConnState::Listen {
        return None;
    }

    let port = local_port(conn)?;
    let on_all_interfaces = conn.local_addr.starts_with("0.0.0.0:");

    // Loopback or specific LAN interface → no risk from exposure.
    if !on_all_interfaces {
        return Some(ListenRisk::None);
    }

    let is_lateral = LATERAL_MOVEMENT_PORTS.contains(&port);
    let is_other_risky = matches!(port, 5900 | 23 | 21 | 4444 | 1337);

    if !is_lateral && !is_other_risky {
        return None;
    }

    match conn.firewall_blocked {
        Some(true) => Some(ListenRisk::Low),
        _ => Some(ListenRisk::Critical),
    }
}

/// Extracted local port from a connection's local_addr.
pub fn local_port(conn: &ConnectionInfo) -> Option<u16> {
    conn.local_addr
        .rsplit(':')
        .next()
        .and_then(|p| p.trim_end_matches(']').parse().ok())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ListenRisk {
    /// Firewall blocks inbound — low concern.
    Low,
    /// Exposed on 0.0.0.0 with no firewall block — critical.
    Critical,
    /// Bound only on loopback / specific interface — no exposure.
    None,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Proto {
    Tcp,
    Udp,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConnState {
    Listen,
    Established,
    TimeWait,
    CloseWait,
    Other(String),
}

impl fmt::Display for Proto {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Proto::Tcp => write!(f, "TCP"),
            Proto::Udp => write!(f, "UDP"),
        }
    }
}

impl fmt::Display for ConnState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ConnState::Listen      => write!(f, "LISTEN"),
            ConnState::Established => write!(f, "ESTABLISHED"),
            ConnState::TimeWait    => write!(f, "TIME_WAIT"),
            ConnState::CloseWait   => write!(f, "CLOSE_WAIT"),
            ConnState::Other(s)    => write!(f, "{s}"),
        }
    }
}
