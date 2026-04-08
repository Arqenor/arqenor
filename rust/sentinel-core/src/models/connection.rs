use std::fmt;

#[derive(Debug, Clone)]
pub struct ConnectionInfo {
    pub pid:         u32,
    pub proto:       Proto,
    pub local_addr:  String,
    pub remote_addr: Option<String>, // None for LISTEN / unconnected UDP
    pub state:       ConnState,
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
