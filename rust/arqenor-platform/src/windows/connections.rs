// Windows connection monitor — native Win32 IP Helper API
// Uses GetExtendedTcpTable / GetExtendedUdpTable instead of spawning `netstat`.

use async_trait::async_trait;
use std::net::Ipv4Addr;

use arqenor_core::{
    error::ArqenorError,
    models::connection::{ConnState, ConnectionInfo, Proto},
    traits::connection_monitor::ConnectionMonitor,
};

use windows::Win32::Foundation::NO_ERROR;
use windows::Win32::NetworkManagement::IpHelper::{
    GetExtendedTcpTable, GetExtendedUdpTable, MIB_TCPROW_OWNER_PID, MIB_TCPTABLE_OWNER_PID,
    MIB_UDPROW_OWNER_PID, MIB_UDPTABLE_OWNER_PID, TCP_TABLE_OWNER_PID_ALL, UDP_TABLE_OWNER_PID,
};
use windows::Win32::Networking::WinSock::AF_INET;

// ---------------------------------------------------------------------------
// Public struct
// ---------------------------------------------------------------------------

pub struct WindowsConnectionMonitor;

impl WindowsConnectionMonitor {
    pub fn new() -> Self {
        Self
    }
}

impl Default for WindowsConnectionMonitor {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// ConnectionMonitor impl
// ---------------------------------------------------------------------------

#[async_trait]
impl ConnectionMonitor for WindowsConnectionMonitor {
    async fn snapshot(&self) -> Result<Vec<ConnectionInfo>, ArqenorError> {
        let mut connections = Vec::new();

        // Collect TCP (IPv4) connections.
        match collect_tcp_v4() {
            Ok(tcp) => connections.extend(tcp),
            Err(e) => tracing::warn!("GetExtendedTcpTable (IPv4) failed: {e}"),
        }

        // Collect UDP (IPv4) endpoints.
        match collect_udp_v4() {
            Ok(udp) => connections.extend(udp),
            Err(e) => tracing::warn!("GetExtendedUdpTable (IPv4) failed: {e}"),
        }

        Ok(connections)
    }
}

// ---------------------------------------------------------------------------
// TCP helpers
// ---------------------------------------------------------------------------

/// Query all IPv4 TCP connections via `GetExtendedTcpTable`.
fn collect_tcp_v4() -> Result<Vec<ConnectionInfo>, ArqenorError> {
    let buf = query_tcp_table()?;

    // SAFETY: buffer was filled by the OS and is at least as large as the
    // returned size value.  We only read within `dwNumEntries` bounds.
    let table = unsafe { &*(buf.as_ptr() as *const MIB_TCPTABLE_OWNER_PID) };
    let count = table.dwNumEntries as usize;

    let mut out = Vec::with_capacity(count);
    for i in 0..count {
        let row = unsafe { &*table.table.as_ptr().add(i) };
        out.push(tcp_row_to_connection(row));
    }
    Ok(out)
}

/// Two-pass call: first to get the required buffer size, then to fill it.
fn query_tcp_table() -> Result<Vec<u8>, ArqenorError> {
    unsafe {
        let mut size: u32 = 0;

        // First call — expected to return ERROR_INSUFFICIENT_BUFFER.
        let _ = GetExtendedTcpTable(
            None,
            &mut size,
            false,
            AF_INET.0 as u32,
            TCP_TABLE_OWNER_PID_ALL,
            0,
        );

        let mut buf = vec![0u8; size as usize];

        let ret = GetExtendedTcpTable(
            Some(buf.as_mut_ptr() as *mut _),
            &mut size,
            false,
            AF_INET.0 as u32,
            TCP_TABLE_OWNER_PID_ALL,
            0,
        );

        if ret != NO_ERROR.0 {
            return Err(ArqenorError::Platform(format!(
                "GetExtendedTcpTable returned error code {ret}"
            )));
        }

        Ok(buf)
    }
}

/// Convert a single TCP row into our domain model.
fn tcp_row_to_connection(row: &MIB_TCPROW_OWNER_PID) -> ConnectionInfo {
    let local_ip = ipv4_from_network_order(row.dwLocalAddr);
    let local_port = port_from_network_order(row.dwLocalPort);

    let remote_ip = ipv4_from_network_order(row.dwRemoteAddr);
    let remote_port = port_from_network_order(row.dwRemotePort);

    let state = tcp_state(row.dwState);

    // Suppress remote address for LISTEN sockets (0.0.0.0:0).
    let remote_addr = if remote_ip.is_unspecified() && remote_port == 0 {
        None
    } else {
        Some(format!("{remote_ip}:{remote_port}"))
    };

    ConnectionInfo {
        pid: row.dwOwningPid,
        proto: Proto::Tcp,
        local_addr: format!("{local_ip}:{local_port}"),
        remote_addr,
        state,
        firewall_blocked: None,
    }
}

/// Map the Win32 `MIB_TCP_STATE` integer to our `ConnState` enum.
fn tcp_state(raw: u32) -> ConnState {
    match raw {
        2 => ConnState::Listen,
        5 => ConnState::Established,
        8 => ConnState::CloseWait,
        11 => ConnState::TimeWait,
        other => ConnState::Other(format!("MIB_TCP_STATE_{other}")),
    }
}

// ---------------------------------------------------------------------------
// UDP helpers
// ---------------------------------------------------------------------------

/// Query all IPv4 UDP endpoints via `GetExtendedUdpTable`.
fn collect_udp_v4() -> Result<Vec<ConnectionInfo>, ArqenorError> {
    let buf = query_udp_table()?;

    let table = unsafe { &*(buf.as_ptr() as *const MIB_UDPTABLE_OWNER_PID) };
    let count = table.dwNumEntries as usize;

    let mut out = Vec::with_capacity(count);
    for i in 0..count {
        let row = unsafe { &*table.table.as_ptr().add(i) };
        out.push(udp_row_to_connection(row));
    }
    Ok(out)
}

fn query_udp_table() -> Result<Vec<u8>, ArqenorError> {
    unsafe {
        let mut size: u32 = 0;

        let _ = GetExtendedUdpTable(
            None,
            &mut size,
            false,
            AF_INET.0 as u32,
            UDP_TABLE_OWNER_PID,
            0,
        );

        let mut buf = vec![0u8; size as usize];

        let ret = GetExtendedUdpTable(
            Some(buf.as_mut_ptr() as *mut _),
            &mut size,
            false,
            AF_INET.0 as u32,
            UDP_TABLE_OWNER_PID,
            0,
        );

        if ret != NO_ERROR.0 {
            return Err(ArqenorError::Platform(format!(
                "GetExtendedUdpTable returned error code {ret}"
            )));
        }

        Ok(buf)
    }
}

fn udp_row_to_connection(row: &MIB_UDPROW_OWNER_PID) -> ConnectionInfo {
    let local_ip = ipv4_from_network_order(row.dwLocalAddr);
    let local_port = port_from_network_order(row.dwLocalPort);

    ConnectionInfo {
        pid: row.dwOwningPid,
        proto: Proto::Udp,
        local_addr: format!("{local_ip}:{local_port}"),
        remote_addr: None,
        state: ConnState::Other("STATELESS".into()),
        firewall_blocked: None,
    }
}

// ---------------------------------------------------------------------------
// Byte-order conversion helpers
// ---------------------------------------------------------------------------

/// Convert a `u32` IPv4 address in network byte order to `Ipv4Addr`.
#[inline]
fn ipv4_from_network_order(raw: u32) -> Ipv4Addr {
    Ipv4Addr::from(u32::from_be(raw))
}

/// Extract a port number from a `u32` value in network byte order.
/// Only the lower 16 bits are meaningful.
#[inline]
fn port_from_network_order(raw: u32) -> u16 {
    u16::from_be((raw & 0xFFFF) as u16)
}
