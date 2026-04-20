// Windows connection monitor — native Win32 IP Helper API
// Uses GetExtendedTcpTable / GetExtendedUdpTable instead of spawning `netstat`.
//
// Supports both IPv4 (AF_INET) and IPv6 (AF_INET6) address families so
// C2 traffic riding over IPv6 is still picked up by beaconing / flow
// analysis downstream.

use async_trait::async_trait;
use std::net::{Ipv4Addr, Ipv6Addr};

use arqenor_core::{
    error::ArqenorError,
    models::connection::{ConnState, ConnectionInfo, Proto},
    traits::connection_monitor::ConnectionMonitor,
};

use windows::Win32::Foundation::NO_ERROR;
use windows::Win32::NetworkManagement::IpHelper::{
    GetExtendedTcpTable, GetExtendedUdpTable, MIB_TCP6ROW_OWNER_PID, MIB_TCP6TABLE_OWNER_PID,
    MIB_TCPROW_OWNER_PID, MIB_TCPTABLE_OWNER_PID, MIB_UDP6ROW_OWNER_PID, MIB_UDP6TABLE_OWNER_PID,
    MIB_UDPROW_OWNER_PID, MIB_UDPTABLE_OWNER_PID, TCP_TABLE_OWNER_PID_ALL, UDP_TABLE_OWNER_PID,
};
use windows::Win32::Networking::WinSock::{AF_INET, AF_INET6};

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

        // Collect TCP (IPv6) connections.
        match collect_tcp_v6() {
            Ok(tcp) => connections.extend(tcp),
            Err(e) => tracing::warn!("GetExtendedTcpTable (IPv6) failed: {e}"),
        }

        // Collect UDP (IPv4) endpoints.
        match collect_udp_v4() {
            Ok(udp) => connections.extend(udp),
            Err(e) => tracing::warn!("GetExtendedUdpTable (IPv4) failed: {e}"),
        }

        // Collect UDP (IPv6) endpoints.
        match collect_udp_v6() {
            Ok(udp) => connections.extend(udp),
            Err(e) => tracing::warn!("GetExtendedUdpTable (IPv6) failed: {e}"),
        }

        Ok(connections)
    }
}

// ---------------------------------------------------------------------------
// TCP helpers — IPv4
// ---------------------------------------------------------------------------

/// Query all IPv4 TCP connections via `GetExtendedTcpTable`.
fn collect_tcp_v4() -> Result<Vec<ConnectionInfo>, ArqenorError> {
    let buf = query_tcp_table(AF_INET.0 as u32)?;
    if buf.len() < std::mem::size_of::<MIB_TCPTABLE_OWNER_PID>() {
        return Ok(Vec::new());
    }

    // SAFETY: buffer was filled by the OS and is at least as large as the
    // returned size value.  We only read within `dwNumEntries` bounds.
    let table = unsafe { &*(buf.as_ptr() as *const MIB_TCPTABLE_OWNER_PID) };
    let count = table.dwNumEntries as usize;

    let mut out = Vec::with_capacity(count);
    for i in 0..count {
        let row = unsafe { &*table.table.as_ptr().add(i) };
        out.push(tcp_v4_row_to_connection(row));
    }
    Ok(out)
}

/// Convert a single IPv4 TCP row into our domain model.
fn tcp_v4_row_to_connection(row: &MIB_TCPROW_OWNER_PID) -> ConnectionInfo {
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

// ---------------------------------------------------------------------------
// TCP helpers — IPv6
// ---------------------------------------------------------------------------

/// Query all IPv6 TCP connections via `GetExtendedTcpTable` with AF_INET6.
fn collect_tcp_v6() -> Result<Vec<ConnectionInfo>, ArqenorError> {
    let buf = query_tcp_table(AF_INET6.0 as u32)?;
    if buf.len() < std::mem::size_of::<MIB_TCP6TABLE_OWNER_PID>() {
        return Ok(Vec::new());
    }

    let table = unsafe { &*(buf.as_ptr() as *const MIB_TCP6TABLE_OWNER_PID) };
    let count = table.dwNumEntries as usize;

    let mut out = Vec::with_capacity(count);
    for i in 0..count {
        let row = unsafe { &*table.table.as_ptr().add(i) };
        out.push(tcp_v6_row_to_connection(row));
    }
    Ok(out)
}

/// Convert a single IPv6 TCP row into our domain model.
///
/// The address bytes are stored in network byte order in the row; the port
/// follows the same `u32` network-byte-order convention as IPv4 rows
/// (only the low 16 bits are meaningful).
pub(crate) fn tcp_v6_row_to_connection(row: &MIB_TCP6ROW_OWNER_PID) -> ConnectionInfo {
    let local_ip = Ipv6Addr::from(row.ucLocalAddr);
    let local_port = port_from_network_order(row.dwLocalPort);

    let remote_ip = Ipv6Addr::from(row.ucRemoteAddr);
    let remote_port = port_from_network_order(row.dwRemotePort);

    let state = tcp_state(row.dwState);

    let remote_addr = if remote_ip.is_unspecified() && remote_port == 0 {
        None
    } else {
        Some(format_ipv6_socket(&remote_ip, remote_port))
    };

    ConnectionInfo {
        pid: row.dwOwningPid,
        proto: Proto::Tcp,
        local_addr: format_ipv6_socket(&local_ip, local_port),
        remote_addr,
        state,
        firewall_blocked: None,
    }
}

// ---------------------------------------------------------------------------
// Shared TCP helpers
// ---------------------------------------------------------------------------

/// Two-pass call: first to get the required buffer size, then to fill it.
///
/// `family` is either `AF_INET.0 as u32` or `AF_INET6.0 as u32`.
fn query_tcp_table(family: u32) -> Result<Vec<u8>, ArqenorError> {
    unsafe {
        let mut size: u32 = 0;

        // First call — expected to return ERROR_INSUFFICIENT_BUFFER.
        let _ = GetExtendedTcpTable(None, &mut size, false, family, TCP_TABLE_OWNER_PID_ALL, 0);

        if size == 0 {
            return Ok(Vec::new());
        }

        let mut buf = vec![0u8; size as usize];

        let ret = GetExtendedTcpTable(
            Some(buf.as_mut_ptr() as *mut _),
            &mut size,
            false,
            family,
            TCP_TABLE_OWNER_PID_ALL,
            0,
        );

        if ret != NO_ERROR.0 {
            return Err(ArqenorError::Platform(format!(
                "GetExtendedTcpTable(family={family}) returned error code {ret}"
            )));
        }

        Ok(buf)
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
// UDP helpers — IPv4
// ---------------------------------------------------------------------------

/// Query all IPv4 UDP endpoints via `GetExtendedUdpTable`.
fn collect_udp_v4() -> Result<Vec<ConnectionInfo>, ArqenorError> {
    let buf = query_udp_table(AF_INET.0 as u32)?;
    if buf.len() < std::mem::size_of::<MIB_UDPTABLE_OWNER_PID>() {
        return Ok(Vec::new());
    }

    let table = unsafe { &*(buf.as_ptr() as *const MIB_UDPTABLE_OWNER_PID) };
    let count = table.dwNumEntries as usize;

    let mut out = Vec::with_capacity(count);
    for i in 0..count {
        let row = unsafe { &*table.table.as_ptr().add(i) };
        out.push(udp_v4_row_to_connection(row));
    }
    Ok(out)
}

fn udp_v4_row_to_connection(row: &MIB_UDPROW_OWNER_PID) -> ConnectionInfo {
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
// UDP helpers — IPv6
// ---------------------------------------------------------------------------

/// Query all IPv6 UDP endpoints via `GetExtendedUdpTable` with AF_INET6.
fn collect_udp_v6() -> Result<Vec<ConnectionInfo>, ArqenorError> {
    let buf = query_udp_table(AF_INET6.0 as u32)?;
    if buf.len() < std::mem::size_of::<MIB_UDP6TABLE_OWNER_PID>() {
        return Ok(Vec::new());
    }

    let table = unsafe { &*(buf.as_ptr() as *const MIB_UDP6TABLE_OWNER_PID) };
    let count = table.dwNumEntries as usize;

    let mut out = Vec::with_capacity(count);
    for i in 0..count {
        let row = unsafe { &*table.table.as_ptr().add(i) };
        out.push(udp_v6_row_to_connection(row));
    }
    Ok(out)
}

fn udp_v6_row_to_connection(row: &MIB_UDP6ROW_OWNER_PID) -> ConnectionInfo {
    let local_ip = Ipv6Addr::from(row.ucLocalAddr);
    let local_port = port_from_network_order(row.dwLocalPort);

    ConnectionInfo {
        pid: row.dwOwningPid,
        proto: Proto::Udp,
        local_addr: format_ipv6_socket(&local_ip, local_port),
        remote_addr: None,
        state: ConnState::Other("STATELESS".into()),
        firewall_blocked: None,
    }
}

// ---------------------------------------------------------------------------
// Shared UDP helpers
// ---------------------------------------------------------------------------

fn query_udp_table(family: u32) -> Result<Vec<u8>, ArqenorError> {
    unsafe {
        let mut size: u32 = 0;

        let _ = GetExtendedUdpTable(None, &mut size, false, family, UDP_TABLE_OWNER_PID, 0);

        if size == 0 {
            return Ok(Vec::new());
        }

        let mut buf = vec![0u8; size as usize];

        let ret = GetExtendedUdpTable(
            Some(buf.as_mut_ptr() as *mut _),
            &mut size,
            false,
            family,
            UDP_TABLE_OWNER_PID,
            0,
        );

        if ret != NO_ERROR.0 {
            return Err(ArqenorError::Platform(format!(
                "GetExtendedUdpTable(family={family}) returned error code {ret}"
            )));
        }

        Ok(buf)
    }
}

// ---------------------------------------------------------------------------
// Byte-order / formatting helpers
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

/// Format an IPv6 socket in the canonical `[addr]:port` form so downstream
/// parsers (`SocketAddr::parse`) can round-trip it.
#[inline]
fn format_ipv6_socket(ip: &Ipv6Addr, port: u16) -> String {
    format!("[{ip}]:{port}")
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::SocketAddr;

    /// Build a simulated `MIB_TCP6ROW_OWNER_PID` for an ESTABLISHED connection
    /// from `fe80::1` (port 49152) to `2001:db8::2` (port 443), and verify the
    /// converter produces the expected `ConnectionInfo`.
    ///
    /// This exercises: IPv6 byte-array decoding, network-byte-order port
    /// extraction, TCP state mapping, and bracketed-host formatting.
    #[test]
    fn simulated_tcp6_row_maps_to_connection_info() {
        // fe80::1
        let local_addr: [u8; 16] = [
            0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01,
        ];
        // 2001:db8::2
        let remote_addr: [u8; 16] = [
            0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x02,
        ];

        // Port 49152 in network byte order: u16::from_be(0xC000) == 49152.
        let local_port_ne = u32::from((49152u16).to_be());
        // Port 443 in network byte order: u16::from_be(0x01BB) == 443.
        let remote_port_ne = u32::from((443u16).to_be());

        let row = MIB_TCP6ROW_OWNER_PID {
            ucLocalAddr: local_addr,
            dwLocalScopeId: 0,
            dwLocalPort: local_port_ne,
            ucRemoteAddr: remote_addr,
            dwRemoteScopeId: 0,
            dwRemotePort: remote_port_ne,
            dwState: 5, // Established
            dwOwningPid: 1234,
        };

        let ci = tcp_v6_row_to_connection(&row);

        assert_eq!(ci.pid, 1234);
        assert_eq!(ci.proto, Proto::Tcp);
        assert_eq!(ci.state, ConnState::Established);
        assert_eq!(ci.local_addr, "[fe80::1]:49152");
        assert_eq!(ci.remote_addr.as_deref(), Some("[2001:db8::2]:443"));

        // The formatted addresses must round-trip through SocketAddr so the
        // pipeline's `parse_addr` keeps working end-to-end.
        let local_sa: SocketAddr = ci.local_addr.parse().expect("local parses");
        assert!(local_sa.is_ipv6());
        assert_eq!(local_sa.port(), 49152);

        let remote_sa: SocketAddr = ci.remote_addr.as_deref().unwrap().parse().unwrap();
        assert!(remote_sa.is_ipv6());
        assert_eq!(remote_sa.port(), 443);
    }

    /// An unspecified remote `[::]:0` must collapse to `None` (LISTEN socket),
    /// mirroring the IPv4 `0.0.0.0:0` behaviour.
    #[test]
    fn tcp6_listen_row_drops_remote_addr() {
        let row = MIB_TCP6ROW_OWNER_PID {
            ucLocalAddr: [0u8; 16], // [::]
            dwLocalScopeId: 0,
            dwLocalPort: u32::from((8080u16).to_be()),
            ucRemoteAddr: [0u8; 16], // [::]
            dwRemoteScopeId: 0,
            dwRemotePort: 0,
            dwState: 2, // Listen
            dwOwningPid: 42,
        };

        let ci = tcp_v6_row_to_connection(&row);
        assert_eq!(ci.state, ConnState::Listen);
        assert_eq!(ci.local_addr, "[::]:8080");
        assert!(ci.remote_addr.is_none());
    }

    #[test]
    fn ipv4_port_network_order_roundtrip() {
        assert_eq!(port_from_network_order(u32::from((443u16).to_be())), 443);
        assert_eq!(port_from_network_order(u32::from((53u16).to_be())), 53);
    }
}
