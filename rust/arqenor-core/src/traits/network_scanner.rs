use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::Duration;

use async_trait::async_trait;
use thiserror::Error;
use tokio::sync::mpsc;

/// Default per-port connect / banner timeout when the caller passes zero.
pub const DEFAULT_PORT_TIMEOUT: Duration = Duration::from_secs(2);

/// Inputs to a single network scan.
#[derive(Debug, Clone)]
pub struct ScanRequest {
    pub cidr: String,
    pub ports: Vec<u16>,
    pub timeout: Duration,
    pub service_detect: bool,
}

/// Per-port findings within a [`HostResult`].
#[derive(Debug, Clone, Default)]
pub struct PortResult {
    pub port: u16,
    pub proto: String,
    pub state: String,
    pub service: String,
    pub banner: String,
    pub version: String,
}

/// Per-host findings emitted on the streaming channel.
#[derive(Debug, Clone, Default)]
pub struct HostResult {
    pub ip: String,
    pub hostname: String,
    pub mac_addr: String,
    pub is_up: bool,
    pub open_ports: Vec<PortResult>,
}

#[derive(Debug, Error)]
pub enum NetworkScanError {
    #[error("invalid CIDR `{0}`")]
    InvalidCidr(String),
    #[error("CIDR range too large ({0} hosts; cap is {1})")]
    RangeTooLarge(usize, usize),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("internal scanner error: {0}")]
    Internal(String),
}

/// Cross-platform network scanner abstraction. Implementations stream
/// [`HostResult`]s on the returned receiver and close it when the scan is
/// complete.
#[async_trait]
pub trait NetworkScanner: Send + Sync {
    async fn scan(&self, req: ScanRequest) -> Result<mpsc::Receiver<HostResult>, NetworkScanError>;
}

/// Parse `cidr` and enumerate every host address in the block.
///
/// IPv4 ranges larger than two addresses have the network and broadcast
/// addresses removed (matching the Go `hostsInCIDR` helper). For IPv6 (or
/// host-only ranges) every address is returned verbatim — broadcast does
/// not exist on IPv6 and a `/32` (v4) or `/128` (v6) is unambiguously a
/// single host.
pub fn parse_cidr(cidr: &str) -> Result<Vec<IpAddr>, NetworkScanError> {
    let (addr_part, prefix_part) = cidr
        .split_once('/')
        .ok_or_else(|| NetworkScanError::InvalidCidr(cidr.to_string()))?;

    let prefix: u32 = prefix_part
        .parse()
        .map_err(|_| NetworkScanError::InvalidCidr(cidr.to_string()))?;

    let base: IpAddr = addr_part
        .parse()
        .map_err(|_| NetworkScanError::InvalidCidr(cidr.to_string()))?;

    match base {
        IpAddr::V4(v4) => parse_cidr_v4(v4, prefix, cidr),
        IpAddr::V6(v6) => parse_cidr_v6(v6, prefix, cidr),
    }
}

fn parse_cidr_v4(addr: Ipv4Addr, prefix: u32, raw: &str) -> Result<Vec<IpAddr>, NetworkScanError> {
    if prefix > 32 {
        return Err(NetworkScanError::InvalidCidr(raw.to_string()));
    }

    let host_bits = 32 - prefix;
    let bits = u32::from(addr);
    let mask: u32 = if prefix == 0 {
        0
    } else {
        u32::MAX << host_bits
    };
    let network = bits & mask;
    let count: u64 = 1u64 << host_bits;

    let mut ips = Vec::with_capacity(count as usize);
    for i in 0..count {
        let raw_ip = network.wrapping_add(i as u32);
        ips.push(IpAddr::V4(Ipv4Addr::from(raw_ip)));
    }

    if ips.len() > 2 {
        ips.remove(ips.len() - 1);
        ips.remove(0);
    }
    Ok(ips)
}

fn parse_cidr_v6(addr: Ipv6Addr, prefix: u32, raw: &str) -> Result<Vec<IpAddr>, NetworkScanError> {
    if prefix > 128 {
        return Err(NetworkScanError::InvalidCidr(raw.to_string()));
    }

    let host_bits = 128 - prefix;
    if host_bits > 16 {
        return Err(NetworkScanError::RangeTooLarge(1usize << 16, 1usize << 16));
    }

    let bits = u128::from(addr);
    let mask: u128 = if prefix == 0 {
        0
    } else {
        u128::MAX << host_bits
    };
    let network = bits & mask;
    let count: u128 = 1u128 << host_bits;

    let mut ips = Vec::with_capacity(count as usize);
    for i in 0..count {
        ips.push(IpAddr::V6(Ipv6Addr::from(network + i)));
    }
    Ok(ips)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_cidr_single_host_v4() {
        let ips = parse_cidr("127.0.0.1/32").expect("valid /32");
        assert_eq!(ips, vec![IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))]);
    }

    #[test]
    fn parse_cidr_strips_network_and_broadcast() {
        let ips = parse_cidr("192.168.1.0/30").expect("valid /30");
        // /30 has 4 addresses: .0 .1 .2 .3 — keep only .1 and .2
        assert_eq!(
            ips,
            vec![
                IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
                IpAddr::V4(Ipv4Addr::new(192, 168, 1, 2)),
            ],
        );
    }

    #[test]
    fn parse_cidr_two_address_block_keeps_both() {
        // /31 has 2 addresses; both kept (point-to-point links per RFC 3021).
        let ips = parse_cidr("10.0.0.0/31").expect("valid /31");
        assert_eq!(ips.len(), 2);
    }

    #[test]
    fn parse_cidr_invalid_returns_error() {
        let err = parse_cidr("invalid").expect_err("must fail");
        assert!(matches!(err, NetworkScanError::InvalidCidr(_)));
    }

    #[test]
    fn parse_cidr_invalid_prefix_returns_error() {
        let err = parse_cidr("10.0.0.0/40").expect_err("prefix > 32");
        assert!(matches!(err, NetworkScanError::InvalidCidr(_)));
    }

    #[test]
    fn parse_cidr_v6_single_host() {
        let ips = parse_cidr("::1/128").expect("valid /128");
        assert_eq!(ips, vec![IpAddr::V6(Ipv6Addr::LOCALHOST)]);
    }
}
