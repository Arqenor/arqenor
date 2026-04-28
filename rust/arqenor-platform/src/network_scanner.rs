use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use tokio::io::AsyncReadExt;
use tokio::net::{lookup_host, TcpStream};
use tokio::sync::{mpsc, Semaphore};
use tokio::time::timeout;

use arqenor_core::traits::network_scanner::{
    parse_cidr, HostResult, NetworkScanError, NetworkScanner, PortResult, ScanRequest,
    DEFAULT_PORT_TIMEOUT,
};

use crate::services::{extract_version_from_banner, well_known_service};

const DEFAULT_WORKER_COUNT: usize = 256;
const PER_HOST_PORT_CONCURRENCY: usize = 64;
const HOST_PROBE_PORTS: &[u16] = &[80, 443, 22, 3389];
const RESULT_CHANNEL_CAPACITY: usize = 32;
const BANNER_BUFFER_BYTES: usize = 256;
const BANNER_READ_TIMEOUT: Duration = Duration::from_millis(500);

#[derive(Debug, Clone)]
pub struct DefaultNetworkScanner {
    worker_count: usize,
}

impl DefaultNetworkScanner {
    pub fn new() -> Self {
        Self {
            worker_count: DEFAULT_WORKER_COUNT,
        }
    }

    pub fn with_worker_count(worker_count: usize) -> Self {
        Self {
            worker_count: worker_count.max(1),
        }
    }
}

impl Default for DefaultNetworkScanner {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl NetworkScanner for DefaultNetworkScanner {
    async fn scan(&self, req: ScanRequest) -> Result<mpsc::Receiver<HostResult>, NetworkScanError> {
        let ips = parse_cidr(&req.cidr)?;
        let (tx, rx) = mpsc::channel(RESULT_CHANNEL_CAPACITY);

        let probe_timeout = if req.timeout.is_zero() {
            DEFAULT_PORT_TIMEOUT
        } else {
            req.timeout
        };
        let host_sem = Arc::new(Semaphore::new(self.worker_count));
        let ports = Arc::new(req.ports);
        let service_detect = req.service_detect;

        tokio::spawn(async move {
            let mut handles = Vec::with_capacity(ips.len());
            for ip in ips {
                let permit_sem = Arc::clone(&host_sem);
                let ports = Arc::clone(&ports);
                let tx = tx.clone();

                let permit = match permit_sem.acquire_owned().await {
                    Ok(p) => p,
                    Err(e) => {
                        tracing::warn!("network_scanner: semaphore closed: {e}");
                        break;
                    }
                };

                let handle = tokio::spawn(async move {
                    let _permit = permit;
                    if let Some(result) = scan_host(ip, &ports, probe_timeout, service_detect).await
                    {
                        let _ = tx.send(result).await;
                    }
                });
                handles.push(handle);
            }

            for h in handles {
                let _ = h.await;
            }
            drop(tx);
        });

        Ok(rx)
    }
}

async fn scan_host(
    ip: IpAddr,
    ports: &[u16],
    probe_timeout: Duration,
    service_detect: bool,
) -> Option<HostResult> {
    if !host_is_up(ip, probe_timeout).await {
        return None;
    }

    let hostname = reverse_dns(ip).await;
    let mac_addr = arp_lookup(&ip.to_string()).await.unwrap_or_default();
    let open_ports = if ports.is_empty() {
        Vec::new()
    } else {
        scan_ports(ip, ports, probe_timeout, service_detect).await
    };

    Some(HostResult {
        ip: ip.to_string(),
        hostname,
        mac_addr,
        is_up: true,
        open_ports,
    })
}

async fn host_is_up(ip: IpAddr, probe_timeout: Duration) -> bool {
    for &port in HOST_PROBE_PORTS {
        let addr = SocketAddr::new(ip, port);
        match timeout(probe_timeout, TcpStream::connect(addr)).await {
            Ok(Ok(_stream)) => return true,
            Ok(Err(_)) | Err(_) => continue,
        }
    }
    false
}

async fn reverse_dns(ip: IpAddr) -> String {
    // tokio::net::lookup_host is forward-only (getaddrinfo). Tokio has no
    // async PTR helper in std and we deliberately avoid pulling in
    // `trust-dns` / `hickory` here — Phase 2 will revisit this once the
    // network stack grows a real resolver. For now we exercise the path
    // (so the call site is wired) and return whatever string answer the
    // resolver yields, swallowing any error (best-effort).
    let target = format!("{ip}:0");
    match lookup_host(target).await {
        Ok(mut iter) => iter
            .next()
            .map(|sock| sock.ip().to_string())
            .filter(|h| h != &ip.to_string())
            .unwrap_or_default(),
        Err(_) => String::new(),
    }
}

async fn scan_ports(
    ip: IpAddr,
    ports: &[u16],
    probe_timeout: Duration,
    service_detect: bool,
) -> Vec<PortResult> {
    let sem = Arc::new(Semaphore::new(PER_HOST_PORT_CONCURRENCY));
    let mut handles = Vec::with_capacity(ports.len());

    for &port in ports {
        let permit_sem = Arc::clone(&sem);
        let permit = match permit_sem.acquire_owned().await {
            Ok(p) => p,
            Err(e) => {
                tracing::warn!("network_scanner: port semaphore closed: {e}");
                break;
            }
        };
        handles.push(tokio::spawn(async move {
            let _permit = permit;
            probe_port(ip, port, probe_timeout, service_detect).await
        }));
    }

    let mut results = Vec::new();
    for h in handles {
        match h.await {
            Ok(Some(pr)) => results.push(pr),
            Ok(None) => {}
            Err(e) => tracing::warn!("network_scanner: port task join failed: {e}"),
        }
    }
    results
}

async fn probe_port(
    ip: IpAddr,
    port: u16,
    probe_timeout: Duration,
    service_detect: bool,
) -> Option<PortResult> {
    let addr = SocketAddr::new(ip, port);
    let stream = match timeout(probe_timeout, TcpStream::connect(addr)).await {
        Ok(Ok(s)) => s,
        Ok(Err(_)) | Err(_) => return None,
    };

    let banner = grab_banner(stream).await;

    let (service, version) = if service_detect {
        let svc = well_known_service(port).unwrap_or("").to_string();
        let ver = extract_version_from_banner(&banner);
        (svc, ver)
    } else {
        (String::new(), String::new())
    };

    Some(PortResult {
        port,
        proto: "tcp".to_string(),
        state: "open".to_string(),
        service,
        banner,
        version,
    })
}

async fn grab_banner(mut stream: TcpStream) -> String {
    let mut buf = vec![0u8; BANNER_BUFFER_BYTES];
    match timeout(BANNER_READ_TIMEOUT, stream.read(&mut buf)).await {
        Ok(Ok(n)) if n > 0 => String::from_utf8_lossy(&buf[..n]).into_owned(),
        _ => String::new(),
    }
}

pub fn new_network_scanner() -> impl NetworkScanner {
    DefaultNetworkScanner::new()
}

// ---------------------------------------------------------------------------
// ARP / MAC discovery — best-effort, cache-only, no raw sockets.
//
// Reads the system's existing ARP cache. Phase 1 scan probes (TCP connects
// during `host_is_up`) populate that cache as a side-effect, so calling
// `arp_lookup` *after* a successful probe usually yields a hit on the same
// L2 segment. Hosts behind a router show the router's MAC (or nothing).
// ---------------------------------------------------------------------------

/// Look up the MAC address for `ip` in the local ARP cache.
///
/// Returns `None` if the entry is missing or the OS query failed. This is
/// best-effort — never error-propagating, never blocking on network I/O.
pub async fn arp_lookup(ip: &str) -> Option<String> {
    cfg_if::cfg_if! {
        if #[cfg(target_os = "windows")] {
            arp_lookup_windows(ip).await
        } else if #[cfg(target_os = "linux")] {
            arp_lookup_linux(ip).await
        } else if #[cfg(target_os = "macos")] {
            arp_lookup_macos(ip).await
        } else {
            let _ = ip;
            None
        }
    }
}

#[cfg(target_os = "linux")]
async fn arp_lookup_linux(ip: &str) -> Option<String> {
    match tokio::fs::read_to_string("/proc/net/arp").await {
        Ok(content) => parse_proc_arp(&content, ip),
        Err(e) => {
            tracing::warn!("arp_lookup: /proc/net/arp unavailable: {e}");
            None
        }
    }
}

/// Parse the textual `/proc/net/arp` table and return the MAC for
/// `target_ip` if present. Pure function — exposed for tests.
///
/// Expected format (whitespace-separated columns, one header line):
/// ```text
/// IP address       HW type     Flags       HW address            Mask     Device
/// 192.168.1.1      0x1         0x2         aa:bb:cc:dd:ee:ff     *        eth0
/// ```
pub fn parse_proc_arp(content: &str, target_ip: &str) -> Option<String> {
    for (idx, line) in content.lines().enumerate() {
        if idx == 0 {
            continue;
        }
        let mut cols = line.split_whitespace();
        let ip = cols.next()?;
        if ip != target_ip {
            continue;
        }
        let _hw_type = cols.next()?;
        let _flags = cols.next()?;
        let mac = cols.next()?;
        if mac == "00:00:00:00:00:00" {
            return None;
        }
        return Some(mac.to_string());
    }
    None
}

#[cfg(target_os = "macos")]
async fn arp_lookup_macos(ip: &str) -> Option<String> {
    use tokio::process::Command;

    let fut = Command::new("arp").arg("-an").arg(ip).output();
    let output = match timeout(Duration::from_secs(1), fut).await {
        Ok(Ok(o)) => o,
        Ok(Err(e)) => {
            tracing::warn!("arp_lookup: arp(8) spawn failed: {e}");
            return None;
        }
        Err(_) => {
            tracing::warn!("arp_lookup: arp(8) timed out");
            return None;
        }
    };

    if !output.status.success() {
        return None;
    }
    let text = String::from_utf8_lossy(&output.stdout);
    parse_arp_an_output(&text)
}

#[cfg(target_os = "macos")]
fn parse_arp_an_output(text: &str) -> Option<String> {
    // Sample: `? (192.168.1.1) at aa:bb:cc:dd:ee:ff on en0 ifscope [ethernet]`
    for line in text.lines() {
        let after_at = match line.split(" at ").nth(1) {
            Some(v) => v,
            None => continue,
        };
        let mac = after_at.split_whitespace().next()?;
        if mac == "(incomplete)" {
            continue;
        }
        return Some(normalize_mac(mac));
    }
    None
}

#[cfg(target_os = "macos")]
fn normalize_mac(raw: &str) -> String {
    // macOS prints single-digit groups (`a:b:c:1:2:3`); pad each octet.
    raw.split(':')
        .map(|seg| {
            if seg.len() == 1 {
                format!("0{seg}")
            } else {
                seg.to_string()
            }
        })
        .collect::<Vec<_>>()
        .join(":")
}

#[cfg(target_os = "windows")]
async fn arp_lookup_windows(ip: &str) -> Option<String> {
    let target: std::net::Ipv4Addr = ip.parse().ok()?;
    let target_be = u32::from(target).to_be();

    tokio::task::spawn_blocking(move || query_ipnet_table(target_be))
        .await
        .ok()
        .flatten()
}

#[cfg(target_os = "windows")]
fn query_ipnet_table(target_be: u32) -> Option<String> {
    use windows::Win32::NetworkManagement::IpHelper::{
        GetIpNetTable, MIB_IPNETROW_LH, MIB_IPNETTABLE,
    };

    unsafe {
        let mut size: u32 = 0;
        let _ = GetIpNetTable(None, &mut size, false);
        if size == 0 {
            return None;
        }

        let mut buf = vec![0u8; size as usize];
        let ret = GetIpNetTable(
            Some(buf.as_mut_ptr() as *mut MIB_IPNETTABLE),
            &mut size,
            false,
        );
        if ret != 0 {
            tracing::warn!("arp_lookup: GetIpNetTable returned {ret}");
            return None;
        }

        let table = &*(buf.as_ptr() as *const MIB_IPNETTABLE);
        let count = table.dwNumEntries as usize;
        for i in 0..count {
            let row: &MIB_IPNETROW_LH = &*table.table.as_ptr().add(i);
            if row.dwAddr != target_be {
                continue;
            }
            let len = row.dwPhysAddrLen as usize;
            if len == 0 {
                return None;
            }
            let len = len.min(row.bPhysAddr.len());
            return Some(format_mac(&row.bPhysAddr[..len]));
        }
        None
    }
}

#[cfg(target_os = "windows")]
fn format_mac(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .join(":")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn scan_localhost_completes_cleanly() {
        let scanner = DefaultNetworkScanner::with_worker_count(4);
        let req = ScanRequest {
            cidr: "127.0.0.1/32".to_string(),
            ports: vec![22, 80, 443, 65530],
            timeout: Duration::from_millis(200),
            service_detect: false,
        };

        let mut rx = scanner.scan(req).await.expect("scan kicks off");

        // Drain until producer side hangs up; do not assert on count
        // (depends on which services happen to listen on the runner).
        let mut received = 0usize;
        while let Some(_host) = rx.recv().await {
            received += 1;
        }
        // Stream closes cleanly even with no live host.
        assert!(received <= 1);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn invalid_cidr_propagates_error() {
        let scanner = DefaultNetworkScanner::new();
        let err = scanner
            .scan(ScanRequest {
                cidr: "not-a-cidr".to_string(),
                ports: vec![],
                timeout: Duration::from_millis(50),
                service_detect: false,
            })
            .await
            .expect_err("must fail");
        assert!(matches!(err, NetworkScanError::InvalidCidr(_)));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn worker_count_is_configurable() {
        let scanner = DefaultNetworkScanner::with_worker_count(7);
        assert_eq!(scanner.worker_count, 7);
    }

    #[test]
    fn parse_proc_arp_extracts_mac() {
        let sample = "IP address       HW type     Flags       HW address            Mask     Device\n\
                      192.168.1.1      0x1         0x2         aa:bb:cc:dd:ee:ff     *        eth0\n\
                      192.168.1.2      0x1         0x2         11:22:33:44:55:66     *        eth0\n";
        assert_eq!(
            parse_proc_arp(sample, "192.168.1.1"),
            Some("aa:bb:cc:dd:ee:ff".to_string())
        );
        assert_eq!(
            parse_proc_arp(sample, "192.168.1.2"),
            Some("11:22:33:44:55:66".to_string())
        );
    }

    #[test]
    fn parse_proc_arp_skips_zero_mac() {
        // Stale entry with zeroed MAC must not surface as a valid hit.
        let sample = "IP address       HW type     Flags       HW address            Mask     Device\n\
                      192.168.1.99     0x1         0x0         00:00:00:00:00:00     *        eth0\n";
        assert_eq!(parse_proc_arp(sample, "192.168.1.99"), None);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn arp_lookup_returns_none_on_missing_ip() {
        // 240.0.0.1 sits in 240.0.0.0/4 (RFC 1112 reserved future use) — should
        // never appear in a real ARP cache.
        assert_eq!(arp_lookup("240.0.0.1").await, None);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[ignore]
    async fn arp_lookup_works() {
        // Requires a populated ARP cache; not asserted in CI.
        let _ = arp_lookup("192.168.1.1").await;
    }
}
