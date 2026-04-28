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
        let _service_detect = req.service_detect;

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
                    if let Some(result) = scan_host(ip, &ports, probe_timeout).await {
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

async fn scan_host(ip: IpAddr, ports: &[u16], probe_timeout: Duration) -> Option<HostResult> {
    if !host_is_up(ip, probe_timeout).await {
        return None;
    }

    let hostname = reverse_dns(ip).await;
    let open_ports = if ports.is_empty() {
        Vec::new()
    } else {
        scan_ports(ip, ports, probe_timeout).await
    };

    Some(HostResult {
        ip: ip.to_string(),
        hostname,
        mac_addr: String::new(),
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

async fn scan_ports(ip: IpAddr, ports: &[u16], probe_timeout: Duration) -> Vec<PortResult> {
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
            probe_port(ip, port, probe_timeout).await
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

async fn probe_port(ip: IpAddr, port: u16, probe_timeout: Duration) -> Option<PortResult> {
    let addr = SocketAddr::new(ip, port);
    let stream = match timeout(probe_timeout, TcpStream::connect(addr)).await {
        Ok(Ok(s)) => s,
        Ok(Err(_)) | Err(_) => return None,
    };

    let banner = grab_banner(stream).await;
    Some(PortResult {
        port,
        proto: "tcp".to_string(),
        state: "open".to_string(),
        service: String::new(),
        banner,
        version: String::new(),
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
}
