use std::sync::Arc;
use std::time::Duration;

use tokio::sync::{broadcast, mpsc};
use tokio_stream::wrappers::ReceiverStream;
use tonic::{Request, Response, Status};

use arqenor_core::traits::network_scanner::{
    parse_cidr, HostResult as CoreHostResult, NetworkScanError, NetworkScanner,
    PortResult as CorePortResult, ScanRequest as CoreScanRequest,
};

use crate::common;
use crate::limits::sanitize_meta_value;
use crate::network::{
    network_scanner_server::NetworkScanner as NetworkScannerSvc, HostResult as ProtoHostResult,
    PortResult as ProtoPortResult, ScanTarget,
};

/// Hard cap on enumerated hosts per scan request. /16 in IPv4 = 65 536 hosts;
/// any larger range is rejected as a DoS guard.
const MAX_HOSTS_PER_SCAN: usize = 65_536;
const DEFAULT_TIMEOUT_MS: u64 = 2_000;
const STREAM_CHANNEL_CAPACITY: usize = 32;

pub struct NetworkScannerService {
    scanner: Arc<dyn NetworkScanner>,
    /// Optional fan-out channel into the host-analyzer alert stream. When
    /// present, `report_anomaly` publishes sanitized alerts here so every
    /// live `WatchAlerts` subscriber sees them. `None` keeps `report_anomaly`
    /// as a logging stub (useful for tests and for orchestrators that don't
    /// host the analyzer service).
    alert_broadcast: Option<broadcast::Sender<common::Alert>>,
}

impl NetworkScannerService {
    pub fn new(
        scanner: Arc<dyn NetworkScanner>,
        alert_broadcast: Option<broadcast::Sender<common::Alert>>,
    ) -> Self {
        Self {
            scanner,
            alert_broadcast,
        }
    }
}

/// Sanitize every externally-supplied string field in a proto Alert before it
/// crosses back into the system. Mirrors `core_alert_to_proto` in
/// `host_analyzer.rs` — see finding GRPC-METADATA.
fn sanitize_external_alert(mut alert: common::Alert) -> common::Alert {
    alert.message = sanitize_meta_value(&alert.message);
    alert.kind = sanitize_meta_value(&alert.kind);
    alert.rule_id = sanitize_meta_value(&alert.rule_id);
    alert.attack_id = sanitize_meta_value(&alert.attack_id);
    alert.metadata = alert
        .metadata
        .into_iter()
        .map(|(k, v)| (k, sanitize_meta_value(&v)))
        .collect();
    alert
}

fn core_port_to_proto(p: CorePortResult) -> ProtoPortResult {
    ProtoPortResult {
        port: u32::from(p.port),
        proto: p.proto,
        state: p.state,
        service: p.service,
        banner: p.banner,
        version: p.version,
    }
}

fn core_host_to_proto(h: CoreHostResult) -> ProtoHostResult {
    ProtoHostResult {
        ip: h.ip,
        hostname: h.hostname,
        mac_addr: h.mac_addr,
        is_up: h.is_up,
        open_ports: h.open_ports.into_iter().map(core_port_to_proto).collect(),
    }
}

#[tonic::async_trait]
impl NetworkScannerSvc for NetworkScannerService {
    type StartScanStream = ReceiverStream<Result<ProtoHostResult, Status>>;

    async fn start_scan(
        &self,
        req: Request<ScanTarget>,
    ) -> Result<Response<Self::StartScanStream>, Status> {
        let target = req.into_inner();
        let cidr = target.cidr.trim();
        if cidr.is_empty() {
            return Err(Status::invalid_argument("cidr is required"));
        }

        let ips = parse_cidr(cidr).map_err(map_parse_error)?;
        if ips.len() > MAX_HOSTS_PER_SCAN {
            return Err(Status::invalid_argument(format!(
                "CIDR too large ({} hosts, max {MAX_HOSTS_PER_SCAN}); consider /16 or smaller",
                ips.len(),
            )));
        }

        let timeout_ms = if target.timeout_ms == 0 {
            DEFAULT_TIMEOUT_MS
        } else {
            u64::from(target.timeout_ms)
        };

        let ports: Vec<u16> = target
            .ports
            .into_iter()
            .filter_map(|p| u16::try_from(p).ok())
            .collect();

        let core_req = CoreScanRequest {
            cidr: cidr.to_string(),
            ports,
            timeout: Duration::from_millis(timeout_ms),
            service_detect: target.service_detect,
        };

        let mut core_rx = self.scanner.scan(core_req).await.map_err(map_scan_error)?;

        let (tx, rx) = mpsc::channel::<Result<ProtoHostResult, Status>>(STREAM_CHANNEL_CAPACITY);
        tokio::spawn(async move {
            while let Some(host) = core_rx.recv().await {
                if tx.send(Ok(core_host_to_proto(host))).await.is_err() {
                    break;
                }
            }
        });

        Ok(Response::new(ReceiverStream::new(rx)))
    }

    async fn report_anomaly(&self, req: Request<common::Alert>) -> Result<Response<()>, Status> {
        let alert = sanitize_external_alert(req.into_inner());
        tracing::info!(
            alert_id = %alert.id,
            kind = %alert.kind,
            severity = alert.severity,
            "network anomaly reported",
        );
        if let Some(tx) = &self.alert_broadcast {
            // No subscribers is a normal idle state — drop silently. Any other
            // outcome means either lag (already counted by the receiver side)
            // or channel close (the broadcaster outlives the service).
            let _ = tx.send(alert);
        }
        Ok(Response::new(()))
    }
}

fn map_parse_error(e: NetworkScanError) -> Status {
    match e {
        NetworkScanError::InvalidCidr(_) | NetworkScanError::RangeTooLarge(_, _) => {
            Status::invalid_argument(e.to_string())
        }
        other => Status::internal(other.to_string()),
    }
}

fn map_scan_error(e: NetworkScanError) -> Status {
    match e {
        NetworkScanError::InvalidCidr(_) | NetworkScanError::RangeTooLarge(_, _) => {
            Status::invalid_argument(e.to_string())
        }
        other => Status::internal(other.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use arqenor_core::traits::network_scanner::HostResult;

    /// Stub scanner: returns an empty receiver immediately.
    struct StubScanner;

    #[tonic::async_trait]
    impl NetworkScanner for StubScanner {
        async fn scan(
            &self,
            _req: CoreScanRequest,
        ) -> Result<mpsc::Receiver<HostResult>, NetworkScanError> {
            let (tx, rx) = mpsc::channel(1);
            drop(tx); // close immediately
            Ok(rx)
        }
    }

    fn svc() -> NetworkScannerService {
        NetworkScannerService::new(Arc::new(StubScanner), None)
    }

    fn svc_with_broadcast() -> (NetworkScannerService, broadcast::Receiver<common::Alert>) {
        let (tx, rx) = broadcast::channel(8);
        (
            NetworkScannerService::new(Arc::new(StubScanner), Some(tx)),
            rx,
        )
    }

    #[tokio::test]
    async fn rejects_empty_cidr() {
        let resp = svc()
            .start_scan(Request::new(ScanTarget {
                cidr: String::new(),
                timeout_ms: 0,
                ports: vec![],
                service_detect: false,
            }))
            .await;
        let err = resp.expect_err("must reject");
        assert_eq!(err.code(), tonic::Code::InvalidArgument);
    }

    #[tokio::test]
    async fn rejects_invalid_cidr() {
        let resp = svc()
            .start_scan(Request::new(ScanTarget {
                cidr: "not-a-cidr".to_string(),
                timeout_ms: 0,
                ports: vec![],
                service_detect: false,
            }))
            .await;
        let err = resp.expect_err("must reject");
        assert_eq!(err.code(), tonic::Code::InvalidArgument);
    }

    #[tokio::test]
    async fn rejects_overlarge_range() {
        // /8 = 16 777 216 hosts → above MAX_HOSTS_PER_SCAN.
        let resp = svc()
            .start_scan(Request::new(ScanTarget {
                cidr: "10.0.0.0/8".to_string(),
                timeout_ms: 0,
                ports: vec![],
                service_detect: false,
            }))
            .await;
        let err = resp.expect_err("must reject");
        assert_eq!(err.code(), tonic::Code::InvalidArgument);
    }

    #[tokio::test]
    async fn accepts_loopback_and_drains_stream() {
        use tokio_stream::StreamExt;

        let resp = svc()
            .start_scan(Request::new(ScanTarget {
                cidr: "127.0.0.1/32".to_string(),
                timeout_ms: 100,
                ports: vec![],
                service_detect: false,
            }))
            .await
            .expect("rpc returns");
        let mut stream = resp.into_inner();
        // Stub scanner returns no hosts; the stream must close cleanly.
        assert!(stream.next().await.is_none());
    }

    #[tokio::test]
    async fn report_anomaly_returns_empty() {
        let resp = svc()
            .report_anomaly(Request::new(common::Alert {
                id: "test-id".into(),
                severity: common::Severity::Info as i32,
                kind: "test".into(),
                message: "ping".into(),
                occurred_at: None,
                metadata: std::collections::HashMap::new(),
                rule_id: String::new(),
                attack_id: String::new(),
            }))
            .await
            .expect("ok");
        let _: () = resp.into_inner();
    }

    #[tokio::test]
    async fn report_anomaly_broadcasts_sanitized_alert() {
        let (svc, mut rx) = svc_with_broadcast();
        let mut meta = std::collections::HashMap::new();
        // Newline + control char must be stripped by sanitize_meta_value.
        meta.insert("source".into(), "scan\nnoisy\x07".into());

        svc.report_anomaly(Request::new(common::Alert {
            id: "abc".into(),
            severity: common::Severity::High as i32,
            kind: "net.anomaly\n".into(),
            message: "host beaconing\r\n".into(),
            occurred_at: None,
            metadata: meta,
            rule_id: String::new(),
            attack_id: String::new(),
        }))
        .await
        .expect("ok");

        let received = rx.recv().await.expect("broadcast received");
        assert_eq!(received.id, "abc");
        // Newlines and control bytes stripped by sanitize_meta_value.
        assert!(!received.kind.contains('\n'));
        assert!(!received.message.contains('\n'));
        assert!(!received.message.contains('\r'));
        assert!(!received.metadata["source"].contains('\n'));
        assert!(!received.metadata["source"].contains('\x07'));
    }
}
