use std::time::Duration;

// Module names match what prost-build generates for cross-proto references.
// `sentinel.host` references `super::super::common::Alert` (two levels up from
// `host_analyzer_client` → `host` module → crate root), so `common` must live
// as a sibling of `host` at this module's root.
pub mod common {
    tonic::include_proto!("sentinel.common");
}

pub mod host {
    tonic::include_proto!("sentinel.host");
}

/// The protobuf Alert type from `sentinel.common`.
pub type ProtoAlert = common::Alert;

/// The generated gRPC client for the HostAnalyzer service.
pub use host::host_analyzer_client::HostAnalyzerClient;

/// Drives a persistent alert stream from `sentinel-grpc` on `127.0.0.1:50051`.
///
/// Loops forever, reconnecting every 3 seconds on error.  Returns only when
/// `tx` is closed (i.e. the TUI has shut down and dropped the receiver).
pub async fn stream_alerts(tx: tokio::sync::mpsc::Sender<ProtoAlert>) {
    loop {
        if let Err(e) = try_stream_alerts(&tx).await {
            tracing::warn!("alert stream error: {e:#}, reconnecting in 3s");
        }
        if tx.is_closed() {
            break;
        }
        tokio::time::sleep(Duration::from_secs(3)).await;
    }
}

/// Connects to `sentinel-grpc`, calls `WatchAlerts`, and forwards every
/// received [`ProtoAlert`] to `tx` until the stream ends or `tx` is closed.
async fn try_stream_alerts(
    tx: &tokio::sync::mpsc::Sender<ProtoAlert>,
) -> anyhow::Result<()> {
    let mut client = HostAnalyzerClient::connect("http://127.0.0.1:50051").await?;
    let mut stream = client
        .watch_alerts(tonic::Request::new(()))
        .await?
        .into_inner();

    while let Some(alert) = stream.message().await? {
        if tx.send(alert).await.is_err() {
            break;
        }
    }

    Ok(())
}
