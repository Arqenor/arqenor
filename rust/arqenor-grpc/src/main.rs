mod limits;
mod server;

// Module names MUST match what prost-build generates for cross-proto references.
// arqenor.network references `super::super::common::Alert`, so the module must
// be named `common` at the crate root.
pub mod common {
    tonic::include_proto!("arqenor.common");
}

pub mod host {
    tonic::include_proto!("arqenor.host");
}

pub mod network {
    tonic::include_proto!("arqenor.network");
}

use anyhow::Result;
use std::time::Duration;
use tower::limit::ConcurrencyLimitLayer;
use tracing::{info, warn};

use crate::limits::{load_allowed_roots, AllowedRoots};

/// HTTP/2 keepalive — protect server resources from clients that silently
/// disappear (TCP fin lost, mobile NAT eviction, etc.). See finding
/// GRPC-STREAM in the 2026-04 security audit.
const HTTP2_KEEPALIVE_INTERVAL: Duration = Duration::from_secs(30);
const HTTP2_KEEPALIVE_TIMEOUT: Duration = Duration::from_secs(10);

/// Maximum age of an HTTP/2 connection before the server politely cycles it.
/// Bounds the blast radius of a stuck client without disrupting healthy long
/// streams (which simply reconnect).
const MAX_CONNECTION_AGE: Duration = Duration::from_secs(3600);
const MAX_CONNECTION_AGE_GRACE: Duration = Duration::from_secs(60);

/// Per-RPC timeout for *unary* requests. Streaming RPCs are not bounded by
/// this — they're protected by the keepalive/age settings above.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(300);

/// Global concurrency cap across all in-flight RPCs (Tower middleware).
/// Prevents a single client from monopolising the engine with thousands of
/// parallel `ScanFilesystem` calls. See finding GRPC-RATE.
///
/// Tower's `RateLimit` (req/sec) is intentionally *not* wired in: in
/// `tower 0.5`, `RateLimit<S>` does not implement `Clone`, which Tonic
/// requires to spawn the service across connections. A concurrency cap
/// covers the same DoS vector for our threat model — the orchestrator
/// is the only legitimate caller and never bursts above this ceiling.
const CONCURRENCY_LIMIT: usize = 64;

/// Soft per-connection cap on concurrent HTTP/2 streams. Combined with
/// [`CONCURRENCY_LIMIT`], this puts a hard ceiling on parallel work per
/// client.
const MAX_CONCURRENT_STREAMS: u32 = 128;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive("arqenor_grpc=debug".parse()?)
                .add_directive("info".parse()?),
        )
        .init();

    let addr = "127.0.0.1:50051".parse()?;
    info!("arqenor-grpc starting on {addr}");

    // Build the filesystem-scan allowlist once at startup. Failing to
    // canonicalize an entry only logs a warning — we don't refuse to start
    // when, e.g., `/var/log` is missing in a containerised dev box. We do
    // emit a loud warning when no entry survives, since every
    // `ScanFilesystem` call will then be rejected.
    let allowed_roots = AllowedRoots::new(load_allowed_roots());
    if allowed_roots.is_empty() {
        warn!(
            "scan-root allowlist is empty after canonicalization — \
             ScanFilesystem requests will be rejected"
        );
    }

    let host_svc = server::host_analyzer::HostAnalyzerService::new(allowed_roots);

    tonic::transport::Server::builder()
        .http2_keepalive_interval(Some(HTTP2_KEEPALIVE_INTERVAL))
        .http2_keepalive_timeout(Some(HTTP2_KEEPALIVE_TIMEOUT))
        .max_connection_age(MAX_CONNECTION_AGE)
        .max_connection_age_grace(MAX_CONNECTION_AGE_GRACE)
        .timeout(REQUEST_TIMEOUT)
        .max_concurrent_streams(Some(MAX_CONCURRENT_STREAMS))
        .layer(ConcurrencyLimitLayer::new(CONCURRENCY_LIMIT))
        .add_service(host::host_analyzer_server::HostAnalyzerServer::new(
            host_svc,
        ))
        .serve(addr)
        .await?;

    Ok(())
}
