mod server;

// Module names MUST match what prost-build generates for cross-proto references.
// sentinel.network references `super::super::common::Alert`, so the module must
// be named `common` at the crate root.
pub mod common {
    tonic::include_proto!("sentinel.common");
}

pub mod host {
    tonic::include_proto!("sentinel.host");
}

pub mod network {
    tonic::include_proto!("sentinel.network");
}

use anyhow::Result;
use tracing::info;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive("sentinel_grpc=debug".parse()?)
                .add_directive("info".parse()?),
        )
        .init();

    let addr = "127.0.0.1:50051".parse()?;
    info!("sentinel-grpc starting on {addr}");

    let host_svc = server::host_analyzer::HostAnalyzerService::new();

    tonic::transport::Server::builder()
        .add_service(host::host_analyzer_server::HostAnalyzerServer::new(host_svc))
        .serve(addr)
        .await?;

    Ok(())
}
