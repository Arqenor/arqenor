mod commands;

use anyhow::Result;
use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(
    name    = "arqenor",
    about   = "ARQENOR — cross-platform host & network security analyzer",
    version = env!("CARGO_PKG_VERSION"),
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Scan host: processes, filesystem, persistence
    Scan(commands::scan::ScanArgs),
    /// Watch mode: continuous monitoring
    Watch(commands::watch::WatchArgs),
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive("arqenor=debug".parse()?)
                .add_directive("warn".parse()?),
        )
        .init();

    let cli = Cli::parse();

    match cli.command {
        Commands::Scan(args) => commands::scan::run(args).await,
        Commands::Watch(args) => commands::watch::run(args).await,
    }
}
