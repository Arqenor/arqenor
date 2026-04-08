use anyhow::Result;
use clap::Args;

#[derive(Args)]
pub struct WatchArgs {
    /// Interval between scans in seconds
    #[arg(long, default_value_t = 30)]
    pub interval: u64,
}

pub async fn run(args: WatchArgs) -> Result<()> {
    use std::time::Duration;
    use tokio::time;

    println!("Watching — interval {}s. Press Ctrl-C to stop.", args.interval);
    let scan_args = super::scan::ScanArgs {
        host:        true,
        persistence: true,
        json:        false,
    };

    loop {
        println!("\n{}", "=".repeat(60));
        super::scan::run(super::scan::ScanArgs {
            host:        scan_args.host,
            persistence: scan_args.persistence,
            json:        scan_args.json,
        })
        .await?;
        time::sleep(Duration::from_secs(args.interval)).await;
    }
}
