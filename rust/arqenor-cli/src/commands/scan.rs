use anyhow::Result;
use arqenor_platform::{new_persistence_detector, new_process_monitor};
use clap::Args;

#[derive(Args)]
pub struct ScanArgs {
    /// Include process snapshot
    #[arg(long, default_value_t = true)]
    pub host: bool,

    /// Include persistence check
    #[arg(long, default_value_t = true)]
    pub persistence: bool,

    /// Output as JSON instead of human-readable
    #[arg(long)]
    pub json: bool,
}

pub async fn run(args: ScanArgs) -> Result<()> {
    if args.host {
        println!("[ PROCESSES ]");
        let monitor = new_process_monitor();
        let snapshot = monitor.snapshot().await?;

        if args.json {
            println!("{}", serde_json::to_string_pretty(&snapshot)?);
        } else {
            println!("{:<8} {:<8} {:<35} PATH", "PID", "PPID", "NAME");
            println!("{}", "-".repeat(90));
            for p in &snapshot {
                println!(
                    "{:<8} {:<8} {:<35} {}",
                    p.pid,
                    p.ppid,
                    &p.name,
                    p.exe_path.as_deref().unwrap_or("-"),
                );
            }
            println!("\n{} processes found.", snapshot.len());
        }
    }

    if args.persistence {
        println!("\n[ PERSISTENCE ]");
        let detector = new_persistence_detector();
        let entries = detector.detect().await?;

        if args.json {
            println!("{}", serde_json::to_string_pretty(&entries)?);
        } else if entries.is_empty() {
            println!("  No persistence entries found.");
        } else {
            for e in &entries {
                println!("  [{:?}] {} → {}", e.kind, e.name, e.command);
                println!("    @ {}", e.location);
            }
        }
    }

    Ok(())
}
