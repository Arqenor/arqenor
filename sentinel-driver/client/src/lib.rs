//! Userspace client for the SENTINEL kernel driver.
//!
//! Connects to the `\SentinelPort` filter communication port and exposes
//! a `tokio` async stream of [`KernelEvent`]s produced by the kernel driver.
//!
//! # Example
//! ```rust,no_run
//! use sentinel_driver_client::DriverClient;
//! use tokio_stream::StreamExt;
//!
//! #[tokio::main]
//! async fn main() -> anyhow::Result<()> {
//!     let client = DriverClient::connect()?;
//!     let mut stream = client.into_event_stream();
//!     while let Some(event) = stream.next().await {
//!         println!("{event:?}");
//!     }
//!     Ok(())
//! }
//! ```

pub use sentinel_driver_common::{KernelEvent, KernelEventKind, KernelMessage};

mod error;
mod recv;

pub use error::ClientError;
pub use recv::DriverClient;
