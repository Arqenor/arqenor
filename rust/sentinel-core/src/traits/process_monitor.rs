use async_trait::async_trait;
use tokio::sync::mpsc::Sender;

use crate::{
    error::SentinelError,
    models::process::{ProcessEvent, ProcessInfo},
};

#[async_trait]
pub trait ProcessMonitor: Send + Sync {
    /// Snapshot of all currently running processes.
    async fn snapshot(&self) -> Result<Vec<ProcessInfo>, SentinelError>;

    /// Stream live process create/terminate events.
    /// Sends events on `tx` until the channel is dropped or an error occurs.
    async fn watch(&self, tx: Sender<ProcessEvent>) -> Result<(), SentinelError>;

    /// Enrich a process by PID (parent chain, hash, loaded modules).
    async fn enrich(&self, pid: u32) -> Result<ProcessInfo, SentinelError>;
}
