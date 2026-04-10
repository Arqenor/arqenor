use async_trait::async_trait;
use tokio::sync::mpsc::Sender;

use crate::{
    error::SentinelError,
    models::connection::ConnectionInfo,
};

#[async_trait]
pub trait ConnectionMonitor: Send + Sync {
    /// Returns a point-in-time snapshot of all active TCP/UDP connections,
    /// each annotated with the owning process PID.
    async fn snapshot(&self) -> Result<Vec<ConnectionInfo>, SentinelError>;

    /// Watch for new connections at a polling interval.
    ///
    /// Default implementation polls [`snapshot()`](Self::snapshot) every
    /// `interval_ms` milliseconds and sends connections not seen in the
    /// previous snapshot on `tx`.
    async fn watch(
        &self,
        tx: Sender<ConnectionInfo>,
        interval_ms: u64,
    ) -> Result<(), SentinelError> {
        // Default: not supported — platform implementations override this.
        let _ = (tx, interval_ms);
        Err(SentinelError::NotSupported)
    }
}
