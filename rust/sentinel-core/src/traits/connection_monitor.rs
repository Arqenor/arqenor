use async_trait::async_trait;

use crate::{
    error::SentinelError,
    models::connection::ConnectionInfo,
};

#[async_trait]
pub trait ConnectionMonitor: Send + Sync {
    /// Returns a point-in-time snapshot of all active TCP/UDP connections,
    /// each annotated with the owning process PID.
    async fn snapshot(&self) -> Result<Vec<ConnectionInfo>, SentinelError>;
}
