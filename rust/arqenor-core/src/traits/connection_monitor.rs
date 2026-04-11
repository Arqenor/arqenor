use async_trait::async_trait;
use std::collections::HashSet;
use tokio::sync::mpsc::Sender;

use crate::{error::ArqenorError, models::connection::ConnectionInfo};

/// Unique key for deduplicating connections between polling cycles.
type ConnKey = (String, Option<String>, u32); // (local_addr, remote_addr, pid)

fn conn_key(c: &ConnectionInfo) -> ConnKey {
    (c.local_addr.clone(), c.remote_addr.clone(), c.pid)
}

#[async_trait]
pub trait ConnectionMonitor: Send + Sync {
    /// Returns a point-in-time snapshot of all active TCP/UDP connections,
    /// each annotated with the owning process PID.
    async fn snapshot(&self) -> Result<Vec<ConnectionInfo>, ArqenorError>;

    /// Watch for new connections at a polling interval.
    ///
    /// Default implementation polls [`snapshot()`](Self::snapshot) every
    /// `interval_ms` milliseconds and sends connections not seen in the
    /// previous snapshot on `tx`.
    async fn watch(
        &self,
        tx: Sender<ConnectionInfo>,
        interval_ms: u64,
    ) -> Result<(), ArqenorError> {
        // Default: not supported — platform implementations override this.
        let _ = (tx, interval_ms);
        Err(ArqenorError::NotSupported)
    }
}

/// Spawn a polling loop that calls `snapshot()` at `interval_ms` and sends
/// newly observed connections on `tx`.  Shared by all platform implementations
/// so each one gets dedup-aware polling for free.
///
/// Returns immediately; the polling happens in a `tokio::spawn`'d task.
pub fn spawn_polling_watch(
    monitor: Box<dyn ConnectionMonitor>,
    tx: Sender<ConnectionInfo>,
    interval_ms: u64,
) {
    tokio::spawn(async move {
        let mut seen: HashSet<ConnKey> = HashSet::new();
        let interval = std::time::Duration::from_millis(interval_ms);

        loop {
            match monitor.snapshot().await {
                Ok(conns) => {
                    let mut current: HashSet<ConnKey> = HashSet::with_capacity(conns.len());

                    for conn in conns {
                        let key = conn_key(&conn);
                        current.insert(key.clone());

                        // Only send connections we haven't seen in the previous cycle.
                        if !seen.contains(&key) && tx.send(conn).await.is_err() {
                            // Receiver dropped — stop polling.
                            return;
                        }
                    }

                    // Replace the seen set so connections that disappear and
                    // reappear are detected again.
                    seen = current;
                }
                Err(e) => {
                    tracing::warn!("connection snapshot failed: {e}");
                }
            }

            tokio::time::sleep(interval).await;
        }
    });
}
