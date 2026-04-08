use async_trait::async_trait;

use crate::{error::SentinelError, models::persistence::PersistenceEntry};

#[async_trait]
pub trait PersistenceDetector: Send + Sync {
    /// Return all known autorun / startup entries on this platform.
    async fn detect(&self) -> Result<Vec<PersistenceEntry>, SentinelError>;

    /// Compare current entries against a saved baseline.
    /// Returns only entries that are new (not present in `baseline`).
    async fn diff_baseline(
        &self,
        baseline: &[PersistenceEntry],
    ) -> Result<Vec<PersistenceEntry>, SentinelError>;
}
