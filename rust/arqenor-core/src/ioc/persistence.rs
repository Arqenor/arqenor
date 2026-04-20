//! Persistence abstraction for the IOC database.
//!
//! The [`IocPersistence`] trait lets callers (CLI, gRPC server, Tauri desktop)
//! plug in a durable store — typically the SQLite store from the
//! `arqenor-store` crate — so that IOCs loaded from abuse.ch feeds survive
//! across restarts and remain available when the network is unreachable.
//!
//! The trait is intentionally minimal and synchronous.  All persistence
//! implementations are expected to be cheap (SQLite on local disk); async is
//! unnecessary and would complicate the fetch-then-persist pipeline in
//! [`feeds`].
//!
//! # Flow
//!
//! 1. At boot, the caller invokes [`load_from_store`] to warm the in-memory
//!    [`IocDatabase`] from persisted feeds.  This is instant and works
//!    offline.
//! 2. The caller then triggers a refresh via
//!    [`feeds::refresh_all_feeds_with_persist`] which consults
//!    `last_modified` / `etag` headers on each feed.  Only feeds whose
//!    upstream payload has changed are re-downloaded and their in-store IOC
//!    rows are replaced atomically.
//!
//! [`feeds`]: super::feeds
//! [`feeds::refresh_all_feeds_with_persist`]:
//!     super::feeds::refresh_all_feeds_with_persist

use chrono::{DateTime, Utc};
use thiserror::Error;

use super::{IocDatabase, IocEntry};

/// Errors returned by an [`IocPersistence`] implementation.
///
/// Implementers should map their underlying storage errors into either
/// [`PersistenceError::Storage`] (opaque) or construct a more specific variant
/// in the future.  The IOC refresh pipeline always treats persistence errors
/// as non-fatal and falls back to in-memory-only operation.
#[derive(Debug, Error)]
pub enum PersistenceError {
    /// Opaque error from the backing store (SQLite, etc.).
    #[error("persistence storage error: {0}")]
    Storage(String),

    /// Serialisation of metadata (tags, etc.) failed.
    #[error("persistence serialization error: {0}")]
    Serialization(String),
}

/// HTTP conditional-GET metadata recorded for a feed so the next refresh can
/// skip the download when the upstream payload has not changed.
///
/// At least one of `etag` or `last_modified` is typically set by abuse.ch
/// endpoints.  If both are `None`, the refresh logic falls back to an
/// unconditional GET.
#[derive(Debug, Clone, Default)]
pub struct FeedMeta {
    /// Feed identifier — must be stable across versions.  Matches the
    /// `source` field of [`IocEntry`] (e.g. `"abuse.ch/malwarebazaar"`).
    pub name: String,
    /// The feed's download URL.  Stored for operator diagnostics.
    pub source_url: String,
    /// Last `ETag` header value returned by the feed, if any.
    pub etag: Option<String>,
    /// Last `Last-Modified` header value returned by the feed, if any.
    pub last_modified: Option<String>,
    /// Wall-clock time the feed was last successfully refreshed.
    pub fetched_at: DateTime<Utc>,
}

/// Durable persistence for IOC feeds and entries.
///
/// Implementations live outside `arqenor-core` (the canonical one is
/// `arqenor_store::IocSqliteStore`) to keep the core crate free of storage
/// dependencies.
pub trait IocPersistence: Send + Sync {
    /// Fetch the stored metadata for a feed.  Returns `Ok(None)` when the
    /// feed has never been persisted.
    fn get_feed_meta(&self, name: &str) -> Result<Option<FeedMeta>, PersistenceError>;

    /// Record (or update) the HTTP caching metadata for a feed.
    fn upsert_feed_meta(&self, meta: &FeedMeta) -> Result<(), PersistenceError>;

    /// Atomically replace all IOC rows for a feed with the supplied entries.
    ///
    /// Implementations must run this inside a single transaction so readers
    /// never observe a partially-updated feed.  Entries whose `source` field
    /// differs from `feed` are silently accepted — the caller is trusted to
    /// group entries correctly.
    fn replace_feed_iocs(&self, feed: &str, entries: &[IocEntry]) -> Result<(), PersistenceError>;

    /// Iterate every IOC row across every feed and feed them to `sink`.
    ///
    /// Used at boot to rebuild the in-memory [`IocDatabase`].  The sink
    /// callback is invoked once per row; implementations should stream rows
    /// rather than buffer the whole dataset.
    fn load_all(&self, sink: &mut dyn FnMut(IocEntry)) -> Result<usize, PersistenceError>;
}

/// Populate `db` from `store` — the offline-ready boot path.
///
/// Returns the number of entries loaded.  On persistence error the in-memory
/// database is left untouched and the error is returned to the caller, who
/// typically logs it and falls back to a network refresh.
pub fn load_from_store(
    store: &dyn IocPersistence,
    db: &mut IocDatabase,
) -> Result<usize, PersistenceError> {
    let mut count = 0usize;
    let mut latest: Option<DateTime<Utc>> = None;
    store.load_all(&mut |entry| {
        let ts = entry.added_at;
        latest = Some(latest.map_or(ts, |l| l.max(ts)));
        db.add(entry);
        count += 1;
    })?;
    if latest.is_some() {
        db.last_updated = latest;
    }
    tracing::info!(count, "IOC database warmed from persistent store");
    Ok(count)
}
