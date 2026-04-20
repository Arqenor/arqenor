//! SQLite-backed persistence for IOC feeds.
//!
//! Implements [`arqenor_core::ioc::persistence::IocPersistence`] on top of a
//! `rusqlite::Connection`.  Kept as a separate connection from [`SqliteStore`]
//! (alerts / events) because:
//!
//! * IOC refresh runs from a background Tokio task and can hold the
//!   connection across thousands of inserts — we don't want to starve alert
//!   writers.
//! * The two stores have independent lifetimes (the IOC store is sometimes
//!   skipped entirely — see the `no-ioc` CLI flag).
//!
//! Both files can safely live in the same on-disk directory.
//!
//! # Schema
//!
//! ```sql
//! CREATE TABLE ioc_feeds (
//!     name          TEXT PRIMARY KEY,
//!     source_url    TEXT NOT NULL,
//!     etag          TEXT,
//!     last_modified TEXT,
//!     fetched_at    INTEGER NOT NULL   -- unix seconds
//! );
//! CREATE TABLE iocs (
//!     feed       TEXT NOT NULL,
//!     ioc_type   TEXT NOT NULL,  -- sha256|md5|ipv4|domain|url
//!     value      TEXT NOT NULL,  -- lowercased
//!     source     TEXT NOT NULL,  -- IocEntry.source (usually == feed)
//!     tags       TEXT NOT NULL,  -- JSON array
//!     added_at   INTEGER NOT NULL,
//!     PRIMARY KEY (feed, ioc_type, value),
//!     FOREIGN KEY (feed) REFERENCES ioc_feeds(name) ON DELETE CASCADE
//! );
//! CREATE INDEX idx_iocs_value ON iocs(value);
//! ```
//!
//! The `(feed, ioc_type, value)` primary key guarantees idempotency on
//! reinsertion and lets [`IocSqliteStore::replace_feed_iocs`] use a cheap
//! `DELETE WHERE feed=?` + bulk `INSERT` inside a single transaction.

use std::path::Path;
use std::sync::Mutex;

use arqenor_core::ioc::persistence::{FeedMeta, IocPersistence, PersistenceError};
use arqenor_core::ioc::{IocEntry, IocType};
use chrono::{DateTime, TimeZone, Utc};
use rusqlite::{params, Connection};
use thiserror::Error;

/// Errors raised by [`IocSqliteStore`] during connection setup.
#[derive(Debug, Error)]
pub enum IocStoreError {
    #[error("sqlite: {0}")]
    Sqlite(#[from] rusqlite::Error),
}

const INIT_SQL: &str = r#"
CREATE TABLE IF NOT EXISTS ioc_feeds (
    name          TEXT PRIMARY KEY,
    source_url    TEXT NOT NULL,
    etag          TEXT,
    last_modified TEXT,
    fetched_at    INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS iocs (
    feed       TEXT NOT NULL,
    ioc_type   TEXT NOT NULL,
    value      TEXT NOT NULL,
    source     TEXT NOT NULL,
    tags       TEXT NOT NULL,
    added_at   INTEGER NOT NULL,
    PRIMARY KEY (feed, ioc_type, value),
    FOREIGN KEY (feed) REFERENCES ioc_feeds(name) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_iocs_value ON iocs(value);
"#;

/// SQLite-backed IOC store.
///
/// Internally wraps a `Mutex<Connection>` because `rusqlite::Connection` is
/// `!Sync`, yet the [`IocPersistence`] trait is `Send + Sync` to let callers
/// share one instance across Tokio tasks.  The lock is held only for the
/// duration of each individual query / transaction.
pub struct IocSqliteStore {
    conn: Mutex<Connection>,
}

impl IocSqliteStore {
    /// Open (or create) the SQLite database at `path` and run the idempotent
    /// schema migration.
    pub fn open(path: &Path) -> Result<Self, IocStoreError> {
        let conn = Connection::open(path)?;
        conn.pragma_update(None, "journal_mode", "WAL")?;
        conn.pragma_update(None, "foreign_keys", "ON")?;
        conn.execute_batch(INIT_SQL)?;
        Ok(Self {
            conn: Mutex::new(conn),
        })
    }

    /// Open an in-memory database.  Only useful for tests.
    #[cfg(test)]
    fn open_in_memory() -> Result<Self, IocStoreError> {
        let conn = Connection::open_in_memory()?;
        conn.pragma_update(None, "foreign_keys", "ON")?;
        conn.execute_batch(INIT_SQL)?;
        Ok(Self {
            conn: Mutex::new(conn),
        })
    }
}

// ── Helpers ──────────────────────────────────────────────────────────────────

fn ioc_type_to_str(t: &IocType) -> &'static str {
    match t {
        IocType::Sha256Hash => "sha256",
        IocType::Md5Hash => "md5",
        IocType::Ipv4 => "ipv4",
        IocType::Domain => "domain",
        IocType::Url => "url",
    }
}

fn ioc_type_from_str(s: &str) -> Option<IocType> {
    Some(match s {
        "sha256" => IocType::Sha256Hash,
        "md5" => IocType::Md5Hash,
        "ipv4" => IocType::Ipv4,
        "domain" => IocType::Domain,
        "url" => IocType::Url,
        _ => return None,
    })
}

fn map_sqlite(e: rusqlite::Error) -> PersistenceError {
    PersistenceError::Storage(e.to_string())
}

fn map_json(e: serde_json::Error) -> PersistenceError {
    PersistenceError::Serialization(e.to_string())
}

fn ts_to_i64(ts: DateTime<Utc>) -> i64 {
    ts.timestamp()
}

fn ts_from_i64(secs: i64) -> DateTime<Utc> {
    Utc.timestamp_opt(secs, 0).single().unwrap_or_else(Utc::now)
}

// ── IocPersistence impl ──────────────────────────────────────────────────────

impl IocPersistence for IocSqliteStore {
    fn get_feed_meta(&self, name: &str) -> Result<Option<FeedMeta>, PersistenceError> {
        let conn = self
            .conn
            .lock()
            .map_err(|e| PersistenceError::Storage(format!("ioc store mutex poisoned: {e}")))?;
        let mut stmt = conn
            .prepare(
                "SELECT name, source_url, etag, last_modified, fetched_at
                 FROM ioc_feeds WHERE name = ?1",
            )
            .map_err(map_sqlite)?;

        let row = stmt.query_row(params![name], |row| {
            Ok(FeedMeta {
                name: row.get::<_, String>(0)?,
                source_url: row.get::<_, String>(1)?,
                etag: row.get::<_, Option<String>>(2)?,
                last_modified: row.get::<_, Option<String>>(3)?,
                fetched_at: ts_from_i64(row.get::<_, i64>(4)?),
            })
        });

        match row {
            Ok(m) => Ok(Some(m)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(map_sqlite(e)),
        }
    }

    fn upsert_feed_meta(&self, meta: &FeedMeta) -> Result<(), PersistenceError> {
        let conn = self
            .conn
            .lock()
            .map_err(|e| PersistenceError::Storage(format!("ioc store mutex poisoned: {e}")))?;
        conn.execute(
            "INSERT INTO ioc_feeds (name, source_url, etag, last_modified, fetched_at)
             VALUES (?1, ?2, ?3, ?4, ?5)
             ON CONFLICT(name) DO UPDATE SET
                source_url    = excluded.source_url,
                etag          = excluded.etag,
                last_modified = excluded.last_modified,
                fetched_at    = excluded.fetched_at",
            params![
                meta.name,
                meta.source_url,
                meta.etag,
                meta.last_modified,
                ts_to_i64(meta.fetched_at),
            ],
        )
        .map_err(map_sqlite)?;
        Ok(())
    }

    fn replace_feed_iocs(&self, feed: &str, entries: &[IocEntry]) -> Result<(), PersistenceError> {
        let mut conn = self
            .conn
            .lock()
            .map_err(|e| PersistenceError::Storage(format!("ioc store mutex poisoned: {e}")))?;
        let tx = conn.transaction().map_err(map_sqlite)?;
        tx.execute("DELETE FROM iocs WHERE feed = ?1", params![feed])
            .map_err(map_sqlite)?;

        {
            let mut stmt = tx
                .prepare(
                    "INSERT OR REPLACE INTO iocs
                     (feed, ioc_type, value, source, tags, added_at)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                )
                .map_err(map_sqlite)?;
            for e in entries {
                let tags_json = serde_json::to_string(&e.tags).map_err(map_json)?;
                stmt.execute(params![
                    feed,
                    ioc_type_to_str(&e.ioc_type),
                    e.value.to_lowercase(),
                    e.source,
                    tags_json,
                    ts_to_i64(e.added_at),
                ])
                .map_err(map_sqlite)?;
            }
        }

        tx.commit().map_err(map_sqlite)?;
        Ok(())
    }

    fn load_all(&self, sink: &mut dyn FnMut(IocEntry)) -> Result<usize, PersistenceError> {
        let conn = self
            .conn
            .lock()
            .map_err(|e| PersistenceError::Storage(format!("ioc store mutex poisoned: {e}")))?;
        let mut stmt = conn
            .prepare("SELECT ioc_type, value, source, tags, added_at FROM iocs")
            .map_err(map_sqlite)?;

        let rows = stmt
            .query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, i64>(4)?,
                ))
            })
            .map_err(map_sqlite)?;

        let mut count = 0usize;
        for row in rows {
            let (ioc_type_s, value, source, tags_json, added_at) = row.map_err(map_sqlite)?;
            let Some(ioc_type) = ioc_type_from_str(&ioc_type_s) else {
                tracing::warn!(
                    ioc_type = ioc_type_s,
                    "skipping IOC with unknown type from store"
                );
                continue;
            };
            let tags: Vec<String> = serde_json::from_str(&tags_json).map_err(map_json)?;
            sink(IocEntry {
                ioc_type,
                value,
                source,
                tags,
                added_at: ts_from_i64(added_at),
            });
            count += 1;
        }
        Ok(count)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use arqenor_core::ioc::persistence::load_from_store;
    use arqenor_core::ioc::IocDatabase;
    use chrono::Utc;

    fn mk_entry(t: IocType, v: &str, source: &str) -> IocEntry {
        IocEntry {
            ioc_type: t,
            value: v.to_string(),
            source: source.to_string(),
            tags: vec!["emotet".into(), "botnet".into()],
            added_at: Utc::now(),
        }
    }

    #[test]
    fn upsert_and_fetch_feed_meta() {
        let store = IocSqliteStore::open_in_memory().unwrap();
        assert!(store
            .get_feed_meta("abuse.ch/malwarebazaar")
            .unwrap()
            .is_none());

        let meta = FeedMeta {
            name: "abuse.ch/malwarebazaar".into(),
            source_url: "https://example/feed".into(),
            etag: Some("\"abc123\"".into()),
            last_modified: Some("Wed, 21 Oct 2026 07:28:00 GMT".into()),
            fetched_at: Utc::now(),
        };
        store.upsert_feed_meta(&meta).unwrap();

        let got = store
            .get_feed_meta("abuse.ch/malwarebazaar")
            .unwrap()
            .unwrap();
        assert_eq!(got.etag.as_deref(), Some("\"abc123\""));
        assert_eq!(got.source_url, "https://example/feed");
    }

    #[test]
    fn replace_feed_iocs_is_atomic_and_replaces() {
        let store = IocSqliteStore::open_in_memory().unwrap();
        // Insert the feed row first so the FK succeeds.
        store
            .upsert_feed_meta(&FeedMeta {
                name: "abuse.ch/feodotracker".into(),
                source_url: "x".into(),
                etag: None,
                last_modified: None,
                fetched_at: Utc::now(),
            })
            .unwrap();

        let first = vec![
            mk_entry(IocType::Ipv4, "1.2.3.4", "abuse.ch/feodotracker"),
            mk_entry(IocType::Ipv4, "5.6.7.8", "abuse.ch/feodotracker"),
        ];
        store
            .replace_feed_iocs("abuse.ch/feodotracker", &first)
            .unwrap();

        let mut collected: Vec<String> = Vec::new();
        store
            .load_all(&mut |e| collected.push(e.value.clone()))
            .unwrap();
        assert_eq!(collected.len(), 2);

        // Replace with a different set — old rows must be gone.
        let second = vec![mk_entry(IocType::Ipv4, "9.9.9.9", "abuse.ch/feodotracker")];
        store
            .replace_feed_iocs("abuse.ch/feodotracker", &second)
            .unwrap();

        let mut collected: Vec<String> = Vec::new();
        store
            .load_all(&mut |e| collected.push(e.value.clone()))
            .unwrap();
        assert_eq!(collected, vec!["9.9.9.9"]);
    }

    #[test]
    fn load_all_roundtrip_preserves_fields() {
        let store = IocSqliteStore::open_in_memory().unwrap();
        store
            .upsert_feed_meta(&FeedMeta {
                name: "abuse.ch/threatfox".into(),
                source_url: "x".into(),
                etag: None,
                last_modified: None,
                fetched_at: Utc::now(),
            })
            .unwrap();
        let e = mk_entry(IocType::Domain, "Evil.COM", "abuse.ch/threatfox");
        store
            .replace_feed_iocs("abuse.ch/threatfox", std::slice::from_ref(&e))
            .unwrap();

        let mut db = IocDatabase::new();
        let n = load_from_store(&store, &mut db).unwrap();
        assert_eq!(n, 1);
        // `value` is lowercased on store write.
        assert!(db.check_domain("evil.com").is_some());
        assert!(db.check_domain("sub.evil.com").is_some());
    }

    #[test]
    fn reboot_simulation_reloads_from_disk() {
        // Use a file-backed DB in a temp directory so we can drop the first
        // store, open a second one, and verify the data persists.
        let tmp =
            std::env::temp_dir().join(format!("arqenor-ioc-test-{}.db", uuid::Uuid::new_v4()));
        let path = tmp.as_path();

        {
            let store = IocSqliteStore::open(path).unwrap();
            store
                .upsert_feed_meta(&FeedMeta {
                    name: "abuse.ch/malwarebazaar".into(),
                    source_url: "https://example/feed".into(),
                    etag: Some("\"etag-1\"".into()),
                    last_modified: None,
                    fetched_at: Utc::now(),
                })
                .unwrap();
            let entries = vec![
                mk_entry(
                    IocType::Sha256Hash,
                    &"a".repeat(64),
                    "abuse.ch/malwarebazaar",
                ),
                mk_entry(
                    IocType::Sha256Hash,
                    &"b".repeat(64),
                    "abuse.ch/malwarebazaar",
                ),
            ];
            store
                .replace_feed_iocs("abuse.ch/malwarebazaar", &entries)
                .unwrap();
        } // first store dropped → connection closed

        // "Reboot": reopen the same file.
        let store2 = IocSqliteStore::open(path).unwrap();
        let meta = store2
            .get_feed_meta("abuse.ch/malwarebazaar")
            .unwrap()
            .expect("feed meta should survive reboot");
        assert_eq!(meta.etag.as_deref(), Some("\"etag-1\""));

        let mut db = IocDatabase::new();
        let n = load_from_store(&store2, &mut db).unwrap();
        assert_eq!(n, 2);
        assert!(db.check_sha256(&"a".repeat(64)).is_some());
        assert!(db.check_sha256(&"b".repeat(64)).is_some());

        let _ = std::fs::remove_file(path);
    }
}
