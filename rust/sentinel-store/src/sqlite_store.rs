use rusqlite::{Connection, Result as SqlResult};
use sentinel_core::models::alert::Alert;
use serde_json;
use std::path::Path;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum StoreError {
    #[error("sqlite: {0}")]
    Sqlite(#[from] rusqlite::Error),
    #[error("json: {0}")]
    Json(#[from] serde_json::Error),
}

pub struct SqliteStore {
    conn: Connection,
}

const INIT_SQL: &str = r#"
CREATE TABLE IF NOT EXISTS config (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS alerts (
    id          TEXT PRIMARY KEY,
    severity    TEXT NOT NULL,
    kind        TEXT NOT NULL,
    message     TEXT NOT NULL,
    occurred_at TEXT NOT NULL,
    metadata    TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS rules (
    id         TEXT PRIMARY KEY,
    kind       TEXT NOT NULL,
    expression TEXT NOT NULL,
    enabled    INTEGER NOT NULL DEFAULT 1
);

CREATE TABLE IF NOT EXISTS persistence_baseline (
    id          TEXT PRIMARY KEY,
    kind        TEXT NOT NULL,
    name        TEXT NOT NULL,
    command     TEXT NOT NULL,
    location    TEXT NOT NULL,
    captured_at TEXT NOT NULL
);
"#;

impl SqliteStore {
    pub fn open(path: &Path) -> SqlResult<Self> {
        let conn = Connection::open(path)?;
        conn.execute_batch(INIT_SQL)?;
        Ok(Self { conn })
    }

    pub fn insert_alert(&self, alert: &Alert) -> Result<(), StoreError> {
        let metadata = serde_json::to_string(&alert.metadata)?;
        self.conn.execute(
            "INSERT OR IGNORE INTO alerts (id, severity, kind, message, occurred_at, metadata)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            rusqlite::params![
                alert.id.to_string(),
                format!("{:?}", alert.severity),
                alert.kind,
                alert.message,
                alert.occurred_at.to_rfc3339(),
                metadata,
            ],
        )?;
        Ok(())
    }

    pub fn get_config(&self, key: &str) -> SqlResult<Option<String>> {
        match self.conn.query_row(
            "SELECT value FROM config WHERE key = ?1",
            [key],
            |row| row.get(0),
        ) {
            Ok(v)                                                => Ok(Some(v)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e)                                               => Err(e),
        }
    }

    pub fn set_config(&self, key: &str, value: &str) -> SqlResult<()> {
        self.conn.execute(
            "INSERT INTO config (key, value) VALUES (?1, ?2)
             ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            [key, value],
        )?;
        Ok(())
    }
}
