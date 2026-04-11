use arqenor_core::models::alert::{Alert, Severity};
use rusqlite::{Connection, Result as SqlResult};
use serde_json;
use std::{collections::HashMap, path::Path};
use thiserror::Error;
use uuid::Uuid;

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
    metadata    TEXT NOT NULL,
    rule_id     TEXT,
    attack_id   TEXT
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

CREATE TABLE IF NOT EXISTS process_events (
    id          TEXT PRIMARY KEY,
    kind        TEXT NOT NULL,
    pid         INTEGER NOT NULL,
    ppid        INTEGER NOT NULL,
    name        TEXT NOT NULL,
    exe_path    TEXT,
    cmdline     TEXT,
    event_time  TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS file_events (
    id          TEXT PRIMARY KEY,
    kind        TEXT NOT NULL,
    path        TEXT NOT NULL,
    sha256      TEXT,
    size        INTEGER,
    event_time  TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_alerts_time    ON alerts(occurred_at);
CREATE INDEX IF NOT EXISTS idx_proc_evt_time  ON process_events(event_time);
CREATE INDEX IF NOT EXISTS idx_file_evt_time  ON file_events(event_time);
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
            "INSERT OR IGNORE INTO alerts (id, severity, kind, message, occurred_at, metadata, rule_id, attack_id)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            rusqlite::params![
                alert.id.to_string(),
                format!("{:?}", alert.severity),
                alert.kind,
                alert.message,
                alert.occurred_at.to_rfc3339(),
                metadata,
                alert.rule_id,
                alert.attack_id,
            ],
        )?;
        Ok(())
    }

    pub fn insert_process_event(
        &self,
        evt: &arqenor_core::models::process::ProcessEvent,
    ) -> Result<(), StoreError> {
        self.conn.execute(
            "INSERT OR IGNORE INTO process_events (id, kind, pid, ppid, name, exe_path, cmdline, event_time)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            rusqlite::params![
                evt.id.to_string(),
                format!("{:?}", evt.kind),
                evt.process.pid,
                evt.process.ppid,
                evt.process.name,
                evt.process.exe_path,
                evt.process.cmdline,
                evt.event_time.to_rfc3339(),
            ],
        )?;
        Ok(())
    }

    pub fn insert_file_event(
        &self,
        evt: &arqenor_core::models::file_event::FileEvent,
    ) -> Result<(), StoreError> {
        self.conn.execute(
            "INSERT OR IGNORE INTO file_events (id, kind, path, sha256, size, event_time)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            rusqlite::params![
                evt.id.to_string(),
                format!("{:?}", evt.kind),
                evt.path,
                evt.sha256,
                evt.size.map(|s| s as i64),
                evt.event_time.to_rfc3339(),
            ],
        )?;
        Ok(())
    }

    /// Count alerts grouped by severity.
    pub fn alert_counts_by_severity(&self) -> Result<Vec<(String, u64)>, StoreError> {
        let mut stmt = self.conn.prepare(
            "SELECT severity, COUNT(*) FROM alerts GROUP BY severity ORDER BY COUNT(*) DESC",
        )?;
        // rusqlite 0.38+ removed the default `FromSql` impl for `u64`/`usize`
        // (see rusqlite CHANGELOG v0.38). SQLite's COUNT(*) is representable as
        // `i64`; we cast back to `u64` for the public API (counts are non-negative).
        let rows = stmt
            .query_map([], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)? as u64))
            })?
            .filter_map(|r| r.ok())
            .collect();
        Ok(rows)
    }

    pub fn get_config(&self, key: &str) -> SqlResult<Option<String>> {
        match self
            .conn
            .query_row("SELECT value FROM config WHERE key = ?1", [key], |row| {
                row.get(0)
            }) {
            Ok(v) => Ok(Some(v)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(e),
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

    /// Return the `limit` most recent alerts, newest first.
    pub fn list_alerts(&self, limit: usize) -> Result<Vec<Alert>, StoreError> {
        let mut stmt = self.conn.prepare(
            "SELECT id, severity, kind, message, occurred_at, metadata, rule_id, attack_id
             FROM alerts ORDER BY occurred_at DESC LIMIT ?1",
        )?;

        let alerts = stmt
            .query_map([limit as i64], |row| {
                Ok((
                    row.get::<_, String>(0)?,         // id
                    row.get::<_, String>(1)?,         // severity
                    row.get::<_, String>(2)?,         // kind
                    row.get::<_, String>(3)?,         // message
                    row.get::<_, String>(4)?,         // occurred_at
                    row.get::<_, String>(5)?,         // metadata JSON
                    row.get::<_, Option<String>>(6)?, // rule_id
                    row.get::<_, Option<String>>(7)?, // attack_id
                ))
            })?
            .filter_map(|r| r.ok())
            .filter_map(|(id, sev, kind, msg, ts, meta_json, rule_id, attack_id)| {
                let id = Uuid::parse_str(&id).ok()?;
                let severity = parse_severity(&sev);
                let metadata: HashMap<String, String> =
                    serde_json::from_str(&meta_json).unwrap_or_default();
                let occurred_at = chrono::DateTime::parse_from_rfc3339(&ts)
                    .ok()?
                    .with_timezone(&chrono::Utc);
                Some(Alert {
                    id,
                    severity,
                    kind,
                    message: msg,
                    occurred_at,
                    metadata,
                    rule_id,
                    attack_id,
                })
            })
            .collect();

        Ok(alerts)
    }
}

fn parse_severity(s: &str) -> Severity {
    match s {
        "Info" => Severity::Info,
        "Low" => Severity::Low,
        "Medium" => Severity::Medium,
        "High" => Severity::High,
        "Critical" => Severity::Critical,
        _ => Severity::Info,
    }
}
