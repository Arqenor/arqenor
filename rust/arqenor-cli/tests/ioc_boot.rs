//! Integration tests for the IOC persistence wiring in `arqenor watch`.
//!
//! These tests exercise the same helpers the CLI invokes at boot
//! (`resolve_data_dir`, `open_ioc_store`) plus a simulated refresh cycle
//! performed against the real `IocSqliteStore` — no network is involved,
//! matching the "mock HTTP or just check the file exists and is non-empty"
//! guidance from the phase-1 spec.

use std::net::IpAddr;
use std::path::Path;
use std::sync::Arc;

use arqenor_cli::commands::watch::{open_ioc_store, resolve_data_dir};
use arqenor_core::ioc::persistence::{load_from_store, FeedMeta, IocPersistence};
use arqenor_core::ioc::{IocDatabase, IocEntry, IocType};
use chrono::Utc;
use tempfile::tempdir;

const FEED_NAME: &str = "abuse.ch/feodotracker";

fn mk_entry(kind: IocType, value: &str) -> IocEntry {
    IocEntry {
        ioc_type: kind,
        value: value.to_string(),
        source: FEED_NAME.to_string(),
        tags: vec!["botnet".into(), "c2".into()],
        added_at: Utc::now(),
    }
}

fn simulate_refresh_cycle(store: &Arc<dyn IocPersistence>, entries: &[IocEntry]) {
    store
        .upsert_feed_meta(&FeedMeta {
            name: FEED_NAME.to_string(),
            source_url: "https://example.invalid/feed".into(),
            etag: Some("\"w/abc\"".into()),
            last_modified: None,
            fetched_at: Utc::now(),
        })
        .expect("upsert_feed_meta must succeed on a fresh temp store");

    store
        .replace_feed_iocs(FEED_NAME, entries)
        .expect("replace_feed_iocs must succeed on a fresh temp store");
}

#[test]
fn resolve_data_dir_prefers_explicit_flag() {
    let explicit = Path::new("/tmp/explicit-arqenor");
    let alert_db = Path::new("/var/lib/arqenor/arqenor.db");
    let got = resolve_data_dir(Some(explicit), alert_db);
    assert_eq!(got, explicit);
}

#[test]
fn resolve_data_dir_falls_back_to_db_parent() {
    let alert_db = Path::new("/var/lib/arqenor/arqenor.db");
    let got = resolve_data_dir(None, alert_db);
    assert_eq!(got, Path::new("/var/lib/arqenor"));
}

#[test]
fn resolve_data_dir_uses_cwd_when_db_has_no_parent() {
    // Bare filename → parent is `Some("")`, which we treat as "no parent"
    // and fall back to `.`.
    let alert_db = Path::new("arqenor.db");
    let got = resolve_data_dir(None, alert_db);
    assert_eq!(got, Path::new("."));
}

#[test]
fn cli_boot_creates_ioc_db_and_loads_after_refresh() {
    // Temp directory stands in for `<data_dir>`; dropped at end of scope.
    let tmp = tempdir().expect("create tempdir");
    let data_dir = tmp.path();
    let ioc_db = data_dir.join("ioc.db");

    // No `ioc.db` yet.
    assert!(
        !ioc_db.exists(),
        "precondition: ioc.db must not exist before boot"
    );

    // The CLI boot path: open (creates the file + schema) …
    let store = open_ioc_store(data_dir, &ioc_db).expect("open ioc store in tempdir");

    assert!(
        ioc_db.exists(),
        "ioc.db must be created by IocSqliteStore::open"
    );

    // Simulate one successful refresh cycle: feed meta + IOC rows persisted.
    let entries = vec![
        mk_entry(IocType::Ipv4, "1.2.3.4"),
        mk_entry(IocType::Ipv4, "5.6.7.8"),
        mk_entry(IocType::Ipv4, "9.10.11.12"),
    ];
    simulate_refresh_cycle(&store, &entries);

    // File should now be non-empty (at minimum, schema + 3 rows).
    let meta = std::fs::metadata(&ioc_db).expect("stat ioc.db");
    assert!(
        meta.len() > 0,
        "ioc.db must be non-empty after a refresh cycle"
    );

    // A fresh IocDatabase warmed from the store must see all three IOCs —
    // this is exactly the boot-time `load_from_store` path the CLI uses.
    let mut db = IocDatabase::new();
    let loaded = load_from_store(store.as_ref(), &mut db).expect("load_from_store");
    assert_eq!(loaded, 3);
    let ip1: IpAddr = "1.2.3.4".parse().expect("parse ip");
    let ip2: IpAddr = "9.10.11.12".parse().expect("parse ip");
    assert!(db.check_ip(ip1).is_some());
    assert!(db.check_ip(ip2).is_some());
}

#[test]
fn cli_boot_creates_data_dir_when_missing() {
    // `<data_dir>` points to a path that does *not* exist yet — `open_ioc_store`
    // must create it (otherwise SQLite will fail on a non-existent parent).
    let tmp = tempdir().expect("create tempdir");
    let nested = tmp.path().join("nested").join("arqenor-data");
    assert!(!nested.exists());

    let db_path = nested.join("ioc.db");
    let store = open_ioc_store(&nested, &db_path).expect("open in non-existent nested dir");

    // Round-trip an empty-feed refresh to confirm the DB is really usable.
    simulate_refresh_cycle(&store, &[]);
    assert!(db_path.exists(), "ioc.db must exist in created data_dir");
}
