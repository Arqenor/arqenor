//! Async threat feed downloaders for public IOC sources.
//!
//! Supported feeds:
//! - **MalwareBazaar** (abuse.ch) — SHA-256 malware hashes
//! - **Feodo Tracker** (abuse.ch) — botnet C2 server IPs
//! - **URLhaus** (abuse.ch) — malicious URLs
//! - **ThreatFox** (abuse.ch) — mixed IOCs (IPs, domains, hashes)
//!
//! # Delta refresh
//!
//! Each fetcher issues a conditional `GET` using the `If-None-Match` and
//! `If-Modified-Since` headers recorded in the persistent store (see
//! [`super::persistence`]).  A `304 Not Modified` short-circuits the parse
//! and keeps the previously-persisted IOCs in the in-memory database.
//! On a `200 OK` the full payload is parsed, the in-store rows are replaced
//! atomically, and the entries are added to the in-memory database.
//!
//! Feeds without `ETag` / `Last-Modified` support fall back to an
//! unconditional download on every refresh — correctness is preserved
//! because the delta is computed by replacing the feed's entire row set
//! inside a transaction.

use chrono::Utc;
use reqwest::header::{HeaderMap, HeaderValue, ETAG, IF_MODIFIED_SINCE, IF_NONE_MATCH, LAST_MODIFIED};
use reqwest::StatusCode;
use std::sync::Arc;
use tokio::sync::RwLock;

use super::persistence::{FeedMeta, IocPersistence};
use super::{IocDatabase, IocEntry, IocType};

// ── Error type ───────────────────────────────────────────────────────────────

#[derive(Debug)]
pub enum IocFeedError {
    Http(reqwest::Error),
    Parse(String),
}

impl std::fmt::Display for IocFeedError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Http(e) => write!(f, "HTTP error: {e}"),
            Self::Parse(msg) => write!(f, "parse error: {msg}"),
        }
    }
}

impl std::error::Error for IocFeedError {}
impl From<reqwest::Error> for IocFeedError {
    fn from(e: reqwest::Error) -> Self {
        Self::Http(e)
    }
}

// ── Feed URLs / names ────────────────────────────────────────────────────────

const MALWARE_BAZAAR_URL: &str = "https://bazaar.abuse.ch/export/csv/recent/";
const FEODO_TRACKER_URL: &str =
    "https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.txt";
const URLHAUS_URL: &str = "https://urlhaus.abuse.ch/downloads/csv_recent/";
const THREATFOX_URL: &str = "https://threatfox.abuse.ch/export/csv/recent/";

/// Canonical feed names.  Match the `source` field of [`IocEntry`] so that a
/// feed's in-store rows can be re-grouped by source when persisted.
pub const FEED_MALWARE_BAZAAR: &str = "abuse.ch/malwarebazaar";
pub const FEED_FEODO: &str = "abuse.ch/feodotracker";
pub const FEED_URLHAUS: &str = "abuse.ch/urlhaus";
pub const FEED_THREATFOX: &str = "abuse.ch/threatfox";

// ── Conditional GET primitive ────────────────────────────────────────────────

/// Outcome of a conditional feed fetch.
enum FetchOutcome {
    /// Server responded `304 Not Modified` — the in-store rows are authoritative.
    NotModified,
    /// Server returned a fresh payload together with the headers to persist.
    Modified {
        body: String,
        etag: Option<String>,
        last_modified: Option<String>,
    },
}

fn header_str(headers: &HeaderMap, name: reqwest::header::HeaderName) -> Option<String> {
    headers
        .get(name)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string())
}

/// Perform a conditional `GET` using the cached `etag` / `last_modified`
/// metadata, if supplied.
async fn conditional_get(
    client: &reqwest::Client,
    url: &str,
    prev: Option<&FeedMeta>,
) -> Result<FetchOutcome, IocFeedError> {
    let mut req = client.get(url);
    if let Some(meta) = prev {
        if let Some(etag) = &meta.etag {
            if let Ok(val) = HeaderValue::from_str(etag) {
                req = req.header(IF_NONE_MATCH, val);
            }
        }
        if let Some(lm) = &meta.last_modified {
            if let Ok(val) = HeaderValue::from_str(lm) {
                req = req.header(IF_MODIFIED_SINCE, val);
            }
        }
    }

    let resp = req.send().await?;
    if resp.status() == StatusCode::NOT_MODIFIED {
        return Ok(FetchOutcome::NotModified);
    }
    let resp = resp.error_for_status()?;
    let headers = resp.headers().clone();
    let body = resp.text().await?;
    Ok(FetchOutcome::Modified {
        body,
        etag: header_str(&headers, ETAG),
        last_modified: header_str(&headers, LAST_MODIFIED),
    })
}

// ── Individual feed parsers ──────────────────────────────────────────────────

/// MalwareBazaar — SHA-256 hashes of known malware samples.
///
/// CSV columns: first_seen_utc, sha256_hash, md5_hash, sha1_hash, reporter,
/// file_name, file_type_guess, mime_type, signature, clamav, vtpercent,
/// imphash, ssdeep, tlsh, tags
fn parse_malware_bazaar(body: &str) -> Vec<IocEntry> {
    let mut out = Vec::new();
    let now = Utc::now();
    for line in body.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with("first_seen") {
            continue;
        }
        let cols: Vec<&str> = line.splitn(15, ',').collect();
        if cols.len() < 14 {
            continue;
        }
        let sha256 = cols[1].trim().trim_matches('"');
        if sha256.len() != 64 {
            continue;
        }
        let tags_raw = cols.get(14).unwrap_or(&"").trim().trim_matches('"');
        let tags: Vec<String> = tags_raw.split_whitespace().map(|t| t.to_string()).collect();
        out.push(IocEntry {
            ioc_type: IocType::Sha256Hash,
            value: sha256.to_string(),
            source: FEED_MALWARE_BAZAAR.to_string(),
            tags,
            added_at: now,
        });
    }
    out
}

/// Feodo Tracker — botnet C2 server IPs (plain text, one per line).
fn parse_feodo(body: &str) -> Vec<IocEntry> {
    let mut out = Vec::new();
    let now = Utc::now();
    for line in body.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if line.parse::<std::net::IpAddr>().is_err() {
            continue;
        }
        out.push(IocEntry {
            ioc_type: IocType::Ipv4,
            value: line.to_string(),
            source: FEED_FEODO.to_string(),
            tags: vec!["botnet".to_string(), "c2".to_string()],
            added_at: now,
        });
    }
    out
}

/// URLhaus — malicious URLs.
///
/// CSV columns: id, dateadded, url, url_status, last_online, threat, tags,
/// urlhaus_link, reporter
fn parse_urlhaus(body: &str) -> Vec<IocEntry> {
    let mut out = Vec::new();
    let now = Utc::now();
    for line in body.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with("id,") {
            continue;
        }
        let cols: Vec<&str> = line.splitn(9, ',').collect();
        if cols.len() < 7 {
            continue;
        }
        let url = cols[2].trim().trim_matches('"');
        if url.is_empty() {
            continue;
        }
        let tags_raw = cols.get(6).unwrap_or(&"").trim().trim_matches('"');
        let tags: Vec<String> = tags_raw
            .split_whitespace()
            .filter(|t| !t.is_empty())
            .map(|t| t.to_string())
            .collect();

        out.push(IocEntry {
            ioc_type: IocType::Url,
            value: url.to_string(),
            source: FEED_URLHAUS.to_string(),
            tags,
            added_at: now,
        });

        if let Some(domain) = extract_domain(url) {
            out.push(IocEntry {
                ioc_type: IocType::Domain,
                value: domain,
                source: FEED_URLHAUS.to_string(),
                tags: vec![],
                added_at: now,
            });
        }
    }
    out
}

/// ThreatFox — mixed IOCs.
///
/// CSV columns: first_seen_utc, ioc_id, ioc_value, ioc_type, threat_type,
/// fk_malware, malware_alias, malware_printable, last_seen_utc,
/// confidence_level, reference, tags, anonymous, reporter
fn parse_threatfox(body: &str) -> Vec<IocEntry> {
    let mut out = Vec::new();
    let now = Utc::now();
    for line in body.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with("first_seen") {
            continue;
        }
        let cols: Vec<&str> = line.splitn(14, ',').collect();
        if cols.len() < 12 {
            continue;
        }
        let ioc_value = cols[2].trim().trim_matches('"');
        let ioc_type_str = cols[3].trim().trim_matches('"');
        let malware = cols.get(7).unwrap_or(&"").trim().trim_matches('"');
        let tags_raw = cols.get(11).unwrap_or(&"").trim().trim_matches('"');
        let mut tags: Vec<String> = tags_raw
            .split_whitespace()
            .filter(|t| !t.is_empty())
            .map(|t| t.to_string())
            .collect();
        if !malware.is_empty() {
            tags.push(malware.to_string());
        }

        let ioc_type = match ioc_type_str {
            "ip:port" => IocType::Ipv4,
            "domain" => IocType::Domain,
            "url" => IocType::Url,
            "sha256_hash" => IocType::Sha256Hash,
            "md5_hash" => IocType::Md5Hash,
            _ => continue,
        };

        let value = if ioc_type_str == "ip:port" {
            ioc_value.split(':').next().unwrap_or(ioc_value).to_string()
        } else {
            ioc_value.to_string()
        };

        out.push(IocEntry {
            ioc_type,
            value,
            source: FEED_THREATFOX.to_string(),
            tags,
            added_at: now,
        });
    }
    out
}

// ── Public single-feed fetchers (backward-compatible) ────────────────────────

/// Shared `reqwest::Client` for all fetchers within a single refresh cycle.
fn new_client() -> reqwest::Client {
    reqwest::Client::builder()
        .user_agent(concat!("arqenor-core/", env!("CARGO_PKG_VERSION")))
        .build()
        .unwrap_or_else(|_| reqwest::Client::new())
}

/// MalwareBazaar fetcher — unconditional GET, kept for backward compatibility.
pub async fn fetch_malware_bazaar(db: &mut IocDatabase) -> Result<usize, IocFeedError> {
    let body = reqwest::get(MALWARE_BAZAAR_URL).await?.text().await?;
    let entries = parse_malware_bazaar(&body);
    let count = entries.len();
    for e in entries {
        db.add(e);
    }
    tracing::info!(count, "MalwareBazaar feed loaded");
    Ok(count)
}

/// Feodo Tracker fetcher — unconditional GET, kept for backward compatibility.
pub async fn fetch_feodo_tracker(db: &mut IocDatabase) -> Result<usize, IocFeedError> {
    let body = reqwest::get(FEODO_TRACKER_URL).await?.text().await?;
    let entries = parse_feodo(&body);
    let count = entries.len();
    for e in entries {
        db.add(e);
    }
    tracing::info!(count, "Feodo Tracker feed loaded");
    Ok(count)
}

/// URLhaus fetcher — unconditional GET, kept for backward compatibility.
pub async fn fetch_urlhaus(db: &mut IocDatabase) -> Result<usize, IocFeedError> {
    let body = reqwest::get(URLHAUS_URL).await?.text().await?;
    let entries = parse_urlhaus(&body);
    let count = entries.len();
    for e in entries {
        db.add(e);
    }
    tracing::info!(count, "URLhaus feed loaded");
    Ok(count)
}

/// ThreatFox fetcher — unconditional GET, kept for backward compatibility.
pub async fn fetch_threatfox(db: &mut IocDatabase) -> Result<usize, IocFeedError> {
    let body = reqwest::get(THREATFOX_URL).await?.text().await?;
    let entries = parse_threatfox(&body);
    let count = entries.len();
    for e in entries {
        db.add(e);
    }
    tracing::info!(count, "ThreatFox feed loaded");
    Ok(count)
}

// ── Store-aware refresh with delta detection ─────────────────────────────────

/// Parser function signature for a feed's raw body.
type FeedParser = fn(&str) -> Vec<IocEntry>;

/// Static description of a feed: (canonical name, URL, parser).
type FeedJob = (&'static str, &'static str, FeedParser);

/// Result of refreshing a single feed.
#[derive(Debug, Clone, Copy)]
pub enum FeedRefresh {
    /// Server returned `304 Not Modified` — nothing changed upstream.
    NotModified,
    /// Feed was re-downloaded; `usize` is the number of entries now active
    /// for this feed.
    Updated(usize),
}

/// Fetch a single feed with conditional-GET semantics.  Returns the parsed
/// entries (empty when `NotModified`) and the outcome.
async fn refresh_one(
    client: &reqwest::Client,
    url: &str,
    feed: &str,
    parse: FeedParser,
    store: Option<&dyn IocPersistence>,
) -> Result<(FeedRefresh, Vec<IocEntry>), IocFeedError> {
    let prev = match store {
        Some(s) => match s.get_feed_meta(feed) {
            Ok(m) => m,
            Err(e) => {
                tracing::warn!(%e, feed, "failed to read persisted feed metadata");
                None
            }
        },
        None => None,
    };

    match conditional_get(client, url, prev.as_ref()).await? {
        FetchOutcome::NotModified => {
            tracing::info!(feed, "feed unchanged (304 Not Modified)");
            Ok((FeedRefresh::NotModified, Vec::new()))
        }
        FetchOutcome::Modified { body, etag, last_modified } => {
            let entries = parse(&body);
            let count = entries.len();

            if let Some(s) = store {
                if let Err(e) = s.replace_feed_iocs(feed, &entries) {
                    tracing::warn!(%e, feed, "failed to persist feed IOCs");
                }
                let meta = FeedMeta {
                    name: feed.to_string(),
                    source_url: url.to_string(),
                    etag,
                    last_modified,
                    fetched_at: Utc::now(),
                };
                if let Err(e) = s.upsert_feed_meta(&meta) {
                    tracing::warn!(%e, feed, "failed to persist feed metadata");
                }
            }

            tracing::info!(count, feed, "feed refreshed");
            Ok((FeedRefresh::Updated(count), entries))
        }
    }
}

// ── Aggregate refresh ────────────────────────────────────────────────────────

/// Refresh all supported feeds.  Returns total new IOCs added.
///
/// Errors from individual feeds are logged but do not prevent others from
/// loading.
pub async fn refresh_all_feeds(db: &mut IocDatabase) -> usize {
    refresh_all_feeds_with_persist(db, None).await
}

/// Refresh all supported feeds, persisting results to `store` when supplied
/// and honouring HTTP conditional-GET for delta refresh.
pub async fn refresh_all_feeds_with_persist(
    db: &mut IocDatabase,
    store: Option<&dyn IocPersistence>,
) -> usize {
    let client = new_client();
    let mut total = 0usize;

    let jobs: [FeedJob; 4] = [
        (FEED_MALWARE_BAZAAR, MALWARE_BAZAAR_URL, parse_malware_bazaar),
        (FEED_FEODO, FEODO_TRACKER_URL, parse_feodo),
        (FEED_URLHAUS, URLHAUS_URL, parse_urlhaus),
        (FEED_THREATFOX, THREATFOX_URL, parse_threatfox),
    ];

    for (feed, url, parse) in jobs {
        match refresh_one(&client, url, feed, parse, store).await {
            Ok((FeedRefresh::NotModified, _)) => {
                // In-store rows are authoritative; they were already loaded at boot.
            }
            Ok((FeedRefresh::Updated(n), entries)) => {
                total += n;
                for e in entries {
                    db.add(e);
                }
            }
            Err(e) => tracing::warn!(%e, feed, "feed refresh failed"),
        }
    }

    db.last_updated = Some(Utc::now());
    tracing::info!(total, "IOC feed refresh complete");
    total
}

/// Spawn a background task that refreshes all feeds on a fixed interval.
///
/// The returned `JoinHandle` can be aborted to stop the refresh loop.
pub fn spawn_feed_refresh_loop(
    db: Arc<RwLock<IocDatabase>>,
    interval: std::time::Duration,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            {
                let mut guard = db.write().await;
                refresh_all_feeds(&mut guard).await;
            }
            tokio::time::sleep(interval).await;
        }
    })
}

/// Variant of [`spawn_feed_refresh_loop`] that persists each refresh to
/// `store`.
pub fn spawn_feed_refresh_loop_with_persist(
    db: Arc<RwLock<IocDatabase>>,
    store: Arc<dyn IocPersistence>,
    interval: std::time::Duration,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            {
                let mut guard = db.write().await;
                refresh_all_feeds_with_persist(&mut guard, Some(store.as_ref())).await;
            }
            tokio::time::sleep(interval).await;
        }
    })
}

// ── Helpers ──────────────────────────────────────────────────────────────────

/// Extract the domain from a URL string (very basic — no URL crate dependency).
fn extract_domain(url: &str) -> Option<String> {
    let stripped = url
        .strip_prefix("https://")
        .or_else(|| url.strip_prefix("http://"))
        .or_else(|| url.strip_prefix("ftp://"))?;
    let host = stripped.split('/').next()?;
    let host = host.split(':').next()?; // strip port
    if host.is_empty() || host.contains(' ') {
        return None;
    }
    Some(host.to_lowercase())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_domain() {
        assert_eq!(
            extract_domain("https://evil.com/path"),
            Some("evil.com".into())
        );
        assert_eq!(
            extract_domain("http://1.2.3.4:8080/mal"),
            Some("1.2.3.4".into())
        );
        assert_eq!(
            extract_domain("ftp://files.bad.org"),
            Some("files.bad.org".into())
        );
        assert_eq!(extract_domain("not a url"), None);
    }

    #[test]
    fn test_parse_feodo_skips_comments_and_junk() {
        let body = "# header\n\n1.2.3.4\n5.6.7.8\nnot-an-ip\n";
        let entries = parse_feodo(body);
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].value, "1.2.3.4");
        assert_eq!(entries[0].source, FEED_FEODO);
    }

    #[test]
    fn test_parse_threatfox_ip_port_stripping() {
        let header = "first_seen_utc,ioc_id,ioc_value,ioc_type,threat_type,fk_malware,malware_alias,malware_printable,last_seen_utc,confidence_level,reference,tags,anonymous,reporter\n";
        let row = r#""2024-01-01","1","1.2.3.4:8080","ip:port","botnet_cc","","","Emotet","","75","","tag1 tag2","0","rep""#;
        let body = format!("{header}{row}");
        let entries = parse_threatfox(&body);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].value, "1.2.3.4");
        assert!(matches!(entries[0].ioc_type, IocType::Ipv4));
        assert!(entries[0].tags.iter().any(|t| t == "Emotet"));
    }
}
