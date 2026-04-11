//! Async threat feed downloaders for public IOC sources.
//!
//! Supported feeds:
//! - **MalwareBazaar** (abuse.ch) — SHA-256 malware hashes
//! - **Feodo Tracker** (abuse.ch) — botnet C2 server IPs
//! - **URLhaus** (abuse.ch) — malicious URLs
//! - **ThreatFox** (abuse.ch) — mixed IOCs (IPs, domains, hashes)

use chrono::Utc;
use std::sync::Arc;
use tokio::sync::RwLock;

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

// ── Feed URLs ────────────────────────────────────────────────────────────────

const MALWARE_BAZAAR_URL: &str = "https://bazaar.abuse.ch/export/csv/recent/";
const FEODO_TRACKER_URL: &str =
    "https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.txt";
const URLHAUS_URL: &str = "https://urlhaus.abuse.ch/downloads/csv_recent/";
const THREATFOX_URL: &str = "https://threatfox.abuse.ch/export/csv/recent/";

// ── Individual feed fetchers ─────────────────────────────────────────────────

/// MalwareBazaar — SHA-256 hashes of known malware samples.
///
/// CSV columns: first_seen_utc, sha256_hash, md5_hash, sha1_hash, reporter,
/// file_name, file_type_guess, mime_type, signature, clamav, vtpercent,
/// imphash, ssdeep, tlsh, tags
pub async fn fetch_malware_bazaar(db: &mut IocDatabase) -> Result<usize, IocFeedError> {
    let body = reqwest::get(MALWARE_BAZAAR_URL).await?.text().await?;
    let mut count = 0;
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

        db.add(IocEntry {
            ioc_type: IocType::Sha256Hash,
            value: sha256.to_string(),
            source: "abuse.ch/malwarebazaar".to_string(),
            tags,
            added_at: now,
        });
        count += 1;
    }

    tracing::info!(count, "MalwareBazaar feed loaded");
    Ok(count)
}

/// Feodo Tracker — botnet C2 server IP addresses.
///
/// Plain text, one IP per line. Comment lines start with `#`.
pub async fn fetch_feodo_tracker(db: &mut IocDatabase) -> Result<usize, IocFeedError> {
    let body = reqwest::get(FEODO_TRACKER_URL).await?.text().await?;
    let mut count = 0;
    let now = Utc::now();

    for line in body.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        // Validate it looks like an IP.
        if line.parse::<std::net::IpAddr>().is_err() {
            continue;
        }

        db.add(IocEntry {
            ioc_type: IocType::Ipv4,
            value: line.to_string(),
            source: "abuse.ch/feodotracker".to_string(),
            tags: vec!["botnet".to_string(), "c2".to_string()],
            added_at: now,
        });
        count += 1;
    }

    tracing::info!(count, "Feodo Tracker feed loaded");
    Ok(count)
}

/// URLhaus — malicious URLs (malware distribution, phishing, C2).
///
/// CSV columns: id, dateadded, url, url_status, last_online, threat, tags,
/// urlhaus_link, reporter
pub async fn fetch_urlhaus(db: &mut IocDatabase) -> Result<usize, IocFeedError> {
    let body = reqwest::get(URLHAUS_URL).await?.text().await?;
    let mut count = 0;
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

        db.add(IocEntry {
            ioc_type: IocType::Url,
            value: url.to_string(),
            source: "abuse.ch/urlhaus".to_string(),
            tags,
            added_at: now,
        });

        // Also extract domain from URL for domain-level matching.
        if let Some(domain) = extract_domain(url) {
            db.add(IocEntry {
                ioc_type: IocType::Domain,
                value: domain,
                source: "abuse.ch/urlhaus".to_string(),
                tags: vec![],
                added_at: now,
            });
        }

        count += 1;
    }

    tracing::info!(count, "URLhaus feed loaded");
    Ok(count)
}

/// ThreatFox — mixed IOCs (IPs, domains, SHA-256, MD5).
///
/// CSV columns: first_seen_utc, ioc_id, ioc_value, ioc_type, threat_type,
/// fk_malware, malware_alias, malware_printable, last_seen_utc,
/// confidence_level, reference, tags, anonymous, reporter
pub async fn fetch_threatfox(db: &mut IocDatabase) -> Result<usize, IocFeedError> {
    let body = reqwest::get(THREATFOX_URL).await?.text().await?;
    let mut count = 0;
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

        // For ip:port entries, strip the port.
        let value = if ioc_type_str == "ip:port" {
            ioc_value.split(':').next().unwrap_or(ioc_value).to_string()
        } else {
            ioc_value.to_string()
        };

        db.add(IocEntry {
            ioc_type,
            value,
            source: "abuse.ch/threatfox".to_string(),
            tags,
            added_at: now,
        });
        count += 1;
    }

    tracing::info!(count, "ThreatFox feed loaded");
    Ok(count)
}

// ── Aggregate refresh ────────────────────────────────────────────────────────

/// Refresh all supported feeds.  Returns total new IOCs added.
///
/// Errors from individual feeds are logged but do not prevent others from
/// loading.
pub async fn refresh_all_feeds(db: &mut IocDatabase) -> usize {
    let mut total = 0;

    match fetch_malware_bazaar(db).await {
        Ok(n) => total += n,
        Err(e) => tracing::warn!("MalwareBazaar feed failed: {e}"),
    }
    match fetch_feodo_tracker(db).await {
        Ok(n) => total += n,
        Err(e) => tracing::warn!("Feodo Tracker feed failed: {e}"),
    }
    match fetch_urlhaus(db).await {
        Ok(n) => total += n,
        Err(e) => tracing::warn!("URLhaus feed failed: {e}"),
    }
    match fetch_threatfox(db).await {
        Ok(n) => total += n,
        Err(e) => tracing::warn!("ThreatFox feed failed: {e}"),
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
}
