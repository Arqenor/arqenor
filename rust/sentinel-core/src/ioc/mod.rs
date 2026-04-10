//! Threat Intelligence IOC (Indicators of Compromise) database.
//!
//! In-memory database with O(1) `HashSet`-backed lookups for SHA-256, MD5,
//! IPv4/IPv6, domains, and URLs.  Populated from public threat feeds
//! (see [`feeds`]) and queried by the detection pipeline (see [`checker`]).

pub mod checker;
pub mod feeds;

use std::collections::{HashMap, HashSet};
use std::net::IpAddr;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

// ── Types ────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum IocType {
    Sha256Hash,
    Md5Hash,
    Ipv4,
    Domain,
    Url,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IocEntry {
    pub ioc_type: IocType,
    pub value:    String,
    pub source:   String,
    pub tags:     Vec<String>,
    pub added_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IocStats {
    pub sha256_count: usize,
    pub md5_count:    usize,
    pub ip_count:     usize,
    pub domain_count: usize,
    pub url_count:    usize,
    pub total:        usize,
    pub last_updated: Option<DateTime<Utc>>,
}

// ── Database ─────────────────────────────────────────────────────────────────

/// In-memory IOC database with O(1) lookups.
///
/// All values are normalised to lowercase on insertion.  Domain lookups support
/// subdomain matching: an IOC for `evil.com` will match `sub.evil.com`.
pub struct IocDatabase {
    sha256: HashSet<String>,
    md5:    HashSet<String>,
    ips:    HashSet<IpAddr>,
    domains: HashSet<String>,
    urls:   HashSet<String>,
    /// Full entries for metadata lookup after a positive match.
    entries: HashMap<String, IocEntry>,
    pub last_updated: Option<DateTime<Utc>>,
}

impl IocDatabase {
    pub fn new() -> Self {
        Self {
            sha256:  HashSet::new(),
            md5:     HashSet::new(),
            ips:     HashSet::new(),
            domains: HashSet::new(),
            urls:    HashSet::new(),
            entries: HashMap::new(),
            last_updated: None,
        }
    }

    /// Insert a single IOC entry.  Normalises the value to lowercase.
    pub fn add(&mut self, entry: IocEntry) {
        let key = entry.value.to_lowercase();
        match &entry.ioc_type {
            IocType::Sha256Hash => { self.sha256.insert(key.clone()); }
            IocType::Md5Hash    => { self.md5.insert(key.clone()); }
            IocType::Ipv4 => {
                if let Ok(ip) = key.parse::<IpAddr>() {
                    self.ips.insert(ip);
                }
            }
            IocType::Domain => { self.domains.insert(key.clone()); }
            IocType::Url    => { self.urls.insert(key.clone()); }
        }
        self.entries.insert(key, entry);
    }

    /// Check a SHA-256 hash (case-insensitive).
    pub fn check_sha256(&self, hash: &str) -> Option<&IocEntry> {
        let key = hash.to_lowercase();
        if self.sha256.contains(&key) {
            self.entries.get(&key)
        } else {
            None
        }
    }

    /// Check an MD5 hash (case-insensitive).
    pub fn check_md5(&self, hash: &str) -> Option<&IocEntry> {
        let key = hash.to_lowercase();
        if self.md5.contains(&key) {
            self.entries.get(&key)
        } else {
            None
        }
    }

    /// Check an IP address.
    pub fn check_ip(&self, ip: IpAddr) -> Option<&IocEntry> {
        if self.ips.contains(&ip) {
            self.entries.get(&ip.to_string())
        } else {
            None
        }
    }

    /// Check a domain.  Supports subdomain matching: an IOC `evil.com` matches
    /// `sub.evil.com`, `deep.sub.evil.com`, etc.
    pub fn check_domain(&self, domain: &str) -> Option<&IocEntry> {
        let domain = domain.to_lowercase();
        // Exact match first.
        if self.domains.contains(&domain) {
            return self.entries.get(&domain);
        }
        // Subdomain walk: strip labels from the left until we find a match.
        let mut d = domain.as_str();
        while let Some(pos) = d.find('.') {
            d = &d[pos + 1..];
            if self.domains.contains(d) {
                return self.entries.get(d);
            }
        }
        None
    }

    /// Check a URL (exact match, case-insensitive).
    pub fn check_url(&self, url: &str) -> Option<&IocEntry> {
        let key = url.to_lowercase();
        if self.urls.contains(&key) {
            self.entries.get(&key)
        } else {
            None
        }
    }

    pub fn stats(&self) -> IocStats {
        IocStats {
            sha256_count: self.sha256.len(),
            md5_count:    self.md5.len(),
            ip_count:     self.ips.len(),
            domain_count: self.domains.len(),
            url_count:    self.urls.len(),
            total:        self.entries.len(),
            last_updated: self.last_updated,
        }
    }
}

impl Default for IocDatabase {
    fn default() -> Self { Self::new() }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_entry(ioc_type: IocType, value: &str, source: &str) -> IocEntry {
        IocEntry {
            ioc_type,
            value: value.to_string(),
            source: source.to_string(),
            tags: vec![],
            added_at: Utc::now(),
        }
    }

    #[test]
    fn test_sha256_lookup() {
        let mut db = IocDatabase::new();
        db.add(make_entry(IocType::Sha256Hash, "AABBCC", "test"));
        assert!(db.check_sha256("aabbcc").is_some());
        assert!(db.check_sha256("AABBCC").is_some());
        assert!(db.check_sha256("112233").is_none());
    }

    #[test]
    fn test_domain_subdomain() {
        let mut db = IocDatabase::new();
        db.add(make_entry(IocType::Domain, "evil.com", "test"));
        assert!(db.check_domain("evil.com").is_some());
        assert!(db.check_domain("sub.evil.com").is_some());
        assert!(db.check_domain("deep.sub.evil.com").is_some());
        assert!(db.check_domain("notevil.com").is_none());
    }

    #[test]
    fn test_ip_lookup() {
        let mut db = IocDatabase::new();
        db.add(make_entry(IocType::Ipv4, "1.2.3.4", "feodo"));
        let ip: IpAddr = "1.2.3.4".parse().unwrap();
        assert!(db.check_ip(ip).is_some());
        let ip2: IpAddr = "5.6.7.8".parse().unwrap();
        assert!(db.check_ip(ip2).is_none());
    }
}
