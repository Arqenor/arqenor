//! IOC checker — integrates the [`IocDatabase`] with the detection pipeline.
//!
//! Produces [`Alert`]s when events match known-malicious indicators.

use std::collections::HashMap;
use std::net::IpAddr;

use chrono::Utc;
use uuid::Uuid;

use super::IocDatabase;
use crate::models::alert::{Alert, Severity};

/// Stateless checker that queries an [`IocDatabase`] reference.
pub struct IocChecker<'a> {
    pub db: &'a IocDatabase,
}

impl<'a> IocChecker<'a> {
    pub fn new(db: &'a IocDatabase) -> Self {
        Self { db }
    }

    /// Check a file hash (from FIM, PE analysis, or process image hash).
    pub fn check_file_hash(&self, sha256: &str, file_path: &str) -> Option<Alert> {
        let entry = self.db.check_sha256(sha256)?;
        let mut meta = HashMap::new();
        meta.insert("sha256".into(), sha256.to_lowercase());
        meta.insert("file_path".into(), file_path.to_string());
        meta.insert("source".into(), entry.source.clone());
        if !entry.tags.is_empty() {
            meta.insert("tags".into(), entry.tags.join(", "));
        }

        Some(Alert {
            id: Uuid::new_v4(),
            severity: Severity::High,
            kind: "ioc_hash_match".into(),
            message: format!(
                "Known malicious file hash detected: {} ({})",
                &sha256[..16],
                entry.source,
            ),
            occurred_at: Utc::now(),
            metadata: meta,
            rule_id: Some("IOC-1001".into()),
            attack_id: Some("T1204".into()), // User Execution / malicious file
        })
    }

    /// Check a network connection destination IP.
    pub fn check_connection(&self, dst_ip: IpAddr, dst_port: u16) -> Option<Alert> {
        let entry = self.db.check_ip(dst_ip)?;
        let mut meta = HashMap::new();
        meta.insert("dst_ip".into(), dst_ip.to_string());
        meta.insert("dst_port".into(), dst_port.to_string());
        meta.insert("source".into(), entry.source.clone());
        if !entry.tags.is_empty() {
            meta.insert("tags".into(), entry.tags.join(", "));
        }

        Some(Alert {
            id: Uuid::new_v4(),
            severity: Severity::High,
            kind: "ioc_ip_match".into(),
            message: format!(
                "Connection to known C2 IP: {}:{} ({})",
                dst_ip, dst_port, entry.source,
            ),
            occurred_at: Utc::now(),
            metadata: meta,
            rule_id: Some("IOC-1002".into()),
            attack_id: Some("T1071".into()), // Application Layer Protocol (C2)
        })
    }

    /// Check a DNS query domain.
    pub fn check_dns(&self, domain: &str) -> Option<Alert> {
        let entry = self.db.check_domain(domain)?;
        let mut meta = HashMap::new();
        meta.insert("domain".into(), domain.to_string());
        meta.insert("matched_ioc".into(), entry.value.clone());
        meta.insert("source".into(), entry.source.clone());
        if !entry.tags.is_empty() {
            meta.insert("tags".into(), entry.tags.join(", "));
        }

        Some(Alert {
            id: Uuid::new_v4(),
            severity: Severity::High,
            kind: "ioc_domain_match".into(),
            message: format!(
                "DNS query to known malicious domain: {} ({})",
                domain, entry.source,
            ),
            occurred_at: Utc::now(),
            metadata: meta,
            rule_id: Some("IOC-1003".into()),
            attack_id: Some("T1071.004".into()), // DNS C2
        })
    }

    /// Check a URL (from process command line, HTTP traffic, or file content).
    pub fn check_url(&self, url: &str) -> Option<Alert> {
        let entry = self.db.check_url(url)?;
        let mut meta = HashMap::new();
        meta.insert("url".into(), url.to_string());
        meta.insert("source".into(), entry.source.clone());
        if !entry.tags.is_empty() {
            meta.insert("tags".into(), entry.tags.join(", "));
        }

        Some(Alert {
            id: Uuid::new_v4(),
            severity: Severity::High,
            kind: "ioc_url_match".into(),
            message: format!("Access to known malicious URL: {} ({})", url, entry.source,),
            occurred_at: Utc::now(),
            metadata: meta,
            rule_id: Some("IOC-1004".into()),
            attack_id: Some("T1204.001".into()), // Malicious Link
        })
    }
}

#[cfg(test)]
mod tests {
    use super::super::{IocEntry, IocType};
    use super::*;

    #[test]
    fn test_hash_match_produces_alert() {
        let mut db = IocDatabase::new();
        db.add(IocEntry {
            ioc_type: IocType::Sha256Hash,
            value: "a".repeat(64),
            source: "test".into(),
            tags: vec!["emotet".into()],
            added_at: Utc::now(),
        });

        let checker = IocChecker::new(&db);
        let alert = checker.check_file_hash(&"a".repeat(64), r"C:\temp\bad.exe");
        assert!(alert.is_some());
        let alert = alert.unwrap();
        assert_eq!(alert.rule_id.as_deref(), Some("IOC-1001"));
        assert_eq!(alert.severity, Severity::High);
    }

    #[test]
    fn test_no_match_returns_none() {
        let db = IocDatabase::new();
        let checker = IocChecker::new(&db);
        assert!(checker.check_file_hash("deadbeef", "test").is_none());
        assert!(checker.check_dns("safe.com").is_none());
    }
}
