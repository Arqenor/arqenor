//! JA4 TLS fingerprinting for C2 detection.
//!
//! JA4 is the successor to JA3 — it fingerprints TLS Client Hello messages into
//! a compact string that can be matched against known C2 framework signatures.
//!
//! Format: `{prefix}_{cipher_hash}_{extension_hash}`
//! Example: `t13d1516h2_8daaf6152771_b186095e22b6`

use crate::models::alert::{Alert, Severity};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use uuid::Uuid;

// ---------------------------------------------------------------------------
// GREASE values (RFC 8701) — must be excluded from fingerprinting
// ---------------------------------------------------------------------------

const GREASE_VALUES: &[u16] = &[
    0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a, 0x4a4a, 0x5a5a, 0x6a6a, 0x7a7a, 0x8a8a, 0x9a9a, 0xaaaa, 0xbaba,
    0xcaca, 0xdada, 0xeaea, 0xfafa,
];

fn is_grease(val: u16) -> bool {
    GREASE_VALUES.contains(&val)
}

// ---------------------------------------------------------------------------
// TLS Client Hello representation
// ---------------------------------------------------------------------------

/// Raw TLS Client Hello fields needed to compute JA4.
#[derive(Debug, Clone)]
pub struct TlsClientHello {
    /// TLS version advertised in the handshake (0x0303 = TLS 1.2, 0x0304 = TLS 1.3).
    pub tls_version: u16,
    /// Server Name Indication value, if present.
    pub sni: Option<String>,
    /// Offered cipher suites (raw u16 values).
    pub cipher_suites: Vec<u16>,
    /// Extension type IDs present in the Client Hello.
    pub extensions: Vec<u16>,
    /// Signature algorithms from the `signature_algorithms` extension.
    pub signature_algos: Vec<u16>,
    /// ALPN protocol strings (e.g. "h2", "http/1.1").
    pub alpn_protocols: Vec<String>,
}

// ---------------------------------------------------------------------------
// JA4 Fingerprint
// ---------------------------------------------------------------------------

/// Computed JA4 fingerprint.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ja4Fingerprint {
    /// Full JA4 string, e.g. `t13d1516h2_8daaf6152771_b186095e22b6`.
    pub full: String,
    /// The prefix segment only (before the first `_`), used for prefix-based matching.
    pub prefix: String,
}

/// Compute a JA4 fingerprint from a TLS Client Hello.
pub fn compute_ja4(hello: &TlsClientHello) -> Ja4Fingerprint {
    // --- Part 1: prefix ---------------------------------------------------
    // Protocol: 't' for TCP (we assume TCP; QUIC would be 'q')
    let proto = 't';

    let version_str = match hello.tls_version {
        0x0304 => "13",
        0x0303 => "12",
        0x0302 => "11",
        0x0301 => "10",
        0x0300 => "s3",
        _ => "00",
    };

    let sni_flag = if hello.sni.is_some() { 'd' } else { 'i' };

    // Filter out GREASE from cipher suites for counting and hashing
    let ciphers_no_grease: Vec<u16> = hello
        .cipher_suites
        .iter()
        .copied()
        .filter(|c| !is_grease(*c))
        .collect();

    let extensions_no_grease: Vec<u16> = hello
        .extensions
        .iter()
        .copied()
        .filter(|e| !is_grease(*e))
        .collect();

    let cipher_count = format!("{:02}", ciphers_no_grease.len().min(99));
    let ext_count = format!("{:02}", extensions_no_grease.len().min(99));

    // First ALPN: take first 2 chars of the first ALPN protocol
    let alpn_tag = match hello.alpn_protocols.first() {
        Some(alpn) => {
            let normalized = match alpn.as_str() {
                "http/1.1" => "h1",
                "http/1.0" => "h1",
                _ => alpn.as_str(),
            };
            let chars: Vec<char> = normalized.chars().collect();
            if chars.len() >= 2 {
                format!("{}{}", chars[0], chars[1])
            } else if chars.len() == 1 {
                format!("{}0", chars[0])
            } else {
                "00".to_string()
            }
        }
        None => "00".to_string(),
    };

    let prefix = format!("{proto}{version_str}{sni_flag}{cipher_count}{ext_count}{alpn_tag}");

    // --- Part 2: cipher hash ----------------------------------------------
    let mut sorted_ciphers = ciphers_no_grease.clone();
    sorted_ciphers.sort_unstable();
    let cipher_csv: String = sorted_ciphers
        .iter()
        .map(|c| format!("{:04x}", c))
        .collect::<Vec<_>>()
        .join(",");
    let cipher_hash = truncated_sha256(&cipher_csv);

    // --- Part 3: extension hash -------------------------------------------
    // Exclude SNI (0x0000) and ALPN (0x0010) in addition to GREASE
    let mut sorted_exts: Vec<u16> = extensions_no_grease
        .iter()
        .copied()
        .filter(|e| *e != 0x0000 && *e != 0x0010)
        .collect();
    sorted_exts.sort_unstable();
    let ext_csv: String = sorted_exts
        .iter()
        .map(|e| format!("{:04x}", e))
        .collect::<Vec<_>>()
        .join(",");
    let ext_hash = truncated_sha256(&ext_csv);

    let full = format!("{prefix}_{cipher_hash}_{ext_hash}");
    Ja4Fingerprint { full, prefix }
}

/// SHA-256, hex-encoded, truncated to 12 characters.
fn truncated_sha256(input: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(input.as_bytes());
    let digest = hasher.finalize();
    let hex_str = hex::encode(digest);
    hex_str[..12].to_string()
}

// ---------------------------------------------------------------------------
// Known C2 Fingerprint Blocklist
// ---------------------------------------------------------------------------

/// Entry in the JA4 blocklist describing a known malicious TLS fingerprint.
#[derive(Debug, Clone)]
pub struct Ja4BlocklistEntry {
    /// The JA4 fingerprint or prefix to match against.
    pub fingerprint: String,
    /// Name of the C2 tool / malware family.
    pub tool_name: String,
    /// Human-readable description.
    pub description: String,
    /// Detection confidence (0.0–1.0).
    pub confidence: f64,
    /// MITRE ATT&CK technique ID.
    pub attack_id: String,
    /// Whether this entry matches by prefix only (first segment) or full string.
    pub prefix_only: bool,
}

/// Database of known malicious JA4 fingerprints.
#[derive(Debug, Clone)]
pub struct Ja4Blocklist {
    /// Full-match entries keyed by full JA4 string.
    full_entries: HashMap<String, Ja4BlocklistEntry>,
    /// Prefix-match entries keyed by JA4 prefix (first segment).
    prefix_entries: HashMap<String, Ja4BlocklistEntry>,
}

impl Ja4Blocklist {
    /// Build the built-in blocklist with known C2 framework fingerprints.
    ///
    /// Fingerprint prefixes are stable across default configurations of each tool.
    /// Full-string matches are higher confidence but less common in the wild because
    /// operators may tweak cipher suites.
    pub fn builtin() -> Self {
        let mut full_entries = HashMap::new();
        let mut prefix_entries = HashMap::new();

        let entries: Vec<Ja4BlocklistEntry> = vec![
            // --- Cobalt Strike -------------------------------------------
            Ja4BlocklistEntry {
                fingerprint: "t13d1517h2".into(),
                tool_name: "Cobalt Strike".into(),
                description:
                    "Cobalt Strike default HTTPS beacon (TLS 1.3, 15 ciphers, 17 extensions, h2)"
                        .into(),
                confidence: 0.85,
                attack_id: "T1071.001".into(),
                prefix_only: true,
            },
            Ja4BlocklistEntry {
                fingerprint: "t12d1517h2".into(),
                tool_name: "Cobalt Strike".into(),
                description:
                    "Cobalt Strike HTTPS beacon (TLS 1.2 variant, 15 ciphers, 17 extensions, h2)"
                        .into(),
                confidence: 0.80,
                attack_id: "T1071.001".into(),
                prefix_only: true,
            },
            Ja4BlocklistEntry {
                fingerprint: "t13d1516h2".into(),
                tool_name: "Cobalt Strike".into(),
                description:
                    "Cobalt Strike HTTPS beacon variant (TLS 1.3, 15 ciphers, 16 extensions, h2)"
                        .into(),
                confidence: 0.80,
                attack_id: "T1071.001".into(),
                prefix_only: true,
            },
            Ja4BlocklistEntry {
                fingerprint: "t13i1517h2".into(),
                tool_name: "Cobalt Strike".into(),
                description: "Cobalt Strike beacon without SNI (rare, high confidence)".into(),
                confidence: 0.90,
                attack_id: "T1071.001".into(),
                prefix_only: true,
            },
            // --- Sliver --------------------------------------------------
            Ja4BlocklistEntry {
                fingerprint: "t13d1715h2".into(),
                tool_name: "Sliver".into(),
                description: "Sliver HTTP/HTTPS implant default profile (Go TLS stack)".into(),
                confidence: 0.80,
                attack_id: "T1071.001".into(),
                prefix_only: true,
            },
            Ja4BlocklistEntry {
                fingerprint: "t13d1715h1".into(),
                tool_name: "Sliver".into(),
                description: "Sliver implant with HTTP/1.1 ALPN (Go TLS)".into(),
                confidence: 0.75,
                attack_id: "T1071.001".into(),
                prefix_only: true,
            },
            // --- Metasploit / Meterpreter --------------------------------
            Ja4BlocklistEntry {
                fingerprint: "t12d0812h1".into(),
                tool_name: "Metasploit Meterpreter".into(),
                description:
                    "Meterpreter reverse_https default (TLS 1.2, 8 ciphers, 12 extensions)".into(),
                confidence: 0.80,
                attack_id: "T1071.001".into(),
                prefix_only: true,
            },
            Ja4BlocklistEntry {
                fingerprint: "t12d0812h2".into(),
                tool_name: "Metasploit Meterpreter".into(),
                description: "Meterpreter reverse_https with h2 ALPN".into(),
                confidence: 0.75,
                attack_id: "T1071.001".into(),
                prefix_only: true,
            },
            // --- Havoc C2 ------------------------------------------------
            Ja4BlocklistEntry {
                fingerprint: "t13d1410h2".into(),
                tool_name: "Havoc C2".into(),
                description: "Havoc demon agent default HTTPS profile".into(),
                confidence: 0.80,
                attack_id: "T1071.001".into(),
                prefix_only: true,
            },
            // --- Brute Ratel C4 ------------------------------------------
            Ja4BlocklistEntry {
                fingerprint: "t13d1613h2".into(),
                tool_name: "Brute Ratel C4".into(),
                description: "Brute Ratel C4 default badger profile (TLS 1.3)".into(),
                confidence: 0.80,
                attack_id: "T1071.001".into(),
                prefix_only: true,
            },
            Ja4BlocklistEntry {
                fingerprint: "t12d1613h2".into(),
                tool_name: "Brute Ratel C4".into(),
                description: "Brute Ratel C4 badger (TLS 1.2 fallback)".into(),
                confidence: 0.75,
                attack_id: "T1071.001".into(),
                prefix_only: true,
            },
            // --- PoshC2 --------------------------------------------------
            Ja4BlocklistEntry {
                fingerprint: "t12d0910h1".into(),
                tool_name: "PoshC2".into(),
                description: "PoshC2 implant default (Python TLS, TLS 1.2, 9 ciphers)".into(),
                confidence: 0.75,
                attack_id: "T1071.001".into(),
                prefix_only: true,
            },
            // --- Tor Client ----------------------------------------------
            Ja4BlocklistEntry {
                fingerprint: "t13d1813h2".into(),
                tool_name: "Tor Client".into(),
                description: "Tor Browser default TLS fingerprint".into(),
                confidence: 0.70,
                attack_id: "T1090.003".into(),
                prefix_only: true,
            },
            Ja4BlocklistEntry {
                fingerprint: "t13i1813h2".into(),
                tool_name: "Tor Client".into(),
                description: "Tor Client without SNI (relay connection)".into(),
                confidence: 0.75,
                attack_id: "T1090.003".into(),
                prefix_only: true,
            },
            // --- Crypto Miners -------------------------------------------
            Ja4BlocklistEntry {
                fingerprint: "t12d0507h1".into(),
                tool_name: "XMRig Miner".into(),
                description: "XMRig TLS mining pool connection (minimal cipher set)".into(),
                confidence: 0.70,
                attack_id: "T1496".into(),
                prefix_only: true,
            },
            Ja4BlocklistEntry {
                fingerprint: "t12d0306h1".into(),
                tool_name: "Crypto Miner".into(),
                description: "Generic crypto miner TLS pool connection (very small cipher/ext set)"
                    .into(),
                confidence: 0.60,
                attack_id: "T1496".into(),
                prefix_only: true,
            },
        ];

        for entry in entries {
            if entry.prefix_only {
                prefix_entries.insert(entry.fingerprint.clone(), entry);
            } else {
                full_entries.insert(entry.fingerprint.clone(), entry);
            }
        }

        Self {
            full_entries,
            prefix_entries,
        }
    }

    /// Check a JA4 fingerprint against the blocklist.
    ///
    /// Returns the first matching entry. Full matches take priority over prefix matches.
    pub fn check(&self, ja4: &str) -> Option<&Ja4BlocklistEntry> {
        // Full match first (highest confidence)
        if let Some(entry) = self.full_entries.get(ja4) {
            return Some(entry);
        }
        // Prefix match: extract first segment (before first '_')
        let prefix = ja4.split('_').next().unwrap_or(ja4);
        self.prefix_entries.get(prefix)
    }

    /// Add a custom entry to the blocklist.
    pub fn add_entry(&mut self, entry: Ja4BlocklistEntry) {
        if entry.prefix_only {
            self.prefix_entries.insert(entry.fingerprint.clone(), entry);
        } else {
            self.full_entries.insert(entry.fingerprint.clone(), entry);
        }
    }
}

// ---------------------------------------------------------------------------
// Alert Generation
// ---------------------------------------------------------------------------

/// Check a JA4 fingerprint against the blocklist and generate an alert if matched.
///
/// `conn_metadata` may contain keys like "remote_addr", "pid", "process_name"
/// to enrich the alert.
pub fn check_ja4_alerts(
    fingerprint: &Ja4Fingerprint,
    blocklist: &Ja4Blocklist,
    conn_metadata: &HashMap<String, String>,
) -> Option<Alert> {
    let entry = blocklist.check(&fingerprint.full)?;

    let severity = if entry.confidence >= 0.85 {
        Severity::Critical
    } else if entry.confidence >= 0.70 {
        Severity::High
    } else if entry.confidence >= 0.50 {
        Severity::Medium
    } else {
        Severity::Low
    };

    let is_full_match = blocklist.full_entries.contains_key(&fingerprint.full);
    let match_type = if is_full_match { "full" } else { "prefix" };

    let mut metadata = conn_metadata.clone();
    metadata.insert("ja4".into(), fingerprint.full.clone());
    metadata.insert("ja4_prefix".into(), fingerprint.prefix.clone());
    metadata.insert("matched_tool".into(), entry.tool_name.clone());
    metadata.insert("match_type".into(), match_type.into());
    metadata.insert("confidence".into(), format!("{:.2}", entry.confidence));

    Some(Alert {
        id: Uuid::new_v4(),
        severity,
        kind: "tls_fingerprint_match".into(),
        message: format!(
            "TLS fingerprint matches {} — {} (JA4: {}, match: {})",
            entry.tool_name, entry.description, fingerprint.full, match_type
        ),
        occurred_at: chrono::Utc::now(),
        metadata,
        rule_id: Some("SENT-TLS-001".into()),
        attack_id: Some(entry.attack_id.clone()),
    })
}

// ---------------------------------------------------------------------------
// TLS Client Hello Parser
// ---------------------------------------------------------------------------

/// Parse a TLS Client Hello from raw bytes starting at the TLS record layer.
///
/// Returns `None` if the data is malformed or not a Client Hello.
pub fn parse_client_hello(data: &[u8]) -> Option<TlsClientHello> {
    let mut pos = 0;

    // --- TLS Record Header (5 bytes) ---
    if data.len() < 5 {
        return None;
    }
    let content_type = data[pos];
    if content_type != 0x16 {
        // Not a handshake record
        return None;
    }
    pos += 1;
    // Record-layer version (ignored for fingerprinting; clients may lie here)
    let _record_version = read_u16(data, pos)?;
    pos += 2;
    let record_length = read_u16(data, pos)? as usize;
    pos += 2;

    if data.len() < pos + record_length {
        return None;
    }

    // --- Handshake Header (4 bytes) ---
    if data.len() < pos + 4 {
        return None;
    }
    let handshake_type = data[pos];
    if handshake_type != 0x01 {
        // Not ClientHello
        return None;
    }
    pos += 1;
    let _hs_length = read_u24(data, pos)?;
    pos += 3;

    // --- ClientHello Body ---
    // client_version (2 bytes)
    let client_version = read_u16(data, pos)?;
    pos += 2;

    // random (32 bytes)
    if data.len() < pos + 32 {
        return None;
    }
    pos += 32;

    // session_id
    if pos >= data.len() {
        return None;
    }
    let session_id_len = data[pos] as usize;
    pos += 1;
    if data.len() < pos + session_id_len {
        return None;
    }
    pos += session_id_len;

    // cipher_suites
    if data.len() < pos + 2 {
        return None;
    }
    let cipher_suites_len = read_u16(data, pos)? as usize;
    pos += 2;
    if data.len() < pos + cipher_suites_len || !cipher_suites_len.is_multiple_of(2) {
        return None;
    }
    let mut cipher_suites = Vec::with_capacity(cipher_suites_len / 2);
    let cipher_end = pos + cipher_suites_len;
    while pos < cipher_end {
        cipher_suites.push(read_u16(data, pos)?);
        pos += 2;
    }

    // compression_methods
    if pos >= data.len() {
        return None;
    }
    let comp_len = data[pos] as usize;
    pos += 1;
    if data.len() < pos + comp_len {
        return None;
    }
    pos += comp_len;

    // --- Extensions ---
    let mut extensions = Vec::new();
    let mut sni: Option<String> = None;
    let mut alpn_protocols = Vec::new();
    let mut signature_algos = Vec::new();
    // Track actual TLS version from supported_versions extension
    let mut real_tls_version = client_version;

    if pos + 2 <= data.len() {
        let extensions_len = read_u16(data, pos)? as usize;
        pos += 2;
        let ext_end = pos + extensions_len;
        if ext_end > data.len() {
            return None;
        }

        while pos + 4 <= ext_end {
            let ext_type = read_u16(data, pos)?;
            pos += 2;
            let ext_len = read_u16(data, pos)? as usize;
            pos += 2;
            if pos + ext_len > ext_end {
                return None;
            }
            let ext_data = &data[pos..pos + ext_len];

            extensions.push(ext_type);

            match ext_type {
                // SNI (0x0000)
                0x0000 => {
                    sni = parse_sni(ext_data);
                }
                // ALPN (0x0010)
                0x0010 => {
                    alpn_protocols = parse_alpn(ext_data);
                }
                // signature_algorithms (0x000d)
                0x000d => {
                    signature_algos = parse_sig_algos(ext_data);
                }
                // supported_versions (0x002b)
                0x002b => {
                    if let Some(v) = parse_supported_versions(ext_data) {
                        real_tls_version = v;
                    }
                }
                _ => {}
            }

            pos += ext_len;
        }
    }

    Some(TlsClientHello {
        tls_version: real_tls_version,
        sni,
        cipher_suites,
        extensions,
        signature_algos,
        alpn_protocols,
    })
}

// ---------------------------------------------------------------------------
// Parser helpers
// ---------------------------------------------------------------------------

fn read_u16(data: &[u8], pos: usize) -> Option<u16> {
    if pos + 2 > data.len() {
        return None;
    }
    Some(u16::from_be_bytes([data[pos], data[pos + 1]]))
}

fn read_u24(data: &[u8], pos: usize) -> Option<u32> {
    if pos + 3 > data.len() {
        return None;
    }
    Some((data[pos] as u32) << 16 | (data[pos + 1] as u32) << 8 | data[pos + 2] as u32)
}

fn parse_sni(data: &[u8]) -> Option<String> {
    // SNI extension: u16 list_length, then entries of (u8 type, u16 len, name_bytes)
    if data.len() < 5 {
        return None;
    }
    let _list_len = read_u16(data, 0)?;
    let name_type = data[2];
    if name_type != 0x00 {
        // Only host_name type
        return None;
    }
    let name_len = read_u16(data, 3)? as usize;
    if data.len() < 5 + name_len {
        return None;
    }
    String::from_utf8(data[5..5 + name_len].to_vec()).ok()
}

fn parse_alpn(data: &[u8]) -> Vec<String> {
    // ALPN extension: u16 list_length, then entries of (u8 len, protocol_bytes)
    let mut result = Vec::new();
    if data.len() < 2 {
        return result;
    }
    let list_len = match read_u16(data, 0) {
        Some(v) => v as usize,
        None => return result,
    };
    let mut pos = 2;
    let end = (2 + list_len).min(data.len());
    while pos < end {
        let proto_len = data[pos] as usize;
        pos += 1;
        if pos + proto_len > end {
            break;
        }
        if let Ok(s) = String::from_utf8(data[pos..pos + proto_len].to_vec()) {
            result.push(s);
        }
        pos += proto_len;
    }
    result
}

fn parse_sig_algos(data: &[u8]) -> Vec<u16> {
    // signature_algorithms: u16 list_length, then u16 entries
    let mut result = Vec::new();
    if data.len() < 2 {
        return result;
    }
    let list_len = match read_u16(data, 0) {
        Some(v) => v as usize,
        None => return result,
    };
    let mut pos = 2;
    let end = (2 + list_len).min(data.len());
    while pos + 2 <= end {
        if let Some(v) = read_u16(data, pos) {
            result.push(v);
        }
        pos += 2;
    }
    result
}

fn parse_supported_versions(data: &[u8]) -> Option<u16> {
    // In ClientHello: u8 list_length, then u16 entries. Pick highest non-GREASE.
    if data.is_empty() {
        return None;
    }
    let list_len = data[0] as usize;
    let mut pos = 1;
    let end = (1 + list_len).min(data.len());
    let mut best: Option<u16> = None;
    while pos + 2 <= end {
        let v = read_u16(data, pos)?;
        pos += 2;
        if is_grease(v) {
            continue;
        }
        if best.is_none_or(|b| v > b) {
            best = Some(v);
        }
    }
    best
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper: build a basic TLS 1.3 Client Hello with known values.
    fn sample_hello() -> TlsClientHello {
        TlsClientHello {
            tls_version: 0x0304, // TLS 1.3
            sni: Some("example.com".into()),
            cipher_suites: vec![
                0x1301, 0x1302, 0x1303, 0xc02c, 0xc02b, 0xc030, 0xc02f, 0xcca9, 0xcca8, 0xc013,
                0xc014, 0x009c, 0x009d, 0x002f, 0x0035,
            ],
            extensions: vec![
                0x0000, // SNI
                0x0017, // extended_master_secret
                0xff01, // renegotiation_info
                0x000a, // supported_groups
                0x000b, // ec_point_formats
                0x0023, // session_ticket
                0x0010, // ALPN
                0x0005, // status_request
                0x000d, // signature_algorithms
                0x002b, // supported_versions
                0x002d, // psk_key_exchange_modes
                0x001c, // record_size_limit
                0x0033, // key_share
                0x001b, // compress_certificate
                0x0015, // padding
                0x0012, // signed_certificate_timestamp
            ],
            signature_algos: vec![0x0403, 0x0503, 0x0603],
            alpn_protocols: vec!["h2".into(), "http/1.1".into()],
        }
    }

    #[test]
    fn test_ja4_prefix_format() {
        let hello = sample_hello();
        let fp = compute_ja4(&hello);

        // proto='t', version='13', sni='d', 15 ciphers='15', 16 extensions='16', alpn='h2'
        assert_eq!(fp.prefix, "t13d1516h2");
        assert!(
            fp.full.starts_with("t13d1516h2_"),
            "Full fingerprint should start with prefix: {}",
            fp.full
        );
        // Should have three parts separated by '_'
        let parts: Vec<&str> = fp.full.split('_').collect();
        assert_eq!(parts.len(), 3);
        assert_eq!(parts[1].len(), 12, "Cipher hash should be 12 hex chars");
        assert_eq!(parts[2].len(), 12, "Extension hash should be 12 hex chars");
    }

    #[test]
    fn test_ja4_deterministic() {
        let hello = sample_hello();
        let fp1 = compute_ja4(&hello);
        let fp2 = compute_ja4(&hello);
        assert_eq!(fp1.full, fp2.full, "JA4 must be deterministic");
    }

    #[test]
    fn test_grease_filtering() {
        let mut hello = sample_hello();
        // Add GREASE values — should not change the fingerprint
        let fp_before = compute_ja4(&hello);
        hello.cipher_suites.push(0x0a0a);
        hello.cipher_suites.push(0xfafa);
        hello.extensions.push(0x2a2a);
        let fp_after = compute_ja4(&hello);
        // Prefix cipher/ext counts should be the same (GREASE excluded)
        assert_eq!(fp_before.prefix, fp_after.prefix);
        // Hashes should also be the same
        assert_eq!(fp_before.full, fp_after.full);
    }

    #[test]
    fn test_no_sni_flag() {
        let mut hello = sample_hello();
        hello.sni = None;
        let fp = compute_ja4(&hello);
        assert!(
            fp.prefix.starts_with("t13i"),
            "No SNI should produce 'i' flag: {}",
            fp.prefix
        );
    }

    #[test]
    fn test_no_alpn() {
        let mut hello = sample_hello();
        hello.alpn_protocols.clear();
        let fp = compute_ja4(&hello);
        assert!(
            fp.prefix.ends_with("00"),
            "No ALPN should end with '00': {}",
            fp.prefix
        );
    }

    #[test]
    fn test_http11_alpn() {
        let mut hello = sample_hello();
        hello.alpn_protocols = vec!["http/1.1".into()];
        let fp = compute_ja4(&hello);
        assert!(
            fp.prefix.ends_with("h1"),
            "http/1.1 ALPN should produce 'h1': {}",
            fp.prefix
        );
    }

    #[test]
    fn test_tls12_version() {
        let mut hello = sample_hello();
        hello.tls_version = 0x0303;
        let fp = compute_ja4(&hello);
        assert!(
            fp.prefix.starts_with("t12"),
            "TLS 1.2 should produce '12': {}",
            fp.prefix
        );
    }

    #[test]
    fn test_blocklist_prefix_match() {
        let blocklist = Ja4Blocklist::builtin();
        // Simulate a Cobalt Strike-like fingerprint
        let fake_ja4 = "t13d1517h2_aabbccddeeff_112233445566";
        let result = blocklist.check(fake_ja4);
        assert!(result.is_some(), "Should match Cobalt Strike prefix");
        let entry = result.expect("checked above");
        assert_eq!(entry.tool_name, "Cobalt Strike");
    }

    #[test]
    fn test_blocklist_no_match_for_browser() {
        let blocklist = Ja4Blocklist::builtin();
        // Chrome-like fingerprint with many ciphers and extensions — not in blocklist
        let browser_ja4 = "t13d2024h2_aabbccddeeff_112233445566";
        assert!(
            blocklist.check(browser_ja4).is_none(),
            "Normal browser fingerprint should not match blocklist"
        );
    }

    #[test]
    fn test_blocklist_cobalt_strike_variants() {
        let blocklist = Ja4Blocklist::builtin();
        let cs_variants = [
            "t13d1517h2_anything_anything",
            "t12d1517h2_anything_anything",
            "t13d1516h2_anything_anything",
            "t13i1517h2_anything_anything",
        ];
        for ja4 in &cs_variants {
            let result = blocklist.check(ja4);
            assert!(
                result.is_some(),
                "Cobalt Strike variant '{}' should be detected",
                ja4
            );
            assert_eq!(result.expect("checked above").tool_name, "Cobalt Strike");
        }
    }

    #[test]
    fn test_alert_generation() {
        let blocklist = Ja4Blocklist::builtin();
        let fp = Ja4Fingerprint {
            full: "t13d1517h2_aabbccddeeff_112233445566".into(),
            prefix: "t13d1517h2".into(),
        };
        let meta = HashMap::from([
            ("remote_addr".into(), "192.168.1.100:443".into()),
            ("pid".into(), "1234".into()),
        ]);
        let alert = check_ja4_alerts(&fp, &blocklist, &meta);
        assert!(alert.is_some());
        let alert = alert.expect("checked above");
        assert_eq!(alert.kind, "tls_fingerprint_match");
        assert_eq!(alert.rule_id.as_deref(), Some("SENT-TLS-001"));
        assert!(alert.metadata.contains_key("ja4"));
        assert!(alert.metadata.contains_key("matched_tool"));
        assert_eq!(
            alert.metadata.get("remote_addr").map(|s| s.as_str()),
            Some("192.168.1.100:443")
        );
    }

    #[test]
    fn test_alert_not_generated_for_clean_fingerprint() {
        let blocklist = Ja4Blocklist::builtin();
        let fp = Ja4Fingerprint {
            full: "t13d2024h2_aabbccddeeff_112233445566".into(),
            prefix: "t13d2024h2".into(),
        };
        let meta = HashMap::new();
        assert!(check_ja4_alerts(&fp, &blocklist, &meta).is_none());
    }

    #[test]
    fn test_parse_client_hello_minimal() {
        // Build a minimal valid TLS ClientHello packet
        let packet = build_test_client_hello();
        let hello = parse_client_hello(&packet);
        assert!(hello.is_some(), "Should parse a valid ClientHello");
        let hello = hello.expect("checked above");
        assert_eq!(hello.tls_version, 0x0303); // TLS 1.2
        assert!(!hello.cipher_suites.is_empty());
    }

    #[test]
    fn test_parse_client_hello_invalid_type() {
        // Application data instead of handshake
        let data = [0x17, 0x03, 0x03, 0x00, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00];
        assert!(parse_client_hello(&data).is_none());
    }

    #[test]
    fn test_parse_client_hello_too_short() {
        let data = [0x16, 0x03, 0x03];
        assert!(parse_client_hello(&data).is_none());
    }

    #[test]
    fn test_end_to_end_compute_from_parsed() {
        let packet = build_test_client_hello();
        let hello = parse_client_hello(&packet).expect("valid packet");
        let fp = compute_ja4(&hello);
        // Should produce a valid JA4 string with 3 parts
        let parts: Vec<&str> = fp.full.split('_').collect();
        assert_eq!(parts.len(), 3);
        assert!(!fp.prefix.is_empty());
    }

    /// Build a minimal but valid TLS 1.2 ClientHello byte sequence for testing.
    fn build_test_client_hello() -> Vec<u8> {
        let mut buf = Vec::new();

        // We'll build the ClientHello body first, then wrap it
        let mut ch_body = Vec::new();

        // client_version: TLS 1.2
        ch_body.extend_from_slice(&[0x03, 0x03]);
        // random: 32 bytes of zeros
        ch_body.extend_from_slice(&[0u8; 32]);
        // session_id: length 0
        ch_body.push(0x00);
        // cipher_suites: 3 ciphers = 6 bytes
        ch_body.extend_from_slice(&[0x00, 0x06]); // length
        ch_body.extend_from_slice(&[0x13, 0x01]); // TLS_AES_128_GCM_SHA256
        ch_body.extend_from_slice(&[0xc0, 0x2f]); // TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
        ch_body.extend_from_slice(&[0x00, 0x2f]); // TLS_RSA_WITH_AES_128_CBC_SHA
                                                  // compression_methods: 1 byte (null)
        ch_body.push(0x01);
        ch_body.push(0x00);

        // Extensions
        let mut exts = Vec::new();
        // SNI extension (type=0x0000)
        {
            let hostname = b"test.example.com";
            let mut sni_data = Vec::new();
            // server_name_list length
            let entry_len = 1 + 2 + hostname.len(); // type + len + name
            sni_data.extend_from_slice(&(entry_len as u16).to_be_bytes());
            sni_data.push(0x00); // host_name type
            sni_data.extend_from_slice(&(hostname.len() as u16).to_be_bytes());
            sni_data.extend_from_slice(hostname);
            exts.extend_from_slice(&[0x00, 0x00]); // extension type
            exts.extend_from_slice(&(sni_data.len() as u16).to_be_bytes());
            exts.extend_from_slice(&sni_data);
        }
        // supported_groups extension (type=0x000a)
        {
            let groups: &[u8] = &[0x00, 0x04, 0x00, 0x17, 0x00, 0x18]; // 2 groups
            exts.extend_from_slice(&[0x00, 0x0a]);
            exts.extend_from_slice(&(groups.len() as u16).to_be_bytes());
            exts.extend_from_slice(groups);
        }
        // signature_algorithms (type=0x000d)
        {
            let algos: &[u8] = &[0x00, 0x04, 0x04, 0x03, 0x05, 0x03]; // 2 algos
            exts.extend_from_slice(&[0x00, 0x0d]);
            exts.extend_from_slice(&(algos.len() as u16).to_be_bytes());
            exts.extend_from_slice(algos);
        }

        ch_body.extend_from_slice(&(exts.len() as u16).to_be_bytes());
        ch_body.extend_from_slice(&exts);

        // Handshake header: type=0x01 (ClientHello), length (3 bytes)
        let mut handshake = Vec::new();
        handshake.push(0x01);
        let len = ch_body.len() as u32;
        handshake.push((len >> 16) as u8);
        handshake.push((len >> 8) as u8);
        handshake.push(len as u8);
        handshake.extend_from_slice(&ch_body);

        // TLS record header: type=0x16 (Handshake), version=0x0301, length
        buf.push(0x16);
        buf.extend_from_slice(&[0x03, 0x01]); // record version
        buf.extend_from_slice(&(handshake.len() as u16).to_be_bytes());
        buf.extend_from_slice(&handshake);

        buf
    }
}
