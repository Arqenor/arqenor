//! String extraction and analysis for PE files.
//!
//! Extracts ASCII and UTF-16LE strings from raw PE bytes, then classifies
//! them into categories relevant for threat detection: URLs, IP literals,
//! registry paths, base64 blobs, and suspicious tool/technique keywords.

use regex::Regex;
use std::sync::OnceLock;

/// Results of string analysis on a PE file.
#[derive(Debug, Clone, Default, serde::Serialize)]
pub struct StringAnalysis {
    pub url_count: u32,
    pub ip_literal_count: u32,
    pub registry_path_count: u32,
    pub base64_blob_count: u32,
    pub suspicious_string_count: u32,
    /// The actual suspicious keywords found (deduplicated).
    pub suspicious_keywords_found: Vec<String>,
}

/// Known-suspicious keywords (lowercased for comparison).
const SUSPICIOUS_KEYWORDS: &[&str] = &[
    "mimikatz",
    "cobalt",
    "metasploit",
    "invoke-expression",
    "powershell -enc",
    "net user",
    "whoami",
    "cmd.exe /c",
    "rundll32",
    "regsvr32",
    "mshta",
    "certutil -decode",
    "bitsadmin /transfer",
];

fn url_regex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"https?://[^\s\x00]{4,}").expect("valid regex"))
}

fn ip_regex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}").expect("valid regex"))
}

fn base64_regex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"[A-Za-z0-9+/=]{40,}").expect("valid regex"))
}

fn registry_regex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r"(?i)(HKLM\\|HKCU\\|HKEY_LOCAL_MACHINE\\|HKEY_CURRENT_USER\\|CurrentVersion\\Run)",
        )
        .expect("valid regex")
    })
}

/// Extract printable ASCII strings of at least `min_len` characters.
pub fn extract_ascii_strings(data: &[u8], min_len: usize) -> Vec<String> {
    let mut strings = Vec::new();
    let mut current = Vec::new();

    for &b in data {
        if b.is_ascii_graphic() || b == b' ' {
            current.push(b);
        } else {
            if current.len() >= min_len {
                // SAFETY: we only pushed ASCII bytes.
                strings.push(String::from_utf8_lossy(&current).into_owned());
            }
            current.clear();
        }
    }
    if current.len() >= min_len {
        strings.push(String::from_utf8_lossy(&current).into_owned());
    }
    strings
}

/// Extract printable UTF-16LE strings of at least `min_len` characters.
pub fn extract_utf16_strings(data: &[u8], min_len: usize) -> Vec<String> {
    let mut strings = Vec::new();
    let mut current: Vec<u16> = Vec::new();

    let mut i = 0;
    while i + 1 < data.len() {
        let ch = u16::from_le_bytes([data[i], data[i + 1]]);
        if ch >= 0x20 && ch < 0x7F {
            current.push(ch);
        } else {
            if current.len() >= min_len {
                strings.push(String::from_utf16_lossy(&current));
            }
            current.clear();
        }
        i += 2;
    }
    if current.len() >= min_len {
        strings.push(String::from_utf16_lossy(&current));
    }
    strings
}

/// Analyze all extracted strings and return classification counts.
///
/// Extracts both ASCII and UTF-16LE strings (minimum 6 characters) from the
/// raw file data, then counts occurrences of URLs, IP literals, registry paths,
/// base64 blobs, and suspicious keywords.
pub fn analyze_strings(data: &[u8]) -> StringAnalysis {
    let mut all_strings = extract_ascii_strings(data, 6);
    let utf16 = extract_utf16_strings(data, 6);
    all_strings.extend(utf16);

    let mut result = StringAnalysis::default();

    for s in &all_strings {
        if url_regex().is_match(s) {
            result.url_count += 1;
        }
        if ip_regex().is_match(s) {
            result.ip_literal_count += 1;
        }
        if registry_regex().is_match(s) {
            result.registry_path_count += 1;
        }
        if base64_regex().is_match(s) {
            result.base64_blob_count += 1;
        }

        let lower = s.to_ascii_lowercase();
        for kw in SUSPICIOUS_KEYWORDS {
            if lower.contains(kw) {
                result.suspicious_string_count += 1;
                if !result.suspicious_keywords_found.contains(&kw.to_string()) {
                    result.suspicious_keywords_found.push(kw.to_string());
                }
                break; // count each string only once
            }
        }
    }

    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_ascii_strings_basic() {
        let data = b"hello world\x00short\x00this is a longer string\x00ab\x00";
        let strings = extract_ascii_strings(data, 6);
        assert_eq!(strings.len(), 2);
        assert_eq!(strings[0], "hello world");
        assert_eq!(strings[1], "this is a longer string");
    }

    #[test]
    fn extract_ascii_strings_min_length_boundary() {
        let data = b"abcdef\x00abcde\x00";
        let strings = extract_ascii_strings(data, 6);
        assert_eq!(strings.len(), 1);
        assert_eq!(strings[0], "abcdef");
    }

    #[test]
    fn url_detection() {
        // Two separate strings, each containing a URL.
        let data = b"some text https://evil.com/payload.exe\x00another http://10.0.0.1/c2 string\x00";
        let analysis = analyze_strings(data);
        assert_eq!(analysis.url_count, 2);
    }

    #[test]
    fn ip_detection() {
        // Two separate strings, each containing an IP.
        let data = b"connecting to 192.168.1.100\x00also found 10.0.0.1 for c2\x00";
        let analysis = analyze_strings(data);
        assert_eq!(analysis.ip_literal_count, 2);
    }

    #[test]
    fn suspicious_keyword_detection() {
        let data =
            b"invoke mimikatz to dump creds\x00powershell -enc base64blob\x00normal string here\x00";
        let analysis = analyze_strings(data);
        assert_eq!(analysis.suspicious_string_count, 2);
        assert!(analysis.suspicious_keywords_found.contains(&"mimikatz".to_string()));
        assert!(analysis
            .suspicious_keywords_found
            .contains(&"powershell -enc".to_string()));
    }

    #[test]
    fn base64_blob_detection() {
        let blob = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqr==";
        let data = format!("prefix {blob} suffix\x00");
        let analysis = analyze_strings(data.as_bytes());
        assert_eq!(analysis.base64_blob_count, 1);
    }

    #[test]
    fn registry_path_detection() {
        let data = b"writing to HKLM\\Software\\Microsoft and HKCU\\CurrentVersion\\Run\x00";
        let analysis = analyze_strings(data);
        assert!(analysis.registry_path_count >= 1);
    }

    #[test]
    fn empty_data_returns_zeroes() {
        let analysis = analyze_strings(&[]);
        assert_eq!(analysis.url_count, 0);
        assert_eq!(analysis.ip_literal_count, 0);
        assert_eq!(analysis.registry_path_count, 0);
        assert_eq!(analysis.base64_blob_count, 0);
        assert_eq!(analysis.suspicious_string_count, 0);
    }

    #[test]
    fn utf16_string_extraction() {
        // "hello" in UTF-16LE: h\0 e\0 l\0 l\0 o\0 \0\0 (null terminator)
        let data: Vec<u8> = "hello world!!"
            .encode_utf16()
            .flat_map(|c| c.to_le_bytes())
            .chain([0, 0]) // null terminator
            .collect();
        let strings = extract_utf16_strings(&data, 6);
        assert_eq!(strings.len(), 1);
        assert_eq!(strings[0], "hello world!!");
    }
}
