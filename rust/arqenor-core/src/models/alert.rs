use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Alert {
    pub id: Uuid,
    pub severity: Severity,
    pub kind: String,
    pub message: String,
    pub occurred_at: DateTime<Utc>,
    pub metadata: HashMap<String, String>,
    pub rule_id: Option<String>,
    pub attack_id: Option<String>,
}

/// Replace ASCII control characters (`< 0x20`, plus `\x7F` DEL) with `'_'`
/// so that values produced from untrusted sources — process command lines,
/// IOC feed contents, file paths chosen by an attacker — cannot inject CR/LF
/// pairs into structured log lines or SSE response bodies (response splitting,
/// log injection).
///
/// The horizontal tab (`\t`) is preserved because it is benign and present in
/// many legitimate command lines / TSV-like outputs. Newlines (`\n`, `\r`),
/// NUL, escape, and the rest of C0 are stripped.
///
/// This is a *replacement*, not an *escape*: callers do not need to know
/// whether their downstream sink is a JSON stringifier, an SSE writer, or a
/// shell — control characters are removed unconditionally.
///
/// # Examples
///
/// ```
/// use arqenor_core::models::alert::sanitize_metadata_value;
/// assert_eq!(sanitize_metadata_value("clean"), "clean");
/// assert_eq!(sanitize_metadata_value("a\nb\rc"), "a_b_c");
/// assert_eq!(sanitize_metadata_value("tab\there"), "tab\there");
/// ```
pub fn sanitize_metadata_value(s: &str) -> String {
    s.chars()
        .map(|c| {
            // Preserve TAB; replace every other ASCII control char (including
            // DEL = 0x7F, which `is_control` returns true for).
            if c.is_control() && c != '\t' {
                '_'
            } else {
                c
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sanitize_replaces_newlines() {
        assert_eq!(sanitize_metadata_value("a\nb"), "a_b");
        assert_eq!(sanitize_metadata_value("a\r\nb"), "a__b");
    }

    #[test]
    fn sanitize_preserves_tab_and_printable() {
        assert_eq!(
            sanitize_metadata_value("tab\there with \"quotes\" and {json}"),
            "tab\there with \"quotes\" and {json}"
        );
    }

    #[test]
    fn sanitize_strips_nul_and_del() {
        assert_eq!(sanitize_metadata_value("a\0b\x7Fc"), "a_b_c");
    }

    #[test]
    fn sanitize_handles_unicode() {
        // Non-ASCII (printable) Unicode must pass through unchanged.
        assert_eq!(sanitize_metadata_value("héllo→世界"), "héllo→世界");
    }

    #[test]
    fn sanitize_strips_escape_sequences() {
        // ANSI escape sequences begin with ESC (0x1B) — sanitised to '_'.
        assert_eq!(
            sanitize_metadata_value("\x1b[31mred\x1b[0m"),
            "_[31mred_[0m"
        );
    }
}
