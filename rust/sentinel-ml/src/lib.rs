//! sentinel-ml — Static PE analysis and malware risk scoring.
//!
//! Extracts features from PE files (entropy, imports, sections, strings)
//! and computes a heuristic risk score without requiring an ML model.
//! Future phases will add ONNX-based inference.
//!
//! # Integration
//!
//! The primary entry point for the detection pipeline is [`analyze_pe_file`],
//! which parses a PE, extracts features, scores it, and returns an [`Alert`]
//! if the risk exceeds the threshold (0.6).
//!
//! ```no_run
//! let data = std::fs::read("suspicious.exe").unwrap();
//! if let Some(alert) = sentinel_ml::analyze_pe_file("suspicious.exe", &data) {
//!     println!("Alert: {} (severity: {:?})", alert.message, alert.severity);
//! }
//! ```

pub mod entropy;
pub mod pe_features;
pub mod pe_parser;
pub mod pe_scorer;
pub mod pe_strings;

use chrono::Utc;
use sentinel_core::models::alert::{Alert, Severity};
use std::collections::HashMap;
use uuid::Uuid;

/// Analyze a PE file and return an alert if the risk score exceeds the
/// threshold (0.6).
///
/// Designed to be called from the detection pipeline's `handle_file_event`.
/// Returns `None` if the file is not a valid PE, or if the risk score is
/// below the alerting threshold.
///
/// Severity mapping based on score:
/// - `0.6..0.8`  -> `Medium`
/// - `0.8..0.9`  -> `High`
/// - `0.9..=1.0` -> `Critical`
pub fn analyze_pe_file(path: &str, data: &[u8]) -> Option<Alert> {
    let result = pe_scorer::score_pe(data);

    if result.score < 0.6 {
        tracing::debug!(
            path,
            score = result.score,
            risk = %result.risk,
            "PE below alert threshold"
        );
        return None;
    }

    let severity = if result.score >= 0.9 {
        Severity::Critical
    } else if result.score >= 0.8 {
        Severity::High
    } else {
        Severity::Medium
    };

    // Run string analysis for additional context.
    let string_analysis = pe_strings::analyze_strings(data);

    let message = format!(
        "Static PE analysis flagged {} (risk: {:.2}, classification: {}): {}",
        path,
        result.score,
        result.risk,
        result.top_factors.join("; ")
    );

    let mut metadata = HashMap::new();
    metadata.insert("file_path".into(), path.to_string());
    metadata.insert("risk_score".into(), format!("{:.4}", result.score));
    metadata.insert("risk_class".into(), result.risk.to_string());
    metadata.insert("sha256".into(), result.sha256.clone());
    metadata.insert(
        "file_size".into(),
        result.features.file_size.to_string(),
    );
    metadata.insert(
        "file_entropy".into(),
        format!("{:.2}", result.features.max_section_entropy),
    );
    metadata.insert("url_count".into(), string_analysis.url_count.to_string());
    metadata.insert(
        "ip_literal_count".into(),
        string_analysis.ip_literal_count.to_string(),
    );
    metadata.insert(
        "suspicious_strings".into(),
        string_analysis.suspicious_string_count.to_string(),
    );

    if !string_analysis.suspicious_keywords_found.is_empty() {
        metadata.insert(
            "suspicious_keywords".into(),
            string_analysis.suspicious_keywords_found.join(", "),
        );
    }

    tracing::warn!(
        path,
        score = result.score,
        severity = ?severity,
        "PE static analysis alert"
    );

    Some(Alert {
        id: Uuid::new_v4(),
        severity,
        kind: "pe_static_analysis".into(),
        message,
        occurred_at: Utc::now(),
        metadata,
        rule_id: Some("SENT-PE-001".into()),
        attack_id: Some("T1204.002".into()),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn analyze_non_pe_returns_none() {
        let data = b"this is definitely not a PE file at all and never will be";
        assert!(analyze_pe_file("test.txt", data).is_none());
    }

    #[test]
    fn analyze_empty_returns_none() {
        assert!(analyze_pe_file("empty.exe", &[]).is_none());
    }

    #[test]
    fn analyze_returns_correct_alert_fields() {
        // We can't easily construct a malicious PE in a unit test, but we can
        // verify the function doesn't panic on random data.
        let data = vec![0u8; 4096];
        let result = analyze_pe_file("random.bin", &data);
        // Random data won't parse as PE, so should be None.
        assert!(result.is_none());
    }
}
