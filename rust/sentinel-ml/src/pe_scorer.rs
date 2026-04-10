//! High-level PE risk scoring API.
//!
//! Ties together PE parsing, feature extraction, and risk classification
//! into a single `score_pe()` / `score_pe_file()` entry point.

use std::path::Path;

use sha2::{Digest, Sha256};

use crate::pe_features::{self, PeFeatures};
use crate::pe_parser;

/// Risk classification based on overall score.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
pub enum PeRisk {
    /// Score < 0.3 — no significant risk indicators.
    Clean,
    /// Score 0.3–0.5 — minor anomalies, likely benign.
    Low,
    /// Score 0.5–0.7 — multiple risk indicators, warrants investigation.
    Medium,
    /// Score 0.7–0.85 — strong malware indicators.
    High,
    /// Score >= 0.85 — very likely malicious.
    Malicious,
}

impl std::fmt::Display for PeRisk {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PeRisk::Clean => write!(f, "Clean"),
            PeRisk::Low => write!(f, "Low"),
            PeRisk::Medium => write!(f, "Medium"),
            PeRisk::High => write!(f, "High"),
            PeRisk::Malicious => write!(f, "Malicious"),
        }
    }
}

/// Complete PE risk assessment result.
#[derive(Debug, Clone, serde::Serialize)]
pub struct PeScore {
    /// Risk classification.
    pub risk: PeRisk,
    /// Numeric score (0.0–1.0).
    pub score: f64,
    /// Extracted features used for scoring.
    pub features: PeFeatures,
    /// Top risk factors in human-readable form (up to 5).
    pub top_factors: Vec<String>,
    /// SHA-256 hash of the input file.
    pub sha256: String,
}

/// Score a PE file from raw bytes.
///
/// Returns a [`PeScore`] with risk classification, numeric score, extracted
/// features, and human-readable top risk factors. Invalid PEs return a
/// `Clean` classification with score 0.0.
pub fn score_pe(data: &[u8]) -> PeScore {
    let sha256 = compute_sha256(data);

    let pe = pe_parser::parse_pe(data);
    if !pe.is_valid {
        return PeScore {
            risk: PeRisk::Clean,
            score: 0.0,
            features: PeFeatures::default(),
            top_factors: vec!["Invalid PE file".into()],
            sha256,
        };
    }

    let features = pe_features::extract_features(data, &pe);
    let risk = classify(features.overall_risk);
    let top_factors = build_top_factors(&features);

    PeScore {
        risk,
        score: features.overall_risk,
        features,
        top_factors,
        sha256,
    }
}

/// Score a PE file from a path on disk.
///
/// Reads the entire file into memory, then delegates to [`score_pe`].
pub fn score_pe_file(path: &Path) -> Result<PeScore, std::io::Error> {
    let data = std::fs::read(path)?;
    Ok(score_pe(&data))
}

/// Map a numeric score to a risk classification.
fn classify(score: f64) -> PeRisk {
    if score >= 0.85 {
        PeRisk::Malicious
    } else if score >= 0.7 {
        PeRisk::High
    } else if score >= 0.5 {
        PeRisk::Medium
    } else if score >= 0.3 {
        PeRisk::Low
    } else {
        PeRisk::Clean
    }
}

/// Build human-readable risk factor descriptions, sorted by significance.
fn build_top_factors(f: &PeFeatures) -> Vec<String> {
    let mut factors: Vec<(f64, String)> = Vec::new();

    // Entropy factors
    if f.max_section_entropy >= 7.5 {
        factors.push((
            0.9,
            format!(
                "High entropy section ({:.1} bits/byte — likely packed/encrypted)",
                f.max_section_entropy
            ),
        ));
    } else if f.max_section_entropy >= 7.0 {
        factors.push((
            0.6,
            format!(
                "Elevated entropy section ({:.1} bits/byte — possibly compressed)",
                f.max_section_entropy
            ),
        ));
    }

    // RWX sections
    if f.rwx_section_count > 0 {
        factors.push((
            0.85,
            format!(
                "{} RWX section(s) (read-write-execute — abnormal, self-modifying code)",
                f.rwx_section_count
            ),
        ));
    }

    // Injection capability
    let injection_funcs: Vec<&str> = f
        .suspicious_imports
        .iter()
        .filter(|s| {
            matches!(
                s.as_str(),
                "VirtualAllocEx"
                    | "WriteProcessMemory"
                    | "CreateRemoteThread"
                    | "NtCreateThreadEx"
                    | "QueueUserAPC"
                    | "NtUnmapViewOfSection"
                    | "SetThreadContext"
            )
        })
        .map(|s| s.as_str())
        .collect();

    if injection_funcs.len() >= 2 {
        factors.push((
            0.8,
            format!(
                "{} imports (process injection capability)",
                injection_funcs.join(" + ")
            ),
        ));
    } else if !injection_funcs.is_empty() {
        factors.push((
            0.5,
            format!("{} import (potential injection vector)", injection_funcs[0]),
        ));
    }

    // Anti-debug imports
    let anti_debug: Vec<&str> = f
        .suspicious_imports
        .iter()
        .filter(|s| {
            matches!(
                s.as_str(),
                "IsDebuggerPresent"
                    | "CheckRemoteDebuggerPresent"
                    | "NtQueryInformationProcess"
            )
        })
        .map(|s| s.as_str())
        .collect();

    if !anti_debug.is_empty() {
        factors.push((
            0.4,
            format!("Anti-debug: {} import(s)", anti_debug.join(", ")),
        ));
    }

    // Abnormal section names
    if f.abnormal_section_names > 0 {
        factors.push((
            0.35,
            format!(
                "{} non-standard section name(s) (packer/protector indicator)",
                f.abnormal_section_names
            ),
        ));
    }

    // No debug info + no relocations
    if !f.has_debug_info && !f.has_relocations {
        factors.push((0.25, "No debug info + no relocations (stripped binary)".into()));
    }

    // Overlay
    if f.overlay_size > 1024 {
        factors.push((
            0.3,
            format!(
                "Overlay data ({} bytes after last section — potential payload)",
                f.overlay_size
            ),
        ));
    }

    // Network + crypto combo
    if f.has_network_imports && f.has_crypto_imports {
        factors.push((
            0.35,
            "Network + cryptography imports (potential C2/exfiltration capability)".into(),
        ));
    }

    // Zero timestamp
    if f.timestamp_is_zero {
        factors.push((0.2, "Zero PE timestamp (compilation date erased)".into()));
    }

    // TLS callbacks
    if f.has_tls {
        factors.push((
            0.3,
            "TLS directory present (TLS callbacks can execute before main)".into(),
        ));
    }

    // Sort by significance (descending) and take top 5.
    factors.sort_by(|a, b| b.0.partial_cmp(&a.0).unwrap_or(std::cmp::Ordering::Equal));
    factors.into_iter().take(5).map(|(_, desc)| desc).collect()
}

/// Compute SHA-256 hash of raw bytes.
fn compute_sha256(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hex::encode(hasher.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classify_thresholds() {
        assert_eq!(classify(0.0), PeRisk::Clean);
        assert_eq!(classify(0.29), PeRisk::Clean);
        assert_eq!(classify(0.3), PeRisk::Low);
        assert_eq!(classify(0.5), PeRisk::Medium);
        assert_eq!(classify(0.7), PeRisk::High);
        assert_eq!(classify(0.85), PeRisk::Malicious);
        assert_eq!(classify(1.0), PeRisk::Malicious);
    }

    #[test]
    fn empty_data_scores_clean() {
        let result = score_pe(&[]);
        assert_eq!(result.risk, PeRisk::Clean);
        assert_eq!(result.score, 0.0);
        assert!(!result.sha256.is_empty());
    }

    #[test]
    fn sha256_is_correct() {
        let data = b"hello world";
        let result = score_pe(data);
        // Known SHA-256 of "hello world"
        assert_eq!(
            result.sha256,
            "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
        );
    }
}
