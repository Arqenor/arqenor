//! Network-based detection rules: C2 beaconing, DNS tunneling, DGA detection.

use crate::models::alert::{Alert, Severity};
use crate::models::network::{BeaconScore, DnsAnomalyScore, DnsQuery, FlowRecord};
use chrono::Utc;
use std::collections::HashMap;
use uuid::Uuid;

// ===========================================================================
// Beaconing analysis
// ===========================================================================

/// Analyze flow records for C2-like beaconing behaviour.
///
/// For each `FlowRecord` with >= 5 timestamps the function computes the
/// inter-connection intervals, their mean, standard deviation and coefficient
/// of variation (CV).  A low CV signals very regular timing — a hallmark of
/// automated C2 beacons.
pub fn analyze_beaconing(flows: &[FlowRecord]) -> Vec<BeaconScore> {
    let mut scores: Vec<BeaconScore> = Vec::new();

    for flow in flows {
        if flow.timestamps.len() < 5 {
            continue;
        }

        // Sort timestamps (clone so we don't require &mut).
        let mut ts: Vec<i64> = flow
            .timestamps
            .iter()
            .map(|t| t.timestamp_millis())
            .collect();
        ts.sort_unstable();

        // Compute intervals in milliseconds.
        let intervals: Vec<f64> = ts.windows(2).map(|w| (w[1] - w[0]) as f64).collect();

        let n = intervals.len() as f64;
        let mean = intervals.iter().sum::<f64>() / n;

        let variance = intervals.iter().map(|i| (i - mean).powi(2)).sum::<f64>() / n;
        let stddev = variance.sqrt();

        let cv = if mean > 0.0 { stddev / mean } else { 1.0 };

        // Score based on coefficient of variation.
        let mut score = if cv < 0.1 {
            0.9
        } else if cv < 0.2 {
            0.7
        } else if cv < 0.3 {
            0.5
        } else {
            0.2
        };

        // Boost score for high connection counts (sustained beaconing).
        if flow.conn_count > 20 {
            score = (score + 0.1_f64).min(1.0);
        }

        scores.push(BeaconScore {
            flow: flow.key.clone(),
            connection_count: flow.conn_count,
            interval_mean_ms: mean,
            interval_stddev_ms: stddev,
            coefficient_of_variation: cv,
            score,
        });
    }

    // Sort by score descending.
    scores.sort_by(|a, b| b.score.partial_cmp(&a.score).unwrap_or(std::cmp::Ordering::Equal));
    scores
}

/// Generate alerts for beacon scores exceeding the given threshold.
pub fn beacon_alerts(scores: &[BeaconScore], threshold: f64) -> Vec<Alert> {
    scores
        .iter()
        .filter(|s| s.score > threshold)
        .map(|s| {
            let mut metadata = HashMap::new();
            metadata.insert("dst_ip".into(), s.flow.dst_ip.to_string());
            metadata.insert("dst_port".into(), s.flow.dst_port.to_string());
            metadata.insert("proto".into(), s.flow.proto.clone());
            metadata.insert("score".into(), format!("{:.2}", s.score));
            metadata.insert(
                "cv".into(),
                format!("{:.2}", s.coefficient_of_variation),
            );

            Alert {
                id: Uuid::new_v4(),
                severity: Severity::High,
                kind: "c2_beacon".into(),
                message: format!(
                    "Potential C2 beaconing: {}:{} \u{2014} {} connections, CV={:.2}",
                    s.flow.dst_ip,
                    s.flow.dst_port,
                    s.connection_count,
                    s.coefficient_of_variation,
                ),
                occurred_at: Utc::now(),
                metadata,
                rule_id: Some("SENT-NET-001".into()),
                attack_id: Some("T1071".into()),
            }
        })
        .collect()
}

// ===========================================================================
// Shannon entropy
// ===========================================================================

/// Standard Shannon entropy on characters — returns bits per character.
pub fn shannon_entropy(s: &str) -> f64 {
    if s.is_empty() {
        return 0.0;
    }

    let len = s.len() as f64;
    let mut freq: HashMap<char, usize> = HashMap::new();
    for c in s.chars() {
        *freq.entry(c).or_insert(0) += 1;
    }

    freq.values()
        .map(|&count| {
            let p = count as f64 / len;
            -p * p.log2()
        })
        .sum()
}

// ===========================================================================
// DNS tunneling analysis
// ===========================================================================

/// Extract the base domain (last two labels) from an FQDN.
///
/// Examples:
///   - `"sub.evil.com"`  -> `"evil.com"`
///   - `"a.b.c.evil.com"` -> `"evil.com"`
///   - `"evil.com"` -> `"evil.com"`
fn extract_base_domain(fqdn: &str) -> &str {
    let fqdn = fqdn.trim_end_matches('.');
    let parts: Vec<&str> = fqdn.rsplitn(3, '.').collect();
    if parts.len() >= 2 {
        // parts[0] = TLD, parts[1] = SLD, parts[2] = rest (if any)
        // We need the offset into the original string.
        let base_len = parts[0].len() + 1 + parts[1].len(); // "sld.tld"
        &fqdn[fqdn.len() - base_len..]
    } else {
        fqdn
    }
}

/// Extract the subdomain portion from an FQDN (everything before the base
/// domain).
///
/// Examples:
///   - `"sub.evil.com"` -> `"sub"`
///   - `"a.b.c.evil.com"` -> `"a.b.c"`
///   - `"evil.com"` -> `""`
fn extract_subdomain(fqdn: &str) -> &str {
    let fqdn = fqdn.trim_end_matches('.');
    let base = extract_base_domain(fqdn);
    if fqdn.len() > base.len() + 1 {
        &fqdn[..fqdn.len() - base.len() - 1]
    } else {
        ""
    }
}

/// Analyze DNS queries for tunneling indicators.
///
/// Groups queries by base domain, then for each domain with >= 10 queries
/// computes:
///   - Unique subdomain count
///   - Average subdomain length
///   - Average Shannon entropy of subdomains
///   - Weighted tunneling score
pub fn analyze_dns_tunneling(queries: &[DnsQuery]) -> Vec<DnsAnomalyScore> {
    // Group queries by base domain.
    let mut groups: HashMap<String, Vec<&DnsQuery>> = HashMap::new();
    for q in queries {
        let base = extract_base_domain(&q.domain).to_lowercase();
        groups.entry(base).or_default().push(q);
    }

    let mut results: Vec<DnsAnomalyScore> = Vec::new();

    for (base_domain, group) in &groups {
        if group.len() < 10 {
            continue;
        }

        let mut unique_subs: std::collections::HashSet<String> = std::collections::HashSet::new();
        let mut total_len: f64 = 0.0;
        let mut total_entropy: f64 = 0.0;
        let mut sub_count: u32 = 0;

        for q in group {
            let sub = extract_subdomain(&q.domain);
            if !sub.is_empty() {
                unique_subs.insert(sub.to_lowercase());
                total_len += sub.len() as f64;
                total_entropy += shannon_entropy(sub);
                sub_count += 1;
            }
        }

        let avg_len = if sub_count > 0 {
            total_len / sub_count as f64
        } else {
            0.0
        };
        let avg_entropy = if sub_count > 0 {
            total_entropy / sub_count as f64
        } else {
            0.0
        };

        let query_count = group.len() as u32;
        let unique_count = unique_subs.len() as u32;
        let unique_ratio = if query_count > 0 {
            unique_count as f64 / query_count as f64
        } else {
            0.0
        };

        // Weighted tunneling score (each indicator contributes up to 0.25).
        let mut tunneling_score = 0.0_f64;
        if avg_len > 30.0 {
            tunneling_score += 0.25;
        }
        if avg_entropy > 3.5 {
            tunneling_score += 0.25;
        }
        if unique_ratio > 0.8 {
            tunneling_score += 0.25;
        }
        if query_count > 100 {
            tunneling_score += 0.25;
        }

        results.push(DnsAnomalyScore {
            domain: base_domain.clone(),
            query_count,
            unique_subdomains: unique_count,
            avg_subdomain_len: avg_len,
            avg_entropy,
            tunneling_score,
            dga_score: 0.0, // populated separately via score_dga
        });
    }

    // Sort by tunneling_score descending.
    results.sort_by(|a, b| {
        b.tunneling_score
            .partial_cmp(&a.tunneling_score)
            .unwrap_or(std::cmp::Ordering::Equal)
    });
    results
}

/// Generate alerts for DNS tunneling scores exceeding the given threshold.
pub fn dns_tunneling_alerts(scores: &[DnsAnomalyScore], threshold: f64) -> Vec<Alert> {
    scores
        .iter()
        .filter(|s| s.tunneling_score > threshold)
        .map(|s| {
            let mut metadata = HashMap::new();
            metadata.insert("domain".into(), s.domain.clone());
            metadata.insert("query_count".into(), s.query_count.to_string());
            metadata.insert(
                "unique_subdomains".into(),
                s.unique_subdomains.to_string(),
            );
            metadata.insert(
                "tunneling_score".into(),
                format!("{:.2}", s.tunneling_score),
            );

            Alert {
                id: Uuid::new_v4(),
                severity: Severity::Critical,
                kind: "dns_tunnel".into(),
                message: format!(
                    "DNS tunneling suspected: {} \u{2014} {} queries, {} unique subdomains, \
                     avg entropy {:.2}, score {:.2}",
                    s.domain, s.query_count, s.unique_subdomains, s.avg_entropy, s.tunneling_score,
                ),
                occurred_at: Utc::now(),
                metadata,
                rule_id: Some("SENT-NET-002".into()),
                attack_id: Some("T1071.004".into()),
            }
        })
        .collect()
}

// ===========================================================================
// DGA scoring
// ===========================================================================

/// Lightweight DGA (Domain Generation Algorithm) scorer.
///
/// Heuristics:
///   - Shannon entropy of the second-level domain
///   - Vowel ratio (< 20% is suspicious)
///   - Digit ratio (> 40% is suspicious)
///   - Length in DGA range (12-20 chars)
///   - Consecutive consonant runs > 4
///
/// Returns a score in 0.0 ..= 1.0.
pub fn score_dga(domain: &str) -> f64 {
    // Extract second-level domain (the label just before the TLD).
    let domain = domain.trim_end_matches('.');
    let labels: Vec<&str> = domain.split('.').collect();
    let sld = if labels.len() >= 2 {
        labels[labels.len() - 2]
    } else {
        labels[0]
    };

    let sld_lower = sld.to_lowercase();
    let len = sld_lower.len();

    if len == 0 {
        return 0.0;
    }

    let mut indicators = 0.0_f64;
    let mut weights = 0.0_f64;

    // 1. Entropy of SLD (weight: 0.30)
    let entropy = shannon_entropy(&sld_lower);
    // High entropy (> 3.5 bits) for a short label is suspicious.
    let entropy_score = if entropy > 4.0 {
        1.0
    } else if entropy > 3.5 {
        0.8
    } else if entropy > 3.0 {
        0.4
    } else {
        0.1
    };
    indicators += 0.30 * entropy_score;
    weights += 0.30;

    // 2. Vowel ratio (weight: 0.20)
    let vowels = sld_lower.chars().filter(|c| "aeiou".contains(*c)).count();
    let vowel_ratio = vowels as f64 / len as f64;
    let vowel_score = if vowel_ratio < 0.1 {
        1.0
    } else if vowel_ratio < 0.2 {
        0.8
    } else if vowel_ratio < 0.3 {
        0.3
    } else {
        0.0
    };
    indicators += 0.20 * vowel_score;
    weights += 0.20;

    // 3. Digit ratio (weight: 0.20)
    let digits = sld_lower.chars().filter(|c| c.is_ascii_digit()).count();
    let digit_ratio = digits as f64 / len as f64;
    let digit_score = if digit_ratio > 0.6 {
        1.0
    } else if digit_ratio > 0.4 {
        0.8
    } else if digit_ratio > 0.2 {
        0.3
    } else {
        0.0
    };
    indicators += 0.20 * digit_score;
    weights += 0.20;

    // 4. Length in DGA range 12-20 chars (weight: 0.15)
    let len_score = if (12..=20).contains(&len) {
        0.8
    } else if len > 20 {
        0.6
    } else {
        0.1
    };
    indicators += 0.15 * len_score;
    weights += 0.15;

    // 5. Consecutive consonant runs > 4 (weight: 0.15)
    let consonants = "bcdfghjklmnpqrstvwxyz";
    let mut max_run = 0_usize;
    let mut current_run = 0_usize;
    for c in sld_lower.chars() {
        if consonants.contains(c) {
            current_run += 1;
            if current_run > max_run {
                max_run = current_run;
            }
        } else {
            current_run = 0;
        }
    }
    let consonant_score = if max_run > 6 {
        1.0
    } else if max_run > 4 {
        0.8
    } else if max_run > 3 {
        0.3
    } else {
        0.0
    };
    indicators += 0.15 * consonant_score;
    weights += 0.15;

    // Normalise to 0.0–1.0.
    if weights > 0.0 {
        (indicators / weights).clamp(0.0, 1.0)
    } else {
        0.0
    }
}

/// Generate alerts for domains whose DGA score exceeds the threshold.
pub fn dga_alerts(domains: &[String], threshold: f64) -> Vec<Alert> {
    domains
        .iter()
        .filter_map(|domain| {
            let score = score_dga(domain);
            if score > threshold {
                let mut metadata = HashMap::new();
                metadata.insert("domain".into(), domain.clone());
                metadata.insert("dga_score".into(), format!("{:.2}", score));

                Some(Alert {
                    id: Uuid::new_v4(),
                    severity: Severity::Medium,
                    kind: "dga_domain".into(),
                    message: format!(
                        "Suspected DGA domain: {} \u{2014} score {:.2}",
                        domain, score,
                    ),
                    occurred_at: Utc::now(),
                    metadata,
                    rule_id: Some("SENT-NET-003".into()),
                    attack_id: Some("T1568.002".into()),
                })
            } else {
                None
            }
        })
        .collect()
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_base_domain() {
        assert_eq!(extract_base_domain("sub.evil.com"), "evil.com");
        assert_eq!(extract_base_domain("a.b.c.evil.com"), "evil.com");
        assert_eq!(extract_base_domain("evil.com"), "evil.com");
        assert_eq!(extract_base_domain("evil.com."), "evil.com");
    }

    #[test]
    fn test_extract_subdomain() {
        assert_eq!(extract_subdomain("sub.evil.com"), "sub");
        assert_eq!(extract_subdomain("a.b.c.evil.com"), "a.b.c");
        assert_eq!(extract_subdomain("evil.com"), "");
    }

    #[test]
    fn test_shannon_entropy() {
        // Single character repeated -> 0 entropy
        assert!((shannon_entropy("aaaa") - 0.0).abs() < 0.001);
        // Two equally frequent characters -> 1 bit
        assert!((shannon_entropy("ab") - 1.0).abs() < 0.001);
        // Empty string
        assert!((shannon_entropy("") - 0.0).abs() < 0.001);
    }

    #[test]
    fn test_score_dga_benign() {
        let score = score_dga("google.com");
        assert!(score < 0.5, "google.com should score low, got {score}");
    }

    #[test]
    fn test_score_dga_suspicious() {
        let score = score_dga("xkcd7rbqmvnt3.com");
        assert!(
            score > 0.4,
            "random-looking domain should score high, got {score}"
        );
    }
}
