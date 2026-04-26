//! YARA-based memory scanning (T1055 / T1059 / TA0005-TA0006).
//!
//! Uses [`yara-x`](https://docs.rs/yara-x), the pure-Rust YARA engine, so we
//! ship a single `cargo build --features yara` away from a working scanner on
//! every supported host platform — no libyara C dependency, no version skew.
//!
//! ## Scope
//!
//! - `YaraScanner::new` compiles a built-in ruleset (see
//!   [`crate::yara_rules`]).  Operators can layer extra rule sources via
//!   [`YaraScanner::add_source`] before [`YaraScanner::build`].
//! - [`YaraScanner::scan_bytes`] matches a single buffer against the compiled
//!   rules — this works on every platform.
//! - [`YaraScanner::scan_process`] / [`YaraScanner::scan_all_processes`] read
//!   committed memory from a target PID and run the rules against each
//!   readable region.  Currently implemented for Windows only; other
//!   platforms return [`YaraError::ProcessScanUnsupported`].
//!
//! ## Threading model
//!
//! The compiled [`yara_x::Rules`] live behind an [`Arc`] so the scanner can be
//! cheaply cloned across scan tasks.  Each scan operation creates a fresh
//! short-lived `yara_x::Scanner` because `Scanner::scan` requires `&mut self`
//! — sharing a single scanner across threads would require external locking
//! and we'd rather pay the (tiny) per-scan construction cost than serialize
//! all callers through a mutex.

use arqenor_core::models::alert::{Alert, Severity};
use chrono::Utc;
use std::collections::HashMap;
use std::sync::Arc;
use thiserror::Error;
use uuid::Uuid;

use crate::yara_rules::{EmbeddedRuleSet, BUILTIN_RULESETS};

/// Maximum bytes read from a single memory region per scan.
///
/// Memory anomaly detection already flags suspicious large RWX regions; YARA
/// rules typically match early in a region (config blocks, headers, residual
/// strings).  16 MiB strikes a balance between coverage and not pinning
/// gigabytes of RAM into the scanner's working buffers.
pub const MAX_REGION_SCAN_BYTES: usize = 16 * 1024 * 1024;

/// Maximum total bytes scanned per process across all regions (safety cap).
pub const MAX_PROCESS_SCAN_BYTES: usize = 256 * 1024 * 1024;

// ── Errors ─────────────────────────────────────────────────────────────────

/// Errors returned by the YARA scanner.
#[derive(Debug, Error)]
pub enum YaraError {
    #[error("YARA rule compilation failed in {ruleset}: {message}")]
    Compile { ruleset: String, message: String },

    #[error("failed to open process {pid}: {source}")]
    OpenProcess {
        pid: u32,
        #[source]
        source: arqenor_core::error::ArqenorError,
    },

    #[error("YARA scan error: {0}")]
    Scan(String),

    #[error("per-process scanning is not supported on this platform")]
    ProcessScanUnsupported,
}

impl YaraError {
    fn open_process(pid: u32, source: arqenor_core::error::ArqenorError) -> Self {
        Self::OpenProcess { pid, source }
    }
}

// ── Match types ────────────────────────────────────────────────────────────

/// A single rule-match emitted by the scanner.
#[derive(Debug, Clone)]
pub struct YaraMatch {
    /// The rule's `identifier:` from the YARA source.
    pub rule_identifier: String,
    /// The rule's namespace, if any (typically `default`).
    pub namespace: String,
    /// Selected metadata fields lifted from the rule's `meta:` block.
    pub metadata: RuleMetadata,
}

/// Metadata fields the scanner extracts from a rule's `meta:` block when
/// emitting an alert.  All fields are best-effort — rules that omit them get
/// `None` / `Severity::Medium`.
#[derive(Debug, Clone)]
pub struct RuleMetadata {
    pub family: Option<String>,
    pub description: Option<String>,
    pub attack_id: Option<String>,
    pub severity: Severity,
}

impl Default for RuleMetadata {
    fn default() -> Self {
        Self {
            family: None,
            description: None,
            attack_id: None,
            // arqenor-core's `Severity` does not derive `Default`; pick the
            // sensible mid-tier here so unannotated YARA rules still have a
            // reasonable severity attached.
            severity: Severity::Medium,
        }
    }
}

/// Per-process scan summary.
#[derive(Debug, Clone)]
pub struct YaraScanResult {
    pub pid: u32,
    pub image_path: String,
    pub regions_scanned: usize,
    pub bytes_scanned: u64,
    pub matches: Vec<YaraMatch>,
}

// ── Scanner ────────────────────────────────────────────────────────────────

/// Source fed to the compiler before [`YaraScannerBuilder::build`].
struct PendingSource {
    name: String,
    source: String,
}

/// Builder for [`YaraScanner`].
///
/// Construct with [`YaraScanner::builder`], optionally call [`add_source`],
/// then call [`build`].
///
/// [`add_source`]: YaraScannerBuilder::add_source
/// [`build`]: YaraScannerBuilder::build
pub struct YaraScannerBuilder {
    sources: Vec<PendingSource>,
}

impl YaraScannerBuilder {
    /// Append additional YARA source.  `name` is used in error messages only.
    pub fn add_source(mut self, name: impl Into<String>, source: impl Into<String>) -> Self {
        self.sources.push(PendingSource {
            name: name.into(),
            source: source.into(),
        });
        self
    }

    /// Append an entire embedded ruleset.
    pub fn add_embedded(self, set: EmbeddedRuleSet) -> Self {
        self.add_source(set.name, set.source)
    }

    /// Compile all sources into a [`YaraScanner`].
    pub fn build(self) -> Result<YaraScanner, YaraError> {
        let mut compiler = yara_x::Compiler::new();
        for src in &self.sources {
            compiler
                .add_source(src.source.as_str())
                .map_err(|e| YaraError::Compile {
                    ruleset: src.name.clone(),
                    message: e.to_string(),
                })?;
        }
        let rules = compiler.build();
        Ok(YaraScanner {
            rules: Arc::new(rules),
        })
    }
}

/// In-memory YARA scanner.
///
/// Cheap to clone — internally holds an [`Arc<yara_x::Rules>`], so all clones
/// share the compiled ruleset.
#[derive(Clone)]
pub struct YaraScanner {
    rules: Arc<yara_x::Rules>,
}

impl YaraScanner {
    /// Start a new builder pre-populated with every embedded ruleset.
    pub fn builder() -> YaraScannerBuilder {
        let mut builder = YaraScannerBuilder {
            sources: Vec::with_capacity(BUILTIN_RULESETS.len()),
        };
        for set in BUILTIN_RULESETS {
            builder = builder.add_embedded(*set);
        }
        builder
    }

    /// Start a new builder with no rules pre-loaded.
    pub fn empty_builder() -> YaraScannerBuilder {
        YaraScannerBuilder {
            sources: Vec::new(),
        }
    }

    /// Compile the default builtin ruleset.
    ///
    /// Equivalent to `Self::builder().build()`.
    pub fn new() -> Result<Self, YaraError> {
        Self::builder().build()
    }

    /// Number of compiled rules.
    pub fn rule_count(&self) -> usize {
        self.rules.iter().count()
    }

    /// Scan a single byte buffer.  Returns one [`YaraMatch`] per matching rule.
    pub fn scan_bytes(&self, data: &[u8]) -> Result<Vec<YaraMatch>, YaraError> {
        let mut scanner = yara_x::Scanner::new(&self.rules);
        let results = scanner
            .scan(data)
            .map_err(|e| YaraError::Scan(e.to_string()))?;

        let mut hits = Vec::new();
        for rule in results.matching_rules() {
            hits.push(extract_match(&rule));
        }
        Ok(hits)
    }

    /// Scan a single process's memory.
    ///
    /// Reads up to [`MAX_REGION_SCAN_BYTES`] per region and stops once
    /// [`MAX_PROCESS_SCAN_BYTES`] of memory has been examined for the PID.
    pub fn scan_process(&self, pid: u32) -> Result<YaraScanResult, YaraError> {
        scan_process_impl(self, pid)
    }

    /// Scan every process the current user can open.
    ///
    /// PIDs that fail to open are silently skipped (they may be protected
    /// processes or have already exited); only PIDs with at least one match
    /// appear in the returned list.
    pub fn scan_all_processes(&self) -> Vec<YaraScanResult> {
        scan_all_processes_impl(self)
    }

    /// Convert a [`YaraScanResult`] into one [`Alert`] per match, ready to be
    /// pushed onto the pipeline's `scan_tx` channel.
    pub fn matches_to_alerts(&self, result: &YaraScanResult) -> Vec<Alert> {
        let mut alerts = Vec::with_capacity(result.matches.len());
        for m in result.matches.iter() {
            let mut metadata = HashMap::new();
            metadata.insert("pid".into(), result.pid.to_string());
            metadata.insert("image_path".into(), result.image_path.clone());
            metadata.insert("rule_identifier".into(), m.rule_identifier.clone());
            metadata.insert("namespace".into(), m.namespace.clone());
            metadata.insert("regions_scanned".into(), result.regions_scanned.to_string());
            metadata.insert("bytes_scanned".into(), result.bytes_scanned.to_string());
            if let Some(ref family) = m.metadata.family {
                metadata.insert("family".into(), family.clone());
            }
            if let Some(ref desc) = m.metadata.description {
                metadata.insert("rule_description".into(), desc.clone());
            }

            let attack_id = m
                .metadata
                .attack_id
                .clone()
                .unwrap_or_else(|| "T1055".into());

            // Stable rule_id keyed on the matching rule's identifier so the
            // correlation engine groups distinct hits of the same rule across
            // different PIDs together — and never collides hits of different
            // rules under the same numeric index.
            let rule_id = format!("SENT-YARA-{}", m.rule_identifier);

            let family = m.metadata.family.as_deref().unwrap_or("Unknown");
            let message = format!(
                "YARA match: {} ({}) in PID {} ({})",
                m.rule_identifier, family, result.pid, result.image_path,
            );

            alerts.push(Alert {
                id: Uuid::new_v4(),
                severity: m.metadata.severity.clone(),
                kind: "yara_match".into(),
                message,
                occurred_at: Utc::now(),
                metadata,
                rule_id: Some(rule_id),
                attack_id: Some(attack_id),
            });
        }
        alerts
    }
}

// ── Match extraction ───────────────────────────────────────────────────────

fn extract_match(rule: &yara_x::Rule<'_, '_>) -> YaraMatch {
    let mut meta = RuleMetadata::default();

    for (key, value) in rule.metadata() {
        match key {
            "family" => meta.family = metadata_value_to_string(&value),
            "description" => meta.description = metadata_value_to_string(&value),
            "attack_id" => meta.attack_id = metadata_value_to_string(&value),
            "severity" => {
                if let Some(s) = metadata_value_to_string(&value) {
                    meta.severity = parse_severity(&s);
                }
            }
            _ => {}
        }
    }

    YaraMatch {
        rule_identifier: rule.identifier().to_string(),
        namespace: rule.namespace().to_string(),
        metadata: meta,
    }
}

fn metadata_value_to_string(value: &yara_x::MetaValue<'_>) -> Option<String> {
    match value {
        yara_x::MetaValue::String(s) => Some((*s).to_string()),
        yara_x::MetaValue::Bytes(b) => Some(String::from_utf8_lossy(b).into_owned()),
        yara_x::MetaValue::Integer(i) => Some(i.to_string()),
        yara_x::MetaValue::Float(f) => Some(f.to_string()),
        yara_x::MetaValue::Bool(b) => Some(b.to_string()),
    }
}

fn parse_severity(s: &str) -> Severity {
    match s.to_ascii_lowercase().as_str() {
        "info" => Severity::Info,
        "low" => Severity::Low,
        "medium" | "med" => Severity::Medium,
        "high" => Severity::High,
        "critical" | "crit" => Severity::Critical,
        _ => Severity::Medium,
    }
}

// ── Platform-specific process memory readers ───────────────────────────────

#[cfg(target_os = "windows")]
mod platform {
    use super::*;
    use std::mem::{size_of, zeroed};
    use sysinfo::{ProcessRefreshKind, RefreshKind, System};
    use windows::Win32::Foundation::{CloseHandle, HANDLE, MAX_PATH};
    use windows::Win32::System::Diagnostics::Debug::ReadProcessMemory;
    use windows::Win32::System::Memory::{
        VirtualQueryEx, MEMORY_BASIC_INFORMATION, MEM_COMMIT, PAGE_GUARD, PAGE_NOACCESS,
    };
    use windows::Win32::System::Threading::{
        OpenProcess, QueryFullProcessImageNameW, PROCESS_QUERY_INFORMATION,
        PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_VM_READ,
    };

    /// Maximum number of regions enumerated per process (safety bound).
    const MAX_REGIONS: usize = 50_000;

    pub fn scan_process(scanner: &YaraScanner, pid: u32) -> Result<YaraScanResult, YaraError> {
        let image_path = process_image_path(pid).unwrap_or_default();

        // SAFETY: OpenProcess is safe; we check the result.
        let handle = unsafe {
            OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, pid).map_err(|e| {
                YaraError::open_process(
                    pid,
                    arqenor_core::error::ArqenorError::Platform(format!("OpenProcess: {e}")),
                )
            })?
        };

        let mut result = YaraScanResult {
            pid,
            image_path,
            regions_scanned: 0,
            bytes_scanned: 0,
            matches: Vec::new(),
        };

        let mut addr: usize = 0;
        let mut total_bytes: u64 = 0;
        let mut region_count: usize = 0;

        while region_count < MAX_REGIONS && total_bytes < MAX_PROCESS_SCAN_BYTES as u64 {
            // SAFETY: VirtualQueryEx with valid handle and out-buf.
            let mut mbi: MEMORY_BASIC_INFORMATION = unsafe { zeroed() };
            let ret = unsafe {
                VirtualQueryEx(
                    handle,
                    Some(addr as *const _),
                    &mut mbi,
                    size_of::<MEMORY_BASIC_INFORMATION>(),
                )
            };
            if ret == 0 {
                break;
            }

            let next_addr = (mbi.BaseAddress as usize).saturating_add(mbi.RegionSize);
            // Guard against rollover at top of address space.
            if next_addr <= mbi.BaseAddress as usize {
                break;
            }

            let readable = mbi.State == MEM_COMMIT
                && (mbi.Protect.0 & PAGE_NOACCESS.0) == 0
                && (mbi.Protect.0 & PAGE_GUARD.0) == 0;

            if readable && mbi.RegionSize > 0 {
                let to_read = mbi.RegionSize.min(MAX_REGION_SCAN_BYTES);
                let mut buf = vec![0u8; to_read];
                let mut bytes_read: usize = 0;

                // SAFETY: ReadProcessMemory with valid handle, valid base,
                // and an owned buffer of correct length.
                let ok = unsafe {
                    ReadProcessMemory(
                        handle,
                        mbi.BaseAddress,
                        buf.as_mut_ptr() as *mut _,
                        to_read,
                        Some(&mut bytes_read),
                    )
                };

                if ok.is_ok() && bytes_read > 0 {
                    buf.truncate(bytes_read);
                    region_count += 1;
                    total_bytes += bytes_read as u64;

                    match scanner.scan_bytes(&buf) {
                        Ok(hits) => result.matches.extend(hits),
                        Err(e) => {
                            tracing::debug!(pid, base = ?mbi.BaseAddress, "scan failed: {e}");
                        }
                    }
                }
            }

            addr = next_addr;
        }

        result.regions_scanned = region_count;
        result.bytes_scanned = total_bytes;

        // SAFETY: closing a handle we own.
        unsafe {
            let _ = CloseHandle(handle);
        }

        Ok(result)
    }

    pub fn scan_all_processes(scanner: &YaraScanner) -> Vec<YaraScanResult> {
        let mut sys = System::new_with_specifics(
            RefreshKind::nothing().with_processes(ProcessRefreshKind::nothing()),
        );
        sys.refresh_processes(sysinfo::ProcessesToUpdate::All, true);

        sys.processes()
            .keys()
            .filter_map(|&pid| {
                let pid_u32 = usize::from(pid) as u32;
                if pid_u32 == 0 || pid_u32 == 4 {
                    return None;
                }
                scanner.scan_process(pid_u32).ok()
            })
            .filter(|r| !r.matches.is_empty())
            .collect()
    }

    fn process_image_path(pid: u32) -> Option<String> {
        // SAFETY: handle obtained inline; checked before use.
        unsafe {
            let handle: HANDLE = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid).ok()?;
            let mut buf = [0u16; MAX_PATH as usize];
            let mut size = buf.len() as u32;
            let ok = QueryFullProcessImageNameW(
                handle,
                Default::default(),
                windows::core::PWSTR(buf.as_mut_ptr()),
                &mut size,
            )
            .is_ok();
            let _ = CloseHandle(handle);
            if ok && size > 0 {
                Some(String::from_utf16_lossy(&buf[..size as usize]))
            } else {
                None
            }
        }
    }
}

#[cfg(not(target_os = "windows"))]
mod platform {
    use super::*;

    pub fn scan_process(_scanner: &YaraScanner, _pid: u32) -> Result<YaraScanResult, YaraError> {
        Err(YaraError::ProcessScanUnsupported)
    }

    pub fn scan_all_processes(_scanner: &YaraScanner) -> Vec<YaraScanResult> {
        Vec::new()
    }
}

fn scan_process_impl(scanner: &YaraScanner, pid: u32) -> Result<YaraScanResult, YaraError> {
    platform::scan_process(scanner, pid)
}

fn scan_all_processes_impl(scanner: &YaraScanner) -> Vec<YaraScanResult> {
    platform::scan_all_processes(scanner)
}

// ── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// Builtin ruleset must compile cleanly.
    #[test]
    fn builtin_rules_compile() {
        let scanner = YaraScanner::new().expect("builtin rules compile");
        assert!(
            scanner.rule_count() >= 9,
            "expected at least one rule per family file, got {}",
            scanner.rule_count()
        );
    }

    /// A trivial custom rule fires on a matching buffer.
    #[test]
    fn custom_rule_matches_synthetic_buffer() {
        let scanner = YaraScanner::empty_builder()
            .add_source(
                "test_marker.yar",
                r#"
                rule TEST_MARKER {
                    meta:
                        family = "TestMarker"
                        attack_id = "T9999"
                        severity = "high"
                    strings:
                        $s = "ARQENOR_YARA_TEST_NEEDLE"
                    condition:
                        $s
                }
            "#,
            )
            .build()
            .expect("test rule compiles");

        let haystack = b"prefix...ARQENOR_YARA_TEST_NEEDLE...suffix";
        let hits = scanner.scan_bytes(haystack).expect("scan succeeds");
        assert_eq!(hits.len(), 1);
        let m = &hits[0];
        assert_eq!(m.rule_identifier, "TEST_MARKER");
        assert_eq!(m.metadata.family.as_deref(), Some("TestMarker"));
        assert_eq!(m.metadata.attack_id.as_deref(), Some("T9999"));
        assert_eq!(m.metadata.severity, Severity::High);
    }

    /// Non-matching buffer yields zero hits.
    #[test]
    fn no_match_on_unrelated_bytes() {
        let scanner = YaraScanner::new().expect("builtin rules compile");
        let benign = b"the quick brown fox jumps over the lazy dog";
        let hits = scanner.scan_bytes(benign).expect("scan succeeds");
        assert!(
            hits.is_empty(),
            "benign text should not trigger any builtin rule, got {hits:?}"
        );
    }

    /// Mimikatz signature catches its own canonical command-line strings.
    #[test]
    fn mimikatz_rule_matches_canonical_strings() {
        let scanner = YaraScanner::new().expect("builtin rules compile");
        // Two markers from ARQENOR_Mimikatz_Strings (condition: 2 of them).
        let buf = b"\
            something_above\n\
            sekurlsa::logonpasswords\n\
            privilege::debug\n\
            something_below";
        let hits = scanner.scan_bytes(buf).expect("scan succeeds");
        assert!(
            hits.iter()
                .any(|m| m.rule_identifier == "ARQENOR_Mimikatz_Strings"),
            "expected ARQENOR_Mimikatz_Strings hit, got {hits:?}",
        );
    }

    /// `matches_to_alerts` produces the expected alert envelope.
    #[test]
    fn matches_to_alerts_format() {
        let scanner = YaraScanner::empty_builder()
            .add_source(
                "alert_format.yar",
                r#"
                rule ALERT_FMT {
                    meta:
                        family = "AlertFmt"
                        attack_id = "T1059"
                        severity = "critical"
                    strings:
                        $s = "FORMAT_NEEDLE"
                    condition:
                        $s
                }
            "#,
            )
            .build()
            .expect("compile");

        let buf = b"FORMAT_NEEDLE here";
        let hits = scanner.scan_bytes(buf).expect("scan");
        let result = YaraScanResult {
            pid: 4242,
            image_path: "/usr/bin/test".into(),
            regions_scanned: 1,
            bytes_scanned: buf.len() as u64,
            matches: hits,
        };

        let alerts = scanner.matches_to_alerts(&result);
        assert_eq!(alerts.len(), 1);
        let a = &alerts[0];
        assert_eq!(a.severity, Severity::Critical);
        assert_eq!(a.kind, "yara_match");
        assert_eq!(a.attack_id.as_deref(), Some("T1059"));
        assert_eq!(a.rule_id.as_deref(), Some("SENT-YARA-ALERT_FMT"));
        assert_eq!(a.metadata.get("pid").map(String::as_str), Some("4242"));
        assert_eq!(
            a.metadata.get("rule_identifier").map(String::as_str),
            Some("ALERT_FMT"),
        );
    }

    /// On non-Windows hosts, scan_process must surface the unsupported error
    /// so callers can downgrade gracefully.
    #[cfg(not(target_os = "windows"))]
    #[test]
    fn process_scan_unsupported_off_windows() {
        let scanner = YaraScanner::new().expect("builtin rules compile");
        let err = scanner.scan_process(1).expect_err("expect error");
        assert!(matches!(err, YaraError::ProcessScanUnsupported));
    }
}
