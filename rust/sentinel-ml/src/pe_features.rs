//! High-level PE feature extraction and sub-score computation.
//!
//! Extracts security-relevant features from a parsed PE and computes
//! entropy, import, and structure sub-scores for risk classification.

use crate::pe_parser::PeInfo;

/// Extracted PE features with computed risk sub-scores.
#[derive(Debug, Clone, serde::Serialize)]
pub struct PeFeatures {
    // Header features
    pub file_size: usize,
    pub is_64bit: bool,
    pub is_dll: bool,
    pub is_signed: bool,
    pub has_debug_info: bool,
    pub has_resources: bool,
    pub has_tls: bool,
    pub has_relocations: bool,
    pub timestamp: u32,
    pub timestamp_is_zero: bool,
    pub timestamp_is_future: bool,

    // Section features
    pub section_count: usize,
    pub max_section_entropy: f64,
    pub mean_section_entropy: f64,
    pub has_high_entropy: bool,
    pub rx_section_count: usize,
    pub rwx_section_count: usize,
    pub abnormal_section_names: usize,
    pub overlay_size: usize,

    // Import features
    pub import_dll_count: usize,
    pub import_function_count: usize,
    pub suspicious_imports: Vec<String>,
    pub has_network_imports: bool,
    pub has_crypto_imports: bool,
    pub has_injection_imports: bool,

    // Computed scores (0.0 to 1.0)
    pub entropy_score: f64,
    pub import_score: f64,
    pub structure_score: f64,
    pub overall_risk: f64,
}

impl Default for PeFeatures {
    fn default() -> Self {
        Self {
            file_size: 0,
            is_64bit: false,
            is_dll: false,
            is_signed: false,
            has_debug_info: false,
            has_resources: false,
            has_tls: false,
            has_relocations: false,
            timestamp: 0,
            timestamp_is_zero: false,
            timestamp_is_future: false,
            section_count: 0,
            max_section_entropy: 0.0,
            mean_section_entropy: 0.0,
            has_high_entropy: false,
            rx_section_count: 0,
            rwx_section_count: 0,
            abnormal_section_names: 0,
            overlay_size: 0,
            import_dll_count: 0,
            import_function_count: 0,
            suspicious_imports: Vec::new(),
            has_network_imports: false,
            has_crypto_imports: false,
            has_injection_imports: false,
            entropy_score: 0.0,
            import_score: 0.0,
            structure_score: 0.0,
            overall_risk: 0.0,
        }
    }
}

/// Import functions associated with process injection and evasion.
const SUSPICIOUS_IMPORTS: &[&str] = &[
    "VirtualAllocEx",
    "VirtualProtectEx",
    "WriteProcessMemory",
    "ReadProcessMemory",
    "CreateRemoteThread",
    "NtCreateThreadEx",
    "QueueUserAPC",
    "SetThreadContext",
    "NtUnmapViewOfSection",
    "RtlCreateUserThread",
    "NtQueueApcThread",
    "NtWriteVirtualMemory",
    "AdjustTokenPrivileges",
    "OpenProcessToken",
    "LookupPrivilegeValue",
    "IsDebuggerPresent",
    "CheckRemoteDebuggerPresent",
    "NtQueryInformationProcess",
    "CryptEncrypt",
    "CryptDecrypt",
    "BCryptEncrypt",
];

/// Imports specifically associated with process injection.
const INJECTION_IMPORTS: &[&str] = &[
    "VirtualAllocEx",
    "WriteProcessMemory",
    "CreateRemoteThread",
    "NtCreateThreadEx",
    "QueueUserAPC",
    "NtUnmapViewOfSection",
    "RtlCreateUserThread",
    "NtQueueApcThread",
    "NtWriteVirtualMemory",
    "SetThreadContext",
];

/// Standard PE section names — anything else is suspicious.
const STANDARD_SECTIONS: &[&str] = &[
    ".text", ".rdata", ".data", ".pdata", ".rsrc", ".reloc", ".bss", ".idata", ".edata", ".tls",
    ".CRT", ".debug",
];

/// DLLs that provide network functionality.
const NETWORK_DLLS: &[&str] = &["ws2_32.dll", "wininet.dll", "winhttp.dll", "urlmon.dll"];

/// DLLs that provide cryptographic functionality.
const CRYPTO_DLLS: &[&str] = &["bcrypt.dll", "ncrypt.dll", "crypt32.dll", "advapi32.dll"];

/// Approximate current timestamp for detecting future-dated PEs.
/// January 2026 as Unix timestamp. Updated periodically.
const CURRENT_EPOCH_APPROX: u32 = 1_767_225_600;

/// Extract all features from a parsed PE and compute risk sub-scores.
pub fn extract_features(data: &[u8], pe: &PeInfo) -> PeFeatures {
    let mut f = PeFeatures::default();

    // ── Header features ─────────────────────────────────────────
    f.file_size = data.len();
    f.is_64bit = pe.is_64bit;
    f.is_dll = pe.is_dll;
    f.is_signed = pe.has_security;
    f.has_debug_info = pe.has_debug;
    f.has_resources = pe.has_resources;
    f.has_tls = pe.has_tls;
    f.has_relocations = pe.has_relocs;
    f.timestamp = pe.timestamp;
    f.timestamp_is_zero = pe.timestamp == 0;
    f.timestamp_is_future = pe.timestamp > CURRENT_EPOCH_APPROX;

    // ── Section features ────────────────────────────────────────
    f.section_count = pe.sections.len();
    f.overlay_size = pe.overlay_size;

    let mut max_entropy: f64 = 0.0;
    let mut sum_entropy: f64 = 0.0;

    for sec in &pe.sections {
        if sec.entropy > max_entropy {
            max_entropy = sec.entropy;
        }
        sum_entropy += sec.entropy;

        if sec.is_readable && sec.is_executable && !sec.is_writable {
            f.rx_section_count += 1;
        }
        if sec.is_readable && sec.is_writable && sec.is_executable {
            f.rwx_section_count += 1;
        }

        let name_lower = sec.name.to_lowercase();
        let is_standard = STANDARD_SECTIONS
            .iter()
            .any(|s| s.to_lowercase() == name_lower);
        if !is_standard && !sec.name.is_empty() {
            f.abnormal_section_names += 1;
        }
    }

    f.max_section_entropy = max_entropy;
    f.mean_section_entropy = if f.section_count > 0 {
        sum_entropy / f.section_count as f64
    } else {
        0.0
    };
    f.has_high_entropy = max_entropy > 7.0;

    // ── Import features ─────────────────────────────────────────
    f.import_dll_count = pe.imports.len();

    let all_functions: Vec<&str> = pe
        .imports
        .iter()
        .flat_map(|imp| imp.functions.iter().map(|s| s.as_str()))
        .collect();
    f.import_function_count = all_functions.len();

    // Find suspicious imports.
    for func in &all_functions {
        if SUSPICIOUS_IMPORTS.iter().any(|s| s == func) {
            f.suspicious_imports.push(func.to_string());
        }
    }
    f.suspicious_imports.sort();
    f.suspicious_imports.dedup();

    // Check for injection imports.
    f.has_injection_imports = all_functions
        .iter()
        .any(|func| INJECTION_IMPORTS.iter().any(|s| s == func));

    // Check for network/crypto DLLs.
    let dll_names: Vec<String> = pe
        .imports
        .iter()
        .map(|imp| imp.dll_name.to_lowercase())
        .collect();

    f.has_network_imports = dll_names
        .iter()
        .any(|dll| NETWORK_DLLS.iter().any(|n| *n == dll.as_str()));

    f.has_crypto_imports = dll_names
        .iter()
        .any(|dll| CRYPTO_DLLS.iter().any(|n| *n == dll.as_str()));

    // ── Compute sub-scores ──────────────────────────────────────
    f.entropy_score = compute_entropy_score(f.max_section_entropy);
    f.import_score = compute_import_score(&f);
    f.structure_score = compute_structure_score(&f);
    f.overall_risk =
        (0.35 * f.entropy_score + 0.35 * f.import_score + 0.30 * f.structure_score).clamp(0.0, 1.0);

    f
}

/// Entropy score: 0.0 if max < 6.5, scales linearly to 1.0 at >= 7.8.
fn compute_entropy_score(max_entropy: f64) -> f64 {
    if max_entropy < 6.5 {
        0.0
    } else if max_entropy >= 7.8 {
        1.0
    } else {
        // Linear interpolation from 6.5 -> 0.0 to 7.8 -> 1.0.
        (max_entropy - 6.5) / (7.8 - 6.5)
    }
}

/// Import score: based on suspicious import count and injection capability.
fn compute_import_score(f: &PeFeatures) -> f64 {
    let mut score: f64 = 0.0;

    // Base score from suspicious import count.
    let n = f.suspicious_imports.len();
    if n >= 6 {
        score += 0.6;
    } else if n >= 3 {
        score += 0.4;
    } else if n >= 1 {
        score += 0.2;
    }

    // Injection capability is a strong signal.
    if f.has_injection_imports {
        score += 0.3;
    }

    // Network + crypto together is suspicious.
    if f.has_network_imports && f.has_crypto_imports {
        score += 0.1;
    }

    score.clamp(0.0, 1.0)
}

/// Structure score: RWX sections, missing debug info, abnormal names, overlay, etc.
fn compute_structure_score(f: &PeFeatures) -> f64 {
    let mut score: f64 = 0.0;

    if f.rwx_section_count > 0 {
        score += 0.4;
    }

    if !f.has_debug_info {
        score += 0.1;
    }

    if f.abnormal_section_names > 0 {
        score += 0.2;
    }

    if f.overlay_size > 1024 {
        score += 0.1;
    }

    if f.timestamp_is_zero {
        score += 0.1;
    }

    if !f.has_relocations {
        score += 0.1;
    }

    score.clamp(0.0, 1.0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn entropy_score_thresholds() {
        assert_eq!(compute_entropy_score(5.0), 0.0);
        assert_eq!(compute_entropy_score(6.5), 0.0);
        assert_eq!(compute_entropy_score(7.8), 1.0);
        assert_eq!(compute_entropy_score(8.0), 1.0);

        let mid = compute_entropy_score(7.15);
        assert!(mid > 0.45 && mid < 0.55, "expected ~0.5, got {mid}");
    }

    #[test]
    fn structure_score_rwx_dominates() {
        let mut f = PeFeatures::default();
        f.rwx_section_count = 1;
        // Neutralise other contributing fields so only RWX counts.
        f.has_debug_info = true;
        f.has_relocations = true;
        let score = compute_structure_score(&f);
        assert!(
            (score - 0.4).abs() < 0.01,
            "expected 0.4, got {score}"
        );
    }
}
