//! Embedded YARA rule sources.
//!
//! Each `.yar` file is included via [`include_str!`] so the binary ships with a
//! base ruleset out of the box.  The rules are intentionally lightweight —
//! string-based and family-focused — to limit false-positive risk on user
//! workstations.  Operators are expected to layer their own threat-intel
//! ruleset on top via the runtime API (see `YaraScanner::add_source`).

/// A single named YARA rule source.
///
/// `name` is used purely for diagnostics (which file failed to compile, etc.);
/// it has no semantic meaning to the YARA engine.
#[derive(Debug, Clone, Copy)]
pub struct EmbeddedRuleSet {
    pub name: &'static str,
    pub source: &'static str,
}

/// Cobalt Strike beacon — config block + residual strings.
pub const COBALT_STRIKE: EmbeddedRuleSet = EmbeddedRuleSet {
    name: "cobalt_strike.yar",
    source: include_str!("cobalt_strike.yar"),
};

/// Metasploit Meterpreter — implant strings + HTTP stager metadata.
pub const METERPRETER: EmbeddedRuleSet = EmbeddedRuleSet {
    name: "meterpreter.yar",
    source: include_str!("meterpreter.yar"),
};

/// Mimikatz / pypykatz — credential dumping toolkit.
pub const MIMIKATZ: EmbeddedRuleSet = EmbeddedRuleSet {
    name: "mimikatz.yar",
    source: include_str!("mimikatz.yar"),
};

/// Sliver C2 implant — Go-based post-exploitation framework.
pub const SLIVER: EmbeddedRuleSet = EmbeddedRuleSet {
    name: "sliver.yar",
    source: include_str!("sliver.yar"),
};

/// Brute Ratel C4 — Badger implant strings.
pub const BRUTE_RATEL: EmbeddedRuleSet = EmbeddedRuleSet {
    name: "brute_ratel.yar",
    source: include_str!("brute_ratel.yar"),
};

/// Havoc framework — Demon agent strings.
pub const HAVOC: EmbeddedRuleSet = EmbeddedRuleSet {
    name: "havoc.yar",
    source: include_str!("havoc.yar"),
};

/// Generic shellcode prologues + API hashing constants.
pub const SHELLCODE: EmbeddedRuleSet = EmbeddedRuleSet {
    name: "shellcode.yar",
    source: include_str!("shellcode.yar"),
};

/// PE injection / reflective DLL / Donut artefacts.
pub const PE_INJECTION: EmbeddedRuleSet = EmbeddedRuleSet {
    name: "pe_injection.yar",
    source: include_str!("pe_injection.yar"),
};

/// Encoded / obfuscated PowerShell command-line patterns.
pub const ENCODED_POWERSHELL: EmbeddedRuleSet = EmbeddedRuleSet {
    name: "encoded_powershell.yar",
    source: include_str!("encoded_powershell.yar"),
};

/// All embedded rulesets, in deterministic load order.
pub const BUILTIN_RULESETS: &[EmbeddedRuleSet] = &[
    COBALT_STRIKE,
    METERPRETER,
    MIMIKATZ,
    SLIVER,
    BRUTE_RATEL,
    HAVOC,
    SHELLCODE,
    PE_INJECTION,
    ENCODED_POWERSHELL,
];
