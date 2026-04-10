//! Embedded YARA rules for detecting common offensive tools and malware families.
//!
//! These rules cover the most prevalent red-team frameworks and injection
//! techniques encountered in the wild.  Users can supplement these with custom
//! rule files via [`super::yara_scan::YaraScanner::from_rules_dir`].

/// Embedded YARA rules covering the most impactful malware/tool signatures.
///
/// Detected families: Cobalt Strike, Metasploit Meterpreter, Mimikatz,
/// Sliver C2, Brute Ratel C4, Havoc C2, common shellcode stubs,
/// PE injection artifacts, and encoded PowerShell payloads.
pub const EMBEDDED_RULES: &str = r#"
rule CobaltStrike_Beacon_Config {
    meta:
        description = "Cobalt Strike Beacon configuration block"
        author = "ARQENOR"
        attack_id = "T1071.001"
        severity = "critical"
    strings:
        $config_start = { 00 01 00 01 00 02 ?? ?? 00 02 00 01 00 02 ?? ?? }
        $sleep_mask = "sleeptime"
        $beacon_dll = "beacon.dll"
        $beacon_x64 = "beacon.x64.dll"
    condition:
        $config_start or ($sleep_mask and ($beacon_dll or $beacon_x64))
}

rule Metasploit_Meterpreter_Reverse_TCP {
    meta:
        description = "Metasploit Meterpreter reverse TCP shellcode"
        author = "ARQENOR"
        attack_id = "T1059.006"
        severity = "critical"
    strings:
        $api_hash_ror13 = { 60 89 E5 31 D2 64 8B 52 30 8B 52 0C 8B 52 14 }
        $ws2_32 = "ws2_32" nocase
        $reverse_tcp = { 68 02 00 ?? ?? 89 E6 6A 10 56 57 }
    condition:
        $api_hash_ror13 or ($ws2_32 and $reverse_tcp)
}

rule Mimikatz_Strings {
    meta:
        description = "Mimikatz credential dumping tool in memory"
        author = "ARQENOR"
        attack_id = "T1003.001"
        severity = "critical"
    strings:
        $s1 = "sekurlsa::logonpasswords" ascii wide nocase
        $s2 = "sekurlsa::wdigest" ascii wide nocase
        $s3 = "lsadump::sam" ascii wide nocase
        $s4 = "lsadump::dcsync" ascii wide nocase
        $s5 = "privilege::debug" ascii wide nocase
        $s6 = "gentilkiwi" ascii wide
        $s7 = "mimikatz" ascii wide nocase
    condition:
        3 of them
}

rule Sliver_C2_Implant {
    meta:
        description = "Sliver C2 framework implant"
        author = "ARQENOR"
        attack_id = "T1071.001"
        severity = "high"
    strings:
        $s1 = "sliverpb" ascii
        $s2 = "sliver.Server" ascii
        $s3 = "StartBeaconLoop" ascii
        $s4 = "GetBeaconJitter" ascii
    condition:
        2 of them
}

rule Shellcode_Common_Stubs {
    meta:
        description = "Common x64 shellcode prologue patterns"
        author = "ARQENOR"
        attack_id = "T1055"
        severity = "high"
    strings:
        $egg_hunter = { 66 81 CA FF 0F 42 52 6A 02 58 CD 2E 3C 05 5A 74 }
        $api_hashing = { 48 31 C0 AC 41 C1 C9 0D 41 01 C1 38 E0 75 F1 }
        $peb_walk_x64 = { 65 48 8B 04 25 60 00 00 00 48 8B 40 18 }
        $peb_walk_x86 = { 64 A1 30 00 00 00 8B 40 0C 8B 40 14 }
    condition:
        any of them
}

rule PE_Injection_Artifact {
    meta:
        description = "PE file loaded in non-image memory (reflective injection)"
        author = "ARQENOR"
        attack_id = "T1055.001"
        severity = "high"
    strings:
        $mz_header = "MZ"
        $pe_sig = "PE\x00\x00"
        $dos_stub = "This program cannot be run in DOS mode"
    condition:
        $mz_header at 0 and $pe_sig and $dos_stub
}

rule PowerShell_Encoded_Payload {
    meta:
        description = "Base64-encoded PowerShell payload in memory"
        author = "ARQENOR"
        attack_id = "T1059.001"
        severity = "high"
    strings:
        $enc1 = "powershell" ascii wide nocase
        $enc2 = "-enc" ascii wide nocase
        $enc3 = "-encodedcommand" ascii wide nocase
        $b64_iex = "SQBFAFgA" ascii
        $b64_iwr = "SQBuAHYAbwBrAGUALQBXAGUAYgBSAGUAcQB1AGUAcwB0" ascii
    condition:
        ($enc1 and ($enc2 or $enc3)) or $b64_iex or $b64_iwr
}

rule Brute_Ratel_C4 {
    meta:
        description = "Brute Ratel C4 framework badger"
        author = "ARQENOR"
        attack_id = "T1071.001"
        severity = "critical"
    strings:
        $s1 = "badger_" ascii
        $s2 = "BRc4" ascii
        $s3 = "bruteratel" ascii nocase
    condition:
        2 of them
}

rule Havoc_C2 {
    meta:
        description = "Havoc C2 framework demon agent"
        author = "ARQENOR"
        attack_id = "T1071.001"
        severity = "high"
    strings:
        $s1 = "HavocDemon" ascii
        $s2 = "demon.x64" ascii
        $s3 = "DemonConfig" ascii
    condition:
        2 of them
}
"#;
