use super::{DetectionRule, Pattern, RuleCondition};
use crate::models::alert::Severity;

pub fn built_in_rules() -> Vec<DetectionRule> {
    vec![
        // SENT-1001: PowerShell Encoded Command T1059.001
        DetectionRule {
            id: "SENT-1001", attack_id: "T1059.001",
            severity: Severity::High,
            title: "PowerShell Encoded Command",
            condition: RuleCondition::ProcessCreate {
                image: Some(Pattern::new("*\\powershell.exe")),
                cmdline: None,
                cmdline_any: Some(vec![
                    Pattern::new("*-EncodedCommand*"),
                    Pattern::new("* -Enc *"),
                    Pattern::new("* -ec *"),
                ]),
                parent: None,
            },
        },
        // SENT-1002: PowerShell Download Cradle T1059.001
        DetectionRule {
            id: "SENT-1002", attack_id: "T1059.001",
            severity: Severity::High,
            title: "PowerShell Download Cradle",
            condition: RuleCondition::ProcessCreate {
                image: Some(Pattern::new("*\\powershell.exe")),
                cmdline: None,
                cmdline_any: Some(vec![
                    Pattern::new("*Invoke-WebRequest*"),
                    Pattern::new("*Net.WebClient*"),
                    Pattern::new("*DownloadString*"),
                    Pattern::new("*DownloadFile*"),
                    Pattern::new("* iwr *"),
                ]),
                parent: None,
            },
        },
        // SENT-1003: Certutil Decode/Download T1140
        DetectionRule {
            id: "SENT-1003", attack_id: "T1140",
            severity: Severity::High,
            title: "Certutil Decode or Download",
            condition: RuleCondition::ProcessCreate {
                image: Some(Pattern::new("*\\certutil.exe")),
                cmdline: None,
                cmdline_any: Some(vec![
                    Pattern::new("*-decode*"),
                    Pattern::new("*-urlcache*"),
                    Pattern::new("*-f http*"),
                ]),
                parent: None,
            },
        },
        // SENT-1004: MSHTA Remote Execution T1218.005
        DetectionRule {
            id: "SENT-1004", attack_id: "T1218.005",
            severity: Severity::High,
            title: "MSHTA Remote Execution",
            condition: RuleCondition::ProcessCreate {
                image: Some(Pattern::new("*\\mshta.exe")),
                cmdline: None,
                cmdline_any: Some(vec![
                    Pattern::new("*http://*"),
                    Pattern::new("*https://*"),
                    Pattern::new("*vbscript*"),
                    Pattern::new("*javascript*"),
                ]),
                parent: None,
            },
        },
        // SENT-1005: Regsvr32 COM Scriptlet T1218.010
        DetectionRule {
            id: "SENT-1005", attack_id: "T1218.010",
            severity: Severity::High,
            title: "Regsvr32 COM Scriptlet",
            condition: RuleCondition::ProcessCreate {
                image: Some(Pattern::new("*\\regsvr32.exe")),
                cmdline: None,
                cmdline_any: Some(vec![
                    Pattern::new("*scrobj.dll*"),
                    Pattern::new("*http://*"),
                    Pattern::new("*https://*"),
                ]),
                parent: None,
            },
        },
        // SENT-1006: Rundll32 Remote T1218.011
        DetectionRule {
            id: "SENT-1006", attack_id: "T1218.011",
            severity: Severity::High,
            title: "Rundll32 Remote Execution",
            condition: RuleCondition::ProcessCreate {
                image: Some(Pattern::new("*\\rundll32.exe")),
                cmdline: None,
                cmdline_any: Some(vec![
                    Pattern::new("*http://*"),
                    Pattern::new("*https://*"),
                ]),
                parent: None,
            },
        },
        // SENT-1007: BITSAdmin Transfer T1197
        DetectionRule {
            id: "SENT-1007", attack_id: "T1197",
            severity: Severity::Medium,
            title: "BITSAdmin File Transfer",
            condition: RuleCondition::ProcessCreate {
                image: Some(Pattern::new("*\\bitsadmin.exe")),
                cmdline: Some(vec![Pattern::new("*/transfer*")]),
                cmdline_any: None,
                parent: None,
            },
        },
        // SENT-1008: WMI Process Spawn T1047
        DetectionRule {
            id: "SENT-1008", attack_id: "T1047",
            severity: Severity::High,
            title: "WMI Spawning Shell",
            condition: RuleCondition::ProcessCreate {
                image: None,
                cmdline: None,
                cmdline_any: None,
                parent: Some(Pattern::new("*\\wmiprvse.exe")),
            },
        },
        // SENT-1009: Office Spawning Shell T1204.002
        DetectionRule {
            id: "SENT-1009", attack_id: "T1204.002",
            severity: Severity::Critical,
            title: "Office Application Spawning Shell",
            condition: RuleCondition::ProcessCreate {
                image: Some(Pattern::new("*\\cmd.exe")),
                cmdline: None,
                cmdline_any: None,
                parent: None,
            },
        },
        // SENT-1009b: Office parent detection
        DetectionRule {
            id: "SENT-1009b", attack_id: "T1204.002",
            severity: Severity::Critical,
            title: "Office Spawning PowerShell",
            condition: RuleCondition::ProcessCreate {
                image: Some(Pattern::new("*\\powershell.exe")),
                cmdline: None,
                cmdline_any: None,
                parent: None,
            },
        },
        // SENT-1010: Schtasks Remote Create T1053.005
        DetectionRule {
            id: "SENT-1010", attack_id: "T1053.005",
            severity: Severity::High,
            title: "Schtasks Remote Scheduled Task",
            condition: RuleCondition::ProcessCreate {
                image: Some(Pattern::new("*\\schtasks.exe")),
                cmdline: Some(vec![
                    Pattern::new("*/create*"),
                    Pattern::new("*/s \\\\*"),
                ]),
                cmdline_any: None,
                parent: None,
            },
        },
        // SENT-1012: Shadow Copy Deletion T1490
        DetectionRule {
            id: "SENT-1012", attack_id: "T1490",
            severity: Severity::Critical,
            title: "Shadow Copy Deletion (Pre-Ransomware)",
            condition: RuleCondition::ProcessCreate {
                image: Some(Pattern::new("*\\vssadmin.exe")),
                cmdline: Some(vec![Pattern::new("*delete shadows*")]),
                cmdline_any: None,
                parent: None,
            },
        },
        // SENT-1012b: WMI shadow delete
        DetectionRule {
            id: "SENT-1012b", attack_id: "T1490",
            severity: Severity::Critical,
            title: "WMI Shadow Copy Deletion (Pre-Ransomware)",
            condition: RuleCondition::ProcessCreate {
                image: Some(Pattern::new("*\\wmic.exe")),
                cmdline: Some(vec![Pattern::new("*shadowcopy delete*")]),
                cmdline_any: None,
                parent: None,
            },
        },
        // SENT-1013: WMIC Process Create T1047
        DetectionRule {
            id: "SENT-1013", attack_id: "T1047",
            severity: Severity::High,
            title: "WMIC Process Creation",
            condition: RuleCondition::ProcessCreate {
                image: Some(Pattern::new("*\\wmic.exe")),
                cmdline: Some(vec![Pattern::new("*process call create*")]),
                cmdline_any: None,
                parent: None,
            },
        },
        // SENT-1014: InstallUtil Execution T1218.004
        DetectionRule {
            id: "SENT-1014", attack_id: "T1218.004",
            severity: Severity::High,
            title: "InstallUtil Execution",
            condition: RuleCondition::ProcessCreate {
                image: Some(Pattern::new("*\\installutil.exe")),
                cmdline: None,
                cmdline_any: Some(vec![
                    Pattern::new("*/logfile=*"),
                    Pattern::new("*\\temp\\*"),
                    Pattern::new("*\\appdata\\*"),
                ]),
                parent: None,
            },
        },
        // SENT-1015: Known Malware Process Names
        DetectionRule {
            id: "SENT-1015", attack_id: "T1059",
            severity: Severity::Critical,
            title: "Known Malware / Credential Tool Process Name",
            condition: RuleCondition::ProcessName {
                names: vec![
                    Pattern::new("mimikatz.exe"),
                    Pattern::new("procdump.exe"),
                    Pattern::new("nanodump.exe"),
                    Pattern::new("lsassy.exe"),
                    Pattern::new("safetykatz.exe"),
                    Pattern::new("sharpdump.exe"),
                    Pattern::new("lazagne.exe"),
                ],
            },
        },
    ]
}
