# SENTINEL — Complete Product Roadmap
> Last updated: 2026-04-11 | Based on 2025-2026 threat intelligence

---

## Vision

SENTINEL is an **open-core, cross-platform security monitoring tool** written in Rust.  
Goal: give independent developers, small teams, and security researchers the detection
capabilities of a commercial EDR — without the $30/endpoint/month price tag.

Open source core → free forever.  
Cloud intelligence + fleet management + MDR → paid tiers.

---

## Current State (v0.1 — April 2026)

| Component | Status | Tech |
|-----------|--------|------|
| Process snapshot + risk scoring | ✅ Done | sysinfo 0.30, Rust |
| Persistence detection (Registry, Scheduled Tasks, Services) | ✅ Done | Windows Registry API |
| Network LAN scanner (TCP port scan) | ✅ Done | tokio async TCP |
| OS fingerprinting (Windows/Linux/Router) | ✅ Done | Port heuristics |
| VPN detection + LAN subnet filtering | ✅ Done | if-addrs, process names |
| Terminal UI (ratatui) | ✅ Done | ratatui + crossterm |
| Desktop app (Tauri v2 + React) | ✅ Done | Tauri v2, Tailwind v4 |
| Network anomaly detection (baseline diff) | ✅ Done | In-memory HashMap |
| Hostname resolution (reverse DNS) | ✅ Done | dns-lookup crate |
| Detection engine + LOLBin rules (15 rules) | ✅ Done | sentinel-core rules engine |
| Extended persistence Win (B1-B9) + Linux (C1-C7) | ✅ Done | Registry, systemd, PAM, SSH, git hooks |
| File Integrity Monitoring (baseline + real-time) | ✅ Done | ReadDirectoryChangesW / inotify |
| Credential theft detection (E1-E6) | ✅ Done | LSASS scan, AMSI bypass, ransomware signals |
| ETW consumer (6 providers, 7 rules) | ✅ Done | windows-rs EvtSubscribe / StartTrace |
| Real-time process watch (Win + Linux) | ✅ Done | EvtSubscribe 4688/4689, /proc poll |
| Real-time detection pipeline | ✅ Done | tokio::select! process + file + conn rules → alerts → SQLite |
| macOS ESF integration (process, FIM, persistence) | ✅ Done | endpoint-sec 0.5, plist parsing, 5 persistence detectors |
| Linux eBPF kernel probes (5 probes) | ✅ Done | libbpf-rs, execve/memory/persistence/privesc/rootkit |
| ETW TDH property parsing | ✅ Done | TdhGetEventInformation → typed fields |
| Windows native connections (IP Helper) | ✅ Done | GetExtendedTcpTable / GetExtendedUdpTable |
| Network analysis (C2 beaconing, DNS tunneling, DGA) | ✅ Done | Flow table + CV scoring + Shannon entropy |
| gRPC WatchAlerts stream + Go SSE bridge | ✅ Done | tonic streaming → Go orchestrator → SSE /alerts/stream |
| Windows kernel driver (minifilter, registry, process, self-protection) | ✅ Done | windows-drivers-rs WDK, FltRegisterFilter, CmRegisterCallbackEx, ObRegisterCallbacks |
| SIGMA rule engine (3000+ community rules) | ✅ Done | YAML parser, 7 modifiers, condition AST, field mapping |
| IOC database (abuse.ch threat feeds) | ✅ Done | MalwareBazaar, Feodo, URLhaus, ThreatFox, async refresh |
| Alert correlation engine | ✅ Done | PID + parent-child grouping, ATT&CK scoring, incident model |
| Memory forensics (VAD walk, hollowing, NTDLL hooks) | ✅ Done | VirtualQueryEx, PE header diff, hook classification |
| BYOVD detection (50 vulnerable drivers) | ✅ Done | EnumDeviceDrivers + LOLDrivers.io blocklist |

**Coverage today:** ~120+ ATT&CK techniques across TA0001-TA0011.
**Gap vs commercial EDR:** ETW-TI/PPL (requires MVI membership ~12mo), behavioral ML (Phase 4 partial), YARA memory scanning.

---

## Roadmap Index

| Phase | Focus | Timeline | ATT&CK Coverage | Status |
|-------|-------|----------|-----------------|--------|
| [Phase 1](phases/phase1-detection-engine.md) | Detection Engine + LOTL Rules | Q2 2026 | +40 techniques | ✅ Done |
| [Phase 2](phases/phase2-kernel-telemetry.md) | Kernel Telemetry (ETW / eBPF / Driver) | Q3 2026 | +30 techniques | ✅ Done (C6 pending MVI) |
| [Phase 3](phases/phase3-network-deep.md) | Deep Network Analysis + C2 Detection | Q3 2026 | +20 techniques | ✅ Done (beaconing, DNS tunnel, DGA) |
| [Phase 4](phases/phase4-ml-behavioral.md) | ML Behavioral Engine | Q4 2026 | +25 techniques | Partial (SIGMA, IOC, correlation done) |
| [Phase 5](phases/phase5-memory-forensics.md) | Memory Forensics + Anti-Injection | Q1 2027 | +15 techniques | Partial (VAD, hollowing, NTDLL, BYOVD done) |
| [Phase 6](phases/phase6-cloud-fleet.md) | Cloud Dashboard + Fleet Management | Q2 2027 | N/A (platform) | ⏳ Not started |

---

## Priority Matrix

```
IMPACT
  │
  │   [P1] ETW kernel telemetry ──────── [P1] LOTL detection rules
  │   [P1] Process injection detection    [P1] Credential theft alerts
  │
  │   [P2] ML behavioral scoring ─────── [P2] C2 beaconing detection
  │   [P2] Memory scanning               [P2] BYOVD driver monitoring
  │
  │   [P3] Cloud fleet ─────────────────  [P3] SIGMA rule engine
  │   [P3] UEFI/bootkit detection         [P3] Identity anomalies
  └───────────────────────────────────────────────────── EFFORT
      Low                                              High
```

---

## The #1 Gap vs Commercial EDR

> **ETW Threat Intelligence provider** — a kernel-mode ETW channel that gives
> `VirtualAllocEx`, `WriteProcessMemory`, `SetThreadContext`, `QueueUserAPC`
> callbacks WITH full call-stack context. This is what CrowdStrike and SentinelOne
> use to detect direct/indirect syscall injection, process hollowing, and
> reflective DLL loading. Open-source tools have ZERO access to this because
> it requires a PPL-signed (Protected Process Light) kernel driver.
>
> SENTINEL's Phase 2 plan: implement a kernel driver + ETW consumer to close this gap.

---

## Threat Coverage Map (planned)

```
TA0001 Initial Access      — Phishing attachment detection via file hashes (P3)
TA0002 Execution           — ✅ LOLBin monitoring (15 rules), script execution (P1)
TA0003 Persistence         — ✅ Win B1-B9, Linux C1-C7, macOS LaunchD+5 detectors (P1+P2)
TA0004 Privilege Escalation — Token impersonation, UAC bypass (P2)
TA0005 Defense Evasion     — AMSI bypass, process hollowing, BYOVD (P2)
TA0006 Credential Access   — ✅ LSASS scan, AMSI bypass, ransomware signals, SAM dump (P1)
TA0007 Discovery           — ✅ Basic + net enumeration patterns (P1)
TA0008 Lateral Movement    — SMB anomalies, PtH/PtT patterns (P3)
TA0009 Collection          — Clipboard, keylogging, screenshot patterns (P3)
TA0010 Exfiltration        — DNS tunneling, large upload anomalies (P3)
TA0011 C2                  — ✅ Beaconing (CV scoring), DGA detection, DNS tunneling (P3)
```
