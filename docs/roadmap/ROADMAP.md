# SENTINEL — Complete Product Roadmap
> Last updated: 2026-04-10 | Based on 2025-2026 threat intelligence

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
| Real-time detection pipeline | ✅ Done | tokio::select! process + file rules → alerts → SQLite |

**Coverage today:** ~60 ATT&CK techniques across TA0002-TA0006 (Execution, Persistence, Priv Esc, Defense Evasion, Credential Access).
**Gap vs commercial EDR:** No kernel driver (ETW-TI), no eBPF probes, no behavioral ML, no memory forensics.

---

## Roadmap Index

| Phase | Focus | Timeline | ATT&CK Coverage |
|-------|-------|----------|-----------------|
| [Phase 1](phases/phase1-detection-engine.md) | Detection Engine + LOTL Rules | Q2 2026 | +40 techniques |
| [Phase 2](phases/phase2-kernel-telemetry.md) | Kernel Telemetry (ETW / eBPF) | Q3 2026 | +30 techniques |
| [Phase 3](phases/phase3-network-deep.md) | Deep Network Analysis + C2 Detection | Q3 2026 | +20 techniques |
| [Phase 4](phases/phase4-ml-behavioral.md) | ML Behavioral Engine | Q4 2026 | +25 techniques |
| [Phase 5](phases/phase5-memory-forensics.md) | Memory Forensics + Anti-Injection | Q1 2027 | +15 techniques |
| [Phase 6](phases/phase6-cloud-fleet.md) | Cloud Dashboard + Fleet Management | Q2 2027 | N/A (platform) |

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
TA0002 Execution           — LOLBin monitoring, script execution (P1)
TA0003 Persistence         — ✅ Registry/Tasks/Services + WMI/COM/DLL side-load (P1)
TA0004 Privilege Escalation — Token impersonation, UAC bypass (P2)
TA0005 Defense Evasion     — AMSI bypass, process hollowing, BYOVD (P2)
TA0006 Credential Access   — LSASS access, browser cred files, shadow copy deletion (P1)
TA0007 Discovery           — ✅ Basic + net enumeration patterns (P1)
TA0008 Lateral Movement    — SMB anomalies, PtH/PtT patterns (P3)
TA0009 Collection          — Clipboard, keylogging, screenshot patterns (P3)
TA0010 Exfiltration        — DNS tunneling, large upload anomalies (P3)
TA0011 C2                  — Beaconing, DGA detection, JA4 fingerprinting (P3)
```
