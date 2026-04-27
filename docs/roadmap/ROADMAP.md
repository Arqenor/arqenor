# ARQENOR — Complete Product Roadmap
> Last updated: 2026-04-27 | Based on 2025-2026 threat intelligence

## Recent activity

- **2026-04-27**: Security audit remediation pass — 29 findings closed across Go orchestrator, Rust gRPC/core/platform, eBPF, CI. See `docs/security-audit-202604.md` § 8.
- **2026-04-26**: eBPF loader live (B7) + YARA memory scanning (F3) shipped.

---

## Vision

ARQENOR is an **open-core, cross-platform security monitoring tool** written in Rust.  
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
| Detection engine + LOLBin rules (15 rules) | ✅ Done | arqenor-core rules engine |
| Extended persistence Win (B1-B9) + Linux (C1-C7) | ✅ Done | Registry, systemd, PAM, SSH, git hooks |
| File Integrity Monitoring (baseline + real-time) | ✅ Done | ReadDirectoryChangesW / inotify |
| Credential theft detection (E1-E6) | ✅ Done | LSASS scan, AMSI bypass, ransomware signals |
| ETW consumer (6 providers, 7 rules) | ✅ Done | windows-rs EvtSubscribe / StartTrace |
| Real-time process watch (Win + Linux) | ✅ Done | EvtSubscribe 4688/4689, /proc poll |
| Real-time detection pipeline | ✅ Done | tokio::select! process + file + conn rules → alerts → SQLite |
| macOS ESF integration (process, FIM, persistence) | ✅ Done | endpoint-sec 0.5, plist parsing, 5 persistence detectors |
| Linux eBPF kernel probes (5 probes) | ✅ Loader live | 5 C probes (execve/memory/persistence/privesc/rootkit) loaded + attached at runtime via `libbpf-cargo` 0.24 skeletons. `EbpfAgent::start()` returns `(Self, mpsc::Receiver<EbpfEvent>)`; per-probe failures degrade gracefully (warn + continue). Wiring the receiver into `DetectionPipeline` is a follow-up. |
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
| Pipeline wiring (SIGMA + IOC + Correlation + host scans) | ✅ Done | All 6 dead modules wired into DetectionPipeline |
| Real-time connection monitoring | ✅ Done | ConnectionMonitor::watch() + polling fallback → beaconing + IOC IP live |
| Static PE analyzer (arqenor-ml) | ✅ Done | goblin-free PE parser, 25+ features, heuristic scoring, 25 tests |
| YARA memory scanning | ✅ Done (feature-gated) | `yara-x = 1.15` behind `arqenor-platform/yara` (off by default), `YaraScanner` in `rust/arqenor-platform/src/yara_scan.rs`, 9 embedded rule files (CS / Meterpreter / Mimikatz / Sliver / Brute Ratel / Havoc / shellcode / PE injection / encoded PS), wired into the Windows host-scan loop with `SENT-YARA-NNN` alert IDs (TA0005 / TA0006). Per-PID scan currently Windows-only. |
| JA4 TLS fingerprinting | 🚧 Module ready | `rust/arqenor-core/src/rules/tls_fingerprint.rs` ships the JA4 algorithm + Client Hello parser + 17 C2 fingerprints + 16 tests. **Not yet wired to a packet source** — `parse_client_hello` and `check_ja4_alerts` are unused outside the test module. Pending pcap/AF_PACKET capture integration in Phase 3. |

| Desktop UI: Incidents page (correlation view) | ✅ Done | React cards, expandable alerts, score pills |
| Desktop UI: Memory Forensics page (3 tabs) | ✅ Done | Injections / NTDLL Hooks / BYOVD tabs |
| Desktop UI: Threat Intel page (IOC stats) | ✅ Done | Stat grid, manual feed refresh, source list |

**Coverage today:** ~120 ATT&CK techniques across TA0001-TA0011 (eBPF agent attaches the 5 probes and `arqenor-cli` bridges `EbpfEvent` → `Alert` via `scan_tx`).
**Gaps vs commercial EDR:**
- ETW-TI / PPL (requires MVI membership ~12mo).
- Behavioral ML — Phase 4 Isolation Forest pending.
- YARA memory scanning is feature-gated (`--features yara`); not enabled in default release builds yet. Per-PID scan currently Windows-only.
- JA4 TLS fingerprinting not yet wired to a live packet source (pcap/AF_PACKET) — module + signatures only.

---

## Roadmap Index

| Phase | Focus | Timeline | ATT&CK Coverage | Status |
|-------|-------|----------|-----------------|--------|
| [Phase 1](phases/phase1-detection-engine.md) | Detection Engine + LOTL Rules | Q2 2026 | +40 techniques | ✅ Done |
| [Phase 2](phases/phase2-kernel-telemetry.md) | Kernel Telemetry (ETW / eBPF / Driver) | Q3 2026 | +30 techniques | 🚧 Mostly done — ETW + Win driver + macOS ESF (Rust `endpoint-sec`, not the original Swift FFI plan) + eBPF loader (5 probes attached) shipped; eBPF→pipeline wiring + C6 ETW-TI pending MVI |
| [Phase 3](phases/phase3-network-deep.md) | Deep Network Analysis + C2 Detection | Q3 2026 | +20 techniques | 🚧 Mostly done — beaconing/DNS-tunnel/DGA/JA4/conn-monitor shipped; A3 IPv6, F2 SMB lateral, F3 Kerberoasting, F4 ARP poisoning still open |
| [Phase 4](phases/phase4-ml-behavioral.md) | ML Behavioral Engine | Q4 2026 | +25 techniques | 🚧 SIGMA + IOC + correlation + static PE analyzer + SQLite IOC persistence (F4) wired; F2 Isolation Forest behavioral ML pending |
| [Phase 5](phases/phase5-memory-forensics.md) | Memory Forensics + Anti-Injection | Q1 2027 | +15 techniques | 🚧 VAD + hollowing + NTDLL hooks + BYOVD + YARA memory scanning (feature-gated `--features yara`, Windows host-scan wired) all shipped |
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
> callbacks WITH full call-stack context. This is what CrowdStrike and ArqenorOne
> use to detect direct/indirect syscall injection, process hollowing, and
> reflective DLL loading. Open-source tools have ZERO access to this because
> it requires a PPL-signed (Protected Process Light) kernel driver.
>
> ARQENOR's Phase 2 plan: implement a kernel driver + ETW consumer to close this gap.

---

## Threat Coverage Map

```
TA0001 Initial Access      — ✅ IOC hash/URL matching, PE static analysis, phishing file detection
TA0002 Execution           — ✅ LOLBin (32 rules), SIGMA (3000+), ETW PS 4104  · 🚧 eBPF execve scaffolded (loader does not attach)  · ❌ YARA memory not integrated
TA0003 Persistence         — ✅ Win B1-B9, Linux C1-C7, macOS 5 detectors, kernel CmRegister
TA0004 Privilege Escalation — ✅ BYOVD detection (50 drivers), UAC bypass rules  · 🚧 eBPF commit_creds scaffolded (not loaded)
TA0005 Defense Evasion     — ✅ NTDLL hook detection, process hollowing (VAD), AMSI bypass  · ❌ YARA (CS/Mimikatz/Sliver) not integrated
TA0006 Credential Access   — ✅ LSASS scan, SAM dump, credential guard check  · ❌ Mimikatz YARA not integrated
TA0007 Discovery           — ✅ Network enumeration patterns, port scan detection
TA0008 Lateral Movement    — ⏳ SMB anomalies (partial — flow-level only); F2/F3/F4 (SMB pattern, Kerberoasting, ARP poisoning) open
TA0009 Collection          — ⏳ Clipboard/keylogging patterns (not started)
TA0010 Exfiltration        — ✅ DNS tunneling (Shannon entropy), DGA detection
TA0011 C2                  — ✅ Beaconing (CV scoring), IOC IP/domain, DGA, DNS tunnel, JA4 TLS fingerprinting
```
