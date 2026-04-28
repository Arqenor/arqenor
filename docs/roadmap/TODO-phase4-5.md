# TODO — Phase 4+5 : ML Behavioral + Memory Forensics
> Q4 2026 – Q1 2027 | ~40 ATT&CK techniques | Priorité : HAUTE
> Last updated: 2026-04-10

Légende : `[ ]` à faire · `[~]` en cours · `[x]` terminé

---

## SECTION A — SIGMA Rule Engine (Phase 4.3)

> fichiers : `rust/arqenor-core/src/rules/sigma.rs` + `sigma_condition.rs`

- [x] **A1** — Parser YAML SIGMA → `SigmaRule` struct
  - `serde_yaml` parsing, `LogSource`, `Detection`, `SelectionGroup`
  - 7 modifiers : `|contains`, `|endswith`, `|startswith`, `|re`, `|base64`, `|cidr`, `|all`
  - Tags → ATT&CK IDs extraction (`attack.t1059.001` → `T1059.001`)

- [x] **A2** — Condition expression parser (`sigma_condition.rs`)
  - Recursive descent : `and`, `or`, `not`, `(parens)`, `1 of X*`, `all of them`
  - `evaluate()` against `HashMap<String, bool>` selection results

- [x] **A3** — Field mapping SIGMA → ARQENOR (30+ fields)
  - `Image` → `image_path`, `CommandLine` → `cmdline`, `TargetObject` → `key_path`...

- [x] **A4** — `load_sigma_rules_from_dir()` + `evaluate()` entry points

- [x] **A5** — Wire SIGMA into `DetectionPipeline`
  - `PipelineConfig.sigma_rules: Vec<SigmaRule>`, loaded at startup via `--sigma-dir`
  - `handle_process_event()` evaluates `process_creation` rules via `sigma::evaluate()`
  - `handle_file_event()` evaluates `file_event` rules
  - Match → `Alert { kind: "sigma_match", rule_id, attack_id }`

---

## SECTION B — IOC Threat Intelligence (Phase 4.4)

> fichiers : `rust/arqenor-core/src/ioc/`

- [x] **B1** — `IocDatabase` in-memory HashSet (SHA-256, MD5, IP, domain, URL)
  - Subdomain matching (`evil.com` matche `sub.evil.com`)
  - Case-insensitive normalization

- [x] **B2** — 4 feeds async (abuse.ch)
  - MalwareBazaar (SHA-256 hashes), Feodo Tracker (C2 IPs)
  - URLhaus (malicious URLs), ThreatFox (mixed IOCs)
  - `refresh_all_feeds()` + `spawn_feed_refresh_loop(Arc<RwLock>)`

- [x] **B3** — `IocChecker` → Alert generation
  - IOC-1001 hash, IOC-1002 IP, IOC-1003 domain, IOC-1004 URL

- [x] **B4** — Wire IOC into `DetectionPipeline`
  - `PipelineConfig.ioc_db: Option<Arc<RwLock<IocDatabase>>>`, shared with feed refresh loop
  - `handle_process_event()` checks process image SHA-256 via `IocChecker::check_file_hash()`
  - `handle_file_event()` checks file SHA-256 via `IocChecker::check_file_hash()`
  - `handle_connection_event()` checks destination IP via `IocChecker::check_connection()`
  - CLI: `--no-ioc` flag, feeds refresh every 4h in background

---

## SECTION C — Alert Correlation Engine (Phase 4.5)

> fichiers : `rust/arqenor-core/src/correlation.rs` + `models/incident.rs`

- [x] **C1** — `CorrelationEngine` avec PID grouping
  - `active: HashMap<u32, Incident>`, `orphan: HashMap<u64, Incident>`
  - Parent-child aliasing via `ppid` metadata field

- [x] **C2** — ATT&CK-weighted scoring
  - Base: Info=1, Low=5, Med=15, High=30, Crit=50
  - Multipliers: T1003 (creds) ×3, T1055 (injection) ×2, T1547 (persistence) ×2

- [x] **C3** — `flush_stale()` (5min window) + 24h retention

- [x] **C4** — `build_summary()` narrative auto-generation

- [x] **C5** — Wire correlation into pipeline + Tauri
  - `DetectionPipeline` holds `Mutex<CorrelationEngine>`, all alerts go through `emit_alert()`
  - `emit_alert()` ingests into correlation, emits `Incident` on `incident_tx` on severity escalation
  - `flush_stale()` runs every 60s on analysis interval
  - `with_incident_channel(tx)` for optional incident consumption
  - Tauri commands stubbed (E5)

---

## SECTION D — Memory Forensics (Phase 5.1-5.2)

> fichiers : `rust/arqenor-platform/src/windows/`

- [x] **D1** — `memory_scan.rs` : VAD tree walk (`VirtualQueryEx` loop)
  - Anonymous executable memory detection (MEM_PRIVATE + EXECUTE)
  - Executable heap detection
  - 50,000 regions safety limit per process

- [x] **D2** — Process hollowing detection (`check_hollowing`)
  - PE header comparison (disk vs memory) : AddressOfEntryPoint, ImageBase, SizeOfImage
  - Supports PE32 and PE32+

- [x] **D3** — `ntdll_check.rs` : NTDLL hook detection
  - 10 critical functions (NtAllocateVirtualMemory, NtWriteVirtualMemory, NtCreateThreadEx...)
  - PE export table parser (DOS → PE → export directory → RVA → file offset)
  - Hook classification : InlineJmp, Trampoline, Breakpoint, Unknown

- [x] **D4** — `byovd.rs` : BYOVD driver detection
  - `EnumDeviceDrivers` + SHA-256 hashing
  - 50 known-vulnerable drivers embedded (Dell DBUtil, Gigabyte gdrv, MSI RTCore64...)

- [x] **D5** — Wire memory scan results into Alert pipeline
  - `scan_tx`/`scan_rx` channel: external scans push `Alert` into pipeline via `with_scan_alerts(rx)`
  - Windows host scans run every 5 min: BYOVD → Alert (SENT-DRV-001, T1068), ntdll hooks → Alert (SENT-MEM-001, T1562.001), memory anomalies → Alert (SENT-MEM-002, T1055/T1055.012)
  - YARA scanning: ❌ not yet — `yara-x` not a dependency in any crate (see F3 below)

---

## SECTION E — Desktop UI (Phase 4-5 frontend)

> fichiers : `arqenor-desktop/src/pages/`

- [x] **E1** — `Incidents.tsx` : vue incidents avec cards
  - Severity filter, score pills, ATT&CK badges, expandable alerts
  - Auto-refresh 10s

- [x] **E2** — `MemoryForensics.tsx` : 3 onglets
  - Injections (VAD anomalies), NTDLL Hooks (10 fonctions), BYOVD Drivers
  - Scan manuel (expensive)

- [x] **E3** — `IocDatabase.tsx` : Threat Intel dashboard
  - Grille 3×2 stat cards, refresh feeds, 4 sources abuse.ch
  - Auto-refresh stats 30s

- [x] **E4** — Sidebar + routes mis à jour (3 nouvelles entrées)

- [x] **E5** — 6 Tauri commands stubs
  - `get_incidents`, `scan_memory`, `check_ntdll`, `check_byovd`, `get_ioc_stats`, `refresh_ioc_feeds`

---

## SECTION F — Remaining (à faire)

- [x] **F1** — PE Static Analyzer (`arqenor-ml` crate)
  - `pe_parser.rs` — parsing PE manuel (DOS → COFF → sections → imports), 100% safe Rust
  - `pe_features.rs` — 25+ features (entropy, imports suspects, RWX, overlay, timestamps)
  - `pe_scorer.rs` — scoring heuristique, classification Clean/Low/Medium/High/Malicious
  - `entropy.rs` + `pe_strings.rs` — Shannon entropy, URL/IP/base64/registry detection
  - 25 tests, `cargo test -p arqenor-ml` all green

- [ ] **F2** — Process Behavior Anomaly Detection
  - `ProcessBehaviorWindow` (5-min windowed features per process)
  - Isolation Forest (unsupervised) — learns normal per-machine baseline
  - Training phase (30 jours), detection phase (continuous)

- [x] **F3** — YARA Memory Scanning
  - `yara-x = "=1.15.0"` added behind `yara` feature in `arqenor-platform` (off by default; `arqenor-cli` exposes a forwarding `yara` feature)
  - `rust/arqenor-platform/src/yara_scan.rs` — `YaraScanner` (pure-Rust `yara-x`), `scan_bytes` / `scan_process` / `scan_all_processes`, `matches_to_alerts` mapping to `SENT-YARA-NNN`
  - `rust/arqenor-platform/src/yara_rules/` — 9 embedded `.yar` files: Cobalt Strike, Meterpreter, Mimikatz, Sliver, Brute Ratel, Havoc, generic shellcode, PE injection (reflective + Donut), encoded PowerShell
  - Wired into the Windows host-scan loop in `arqenor-cli/src/commands/watch.rs::run_yara_scan` alongside BYOVD / ntdll-hooks / memory anomalies (5-min cadence)
  - Per-process scan currently Windows-only (`ReadProcessMemory` + `VirtualQueryEx`); Linux/macOS return `YaraError::ProcessScanUnsupported` while `scan_bytes` works everywhere
  - 5 unit tests in `yara_scan::tests` — builtin compile, custom rule match, no-match on benign bytes, Mimikatz canonical strings, alert-format roundtrip

- [x] **F4** — SQLite IOC persistence
  - `IocSqliteStore` in `rust/arqenor-store/src/ioc_store.rs` (schema `ioc_feeds` + `iocs` documented at top of file), implements the `IocPersistence` trait from `rust/arqenor-core/src/ioc/persistence.rs`
  - Wired into the watch loop via `open_ioc_store` + `IocSqliteStore::open` in `rust/arqenor-cli/src/commands/watch.rs:70-281`
  - Boot-time integration test: `rust/arqenor-cli/tests/ioc_boot.rs`
  - Landed in commit `9e19a49 feat(ioc,correlation): persistence wiring + configurable flush window (#39)`
  - Incremental delta feed updates remain a follow-up (current path persists full snapshots)

- [x] **F5** — Wiring cleanup — ALL DONE
  - ✅ SIGMA rules in pipeline (process + file events → sigma::evaluate)
  - ✅ IOC checker in pipeline (hash on process/file, IP on connections)
  - ✅ Correlation engine in pipeline (emit_alert → ingest, flush_stale 60s, incident_tx)
  - ✅ Memory scan / ntdll / BYOVD → alerts via scan_tx (periodic 5 min)
  - ✅ YARA scanning wired (F3 — `yara-x` engine + 9 embedded rule files behind the `yara` feature, Windows host-scan loop pushes `SENT-YARA-NNN` alerts via `scan_tx`)
  - ✅ ConnectionMonitor wired: live beaconing + IOC IP detection
  - ✅ JA4 TLS fingerprinting module ready (needs packet source integration)
  - ✅ gRPC WatchProcesses / WatchFilesystem implemented in `rust/arqenor-grpc/src/server/host_analyzer.rs` (`watch_processes` lines 241-269 bridges core `ProcessEvent` → stream via `ReceiverStream`; `watch_filesystem` lines 309-352 bridges core `FileEvent` → stream, falling back to `default_fim_path()` when `root_path` is empty). Smoke-tested by `watch_filesystem_smoke` (line 584).

---

## Crates touchées

| Crate | Sections | Statut |
|-------|----------|--------|
| `arqenor-core` (rules/sigma) | A1–A4 | ✅ |
| `arqenor-core` (ioc) | B1–B3 | ✅ |
| `arqenor-core` (correlation) | C1–C4 | ✅ |
| `arqenor-platform` (memory) | D1–D4 | ✅ |
| `arqenor-desktop` (UI) | E1–E5 | ✅ |
| `arqenor-core` (pipeline wiring) | A5, B4, C5, D5, F5 | ✅ all wired |
| `arqenor-ml` (nouveau) | F1 | ✅ (F2 behavioral pending) |
| `arqenor-platform` (yara) | F3 | 🔴 not started — no `yara-x` dep yet |
| `arqenor-core` (tls_fingerprint) | (Phase 3 F1) | ✅ |
| `arqenor-store` (ioc persist) | F4 | ✅ |

---

## Hardening (2026-04-27 security pass)

### SIGMA engine

- [x] **A-HARD-1** — Replace deprecated `serde_yaml 0.9` (RUSTSEC-2024-0320) with `serde_yml 0.0.12` for SIGMA YAML parsing (DEP-SERDE_YAML). `arqenor-core/Cargo.toml`. (2026-04-27)
- [x] **A-HARD-2** — Bound regex input length to `MAX_REGEX_INPUT = 64 KiB`, `RegexBuilder::size_limit(1 MB)`, LRU cache for compiled regexes (SIGMA-REGEX). `arqenor-core/src/rules/sigma.rs`. (2026-04-27)

### IOC pipeline

- [x] **B-HARD-1** — Replace handcrafted `splitn(',')` parser with the `csv` crate (`ReaderBuilder::flexible(true).comment(b'#')`) for MalwareBazaar / Feodo / URLhaus feeds (IOC-CSV). (2026-04-27)
- [x] **B-HARD-2** — `tokio::time::timeout(120s)` global on feed refresh; fetch + parse moved outside the lock; atomic swap on `RwLock<IocDb>` (IOC-FEED-TIMEOUT). (2026-04-27)
- [x] **B-HARD-3** — `MAX_FEED_SIZE = 256 MiB`; streaming `read_body_capped` with `Content-Length` belt + `take` (IOC-SIZE). `arqenor-core/src/ioc/feeds.rs`. (2026-04-27)

### Correlation engine

- [x] **C-HARD-1** — `MAX_ACTIVE_INCIDENTS = 100_000` cap with auto-flush when reached, hardened doc-comment on `CorrelationEngine` (CORR-LEAK). (2026-04-27)
- [x] **C-HARD-2** — `sanitize_metadata_value` applied in `pipeline::emit_alert` and `correlation::ingest` to strip control chars from `Alert.metadata` (CORR-INJECT). (2026-04-27)

### Memory forensics

- [x] **D-HARD-1** — PPL-protected processes: fallback to `OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION)` when `VM_READ` denied; new public `MemoryScanResult::vm_read_denied` flag (MEMORY-PPL). (2026-04-27)
- [x] **D-HARD-2** — Streaming SHA-256 (`arqenor-platform/src/hash.rs`, 512 MiB cap) replaces `std::fs::read()` in `byovd`, `memory_scan`, `ntdll_check` (PIPE-HASH-OOM). (2026-04-27)
