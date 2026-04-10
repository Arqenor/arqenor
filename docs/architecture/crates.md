# Rust Crates Reference

The Rust workspace lives under `rust/` and contains seven crates (plus two standalone: `sentinel-ebpf`, `sentinel-driver`).

```
sentinel-core
    ├── sentinel-platform
    ├── sentinel-ml
    └── sentinel-store
            ├── sentinel-grpc
            ├── sentinel-cli
            └── sentinel-tui
```

---

## sentinel-core

**Path:** `rust/sentinel-core/`
**Type:** Library
**Role:** Domain nucleus — shared traits, models, and error type. Zero platform dependencies.

### Error type

```rust
pub enum SentinelError {
    Platform(String),
    Io(std::io::Error),
    Database(String),
    Serialization(String),
    NotSupported,
}
```

### Models

| Module | Types |
|---|---|
| `models/process.rs` | `ProcessInfo` (pid, ppid, name, exe_path, cmdline, user, sha256, loaded_modules) · `ProcessEvent` (Created / Terminated / Modified) · `ProcessScore`, `ScoreFactor` |
| `models/persistence.rs` | `PersistenceKind` enum: RegistryRun, ScheduledTask, WindowsService, WmiSubscription, ComHijacking, DllSideloading, BitsJob, AppInitDll, IfeoHijack, AccessibilityHijack, PrintMonitor, LsaProvider, NetshHelper, ActiveSetup, SystemdUnit, Cron, RcLocal, LdPreload, KernelModule, SshAuthorizedKey, PamModule, ShellProfile, GitHook, LaunchDaemon, LaunchAgent, StartupFolder |
| `models/file_event.rs` | `FileEvent` — kind (Created / Modified / Deleted / Renamed), path, hash, size |
| `models/alert.rs` | `Alert` — id, severity, kind, message, timestamp, metadata, rule_id, attack_id |
| `models/connection.rs` | `ConnectionInfo` (pid, proto, local_addr, remote_addr, state) · `Proto` (Tcp/Udp) · `ConnState` |
| `models/network.rs` | `FlowKey`, `FlowRecord` (timestamps, conn_count) · `BeaconScore` (CV, score) · `DnsQuery` · `DnsAnomalyScore` (tunneling_score, dga_score) · `TlsInfo` (ja4, server_name, tls_version) |
| `models/incident.rs` | `Incident` — id, score, severity, attack_ids, alerts, summary, pid, first/last_seen, is_closed |

### Rules engine (`rules/`)

| Module | Purpose |
|---|---|
| `rules/mod.rs` | `DetectionRule`, `RuleCondition` (ProcessCreate / ProcessName), `Pattern` glob matcher |
| `rules/engine.rs` | `evaluate(rule, event) -> Option<Alert>`, `evaluate_all(rules, event) -> Vec<Alert>` |
| `rules/lolbin.rs` | 15 built-in LOLBin rules (SENT-1001 to SENT-1015) |
| `rules/network.rs` | `analyze_beaconing()` (C2 T1071), `analyze_dns_tunneling()` (T1071.004), `score_dga()` (T1568.002), `shannon_entropy()` |
| `rules/sigma.rs` | SIGMA YAML parser + evaluator: 7 modifiers, condition AST, 30+ field mappings, `evaluate()` against `EventFields` |
| `rules/sigma_condition.rs` | Recursive descent parser for SIGMA conditions (`and`, `or`, `not`, `1 of`, `all of them`) |
| `rules/tls_fingerprint.rs` | JA4 TLS fingerprinting: `compute_ja4()`, `parse_client_hello()`, `Ja4Blocklist` (17 C2 fingerprints), `check_ja4_alerts()` |

### IOC Threat Intelligence (`ioc/`)

| Module | Purpose |
|---|---|
| `ioc/mod.rs` | `IocDatabase` — in-memory O(1) HashSet lookup (SHA-256, MD5, IP, domain, URL). Subdomain matching. |
| `ioc/checker.rs` | `IocChecker` — stateless checker producing `Alert` on match (IOC-1001 hash, IOC-1002 IP, IOC-1003 domain, IOC-1004 URL) |
| `ioc/feeds.rs` | 4 async feed fetchers (MalwareBazaar, Feodo Tracker, URLhaus, ThreatFox). `spawn_feed_refresh_loop(Arc<RwLock<IocDatabase>>)` |

### Alert Correlation (`correlation.rs`)

| Type | Purpose |
|---|---|
| `CorrelationEngine` | Groups alerts into `Incident`s by PID + parent-child aliasing. ATT&CK-weighted scoring (T1003 ×3, T1055 ×2). 5-min window, 24h retention. |

### Detection pipeline (`pipeline.rs`)

| Type | Purpose |
|---|---|
| `DetectionPipeline` | `tokio::select!` loop: `ProcessEvent` + `FileEvent` + `ConnectionInfo` + `scan_rx` (external alerts) + 60s analysis interval. LOLBin rules, SIGMA evaluation, IOC checks, file-path rules, C2 beaconing, correlation. |
| `PipelineConfig` | `rules`, `sensitive_paths`, `sigma_rules: Vec<SigmaRule>`, `ioc_db: Option<Arc<RwLock<IocDatabase>>>` |
| `PipelineStats` | Atomic counters: process_events, file_events, conn_events, alerts_fired |
| `with_connections()` | Constructor variant that adds a `Receiver<ConnectionInfo>` for network analysis |
| `with_scan_alerts()` | Adds a `Receiver<Alert>` for external scan results (memory, YARA, BYOVD, ntdll) |
| `with_incident_channel()` | Adds a `Sender<Incident>` for correlated incident output |
| `emit_alert()` | Internal: sends alert on `alert_tx` AND ingests into `CorrelationEngine` |
| `DetectionEngine` | Legacy convenience builder with `.with_sigma_rules()` + `.with_ioc_db()` |

### Traits

| Trait | Methods |
|---|---|
| `ProcessMonitor` | `async fn snapshot() -> Vec<ProcessInfo>` · `async fn watch(Sender<ProcessEvent>)` · `async fn enrich(pid) -> ProcessInfo` |
| `PersistenceDetector` | `async fn detect() -> Vec<PersistenceEntry>` · `async fn diff_baseline(&[PersistenceEntry]) -> Vec<PersistenceEntry>` |
| `FsScanner` | `async fn scan_path(root, config) -> Vec<FileEvent>` · `async fn hash_file(path) -> FileHash` · `async fn watch_path(root, Sender<FileEvent>)` |
| `ConnectionMonitor` | `async fn snapshot() -> Vec<ConnectionInfo>` · `async fn watch(Sender<ConnectionInfo>, interval_ms)` (default: NotSupported) · `spawn_polling_watch()` generic fallback (5s dedup polling) |

---

## sentinel-platform

**Path:** `rust/sentinel-platform/`
**Type:** Library
**Role:** Platform-specific implementations selected at compile time via `cfg_if!`.

### Factory API (public surface)

```rust
pub fn new_process_monitor()    -> impl ProcessMonitor
pub fn new_fs_scanner()         -> impl FsScanner
pub fn new_persistence_detector() -> impl PersistenceDetector
```

These are the only entry points. Callers never import platform sub-modules directly.

### Platform matrix

| Feature | Windows | Linux | macOS |
|---|---|---|---|
| Process snapshot | `sysinfo` | `sysinfo` | `sysinfo` |
| Process events | EvtSubscribe (Security 4688/4689) | /proc poll (500ms HashSet diff) | ESF `NOTIFY_EXEC/EXIT` via `endpoint-sec` |
| Filesystem watch | `ReadDirectoryChangesW` | `inotify` | ESF `NOTIFY_CREATE/WRITE/UNLINK/RENAME` |
| Persistence — system | Registry Run/RunOnce, Services, WMI, COM, BITS, AppInit, IFEO, PrintMon, LSA, Netsh, ActiveSetup | systemd units, cron, LD_PRELOAD, kernel modules, PAM modules, shell profiles, git hooks | LaunchDaemon/Agent + plist parsing, Login Items, Auth Plugins, periodic scripts, cron tabs |
| Persistence — user | HKCU Run keys, Startup folder, Accessibility hijack | SSH authorized_keys, user shell profiles | LaunchAgent, DYLD_INSERT_LIBRARIES |
| Connections | `GetExtendedTcpTable` / `GetExtendedUdpTable` (native IP Helper) | `/proc/net/tcp[6]` + inode→PID | `lsof -i -n -P` |
| Process enrichment | `CreateToolhelp32Snapshot` (loaded DLLs) | `/proc/<pid>/maps` (shared libs) | `sysinfo` |
| ESF / Kernel | ETW (10 providers, TDH parsing) + EvtSubscribe | eBPF (5 probes: execve, memory, persistence, privesc, rootkit) | Endpoint Security Framework (`endpoint-sec` crate) |
| YARA memory scanning | `yara_scan.rs` + `yara_rules.rs` (feature `yara`, off by default) — 9 embedded rules | — | — |
| Extra deps | `windows-rs 0.52`, `winreg`, `yara-x` (optional) | `inotify 0.10`, `libbpf-rs` | `plist`, `endpoint-sec 0.5` |

### Adding a new platform

1. Create `src/<platform>/` with `process_monitor.rs`, `fs_scanner.rs`, `persistence.rs`
2. Implement the three traits from `sentinel-core`
3. Add a branch in `src/lib.rs` factory functions inside `cfg_if!`
4. Add conditional deps in `Cargo.toml` with `[target.'cfg(...)'.dependencies]`

---

## sentinel-ml

**Path:** `rust/sentinel-ml/`
**Type:** Library
**Role:** Static PE analysis and malware scoring. No external ML model — pure heuristic scoring.

### Modules

| Module | Purpose |
|---|---|
| `pe_parser.rs` | Custom PE parser (DOS → COFF → sections → imports). 100% safe Rust, no `goblin`. |
| `pe_features.rs` | 25+ feature extraction: entropy, section flags (RWX), import analysis, overlay, timestamps, TLS, anti-debug |
| `pe_scorer.rs` | Heuristic scoring engine: weighted features → risk score 0.0-1.0, classification (Clean/Low/Medium/High/Malicious) |
| `pe_strings.rs` | ASCII/UTF-16LE string extraction, URL/IP/registry/base64/suspicious keyword detection |
| `entropy.rs` | Shannon entropy computation |

### Public API

```rust
pub fn analyze_pe_file(path: &str, data: &[u8]) -> Option<Alert>
// Returns Alert if risk >= 0.6 (Medium/High/Critical based on score)
// rule_id: "SENT-PE-001", attack_id: "T1204.002"
```

### Tests

25 unit tests covering feature extraction, scoring, string analysis, and integration.

---

## sentinel-grpc

**Path:** `rust/sentinel-grpc/`
**Type:** Binary (`sentinel-grpc`)
**Role:** Tonic gRPC server exposing host analysis over the network.

### Build note

`build.rs` runs `tonic-build` on every `proto/*.proto` file automatically during `cargo build`. Requires `protoc` in `PATH`. Generated stubs land in `src/generated/`.

### Services implemented

#### `HostAnalyzer` (port 50051)

| RPC | Type | Description |
|---|---|---|
| `GetProcessSnapshot` | Unary | Full snapshot of running processes |
| `WatchProcesses` | Server-streaming | Emit `ProcessEvent` on create / terminate / modify |
| `ScanFilesystem` | Server-streaming | Walk filesystem from `ScanRequest.root_path` |
| `WatchFilesystem` | Server-streaming | Inotify/FSEvents watch, emit `FileEvent` |
| `GetPersistence` | Unary | Detect all persistence mechanisms |
| `Health` | Unary | Returns status, platform string, version |

#### `NetworkScanner` (port 50052) — planned Phase 3

| RPC | Type | Description |
|---|---|---|
| `StartScan` | Server-streaming | CIDR sweep → `HostResult` stream |
| `ReportAnomaly` | Unary | Ingest anomaly detected by Go network layer |

### Internal structure

```
sentinel-grpc/
├── build.rs              # tonic-build invocation
├── src/
│   ├── main.rs           # Tokio runtime, tonic Server::builder
│   ├── services/
│   │   ├── host_analyzer.rs   # HostAnalyzerService impl
│   │   └── network_scanner.rs # NetworkScannerService impl (stub)
│   └── generated/        # Auto-generated — do not edit
│       ├── sentinel.rs
│       └── sentinel_grpc.rs
```

---

## sentinel-store

**Path:** `rust/sentinel-store/`
**Type:** Library
**Role:** SQLite persistence layer using `rusqlite` (bundled libsqlite3).

### Schema

| Table | Purpose | Key columns |
|---|---|---|
| `config` | Key-value store | `key TEXT PK`, `value TEXT` |
| `alerts` | Alert history | `id`, `severity`, `kind`, `message`, `occurred_at`, `metadata JSON`, `rule_id`, `attack_id` |
| `rules` | Detection rules | `id`, `kind`, `expression TEXT`, `enabled BOOL` |
| `persistence_baseline` | Drift detection baseline | `kind`, `name`, `command`, `location`, `captured_at` |
| `process_events` | Real-time process event log | `id`, `kind`, `pid`, `ppid`, `name`, `exe_path`, `cmdline`, `event_time` |
| `file_events` | Real-time file event log | `id`, `kind`, `path`, `sha256`, `size`, `event_time` |

Indexes: `idx_alerts_time`, `idx_proc_evt_time`, `idx_file_evt_time`.

### Public API

```rust
pub struct SqliteStore { /* ... */ }

impl SqliteStore {
    pub fn open(path: &Path) -> Result<Self>
    pub fn insert_alert(&self, alert: &Alert) -> Result<()>
    pub fn insert_process_event(&self, evt: &ProcessEvent) -> Result<()>
    pub fn insert_file_event(&self, evt: &FileEvent) -> Result<()>
    pub fn list_alerts(&self, limit: usize) -> Result<Vec<Alert>>
    pub fn alert_counts_by_severity(&self) -> Result<Vec<(String, u64)>>
    pub fn get_config(&self, key: &str) -> Result<Option<String>>
    pub fn set_config(&self, key: &str, value: &str) -> Result<()>
}
```

### DuckDB (Phase 4)

`duckdb_store.rs` is present but disabled. The `arrow-arith 0.10` / `chrono` dependency conflict on Rust 1.80+ must resolve before enabling. It will power event-level analytics queries.

---

## sentinel-cli

**Path:** `rust/sentinel-cli/`
**Type:** Binary (`sentinel`)
**Role:** Quick-access command-line scanner.

### Commands

```
sentinel scan [OPTIONS]
    --host           Include running processes
    --persistence    Include persistence mechanisms
    --json           Output machine-readable JSON

sentinel watch [OPTIONS]
    --watch-path <PATH>     FIM watch directory (default: C:\Windows\System32 or /etc)
    --db <PATH>             SQLite database (default: sentinel.db)
    --sigma-dir <PATH>      Directory containing SIGMA YAML rules
    --no-ioc                Disable IOC threat-intelligence feed loading
    --yara-dir <PATH>       Custom YARA rules directory (requires --features yara)
```

### Features

| Feature | Description |
|---|---|
| `kernel-driver` | Enable kernel driver bridge for kernel-level telemetry |
| `yara` | Enable YARA memory scanning (pulls in `yara-x`) |

### Example output

```
$ sentinel scan --host --persistence
Processes (42 running)
 PID   PPID  NAME             USER     RISK
 1234  800   chrome.exe       alice    Normal
 5678  1     svchost.exe      SYSTEM   Normal
 9012  1     unknown.exe      SYSTEM   HIGH    ← sha256: aabbcc...

Persistence (3 entries)
 KIND          NAME               COMMAND
 RegistryRun   MyCoolApp          C:\Temp\malware.exe   ← NEW
 SystemService  WinDefend         ...
```

---

## sentinel-tui

**Path:** `rust/sentinel-tui/`
**Type:** Binary (`sentinel-tui`)
**Role:** Live Ratatui terminal dashboard.

### Tabs

| Tab | Shortcut | Content |
|---|---|---|
| **Processes** | `1` | Scrollable process table with risk badges |
| **Persistence** | `2` | Detected persistence entries, NEW items highlighted |
| **Network** | `3` | LAN host discovery, open ports, VPN status |

### Keyboard controls

| Key | Action |
|---|---|
| `Tab` / `1` `2` `3` | Switch tab |
| `↑` / `k` | Move up |
| `↓` / `j` | Move down |
| `r` | Refresh current tab |
| `s` | Start network scan |
| `/` | Open filter input |
| `q` / `Ctrl+C` | Quit |

### Risk levels

| Level | Colour | Criteria |
|---|---|---|
| Normal | Green | Known system process, signed binary |
| Low | Cyan | Unsigned but recognised path |
| Medium | Yellow | Unknown hash, suspicious parent |
| High | Red | Unsigned + anomalous location |
| Critical | Magenta | Active threat indicator match |

### VPN detection

Identified by process name match against: Mullvad, NordVPN, OpenVPN, WireGuard, ExpressVPN, ProtonVPN, Surfshark, PIA. VPN status shown in the Network tab header.
