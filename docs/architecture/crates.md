# Rust Crates Reference

The Rust workspace lives under `rust/` and contains six crates arranged in a strict dependency hierarchy.

```
sentinel-core
    └── sentinel-platform
    └── sentinel-store
            └── sentinel-grpc
            └── sentinel-cli
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
| `models/network.rs` | `FlowKey`, `FlowRecord` (timestamps, conn_count) · `BeaconScore` (CV, score) · `DnsQuery` · `DnsAnomalyScore` (tunneling_score, dga_score) |

### Rules engine (`rules/`)

| Module | Purpose |
|---|---|
| `rules/mod.rs` | `DetectionRule`, `RuleCondition` (ProcessCreate / ProcessName), `Pattern` glob matcher |
| `rules/engine.rs` | `evaluate(rule, event) -> Option<Alert>`, `evaluate_all(rules, event) -> Vec<Alert>` |
| `rules/lolbin.rs` | 15 built-in LOLBin rules (SENT-1001 to SENT-1015) |
| `rules/network.rs` | `analyze_beaconing()` (C2 T1071), `analyze_dns_tunneling()` (T1071.004), `score_dga()` (T1568.002), `shannon_entropy()` |

### Detection pipeline (`pipeline.rs`)

| Type | Purpose |
|---|---|
| `DetectionPipeline` | `tokio::select!` loop consuming `ProcessEvent` + `FileEvent` + `ConnectionInfo` streams + 60s analysis interval. Process rules, file-path rules, C2 beaconing flow analysis |
| `PipelineConfig` | Holds process rules + sensitive path rules (default loads all built-in rules) |
| `PipelineStats` | Atomic counters: process_events, file_events, conn_events, alerts_fired |
| `with_connections()` | Constructor variant that adds a `Receiver<ConnectionInfo>` for network analysis |
| `DetectionEngine` | Legacy convenience builder (spawns pipeline, returns stats handle) |

### Traits

| Trait | Methods |
|---|---|
| `ProcessMonitor` | `async fn snapshot() -> Vec<ProcessInfo>` · `async fn watch(Sender<ProcessEvent>)` · `async fn enrich(pid) -> ProcessInfo` |
| `PersistenceDetector` | `async fn detect() -> Vec<PersistenceEntry>` · `async fn diff_baseline(&[PersistenceEntry]) -> Vec<PersistenceEntry>` |
| `FsScanner` | `async fn scan_path(root, config) -> Vec<FileEvent>` · `async fn hash_file(path) -> FileHash` · `async fn watch_path(root, Sender<FileEvent>)` |
| `ConnectionMonitor` | `async fn snapshot() -> Vec<ConnectionInfo>` · `async fn watch(Sender<ConnectionInfo>, interval_ms)` (default: NotSupported) |

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
| Extra deps | `windows-rs 0.52`, `winreg` | `inotify 0.10`, `libbpf-rs` | `plist`, `endpoint-sec 0.5` |

### Adding a new platform

1. Create `src/<platform>/` with `process_monitor.rs`, `fs_scanner.rs`, `persistence.rs`
2. Implement the three traits from `sentinel-core`
3. Add a branch in `src/lib.rs` factory functions inside `cfg_if!`
4. Add conditional deps in `Cargo.toml` with `[target.'cfg(...)'.dependencies]`

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
    --interval <SECS>   Repeat scan every N seconds (default: 30)
```

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
