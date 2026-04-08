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
| `models/process.rs` | `ProcessInfo` (pid, ppid, name, exe_path, cmdline, user, sha256, loaded_modules) · `ProcessEvent` (Created / Terminated / Modified) |
| `models/persistence.rs` | `PersistenceKind` enum: RegistryRun, ScheduledTask, WindowsService, SystemdUnit, Cron, RcLocal, LdPreload, LaunchDaemon, LaunchAgent, StartupFolder |
| `models/file_event.rs` | `FileEvent` — kind (Created / Modified / Deleted / Renamed), path, hash, size |
| `models/alert.rs` | `Alert` — id, severity, kind, message, timestamp, metadata |

### Traits

| Trait | Methods |
|---|---|
| `ProcessMonitor` | `async fn snapshot() -> Vec<ProcessInfo>` · `async fn watch() -> Stream<ProcessEvent>` · `async fn enrich(ProcessInfo) -> ProcessInfo` |
| `PersistenceDetector` | `async fn detect() -> Vec<PersistenceEntry>` |
| `FsScanner` | `async fn scan(root, opts) -> Stream<FileEvent>` · `async fn watch(root) -> Stream<FileEvent>` |

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
| Process snapshot | `sysinfo` | `procfs` | `sysinfo` |
| Process events | placeholder (ETW Phase 2) | `inotify` on `/proc` | placeholder |
| Filesystem watch | planned | `inotify` | planned |
| Persistence — system | Registry Run/RunOnce, Services | systemd units, rc.local | LaunchDaemon (`/Library/LaunchDaemons`) |
| Persistence — user | HKCU Run keys, Startup folder | cron, LD_PRELOAD | LaunchAgent (`~/Library/LaunchAgents`) |
| Extra deps | `winreg`, `wmi`, `windows` | `procfs`, `inotify` | `plist` |

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
| `alerts` | Alert history | `id`, `severity`, `kind`, `message`, `timestamp`, `metadata JSON` |
| `rules` | Detection rules | `id`, `kind`, `expression TEXT`, `enabled BOOL` |
| `persistence_baseline` | Drift detection baseline | `kind`, `name`, `command`, `location`, `first_seen` |

### Public API

```rust
pub struct SqliteStore { /* ... */ }

impl SqliteStore {
    pub fn open(path: &Path) -> Result<Self>
    pub fn insert_alert(&self, alert: &Alert) -> Result<()>
    pub fn list_alerts(&self, min_severity: Severity) -> Result<Vec<Alert>>
    pub fn get_config(&self, key: &str) -> Result<Option<String>>
    pub fn set_config(&self, key: &str, value: &str) -> Result<()>
    pub fn upsert_baseline(&self, entries: &[PersistenceEntry]) -> Result<()>
    pub fn diff_baseline(&self, current: &[PersistenceEntry]) -> Result<Vec<PersistenceEntry>>
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
