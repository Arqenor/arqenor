# Configuration Reference

All runtime configuration lives in `configs/sentinel.toml` (TOML format). At startup, each binary looks for this file in the current working directory, then falls back to `~/.config/sentinel/sentinel.toml`.

Override the path with the `--config <path>` flag (CLI / gRPC server) or `SENTINEL_CONFIG` environment variable.

---

## Full annotated example

```toml
# ─────────────────────────────────────────────
# [general] — global runtime settings
# ─────────────────────────────────────────────
[general]

# Log verbosity. Affects both Rust (tracing) and Go (zap) components.
# Values: trace | debug | info | warn | error
log_level = "info"

# Directory for SQLite database and log files.
# Created automatically if it does not exist.
data_dir = "./data"


# ─────────────────────────────────────────────
# [grpc] — gRPC server addresses
# ─────────────────────────────────────────────
[grpc]

# Address of the Rust sentinel-grpc server (HostAnalyzer service).
# Change only if running gRPC on a non-default port or remote host.
host_analyzer_addr = "127.0.0.1:50051"

# Address of the network scanner gRPC service (Phase 3).
network_scanner_addr = "127.0.0.1:50052"


# ─────────────────────────────────────────────
# [api] — Go REST API
# ─────────────────────────────────────────────
[api]

# Bind address for the Gin REST API served by the Go orchestrator.
# Change to "0.0.0.0:8080" to expose externally (use with care).
listen_addr = "127.0.0.1:8080"


# ─────────────────────────────────────────────
# [scan] — filesystem scan parameters
# ─────────────────────────────────────────────
[scan]

# Root paths to scan. Supports multiple entries.
# Windows paths use double backslashes.
fs_roots = [
  "C:\\Users",
  "C:\\Windows\\System32",
]

# Maximum file size to hash (SHA-256), in bytes.
# Files larger than this are recorded but not hashed.
# 0 = no limit (not recommended for large roots).
max_file_size = 10485760   # 10 MB

# Interval between automatic scans in watch mode (seconds).
interval_secs = 60


# ─────────────────────────────────────────────
# [alerts] — alert filtering
# ─────────────────────────────────────────────
[alerts]

# Minimum severity to record in the database and surface in TUI.
# Values: info | low | medium | high | critical
# Set to "info" during initial baselining; raise to "medium" in production.
min_severity = "medium"
```

---

## Key reference

### [general]

| Key | Type | Default | Description |
|---|---|---|---|
| `log_level` | string | `"info"` | Verbosity: `trace` `debug` `info` `warn` `error` |
| `data_dir` | path | `"./data"` | Runtime data directory (SQLite, logs) |

### [grpc]

| Key | Type | Default | Description |
|---|---|---|---|
| `host_analyzer_addr` | address | `"127.0.0.1:50051"` | Rust HostAnalyzer gRPC endpoint |
| `network_scanner_addr` | address | `"127.0.0.1:50052"` | Network scanner gRPC endpoint |

### [api]

| Key | Type | Default | Description |
|---|---|---|---|
| `listen_addr` | address | `"127.0.0.1:8080"` | Go orchestrator REST bind address |

### [scan]

| Key | Type | Default | Description |
|---|---|---|---|
| `fs_roots` | string[] | — | Filesystem roots to scan |
| `max_file_size` | integer | `10485760` | Max bytes to hash per file |
| `interval_secs` | integer | `60` | Seconds between scans in watch mode |

### [alerts]

| Key | Type | Default | Description |
|---|---|---|---|
| `min_severity` | enum | `"medium"` | Minimum severity to persist/show |

---

## Environment variable overrides

Any config key can be overridden via environment variables using the pattern `SENTINEL_<SECTION>_<KEY>` (uppercase, underscores):

```bash
SENTINEL_GENERAL_LOG_LEVEL=debug
SENTINEL_API_LISTEN_ADDR=0.0.0.0:9090
SENTINEL_ALERTS_MIN_SEVERITY=info
```

Environment variables take precedence over the TOML file.

---

## Multiple environments

Use separate config files and pass `--config`:

```bash
# Development — verbose, scan temp dirs
sentinel-grpc --config configs/sentinel.dev.toml

# Production — medium+ alerts only, scan system dirs
sentinel-grpc --config configs/sentinel.prod.toml
```
