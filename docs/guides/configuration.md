# Configuration Reference

All runtime configuration lives in `configs/arqenor.toml` (TOML format).

**Path probe order** (both Rust and Go sides):

1. Explicit path argument (`--config <path>`).
2. `ARQENOR_CONFIG` environment variable.
3. `./configs/arqenor.toml` (relative to the current working directory).

The Rust loader is `arqenor_core::config::Config::load()` / `Config::load_from(path)`. The Go loader lives in `internal/config` and follows the same probe order. Defaults are secure: API and gRPC bind to `127.0.0.1`, `max_file_size = 10 MiB`, `min_severity = medium`. **Do not flip `[api].listen_addr` to `0.0.0.0` until the Next.js SaaS auth layer is in place.**

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

# Address of the Rust arqenor-grpc server (HostAnalyzer service).
# Change only if running gRPC on a non-default port or remote host.
host_analyzer_addr = "127.0.0.1:50051"

# Address of the network scanner gRPC service (Phase 3).
network_scanner_addr = "127.0.0.1:50052"


# ─────────────────────────────────────────────
# [api] — Go REST API
# ─────────────────────────────────────────────
[api]

# Bind address for the Gin REST API served by the Go orchestrator.
# Defaults to localhost. Do NOT switch to 0.0.0.0 until the SaaS auth layer ships.
listen_addr = "127.0.0.1:8080"

# Maximum concurrent SSE alert subscribers. New subscribers above this cap
# receive HTTP 503 with body {"error":"max sse connections reached"}.
max_sse_connections = 100         # optional, default 100

# Per-IP token-bucket rate limit (requests/second). Excess returns HTTP 429.
rate_limit_per_sec = 20           # optional, default 20

# Hard timeout (seconds) applied to scans triggered via POST /scans.
# The handler wraps the scan goroutine in a context.WithTimeout of this duration.
scan_timeout_seconds = 600        # optional, default 600


# ─────────────────────────────────────────────
# [scan] — filesystem scan parameters
# ─────────────────────────────────────────────
[scan]

# Root paths to scan. Supports multiple entries.
# Windows paths use double backslashes.
#
# IMPORTANT: this list is also the gRPC server's allowlist. Any incoming
# ScanRequest whose root_path (after canonicalisation) does not start with
# one of these prefixes is rejected with Status::permission_denied.
fs_roots = [
  "C:\\Users",
  "C:\\Windows\\System32",
]

# Maximum file size to hash (SHA-256), in bytes.
# Files larger than this are recorded but not hashed.
# 0 = no limit (not recommended for large roots).
# On the gRPC wire: max_size_bytes = 0 maps to the server default (10 GiB),
# any value > 10 GiB is rejected.
max_file_size = 10485760   # 10 MiB

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
| `max_sse_connections` | integer | `100` | SSE alert stream subscriber cap (HTTP 503 on overflow) |
| `rate_limit_per_sec` | integer | `20` | Per-IP token-bucket rate limit (HTTP 429 on overflow) |
| `scan_timeout_seconds` | integer | `600` | Per-scan `context.WithTimeout` for `POST /scans` |

### [scan]

| Key | Type | Default | Description |
|---|---|---|---|
| `fs_roots` | string[] | — | Filesystem roots to scan. Also the gRPC server allowlist for `ScanRequest.root_path` — paths outside it return `Status::permission_denied`. |
| `max_file_size` | integer | `10485760` | Max bytes to hash per file. gRPC wire: `0` maps to 10 GiB, `> 10 GiB` is rejected. |
| `interval_secs` | integer | `60` | Seconds between scans in watch mode |

### [alerts]

| Key | Type | Default | Description |
|---|---|---|---|
| `min_severity` | enum | `"medium"` | Minimum severity to persist/show |

---

## Environment variable overrides

Any config key can be overridden via environment variables using the pattern `ARQENOR_<SECTION>_<KEY>` (uppercase, underscores):

```bash
ARQENOR_GENERAL_LOG_LEVEL=debug
ARQENOR_API_LISTEN_ADDR=127.0.0.1:9090
ARQENOR_API_RATE_LIMIT_PER_SEC=50
ARQENOR_ALERTS_MIN_SEVERITY=info
```

Environment variables take precedence over the TOML file.

The path of the config file itself is overridable with `ARQENOR_CONFIG=/etc/arqenor/arqenor.toml`.

---

## Multiple environments

Use separate config files and pass `--config`:

```bash
# Development — verbose, scan temp dirs
arqenor-grpc --config configs/arqenor.dev.toml

# Production — medium+ alerts only, scan system dirs
arqenor-grpc --config configs/arqenor.prod.toml
```
