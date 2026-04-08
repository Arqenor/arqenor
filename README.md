# SENTINEL

**Cross-platform host & network security analyzer** — open-core, built in Rust and Go.

SENTINEL monitors your machine in real time: running processes, filesystem changes, persistence mechanisms (registry keys, scheduled tasks, cron jobs, launch daemons), and local network topology. A terminal UI, CLI scanner, gRPC server, and REST orchestrator ship out of the box.

```
┌──────────────────────────────────────────────────────────┐
│                      SENTINEL Stack                      │
│                                                          │
│  ┌──────────────┐  ┌─────────────┐  ┌────────────────┐  │
│  │ sentinel-tui │  │ sentinel-cli│  │  External API  │  │
│  │   (Ratatui)  │  │   (clap)    │  │    Clients     │  │
│  └──────┬───────┘  └──────┬──────┘  └───────┬────────┘  │
│         │                 │                  │           │
│         └─────────────────┼──────────────────┘           │
│                           ▼                              │
│               ┌───────────────────────┐                  │
│               │    Go Orchestrator    │                  │
│               │  REST API :8080 (Gin) │                  │
│               └──────────┬────────────┘                  │
│                          │ gRPC                          │
│                          ▼                               │
│               ┌───────────────────────┐                  │
│               │   sentinel-grpc       │                  │
│               │   Tonic :50051        │                  │
│               └──────────┬────────────┘                  │
│                          │                               │
│         ┌────────────────┼────────────────┐              │
│         ▼                ▼                ▼              │
│  ┌─────────────┐  ┌──────────────┐  ┌──────────────┐    │
│  │sentinel-    │  │sentinel-     │  │sentinel-     │    │
│  │platform     │  │store         │  │core          │    │
│  │(Win/Lin/Mac)│  │(SQLite)      │  │(traits+models│    │
│  └─────────────┘  └──────────────┘  └──────────────┘    │
└──────────────────────────────────────────────────────────┘
```

---

## Features

| Category | Capability |
|---|---|
| **Processes** | Snapshot + streaming monitor, SHA-256 hashing, risk scoring |
| **Persistence** | Registry Run keys, Scheduled Tasks, Services (Win) · Cron, Systemd, LD_PRELOAD (Lin) · LaunchDaemon/Agent (Mac) |
| **Filesystem** | Recursive scan with configurable roots, inotify/FSEvents watch |
| **Network** | LAN host discovery, port scanning, VPN detection |
| **Alerts** | Severity-filtered (info → critical), stored in SQLite |
| **TUI** | Live Ratatui dashboard — Processes / Persistence / Network tabs |
| **CLI** | `sentinel scan` · `sentinel watch` |
| **API** | REST (Go/Gin) + gRPC (Rust/Tonic) |
| **Cross-platform** | Windows 10+, Linux, macOS — single codebase via `cfg-if` |

---

## Quick Start

### Prerequisites

| Tool | Version | Purpose |
|---|---|---|
| Rust toolchain | 1.80+ | Build Rust crates |
| Go | 1.23+ | Build orchestrator |
| protoc | 3.x | Regenerate gRPC stubs |
| protoc-gen-go / protoc-gen-go-grpc | latest | Go proto codegen |

### Build

```bash
# 1. Clone
git clone https://github.com/your-org/sentinel.git
cd sentinel

# 2. Build all Rust binaries
cargo build --release \
  -p sentinel-cli \
  -p sentinel-tui \
  -p sentinel-grpc

# 3. Build Go orchestrator
cd go && go build ./cmd/orchestrator && cd ..

# 4. (Optional) Regenerate proto stubs
./scripts/gen-proto.ps1   # Windows PowerShell
```

### Run

```bash
# Terminal 1 — gRPC host analyzer
./rust/target/release/sentinel-grpc

# Terminal 2 — REST orchestrator
./go/orchestrator

# Terminal 3 — choose your interface
./rust/target/release/sentinel scan          # one-shot CLI
./rust/target/release/sentinel watch         # continuous CLI
./rust/target/release/sentinel-tui           # dashboard UI
```

---

## Project Structure

```
sentinel/
├── rust/
│   ├── sentinel-core/       # Shared traits & domain models
│   ├── sentinel-platform/   # Windows / Linux / macOS implementations
│   ├── sentinel-grpc/       # Tonic gRPC server (port 50051)
│   ├── sentinel-store/      # SQLite persistence layer
│   ├── sentinel-tui/        # Ratatui terminal dashboard
│   └── sentinel-cli/        # clap CLI (scan / watch)
├── go/
│   ├── cmd/orchestrator/    # Entry point
│   ├── internal/api/        # Gin REST handlers
│   ├── internal/grpc/       # gRPC client + generated stubs
│   └── pkg/models/          # Shared Go models
├── proto/
│   ├── common.proto
│   ├── host_analyzer.proto
│   └── network_scanner.proto
├── configs/
│   └── sentinel.toml        # Runtime configuration
├── scripts/
│   └── gen-proto.ps1        # Proto codegen helper
└── data/                    # SQLite database + logs (runtime)
```

---

## Configuration

Copy `configs/sentinel.toml` to your working directory and adjust paths:

```toml
[general]
log_level = "info"       # trace | debug | info | warn | error
data_dir  = "./data"

[grpc]
host_analyzer_addr   = "127.0.0.1:50051"
network_scanner_addr = "127.0.0.1:50052"

[api]
listen_addr = "127.0.0.1:8080"

[scan]
fs_roots      = ["C:\\Users", "C:\\Windows\\System32"]
max_file_size = 10485760   # bytes (10 MB)
interval_secs = 60

[alerts]
min_severity = "medium"    # info | low | medium | high | critical
```

Full reference → [`docs/guides/configuration.md`](docs/guides/configuration.md)

---

## Documentation

| Document | Description |
|---|---|
| [Architecture Overview](docs/architecture/overview.md) | Component diagram, data flow, design decisions |
| [Rust Crates](docs/architecture/crates.md) | Detailed breakdown of each crate |
| [gRPC Services](docs/architecture/grpc-services.md) | Proto definitions, RPC methods, message types |
| [Go Orchestrator](docs/architecture/go-orchestrator.md) | REST API, gRPC client, orchestration logic |
| [Installation Guide](docs/guides/installation.md) | Prerequisites, build steps, cross-compilation |
| [Configuration Reference](docs/guides/configuration.md) | Every `sentinel.toml` key explained |
| [Usage Guide](docs/guides/usage.md) | CLI commands, TUI controls, API calls |
| [Build System](docs/development/build.md) | Cargo workspace, proto codegen, CI targets |
| [Platform Notes](docs/development/platform-notes.md) | Windows/Linux/macOS specific details |
| [Contributing](docs/development/contributing.md) | Code style, PR flow, adding new platforms |
| [REST API Reference](docs/reference/api.md) | Endpoint spec with request/response examples |
| [CLI Reference](docs/reference/cli.md) | All flags and subcommands |
| [Proto Reference](docs/reference/proto.md) | Full proto3 message and service definitions |

---

## Roadmap

- **Phase 1 — Foundation** ✅ SQLite · trait abstractions · IPC skeleton · CLI/TUI MVP
- **Phase 2 — Host Analyzer** ETW (Windows) · eBPF (Linux) · ES framework (macOS) · process module enrichment
- **Phase 3 — Network Scanner** Host discovery · port scan · service fingerprinting · anomaly detection
- **Phase 4 — Orchestrator** Rule engine · alert pipeline · DuckDB event analytics · correlation
- **Phase 5 — TUI Polish** Reports · export · dashboard themes
- **Phase 6 — Advanced** YARA-X scanning · traffic anomaly · supply chain checks

---

## Business Model

SENTINEL is **open-core**:

- **Open source** — `sentinel-core`, `sentinel-platform`, `sentinel-cli`, `sentinel-tui`, `sentinel-grpc`
- **Closed / commercial** — cloud dashboard, threat intelligence feeds, multi-host management, enterprise alerting

---

## License

See `LICENSE` for details.
