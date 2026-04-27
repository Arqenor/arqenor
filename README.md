<div align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="images/branding/arqenor-icon-white.png" />
    <img src="images/branding/arqenor-icon-blue.png" alt="Arqenor" width="96" height="96" />
  </picture>
  <h1>ARQENOR</h1>
  <p><strong>Open-source EDR — cross-platform, built in Rust and Go</strong></p>
  <p>
    <a href="https://github.com/Arqenor/arqenor/actions/workflows/ci.yml"><img src="https://github.com/Arqenor/arqenor/actions/workflows/ci.yml/badge.svg?branch=dev" alt="CI" /></a>
    <a href="LICENSE"><img src="https://img.shields.io/badge/License-Apache_2.0-blue.svg" alt="License: Apache 2.0" /></a>
    <img src="https://img.shields.io/badge/Platform-Windows%20%7C%20Linux%20%7C%20macOS-blue" alt="Platform" />
    <img src="https://img.shields.io/badge/Rust-1.80%2B-orange" alt="Rust 1.80+" />
    <img src="https://img.shields.io/badge/Go-1.23%2B-blue" alt="Go 1.23+" />
  </p>
</div>

ARQENOR gives independent developers, small teams, and security researchers commercial-grade detection capabilities without the $30/endpoint/month price tag. Real-time monitoring of processes, filesystem, network connections, persistence mechanisms, and memory — with SIGMA rules, IOC threat intelligence, YARA scanning, and alert correlation built in.

```
┌──────────────────────────────────────────────────────────┐
│                      ARQENOR Stack                      │
│                                                          │
│  ┌──────────────┐  ┌─────────────┐  ┌────────────────┐  │
│  │ arqenor-tui │  │ arqenor-cli│  │  External API  │  │
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
│               │   arqenor-grpc       │                  │
│               │   Tonic :50051        │                  │
│               └──────────┬────────────┘                  │
│                          │                               │
│         ┌────────────────┼────────────────┐              │
│         ▼                ▼                ▼              │
│  ┌─────────────┐  ┌──────────────┐  ┌──────────────┐    │
│  │arqenor-    │  │arqenor-     │  │arqenor-     │    │
│  │platform     │  │store         │  │core          │    │
│  │(Win/Lin/Mac)│  │(SQLite)      │  │(traits+models│    │
│  └─────────────┘  └──────────────┘  └──────────────┘    │
└──────────────────────────────────────────────────────────┘
```

---

## Screenshots

### Terminal UI (Ratatui)
![ARQENOR Terminal UI](images/terminal-ui.png)

---

## Features

| Category | Capability |
|---|---|
| **Detection Engine** | 32 LOLBin rules, 3000+ SIGMA community rules, file-path rules, PE static analysis |
| **Threat Intelligence** | IOC database (abuse.ch feeds: MalwareBazaar, Feodo, URLhaus, ThreatFox), auto-refresh 4h |
| **Alert Correlation** | PID + parent-child grouping, ATT&CK-weighted scoring, incident model |
| **Memory Forensics** | VAD walk (shellcode detection), process hollowing, NTDLL hook detection |
| **YARA Scanning** | Shipped — in-memory scanning via `yara-x` (pure Rust) with 9 embedded rule families: Cobalt Strike, Meterpreter, Mimikatz, Sliver, Brute Ratel, Havoc, generic shellcode, PE injection, encoded PowerShell. Opt-in via the `yara` Cargo feature (off by default to keep clean builds fast): `cargo build --release -p arqenor-cli --features arqenor-platform/yara`. Per-PID `scan_process` is currently Windows-only — Linux/macOS support is tracked in #46. |
| **BYOVD Detection** | 50 known-vulnerable kernel drivers (LOLDrivers.io blocklist) |
| **Network Analysis** | C2 beaconing (CV scoring), DNS tunneling, DGA detection, JA4 TLS fingerprinting |
| **Processes** | Snapshot + streaming monitor, SHA-256 hashing, risk scoring, real-time connection monitoring |
| **Persistence** | Win: Registry, Tasks, Services, WMI, COM, BITS, AppInit, IFEO (B1-B9) · Lin: Cron, Systemd, LD_PRELOAD, PAM, SSH, git hooks (C1-C7) · Mac: LaunchDaemon/Agent, login items, auth plugins |
| **Filesystem** | FIM baseline + real-time watch (ReadDirectoryChangesW / inotify / ESF) |
| **Kernel Telemetry** | ETW (10 providers, TDH parsing) · eBPF (5 probes loaded + attached at runtime) · ESF (macOS) |
| **TUI** | Live Ratatui dashboard with alert streaming |
| **CLI** | `arqenor scan` · `arqenor watch --sigma-dir --yara-dir --no-ioc` |
| **API** | REST (Go/Gin) + gRPC (Rust/Tonic) + SSE alert streaming |
| **Cross-platform** | Windows 10+, Linux, macOS — single codebase via `cfg-if` |
| **ATT&CK Coverage** | ~140+ techniques across TA0001-TA0011 |

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
git clone https://github.com/Arqenor/arqenor.git
cd arqenor

# 2. Build all Rust binaries (lean — fast clean compile, no YARA)
cargo build --release \
  -p arqenor-cli \
  -p arqenor-tui \
  -p arqenor-grpc

# 2b. (Recommended for production) build the CLI with the full detection
#     stack — currently activates in-memory YARA scanning via yara-x.
#     ~100 extra transitive crates; first compile is noticeably slower.
cargo build --release -p arqenor-cli --features full-detection

# 3. Build Go orchestrator
cd go && go build ./cmd/orchestrator && cd ..

# 4. (Optional) Regenerate proto stubs
./scripts/gen-proto.ps1   # Windows PowerShell
```

### Run

```bash
# Terminal 1 — gRPC host analyzer
./rust/target/release/arqenor-grpc

# Terminal 2 — REST orchestrator
./go/orchestrator

# Terminal 3 — choose your interface
./rust/target/release/arqenor scan          # one-shot CLI
./rust/target/release/arqenor watch         # continuous CLI
./rust/target/release/arqenor-tui           # dashboard UI
```

---

## Project Structure

```
arqenor/
├── rust/
│   ├── arqenor-core/       # Domain nucleus: traits, models, pipeline, rules, IOC, correlation
│   ├── arqenor-platform/   # Win/Lin/Mac: ETW, ESF, connections, memory scan, YARA, BYOVD
│   ├── arqenor-grpc/       # Tonic gRPC server (port 50051)
│   ├── arqenor-store/      # SQLite persistence layer
│   ├── arqenor-tui/        # Ratatui terminal dashboard
│   └── arqenor-cli/        # clap CLI (scan / watch)
├── arqenor-ebpf/           # Linux eBPF kernel probes (libbpf-rs, 5 probes loaded + attached at runtime)
├── go/
│   ├── cmd/orchestrator/   # Entry point
│   ├── internal/api/       # Gin REST handlers + SSE alert streaming
│   ├── internal/grpc/      # gRPC client + generated stubs
│   └── internal/store/     # Go-side SQLite store
├── proto/                   # Protobuf definitions
├── configs/                 # Runtime configuration (arqenor.toml)
└── docs/                    # Architecture, roadmap, guides
```

---

## Security posture / threat model

ARQENOR runs as a local agent. Authentication on the REST and gRPC surfaces is
**deliberately deferred** to the upcoming SaaS control-plane (Next.js); it is
**not implemented in this OSS repo**. To keep the default install safe:

- **Bind localhost only.** The Go orchestrator binds `127.0.0.1:8080` and the
  Tonic host analyzer binds `127.0.0.1:50051` by default. **Do not expose
  ports 8080 / 50051 on the network** until the SaaS layer ships — there is
  no auth gate in front of them.
- **Per-IP rate-limit on REST.** Token-bucket middleware (default 20 req/s)
  plus a hard cap on concurrent SSE subscribers (default 100) protect the
  orchestrator against trivial DoS.
- **Bounded file hashing.** SHA-256 hashing streams in 64 KiB chunks and
  refuses files larger than 512 MiB by default — no OOM on accidental large
  inputs.
- **gRPC server limits.** Tonic is configured with HTTP/2 keepalive,
  per-connection age caps, a 5 min unary timeout, max 128 concurrent streams,
  and a Tower concurrency cap of 64.
- **Path validation.** Reparse-point and (on Linux) world-writable parent
  checks gate filesystem watchers.
- **Supply-chain hardening.** `cargo-audit` is blocking in CI, `cargo-deny`
  enforces license/source policy, and `govulncheck` runs on every PR.

The full third-party security audit and the remediation history live in
[`docs/security-audit-202604.md`](docs/security-audit-202604.md).

---

## Configuration

Copy `configs/arqenor.toml` to your working directory and adjust paths:

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
| [Configuration Reference](docs/guides/configuration.md) | Every `arqenor.toml` key explained |
| [Usage Guide](docs/guides/usage.md) | CLI commands, TUI controls, API calls |
| [Build System](docs/development/build.md) | Cargo workspace, proto codegen, CI targets |
| [Platform Notes](docs/development/platform-notes.md) | Windows/Linux/macOS specific details |
| [Contributing](docs/development/contributing.md) | Code style, PR flow, adding new platforms |
| [REST API Reference](docs/reference/api.md) | Endpoint spec with request/response examples |
| [CLI Reference](docs/reference/cli.md) | All flags and subcommands |
| [Proto Reference](docs/reference/proto.md) | Full proto3 message and service definitions |
| [Security Audit (2026-04)](docs/security-audit-202604.md) | Third-party audit findings, remediation history, hardening summary |

---

## Roadmap

See [`docs/roadmap/ROADMAP.md`](docs/roadmap/ROADMAP.md) for the full 6-phase plan.

| Phase | Focus | Status |
|-------|-------|--------|
| **Phase 1** | Detection Engine + LOTL Rules (32 LOLBin rules, persistence B1-B9/C1-C7, FIM, credential theft) | ✅ Done |
| **Phase 2** | Kernel Telemetry: ETW (10 providers), eBPF (5 probes loaded + attached), ESF (macOS), WDK driver | 🟡 Partial |
| **Phase 3** | Network: C2 beaconing, DNS tunneling, DGA, JA4 TLS fingerprinting, connection monitoring | ✅ Done |
| **Phase 4** | SIGMA engine (3000+ rules), IOC feeds (abuse.ch), correlation engine, PE static analyzer | ✅ Done (behavioral ML pending) |
| **Phase 5** | Memory forensics (VAD, hollowing, NTDLL hooks), BYOVD (50 drivers), YARA scanning (opt-in) | ✅ Done |
| **Phase 6** | Cloud dashboard, fleet management, automated response | Not started |

---

## Current limitations

- **eBPF → DetectionPipeline bridge** — All 5 probes (execve, memory, persistence, privesc, rootkit) are loaded and attached at runtime, and `arqenor-cli` already forwards `EbpfEvent` → `Alert` over `scan_tx`. Plugging the receiver directly into `DetectionPipeline` so eBPF events flow through the same correlation / SIGMA / IOC stages as ETW events is the remaining follow-up. `EbpfAgent::start` now fails fast if zero probes attach, and a background drop-monitor logs a warning every 60 s if events are being lost.
- **YARA in default release builds** — `yara-x` is wired into `arqenor-platform` and ships behind the `yara` Cargo feature (off by default to keep clean builds fast; enable with `--features full-detection` on the CLI). Per-PID `scan_process` is currently Windows-only (`scan_bytes` works everywhere). Not enabled in the stock release builds yet.
- **JA4 TLS fingerprinting — packet source** — Detection module + 17 C2 signatures are in `arqenor-core`, but `parse_client_hello` / `check_ja4_alerts` are not yet wired to a pcap / AF_PACKET capture loop.
- **Behavioral ML scoring** — Isolation Forest scoring is still pending. SIGMA, IOC, correlation, static PE analyzer and IOC SQLite persistence are wired.
- **REST / gRPC authentication** — Deliberately not implemented here; gated by the upcoming SaaS control-plane. Mitigated by strict localhost binding, per-IP rate-limit and SSE caps. See "Security posture" above.

---

## Business Model

ARQENOR is **open-core**:

- **Open source** (Apache 2.0, this repo) — `arqenor-core`, `arqenor-platform`, `arqenor-cli`, `arqenor-tui`, `arqenor-grpc`, `arqenor-store`, `arqenor-ebpf`, Go orchestrator
- **Closed / commercial** (`arqenor-enterprise`) — Windows kernel driver (WDK), ML scorer (PE static analyzer with EMBER2024 LightGBM ONNX), native Tauri desktop SOC console, drift telemetry, multi-host management, premium threat intelligence feeds, enterprise alerting

The commercial console consumes this OSS engine over its public crates (`arqenor-core`, `arqenor-platform`) — every detection rule and platform integration lives here.

---

## Contributing

See [`CONTRIBUTING.md`](CONTRIBUTING.md) for build instructions, commit conventions, and the PR process.
Security issues: see [`SECURITY.md`](SECURITY.md) — please do **not** open a public issue.

---

## License

Licensed under the [Apache License, Version 2.0](LICENSE). See [`NOTICE`](NOTICE) for attribution.
