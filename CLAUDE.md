# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

> **⚠ Parent CLAUDE.md is required reading.** The file at `D:\dev\_ecosystems\arqenor\CLAUDE.md` (one level up, outside any git repo) defines the cross-repo contract between this repo (`arqenor/`, OSS, Apache 2.0) and `arqenor-enterprise/` (private, commercial). Claude Code loads it automatically when working from this directory, but **go re-read it** whenever you:
>
> - are tempted to reference anything from `../arqenor-enterprise/` in this repo — **forbidden**. OSS must never depend on enterprise (parent §"Golden rules" #1).
> - make a breaking change to `arqenor-core` or `arqenor-platform` — downstream `arqenor-enterprise` consumes these via git on branch `dev`, so your push is the release trigger for them.
> - need to test an OSS change against enterprise in the same session — use the local `[patch]` block on the enterprise side, never a reciprocal edit here.
>
> This file covers only what is specific to the OSS `arqenor/` repo. See `README.md` for product overview/features and `CONTRIBUTING.md` for PR flow and rule-contribution conventions.

## Runtime architecture — three binaries, gRPC in the middle

```
┌──────────────┐   ┌──────────────┐   ┌─────────────────────┐
│ arqenor-cli  │   │ arqenor-tui  │   │ External REST clients│
└──────┬───────┘   └──────┬───────┘   └──────────┬──────────┘
       │                  │                      │ HTTP :8080
       └──────────────────┴──────────────────────┘
                          │
                          ▼
              ┌─────────────────────────┐
              │  Go orchestrator (Gin)  │  go/cmd/orchestrator
              │  REST :8080, SSE stream │
              └────────────┬────────────┘
                           │ gRPC :50051
                           ▼
              ┌─────────────────────────┐
              │ arqenor-grpc (Tonic)    │  Rust host analyzer
              └────────────┬────────────┘
                           │
          ┌────────────────┴────────────────┐
          ▼                                 ▼
┌──────────────────┐              ┌──────────────────┐
│ arqenor-platform │◄── traits ──►│   arqenor-core   │
│ Win/Lin/Mac      │              │ models, pipeline,│
│ collectors       │              │ rules, IOC, corr.│
└──────────────────┘              └──────────────────┘
```

Key flow to keep in mind when editing: **`arqenor-core` defines traits; `arqenor-platform` implements them per-OS**. The factory functions (`new_connection_monitor`, `new_process_monitor`, `new_persistence_detector`, etc. in `arqenor-platform/src/lib.rs`) are the single entry point via `cfg_if!`. When adding a platform capability, add the trait in `arqenor-core/src/traits/`, then the Win/Lin/Mac impl under `arqenor-platform/src/{windows,linux,macos}/`, then wire a factory.

## Two workspaces, one repo

1. **Rust** — root `Cargo.toml` (`resolver = "2"`). Members:

   | Crate | Role |
   |---|---|
   | `rust/arqenor-core` | Domain nucleus: `models/`, `traits/`, `rules/`, `ioc/`, `pipeline.rs`, `correlation.rs`. Zero platform deps. |
   | `rust/arqenor-platform` | Per-OS collectors. Gated by `#[cfg(target_os = …)]` + `compile_error!` on unsupported. Uses `cfg-if` in factories. |
   | `rust/arqenor-grpc` | Tonic server on `:50051`. Exposes host analyzer to the Go orchestrator. |
   | `rust/arqenor-store` | SQLite persistence via `rusqlite` (bundled). |
   | `rust/arqenor-tui` | Ratatui 0.30 dashboard. |
   | `rust/arqenor-cli` | `clap` CLI (`scan` / `watch --sigma-dir --yara-dir --no-ioc`). |
   | `arqenor-ebpf` | Linux-only eBPF probes via `libbpf-cargo` 0.26 skeletons. **Loader is live since B7** (commit `20f0e99`, 2026-04-26): `EbpfAgent::start()` attaches the 5 probes (execve / memory / persistence / privesc / rootkit) and returns `(Self, mpsc::Receiver<EbpfEvent>)`; per-probe failures degrade gracefully. `arqenor-cli` already bridges that receiver into the scan loop — wiring it directly into `DetectionPipeline` is the remaining follow-up. See the `loader_stub.rs` fallback below for the CI no-op build. |

2. **Go** — `go.work` at repo root pointing into `go/`. REST orchestrator in `go/cmd/orchestrator`, internals under `go/internal/{api,grpc,scanner,store}`. Separate toolchain (`go 1.23+`) and its own `go.sum`.

3. **Proto** — `proto/*.proto` is the source of truth; Rust stubs are generated by Tonic at build time, Go stubs must be regenerated manually (see commands below).

## Common commands

### Rust (from repo root)

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace --all-targets

# Single test
cargo test -p arqenor-core <filter>
cargo test -p arqenor-platform -- <filter> --nocapture

# Build just the release binaries the README ships
cargo build --release -p arqenor-cli -p arqenor-tui -p arqenor-grpc

# eBPF crate — Linux only, needs libbpf + vmlinux.h (see CI for full toolchain)
cd arqenor-ebpf && cargo build
```

> **CI nuance — eBPF SKIP path is now first-class.** The Linux job (`rust-clippy-linux`) probes for BTF + a working `bpftool`. If either is missing it sets `SKIP_EBPF=1` and excludes `arqenor-ebpf` from clippy/test. The crate's own `build.rs` honours the same env var: when set, it emits `cargo:rustc-cfg=ebpf_stubs`, which swaps in `loader_stub.rs` (no-op API-compatible stub exposing the same `EbpfAgent` symbol — downstream crates need no `cfg`). Locally on Linux you still want `libbpf-dev libelf-dev zlib1g-dev clang llvm` + a working `bpftool` for the real loader path. On Windows, CI runs `cargo check --workspace --exclude arqenor-ebpf` only.

### Go (from `go/`)

```bash
gofmt -l .                        # must return empty — CI fails on output
go vet ./...
go test -race -count=1 ./...      # -race matches CI
go build ./cmd/orchestrator
```

### Proto codegen

```bash
# Windows host
./scripts/gen-proto.ps1

# Linux/manual (matches what go CI does)
protoc --proto_path=proto \
  --go_out=go/internal/grpc/generated --go_opt=paths=source_relative \
  --go-grpc_out=go/internal/grpc/generated --go-grpc_opt=paths=source_relative \
  proto/common.proto proto/host_analyzer.proto proto/network_scanner.proto
```

Rust proto bindings are generated by Tonic's `build.rs` — no manual step.

### Run the full stack locally

```bash
# Terminal 1: host analyzer (gRPC)
./target/release/arqenor-grpc

# Terminal 2: Go orchestrator (REST + SSE)
./go/orchestrator

# Terminal 3: pick one
./target/release/arqenor scan          # one-shot
./target/release/arqenor watch         # continuous
./target/release/arqenor-tui           # dashboard
```

## CI layout

### `.github/workflows/ci.yml` — concurrency-gated, least-privilege `permissions: contents: read` by default

| Job | Runner | Scope | Notes |
|---|---|---|---|
| `rust-fmt` | ubuntu | `cargo fmt --all --check` | |
| `rust-clippy-linux` | ubuntu | clippy + test on full workspace | Generates `vmlinux.h` via `bpftool`; auto-sets `SKIP_EBPF=1` if BTF/bpftool missing → excludes `arqenor-ebpf` (loader gracefully degrades to `loader_stub.rs`) |
| `rust-check-windows` | windows | `cargo check --workspace --exclude arqenor-ebpf` | eBPF is Linux-only by design |
| `go` | ubuntu | gofmt + vet + `test -race` (Go **1.25**) | Regenerates proto stubs fresh each run via `protoc` + `protoc-gen-go{,-grpc}` |
| `audit` | ubuntu | `rustsec/audit-check` | **Blocking** since the 2026-04 hardening pass; explicit `checks: write` permission to publish check-runs |
| `cargo-deny` | ubuntu | `EmbarkStudios/cargo-deny-action@v2` | License + source allowlist driven by `deny.toml` at repo root |
| `govulncheck` | ubuntu | Go module vulnerability scan (Go 1.25) | Runs against `go/` |

### `.github/workflows/enforce-main-policy.yml` — soft mirror of the `Protect main` repo ruleset

Runs on push to `main` only. Hard-fails if HEAD has more than one parent (linear history) or if the commit subject doesn't end in ` (#NNN)` (squash-merge convention). Mirrors the equivalent workflow on the enterprise side; the enterprise mirror carries more weight because the private repo can't use rulesets on the free plan.

### Other workflows: `clippy-sarif.yml` (separate SARIF upload), `auto-assign.yml`, plus `dependabot.yml` grouped by ecosystem family.

`RUSTFLAGS: "-Dwarnings"` is set workspace-wide — a warning anywhere fails Linux clippy.

### Pre-push hook

`.githooks/pre-push` rejects direct pushes to `main`/`master` (zero-network mirror of the `enforce-main-policy` server check). Install once with `bash scripts/setup-hooks.sh` (or `pwsh scripts\setup-hooks.ps1`). Bypass with `--no-verify` only deliberately.

## Style rules that catch people out

Lifted from `CONTRIBUTING.md` — the ones worth internalising:

- **Library crates (`arqenor-core`, `arqenor-platform`, `arqenor-store`, `arqenor-grpc`)**: prefer explicit `thiserror` error types over `anyhow`. `anyhow` is fine in the binaries (`arqenor-cli`, `arqenor-tui`, orchestrator main).
- **No `unwrap()` / `expect()` in library code.** Propagate the error.
- **Public types get `Debug` + `Clone`** where reasonable.
- **Platform code uses `#[cfg(target_os = …)]`, not runtime detection.** The `compile_error!` at `arqenor-platform/src/lib.rs:11` enforces Win/Lin/Mac only — don't weaken it.
- **Conventional Commits** (`feat(platform):`, `fix(core):`, etc.). Branch from and PR to `dev`, not `main`.

### Adding a detection rule (SIGMA / LOLBin)

- LOLBin rules live in `rust/arqenor-core/src/rules/lolbin.rs`; SIGMA engine in `sigma.rs` + `sigma_condition.rs`; runtime YAML loading is supported.
- Each rule must carry the relevant **MITRE ATT&CK ID(s)** in metadata.
- PRs must include test fixtures for both **true positives** and **known false positives you tuned out** — CONTRIBUTING.md is non-negotiable here.

## Current state of "limitations" (was "doesn't ship" in earlier revisions — most have shipped, keep this honest)

- **eBPF (B7 — shipped 2026-04-26, hardened 2026-04-27).** The five probes (`execve`, `memory`, `persistence`, `privesc`, `rootkit` — `.bpf.c` in `arqenor-ebpf/src/probes/`) are loaded + attached at runtime via `libbpf-cargo`-generated skeletons. `EbpfAgent::start` now returns `Err(EbpfLoadError::NoProbesAttached)` when **zero** probes attach (previous behaviour silently returned `Ok`); when `attached < TOTAL_PROBES` (5) it warns and continues in degraded mode. A public `EBPF_DROPPED_EVENTS: AtomicU64` counter (helper `ebpf_dropped_events_total()`) is monitored by a background task that logs `warn!` every 60 s on non-zero deltas and `error!` past 1000. `arqenor-cli` bridges `EbpfEvent` → `Alert` over `scan_tx`. **Remaining gap:** plug that receiver directly into `DetectionPipeline` so eBPF events flow through the same correlation / SIGMA / IOC stages as ETW events.
- **YARA memory scanning (F3 — shipped 2026-04-26).** `yara-x` 1.15 is now a dep of `arqenor-platform` behind the `yara` Cargo feature (off by default to keep clean CI fast). `YaraScanner` lives in `rust/arqenor-platform/src/yara_scan.rs` with 9 embedded rule families under `src/yara_rules/` (Cobalt Strike, Meterpreter, Mimikatz, Sliver, Brute Ratel, Havoc, generic shellcode, PE injection, encoded PowerShell). Wired into the Windows host-scan loop with `SENT-YARA-NNN` alert IDs (TA0005 / TA0006). **Remaining gaps:** per-PID `scan_process` is Windows-only (`scan_bytes` works everywhere); not enabled in default release builds yet.
- **JA4 TLS fingerprinting** — module + 17 C2 signatures + 16 tests live in `rust/arqenor-core/src/rules/tls_fingerprint.rs`, but `parse_client_hello` / `check_ja4_alerts` are **not yet wired to a packet source**. Pcap/AF_PACKET capture integration is the open Phase 3 item.
- **Behavioral ML (Phase 4 F2)** — Isolation Forest scoring is still pending. SIGMA + IOC + correlation + static PE analyzer + IOC SQLite persistence are all wired.
- **Configuration loader — now consumed end-to-end (2026-04-27).** `configs/arqenor.toml` is read by Go orchestrator (`go/internal/config`, with `Api.MaxSSEConnections`, `Api.RateLimitPerSec`, `Api.ScanTimeoutSeconds`), Rust gRPC (`limits::load_allowed_roots` reads `[scan].fs_roots` and the server file-size cap), and exposed via `arqenor_core::config::Config::load()` (resolution order: explicit arg → `ARQENOR_CONFIG` env → `./configs/arqenor.toml`). Defaults are localhost-bound. Before this pass the Go side ignored the TOML entirely.
- **Supply-chain hardening (2026-04-27).** `serde_yaml` (unmaintained, RUSTSEC-2024-0320) was replaced workspace-wide by `serde_yml = "0.0.12"` — every `use serde_yaml::*` is now `serde_yml::*`. CI gained `cargo-deny` (license + source allowlist via root `deny.toml`) and `govulncheck` jobs, and `rustsec/audit-check` is now blocking instead of `continue-on-error`. Root `Cargo.toml` pins `[workspace.dependencies.windows-sys] = "0.61"` (partial consolidation — `ring`, `rustix 0.38` and `quinn-udp` still drag older minor versions).
- **Auth on REST + gRPC** — Deliberately deferred to the upcoming SaaS layer (Next.js, not in this repo). Current mitigation is strict localhost binding (Go orchestrator on `127.0.0.1:8080`, Tonic on `127.0.0.1:50051`), per-IP token-bucket rate-limit, SSE subscriber cap, scan-goroutine timeout, Tonic HTTP/2 keepalive + connection-age + 5 min unary timeout + 128 max streams + Tower `ConcurrencyLimitLayer(64)`. **Do not expose 8080 / 50051 on the network until the SaaS auth layer ships.** Full audit and remediation log: `docs/security-audit-202604.md`.
- **ETW-TI / PPL** — requires MVI membership (~12 mo lead). Not in scope for OSS short-term.

## User language

User writes in French; respond in French unless they switch to English. (Inherited from parent CLAUDE.md — see there for the "the repo" disambiguation rule.)
