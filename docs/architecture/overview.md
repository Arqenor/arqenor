# Architecture Overview

## Philosophy

SENTINEL follows three core principles:

1. **Trait-first abstraction** — platform behaviour is expressed as Rust traits (`ProcessMonitor`, `FsScanner`, `PersistenceDetector`) defined in `sentinel-core`. No platform `#[cfg]` leaks into business logic.
2. **gRPC as the internal bus** — all host analysis data flows through typed Protobuf messages over gRPC, giving language-agnostic, versioned contracts between Rust and Go.
3. **SQLite-local, cloud-optional** — everything persists locally first; the cloud tier (commercial) syncs on top.

---

## Component Map

```
┌─────────────────────────────────────────────────────────────────────┐
│                           User Interfaces                           │
│                                                                     │
│   ┌──────────────┐   ┌──────────────┐   ┌───────────────────────┐  │
│   │ sentinel-tui │   │ sentinel-cli │   │  HTTP / REST clients  │  │
│   │  (Ratatui)   │   │   (clap)     │   │  curl, web UI, etc.   │  │
│   └──────┬───────┘   └──────┬───────┘   └──────────┬────────────┘  │
│          │ direct lib        │ direct lib            │ HTTP :8080    │
└──────────┼───────────────────┼────────────────────── ┼─────────────-┘
           │                   │                        │
           │    ┌──────────────┘         ┌──────────────┘
           │    │                        ▼
           │    │          ┌─────────────────────────┐
           │    │          │     Go Orchestrator      │
           │    │          │   Gin REST API :8080     │
           │    │          │   gRPC client → :50051   │
           │    │          └──────────────┬────────────┘
           │    │                         │ gRPC (protobuf)
           ▼    ▼                         ▼
   ┌────────────────────────────────────────────────┐
   │               sentinel-grpc (Tonic)            │
   │               HostAnalyzer  :50051             │
   │               NetworkScanner :50052 (planned)  │
   └──────────────────────┬─────────────────────────┘
                          │
          ┌───────────────┼───────────────┐
          ▼               ▼               ▼
  ┌──────────────┐ ┌────────────┐ ┌────────────┐
  │sentinel-     │ │sentinel-   │ │sentinel-   │
  │platform      │ │store       │ │core        │
  │              │ │(SQLite)    │ │(traits)    │
  │ Windows ───┐ │ │            │ │            │
  │ Linux   ───┤ │ │ alerts     │ │ models     │
  │ macOS   ───┘ │ │ rules      │ │ traits     │
  └──────────────┘ │ baselines  │ │ errors     │
                   └────────────┘ └────────────┘
```

---

## Data Flow — Process Snapshot

```
CLI / TUI
   │
   │ calls sentinel-platform::new_process_monitor()
   ▼
sentinel-platform (factory)
   │
   │ cfg_if! selects Windows / Linux / macOS impl
   ▼
sysinfo / procfs / etc.
   │
   │ returns Vec<ProcessInfo>
   ▼
sentinel-core ProcessInfo models
   │
   │ optionally stored via sentinel-store
   ▼
SQLite (data/sentinel.db)
```

When accessed via gRPC:

```
Client (TUI or Go)
   │ GetProcessSnapshot()
   ▼
sentinel-grpc HostAnalyzerService
   │ calls sentinel-platform internally
   ▼
same factory → platform impl → Vec<ProcessInfo>
   │ serialized as protobuf ProcessInfo
   ▼
Client receives typed stream / response
```

---

## Data Flow — Alerts

```
Any detector (platform impl)
   │ emits SentinelError or Alert struct
   ▼
sentinel-grpc service handler
   │ maps to Alert{severity, kind, message, metadata}
   ▼
sentinel-store::insert_alert()
   │ persists to SQLite alerts table
   ▼
Go orchestrator polls / streams
   │ via REST GET /api/v1/alerts
   ▼
External client or TUI
```

---

## Key Design Decisions

### Why Rust for the core?

- Zero-cost abstractions for tight platform API bindings (WMI, ETW, eBPF, kext)
- Memory safety without GC — critical when parsing untrusted data (file hashes, network packets)
- `async/await` with Tokio for concurrent scanning without thread-per-watcher overhead

### Why Go for the orchestrator?

- Excellent gRPC client library (`google/grpc-go`)
- Gin is idiomatic and fast for REST APIs
- Go's goroutines suit the fan-out pattern of multi-host orchestration
- Simpler deployment (single static binary)

### Why gRPC?

- Typed, versioned contracts via proto3 — breaking changes surface at compile time
- Bidirectional streaming for event fans (process watch, filesystem watch)
- Language-agnostic: future Python or TypeScript clients work out of the box

### Why SQLite (not Postgres/etc)?

- Zero-config local deployment — no database server to install
- `rusqlite` bundles libsqlite3 — single binary distribution
- DuckDB planned for Phase 4 event analytics once the arrow-arith dependency conflict resolves

---

## Thread / Task Model

```
sentinel-grpc process
├── Tokio runtime (multi-thread)
│   ├── tonic gRPC listener task
│   ├── HostAnalyzerService tasks (one per RPC call)
│   └── Background refresh task (optional interval scan)
│
sentinel-tui process
├── Tokio runtime
│   ├── Data fetch task (calls gRPC or platform directly)
│   └── TUI event loop (crossterm input + ratatui render)
│
Go orchestrator process
├── Gin HTTP goroutine pool
├── gRPC client connection (persistent)
└── Background goroutines (future: alert stream consumer)
```

---

## Security Posture

| Concern | Mitigation |
|---|---|
| Privilege escalation | SENTINEL reads only; no kernel writes by default |
| Local API exposure | REST and gRPC bound to `127.0.0.1` by default |
| Sensitive data at rest | SQLite not encrypted in Phase 1; encryption planned Phase 4 |
| Proto injection | Typed protobuf — no raw string parsing on the wire |
| Hash collisions | SHA-256 for file identity — collision-resistant for operational use |
