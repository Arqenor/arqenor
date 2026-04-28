# Go Orchestrator

**Path:** `go/`
**Language:** Go 1.25 (CI), builds on 1.23+
**Role:** REST API gateway + gRPC client + multi-host orchestration layer

The orchestrator is the public-facing service. External clients (web dashboards, scripts, CI pipelines) talk REST; the orchestrator translates to gRPC calls into the Rust host-analyzer engine.

---

## Package Structure

```
go/
├── cmd/
│   └── orchestrator/
│       └── main.go               # Entry point
├── internal/
│   ├── api/
│   │   ├── routes/
│   │   │   └── server.go         # Gin router + handlers (NewServer takes config.ApiConfig)
│   │   └── middleware/
│   │       ├── ratelimit.go      # Token-bucket rate limiter (per-IP)
│   │       └── logger.go         # Structured logger with redacted query strings
│   ├── config/                   # TOML loader for configs/arqenor.toml
│   ├── util/
│   │   └── redact/               # RedactCmdline / RedactURL / RedactHeader
│   └── grpc/
│       ├── client.go             # gRPC connection management
│       └── generated/            # Proto stubs (output of gen-proto.ps1)
└── pkg/
    └── models/
        └── models.go             # Shared Go structs
```

---

## Startup Sequence

```go
// cmd/orchestrator/main.go (simplified)
func main() {
    cfg := config.Load("configs/arqenor.toml")    // TOML loader, internal/config

    // data_dir is created with 0o700; arqenor.db chmod'd to 0o600 after open.
    grpcClient := grpc.NewClient(cfg.GRPC.HostAnalyzerAddr)
    defer grpcClient.Close()

    store := store.Open(cfg.General.DataDir)

    // routes.NewServer now takes the API sub-config so it can wire the
    // per-route timeout, the rate-limit middleware and the SSE cap.
    router := routes.NewServer(grpcClient, store, cfg.Api)
    router.Run(cfg.Api.ListenAddr)   // 127.0.0.1:8080 by default (read from TOML)
}
```

Previously the API listener was hardcoded as `:8080` — meaning it bound on `0.0.0.0`. It now binds to `cfg.Api.ListenAddr`, which defaults to `127.0.0.1:8080`.

---

## REST API

Base URL: `http://127.0.0.1:8080/api/v1`

| Method | Path | Status | Description |
|---|---|---|---|
| `GET` | `/health` | Implemented | Service liveness + gRPC connectivity |
| `GET` | `/alerts` | TODO | List stored alerts with severity filter |
| `GET` | `/scans` | TODO | Scan history |
| `POST` | `/scans` | TODO | Trigger a new on-demand scan |
| `GET` | `/hosts` | TODO | Known hosts from network scan |

### GET /health

```json
{
  "status": "ok",
  "grpc_connected": true,
  "platform": "windows",
  "version": "0.1.0"
}
```

### POST /scans (planned)

Request:
```json
{
  "type": "filesystem",
  "root_path": "C:\\Users",
  "recursive": true,
  "extensions": [".exe", ".dll", ".ps1"]
}
```

Response:
```json
{
  "scan_id": "uuid-here",
  "status": "running"
}
```

---

## gRPC Client

`internal/grpc/client.go` maintains a persistent connection to `arqenor-grpc`:

```go
type Client struct {
    conn *grpc.ClientConn
    host arqenor.HostAnalyzerClient
}

func NewClient(addr string) (*Client, error) {
    conn, err := grpc.Dial(addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
    // ...
    return &Client{conn: conn, host: arqenor.NewHostAnalyzerClient(conn)}, nil
}

func (c *Client) GetProcessSnapshot(ctx context.Context) (*arqenor.ProcessSnapshot, error) {
    return c.host.GetProcessSnapshot(ctx, &emptypb.Empty{})
}
```

All calls use the context from the incoming HTTP request for cancellation propagation.

---

## Middleware

### Rate limit

`internal/api/middleware/ratelimit.go` implements a per-IP token bucket using `golang.org/x/time/rate`. Buckets idle for more than 5 minutes are garbage-collected. On reject, the response is HTTP `429` with a `Retry-After` header. Configurable via `[api].rate_limit_per_sec` (default 20 req/s).

### Structured logger

`internal/api/middleware/logger.go` replaces `gin.Logger()`. Query strings logged through it pass through `util/redact.RedactURL`. Companion helpers `RedactCmdline` and `RedactHeader` are available for ad-hoc use elsewhere.

### SSE alert broadcaster

`AlertBroadcaster` is now constructed with a max-subscriber cap:

```go
b := api.NewAlertBroadcaster(cfg.Api.MaxSseConnections)   // default 100

// Subscribe returns ok=false if the cap is reached.
id, ch, ok := b.Subscribe()
if !ok {
    c.AbortWithStatusJSON(http.StatusServiceUnavailable, gin.H{
        "error": "max sse connections reached",
    })
    return
}
```

This is a breaking change vs the previous parameterless `NewAlertBroadcaster()` and `Subscribe() (id, ch)`.

### Per-scan context timeout

`handleStartScan` now wraps the scan goroutine in:

```go
ctx, cancel := context.WithTimeout(context.Background(),
    time.Duration(cfg.Api.ScanTimeoutSeconds)*time.Second)   // default 600s
defer cancel()
```

This prevents background scans from running indefinitely after the originating HTTP request returns.

---

## Logging

Uses `go.uber.org/zap` (structured JSON logging):

```
{"level":"info","ts":1712345678.12,"msg":"gRPC connected","addr":"127.0.0.1:50051"}
{"level":"info","ts":1712345679.00,"msg":"REST API listening","addr":"127.0.0.1:8080"}
```

Log level controlled by `ARQENOR_LOG_LEVEL` env var or `[general] log_level` in `arqenor.toml`.

---

## Configuration

The orchestrator reads `arqenor.toml` at startup via `internal/config` (path overridable via `--config` flag). Previously the Go side ignored the TOML file entirely.

```toml
[grpc]
host_analyzer_addr = "127.0.0.1:50051"

[api]
listen_addr           = "127.0.0.1:8080"
max_sse_connections   = 100      # optional, default 100
rate_limit_per_sec    = 20       # optional, default 20
scan_timeout_seconds  = 600      # optional, default 600
```

See [Configuration Guide](../guides/configuration.md) for the full schema.

---

## Future: Multi-host Mode (Phase 4)

In the commercial tier, the orchestrator will:

1. Maintain a registry of remote `arqenor-grpc` agents
2. Fan out scan requests across agents concurrently
3. Correlate alerts across hosts (same SHA-256 seen on N machines)
4. Stream aggregated results to a cloud dashboard via WebSocket

The gRPC client abstraction in `internal/grpc/client.go` is designed to support a pool of connections with minimal refactoring.

---

## Network Packet Analysis

`go/` depends on `google/gopacket` for local network capture (planned Phase 3):

- Capture on default interface using `pcap` or `npcap` (Windows)
- Detect ARP spoofing, port scan signatures, unusual beacon intervals
- Emit anomalies via `NetworkScanner.ReportAnomaly` RPC to store in SQLite

---

## Building

```bash
cd go
go build ./cmd/orchestrator -o orchestrator
```

Or with ldflags for version embedding:

```bash
go build -ldflags "-X main.version=$(git describe --tags)" ./cmd/orchestrator
```
