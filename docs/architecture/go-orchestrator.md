# Go Orchestrator

**Path:** `go/`
**Language:** Go 1.23
**Role:** REST API gateway + gRPC client + multi-host orchestration layer

The orchestrator is the public-facing service. External clients (web dashboards, scripts, CI pipelines) talk REST; the orchestrator translates to gRPC calls into the Rust host-analyzer engine.

---

## Package Structure

```
go/
├── cmd/
│   └── orchestrator/
│       └── main.go          # Entry point
├── internal/
│   ├── api/
│   │   └── server.go        # Gin router + handlers
│   └── grpc/
│       ├── client.go        # gRPC connection management
│       └── generated/       # Proto stubs (output of gen-proto.ps1)
└── pkg/
    └── models/
        └── models.go        # Shared Go structs
```

---

## Startup Sequence

```go
// cmd/orchestrator/main.go (simplified)
func main() {
    cfg := config.Load("configs/sentinel.toml")

    grpcClient := grpc.NewClient(cfg.GRPC.HostAnalyzerAddr)
    defer grpcClient.Close()

    store := store.Open(cfg.General.DataDir)

    router := api.NewServer(grpcClient, store)
    router.Run(cfg.API.ListenAddr)   // :8080
}
```

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

`internal/grpc/client.go` maintains a persistent connection to `sentinel-grpc`:

```go
type Client struct {
    conn *grpc.ClientConn
    host sentinel.HostAnalyzerClient
}

func NewClient(addr string) (*Client, error) {
    conn, err := grpc.Dial(addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
    // ...
    return &Client{conn: conn, host: sentinel.NewHostAnalyzerClient(conn)}, nil
}

func (c *Client) GetProcessSnapshot(ctx context.Context) (*sentinel.ProcessSnapshot, error) {
    return c.host.GetProcessSnapshot(ctx, &emptypb.Empty{})
}
```

All calls use the context from the incoming HTTP request for cancellation propagation.

---

## Logging

Uses `go.uber.org/zap` (structured JSON logging):

```
{"level":"info","ts":1712345678.12,"msg":"gRPC connected","addr":"127.0.0.1:50051"}
{"level":"info","ts":1712345679.00,"msg":"REST API listening","addr":"127.0.0.1:8080"}
```

Log level controlled by `SENTINEL_LOG_LEVEL` env var or `[general] log_level` in `sentinel.toml`.

---

## Configuration

The orchestrator reads `sentinel.toml` at startup (path overridable via `--config` flag):

```toml
[grpc]
host_analyzer_addr = "127.0.0.1:50051"

[api]
listen_addr = "127.0.0.1:8080"
```

---

## Future: Multi-host Mode (Phase 4)

In the commercial tier, the orchestrator will:

1. Maintain a registry of remote `sentinel-grpc` agents
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
