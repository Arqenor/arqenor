# Usage Guide

## Starting the stack

SENTINEL has three independent binaries. Run them in order:

```bash
# 1. Host analyzer gRPC server (Rust)
./sentinel-grpc

# 2. REST orchestrator (Go) — optional, needed for HTTP clients
./orchestrator

# 3. Your preferred interface
./sentinel scan          # one-shot CLI
./sentinel watch         # continuous CLI
./sentinel-tui           # live dashboard
```

All three can run simultaneously. The TUI and CLI can operate without the orchestrator — they call the platform library directly.

---

## CLI (`sentinel`)

### One-shot scan

```bash
# Scan running processes
sentinel scan --host

# Scan persistence mechanisms
sentinel scan --persistence

# Both, machine-readable JSON
sentinel scan --host --persistence --json

# Pipe to jq
sentinel scan --host --json | jq '.processes[] | select(.risk == "HIGH")'
```

### Continuous watch

```bash
# Default: repeat every 30 seconds
sentinel watch

# Custom interval
sentinel watch --interval 10
```

Watch mode prints only changes (new processes, new persistence entries, changed file hashes) relative to the previous snapshot.

### Exit codes

| Code | Meaning |
|---|---|
| `0` | Clean — no anomalies above `min_severity` |
| `1` | Anomalies detected |
| `2` | Runtime error (config missing, permission denied) |

This makes `sentinel scan` scriptable in CI pipelines:

```bash
sentinel scan --host --persistence || alert "SENTINEL detected threats on $(hostname)"
```

---

## Terminal UI (`sentinel-tui`)

Launch with no arguments:

```bash
./sentinel-tui
```

### Tab: Processes

- Shows all running processes with PID, PPID, name, user, and risk level
- Risk column is colour-coded (green → magenta)
- New processes since last refresh are highlighted

### Tab: Persistence

- Lists all detected persistence mechanisms
- `NEW` badge on entries not in the baseline
- Baseline is updated each time you press `r` after reviewing

### Tab: Network

- Auto-detects local subnets and shows discovered hosts
- Press `s` to start a port scan of highlighted host
- VPN indicator in header shows if a VPN process is detected

### Keyboard quick reference

| Key | Action |
|---|---|
| `Tab` | Next tab |
| `1` / `2` / `3` | Jump to tab by number |
| `↑` `↓` or `j` `k` | Navigate list |
| `r` | Refresh data |
| `s` | Network scan (Network tab) |
| `/` | Filter input |
| `Esc` | Clear filter |
| `q` | Quit |

---

## REST API (via Go orchestrator)

### Health check

```bash
curl http://127.0.0.1:8080/api/v1/health
```

```json
{"status":"ok","grpc_connected":true,"platform":"windows","version":"0.1.0"}
```

### Trigger a scan (Phase 2+)

```bash
curl -X POST http://127.0.0.1:8080/api/v1/scans \
  -H 'Content-Type: application/json' \
  -d '{"type":"filesystem","root_path":"C:\\Users","recursive":true}'
```

### List alerts

```bash
# All alerts at medium severity or above
curl 'http://127.0.0.1:8080/api/v1/alerts?min_severity=medium'
```

---

## gRPC (direct)

Use `grpcurl` for quick manual testing:

```bash
# Install
go install github.com/fullstorydev/grpcurl/cmd/grpcurl@latest

# Health check
grpcurl -plaintext 127.0.0.1:50051 sentinel.HostAnalyzer/Health

# Process snapshot
grpcurl -plaintext 127.0.0.1:50051 sentinel.HostAnalyzer/GetProcessSnapshot

# Watch process events (streams until Ctrl+C)
grpcurl -plaintext 127.0.0.1:50051 sentinel.HostAnalyzer/WatchProcesses

# Filesystem scan
grpcurl -plaintext -d '{"root_path":"C:\\\\Users","recursive":true}' \
  127.0.0.1:50051 sentinel.HostAnalyzer/ScanFilesystem

# Persistence detection
grpcurl -plaintext 127.0.0.1:50051 sentinel.HostAnalyzer/GetPersistence
```

---

## Workflow: Initial baselining

On first run, every persistence entry will be flagged as `NEW`. Follow this workflow to establish a clean baseline:

```bash
# 1. Lower severity threshold temporarily
SENTINEL_ALERTS_MIN_SEVERITY=info sentinel scan --persistence --json > baseline_review.json

# 2. Review — remove any entries you don't recognise before accepting
cat baseline_review.json | jq '.persistence[]'

# 3. Accept the baseline in TUI: launch, switch to Persistence tab, press r
./sentinel-tui

# 4. Subsequent runs will only flag NEW entries not in the accepted baseline
sentinel scan --persistence
```

---

## Workflow: Monitoring a specific directory

```bash
# Watch C:\Downloads for any new executables
sentinel-grpc &
grpcurl -plaintext \
  -d '{"root_path":"C:\\\\Downloads","recursive":true,"extensions":[".exe",".dll",".ps1",".bat"]}' \
  127.0.0.1:50051 sentinel.HostAnalyzer/WatchFilesystem
```

---

## Workflow: Scripted threat check (CI/CD)

```yaml
# GitHub Actions example
- name: SENTINEL threat check
  run: |
    ./sentinel scan --host --persistence --json > results.json
    HIGH=$(jq '[.processes[] | select(.risk == "HIGH" or .risk == "CRITICAL")] | length' results.json)
    if [ "$HIGH" -gt 0 ]; then
      echo "::error::SENTINEL detected $HIGH high-risk processes"
      exit 1
    fi
```
