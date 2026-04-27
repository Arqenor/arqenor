# REST API Reference

Base URL: `http://127.0.0.1:8080/api/v1`

The orchestrator binds to `127.0.0.1` by default — change `[api].listen_addr` in `configs/arqenor.toml` to expose externally. Do **not** flip this to `0.0.0.0` until the SaaS auth layer ships.

All responses are JSON. Error responses follow the shape:

```json
{
  "error": "human readable message",
  "code": "ERROR_CODE"
}
```

## Cross-cutting limits

- **Rate limiting:** per-IP token bucket, default 20 req/s (`[api].rate_limit_per_sec`). Excess returns `429 Too Many Requests` with a `Retry-After` header.
- **Per-scan timeout:** scans triggered via `POST /scans` run inside a `context.WithTimeout` of `[api].scan_timeout_seconds` (default 600 s). Scans exceeding this are cancelled.
- **SSE alert stream cap:** at most `[api].max_sse_connections` concurrent subscribers (default 100). When the cap is reached, new subscribers receive `503 Service Unavailable` with body `{"error":"max sse connections reached"}`.
- **Logging:** query strings are redacted before being logged.

---

## GET /health

Liveness check. Returns orchestrator status and gRPC connectivity.

**Request:** none

**Response 200:**

```json
{
  "status": "ok",
  "grpc_connected": true,
  "platform": "windows",
  "version": "0.1.0"
}
```

| Field | Type | Description |
|---|---|---|
| `status` | string | `"ok"` or `"degraded"` |
| `grpc_connected` | bool | Whether the gRPC connection to `arqenor-grpc` is alive |
| `platform` | string | OS of the arqenor-grpc server |
| `version` | string | arqenor-grpc version |

**Example:**

```bash
curl http://127.0.0.1:8080/api/v1/health
```

---

## GET /alerts

List stored alerts. Supports filtering by severity.

**Query parameters:**

| Param | Type | Default | Description |
|---|---|---|---|
| `min_severity` | string | `medium` | Minimum severity: `info` `low` `medium` `high` `critical` |
| `limit` | integer | `100` | Maximum number of results |
| `offset` | integer | `0` | Pagination offset |

**Response 200:**

```json
{
  "total": 42,
  "alerts": [
    {
      "id": "uuid-here",
      "severity": "high",
      "kind": "NewPersistence",
      "message": "New registry run key detected: C:\\Temp\\bad.exe",
      "timestamp": 1712345678,
      "metadata": {
        "registry_path": "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
        "entry_name": "MyCoolApp"
      }
    }
  ]
}
```

**Status: TODO (Phase 2)**

---

## GET /scans

List scan history.

**Query parameters:**

| Param | Type | Default | Description |
|---|---|---|---|
| `type` | string | all | `filesystem` `process` `persistence` |
| `limit` | integer | `20` | Maximum results |

**Response 200:**

```json
{
  "scans": [
    {
      "id": "uuid",
      "type": "filesystem",
      "started_at": 1712345600,
      "completed_at": 1712345720,
      "status": "completed",
      "root_path": "C:\\Users",
      "files_scanned": 18432,
      "alerts_raised": 2
    }
  ]
}
```

**Status: TODO (Phase 2)**

---

## POST /scans

Trigger an on-demand scan.

**Request body:**

```json
{
  "type": "filesystem",
  "root_path": "C:\\Users",
  "recursive": true,
  "extensions": [".exe", ".dll", ".ps1"],
  "max_size": 10485760
}
```

| Field | Type | Required | Description |
|---|---|---|---|
| `type` | string | Yes | `filesystem` `process` `persistence` |
| `root_path` | string | For `filesystem` | Scan root. Server-side allowlist (`[scan].fs_roots`) — paths outside it are rejected with `403`. |
| `recursive` | bool | No (default true) | Recurse into subdirectories |
| `extensions` | string[] | No | Filter by extension; empty = all |
| `max_size` | integer | No | Max file size to hash. `0` = server default (10 GiB). Values > 10 GiB are rejected. |

**Response 202:**

```json
{
  "scan_id": "uuid",
  "status": "running"
}
```

**Status: TODO (Phase 2)**

---

## GET /hosts

List known network hosts from the most recent network scan.

**Response 200:**

```json
{
  "hosts": [
    {
      "ip": "192.168.1.100",
      "hostname": "mypc.local",
      "mac": "aa:bb:cc:dd:ee:ff",
      "is_up": true,
      "open_ports": [
        {"port": 22, "protocol": "tcp", "service": "ssh", "state": "open"},
        {"port": 80, "protocol": "tcp", "service": "http", "state": "open"}
      ]
    }
  ]
}
```

**Status: TODO (Phase 3)**

---

## Error codes

| Code | HTTP | Description |
|---|---|---|
| `GRPC_UNAVAILABLE` | 503 | Cannot reach `arqenor-grpc` |
| `SCAN_NOT_FOUND` | 404 | Scan ID does not exist |
| `INVALID_SEVERITY` | 400 | Unknown severity value |
| `INVALID_SCAN_TYPE` | 400 | Unknown scan type |
| `PATH_NOT_ALLOWED` | 403 | `root_path` outside `[scan].fs_roots` allowlist |
| `MAX_SIZE_EXCEEDED` | 400 | `max_size` greater than the 10 GiB server cap |
| `RATE_LIMITED` | 429 | Per-IP rate limit exceeded; retry after `Retry-After` |
| `SSE_CAP_REACHED` | 503 | SSE alert stream subscriber cap reached |
| `INTERNAL` | 500 | Unexpected server error |
