# REST API Reference

Base URL: `http://127.0.0.1:8080/api/v1`

All responses are JSON. Error responses follow the shape:

```json
{
  "error": "human readable message",
  "code": "ERROR_CODE"
}
```

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
| `grpc_connected` | bool | Whether the gRPC connection to `sentinel-grpc` is alive |
| `platform` | string | OS of the sentinel-grpc server |
| `version` | string | sentinel-grpc version |

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
| `root_path` | string | For `filesystem` | Scan root |
| `recursive` | bool | No (default true) | Recurse into subdirectories |
| `extensions` | string[] | No | Filter by extension; empty = all |
| `max_size` | integer | No | Max file size to hash |

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
| `GRPC_UNAVAILABLE` | 503 | Cannot reach `sentinel-grpc` |
| `SCAN_NOT_FOUND` | 404 | Scan ID does not exist |
| `INVALID_SEVERITY` | 400 | Unknown severity value |
| `INVALID_SCAN_TYPE` | 400 | Unknown scan type |
| `INTERNAL` | 500 | Unexpected server error |
