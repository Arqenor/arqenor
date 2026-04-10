# Protocol Buffer Reference

All `.proto` files use `proto3` syntax and are located in `proto/`. Package: `arqenor`.

For the full gRPC service documentation including RPC methods and streaming patterns, see [gRPC Services](../architecture/grpc-services.md).

---

## common.proto

### Severity enum

```protobuf
enum Severity {
  INFO     = 0;
  LOW      = 1;
  MEDIUM   = 2;
  HIGH     = 3;
  CRITICAL = 4;
}
```

### Alert message

```protobuf
message Alert {
  string   id        = 1;
  Severity severity  = 2;
  string   kind      = 3;
  string   message   = 4;
  int64    timestamp = 5;
  string   metadata  = 6;   // JSON string
}
```

---

## host_analyzer.proto

### Enums

```protobuf
enum ProcessEventKind {
  PROCESS_CREATED    = 0;
  PROCESS_TERMINATED = 1;
  PROCESS_MODIFIED   = 2;
}

enum FileEventKind {
  FILE_CREATED  = 0;
  FILE_MODIFIED = 1;
  FILE_DELETED  = 2;
  FILE_RENAMED  = 3;
}
```

### Messages

```protobuf
message ProcessInfo {
  uint32          pid            = 1;
  uint32          ppid           = 2;
  string          name           = 3;
  string          exe_path       = 4;
  string          cmdline        = 5;
  string          user           = 6;
  string          sha256         = 7;
  repeated string loaded_modules = 8;
}

message ProcessSnapshot {
  repeated ProcessInfo processes = 1;
  int64                timestamp = 2;
}

message ProcessEvent {
  ProcessEventKind kind      = 1;
  ProcessInfo      process   = 2;
  int64            timestamp = 3;
}

message FileEvent {
  FileEventKind kind      = 1;
  string        path      = 2;
  string        hash      = 3;
  uint64        size      = 4;
}

message PersistenceEntry {
  string kind     = 1;
  string name     = 2;
  string command  = 3;
  string location = 4;
  bool   is_new   = 5;
}

message PersistenceList {
  repeated PersistenceEntry entries  = 1;
  int64                     timestamp = 2;
}

message ScanRequest {
  string          root_path  = 1;
  bool            recursive  = 2;
  repeated string extensions = 3;
  uint64          max_size   = 4;
}

message HealthResponse {
  string status   = 1;
  string platform = 2;
  string version  = 3;
}
```

### Service

```protobuf
service HostAnalyzer {
  // Unary — full snapshot of running processes
  rpc GetProcessSnapshot (google.protobuf.Empty) returns (ProcessSnapshot);

  // Server-streaming — emit ProcessEvent as processes start/stop/change
  rpc WatchProcesses (google.protobuf.Empty) returns (stream ProcessEvent);

  // Server-streaming — walk filesystem and emit FileEvent per file
  rpc ScanFilesystem (ScanRequest) returns (stream FileEvent);

  // Server-streaming — watch filesystem for changes in real time
  rpc WatchFilesystem (ScanRequest) returns (stream FileEvent);

  // Unary — detect all persistence mechanisms
  rpc GetPersistence (google.protobuf.Empty) returns (PersistenceList);

  // Unary — health check
  rpc Health (google.protobuf.Empty) returns (HealthResponse);
}
```

---

## network_scanner.proto

### Messages

```protobuf
message ScanTarget {
  string          cidr           = 1;   // CIDR notation, e.g. "192.168.1.0/24"
  uint32          timeout_ms     = 2;
  repeated uint32 ports          = 3;   // empty = well-known ports
  bool            service_detect = 4;
}

message PortResult {
  uint32 port     = 1;
  string protocol = 2;   // "tcp" | "udp"
  string state    = 3;   // "open" | "filtered" | "closed"
  string service  = 4;
  string banner   = 5;
  string version  = 6;
}

message HostResult {
  string            ip       = 1;
  string            hostname = 2;
  string            mac      = 3;
  bool              is_up    = 4;
  repeated PortResult ports  = 5;
}
```

### Service

```protobuf
service NetworkScanner {
  // Server-streaming — sweep CIDR, emit HostResult per discovered host
  rpc StartScan (ScanTarget) returns (stream HostResult);

  // Unary — report an anomaly detected by the Go network layer
  rpc ReportAnomaly (Alert) returns (google.protobuf.Empty);
}
```

---

## Wire encoding notes

- All integers use varint encoding (proto3 default)
- `int64 timestamp` fields are Unix epoch seconds
- `string metadata` in `Alert` is a JSON object serialized to string — parse with your language's JSON library
- Empty repeated fields are omitted on the wire (proto3 default)
- `is_new` in `PersistenceEntry` defaults to `false` if not set

---

## Versioning policy

Proto files follow the package version (`arqenor` package = v0.x). Breaking changes:

- Adding fields: **safe** (proto3 unknown fields are ignored)
- Renaming fields: **safe** (wire encoding uses field numbers, not names)
- Changing field numbers: **breaking** — never do this
- Removing fields: **reserve** the number with `reserved` keyword
- Changing field types: **breaking** — create a new field number instead
