# Installation Guide

## Prerequisites

### All platforms

| Tool | Minimum version | Install |
|---|---|---|
| Rust toolchain | 1.87 | `curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs \| sh` |
| Go | 1.25 (CI), 1.23+ to build | https://go.dev/dl/ |
| protoc | 3.x | See below |

### protoc installation

**Windows (Chocolatey):**
```powershell
choco install protoc
```

**Windows (manual):**
Download the `protoc-*.zip` from the [protobuf releases](https://github.com/protocolbuffers/protobuf/releases), extract `bin/protoc.exe` to a directory in your `PATH`.

**Linux (apt):**
```bash
apt install -y protobuf-compiler
```

**macOS (Homebrew):**
```bash
brew install protobuf
```

### Go proto plugins (for regenerating Go stubs)

```bash
go install google.golang.org/protobuf/cmd/protoc-gen-go@latest
go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@latest
```

---

## Building from Source

### 1. Clone the repository

```bash
git clone https://github.com/your-org/arqenor.git
cd arqenor
```

### 2. Build Rust binaries

```bash
# CLI scanner
cargo build --release -p arqenor-cli

# Terminal UI
cargo build --release -p arqenor-tui

# gRPC server (requires protoc)
cargo build --release -p arqenor-grpc

# All at once
cargo build --release -p arqenor-cli -p arqenor-tui -p arqenor-grpc
```

Binaries are written to `rust/target/release/`.

> **Note:** `arqenor-grpc` triggers `build.rs` which runs `tonic-build`. Make sure `protoc` is in your `PATH` before building this crate.

### 3. Build Go orchestrator

```bash
cd go
go mod download
go build ./cmd/orchestrator
# outputs: go/orchestrator (or orchestrator.exe on Windows)
```

### 4. (Optional) Regenerate proto stubs

Only needed if you modify `.proto` files:

```powershell
# Windows
./scripts/gen-proto.ps1

# Linux / macOS
protoc \
  --proto_path=proto \
  --go_out=go/internal/grpc/generated \
  --go_opt=paths=source_relative \
  --go-grpc_out=go/internal/grpc/generated \
  --go-grpc_opt=paths=source_relative \
  proto/common.proto proto/host_analyzer.proto proto/network_scanner.proto
```

Rust stubs regenerate automatically on `cargo build -p arqenor-grpc`.

---

## Platform-specific Notes

### Windows

- Run as Administrator for full process enumeration (otherwise some SYSTEM processes will be hidden)
- Registry scanning works without elevation for HKCU; HKLM requires elevation
- For network capture (Phase 3): install [Npcap](https://npcap.com/) in WinPcap compatibility mode

### Linux

- Run as root (or with `CAP_SYS_PTRACE`) for `/proc` access to all processes
- `inotify` limits: if watch mode reports too many open files, raise `fs.inotify.max_user_watches`:
  ```bash
  echo fs.inotify.max_user_watches=524288 | sudo tee -a /etc/sysctl.conf
  sudo sysctl -p
  ```

### macOS

- System Integrity Protection (SIP) limits access to some system processes — expected
- LaunchDaemon scanning reads `/Library/LaunchDaemons` (root-owned); run with `sudo` for full detection

---

## Cross-compilation

### Windows → Linux (from Windows host)

```bash
rustup target add x86_64-unknown-linux-gnu
cargo build --release --target x86_64-unknown-linux-gnu -p arqenor-cli
```

You may need `cross` for a fully linked binary:

```bash
cargo install cross
cross build --release --target x86_64-unknown-linux-gnu -p arqenor-cli
```

### Linux → Windows

```bash
rustup target add x86_64-pc-windows-gnu
sudo apt install gcc-mingw-w64-x86-64
cargo build --release --target x86_64-pc-windows-gnu -p arqenor-cli
```

---

## Runtime data directory

On first launch the orchestrator creates `data/` (path from `[general].data_dir`) with mode `0o700` and the SQLite file `arqenor.db` is chmod'd to `0o600`. Keep these permissions — relaxing them exposes alert history and any captured metadata.

---

## Verifying the Installation

```bash
# CLI
./arqenor --version

# TUI (launches dashboard — press q to exit)
./arqenor-tui

# gRPC server
./arqenor-grpc &
# test health with grpc_cli or grpcurl:
grpcurl -plaintext 127.0.0.1:50051 arqenor.HostAnalyzer/Health

# Orchestrator
./orchestrator &
curl http://127.0.0.1:8080/api/v1/health
```
