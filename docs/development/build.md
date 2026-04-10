# Build System

## Rust workspace

The Rust code lives under `rust/` as a Cargo workspace. The workspace root `Cargo.toml` lists all member crates:

```toml
[workspace]
members = [
    "arqenor-core",
    "arqenor-platform",
    "arqenor-grpc",
    "arqenor-store",
    "arqenor-tui",
    "arqenor-cli",
]
resolver = "2"
```

### Common commands

```bash
# Check all crates (fast, no binary generation)
cargo check --workspace

# Build specific binary
cargo build --release -p arqenor-cli
cargo build --release -p arqenor-tui
cargo build --release -p arqenor-grpc   # requires protoc

# Run tests
cargo test --workspace

# Run tests excluding arqenor-grpc (if protoc unavailable)
cargo test --workspace --exclude arqenor-grpc

# Linting
cargo clippy --workspace -- -D warnings

# Format
cargo fmt --all
```

### Why `arqenor-grpc` is excluded from some commands

`arqenor-grpc/build.rs` runs `tonic-build` which invokes `protoc`. If `protoc` is not installed, `cargo check --workspace` will fail. Use `--exclude arqenor-grpc` in that case:

```bash
cargo check --workspace --exclude arqenor-grpc
```

---

## Proto code generation

### Rust (automatic)

`arqenor-grpc/build.rs`:

```rust
fn main() -> Result<(), Box<dyn std::error::Error>> {
    tonic_build::configure()
        .build_server(true)
        .build_client(false)
        .out_dir("src/generated")
        .compile(
            &["../../proto/host_analyzer.proto", "../../proto/network_scanner.proto"],
            &["../../proto"],
        )?;
    Ok(())
}
```

Triggered automatically by `cargo build -p arqenor-grpc`. Generated files in `src/generated/` are committed to the repo so that builds without `protoc` can proceed for other crates.

### Go (manual script)

```powershell
# Windows PowerShell
./scripts/gen-proto.ps1
```

Output goes to `go/internal/grpc/generated/`. Commit the generated `.go` files.

---

## Dependency notes

### sysinfo 0.30 API changes

`Process::name()` returns `&str` (not `OsStr`). Use `Pid::from(usize)` for PID conversion. Update call sites if upgrading from 0.29:

```rust
// 0.29 (old)
let pid = sysinfo::Pid::from(1234usize);
let name = proc.name().to_string_lossy();

// 0.30+ (current)
let pid = sysinfo::Pid::from(1234usize);
let name = proc.name().to_string();   // already &str
```

### DuckDB conflict (disabled)

`duckdb` 0.10 pulls in `arrow-arith` which conflicts with `chrono` on Rust 1.80+. The `duckdb_store.rs` module is present but gated behind a `duckdb` feature flag that is not enabled in the workspace. Re-enable in Phase 4 when the upstream conflict resolves.

### cfg-if requirement

`arqenor-platform` uses the `cfg-if` crate for clean platform dispatch in `lib.rs`. Do not replace with `#[cfg]` attribute soup — the crate enforces a single dispatch point.

---

## Go module

```bash
cd go

# Download dependencies
go mod download

# Tidy (remove unused, add missing)
go mod tidy

# Build orchestrator
go build -o orchestrator ./cmd/orchestrator

# Test
go test ./...

# Vet
go vet ./...
```

---

## Release checklist

1. Bump version in `arqenor-core/Cargo.toml` (workspace version)
2. Bump version in `go/cmd/orchestrator/main.go` `version` constant
3. Regenerate Go stubs if protos changed: `./scripts/gen-proto.ps1`
4. `cargo build --release -p arqenor-cli -p arqenor-tui -p arqenor-grpc`
5. `cd go && go build ./cmd/orchestrator`
6. Run integration smoke test (see `tests/smoke.sh`)
7. Tag: `git tag v0.x.0`

---

## IDE setup

### VS Code (Rust)

Install `rust-analyzer`. Add to `.vscode/settings.json`:

```json
{
  "rust-analyzer.linkedProjects": ["rust/Cargo.toml"],
  "rust-analyzer.cargo.features": "all"
}
```

### GoLand / VS Code (Go)

Open `go/` as the workspace root so that `go.mod` is at the root.

---

## CI targets (planned)

| Job | Command | When |
|---|---|---|
| `check` | `cargo check --workspace --exclude arqenor-grpc` | Every push |
| `test` | `cargo test --workspace --exclude arqenor-grpc` | Every push |
| `clippy` | `cargo clippy --workspace -- -D warnings` | Every push |
| `go-test` | `cd go && go test ./...` | Every push |
| `build-windows` | `cargo build --release ...` on windows runner | Tag |
| `build-linux` | `cargo build --release ...` on ubuntu runner | Tag |
| `build-macos` | `cargo build --release ...` on macos runner | Tag |
