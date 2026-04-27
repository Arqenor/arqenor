# Contributing

## Code style

### Rust

- Follow `rustfmt` defaults — run `cargo fmt --all` before committing
- Pass `cargo clippy --workspace -- -D warnings` with zero warnings
- Use `tracing::{info, debug, warn, error}` for logging — no `println!` in library code
- All public items must have doc comments (`///`)
- Prefer `Result<T, ArqenorError>` in public APIs; use `?` for propagation

### Go

- Follow `gofmt` — run before committing
- Use `go vet ./...` — zero warnings
- Structured logging via `zap.Logger` — no `fmt.Println` in package code
- Error wrapping: `fmt.Errorf("context: %w", err)`

---

## Branching

| Branch | Purpose |
|---|---|
| `main` | Stable, buildable |
| `dev` | Integration branch — merged into main on release |
| `feat/<name>` | New features |
| `fix/<name>` | Bug fixes |
| `phase/<n>` | Phase-level feature branches |

## Commit messages

```
<type>(<scope>): <short description>

[optional body]
```

Types: `feat` `fix` `refactor` `docs` `test` `chore`
Scopes: `core` `platform` `grpc` `store` `tui` `cli` `go` `proto`

Examples:
```
feat(platform): add LD_PRELOAD detection for Linux
fix(tui): prevent panic on empty process list
docs(grpc): add Python client example
chore(deps): bump tonic to 0.12
```

---

## Pull request process

1. Branch from `dev`
2. Keep PRs focused — one logical change per PR
3. All CI checks must pass: `rust-fmt`, `rust-clippy-linux`, `rust-check-windows`, `go`, `audit` (blocking), `cargo-deny`, `govulncheck`
4. At least one reviewer approval required
5. Squash-merge into `dev` (subject must end in ` (#NNN)`; the `enforce-main-policy` workflow rejects pushes to `main` that violate this)

---

## Adding a new detection (persistence mechanism)

1. Add a variant to `PersistenceKind` in `arqenor-core/src/models/persistence.rs`
2. Add proto string mapping in `arqenor-grpc/src/services/host_analyzer.rs`
3. Implement detection in the relevant platform module(s) under `arqenor-platform/src/<os>/persistence.rs`
4. Add a test case in `arqenor-platform/tests/persistence_test.rs`
5. Update `docs/development/platform-notes.md` with the new mechanism

---

## Testing

### Rust unit tests

```bash
cargo test --workspace --exclude arqenor-grpc
```

Tests live in `#[cfg(test)]` modules within each source file.

### Rust integration tests

```bash
cargo test -p arqenor-platform --test '*'
```

Platform integration tests run against the real OS — they must be run on the target platform (not in CI cross-compile).

### Go tests

```bash
cd go && go test ./...
```

### Manual smoke test

```bash
# Start gRPC server
cargo run -p arqenor-grpc &

# Run CLI scan and verify output
cargo run -p arqenor-cli -- scan --host --json | jq '.processes | length'

# Kill server
kill %1
```

---

## Dependency policy

- **No new platform-specific dependencies** in crates other than `arqenor-platform`
- Prefer crates with `no_std` compatibility where possible for future embedded targets
- Pin major versions in `Cargo.toml`; use `cargo update` for patch bumps
- All new Go dependencies must be audited with `go mod tidy` and have a clear justification

---

## Commit signing

All commits to `main` and `dev` must be GPG-signed. Configure:

```bash
git config --global commit.gpgsign true
git config --global user.signingkey <YOUR_KEY_ID>
```
