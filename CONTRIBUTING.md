# Contributing to Arqenor

Thanks for your interest in contributing! Arqenor is a cross-platform
host and network security analyzer, and we welcome contributions of all
kinds — bug reports, fixes, new detections, documentation, and rule
contributions.

This document covers what you need to know before opening a PR.

## Code of conduct

This project follows the [Contributor Covenant](CODE_OF_CONDUCT.md).
By participating, you agree to uphold it.

## Open-core model

Arqenor follows an **open-core** model:

- **This repo (`arqenor/arqenor`, Apache 2.0)** contains the core
  platform: detection engine, collectors, rules, CLI, TUI, gRPC, Go
  orchestrator, eBPF probes.
- **`arqenor/arqenor-enterprise` (private)** contains commercial
  modules: Windows kernel driver, ML scorer, desktop app, premium
  threat intel feeds.

If your contribution touches anything in the enterprise repo, please
reach out first via a GitHub issue so we can coordinate.

## Getting started

### Prerequisites

- **Rust** 1.75 or newer (`rustup`)
- **Go** 1.22 or newer
- **Protoc** (for gRPC codegen)
- Platform-specific:
  - **Windows:** MSVC toolchain, Windows 10 SDK
  - **Linux:** `libbpf`, kernel headers (for eBPF probes)
  - **macOS:** Xcode Command Line Tools

### Build

```bash
git clone https://github.com/Arqenor/arqenor.git
cd arqenor
cargo build --workspace
```

The Go orchestrator:

```bash
cd go
go build ./...
```

### Run the tests

```bash
cargo test --workspace
cd go && go test ./...
```

## Making changes

### Branch naming

- `feat/short-description` — new features
- `fix/short-description` — bug fixes
- `docs/short-description` — documentation
- `refactor/short-description` — internal refactors
- `chore/short-description` — build, CI, deps

### Commit messages

We use [Conventional Commits](https://www.conventionalcommits.org/):

```
<type>(<scope>): <short summary>

<longer explanation if needed>

<footer, e.g. closes #123>
```

Examples:
- `feat(platform): add macOS ESF process monitor`
- `fix(core): correct severity calculation for blocked ports`
- `docs(readme): update install instructions`

### Code style

**Rust:**
- Run `cargo fmt` before committing
- Run `cargo clippy --workspace -- -D warnings` and fix all warnings
- Prefer explicit error types over `anyhow` in library crates
- Public types must implement `Debug` and `Clone` where reasonable
- No `unwrap()` or `expect()` in library code — propagate errors

**Go:**
- Run `gofmt -w .` before committing
- Run `go vet ./...` and fix all warnings
- Follow [Effective Go](https://go.dev/doc/effective_go)

### Pull request process

1. Fork the repo and create your branch from `dev`
2. Add tests for any new functionality
3. Ensure `cargo test --workspace` and `go test ./...` pass
4. Ensure CI passes (fmt, clippy, vet, tests, `enforce-main-policy`)
5. Update documentation if you changed public APIs or user-facing behavior
6. Open a PR against the `dev` branch with a clear description of the
   change and the motivation behind it

### Local git hooks

The `.githooks/pre-push` hook refuses direct pushes to `main` so the
"Protect main" ruleset doesn't have to do the rejecting after a network
roundtrip. Install it once after cloning:

```bash
bash scripts/setup-hooks.sh        # macOS / Linux / Git Bash on Windows
# or
pwsh scripts/setup-hooks.ps1       # PowerShell on Windows
```

To bypass intentionally (e.g. emergency fix): `git push --no-verify`.

### Contributing detection rules

Sigma rules go in `rust/arqenor-core/src/rules/` or can be loaded at
runtime from YAML files. When contributing a rule:

- Reference the relevant MITRE ATT&CK ID(s) in the rule metadata
- Include test fixtures demonstrating true positives
- Include test fixtures demonstrating known false positives you tuned out
- Document any expected performance impact

## Reporting bugs

Use the [Bug Report](https://github.com/Arqenor/arqenor/issues/new?template=bug_report.yml)
issue template. Include:

- Arqenor version / commit SHA
- OS and version
- Steps to reproduce
- Expected vs. actual behavior
- Logs (with sensitive data redacted)

## Reporting security vulnerabilities

**Do not open a public issue.** See [SECURITY.md](SECURITY.md) for
the disclosure process.

## License

By contributing, you agree that your contributions will be licensed
under the [Apache License 2.0](LICENSE) that covers the project.
