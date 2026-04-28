# Wire .githooks/ as the active hook directory for this clone.
# Run once after cloning. Idempotent.

$ErrorActionPreference = 'Stop'

$repoRoot = git rev-parse --show-toplevel
if (-not $repoRoot) {
    Write-Error "setup-hooks: not a git checkout"
    exit 1
}

if (-not (Test-Path (Join-Path $repoRoot ".githooks"))) {
    Write-Error "setup-hooks: .githooks/ not found at repo root"
    exit 1
}

git -C $repoRoot config core.hooksPath .githooks
Write-Host "✓ git hooks wired (core.hooksPath=.githooks)" -ForegroundColor Green
