#!/usr/bin/env bash
# Wire .githooks/ as the active hook directory for this clone.
# Run once after cloning. Idempotent.

set -euo pipefail

cd "$(dirname "$0")/.."

if [ ! -d ".githooks" ]; then
  echo "setup-hooks: .githooks/ not found at repo root" >&2
  exit 1
fi

git config core.hooksPath .githooks
echo "✓ git hooks wired (core.hooksPath=.githooks)"
