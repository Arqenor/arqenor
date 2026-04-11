<!--
Thanks for contributing to Arqenor!

Please make sure you are opening this PR against the `dev` branch and
that you have read CONTRIBUTING.md.
-->

## Summary

<!-- What does this PR change, and why? 1-3 sentences. -->

## Type of change

- [ ] Bug fix (non-breaking change that fixes an issue)
- [ ] New feature (non-breaking change that adds functionality)
- [ ] New detection rule (Sigma / YARA / heuristic)
- [ ] Refactor (no behavior change)
- [ ] Docs
- [ ] Build / CI / chore
- [ ] Breaking change (fix or feature that changes existing behavior)

## Related issues

<!-- e.g. "Closes #123", "Part of #456" -->

## Checklist

- [ ] I have read [CONTRIBUTING.md](../CONTRIBUTING.md)
- [ ] My commits follow [Conventional Commits](https://www.conventionalcommits.org/)
- [ ] `cargo fmt --all -- --check` passes
- [ ] `cargo clippy --workspace --all-targets -- -D warnings` passes
- [ ] `cargo test --workspace` passes
- [ ] `go vet ./...` and `go test ./...` pass (if Go code changed)
- [ ] I have added tests covering the new behavior (or explained why not)
- [ ] I have updated docs for any user-facing change
- [ ] This change does not touch anything that belongs in the private
      `arqenor-enterprise` repo (kernel driver, ML scorer, desktop app,
      premium intel feeds)

## Notes for reviewers

<!-- Anything that would help a reviewer: tricky areas, alternative
designs you considered, known follow-ups. -->
