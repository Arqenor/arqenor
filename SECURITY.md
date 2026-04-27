# Security Policy

Arqenor is a security tool, so we take vulnerabilities in our own code
seriously. Thank you for helping keep Arqenor and its users safe.

## Supported versions

Arqenor is pre-1.0 and under active development. Security fixes are
applied to the latest `master` and the most recent release branch.

| Version       | Supported          |
| ------------- | ------------------ |
| `master`      | :white_check_mark: |
| `dev`         | :white_check_mark: |
| older commits | :x:                |

## Reporting a vulnerability

**Please do not report security vulnerabilities through public GitHub
issues, discussions, or pull requests.**

Instead, report them privately to:

- **Email:** security@arqenor.com
- **GitHub Security Advisory:** [Report a vulnerability](https://github.com/Arqenor/arqenor/security/advisories/new)

Please include as much of the following information as possible:

- Type of issue (e.g. buffer overflow, privilege escalation, TOCTOU,
  authentication bypass, etc.)
- Affected component (crate, module, file path, line numbers)
- Full paths of source file(s) related to the issue
- Step-by-step reproduction instructions
- Proof-of-concept or exploit code (if available)
- Impact assessment — what an attacker could achieve
- Suggested mitigation, if you have one

The more detail you provide, the faster we can triage and fix the issue.

## Response timeline

We aim to:

- **Acknowledge** your report within **48 hours**
- **Triage** and confirm the issue within **7 days**
- **Release a fix** for confirmed High/Critical issues within **30 days**
- **Publish a CVE and advisory** once a fix is available

We will keep you updated throughout the process and credit you in the
advisory (unless you prefer to remain anonymous).

## Scope

**In scope:**
- Vulnerabilities in the Arqenor codebase (Rust crates, Go services)
- Privilege escalation via Arqenor agents or drivers
- Sandbox escapes, detection bypasses that compromise security guarantees
- Dependency vulnerabilities with direct impact on Arqenor

**Out of scope:**
- Vulnerabilities in third-party dependencies without a working exploit
  against Arqenor itself — please report those upstream
- Missing defense-in-depth measures that don't lead to a concrete exploit
- Denial-of-service against an already-compromised host
- Social engineering of Arqenor maintainers

## Audit history

A third-party security audit and the corresponding remediation log are
published in [`docs/security-audit-202604.md`](docs/security-audit-202604.md).
That document tracks each finding's status (fixed / mitigated / accepted) and
points to the commits that addressed it. Use it as the canonical source of
truth for "is this already known?" before filing a report.

## Safe harbor

We support good-faith security research. If you follow this policy, we
will:

- Not pursue or support legal action against you for your research
- Work with you to understand and resolve the issue quickly
- Recognize your contribution in the published advisory

Thank you for helping keep Arqenor secure.
