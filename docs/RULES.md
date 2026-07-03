# Zejtron Project Maintenance Rules

This document codifies the maintenance discipline for the Zejtron project.
All contributors and maintainers must follow these rules.

## LOC Discipline

Core engine source files must stay under **1000 lines of code (LOC)**.

This rule applies to all code files: `*.rs`, `*.c`, `*.css`, and similar
source files that contain program logic.

Documentation and plain-text files are excluded from this rule: `*.md`,
`*.txt`, `*.sh` (scripts), and other non-code files are not subject to the
LOC limit.

When a source file approaches or exceeds the 1000 LOC threshold, it must
be split by responsibility before it becomes a maintenance burden. The split
should follow the principle of cohesion: each resulting file should have a
clear, single purpose such as parsing, data models, output rendering, or
owner mapping.

## main.rs Scope

`main.rs` should stay small and only handle bootstrap and wiring. The
preferred range is **100 to 300 LOC**. It should parse CLI arguments and
dispatch commands to the appropriate modules, without containing substantive
business logic.

## Feature Freeze

Zejtron is currently **feature-frozen**. No new commands or runtime features
should be added. The project is in stabilization mode, and all work should
focus on:

- Bug fixes that do not change behavior for correct inputs.
- Stability and reliability improvements.
- Maintainability and code quality.
- Supply-chain hardening.
- CI/CD maturity.

Feature creep is explicitly prohibited. If a new feature idea arises, it
should be documented in the issue tracker but not implemented until the
project exits stabilization mode.

## Read-Only Behavior

Zejtron is designed to be **read-only by default**. It must not kill
processes, close ports, start or stop services, modify files, or alter system
state in any way. Any change that would introduce write side-effects must be
rejected during review.

## CI/CD Maturity

CI must remain **green** at all times. All changes must pass the full
`./scripts/build.sh` suite before being merged to `main`. The normal CI pipeline must
run as read-only and must not require broad write tokens.

Release workflows must use the **minimum permissions necessary**. The release
workflow requires `contents: write` only for creating GitHub Releases and
dispatching AUR sync. The weekly maintenance workflow may use `contents: write`
only to commit a validated dependency refresh directly to the default branch.

## Supply-Chain Surface

The dependency footprint must stay **minimal**. No new runtime dependencies
should be added unless absolutely necessary. Dependency refreshes are handled by
the weekly maintenance workflow, which runs `cargo update`, executes the full
`./scripts/build.sh` suite, and commits `Cargo.lock` directly to the default branch only
when validation succeeds.

## Code Quality

All Rust source files must carry the SPDX license header:

```rust
// SPDX-FileCopyrightText: 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only
```

Headers must not be duplicated.

All code must pass:

- `cargo fmt --all -- --check`
- `cargo clippy --all-targets --all-features --locked -- -D warnings`
- `cargo test --all-targets --all-features --locked`

## AUR Consistency

The AUR package metadata (`PKGBUILD` and `.SRCINFO`) must remain consistent
with the released version. The AUR sync workflow must validate that `pkgver`
matches the release tag and that `pkgdesc` is identical in both files. Both
`PKGBUILD` and `.SRCINFO` must be committed and copied together.

## Major Release Design Gates

Major releases (e.g. v5.0.0) carry additional requirements beyond normal
maintenance. These gates must be satisfied before a major version tag is
created:

- All tests pass, including new namespace tests.
- `actionlint .github/workflows/*` and `yamllint .github/workflows/*` pass.
- No source file exceeds 1000 LOC.
- No new high-risk dependencies without written justification in the commit
  message.
- AUR and release CI workflows stay green on the tagged commit.
- Documentation and command help text remain consistent with actual behavior.
- `git diff --check` reports no whitespace errors.
- `bash -n check.sh version-to.sh` passes syntax validation.
- No regression against the previous stable release for any existing command.

The major release design plan is documented in [ROADMAP-current.md](ROADMAP-current.md) and
[v5.md](v5.md).

## Version Bumps

Version bumps must use the `./scripts/version-to.sh vX.Y.Z` script, which updates
`Cargo.toml`, `Cargo.lock`, `README.md`, `docs/workflow/about-ci.md`, and the AUR
metadata in a single, consistent pass. Manual version edits are prohibited.
