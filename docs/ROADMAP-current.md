# Zejtron Roadmap

This document describes the design direction and staged delivery plan for
future Zejtron releases. Nothing here is implemented. This is a design-only
reference to guide deliberate, disciplined development when the project exits
stabilization mode.

See [docs/v5.md](v5.md) for the full v5.0.0 design specification.

## Project Identity

Zejtron is a Linux introspection tool. It exists to answer operational
questions about processes, ports, files, services, and system readiness from a
single terminal binary. The project serves operators, engineers, and incident
responders who need fast, reliable answers without installing a toolkit of
independent utilities.

The following identity constraints are non-negotiable:

- Linux-first, procfs-based. No cross-platform ambitions.
- Read-only by default. Zejtron never modifies system state.
- Single binary distribution. No runtime dependencies beyond what ships
  with standard Linux systems.
- Low maintenance burden. Minimal dependency footprint, disciplined LOC
  limits, and CI-first development.
- No feature creep. Every addition must serve introspection and must carry
  clear operational value.

## Staged Roadmap

### Phase 1: Design Freeze

Goal: Lock the v5.0.0 design before any implementation begins.

- Publish ROADMAP.md and docs/v5.md.
- Define all proposed namespaces, their scope, and their boundaries.
- Define release gates, architecture rules, and testing requirements.
- Collect feedback (if applicable) and refine.
- No code changes. No version bump. No tags.

Outcome: A frozen design document that all subsequent implementation
references.

### Phase 2: v5-alpha Internal Branch

Goal: Begin implementation on a dedicated branch, off main.

- Create a `v5` branch from `main`.
- Implement one namespace at a time (see Phase 3).
- Each namespace must pass all existing and new checks before the next
  namespace begins.
- No simultaneous shell/net/git implementation.
- No merges to `main` until the full v5 scope is soak-tested.

Outcome: A working v5 branch with incremental, validated additions.

### Phase 3: One Namespace at a Time

Goal: Implement each proposed namespace sequentially, with full validation
between stages.

Each namespace follows the same delivery cycle:

1. Design review against docs/v5.md.
2. Implementation with full test coverage.
3. LOC compliance (no source file exceeds 1000 LOC).
4. ./scripts/build.sh passes.
5. Codespell passes on all new documentation.
6. Soak testing on real systems.

Proposed namespace order:

| Order | Namespace | Scope | Status |
|-------|-----------|-------|--------|
| 1 | `zejtron shell` | Shell process and environment introspection | Implemented in v3.0.0 |
| 2 | `zejtron net`   | Network interface and routing inspection | Implemented in v5.0.0 |
| 3 | `zejtron git`   | Git repository state inspection | Implemented in v5.0.0 |

This order is deliberate. `shell` builds on existing process and environment
infrastructure. `net` extends the port inspection model. `git` is the most
self-contained and carries the least risk to core functionality.

### Phase 4: Soak Test and Release

Goal: Validate the complete v5 build under real-world conditions before
shipping.

- Run the full v5 build on multiple Linux distributions and kernel versions.
- Verify all existing commands produce identical output to v2.4.6.
- Verify all new commands meet their design specification.
- Confirm no regression in binary size, startup time, or memory usage beyond
  acceptable thresholds.
- Update CHANGELOG.md.
- Bump version via ./scripts/version-to.sh.
- Tag and release only after all gates pass.

Outcome: v5.0.0 release on main with full CI green.

## Release Gates (v5 and Beyond)

All releases must satisfy the following conditions before tagging:

1. `./scripts/build.sh` passes on stable Rust.
2. `actionlint .github/workflows/*` passes with no warnings.
3. `yamllint .github/workflows/*` passes with no warnings.
4. `git diff --check` reports no whitespace errors.
5. `bash -n check.sh version-to.sh` passes syntax validation.
6. No source file exceeds 1000 LOC.
7. No new high-risk dependencies without written justification in the
   commit message.
8. AUR/release workflow stays green on the tagged commit.
9. Documentation and command help text remain consistent.
10. `codespell` passes on all documentation.

## What Belongs in Zejtron

Introspection commands that answer operational questions about the current
system without modifying it. Specifically:

- Process, port, and file holder inspection.
- File modification evidence and explanation.
- Environment variable snapshot and diff.
- Service status inspection.
- System readiness checks.
- (Proposed) Shell environment, network state, and git repository inspection.

## What Does Not Belong in Zejtron

- Any command that modifies system state (process killing, file writing,
  service management, package installation).
- Interactive shells, REPLs, or persistent daemons.
- Network monitoring, packet capture, or bandwidth measurement.
- Configuration management or provisioning.
- Log aggregation, parsing pipelines, or search tools.
- GUI components or web interfaces.

## Separate Projects

The following capabilities are valuable but should remain independent
projects rather than being absorbed into Zejtron:

- Process killing or signal management (e.g. pkill, kill).
- Package management or system updates.
- Container or VM orchestration.
- Performance profiling or benchmarking.
- Network packet analysis (e.g. tcpdump).
- Full-featured log management systems.
