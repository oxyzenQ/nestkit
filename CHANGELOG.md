# Changelog

All notable changes to zejtron.

## [v11.0.0] — 2026-07-09

### Masterclass Depth Upgrades — "dragon hunts the meal"

Three waves of depth upgrades across all 13 subcommands, turning zejtron from a
shallow introspection tool into an investigator-grade command center.

### Foundation
- New `process.rs` shared helper — single source of truth for process context
  (cmdline, ppid, state, memory, threads, cgroup, netns/pidns)
- `extract_systemd_unit()` + `read_systemd_unit()` — cgroup v2 unit extraction
- `parent_chain()` — walks from any PID to PID 1 with cycle guard

### env — investigate ANY process env
- `--pid <PID>` reads `/proc/<PID>/environ`
- `--mask-secrets` redacts AWS/GitHub/JWT/PEM patterns and key names containing
  TOKEN/SECRET/PASSWORD/AUTH/API_KEY

### net — full interface picture
- IPv4 + IPv6 addresses per interface
- Link stats: rx/tx bytes, packets, errors, drops
- Interface flags decoded: UP, BROADCAST, LOOPBACK, PROMISC, MULTICAST
- ARP neighbor table
- Full routing table with gateway + metric
- `/etc/resolv.conf` parsed (nameservers, search, options)

### touch — full forensic metadata
- type, size, owner (uid:gid→name), perms (octal), inode, dev
- mtime + atime + **ctime** (inode-change time)
- Symlink detection with target

### git — full repo snapshot
- Full HEAD hash, detached HEAD detection
- Upstream tracking + ahead/behind counts (↑N ↓N)
- Full commit info: hash, author, email, date, subject
- Stash count, last tag (describe)

### doctor — context-aware readiness
- Kernel version + distro detection
- Container detection (Docker/Podman/LXC/Kubernetes)
- Non-zero exit code on FAIL

### port — full connection picture
- Remote endpoint parsed and shown: `ESTABLISHED <- 5.6.7.8:54404`
- FD number per owner: `nginx pid=1234 fd=12`
- State breakdown in summary: `states: 5 LISTEN · 12 ESTABLISHED`

### proc — full process context
- `--verbose` flag: cmdline + RSS memory + thread count
- State char (R/S/D/Z/T) always shown — zombie detection

### holds — fix dead-evidence bug + FD access mode
- BUG FIX: port holder FD evidence was computed but never rendered
- FD access mode (r/w/rw) from `/proc/<pid>/fdinfo/<fd>` flags
- mmap permissions (r-xp) from `/proc/<pid>/maps` column 2

### service — single-unit detail mode
- `zejtron service <unit>` runs `systemctl show` and renders 15 fields:
  MainPID, ExecStart, FragmentPath, NRestarts, MemoryCurrent, CPUUsageNSec,
  TasksCurrent, Wants/Requires/WantedBy

### why — combinatorial cross-referencing
- Always runs BOTH holds AND touch (was: holds→skip touch)
- Reads systemd unit via cgroup for each holder
- Synthesis one-liner combining all evidence sources
- Metadata section with type/size/perms/modified/changed

### path — multi-backend package owner + PATH audit
- Multi-backend: pacman → dpkg → rpm → apk (was: Arch-only)
- `--verbose`: file metadata (size, owner, perms, mtime)
- PATH audit: flags world-writable, missing, non-root-owned dirs

### recent — full file metadata
- ctime (inode-change time) alongside mtime
- File size, owner, perms shown per entry

### shell — ancestor chain to PID 1
- Full ancestor chain from current process to PID 1
- Each entry shows pid, ppid, name, cmdline

### Security
- `pathguard.rs` — strict allowlist for env state I/O
  - Blocks XDG_DATA_HOME overrides to system paths (/etc, /usr, /var, etc.)
  - Blocks credential paths (~/.ssh, ~/.gnupg) even via XDG override
  - Default-deny policy, not blacklist

### Dependency
- `regex-lite` 0.1 — for env secret-pattern matching (~30KB binary impact)

### Verified
- `./scripts/build.sh --check-all` PASS (fmt + clippy + build + 267 tests)
- 18 end-to-end manual tests covering all 13 subcommands + pathguard

## [v10.0.0] — 2026-07-01

### Architecture Alignment

### Changed — amd64 Only + Static musl Binary
- Release binaries: amd64 Linux only (gnu + musl) per project policy
- Removed aarch64 cross-compile target
- Added x86_64-unknown-linux-musl (static binary, zero dynamic deps)
- Both archives served on GitHub Release page automatically

### Verified
- 240 tests PASS
- clippy: 0 warnings
- Binary size: 1.5 MB (3 deps: chrono, clap, ctrlc)
- All CI checks PASS (fmt, clippy, test, codespell, yamllint, actionlint)

## [v5.0.2] — Previous release

- Unified Linux introspection toolkit
- Paths, ports, processes, files, services, diagnostics
- 240 tests, 3 dependencies
