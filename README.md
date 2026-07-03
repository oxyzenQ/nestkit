<p align="center">
  <img src="assets/zejtron-logo-new.png" alt="zejtron logo" width="260">
</p>

<h1 align="center">zejtron</h1>

<p align="center">
  <strong>A serious Linux introspection command center for operators, engineers, and incident work.</strong>
</p>

<p align="center">
  Trace commands, ports, process trees, file holders, service evidence, and host readiness from one disciplined terminal interface.
</p>

<p align="center">
  <a href="https://ko-fi.com/rezky">
    <img src="https://img.shields.io/badge/Ko--fi-support-7C3AED?style=flat-square&logo=kofi&logoColor=white&labelColor=111827" alt="Support on Ko-fi">
  </a>
</p>

## What Is Zejtron?

Zejtron is a Linux-first command center for terminal introspection.
It consolidates functionality from pidnest and Zenlixem into one binary with one release flow.

| Origin | Zejtron command |
| --- | --- |
| pidnest | `zejtron proc` |
| Zenlixem `whoholds` | `zejtron holds` |
| Zenlixem `lasttouch` | `zejtron touch` |
| Zenlixem `whyopen` | `zejtron why` |
| Zenlixem `doctor` | `zejtron net` |
| Zenlixem `envpath` | covered by `zejtron path` |

## Install

### AUR

```sh
paru -S zejtron-bin
yay -S zejtron-bin
```

### GitHub Release

```sh
TAG=v10.0.1
curl -LO "https://github.com/oxyzenQ/zejtron/releases/download/${TAG}/zejtron-bin-${TAG}-linux-amd64-gnu.tar.gz"
curl -LO "https://github.com/oxyzenQ/zejtron/releases/download/${TAG}/zejtron-bin-${TAG}-linux-amd64-gnu.tar.gz.sha512sum"
sha512sum --check "zejtron-bin-${TAG}-linux-amd64-gnu.tar.gz.sha512sum"
tar -xzf "zejtron-bin-${TAG}-linux-amd64-gnu.tar.gz"
install -Dm755 zejtron "$HOME/.local/bin/zejtron"
```

For a statically-linked musl build, replace `linux-amd64-gnu` with `linux-amd64-musl`.

### From Source

```sh
git clone https://github.com/oxyzenQ/zejtron
cd zejtron
cargo install --path .
```

## Command Overview

| Command | Purpose |
| --- | --- |
| `path` | Trace command origin |
| `recent` | Show recently modified files |
| `port` | Inspect ports and process owners |
| `proc` | Inspect process trees by user or UID |
| `holds` | Show processes holding a file, device, or port |
| `touch` | Inspect last modification evidence for a path |
| `why` | Explain visible evidence for a path or port |
| `env` | Snapshot and diff environment variables |
| `service` | Inspect systemd services |
| `shell` | Inspect current shell context |
| `net`   | Inspect network interfaces and routing |
| `git`   | Inspect git repository context |
| `doctor` | Check Zejtron system capability/readiness |

## Quick Examples

```sh
zejtron path sh
zejtron port --tcp --group
zejtron proc --me --depth 1
zejtron holds 53
sudo zejtron holds 53
zejtron touch /etc/resolv.conf
zejtron why /etc/resolv.conf
zejtron doctor
zejtron -V
zejtron --check-update
```

`-V` and `--version` print complete version, build, license, and source
metadata. `--check-update` checks the latest upstream GitHub release; the
`--check-updated` alias is accepted too.

## Compatibility

Zejtron is Linux-first and expects procfs at `/proc`. Most commands work without systemd: `path`, `recent`, `port`, `env`, `proc`, `holds`, `touch`, `why`, and `doctor`.

`service` requires systemd and `systemctl`. `touch` and `why` can use filesystem metadata on supported Linux systems, while journal evidence depends on `journalctl` and systemd journal availability. `holds`, `port`, and `proc` may show more complete details with `sudo` on hardened systems. `net` reads from sysfs and procfs without external commands. `git` requires the `git` binary and only invokes read-only subcommands.

## Safety

Zejtron is read-only by design. It does not kill processes, close ports, start or stop services, or modify files. `zejtron touch` inspects file evidence; it is not shell `touch` and does not create files or change timestamps.

## Commands

### `path`

Trace where a command comes from by scanning `PATH`, showing all matches, the active match, executable status, symlink targets, and Arch package ownership when `pacman` is available.

```sh
zejtron path sh
```

### `recent`

Show recently modified files under a path.

```sh
zejtron recent
zejtron recent . --limit 5
zejtron recent ~/src --since 1d
```

### `port`

Show listening TCP/UDP ports and process owners when discoverable.

```sh
zejtron port
zejtron port 3000
zejtron port --tcp --group
zejtron port --udp
zejtron port --all
zejtron port --no-pid
```

### `proc`

Show a clean process tree for a Linux user or UID.

```sh
zejtron proc --me
zejtron proc rezky
zejtron proc root --depth 1
zejtron proc rezky --find python
zejtron proc rezky --no-pid
zejtron proc rezky --live --interval 6
```

### `holds`

Show processes holding a file, device, or specific TCP/UDP port.

```sh
zejtron holds 3000
zejtron holds /etc/resolv.conf
zejtron holds /dev/nvme0n1
```

### `touch`

Inspect last modification evidence for a path. Metadata shows when a path changed, not who changed it; audit and journal evidence is best-effort.

```sh
zejtron touch /etc/resolv.conf
zejtron touch ./README.md
zejtron touch "/path/with spaces/file.txt"
```

### `why`

Explain visible evidence for a path or port without inferring intent.

```sh
zejtron why 53
zejtron why 3000
zejtron why /etc/resolv.conf
zejtron why ./README.md
```

### `env`

Inspect current environment variables, save named snapshots, and diff a saved snapshot against the current terminal environment.

```sh
zejtron env
zejtron env --keys
zejtron env --filter path
zejtron env save base
zejtron env diff base
zejtron env list
zejtron env delete base
```

### `service`

Inspect systemd service units in a read-only view.

```sh
zejtron service
zejtron service --user
zejtron service --failed
zejtron service --all
zejtron service --filter unbound
```

### `doctor`

Check Linux/procfs visibility, visible processes, `/proc/net` socket parsing, holder scan readiness, optional audit and journal evidence, systemctl/systemd availability, and build metadata.

```sh
zejtron doctor
```

### `shell`

Inspect current shell context in a read-only view. Reports the parent process, login shell, terminal, shell-related environment variables, and known config file paths for the detected shell.

```sh
zejtron shell
```

### `net`

Inspect network interfaces and routing context in a read-only view. Reports interfaces from sysfs with state, MTU, and MAC address. Shows default route from procfs and resolver file status.

```sh
zejtron net
```

### `git`

Inspect git repository context in a read-only view. Reports the repository root, branch, working tree status, latest commit, and remote URLs. Only invokes read-only git subcommands. Credentials embedded in remote URLs (e.g. PATs in HTTPS URLs) are redacted as `<redacted>` in output.

```sh
zejtron git
```

## Roadmap

See [docs/ROADMAP.md](docs/ROADMAP.md) for the project roadmap and design direction, or [docs/ROADMAP-current.md](docs/ROADMAP-current.md) for the current design document.

## Migration

`pidnest` and Zenlixem are superseded by Zejtron. See the origin table above for command mapping.

## Development

```sh
./scripts/build.sh
SKIP_CODESPELL=1 ./scripts/build.sh
./scripts/version-to.sh vX.Y.Z
```

## Intellectual Property & Trademark

**zejtron** is the exclusive intellectual property of
**rezky_nightky (oxyzenQ)**.

- Source code: licensed under **GPL-3.0-only** (see [LICENSE](LICENSE)).
- Name, logo, and branding ("the Marks"): governed by
  [TRADEMARK.md](TRADEMARK.md). The Marks are NOT covered by the GPL and
  are reserved by the owner.
- This project is **NOT for sale**. Unauthorized rebranding, relicensing,
  or source-code theft is strictly prohibited.

For trademark licensing or written permission, contact
**rezky_nightky (oxyzenQ)** — https://github.com/oxyzenQ.

---

© 2026 rezky_nightky (oxyzenQ). All rights reserved.
