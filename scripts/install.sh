#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2026 rezky_nightky (oxyzenQ)
#
# Install script for zejtron.
# Supports --system (system-wide) and --user (default, ~/.local/bin).
# Run WITHOUT sudo: the script escalates via sudo ONLY for the --system install step.

set -euo pipefail

zejtron="zejtron"
REPO_URL="https://github.com/oxyzenQ/zejtron"

usage() {
    cat <<EOF
Usage: $0 [--system|--user]

  --system   Install system-wide to /usr/bin/${zejtron}
             (script invokes sudo for the install step only)
  --user     Install to ~/.local/bin/${zejtron}  (default, no sudo)

The build step (cargo build --release --locked) ALWAYS runs as the current user.
EOF
}

MODE="--user"
while [[ $# -gt 0 ]]; do
    case "$1" in
        --system) MODE="--system"; shift ;;
        --user)   MODE="--user";   shift ;;
        -h|--help) usage; exit 0 ;;
        *) echo "error: unknown argument: $1" >&2; usage; exit 2 ;;
    esac
done

if [[ ! -f Cargo.toml ]]; then
    echo "error: Cargo.toml not found. Run this script from the repo root." >&2
    exit 1
fi

echo ">> [1/3] Building ${zejtron} (release, locked)"
cargo build --release --locked

BINARY="target/release/${zejtron}"
if [[ ! -f "${BINARY}" ]]; then
    echo "error: build produced no binary at ${BINARY}" >&2
    exit 1
fi

echo ">> [2/3] Installing ${zejtron} (${MODE})"

case "${MODE}" in
    --system)
        # Invoked WITHOUT sudo; escalate only for the install step.
        sudo install -Dm755 "${BINARY}" "/usr/bin/${zejtron}"
        echo "   installed: /usr/bin/${zejtron}"
        ;;
    --user)
        user_bin="${HOME}/.local/bin"
        mkdir -p "${user_bin}"
        install -Dm755 "${BINARY}" "${user_bin}/${zejtron}"
        echo "   installed: ${user_bin}/${zejtron}"
        ;;
esac

echo ">> [3/3] Done."
echo
echo "Next steps:"
case "${MODE}" in
    --system) echo "  - Run: ${zejtron} --help" ;;
    --user)   echo "  - Ensure ~/.local/bin is on your PATH" ;;
esac
echo "  - Docs: ${REPO_URL}#readme"
