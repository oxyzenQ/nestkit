#!/usr/bin/env bash
# Copyright (C) 2026 rezky_nightky
# SPDX-License-Identifier: GPL-3.0-only

set -Eeuo pipefail

error() {
  echo "error: $*" >&2
  exit 1
}

if [[ $# -ne 1 ]]; then
  error "usage: ./scripts/version-to.sh vX.Y.Z"
fi

input="$1"
if [[ "$input" =~ ^v?([0-9]+)\.([0-9]+)\.([0-9]+)$ ]]; then
  VERSION="${BASH_REMATCH[1]}.${BASH_REMATCH[2]}.${BASH_REMATCH[3]}"
  TAG="v${VERSION}"
else
  error "version must be normal semver: vX.Y.Z or X.Y.Z"
fi

for command in git cargo makepkg; do
  if ! command -v "$command" >/dev/null 2>&1; then
    if [[ "$command" == "makepkg" ]]; then
      error "makepkg is required to regenerate .SRCINFO"
    fi
    error "required command not found: $command"
  fi
done

repo_root="$(git rev-parse --show-toplevel)"
cd "$repo_root"

[[ -f Cargo.toml ]] || error "Cargo.toml not found"
[[ -f Cargo.lock ]] || error "Cargo.lock not found"
[[ -f aur/zejtron-bin/PKGBUILD ]] || error "aur/zejtron-bin/PKGBUILD not found"
[[ -f README.md ]] || error "README.md not found"
[[ -f docs/workflow/about-ci.md ]] || error "docs/workflow/about-ci.md not found"

echo "Updating zejtron to ${TAG}"

sed -i -E 's/^version = "[0-9]+\.[0-9]+\.[0-9]+"/version = "'"${VERSION}"'"/' Cargo.toml
cargo update -p zejtron

sed -i -E 's/^pkgver=.*/pkgver='"${VERSION}"'/' aur/zejtron-bin/PKGBUILD
sed -i -E 's/^pkgrel=.*/pkgrel=1/' aur/zejtron-bin/PKGBUILD

(
  cd aur/zejtron-bin
  makepkg --printsrcinfo > .SRCINFO
)

sed -i -E 's/^TAG=v[0-9]+\.[0-9]+\.[0-9]+/TAG='"${TAG}"'/' README.md docs/workflow/about-ci.md
sed -i -E 's#(zejtron-bin-)v[0-9]+\.[0-9]+\.[0-9]+(-linux-)#\1'"${TAG}"'\2#g' README.md docs/workflow/about-ci.md
sed -i -E 's#(/download/)v[0-9]+\.[0-9]+\.[0-9]+/#\1'"${TAG}"'/#g' README.md docs/workflow/about-ci.md
sed -i -E 's#(git tag -a )v[0-9]+\.[0-9]+\.[0-9]+#\1'"${TAG}"'#g' docs/workflow/about-ci.md
sed -i -E 's#(git tag -a v[0-9]+\.[0-9]+\.[0-9]+ -m ")v[0-9]+\.[0-9]+\.[0-9]+(")#\1'"${TAG}"'\2#g' docs/workflow/about-ci.md
sed -i -E 's#(git push origin )v[0-9]+\.[0-9]+\.[0-9]+#\1'"${TAG}"'#g' docs/workflow/about-ci.md
sed -i -E 's#(git commit -m "chore: prepare )v[0-9]+\.[0-9]+\.[0-9]+( release")#\1'"${TAG}"'\2#g' docs/workflow/about-ci.md
sed -i -E 's#(./version-to\.sh )v[0-9]+\.[0-9]+\.[0-9]+#\1'"${TAG}"'#g' README.md docs/workflow/about-ci.md
sed -i -E 's#(img\.shields\.io/badge/version-)v[0-9]+\.[0-9]+\.[0-9]+-#\1'"${TAG}"'-#g' README.md
sed -i -E 's#(alt="Version )v[0-9]+\.[0-9]+\.[0-9]+(")#\1'"${TAG}"'\2#g' README.md

grep -q '^version = "'"${VERSION}"'"$' Cargo.toml || error "Cargo.toml version was not updated"
grep -A3 'name = "zejtron"' Cargo.lock | grep -q 'version = "'"${VERSION}"'"' || error "Cargo.lock zejtron version was not updated"
grep -q '^pkgver='"${VERSION}"'$' aur/zejtron-bin/PKGBUILD || error "PKGBUILD pkgver was not updated"
grep -q 'pkgver = '"${VERSION}" aur/zejtron-bin/.SRCINFO || error ".SRCINFO pkgver was not updated"
grep -q "TAG=${TAG}" README.md || error "README.md release examples do not mention TAG=${TAG}"
grep -q "version-${TAG}-" README.md || error "README.md version badge does not mention ${TAG}"
grep -q "TAG=${TAG}" docs/workflow/about-ci.md || error "docs/workflow/about-ci.md release examples do not mention TAG=${TAG}"

echo "VERSION=${VERSION}"
echo "TAG=${TAG}"
echo "Updated Cargo.toml, Cargo.lock, AUR metadata, README.md, and docs/workflow/about-ci.md"
