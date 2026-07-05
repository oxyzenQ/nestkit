# Release Workflow

This project uses GitHub Actions for CI, GitHub Releases, and optional AUR sync for `zejtron-bin`.

## CI

CI runs on pushes and pull requests targeting `main`.

It installs stable Rust with `rustfmt` and `clippy`, installs `codespell`, restores the Rust cache, and runs:

```sh
./scripts/build.sh
```

## Maintenance deps weekly

The `Maintenance deps weekly` workflow runs every Monday at 07:00 WIB (00:00 UTC) and can also be run manually. It checks out the default branch, runs `cargo update`, executes `./scripts/build.sh`, and commits the refreshed `Cargo.lock` directly back to the default branch only after validation passes.

Maintenance workflow commits use:

- `github-actions[bot]`
- `41898282+github-actions[bot]@users.noreply.github.com`

## Release

Release builds run for tags matching `v*`. The workflow builds:

- `x86_64-unknown-linux-gnu`
- `x86_64-unknown-linux-musl`

Release archives use a flat layout:

- `zejtron`
- `README.md`
- `LICENSE`

Example release asset flow:

```sh
TAG=v10.0.2
cargo build --release --locked --target x86_64-unknown-linux-gnu
```

The release workflow uploads `zejtron-bin-${TAG}-linux-amd64-gnu.tar.gz`, `zejtron-bin-${TAG}-linux-amd64-musl.tar.gz`, and matching `.sha512sum` files.

## AUR Sync

The release workflow dispatches AUR sync only for normal semver tags (e.g. `vX.Y.Z`).

AUR sync can also be run manually. Manual sync checks out `main`, validates that `aur/zejtron-bin/PKGBUILD` and `aur/zejtron-bin/.SRCINFO` have matching `pkgver` and `pkgdesc` values, copies both files as committed, commits as `rezky_nightky <with dot rezky at gmail dot com>`, and pushes to `ssh://aur@aur.archlinux.org/zejtron-bin.git`. Release-triggered sync also verifies that the release tag version matches the committed AUR `pkgver`.

Required repository secret:

- `AUR_SSH_PRIVATE_KEY`

Configure it in GitHub at:

`Settings -> Secrets and variables -> Actions -> Repository secrets -> AUR_SSH_PRIVATE_KEY`

The AUR workflow does not set `environment:`, so environment secrets are not used.

## AUR Troubleshooting

If the release workflow `aur-sync` job succeeds quickly, that only means the dispatch request was sent. Open the Actions list and look for a separate run named `zejtron - AUR Sync`.

If `zejtron - AUR Sync` does not trigger, check:

- `.github/workflows/aur.yml` exists on the default branch, currently `main`
- the release workflow dispatches `event_type: aur-sync`
- the AUR workflow listens to `repository_dispatch` with `types: [aur-sync]`

If `zejtron - AUR Sync` triggers but authentication fails, check that `AUR_SSH_PRIVATE_KEY` is configured as a repository secret, not only as an environment secret.

The AUR workflow runs on `ubuntu-latest`, validates committed package metadata, pins the AUR Ed25519 host key, and clones the AUR repository before copying both `PKGBUILD` and `.SRCINFO`. If clone fails because of authentication or host-key verification, the job fails clearly. If the AUR repository is empty or not initialized yet, the workflow bootstraps a local repository and pushes `master`.

## Version Bump Flow

```sh
./scripts/version-to.sh v10.0.2
./scripts/build.sh
```

## Release Command Flow

```sh
./scripts/version-to.sh v10.0.2
./scripts/build.sh
git add .
git commit -m "chore: prepare v10.0.2 release"
git push origin main
git tag -a v10.0.2 -m "v10.0.2"
git push origin v10.0.2
```
