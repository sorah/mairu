---
name: releng
description: Release engineering for mairu. Use whenever the user asks to cut, prepare, tag, or ship a mairu release, bump the version, write the CHANGELOG for a release, open a "releng X.Y.Z" PR, or update the Homebrew formula (homebrew-sorah) or AUR packages (mairu, mairu-bin) for a new mairu version, even if they only say "release it" or "ship 0.x".
---

# mairu release engineering

Run steps in order and stop at each gate marked (user). Ask before every commit, push, tag, or PR; the user merges PRs and publishes the GitHub release. Never use `git -C`; `cd` into the repo instead. Put temp files in `tmp/` under the repo root.

## 1. Decide the version

1. `git fetch origin`, then review `git log vPREV..origin/main` and the merged PRs (`gh pr list --state merged`).
2. Version is 0.x: if any new feature landed since the last release, bump minor (0.12.0 -> 0.13.0); only fixes/chores bump patch.
3. (user) Confirm the version.

## 2. Releng PR

1. Branch `releng/X.Y.Z` from an up-to-date `main`.
2. Bump `version` in `Cargo.toml`, run `cargo build` once to update `Cargo.lock`.
3. Update `CHANGELOG.md`:
   - Keep `## [not yet released]` at the top; insert `## X.Y.Z` directly beneath it and move any unreleased entries into it.
   - Sections, only those that apply: `### Enhancements`, `### Bug fixes`, `### Miscellaneous`.
   - End each entry with PR links, e.g. `[#59](https://github.com/sorah/mairu/pull/59)`. Follow the wording style of previous entries (optional `subcommand:` prefix).
   - Be precise about affected builds: `--features rustls` is used for the Linux musl binaries and the .debs on GitHub Releases; macOS binaries use the default native-tls.
4. Commit `Cargo.toml`, `Cargo.lock`, `CHANGELOG.md` as `releng X.Y.Z`, push, then `gh pr create --title 'releng X.Y.Z'`.
5. Wait for PR CI to pass.
6. (user) Ask the user to merge the PR; merging is blocked for Claude.

## 3. Tag

On updated `main` at the merge commit:

```
git tag --sign vX.Y.Z -m vX.Y.Z
git tag -v vX.Y.Z
git push origin vX.Y.Z
```

If signing fails with `Inappropriate ioctl for device`, ask the user to unlock their key; never skip signing.

## 4. Release workflow

The tag triggers `.github/workflows/release.yml`: test -> create-release (DRAFT, checks the tag matches `Cargo.toml`) -> upload-binaries (linux musl x86_64/aarch64 with rustls, x86_64/aarch64 apple-darwin; each archive holds `mairu` and its attestation `mairu.sigstore.json`) and upload-debs (attested too) -> publish-crate (crates.io trusted publishing, runs last).

Watch it (`gh run watch`). (user) The user publishes the draft release.

The universal apple-darwin archive is no longer published (since the release after 0.12.0). Until done once, check that the Homebrew tap and the aqua registry (`pkgs/sorah/mairu` in aquaproj/aqua-registry) select `mairu-{x86_64,aarch64}-apple-darwin.tar.gz` instead of `mairu-universal-apple-darwin.tar.gz`, and propose updates there if not.

## 5. Homebrew (`~/git/github.com/sorah/homebrew-sorah`)

1. Branch `mairu/X.Y.Z` from up-to-date `main`.
2. In `Formula/mairu.rb` set `url` to `https://github.com/sorah/mairu/archive/refs/tags/vX.Y.Z.tar.gz` and `sha256` to that tarball's sum (download into `tmp/`, `sha256sum`).
3. Commit `mairu/X.Y.Z`, push, open a PR titled `mairu/X.Y.Z`.
4. Wait for test-bot (macos-15, ubuntu-24.04). `brew style` requires a `test do` block.
5. Add label `pr-pull` (`gh pr edit N --add-label pr-pull`). The `brew pr-pull` workflow (pull_request_target, runs from `main`) builds bottles, pushes "mairu: update X.Y.Z bottle." and closes the PR. Any CI fix for that workflow must land on `main` first.

## 6. AUR

Each of `~/git/github.com/sorah/arch.sorah.jp/aur-sorah/PKGBUILDs/mairu` and `.../mairu-bin` is its own git repo (branch `master`, remote `aur@aur.archlinux.org`). For each:

1. Set `pkgver=X.Y.Z`, `pkgrel=1`.
2. `updpkgsums`, then `makepkg --printsrcinfo > .SRCINFO`.
3. Commit as `X.Y.Z` and push.

`mairu` uses the tag source tarball, so it can be pushed once the tag exists.

`mairu-bin` downloads release assets, which 404 while the release is a draft. Before `updpkgsums`, prefetch them for each arch (x86_64, aarch64):

```
gh release download vX.Y.Z -R sorah/mairu -p 'mairu-<arch>-unknown-linux-musl.tar.gz' -O mairu-X.Y.Z-<arch>.tar.gz
```

Optionally verify with `makepkg -fc`. Push only after the release is published, after re-checking that the public download's sha256 matches.
