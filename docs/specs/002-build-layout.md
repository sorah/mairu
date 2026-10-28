# 002-build-layout

## Summary

Before new code lands, this step settles how mairu is built, so that later steps add code without moving it. Release builds use link-time optimization, a single codegen unit and full symbol stripping. Within the one `mairu` package, the heavy dependencies and the client and agent modules move behind a default `cli` feature. That lets 006 build a small second binary, the platform helper, from the same crate, with the compiler keeping client code out of it.

It also defines how release archives ship helpers next to the binary, and how mairu finds them. CI reports the size of the release binaries, so growth is noticed when it happens. macOS releases become one binary per architecture, x86_64 and arm64, and the universal binary is dropped. mairu stays a single crate on crates.io, and every release still ships all artifacts from one tag in one workflow run.

## Motivation

Release archives will carry helpers next to the binary: a signed helper app bundle in official macOS archives (019), and the Windows Hello helper for WSL2 in Linux archives (016). Whatever a helper links is carried in every download and every installed copy, so its size has to be controlled before it exists.

Measured on Linux x86_64, release builds, on 2026-10-29 (mairu 0.12.0, rustc 1.96.0):

| Build | Size |
|---|---|
| mairu, current release profile | 31.0 MB |
| mairu, stripped | 23.2 MB |
| mairu, LTO (`fat`) + `codegen-units = 1` + strip | 18.2 MB |
| Helper stand-in: tokio current-thread, tonic server for the `mairu.platform` protocol, prost, tracing | 4.2 MB |
| Same helper, LTO + strip | 2.5 MB |
| `cedar-policy` 4.14 alone (`default-features = false`), LTO + strip | 6.3 MB |

For comparison, the v0.12.0 downloads are 9.4 MB for `aarch64-apple-darwin` and 19.1 MB for `universal-apple-darwin`, gzipped.

Three things follow:

- **The release profile is the biggest lever.** LTO and stripping cut mairu by about 40% with no change in behavior. Release builds take about twice as long (88 s to 176 s in this measurement).
- **The helper must not link client and agent code.** A helper built from the same package with every dependency would carry the AWS SDK, the HTTP client and the OAuth code, and only dead-code elimination would keep them out. That breaks easily: `crate::Error` has variants wrapping `oauth2`, `reqwest` and AWS SDK errors, so any helper code returning it pulls in their formatting code. Gating that code behind a feature makes the compiler enforce the split.
- **A universal binary doubles everything.** A universal archive would carry both architectures of mairu and of the helper bundle, while Apple is phasing out Intel Macs. Per-architecture archives carry one of each.

The authorization work adds the Cedar engine (007), up to about 6 MB on top of the 18 MB. It is the policy engine, so it cannot be optional. The size reports keep that and later growth visible.

## Explanation

### Release profile

```toml
[profile.release]
lto = "fat"
codegen-units = 1
strip = true
```

- Applies to every release artifact. The `deb` profile inherits it.
- `panic` stays `unwind`. With `abort`, one panicking task would take down the whole agent, while tokio contains a panic within its task.
- Debug builds are unchanged.

### Cargo features

```toml
[features]
default = ["cli", "native-tls"]
cli = ["dep:aws-config", "dep:aws-sdk-sso", "dep:aws-sdk-sts", "dep:aws-sdk-ssooidc", "dep:axum", "dep:clap", "dep:oauth2", "dep:reqwest", …]
native-tls = ["cli", "reqwest/default-tls"]
rustls = ["cli", "reqwest/rustls-tls-native-roots"]

[[bin]]
name = "mairu"
path = "src/main.rs"
required-features = ["cli"]
```

- `cli` is the whole client and agent: everything `mairu` does today.
- `native-tls` and `rustls` imply `cli`. Existing build commands keep producing the full CLI, including the packagers' `--no-default-features --features rustls` and the deb metadata.
- `cargo install mairu` is unchanged.
- Without `cli`, only the core library builds. At this step that is the protocol code and a few small utilities. Later steps add their modules to the core only when the platform helper needs them. 006 adds the `platform-helper` feature and the helper binary on top of the core.

| Command | Result |
|---|---|
| `cargo build` | full CLI, native TLS |
| `cargo build --no-default-features --features rustls` | full CLI, rustls (musl releases, deb) |
| `cargo check --lib --no-default-features` | core library only; fails if core code reaches client or agent code |

### Release artifacts

```text
mairu-x86_64-unknown-linux-musl.tar.gz      unchanged
mairu-aarch64-unknown-linux-musl.tar.gz     unchanged
mairu-aarch64-apple-darwin.tar.gz           unchanged
mairu-x86_64-apple-darwin.tar.gz            new
mairu-universal-apple-darwin.tar.gz         no longer published
mairu_<version>-1_{amd64,arm64}.deb         unchanged
```

Everything is still built and uploaded by one workflow run from one `v<version>` tag, and the crate is published last, as today.

### Shipped helpers

Two helpers live outside the `mairu` binary: the macOS helper bundle (019) and, for WSL2, the Windows Hello helper (016). Release archives ship them as files next to `mairu`, and mairu finds them relative to its own canonical path. Nothing is embedded in the binary, and release builds write nothing out at run time.

```text
mairu-<target>.tar.gz
├── mairu
├── Mairu Helper.app/            macOS targets (019)
└── mairu-windows-hello.exe      Linux targets, for the matching Windows architecture (016)
```

Lookup, for a helper file named `F`:

1. `<dir>/F`, where `<dir>` is the directory of `canonicalize(current_exe())`. On macOS `current_exe()` returns the path mairu was started through, which may be a symlink from Homebrew's `bin` or another directory on `PATH`, so it is canonicalized first.
2. `<dir>/../lib/mairu/F`, where distribution packages install helpers.
3. Otherwise the helper is missing, and the fallback of its spec applies.

| Installed by | Helpers next to `mairu` |
|---|---|
| mise (github and aqua backends), aqua | yes, in a directory per version |
| ubi with `--extract-all` | yes, in its single `--in` directory. Files are overwritten in place on upgrade, so stop the agent with `mairu kill-agent` first. |
| ubi without `--extract-all` | no, only the binary |
| Homebrew cask with `binary "mairu"` | yes, in the Caskroom directory of the version. The `app` stanza is not used, because it moves a bundle to `/Applications`. |
| deb, AUR `mairu-bin` | in `/usr/lib/mairu/` |
| `mairu harden` | copies the helpers found next to itself next to the hardened copy (005) |
| `cargo install`, AUR `mairu`, Homebrew `mairu-src`, other builds from source | none; the fallbacks apply |

- **Fallbacks.** A macOS build without a shipped bundle assembles one around its own binary, under `~/Library/Application Support/mairu` (019). On WSL2, the helper path comes from `config.json`, pointing at the release's `mairu-windows-hello-<target>.zip` (016).
- **Checked before use.** An installer's directory is often writable by the user's processes, so a helper may be swapped at any time. Each helper's consumer checks it right before use, by the code signature of the running child or by a pinned SHA-256, and relies on nothing beyond what that check proves.
- **One version per directory.** A helper is used only from beside the binary that found it, so versions installed side by side never mix.

### Size reports

Every pull request reports the release-profile size of `mairu` per target in the CI job summary. From 006 on, the report also covers `mairu-platform-helper`. A generous ceiling per binary fails the job when it is exceeded. The pull request that adds a large dependency raises the ceiling on purpose, so the growth is visible in review.

```text
| target                      | binary | size    | ceiling |
|-----------------------------|--------|---------|---------|
| x86_64-unknown-linux-musl   | mairu  | 18.4 MB | 30 MB   |
| aarch64-apple-darwin        | mairu  | 16.9 MB | 30 MB   |
```

The figures above are illustrative.

## Drawbacks

- Release builds take about twice as long. CI's size job pays the same cost on every pull request.
- Release binaries carry no symbol table, so a panic backtrace from a release build shows addresses instead of function names.
- Every module and dependency has to sit on the right side of the `cli` gate. The `--no-default-features` check catches mistakes in core code, but not a dependency left required when only `cli` uses it; the size report shows those.
- Users of the universal macOS download have to switch to their architecture's file. Anything that selects the universal asset by name breaks until updated.

## Considered Alternatives

- **A separate workspace crate for the platform side** (`mairu-platform`, holding the protocol, traits, helper server and backends, with the helper binary in it). The compiler would keep client code out structurally. Rejected because every release would have to publish two crates in lockstep. That is exactly the release complexity this project avoids: GitHub Releases do not work well with several release pipelines, so everything must ship at once from one tag, with strict version requirements between parts. The research behind this is under Prior Art.
- **An unpublished helper crate** (`publish = false`) depending on `mairu` with `default-features = false`. It never reaches crates.io, but still needs the same feature gating inside `mairu`, and adds a workspace member for no further gain.
- **LTO dead-code elimination alone,** with the helper as an extra binary of the full package. No enforcement, and shared types such as `crate::Error` pull client code in silently.
- **Feature flags that switch off security features** (the Cedar engine, gate 2, presence methods) for smaller builds. Rejected: official builds need every feature, so the official binary would not shrink, and builds where a hardened agent lacks its checks would become possible.
- **`panic = "abort"`.** Smaller and faster, but one panicking task would end the agent.
- **`opt-level = "s"` or `"z"`.** Not measured. LTO and stripping already give about 40%; the size reports can show whether more is worth it.
- **Self-extraction:** embedding the helpers in the binary and writing them out at run time. Rejected (decided 2026-10-29) in favor of shipping them next to the binary:
  - It adds every helper to every binary (about 2.5 MB for the macOS helper), a build-order dependency in the release workflow, and write-out code with its own atomicity and cleanup rules.
  - mise, aqua, ubi with `--extract-all`, Homebrew casks and distribution packages all keep files next to the binary. Builds from source would embed nothing anyway, so they need the fallbacks either way.
  - Only ubi's default mode drops sibling files; ubi users install with `--extract-all`.
  - Tools that ship an app bundle in their tarball (tart, Teleport, terminal-notifier) are prior art for archives carrying bundles.
- **Keeping the universal macOS binary.** It would carry both architectures and, from 019, a helper bundle per architecture slice, while Intel Macs are being phased out.

## Prior Art

Extra binaries from one package, behind a feature:

- sccache ships `sccache-dist` as `[[bin]]` with `required-features = ["dist-server"]` ([Cargo.toml](https://github.com/mozilla/sccache/blob/main/Cargo.toml)).
- rage ships `rage-mount` with `required-features = ["mount"]` ([rage/Cargo.toml](https://github.com/str4d/rage/blob/main/rage/Cargo.toml)).

What multi-crate Rust CLIs do to release together:

| Project | How it releases | The cost |
|---|---|---|
| zellij | `cargo x publish` bumps, tags `vX.Y.Z`, `git push --atomic`, then publishes each crate in a loop ([xtask/src/pipelines.rs](https://github.com/zellij-org/zellij/blob/main/xtask/src/pipelines.rs)) | A failed crate stops at an interactive retry/abort/ignore prompt. A dry run needs a private registry (ktra) set up locally ([docs/RELEASE.md](https://github.com/zellij-org/zellij/blob/main/docs/RELEASE.md)). |
| atuin | dist builds the GitHub release from one `v*` tag; a maintainer publishes 13 crates from a hand-ordered list in [scripts/release.sh](https://github.com/atuinsh/atuin/blob/main/scripts/release.sh) | Publishes with `--no-verify`, because just-published crates are not indexed yet, and skips "already uploaded" so a broken run can be repeated |
| nushell | A tag starts the release workflow; crates are published by `nu_release.nu` in an order computed by `nu_deps.nu` ([nu_scripts make_release](https://git.rgbcu.be/RGBCube/nu_scripts/src/branch/main/make_release)) | A failed run is resumed by editing the script's starting point; new crates must join the publishing owner group |
| jj | One `[workspace.package] version`; `jj-lib` pinned at that version in `[workspace.dependencies]` ([Cargo.toml](https://github.com/jj-vcs/jj/blob/main/Cargo.toml)); the release workflow builds binaries only | crates.io publishing sits outside the workflow; the pin is a caret, not exact |

Tools:

- Cargo 1.90 stabilized `cargo publish --workspace`. It publishes in dependency order and verifies the whole set before uploading, but the [release notes](https://blog.rust-lang.org/2025/09/18/Rust-1.90.0/) warn that a failure can still leave a partly published workspace.
- dist groups packages of one version under one `vX.Y.Z` tag and one GitHub release ([concepts](https://axodotdev.github.io/cargo-dist/book/reference/concepts.html)).
- release-plz needs tags turned off for all crates but one, or the second crate's tag collides after the first crate is already live ([write-up](https://blog-570662.gitlab.io/three-traps-release-plz-workspace/)).
- Installers and multi-file archives, for shipping helpers next to the binary: ubi's [installer](https://github.com/houseabsolute/ubi/blob/88c2ce36af284e675921dc00f9aafcbd49129883/ubi/src/installer.rs#L157) and [`--extract-all`](https://github.com/houseabsolute/ubi/blob/88c2ce36af284e675921dc00f9aafcbd49129883/README.md#L91-L97), mise's [github backend](https://github.com/jdx/mise/blob/e0f96486baa98ae4a5fdab71cecca432af9fff82/src/backend/github.rs#L2184-L2257), aqua's [unarchiver](https://github.com/aquaproj/aqua/blob/b65c14634ef70a848471a1e5dd1e43613138578e/pkg/unarchive/archives.go#L61-L170), cargo-binstall's [bin handling](https://github.com/cargo-bins/cargo-binstall/blob/81df5c23b0dc775b009efdfc9895c5965b7a4e40/crates/binstalk-bins/src/lib.rs#L263-L273), and [tart](https://github.com/openai/tart/blob/c8bfa928b7dd462a73d1ff090efa4a39032c18d7/.goreleaser.yml#L36-L48) shipping `tart.app` in its tarball.
- On crates.io, a new crate's first version must be published with an API token before trusted publishing can be configured for it ([crates.io development update](https://blog.rust-lang.org/2025/07/11/crates-io-development-update-2025-07)).

## Security and Privacy Considerations

- A helper built without `cli` contains no client or agent code. On macOS it is the process that holds platform entitlements (019), so this keeps that process's code small.
- The build settings change no runtime behavior.

## Mission Scope

### Out of scope

- The helper binary itself and the `platform-helper` feature (006)
- The helpers themselves: the macOS helper bundle (019) and the Windows Hello helper (016). This step defines how release archives ship them and how mairu finds them.
- `opt-level` tuning
- Updates in other repositories that select release assets by name: the Homebrew tap, the aqua registry, and installers such as ubi or mise. They are follow-ups once the first per-architecture release is out.

### Expected Outcomes

- The release `mairu` on Linux x86_64 is about 18 MB instead of 31 MB.
- `cargo check --lib --no-default-features` passes, and CI keeps it passing.
- Every pull request shows the release binary sizes; a binary over its ceiling fails CI.
- Releases publish `x86_64-apple-darwin` and `aarch64-apple-darwin` binaries and no universal binary, from one tag in one workflow run, with one crate on crates.io.
- Existing build commands, including packagers' `--no-default-features --features rustls`, still produce the full CLI.
- `crate::helpers::locate` finds helpers next to the canonical executable or in `../lib/mairu/`, with its tests passing.

## Implementation Plan

Stack layer: `hardening/build-layout`.

**`Cargo.toml`**

- Add the release profile above.
- Add `cli` and make `native-tls` and `rustls` imply it.
- A dependency becomes `optional = true` under `cli` unless core code needs it. Optional at this step: `aws-config`, `aws-sdk-sso`, `aws-sdk-sts`, `aws-sdk-ssooidc`, `aws-smithy-runtime-api`, `aws-smithy-types`, `axum`, `headers`, `hyper`, `hyper-util`, `oauth2`, `reqwest`, `clap`, `daemonize`, `tracing-appender`, `serde_with`, `async-recursion`, `indoc`, `process_path`.
- The protocol and small utilities stay required: `tokio`, `tokio-stream`, `tonic`, `tonic-prost`, `prost`, `prost-types`, `tracing`, `libc`, `nix`, `thiserror`, `serde`, `serde_json`, and similar.
- `tokio` keeps only the features the core needs (`rt`, `net`, `macros`, `io-util`, `sync`, `time`, `signal`), and `cli` adds `tokio/full`. `tracing-subscriber`'s `json`, `local-time` and `time` features move under `cli` the same way.
- `[[bin]] mairu` gets `required-features = ["cli"]`.

**`src/lib.rs`**

- Core modules stay unconditional: `error`, `os`, `ppid`, `proto`.
- Every other module gets `#[cfg(feature = "cli")]`.
- In `src/error.rs`, the `Error` variants that wrap `cli`-only types (`oauth2`, `reqwest`, the AWS SDK) get `#[cfg(feature = "cli")]`, so core code can keep using `crate::Error`.

**Shipped helpers** (`src/helpers.rs`)

- `crate::helpers::locate(file_name) -> Option<PathBuf>` implements the lookup above. It never falls back to `PATH`.
- Unit tests: a symlinked executable (the lookup follows the canonical path), the package layout, a missing helper.

**CI** (`.github/workflows/_test.yml`)

- A job running `cargo check --lib --no-default-features` and `cargo clippy --lib --no-default-features`.
- A `size` job that builds the release artifacts' configurations (`x86_64-unknown-linux-musl` with `--no-default-features --features rustls`, and `aarch64-apple-darwin` with default features), writes the size table to `$GITHUB_STEP_SUMMARY`, and fails above the ceiling.
- The ceilings live in the workflow as environment variables, starting at 30 MB for `mairu`.

**Release** (`.github/workflows/release.yml`)

- `upload-binaries` builds `x86_64-apple-darwin` (cross-compiled on the macOS runner) and `aarch64-apple-darwin`, and no longer builds `universal-apple-darwin`.
- The rest of the workflow is unchanged: one tag, one run, crate published last.

**Documentation**

- README: the per-architecture macOS download names.
- CHANGELOG: the universal macOS binary is no longer published.
- `.claude/skills/releng/SKILL.md`: the artifact list (x86_64 and aarch64 apple-darwin), and the follow-ups for asset names in the Homebrew tap and the aqua registry.

**Tests**

- `cargo test` and `cargo clippy --all-targets` with default features, as today.
- `cargo build --no-default-features --features rustls` still produces `mairu`.
- `cargo check --lib --no-default-features` passes.

## Current Status

Spec drafted; awaiting review before implementation. Implementors MUST keep this section updated as they work.

### Checklist

- [ ] Release profile: LTO, one codegen unit, strip
- [ ] `cli` feature: optional dependencies, gated modules and `Error` variants, `required-features` on `mairu`
- [ ] CI: core library check without default features
- [ ] Shipped helpers: `crate::helpers::locate` with its tests
- [ ] CI: size reports with ceilings
- [ ] Release: `x86_64-apple-darwin` and `aarch64-apple-darwin`, no universal binary
- [ ] README, CHANGELOG and the releng skill updated
- [ ] Follow-ups: release asset names in the Homebrew tap and the aqua registry

### Updates

- 2026-10-29: Drafted. Sizes measured on Linux x86_64; the universal macOS binary is dropped.
