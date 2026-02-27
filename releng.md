# Release flow

1. Releng Pull Request
    - Bump `Cargo.toml` version field and run `cargo build` once
    - Commit Cargo.* changes, including CHANGELOG.md update
2. Merge, `git tag --sign vX.Y.Z` and push
3. Wait for CI

### Binaries

#### Homebrew

1. Update https://github.com/sorah/homebrew-sorah
2. Wait for CI
3. Label PR for auto-merge including built bottles

#### AUR

1. Update mairu, mairu-bin
