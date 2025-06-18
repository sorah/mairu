# Mairu Project Guide

## Project Overview
Mairu is a secure AWS credentials management tool written in Rust that allows seamless use of multiple AWS roles and accounts concurrently.

## Development Commands
- Build: `cargo build`
- Test: `cargo test`
- Type check: `cargo clippy` (preferred over `cargo check` for extensive linting)
- Format: `cargo fmt`
- Lint: `cargo clippy`

## Key Architecture Notes
- Agent-based architecture with gRPC communication
- Credentials stored only in memory (never persisted to disk)
- Uses Protocol Buffers for IPC (definitions in `proto/`)
- Heavy use of async/await with Tokio runtime

## Code Style
- Follow standard Rust conventions
- Use `thiserror` for error types
- Use `zeroize` and `secrecy` for sensitive data handling
- Prefer explicit error handling over panics
- **Always run `cargo fmt` after writing or modifying code**
- **Always run `cargo clippy` after writing or modifying code for extensive linting checks**
- **Import (`use`) statements**: 
  - Global `use` statements at the top of files are discouraged (except in `mod.rs` and `lib.rs`)
  - Avoid `use` for structs and enums - prefer full paths (e.g., `std::collections::HashMap` instead of `use std::collections::HashMap`)
  - `use` is allowed for frequently used modules within the same crate (e.g., `use crate::error::Error`)
  - When importing traits, place the `use` statement in the most specific scope where they're needed
  - Default: Don't use `use` unless explicitly requested by humans

## Testing
- Write unit tests in `#[cfg(test)]` modules
- Run `cargo test` before committing changes
- Tests require `protobuf-compiler` installed on the system

## Security Considerations
- AWS credentials are stored only in memory, never persisted to disk
- Use `zeroize` for secure cleanup of sensitive data
- OAuth 2.0 with PKCE is required for authorization code grant
- Report security issues to security@sorah.jp and security@cookpad.com (not GitHub Issues)

## Feature Flags
- `default`: Uses native TLS implementation
- `rustls`: Uses Rust TLS implementation (used for Debian packages)
- Choose features with `cargo build --features rustls --no-default-features`

## Release Process
- Version is in `Cargo.toml`
- Create tags as `v{VERSION}` (e.g., `v0.7.0`)
- CI automatically builds releases for multiple architectures

## Important Files
- Server configs: `~/.config/mairu/servers.d/*.json`
- Agent socket: `$XDG_RUNTIME_DIR/mairu-agent.sock`
- Auto role config: `.mairu.json` in project directories
- HTTP API spec: `HTTP_API_SPEC.md`

## CI/CD
- GitHub Actions runs tests on push/PR
- Tests multiple targets: Linux (x86_64/aarch64, glibc/musl), macOS (aarch64)
- Release workflow builds binaries and Debian packages