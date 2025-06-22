# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Build and Development Commands

### Prerequisites
- Install Rust toolchain
- Install `protobuf-compiler` package (required for building proto files)
- For musl builds: Install `musl-tools` package

### Common Commands

```bash
# Run tests
cargo test

# Build debug version
cargo build

# Build release version
cargo build --release

# Build with rustls feature (instead of native-tls)
cargo build --no-default-features --features rustls

# Build for musl target (static binary)
cargo build --target x86_64-unknown-linux-musl --no-default-features --features rustls

# Build Debian package
cargo install cargo-deb --locked
cargo deb --target=x86_64-unknown-linux-musl

# Run a single test
cargo test test_name
```

## Architecture Overview

Mairu is an on-memory AWS credentials agent that manages and provides AWS credentials to CLI tools. It consists of several key components:

### Core Components

1. **Agent Process** (`src/agent.rs`): Background daemon that manages sessions and credentials
   - Communicates via gRPC protocol defined in `proto/mairu.proto`
   - Listens on Unix domain socket at `$XDG_RUNTIME_DIR/mairu-agent.sock`
   - Handles OAuth flows, session management, and credential caching

2. **CLI Interface** (`src/main.rs`): Command-line interface with subcommands
   - `exec`: Execute commands with AWS credentials
   - `login`: Authenticate with credential servers
   - `credential-process`: AWS SDK credential process provider
   - `agent`: Manually start agent process

3. **Credential Providers**:
   - **AWS SSO** (`src/awssso_client.rs`): Integration with AWS IAM Identity Center
   - **API Client** (`src/api_client.rs`): Generic client for custom credential servers

4. **ECS Server** (`src/ecs_server.rs`): HTTP server that emulates ECS credential endpoint
   - Provides credentials to AWS SDKs via container credential provider protocol
   - Protected by bearer token authentication

5. **Session Management** (`src/session_manager.rs`): In-memory session storage
   - Manages authentication tokens and credential cache per server

6. **Auto Role Selection** (`src/auto.rs`): Reads `.mairu.json` files for automatic role selection
   - Trust verification with SHA-384 digest

### Key Design Patterns

- **Agent-Client Separation**: Agent runs as background process, CLI commands communicate via gRPC
- **Protocol Abstraction**: gRPC interface allows different credential provider implementations
- **Credential Provider Modes**: Support for ECS (default), static, and credential process modes
- **Security**: Uses `zeroize` for secure memory handling, bearer tokens for authentication

### Configuration

Server configurations are stored in `~/.config/mairu/servers.d/*.json`. Supports:
- AWS SSO configuration with region
- Custom OAuth servers with flexible endpoint configuration

### Protocol

The gRPC protocol (`proto/mairu.proto`) defines the agent communication interface. Key service methods:
- `AssumeRole`: Get AWS credentials for a role
- `GetServer`: Retrieve server configuration
- `InitiateOauth*`: Start OAuth flows
- `RefreshSession`: Renew sessions

## Coding Guidelines

### Import (`use`) Statements
- Global `use` statements at the top of files are discouraged (except in `mod.rs` and `lib.rs`)
- Avoid `use` for structs and enums - prefer full paths (e.g., `std::collections::HashMap` instead of `use std::collections::HashMap`)
- `use` is allowed for frequently used modules within the same crate (e.g., `use crate::error::Error`)
- When importing traits, place the `use` statement in the most specific scope where they're needed
- Default: Don't use `use` unless explicitly requested by humans

## Development Practices

- Must pass cargo clippy before commit