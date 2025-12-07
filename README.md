# Telfin Agent

A lightweight Rust-based SSH tunnel agent that enables browser-based SSH access to local machines through the Telfin gateway.

## Overview

The Telfin agent is a single-binary application (~3-5MB) that:
- Authenticates users via OAuth 2.0 Device Code Flow (RFC 8628)
- Maintains a persistent WebSocket connection to the Telfin gateway
- Spawns SSH sessions to localhost via PTY
- Forwards terminal I/O over WebSocket using a binary protocol
- Stores credentials securely in the OS keychain

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│  Telfin Agent (Rust)                                    │
│  ┌───────────────────────────────────────────────────┐  │
│  │  CLI Interface (clap)                             │  │
│  │  - login: Device code flow                        │  │
│  │  - start: Connect to gateway                      │  │
│  │  - status: Check connection                       │  │
│  │  - logout: Remove credentials                     │  │
│  └───────────────────────────────────────────────────┘  │
│  ┌───────────────────────────────────────────────────┐  │
│  │  Agent Core                                       │  │
│  │  - WebSocket client (tokio-tungstenite)          │  │
│  │  - Auto-reconnect with exponential backoff        │  │
│  │  - Heartbeat (30s interval)                       │  │
│  │  - Session management (HashMap)                   │  │
│  └───────────────────────────────────────────────────┘  │
│  ┌───────────────────────────────────────────────────┐  │
│  │  PTY Manager (portable-pty)                       │  │
│  │  - Spawn SSH processes                            │  │
│  │  - Forward terminal I/O                           │  │
│  │  - Handle resize events                           │  │
│  └───────────────────────────────────────────────────┘  │
│  ┌───────────────────────────────────────────────────┐  │
│  │  Keychain (platform-specific)                     │  │
│  │  - macOS: security-framework                      │  │
│  │  - Windows: Credential Manager                    │  │
│  │  - Linux: Secret Service (libsecret)              │  │
│  └───────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────┘
```

## Project Structure

```
telfin-agent/
├── Cargo.toml              # Dependencies and build configuration
├── README.md               # This file
└── src/
    ├── main.rs             # CLI entry point (clap commands)
    ├── agent.rs            # Core agent with WebSocket & PTY handling
    ├── auth.rs             # Device code flow implementation
    ├── config.rs           # Configuration management
    ├── error.rs            # Error types (thiserror)
    ├── fingerprint.rs      # Device fingerprint generation
    ├── protocol.rs         # Binary message protocol
    └── keychain/
        ├── mod.rs          # Keychain trait and provider
        ├── macos.rs        # macOS Keychain implementation
        ├── windows.rs      # Windows Credential Manager
        └── linux.rs        # Linux Secret Service
```

## Features

### Authentication
- **Device Code Flow (RFC 8628)**: Secure browser-based authentication
- **OS Keychain Storage**: Credentials stored securely (never in plaintext)
- **Device Fingerprint**: Hardware-based unique identifier
- **Token Rotation**: 90-day automatic token refresh

### Agent Core
- **Auto-Reconnect**: Exponential backoff (1s → 60s max)
- **Heartbeat**: 30-second ping/pong to keep connection alive
- **Graceful Shutdown**: SIGINT/SIGTERM handling with session cleanup
- **Multiple Sessions**: Support for concurrent SSH sessions

### PTY Handling
- **portable-pty**: Cross-platform PTY management
- **SSH to localhost**: Spawns `ssh -tt localhost`
- **Terminal I/O**: Async forwarding via channels
- **Resize Events**: Terminal size updates (partial support)

### Protocol
Binary protocol with 10-byte header:
```
┌─────────┬─────────┬───────────────┬─────────────┬─────────────┐
│ Version │ Type    │ Session ID    │ Length      │ Payload     │
│ 1 byte  │ 1 byte  │ 4 bytes (BE)  │ 4 bytes (BE)│ Variable    │
└─────────┴─────────┴───────────────┴─────────────┴─────────────┘

Message Types:
0x01 = SessionStart
0x02 = TerminalInput
0x03 = TerminalOutput
0x04 = TerminalResize
0x05 = SessionEnd
0x06 = Heartbeat
0x07 = Error
```

## Building

### Prerequisites
- Rust 1.70+ (2021 edition)
- Platform-specific dependencies:
  - **macOS**: Xcode Command Line Tools
  - **Windows**: Visual Studio Build Tools
  - **Linux**: `libdbus-1-dev` (for secret-service)

### Development Build
```bash
cargo build
```

### Release Build (optimized for size)
```bash
cargo build --release
```

Binary size optimizations in `Cargo.toml`:
- `opt-level = "z"` - Optimize for size
- `lto = true` - Link-time optimization
- `codegen-units = 1` - Better optimization
- `strip = true` - Strip symbols

Expected binary size: **3-5MB**

## Usage

### 1. Login (Device Code Flow)
```bash
telfin login --server https://app.telfin.io
```

This will:
1. Request a device code from the server
2. Display a user code (e.g., `ABCD-EFGH`)
3. Prompt you to visit `https://app.telfin.io/device`
4. Poll for authorization every 5 seconds
5. Store the token in your OS keychain

### 2. Start the Agent
```bash
telfin start --machine-name my-laptop
```

The agent will:
- Load the token from keychain
- Generate a device fingerprint
- Connect to the gateway via WebSocket
- Maintain the connection with auto-reconnect

### 3. Check Status
```bash
telfin status
```

Shows:
- Login status
- Server URL
- Machine name
- Device fingerprint (first 16 chars)

### 4. Logout
```bash
telfin logout
```

Removes credentials from the keychain.

## Configuration

Config file: `~/.config/telfin/config.json` (auto-created)

```json
{
  "server_url": "https://app.telfin.io",
  "machine_name": "my-laptop",
  "reconnect_interval": 5,
  "heartbeat_interval": 30,
  "log_level": "info"
}
```

## Environment Variables

- `RUST_LOG`: Set log level (e.g., `RUST_LOG=debug`)

## Cross-Compilation

### macOS (Intel)
```bash
rustup target add x86_64-apple-darwin
cargo build --release --target x86_64-apple-darwin
```

### macOS (Apple Silicon)
```bash
rustup target add aarch64-apple-darwin
cargo build --release --target aarch64-apple-darwin
```

### Linux (static musl)
```bash
rustup target add x86_64-unknown-linux-musl
cargo build --release --target x86_64-unknown-linux-musl
```

### Windows
```bash
rustup target add x86_64-pc-windows-msvc
cargo build --release --target x86_64-pc-windows-msvc
```

## Security

### Token Storage
- **macOS**: Keychain (`security-framework`)
- **Windows**: Credential Manager (`windows` crate)
- **Linux**: Secret Service D-Bus API (`secret-service` crate)

Tokens are **never** stored in plaintext files or environment variables.

### Device Fingerprint
Generated from:
- Machine ID (`/etc/machine-id` on Linux, `IOPlatformUUID` on macOS, `wmic csproduct` on Windows)
- Hostname
- SHA-256 hash of combined identifiers

The fingerprint is stable across reboots but unique per machine.

### Transport Security
- WebSocket over TLS 1.3 (`wss://`)
- Certificate validation via `native-tls`
- Token sent as query parameter (consider moving to header in production)

## Known Limitations

1. **PTY Resize**: Full resize support is limited due to `portable-pty` API constraints after writer is taken. Consider using a different PTY library for production.

2. **Single SSH Session**: Currently spawns `ssh -tt localhost`. For multi-user support, parameterize the SSH command.

3. **No Auto-Update**: Manual updates required. Consider implementing auto-update mechanism.

4. **Platform Dependencies**: Requires OS-specific keychain services to be available.

## Dependencies

### Core
- `tokio` (1.40) - Async runtime
- `tokio-tungstenite` (0.23) - WebSocket client
- `portable-pty` (0.8) - Cross-platform PTY
- `clap` (4.5) - CLI parser

### HTTP/Serialization
- `reqwest` (0.12) - HTTP client (for auth)
- `serde` (1.0) - Serialization
- `serde_json` (1.0) - JSON support

### Crypto/Utils
- `sha2` (0.10) - SHA-256 hashing
- `hex` (0.4) - Hex encoding
- `base64` (0.22) - Base64 encoding
- `uuid` (1.10) - UUID generation
- `chrono` (0.4) - Timestamp handling

### Platform-Specific
- `security-framework` (2.11) - macOS Keychain
- `windows` (0.58) - Windows Credential Manager
- `secret-service` (4.0) - Linux libsecret

### Logging
- `tracing` (0.1) - Structured logging
- `tracing-subscriber` (0.3) - Log formatting

### Error Handling
- `thiserror` (1.0) - Error derive macros
- `anyhow` (1.0) - Error context

## Testing

### Unit Tests
```bash
cargo test
```

### Keychain Tests (requires user interaction)
```bash
cargo test --ignored
```

### Integration Test
```bash
# Terminal 1: Start a local gateway (or use dev server)
cd ../telfin-gateway
cargo run

# Terminal 2: Login and start agent
cd ../telfin-agent
cargo run -- login
cargo run -- start
```

## Contributing

1. Follow Rust idioms and zero-cost abstractions
2. Run `cargo clippy` before committing
3. Ensure tests pass: `cargo test`
4. Update documentation for new features

## License

MIT License (see project root)

## Related Projects

- **telfin-gateway**: Rust gateway service (auth + relay)
- **remote-coder-webapp**: Node.js webapp (UI + pod management)

## Support

For issues or questions:
- GitHub Issues: https://github.com/telfin/agent/issues
- Documentation: https://docs.telfin.io
