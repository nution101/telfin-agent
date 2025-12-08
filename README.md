# Telfin Agent

A secure, lightweight SSH tunnel agent that enables browser-based terminal access to your machine from anywhere. Built in Rust for performance, security, and cross-platform compatibility.

## What is Telfin?

Telfin Agent runs on your local machine and establishes a secure WebSocket tunnel to the Telfin gateway. This allows you to access your machine's terminal through a web browser without exposing SSH ports, configuring firewalls, or dealing with dynamic IPs.

**Use Cases:**
- Access your home development machine from work
- Manage remote servers without VPN setup
- Provide temporary access to collaborators
- Access machines behind NAT/firewalls

## Features

- **Zero Configuration** - Works out of the box, no firewall rules needed
- **Secure by Default** - OAuth 2.0 authentication, TLS encryption, optional certificate pinning
- **Cross-Platform** - Linux, macOS, Windows (x64 and ARM64)
- **Lightweight** - Small binary (~5MB), minimal resource usage
- **Auto-Reconnect** - Handles network interruptions gracefully
- **Auto-Update** - Built-in update checker with rollback support
- **Keychain Integration** - Secure credential storage using OS keychains
- **Service Mode** - Run as system service with auto-start on boot
- **Browser-Based** - Access terminal from any modern web browser

## Quick Installation

```bash
curl -fsSL https://raw.githubusercontent.com/nution101/telfin-agent/master/install.sh | sh
```

Or download from [Releases](https://github.com/nution101/telfin-agent/releases).

## Basic Usage

### Authenticate
```bash
telfin login
```
Opens your browser to authenticate. Credentials stored securely in OS keychain.

### Start the Agent
```bash
telfin start
```
Connects to gateway and makes your machine available for browser SSH access.

### Check Status
```bash
telfin status
```

### Logout
```bash
telfin logout
```

### Auto-Start on Boot
```bash
telfin install
```
Configures systemd (Linux), launchd (macOS), or Windows Service. See [AUTO_START_GUIDE.md](AUTO_START_GUIDE.md).

### Update Agent
```bash
# Check for available updates
telfin update --check

# Download and install update (with automatic rollback on failure)
telfin update
```
The agent also checks for updates on startup (can be disabled in config).

## Platform Support

| Platform | Architecture | Status |
|----------|-------------|--------|
| Linux | x86_64, ARM64 | ✓ Supported |
| macOS | Intel, Apple Silicon | ✓ Supported |
| Windows | x86_64 | ✓ Supported |

## Architecture

```
Browser ◄──(TLS)──► Gateway ◄──(WebSocket)──► Agent ◄──(SSH)──► Local Shell
```

1. Agent authenticates using OAuth 2.0 device code flow
2. Establishes encrypted WebSocket tunnel to gateway
3. Gateway relays terminal I/O between browser and agent
4. Agent spawns local SSH session to localhost
5. Binary protocol ensures efficient, secure communication

See [IMPLEMENTATION.md](IMPLEMENTATION.md) for technical details.

## Security Features

- **OAuth 2.0 Authentication** - Industry-standard device code flow (RFC 8628)
- **Bearer Token in Headers** - No token exposure in URLs or logs
- **TLS Encryption** - All communication encrypted with rustls
- **Certificate Pinning** - Optional SHA-256 fingerprint validation
- **Command Injection Prevention** - Proper shell parsing
- **Memory Exhaustion Protection** - 1MB message size limit
- **Secure Credential Storage** - OS keychain integration

See [SECURITY_FIXES.md](SECURITY_FIXES.md) for detailed improvements.

## Configuration

Config location:
- Linux/macOS: `~/.config/telfin/config.json`
- Windows: `%APPDATA%\telfin\config.json`

**Example:**
```json
{
  "server_url": "https://gateway.telfin.io",
  "machine_name": "my-laptop",
  "reconnect_interval": 5,
  "heartbeat_interval": 15,
  "log_level": "info",
  "shell_command": "/bin/bash -l",
  "tls_cert_fingerprint": null,
  "auto_update_check": true
}
```

**Options:**
- `server_url` - Gateway URL (default: https://gateway.telfin.io)
- `machine_name` - Custom machine identifier (default: hostname)
- `reconnect_interval` - Seconds between reconnect attempts (default: 5)
- `heartbeat_interval` - Seconds between heartbeats (default: 15)
- `log_level` - debug, info, warn, error (default: info)
- `shell_command` - Terminal command (default: /bin/bash -l)
- `tls_cert_fingerprint` - Optional SHA-256 pin (default: null)
- `auto_update_check` - Check for updates on startup (default: true)

See [TLS_PINNING.md](TLS_PINNING.md) for certificate pinning.

## Documentation

- [IMPLEMENTATION.md](IMPLEMENTATION.md) - Architecture and technical design
- [SECURITY_FIXES.md](SECURITY_FIXES.md) - Security improvements and fixes
- [AUTO_START_GUIDE.md](AUTO_START_GUIDE.md) - Service installation and management
- [BUILD_REFERENCE.md](BUILD_REFERENCE.md) - Building from source
- [CROSS_COMPILATION.md](CROSS_COMPILATION.md) - Cross-platform builds
- [TLS_PINNING.md](TLS_PINNING.md) - Certificate pinning guide
- [CHANGES.md](CHANGES.md) - Version history and changelog

## Building from Source

Requires Rust 1.85+.

```bash
git clone https://github.com/nution101/telfin-agent.git
cd telfin-agent
cargo build --release
./target/release/telfin --version
```

See [CROSS_COMPILATION.md](CROSS_COMPILATION.md) for multi-platform builds.

## Troubleshooting

**Agent won't connect:**
- Check network connectivity to gateway
- Verify authentication: `telfin status`
- Review logs: `~/.config/telfin/agent.log`

**Authentication fails:**
- Ensure browser can access auth portal
- Try `telfin logout` and re-authenticate
- Verify system time is synchronized

**Service won't start:**
- Check service logs (journalctl/Console.app)
- Authenticate before installing service
- Verify binary permissions

**Connection drops:**
- Check network stability
- Increase `reconnect_interval` in config
- Review gateway logs

## Contributing

Contributions welcome! Fork the repo, create a feature branch, add tests, and submit a PR.

## License

MIT License - see [LICENSE](LICENSE) for details.

## Support

- GitHub Issues: https://github.com/nution101/telfin-agent/issues
- Documentation: https://github.com/nution101/telfin-agent
