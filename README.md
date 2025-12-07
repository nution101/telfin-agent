# Telfin Agent

A lightweight SSH tunnel agent that enables browser-based terminal access to your machine.

## Install

```bash
curl -fsSL https://raw.githubusercontent.com/nution101/telfin-agent/master/install.sh | sh
```

Or download from [Releases](https://github.com/nution101/telfin-agent/releases).

## Usage

### Login
```bash
telfin login
```
Opens your browser to authenticate. Credentials are stored securely in your OS keychain.

### Start the agent
```bash
telfin start
```
Connects to the gateway and makes your machine available for browser SSH access.

### Check status
```bash
telfin status
```

### Logout
```bash
telfin logout
```

## Platforms

- Linux (x64, ARM64)
- macOS (Intel, Apple Silicon)
- Windows (x64)

## License

MIT
