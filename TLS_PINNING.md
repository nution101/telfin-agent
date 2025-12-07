# TLS Certificate Pinning

This document describes the optional TLS certificate pinning feature for enhanced security.

## Overview

Certificate pinning provides protection against man-in-the-middle attacks by verifying the gateway's TLS certificate matches a known fingerprint. This is useful when you want to ensure the agent only connects to a specific server certificate, even if the CA chain is compromised.

## Configuration

Add the `tls_cert_fingerprint` field to your config file at `~/.config/telfin/config.json`:

```json
{
  "server_url": "https://gateway.telfin.io",
  "machine_name": "my-machine",
  "reconnect_interval": 5,
  "heartbeat_interval": 15,
  "log_level": "info",
  "tls_cert_fingerprint": "AB:CD:EF:01:23:45:67:89:AB:CD:EF:01:23:45:67:89:AB:CD:EF:01:23:45:67:89:AB:CD:EF:01:23:45:67:89"
}
```

### Format

The fingerprint must be a SHA-256 hash of the server's certificate in hex format. It can be provided:

- With colons: `AB:CD:EF:...` (64 hex chars + 31 colons)
- Without colons: `abcdef...` (64 hex chars)
- Mixed case is supported

## Getting the Certificate Fingerprint

To obtain the SHA-256 fingerprint of a server's certificate:

```bash
# Using openssl
echo | openssl s_client -connect gateway.telfin.io:443 2>/dev/null | \
  openssl x509 -noout -fingerprint -sha256 | \
  cut -d= -f2

# Alternative: using openssl with better formatting
openssl s_client -connect gateway.telfin.io:443 </dev/null 2>/dev/null | \
  openssl x509 -outform DER | \
  shasum -a 256 | \
  cut -d' ' -f1
```

## Security Considerations

**Benefits:**
- Prevents MITM attacks even if CA is compromised
- Ensures connection only to specific certificate
- No dependency on system certificate stores

**Limitations:**
- Certificate rotation requires config updates
- Must update fingerprint when server cert is renewed
- Testing/development may need this disabled

**Recommendations:**
- Use for production deployments with controlled certificate management
- Disable (set to `null` or omit field) for development/testing
- Monitor certificate expiration and plan rotation
- Consider using this only for sensitive environments

## Current Implementation Status

The TLS certificate pinning infrastructure is implemented and tested:

- Configuration validation
- Custom certificate verifier
- SHA-256 fingerprint matching
- Test coverage

**Note:** Full WebSocket integration requires additional work. The current `tokio-tungstenite` dependency uses its own TLS handling. To fully enable certificate pinning, the WebSocket connection in `src/agent.rs` would need to be modified to use a custom TLS connector built from the `build_tls_config()` function.

For now, this serves as the foundation that can be integrated when needed.

## Example Usage

### Development (No Pinning)

```json
{
  "server_url": "https://gateway.telfin.io",
  "machine_name": "dev-machine"
}
```

### Production (With Pinning)

```json
{
  "server_url": "https://gateway.telfin.io",
  "machine_name": "prod-machine",
  "tls_cert_fingerprint": "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"
}
```

## Troubleshooting

**Error: "Invalid certificate fingerprint"**
- Ensure the fingerprint is exactly 64 hex characters (32 bytes)
- Check that only valid hex characters (0-9, A-F) are used

**Error: "Certificate fingerprint mismatch"**
- The server's certificate has changed
- Verify you're connecting to the correct server
- Update the fingerprint in the config file
