# Cross-Compilation Guide for Telfin Agent

This document describes the cross-compilation setup for building telfin-agent binaries for multiple platforms.

## Supported Platforms

The build system produces static binaries for:

- **Linux x86_64** (Intel/AMD 64-bit) - `telfin-linux-amd64`
- **Linux aarch64** (ARM 64-bit) - `telfin-linux-arm64`
- **macOS x86_64** (Intel Mac) - `telfin-darwin-amd64`
- **macOS aarch64** (Apple Silicon) - `telfin-darwin-arm64`
- **Windows x86_64** (64-bit) - `telfin-windows-amd64.exe`

## Quick Start

### Build All Platforms

```bash
# Using the build script
./build.sh

# Or using Make
make build
```

### Build Specific Platforms

```bash
# Linux only (requires Docker)
make build-linux

# macOS only (requires macOS host)
make build-macos

# Windows only (requires mingw-w64)
make build-windows
```

## Prerequisites

### For Linux Builds

- **Docker** - Required for building Linux binaries
- Docker Buildx (usually included with modern Docker installations)

Install Docker:
```bash
# macOS
brew install docker

# Ubuntu/Debian
sudo apt install docker.io
```

### For macOS Builds

- **macOS host** - Required for building macOS binaries
- Xcode Command Line Tools
- Rust toolchain

Install prerequisites:
```bash
xcode-select --install
rustup target add x86_64-apple-darwin aarch64-apple-darwin
```

### For Windows Builds

- **mingw-w64** cross-compiler

Install mingw-w64:
```bash
# macOS
brew install mingw-w64

# Ubuntu/Debian
sudo apt install mingw-w64

# Arch Linux
sudo pacman -S mingw-w64-gcc
```

Add Rust target:
```bash
rustup target add x86_64-pc-windows-gnu
```

## Build System Architecture

### Docker Multi-Stage Build

The `Dockerfile.build` uses a multi-stage approach:

1. **builder-amd64** - Alpine-based Rust environment for x86_64
2. **builder-arm64** - Cross-compilation toolchain for ARM64
3. **collector** - Combines binaries from both builders

Linux binaries are **statically linked** using musl libc, making them portable across all Linux distributions.

### Cargo Configuration

The `.cargo/config.toml` file configures:

- Static linking for Linux (musl) targets
- Cross-compilation linkers
- Platform-specific flags (e.g., macOS version minimums)

### Build Script

The `build.sh` script:

- Detects the host platform
- Builds appropriate targets
- Generates SHA256 checksums
- Outputs all binaries to `dist/` directory

## Binary Verification

### Static Linking Verification

Linux binaries should be statically linked:

```bash
# Check with file command
file dist/telfin-linux-amd64
# Output: ELF 64-bit LSB executable, x86-64, static-pie linked

# Check with ldd (should show "not a dynamic executable")
ldd dist/telfin-linux-amd64
```

### Size Optimization

The `Cargo.toml` release profile is optimized for size:

```toml
[profile.release]
opt-level = "z"        # Optimize for size
lto = true             # Link-time optimization
codegen-units = 1      # Better optimization
panic = "abort"        # Smaller binary
strip = true           # Strip symbols
```

Typical binary sizes:
- Linux: ~15-20 MB (static, stripped)
- macOS: ~10-15 MB (stripped)
- Windows: ~12-18 MB (stripped)

## GitHub Actions CI/CD

### Continuous Integration

`.github/workflows/ci.yml` runs on every push:

- Tests on Linux, macOS, and Windows
- Clippy linting
- Format checking
- Build verification

### Automated Releases

`.github/workflows/release.yml` triggers on version tags:

1. Builds binaries for all platforms in parallel
2. Generates checksums
3. Creates GitHub release with all binaries attached

To create a release:

```bash
# Tag a version
git tag v0.1.0
git push origin v0.1.0

# GitHub Actions will automatically:
# - Build all platform binaries
# - Create a release
# - Upload binaries and checksums
```

## Development Workflow

### Local Development Build

```bash
# Fast debug build (current platform only)
cargo build

# Or use Make
make dev
```

### Testing

```bash
# Run tests
cargo test

# Or use Make
make test
```

### Linting and Formatting

```bash
# Run clippy
make lint

# Format code
make fmt

# Check without building
make check
```

## Platform-Specific Notes

### Linux (musl)

Linux binaries use musl libc for static linking. This ensures:
- No runtime dependencies
- Works on any Linux distribution
- Portable across different glibc versions

The binaries are built with `+crt-static` to ensure all C runtime is included.

### macOS

macOS binaries set minimum deployment targets:
- x86_64: macOS 10.14 (Mojave)
- aarch64: macOS 11.0 (Big Sur)

The agent uses the macOS Security Framework for keychain access.

### Windows

Windows builds require:
- `ws2_32.lib` - Winsock 2 (network)
- `userenv.lib` - User environment (for home directory)

These are automatically linked via rustflags in `.cargo/config.toml`.

## Troubleshooting

### Docker Build Fails

```bash
# Ensure Docker is running
docker ps

# Clean Docker cache
docker system prune -a

# Rebuild without cache
docker buildx build --no-cache -f Dockerfile.build --target collector -o type=local,dest=dist .
```

### macOS Cross-Compilation Fails

Ensure both targets are installed:

```bash
rustup target list --installed
# Should include:
# x86_64-apple-darwin
# aarch64-apple-darwin

# Add missing targets
rustup target add x86_64-apple-darwin aarch64-apple-darwin
```

### Windows Cross-Compilation Fails

Verify mingw-w64 is installed correctly:

```bash
# Check compiler
x86_64-w64-mingw32-gcc --version

# Reinstall if needed
brew reinstall mingw-w64
```

### Binary Size Too Large

If binaries are unexpectedly large:

1. Ensure release mode: `cargo build --release`
2. Check strip is enabled in `Cargo.toml`: `strip = true`
3. Manually strip: `strip dist/telfin-*`

## CI/CD Integration

### Dockerfile for Deployment

The `Dockerfile.build` can be used in CI pipelines:

```yaml
# Example GitHub Actions step
- name: Build Linux binaries
  run: |
    docker buildx build \
      -f Dockerfile.build \
      --target collector \
      -o type=local,dest=dist \
      .
```

### Version Management

Version is embedded in binary via Cargo:

```bash
./telfin-linux-amd64 --version
# Output: telfin 0.1.0
```

The version comes from `Cargo.toml`:

```toml
[package]
version = "0.1.0"
```

## Distribution

### Installation Scripts

Linux/macOS one-liner:

```bash
curl -L -o telfin https://github.com/USER/REPO/releases/latest/download/telfin-linux-amd64
chmod +x telfin
sudo mv telfin /usr/local/bin/
```

### Homebrew Formula

Create a Homebrew tap for macOS distribution:

```ruby
class Telfin < Formula
  desc "Telfin SSH Tunnel Agent"
  homepage "https://github.com/USER/REPO"
  version "0.1.0"

  on_macos do
    if Hardware::CPU.intel?
      url "https://github.com/USER/REPO/releases/download/v0.1.0/telfin-darwin-amd64"
      sha256 "..."
    elsif Hardware::CPU.arm?
      url "https://github.com/USER/REPO/releases/download/v0.1.0/telfin-darwin-arm64"
      sha256 "..."
    end
  end

  def install
    bin.install "telfin-darwin-amd64" => "telfin"
  end
end
```

## Security Considerations

### Static Linking Security

Static binaries include all dependencies, which means:
- **Pros**: No runtime dependency issues, portable
- **Cons**: Security updates require rebuilding

Recommendation: Rebuild and re-release when dependencies have security updates.

### Binary Signing

For production releases, consider code signing:

- **macOS**: Sign with Apple Developer certificate
- **Windows**: Sign with Authenticode certificate

### Checksums

Always verify checksums after download:

```bash
# Linux/macOS
sha256sum -c checksums.txt

# macOS alternative
shasum -a 256 -c checksums.txt
```

## Performance Benchmarks

Typical performance characteristics:

- **Binary size**: 10-20 MB (varies by platform)
- **Startup time**: <100ms
- **Memory usage**: ~5-10 MB baseline
- **CPU usage**: Minimal when idle

Profile with:

```bash
# Build with profiling
RUSTFLAGS='-C profile-generate' cargo build --release

# Run workload
./target/release/telfin-agent start

# Rebuild with profile data
RUSTFLAGS='-C profile-use' cargo build --release
```

## Future Improvements

Potential enhancements:

1. **FreeBSD support** - Add `x86_64-unknown-freebsd` target
2. **ARM32 support** - Add `armv7-unknown-linux-musleabihf` target
3. **Binary compression** - Use UPX for smaller binaries
4. **Auto-update mechanism** - Self-updating binaries
5. **Package managers** - apt, yum, Chocolatey packages

## References

- [Rust Cross-Compilation](https://rust-lang.github.io/rustup/cross-compilation.html)
- [rust-musl-cross](https://github.com/messense/rust-musl-cross)
- [GitHub Actions Rust](https://github.com/actions-rs)
- [Docker Buildx](https://docs.docker.com/buildx/working-with-buildx/)
