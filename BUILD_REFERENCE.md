# Build Reference - Quick Start

## One-Command Builds

```bash
# Build everything (recommended)
./build.sh

# Or use Make
make build
```

## Output

All binaries are placed in `dist/`:

```
dist/
├── telfin-linux-amd64        # Linux x86_64 (static)
├── telfin-linux-arm64        # Linux ARM64 (static)
├── telfin-darwin-amd64       # macOS Intel
├── telfin-darwin-arm64       # macOS Apple Silicon
├── telfin-windows-amd64.exe  # Windows 64-bit
└── checksums.txt             # SHA256 checksums
```

## Platform-Specific Builds

```bash
# Linux only (requires Docker)
make build-linux

# macOS only (requires macOS host)
make build-macos

# Windows only (requires mingw-w64)
make build-windows
```

## Prerequisites

### Required for All Builds
- Rust 1.75+ (`rustup update`)

### Linux Builds
- Docker Desktop or Docker Engine
- Docker Buildx (included in modern Docker)

```bash
# macOS
brew install docker

# Ubuntu/Debian
sudo apt install docker.io
```

### macOS Builds (macOS host only)
- Xcode Command Line Tools
- Rust targets

```bash
xcode-select --install
rustup target add x86_64-apple-darwin aarch64-apple-darwin
```

### Windows Builds (optional)
- mingw-w64 cross-compiler

```bash
# macOS
brew install mingw-w64

# Ubuntu/Debian
sudo apt install mingw-w64

# Add Rust target
rustup target add x86_64-pc-windows-gnu
```

## Development

```bash
# Quick dev build (current platform only)
cargo build
# or
make dev

# Run tests
cargo test
# or
make test

# Lint with clippy
make lint

# Format code
make fmt

# Clean build artifacts
make clean
```

## Install Rust Targets

Install all cross-compilation targets:

```bash
make install-targets
```

Or manually:

```bash
rustup target add x86_64-unknown-linux-musl
rustup target add aarch64-unknown-linux-musl
rustup target add x86_64-apple-darwin
rustup target add aarch64-apple-darwin
rustup target add x86_64-pc-windows-gnu
```

## CI/CD

### GitHub Actions Workflows

1. **CI** (`.github/workflows/ci.yml`)
   - Runs on every push/PR
   - Tests on Linux, macOS, Windows
   - Lints and checks formatting

2. **Release** (`.github/workflows/release.yml`)
   - Triggers on version tags
   - Builds all platforms
   - Creates GitHub release

### Create a Release

```bash
# Tag a version
git tag v0.1.0
git push origin v0.1.0

# GitHub Actions automatically:
# - Builds all binaries
# - Generates checksums
# - Creates release with downloads
```

## Binary Characteristics

### Linux (musl)
- **Statically linked** - No dependencies
- **Portable** - Works on any Linux distro
- **Size**: ~15-20 MB (stripped)

```bash
# Verify static linking
file dist/telfin-linux-amd64
ldd dist/telfin-linux-amd64  # Should say "not a dynamic executable"
```

### macOS
- **Minimum versions**:
  - Intel: macOS 10.14+
  - ARM: macOS 11.0+
- **Size**: ~10-15 MB (stripped)

### Windows
- **Dependencies**: Included in binary
- **Size**: ~12-18 MB (stripped)

## Troubleshooting

### Docker build fails
```bash
# Check Docker is running
docker ps

# Clean and rebuild
docker system prune -a
make clean && make build-linux
```

### macOS targets missing
```bash
rustup target add x86_64-apple-darwin aarch64-apple-darwin
```

### Windows cross-compile fails
```bash
# Verify mingw-w64
x86_64-w64-mingw32-gcc --version

# Reinstall if needed
brew reinstall mingw-w64
```

## Manual Build Commands

### Linux AMD64 (via Docker)
```bash
docker buildx build -f Dockerfile.build --target collector -o type=local,dest=dist .
```

### macOS Intel
```bash
cargo build --release --target x86_64-apple-darwin
cp target/x86_64-apple-darwin/release/telfin-agent dist/telfin-darwin-amd64
```

### macOS Apple Silicon
```bash
cargo build --release --target aarch64-apple-darwin
cp target/aarch64-apple-darwin/release/telfin-agent dist/telfin-darwin-arm64
```

### Windows
```bash
cargo build --release --target x86_64-pc-windows-gnu
cp target/x86_64-pc-windows-gnu/release/telfin-agent.exe dist/telfin-windows-amd64.exe
```

## Version Management

Version is set in `Cargo.toml`:

```toml
[package]
version = "0.1.0"
```

Check version:

```bash
./dist/telfin-linux-amd64 --version
# telfin 0.1.0
```

## Checksums

Verify downloads:

```bash
# After download
cd dist
sha256sum -c checksums.txt

# Or on macOS
shasum -a 256 -c checksums.txt
```

## Distribution

### Direct Download
```bash
# Linux AMD64
curl -L -o telfin https://github.com/USER/REPO/releases/latest/download/telfin-linux-amd64
chmod +x telfin
sudo mv telfin /usr/local/bin/

# macOS Apple Silicon
curl -L -o telfin https://github.com/USER/REPO/releases/latest/download/telfin-darwin-arm64
chmod +x telfin
sudo mv telfin /usr/local/bin/
```

### Verify After Install
```bash
telfin --version
telfin --help
```

## Make Targets

| Command | Description |
|---------|-------------|
| `make build` | Build all platform binaries |
| `make build-linux` | Build Linux binaries only |
| `make build-macos` | Build macOS binaries only |
| `make build-windows` | Build Windows binary only |
| `make install-targets` | Install Rust cross-compilation targets |
| `make clean` | Remove build artifacts |
| `make test` | Run tests |
| `make lint` | Run clippy linter |
| `make fmt` | Format code |
| `make check` | Check code without building |
| `make dev` | Quick development build |
| `make help` | Show all targets |

## File Structure

```
telfin-agent/
├── Cargo.toml              # Package manifest
├── Dockerfile.build        # Multi-stage build for Linux
├── build.sh                # Cross-platform build script
├── Makefile                # Build automation
├── .cargo/
│   └── config.toml         # Cross-compilation config
├── .github/
│   └── workflows/
│       ├── ci.yml          # Continuous integration
│       └── release.yml     # Release automation
├── src/                    # Rust source code
└── dist/                   # Build output (gitignored)
```

## Performance

Optimizations in `Cargo.toml`:

```toml
[profile.release]
opt-level = "z"        # Optimize for size
lto = true             # Link-time optimization
codegen-units = 1      # Better optimization
panic = "abort"        # Smaller binary
strip = true           # Strip symbols
```

## Support

For detailed information, see:
- `CROSS_COMPILATION.md` - Full guide
- `README.md` - Project overview
- `IMPLEMENTATION.md` - Technical details

## Quick Reference Card

```bash
# Setup
rustup update
make install-targets

# Build everything
./build.sh

# Build specific platform
make build-linux    # Requires Docker
make build-macos    # Requires macOS
make build-windows  # Requires mingw-w64

# Development
make dev            # Quick build
make test           # Run tests
make lint           # Check code

# Release
git tag v0.1.0
git push origin v0.1.0
# GitHub Actions builds and releases

# Clean
make clean
```
