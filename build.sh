#!/bin/bash
set -e

VERSION=${1:-"v0.1.0"}
OUTPUT_DIR="dist"

echo "========================================="
echo "Building telfin-agent $VERSION"
echo "========================================="
echo ""

# Create output directory
mkdir -p $OUTPUT_DIR

# Detect platform
OS_TYPE=$(uname -s)
ARCH=$(uname -m)

echo "Build host: $OS_TYPE $ARCH"
echo ""

# Linux builds via Docker
echo ">>> Building Linux binaries (via Docker)..."
echo ""

if ! command -v docker &> /dev/null; then
    echo "WARNING: Docker not found. Skipping Linux builds."
    echo "Install Docker to build Linux binaries."
    echo ""
else
    # Build using multi-stage Dockerfile
    docker buildx build \
        -f Dockerfile.build \
        --target collector \
        --output type=local,dest=$OUTPUT_DIR \
        .

    echo "✓ Linux binaries built successfully"
    echo ""
fi

# macOS builds (only on macOS host)
if [[ "$OS_TYPE" == "Darwin" ]]; then
    echo ">>> Building macOS binaries..."
    echo ""

    # Add targets if not already installed
    rustup target add x86_64-apple-darwin 2>/dev/null || true
    rustup target add aarch64-apple-darwin 2>/dev/null || true

    # Intel Mac
    echo "Building for x86_64-apple-darwin..."
    cargo build --release --target x86_64-apple-darwin
    cp target/x86_64-apple-darwin/release/telfin-agent $OUTPUT_DIR/telfin-darwin-amd64
    echo "✓ x86_64 macOS binary built"

    # Apple Silicon
    echo "Building for aarch64-apple-darwin..."
    cargo build --release --target aarch64-apple-darwin
    cp target/aarch64-apple-darwin/release/telfin-agent $OUTPUT_DIR/telfin-darwin-arm64
    echo "✓ ARM64 macOS binary built"

    echo ""
else
    echo "INFO: Skipping macOS builds (not on macOS host)"
    echo ""
fi

# Windows cross-compile (requires mingw)
if command -v x86_64-w64-mingw32-gcc &> /dev/null; then
    echo ">>> Building Windows binary..."
    echo ""

    rustup target add x86_64-pc-windows-gnu 2>/dev/null || true
    cargo build --release --target x86_64-pc-windows-gnu
    cp target/x86_64-pc-windows-gnu/release/telfin-agent.exe $OUTPUT_DIR/telfin-windows-amd64.exe
    echo "✓ Windows binary built"
    echo ""
else
    echo "INFO: Skipping Windows build (mingw-w64 not installed)"
    echo "Install with: brew install mingw-w64 (macOS) or apt install mingw-w64 (Linux)"
    echo ""
fi

# Create checksums
echo ">>> Generating checksums..."
cd $OUTPUT_DIR

if command -v sha256sum &> /dev/null; then
    sha256sum telfin-* 2>/dev/null > checksums.txt || true
elif command -v shasum &> /dev/null; then
    shasum -a 256 telfin-* 2>/dev/null > checksums.txt || true
else
    echo "WARNING: No SHA256 tool found. Skipping checksums."
fi

cd ..

echo ""
echo "========================================="
echo "Build complete! Binaries in $OUTPUT_DIR/"
echo "========================================="
echo ""
ls -lh $OUTPUT_DIR/
echo ""

# Display binary sizes
if [[ -f "$OUTPUT_DIR/checksums.txt" ]]; then
    echo "SHA256 checksums:"
    cat "$OUTPUT_DIR/checksums.txt"
fi
