#!/bin/sh
# Telfin Agent Installer
# Usage: curl -fsSL https://telfin.io/install.sh | sh

set -e

REPO="nution101/telfin-agent"
INSTALL_DIR="/usr/local/bin"
BINARY_NAME="telfin"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

info() { echo "${GREEN}[INFO]${NC} $1"; }
warn() { echo "${YELLOW}[WARN]${NC} $1"; }
error() { echo "${RED}[ERROR]${NC} $1"; exit 1; }

# Detect OS
detect_os() {
    OS=$(uname -s | tr '[:upper:]' '[:lower:]')
    case "$OS" in
        linux) OS="linux" ;;
        darwin) OS="darwin" ;;
        *) error "Unsupported operating system: $OS" ;;
    esac
}

# Detect architecture
detect_arch() {
    ARCH=$(uname -m)
    case "$ARCH" in
        x86_64|amd64) ARCH="amd64" ;;
        aarch64|arm64) ARCH="arm64" ;;
        *) error "Unsupported architecture: $ARCH" ;;
    esac
}

# Get latest release version
get_latest_version() {
    VERSION=$(curl -s "https://api.github.com/repos/$REPO/releases/latest" | grep '"tag_name":' | sed -E 's/.*"([^"]+)".*/\1/')
    if [ -z "$VERSION" ]; then
        error "Failed to fetch latest version"
    fi
}

# Download and install
install() {
    detect_os
    detect_arch
    get_latest_version
    
    ASSET_NAME="telfin-${OS}-${ARCH}.tar.gz"
    DOWNLOAD_URL="https://github.com/$REPO/releases/download/$VERSION/$ASSET_NAME"
    
    info "Downloading telfin-agent $VERSION for $OS/$ARCH..."
    
    TMP_DIR=$(mktemp -d)
    trap "rm -rf $TMP_DIR" EXIT
    
    curl -fsSL "$DOWNLOAD_URL" -o "$TMP_DIR/$ASSET_NAME" || error "Download failed. Check https://github.com/$REPO/releases"
    
    info "Extracting..."
    tar -xzf "$TMP_DIR/$ASSET_NAME" -C "$TMP_DIR"
    
    info "Installing to $INSTALL_DIR..."
    
    # Install binary FIRST (before killing old process)
    # This ensures old agent keeps running if install fails
    if [ -w "$INSTALL_DIR" ]; then
        mv "$TMP_DIR/telfin-agent" "$INSTALL_DIR/$BINARY_NAME"
        chmod +x "$INSTALL_DIR/$BINARY_NAME"
    else
        sudo mv "$TMP_DIR/telfin-agent" "$INSTALL_DIR/$BINARY_NAME"
        sudo chmod +x "$INSTALL_DIR/$BINARY_NAME"
    fi
    
    info "Binary installed to $INSTALL_DIR/$BINARY_NAME"
    
    # Kill any running telfin processes AFTER successful install
    # This prevents stale old agents from continuing to run after upgrade
    if pgrep -x "telfin" > /dev/null 2>&1 || pgrep -x "telfin-agent" > /dev/null 2>&1; then
        info "Stopping old telfin processes..."
        pkill -9 -x "telfin" 2>/dev/null || true
        pkill -9 -x "telfin-agent" 2>/dev/null || true
        sleep 1
    fi
    
    echo ""

    # Auto-run setup (login + install service + start)
    info "Starting Telfin setup..."
    echo ""

    # Run telfin install which handles: login -> install service -> start service
    "$INSTALL_DIR/$BINARY_NAME" install
}

install
