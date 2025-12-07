# Makefile for telfin-agent cross-compilation

VERSION ?= v0.1.0
OUTPUT_DIR = dist

.PHONY: all build build-linux build-macos build-windows clean install-targets help

# Default target
all: build

# Build all available platforms
build:
	@./build.sh $(VERSION)

# Build Linux binaries via Docker
build-linux:
	@echo "Building Linux binaries..."
	@mkdir -p $(OUTPUT_DIR)
	docker buildx build -f Dockerfile.build --target collector -o type=local,dest=$(OUTPUT_DIR) .
	@echo "✓ Linux binaries built"

# Build macOS binaries (only on macOS)
build-macos:
	@echo "Building macOS binaries..."
	@mkdir -p $(OUTPUT_DIR)
	@rustup target add x86_64-apple-darwin 2>/dev/null || true
	@rustup target add aarch64-apple-darwin 2>/dev/null || true
	cargo build --release --target x86_64-apple-darwin
	cargo build --release --target aarch64-apple-darwin
	cp target/x86_64-apple-darwin/release/telfin-agent $(OUTPUT_DIR)/telfin-darwin-amd64
	cp target/aarch64-apple-darwin/release/telfin-agent $(OUTPUT_DIR)/telfin-darwin-arm64
	@echo "✓ macOS binaries built"

# Build Windows binary
build-windows:
	@echo "Building Windows binary..."
	@mkdir -p $(OUTPUT_DIR)
	@rustup target add x86_64-pc-windows-gnu 2>/dev/null || true
	cargo build --release --target x86_64-pc-windows-gnu
	cp target/x86_64-pc-windows-gnu/release/telfin-agent.exe $(OUTPUT_DIR)/telfin-windows-amd64.exe
	@echo "✓ Windows binary built"

# Install all cross-compilation targets
install-targets:
	@echo "Installing Rust cross-compilation targets..."
	rustup target add x86_64-unknown-linux-musl
	rustup target add aarch64-unknown-linux-musl
	rustup target add x86_64-apple-darwin
	rustup target add aarch64-apple-darwin
	rustup target add x86_64-pc-windows-gnu
	@echo "✓ Targets installed"

# Clean build artifacts
clean:
	@echo "Cleaning build artifacts..."
	rm -rf $(OUTPUT_DIR) target
	@echo "✓ Clean complete"

# Run tests on all platforms
test:
	@echo "Running tests..."
	cargo test --all-features

# Run clippy linter
lint:
	@echo "Running clippy..."
	cargo clippy --all-targets --all-features -- -D warnings

# Format code
fmt:
	@echo "Formatting code..."
	cargo fmt --all

# Check code without building
check:
	@echo "Checking code..."
	cargo check --all-targets --all-features

# Development build (fast, unoptimized)
dev:
	@echo "Building development binary..."
	cargo build

# Help
help:
	@echo "Telfin Agent Build System"
	@echo ""
	@echo "Targets:"
	@echo "  make build          - Build all platform binaries"
	@echo "  make build-linux    - Build Linux binaries only"
	@echo "  make build-macos    - Build macOS binaries only"
	@echo "  make build-windows  - Build Windows binary only"
	@echo "  make install-targets - Install Rust cross-compilation targets"
	@echo "  make clean          - Remove build artifacts"
	@echo "  make test           - Run tests"
	@echo "  make lint           - Run clippy linter"
	@echo "  make fmt            - Format code"
	@echo "  make check          - Check code without building"
	@echo "  make dev            - Quick development build"
	@echo ""
	@echo "Variables:"
	@echo "  VERSION=$(VERSION) - Set build version"
	@echo ""
	@echo "Example:"
	@echo "  make build VERSION=v0.2.0"
