#!/usr/bin/env bash
set -euo pipefail

# Build the Mediated Mental Poker Demo

# Default build directory
BUILD_DIR="${BUILD_DIR:-build}"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

info() {
    echo -e "${GREEN}[INFO]${NC} $*"
}

warn() {
    echo -e "${YELLOW}[WARN]${NC} $*"
}

error() {
    echo -e "${RED}[ERROR]${NC} $*"
}

# Check for CMake
if ! command -v cmake &> /dev/null; then
    error "CMake not found. Please install CMake (minimum version 3.10)."
    exit 1
fi

# Check for GMP (required by Relic)
if ! command -v gmp-config &> /dev/null && ! dpkg -l libgmp-dev &> /dev/null; then
    warn "GMP library not found. Relic requires GMP for multi-precision arithmetic."
    warn "Install with: sudo apt install libgmp-dev (Debian/Ubuntu) or brew install gmp (macOS)"
fi

info "Building in directory: $BUILD_DIR"

# Configure with CMake
info "Configuring with CMake..."
cmake -S . -B "$BUILD_DIR" "$@"

# Build
info "Building..."
cmake --build "$BUILD_DIR" -j "$(nproc 2>/dev/null || sysctl -n hw.ncpu 2>/dev/null || echo 4)"

info "Build completed successfully."
info "Demo executable: $BUILD_DIR/mediated_demo.x"
