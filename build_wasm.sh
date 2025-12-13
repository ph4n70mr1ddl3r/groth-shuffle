#!/usr/bin/env bash
set -euo pipefail

if ! command -v emcmake &> /dev/null; then
    echo "Error: emcmake not found. Make sure Emscripten SDK is active."
    exit 1
fi

BUILD_DIR="build_wasm"

echo "Configuring WASM build..."
emcmake cmake -S . -B "$BUILD_DIR" -DCMAKE_BUILD_TYPE=Release

echo "Building..."
cmake --build "$BUILD_DIR" --target groth_shuffle_js -j

echo "Done. Output in $BUILD_DIR/groth_shuffle_js.js and .wasm"
