#!/bin/bash
set -euo pipefail

# Build Verity xcframework for macOS (Apple Silicon) with ProveKit backend.
# This enables the Swift CLI to run the full proving pipeline on macOS.
#
# Prerequisites:
#   1. ProveKit FFI must be built:
#      cd $PROVEKIT_ROOT && cargo build --release -p provekit-ffi
#
# Usage:
#   bash scripts/build-macos.sh
#
# Then build and run the Swift CLI:
#   VERITY_SWIFT_SDK_MODE=native VERITY_DIR=$VERITY_DIR swift build
#   VERITY_SWIFT_SDK_MODE=native VERITY_DIR=$VERITY_DIR swift run passport-prover ...

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
SDK_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
VERITY_DIR="${VERITY_DIR:-$(cd "$SDK_DIR/../../../verity" && pwd)}"
PROVEKIT_ROOT="${PROVEKIT_ROOT:-$(cd "$SDK_DIR/../../../provekit" && pwd)}"

CORE_DIR="$VERITY_DIR/core"
DISPATCHER_DIR="$CORE_DIR/dispatcher"
INCLUDE_DIR="$CORE_DIR/include"
OUTPUT_DIR="$VERITY_DIR/output"

# ProveKit FFI static library
PK_FFI="$PROVEKIT_ROOT/target/release/libprovekit_ffi.a"
if [ ! -f "$PK_FFI" ]; then
    echo "ERROR: ProveKit FFI not found at $PK_FFI"
    echo "Build it first: cd $PROVEKIT_ROOT && cargo build --release -p provekit-ffi"
    exit 1
fi

echo "=== Building Verity xcframework for macOS (ProveKit) ==="
echo "Verity dir:    $VERITY_DIR"
echo "ProveKit FFI:  $PK_FFI"
echo ""

WORK_DIR=$(mktemp -d)
trap "rm -rf $WORK_DIR" EXIT

CC=clang
ARCH="arm64"

# Compile dispatch layer
echo "Compiling dispatch layer..."
$CC -c -I"$INCLUDE_DIR" -I"$DISPATCHER_DIR" -I"$DISPATCHER_DIR/include" -fPIC -arch $ARCH \
    "$DISPATCHER_DIR/verity_dispatch.c" -o "$WORK_DIR/verity_dispatch.o"

# Compile ProveKit backend
echo "Compiling PK backend..."
$CC -c -I"$INCLUDE_DIR" -I"$DISPATCHER_DIR" -I"$DISPATCHER_DIR/include" -fPIC -arch $ARCH \
    "$DISPATCHER_DIR/backends/pk_backend.c" -o "$WORK_DIR/pk_backend.o"

# Extract all static libraries into object files for a combined archive
echo "Extracting static libraries..."
COMBINED_DIR="$WORK_DIR/combined"
mkdir -p "$COMBINED_DIR"

pushd "$COMBINED_DIR" > /dev/null
ar x "$PK_FFI"

# Collect ProveKit build deps (blake3, ring, lzma, etc.)
PK_BUILD_DIR="$PROVEKIT_ROOT/target/release/build"
if [ -d "$PK_BUILD_DIR" ]; then
    for lib in $(find "$PK_BUILD_DIR" -name "lib*.a" 2>/dev/null); do
        ar x "$lib" 2>/dev/null || true
    done
fi
popd > /dev/null

# Create combined static library
echo "Creating libverity.a..."
ar rcs "$WORK_DIR/libverity.a" \
    "$WORK_DIR/verity_dispatch.o" \
    "$WORK_DIR/pk_backend.o" \
    "$COMBINED_DIR"/*.o

# Prepare headers
HEADERS_DIR="$WORK_DIR/headers"
mkdir -p "$HEADERS_DIR"
cp "$DISPATCHER_DIR/include/verity_ffi.h" "$HEADERS_DIR/"
cp "$INCLUDE_DIR/verity_ffi_raw.h" "$HEADERS_DIR/"

cat > "$HEADERS_DIR/module.modulemap" << 'MMAP'
framework module VerityFFI {
    header "verity_ffi.h"
    export *
}
MMAP

# Create xcframework using xcodebuild
echo "Creating xcframework..."
rm -rf "$OUTPUT_DIR/Verity.xcframework"
mkdir -p "$OUTPUT_DIR"

xcodebuild -create-xcframework \
    -library "$WORK_DIR/libverity.a" \
    -headers "$HEADERS_DIR" \
    -output "$OUTPUT_DIR/Verity.xcframework"

# Write backends marker (used by Verity SDK Package.swift)
echo "provekit" > "$OUTPUT_DIR/Verity.xcframework/backends"

echo ""
echo "=== Done! ==="
ls -lh "$OUTPUT_DIR/Verity.xcframework"
echo ""
echo "Now build and run:"
echo "  cd $SDK_DIR"
echo "  VERITY_SWIFT_SDK_MODE=native VERITY_DIR=$VERITY_DIR swift build"
echo "  VERITY_SWIFT_SDK_MODE=native VERITY_DIR=$VERITY_DIR swift run passport-prover \\"
echo "    --dg1 <path> --sod <path> --pkp_dir ../../pkp --csca_registry ../../csca_registry/csca_public_key.json"
