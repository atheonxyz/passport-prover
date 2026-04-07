#!/bin/bash
set -euo pipefail

# Build libverity.a static library for macOS (Apple Silicon) with ProveKit backend.
# This enables the Swift CLI to run the full proving pipeline on macOS.
#
# Prerequisites:
#   1. ProveKit FFI must be built:
#      cd <provekit> && cargo build --release -p provekit-ffi
#
# Usage:
#   bash scripts/build-macos.sh
#
# Then build the Swift package with the native library:
#   VERITY_SWIFT_SDK_MODE=native swift build

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

echo "=== Building Verity static library for macOS (ProveKit) ==="
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

# Create a combined static library with dispatch + pk_backend + provekit_ffi
echo "Creating combined static library..."
COMBINED_DIR="$WORK_DIR/combined"
mkdir -p "$COMBINED_DIR"

# Extract ProveKit FFI objects
pushd "$COMBINED_DIR" > /dev/null
ar x "$PK_FFI"
popd > /dev/null

# Collect extra build deps from ProveKit (blake3, ring, lzma, etc.)
PK_BUILD_DIR="$PROVEKIT_ROOT/target/release/build"
if [ -d "$PK_BUILD_DIR" ]; then
    for lib in $(find "$PK_BUILD_DIR" -name "lib*.a" 2>/dev/null); do
        pushd "$COMBINED_DIR" > /dev/null
        ar x "$lib" 2>/dev/null || true
        popd > /dev/null
    done
fi

# Also extract any deps from verity core build dir
VERITY_BUILD_DIR="$CORE_DIR/target/release/build"
if [ -d "$VERITY_BUILD_DIR" ]; then
    for lib in $(find "$VERITY_BUILD_DIR" -name "lib*.a" 2>/dev/null); do
        pushd "$COMBINED_DIR" > /dev/null
        ar x "$lib" 2>/dev/null || true
        popd > /dev/null
    done
fi

# Build the fat static lib
echo "Archiving libverity.a..."
ar rcs "$WORK_DIR/libverity.a" \
    "$WORK_DIR/verity_dispatch.o" \
    "$WORK_DIR/pk_backend.o" \
    "$COMBINED_DIR"/*.o

# Create xcframework directory structure for macOS
XCFW_DIR="$OUTPUT_DIR/Verity.xcframework"
MACOS_DIR="$XCFW_DIR/macos-arm64"
HEADERS_DIR="$MACOS_DIR/Headers"

echo "Creating xcframework at $XCFW_DIR..."
mkdir -p "$HEADERS_DIR"

cp "$WORK_DIR/libverity.a" "$MACOS_DIR/libverity.a"
cp "$INCLUDE_DIR/verity_ffi.h" "$HEADERS_DIR/"
cp "$INCLUDE_DIR/verity_ffi_raw.h" "$HEADERS_DIR/"
cp "$DISPATCHER_DIR/include/verity_ffi.h" "$HEADERS_DIR/" 2>/dev/null || true

# Write Info.plist
cat > "$XCFW_DIR/Info.plist" << 'PLIST'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>AvailableLibraries</key>
    <array>
        <dict>
            <key>BinaryPath</key>
            <string>libverity.a</string>
            <key>HeadersPath</key>
            <string>Headers</string>
            <key>LibraryIdentifier</key>
            <string>macos-arm64</string>
            <key>SupportedArchitectures</key>
            <array>
                <string>arm64</string>
            </array>
            <key>SupportedPlatform</key>
            <string>macos</string>
        </dict>
    </array>
    <key>CFBundlePackageType</key>
    <string>XFWK</string>
    <key>XCFrameworkFormatVersion</key>
    <string>1.0</string>
</dict>
</plist>
PLIST

# Write backends marker
echo "provekit" > "$XCFW_DIR/backends"

echo ""
echo "=== Done! ==="
ls -lh "$MACOS_DIR/libverity.a"
echo ""
echo "xcframework: $XCFW_DIR"
echo ""
echo "Now build the Swift CLI with native backend:"
echo "  cd $SDK_DIR"
echo "  VERITY_SWIFT_SDK_MODE=native swift build"
echo ""
echo "Then run:"
echo "  VERITY_SWIFT_SDK_MODE=native swift run passport-prover --dg1 ... --sod ... --pkp_dir ... --csca_registry ..."
