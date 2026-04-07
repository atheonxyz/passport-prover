#!/bin/bash
set -euo pipefail

# Build libverity_jni.dylib for macOS (Apple Silicon) with ProveKit backend.
#
# Prerequisites:
#   1. ProveKit must be built: cd <provekit> && cargo build --release -p provekit-ffi
#   2. JDK with JNI headers (openjdk@17 via Homebrew).
#
# Usage:
#   bash scripts/build-macos-jni.sh

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
SDK_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
VERITY_DIR="${VERITY_DIR:-$(cd "$SDK_DIR/../../../verity" && pwd)}"
PROVEKIT_ROOT="${PROVEKIT_ROOT:-$(cd "$SDK_DIR/../../../provekit" && pwd)}"

CORE_DIR="$VERITY_DIR/core"
DISPATCHER_DIR="$CORE_DIR/dispatcher"
INCLUDE_DIR="$CORE_DIR/include"
JNI_SRC="$VERITY_DIR/sdks/kotlin/src/main/jni"
OUTPUT_DIR="$SDK_DIR/native"

# Find JDK headers
if [ -d "/opt/homebrew/Cellar/openjdk@17" ]; then
    JDK_HOME="$(ls -d /opt/homebrew/Cellar/openjdk@17/*/libexec/openjdk.jdk/Contents/Home 2>/dev/null | tail -1)"
elif [ -n "${JAVA_HOME:-}" ]; then
    JDK_HOME="$JAVA_HOME"
else
    echo "ERROR: Cannot find JDK. Set JAVA_HOME or install openjdk@17."
    exit 1
fi

JNI_INCLUDE="$JDK_HOME/include"
JNI_INCLUDE_DARWIN="$JNI_INCLUDE/darwin"

if [ ! -f "$JNI_INCLUDE/jni.h" ]; then
    echo "ERROR: jni.h not found at $JNI_INCLUDE/jni.h"
    exit 1
fi

# ProveKit FFI static library
PK_FFI="$PROVEKIT_ROOT/target/release/libprovekit_ffi.a"
if [ ! -f "$PK_FFI" ]; then
    echo "ERROR: ProveKit FFI not found at $PK_FFI"
    echo "Build it first: cd $PROVEKIT_ROOT && cargo build --release -p provekit-ffi"
    exit 1
fi

echo "=== Building libverity_jni.dylib for macOS (ProveKit) ==="
echo "Verity dir:    $VERITY_DIR"
echo "ProveKit:      $PK_FFI"
echo "JDK:           $JDK_HOME"
echo ""

WORK_DIR=$(mktemp -d)
trap "rm -rf $WORK_DIR" EXIT

CC=clang

# Compile dispatch layer
echo "Compiling dispatch layer..."
$CC -c -I"$INCLUDE_DIR" -I"$DISPATCHER_DIR" -fPIC \
    "$DISPATCHER_DIR/verity_dispatch.c" -o "$WORK_DIR/verity_dispatch.o"

# Compile ProveKit backend
echo "Compiling PK backend..."
$CC -c -I"$INCLUDE_DIR" -I"$DISPATCHER_DIR" -fPIC \
    "$DISPATCHER_DIR/backends/pk_backend.c" -o "$WORK_DIR/pk_backend.o"

# Compile JNI bridge
echo "Compiling JNI bridge..."
$CC -c -I"$INCLUDE_DIR" -I"$JNI_INCLUDE" -I"$JNI_INCLUDE_DARWIN" -fPIC \
    "$JNI_SRC/verity_jni.c" -o "$WORK_DIR/verity_jni.o"

# Collect ProveKit build deps (blake3, ring, lzma, etc.)
EXTRA_LIBS=""
PK_BUILD_DIR="$PROVEKIT_ROOT/target/release/build"
if [ -d "$PK_BUILD_DIR" ]; then
    for lib in $(find "$PK_BUILD_DIR" -name "lib*.a" 2>/dev/null); do
        EXTRA_LIBS="$EXTRA_LIBS $lib"
    done
fi

# Link into shared library
echo "Linking libverity_jni.dylib..."
mkdir -p "$OUTPUT_DIR"

$CC -shared -dynamiclib \
    -o "$OUTPUT_DIR/libverity_jni.dylib" \
    "$WORK_DIR/verity_dispatch.o" \
    "$WORK_DIR/pk_backend.o" \
    "$WORK_DIR/verity_jni.o" \
    -Wl,-force_load,"$PK_FFI" \
    $EXTRA_LIBS \
    -lc++ -framework Security -framework CoreFoundation \
    -Wl,-undefined,dynamic_lookup

echo ""
echo "=== Done! ==="
ls -lh "$OUTPUT_DIR/libverity_jni.dylib"
echo ""
echo "Run with:"
echo "  java -Djava.library.path=$OUTPUT_DIR -jar build/libs/passport-prover-0.1.0-all.jar ..."
