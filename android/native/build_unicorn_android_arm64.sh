#!/usr/bin/env bash
set -euo pipefail
: "${ANDROID_NDK_HOME:?Set ANDROID_NDK_HOME}"
UC_SRC="${1:?usage: $0 /path/to/unicorn-source}"
OUT="${2:-../app/src/main/jniLibs/arm64-v8a}"
BUILD="${3:-./build-unicorn-arm64}"
mkdir -p "$BUILD" "$OUT"
cmake -S "$UC_SRC" -B "$BUILD" \
  -DCMAKE_TOOLCHAIN_FILE="$ANDROID_NDK_HOME/build/cmake/android.toolchain.cmake" \
  -DANDROID_ABI=arm64-v8a \
  -DANDROID_PLATFORM=android-26 \
  -DCMAKE_BUILD_TYPE=Release \
  -DUNICORN_BUILD_TESTS=OFF
cmake --build "$BUILD" --parallel
LIB="$(find "$BUILD" -name 'libunicorn.so' -type f | head -n 1)"
test -n "$LIB"
cp "$LIB" "$OUT/libunicorn.so"
echo "Installed: $OUT/libunicorn.so"
