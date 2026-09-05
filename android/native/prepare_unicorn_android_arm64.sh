#!/usr/bin/env bash
set -euo pipefail

: "${ANDROID_NDK_HOME:?Set ANDROID_NDK_HOME to your Android NDK}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
APP="$(cd "$ROOT/app" && pwd)"
WORK="${1:-$ROOT/.work-unicorn}"
VER="2.1.4"
URL="https://github.com/unicorn-engine/unicorn/archive/refs/tags/${VER}.tar.gz"

mkdir -p "$WORK"
ARCHIVE="$WORK/unicorn-${VER}.tar.gz"
SRC="$WORK/unicorn-${VER}"
BUILD="$WORK/build-arm64"

if [ ! -f "$ARCHIVE" ]; then
  curl -L --fail --retry 3 "$URL" -o "$ARCHIVE"
fi

if [ -n "${UNICORN_SOURCE_SHA256:-}" ]; then
  printf '%s  %s\n' "$UNICORN_SOURCE_SHA256" "$ARCHIVE" | sha256sum -c -
else
  sha256sum "$ARCHIVE" | tee "$WORK/SOURCE_SHA256.txt"
fi

rm -rf "$SRC" "$BUILD"
mkdir -p "$SRC"
tar -xzf "$ARCHIVE" --strip-components=1 -C "$SRC"

cmake -S "$SRC" -B "$BUILD" \
  -DCMAKE_TOOLCHAIN_FILE="$ANDROID_NDK_HOME/build/cmake/android.toolchain.cmake" \
  -DANDROID_ABI=arm64-v8a \
  -DANDROID_PLATFORM=android-26 \
  -DCMAKE_BUILD_TYPE=Release \
  -DBUILD_SHARED_LIBS=ON \
  -DUNICORN_BUILD_TESTS=OFF

cmake --build "$BUILD" --parallel

LIB="$(find "$BUILD" -type f -name libunicorn.so | head -n 1)"
test -n "$LIB"
mkdir -p "$APP/src/main/jniLibs/arm64-v8a"
cp "$LIB" "$APP/src/main/jniLibs/arm64-v8a/libunicorn.so"

PY_SRC="$SRC/bindings/python/unicorn"
test -d "$PY_SRC"
rm -rf "$APP/src/main/python/unicorn"
cp -R "$PY_SRC" "$APP/src/main/python/unicorn"

file "$APP/src/main/jniLibs/arm64-v8a/libunicorn.so" || true
sha256sum "$APP/src/main/jniLibs/arm64-v8a/libunicorn.so" \
  | tee "$WORK/LIBUNICORN_ANDROID_ARM64_SHA256.txt"

echo "Gate B dependency prepared."
