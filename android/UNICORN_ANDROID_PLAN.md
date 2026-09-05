# Unicorn Android integration — Gate B

## Important architecture fact

The Android device is expected to be arm64-v8a, but the original N-Gage game is
ARM32. These are separate layers:

* host ABI: Android arm64-v8a
* emulator library: libunicorn.so built for Android arm64-v8a
* emulated guest: UC_ARCH_ARM + UC_MODE_ARM (ARM32)

So the game itself does **not** need to be translated to AArch64.

## 0.3 acceptance test

`runtime_probe.py` now creates a UC_ARCH_ARM engine, maps one page, executes two
ARM32 instructions and verifies R0=1 and R1=2. This is intentionally independent
of proprietary game data.

When that succeeds on-device, we have proved:

Android -> Chaquopy Python -> Unicorn Python API -> Android arm64 libunicorn ->
ARM32 guest execution.

## Native packaging target

The next package should contain an arm64-v8a `libunicorn.so` built with the
Android NDK and the matching Unicorn Python package. Do not commit game data.

Preferred source layout:

app/src/main/jniLibs/arm64-v8a/libunicorn.so
app/src/main/python/unicorn/...

The native library must be built from a matching Unicorn release/source tree.
The Python binding and C library version should stay matched.

## Why not fake this with desktop wheels?

Desktop Linux wheels contain host-specific native libraries. Android requires an
Android-targeted ELF shared object. Gate B is therefore a cross-compilation and
packaging task, not simply `pip install unicorn` on the build PC.
