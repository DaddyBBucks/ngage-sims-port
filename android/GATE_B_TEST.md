# Gate B device test

Success requires all of the following on an arm64 Android device:

1. `System.loadLibrary("unicorn")` succeeds.
2. Python `import unicorn` succeeds.
3. `Uc(UC_ARCH_ARM, UC_MODE_ARM)` succeeds.
4. The embedded ARM32 instructions execute.
5. The result reports `r0=1, r1=2` and `runtime_ready=True`.

Only after these five checks pass should the private N-Gage compatibility
runtime be copied into the Android tree.

This gate uses no game data.
