# 0.2 private runtime bridge

The v313 backup confirms the desktop entry point imports Unicorn directly and
uses ARM registers/hooks through the Python binding. Therefore the Android
bootstrap now embeds Python first, rather than prematurely rewriting the
compatibility runtime.

## Gate A — completed in this tree
Android -> Java -> Chaquopy -> Python call path.

## Gate B — next
Provide an Android arm64 Unicorn native library/binding and make `import unicorn`
succeed inside the embedded Python runtime.

## Gate C
Copy only compatibility-layer Python modules from the private authoritative
working tree, then replace desktop paths/presentation/input with Android
adapters.

No original game binary, DAT, save, DLL, extracted asset or firmware is bundled.
