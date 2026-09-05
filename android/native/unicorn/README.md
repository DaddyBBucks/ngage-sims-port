# Android Unicorn dependency

Pinned release: Unicorn 2.1.4.

This directory intentionally contains no prebuilt binary. The build script
downloads the pinned upstream source and cross-builds the Android arm64 shared
library with the Android NDK.

The Python binding is copied from the same source tree into
`app/src/main/python/unicorn`, keeping the API and native library matched.
