# Public release audit

Updated for the v385 source/research milestone.

## Release model

The public tree contains original compatibility-layer source, research tooling,
interoperability notes, and independently measured constants. Private repository
history is not copied into the public tree.

## Included

- Original Python harness and compatibility-layer source
- Original research instrumentation and archive-analysis utility source
- Independently produced import/address/ordinal mapping
- Dependency declarations and public-facing documentation
- MIT license for original project material

## Excluded

- Game executable and all other game binaries
- Resource archives, save files, ROM/firmware images, Symbian/N-Gage DLLs
- IDA/Ghidra databases and private analysis workspaces
- Extracted game assets and game-derived cache payloads
- Framebuffer/memory dumps, screenshots, videos, audio, raw logs and outputs
- Historical private reports and private Git history

## v385 checks

- Included Python source was syntax-compiled during package preparation.
- Source was scanned for common personal-name/e-mail/cloud-ID/host-path patterns.
- Source was scanned for suspicious embedded payload/credential patterns.
- Restricted binary/game-data extensions were excluded.
- Generated region PNGs, saves, extracted records, cache data, and analysis databases remain outside Git.

## Residual considerations

This is a technical publication audit, not legal advice or a legal guarantee.
Numeric addresses, ordinals, archive layouts, dimensions, counts, and behavioral
descriptions are retained as independently produced interoperability facts.

The code's MIT license applies only to original material in this repository. It
does not grant rights to any third-party game, firmware, asset, trademark, or
locally supplied input.
