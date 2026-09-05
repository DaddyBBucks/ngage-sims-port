# Research status through v385

This file is a public, source-only summary. It contains addresses, dimensions,
counts, and behavior observations useful for interoperability research, but no
game bytes, extracted assets, screenshots, saves, or proprietary payloads.

## Compatibility runtime

The project is a game-specific compatibility runtime. Original ARM32 game logic
continues to execute under Unicorn while Symbian/platform behavior is supplied
or instrumented by Python. The long-term approach is incremental replacement:
keep the ARM path as the oracle, implement one understood subsystem on the host,
compare, then retire only what has achieved parity.

By the v357 line, previously experimental global-buffer and gate patches had
been retired from the canonical route after the underlying runtime behavior was
identified. A redraw sink also removed null-PC redraw notification calls without
changing measured frame output.

## Archive / resource research (v371-v373)

The resource archive layout was independently mapped sufficiently for tooling:
497 records were observed; local tools can enumerate and unpack a user-supplied
archive. The runtime gained an asset-provider abstraction that can serve a
locally unpacked directory. The public repository contains only parser/provider
code; unpacked records and archive metadata copied from a game file are excluded.

A short-read semantic bug in the directory provider was identified: a short
read must write only the bytes actually available rather than zero-padding the
caller's destination. Correcting that behavior allowed the runtime to operate
with a local extracted-resource provider without requiring the original archive
on that route.

## Native graphics (v375-v377)

A host-side native renderer implements the measured tile/layer path and software
compositor, followed by canonical sprite pixel generation. The ARM renderer is
retained and can be selected as an oracle. Verification/on/off modes exist so
host output can be compared against the original path.

Measured canonical work reported exact frame agreement for validated paths. A
208x208 native viewport was also validated as a clean horizontal extension of
the original 176x208 presentation. Merely enlarging the old framebuffer beyond
that is not treated as proof of additional authored world data.

## Full-region world reconstruction (v378)

A currently loaded outdoor world was observed as one larger map in memory. In
the measured case it was 20x26 metatiles, reconstructing to 640x832 pixels at
native tile scale. An observed interior used 20x16 metatiles (640x512 pixels).

The active region layer-entry array was observed at `0x00990C30`, with entries
spaced by `0xA40`. For the measured layout, the world map pointer is at entry+4,
the metatile table pointer at entry+8, and metatile width/height at
entry+0x14/+0x16.

This is data-level reconstruction of the loaded region, not framebuffer
upscaling. The active-region PNG work deliberately exports background/world
layers only; Sims, NPC sprites, sprite-pipeline objects, and HUD are not claimed
to be part of that image.

## Entity and OAM research (v379)

The sprite/OAM pipeline was traced through the producer, slot writer,
shadow-to-live copy, and list builder. Region-space object coordinates can be
read from linked entity records directly, so the original OAM 9-bit screen
coordinate representation does not have to define what exists in the wider
region.

In one measured frame, 37 entity records were present while only a subset were
inside the original screen/OAM view. Off-screen entity positions were observed
to update. This does **not** prove every off-screen AI behavior runs at the same
cadence as an on-screen entity; rendering visibility and simulation rate remain
separate questions.

## Sprite definition work (v380-v383)

The sprite definition frame table and 4-byte piece format were mapped far enough
to build an experimental OAM-free region-space sprite renderer. Main/simple
sprite-state parsing achieved parity for the measured main producer calls.

The second, layered caller uses four 12-byte records and a selector-driven
sprite-definition lookup. Captured producer evidence showed valid layer records
with record byte 0 equal to zero. Therefore byte0 bit0 is **not** an enable gate
on this path; the corrected parser filters on the selector field instead.

Important: that source correction is evidence-based but has not yet been rerun
through the complete producer-input parity test. The last pre-fix measurement
was 111 matched / 189 producer calls, with all remaining 78 classified as
`layered_no_state`. The next step is to rerun that test, then proceed to
per-piece/OAM parity before claiming complete full-region sprite rendering.

## Active-region PNG milestone (v385)

The current active-region tool loads a disposable copy of a user-supplied save,
follows the measured load-game route, waits for Module 1, snapshots active
map/metatile/VRAM/palette state, and reconstructs the full background/world
image locally. Generated PNG/JSON outputs are not distribution material.

## Current graphics priority

The graphics milestone is not complete until region-space sprite state and
piece generation are verified against the original producer/OAM path. Intended
order:

1. rerun v383 producer-input parity with the layered-gate correction;
2. compare generated pieces/OAM attributes and positions;
3. achieve visible-frame sprite parity;
4. connect verified region-space sprites to expanded region presentation;
5. only then move on to later subsystems such as audio.
