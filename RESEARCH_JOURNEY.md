# Research Journey — from compatibility harness to full-region rendering

This document explains **how the project reached its current state**, rather
than merely listing the current findings. It is intentionally evidence-driven:
each stage describes the problem being investigated, the experiment or
measurement that changed our understanding, and why that result led to the
next stage.

The project is an interoperability/reverse-engineering effort. It does not
contain or distribute the original game, game assets, firmware, system
libraries, saves, or extracted resources.

## 1. Starting point: make the original ARM program observable

The project began as a game-specific ARM/Symbian compatibility harness. The
original ARM game code executes under Unicorn while Python-side services model
the minimum platform behavior needed to let execution advance.

This was deliberately not designed as a generic N-Gage emulator. The immediate
goal was narrower: preserve the original game code as the behavioral reference,
make its execution deterministic enough to measure, and replace understood
platform/high-frequency paths only after their behavior could be compared.

Early work therefore concentrated on:

- executable loading and guest memory layout;
- imported Symbian/N-Gage APIs;
- input injection and menu navigation;
- asynchronous request behavior;
- frame capture and reproducible execution traces;
- identifying crashes caused by missing platform objects rather than game
  logic itself.

That foundation eventually allowed the runtime to reach normal gameplay with
objects, text, game logic and Sim behavior running through the original ARM
program.

## 2. v344: language/resource decode was dominating startup

Once execution was stable enough to profile, startup contained an unexpectedly
expensive resource/language decode path. Measurement showed one large DTRZ /
range-code decode around `0x40ea44`, producing roughly 218 KiB of data.

A language cache reduced the measured module-1 arrival instruction count from
roughly 117 million to 61 million instructions.

The important lesson was not simply "caching is faster". It separated
**startup/loading cost** from **gameplay rendering cost**. Later graphics work
therefore did not incorrectly attribute runtime FPS limits to the language
path.

## 3. v353–v357: remove compatibility patches by finding their real causes

Several early patches existed because the guest expected Symbian services that
the research runtime did not yet reproduce.

### Redraw / null-PC failure

A recurring jump to PC=0 was traced to redraw-notification virtual calls that
normally terminate in Window Server objects. A small redraw sink with an
appropriate fake vtable reproduced the missing platform endpoint.

After this change the observed PC=0 hits fell from hundreds to zero while the
captured frame sequence remained identical.

The lesson was important for the rest of the project: when a patch makes the
game run, treat it as a **clue**, not as the final implementation.

### Gate patches

Two other gates were eventually traced to a missing shared `RChunk`-style
app-manager block rather than to focus/input state. Reproducing the underlying
shared state allowed both patches to be retired.

By v357 the project had a much cleaner canonical baseline. This baseline became
the oracle used by later native-renderer comparisons.

## 4. v356–v369: understand the framebuffer before trying widescreen

A former `global_buffer_seed` workaround was shown to be heap-layout filler,
not meaningful game state. Turning it on/off moved the framebuffer allocation
but did not change the rendered content. This established an essential rule:
**the framebuffer address is dynamic** and must be read through the game's
pointer rather than hard-coded.

The next question was whether the 176x208 N-Gage presentation could be widened
without stretching pixels.

Experiments showed:

- the canonical logical screen is 176x208;
- a clean 208x208 path can expose 32 additional horizontal pixels of real
  authored content;
- simply increasing the width farther does not automatically expose arbitrary
  additional world data;
- the bottom 32 pixels are the HUD, not hidden vertical world space;
- a shared viewport/origin value also participates in unrelated flag logic, so
  globally rewriting it is unsafe.

This changed the project's direction. The correct long-term solution was not
"make the old framebuffer enormous". We needed to understand the **world data
beneath the viewport**.

## 5. v370–v373: document the engine and remove runtime dependence on the DAT

The next stage mapped enough of the engine's graphics/data contracts to stop
treating the program as an opaque framebuffer generator.

Among the documented structures were:

- executable CODE/DATA/BSS layout;
- dynamic framebuffer pointer;
- 4bpp 8x8 tile representation;
- tile-map entry bits for tile index, flips and palette;
- scrolling layer memory and 32/64-tile screenblock addressing;
- map-copy behavior and the HUD tile map.

In parallel, the game's DTRZ archive was studied. The archive contained 497
records with raw, StreamB and one special record type. A complete local
unpacker was produced and all 497 records were accounted for in the research
environment.

A first attempt to serve extracted files directly caused a crash. The crash was
not evidence that the original archive performed hidden magic: the replacement
provider had incorrectly padded short reads with zeroes, overwriting live guest
memory. Reproducing normal `fread` semantics — write only the bytes actually
available and return that count — fixed the problem.

By v373 the measured route could run with the directory provider and without
opening the real DAT at runtime. This was a major architectural step: archive
storage and game execution were now separable.

## 6. v375–v377: move graphics work out of ARM one verified subsystem at a time

With a reliable baseline, high-frequency pixel work became the next target.

### v375 — native tile/layer renderer

Tile/layer composition and the software compositor were implemented on the
host side. Verification compared the native path with the ARM oracle:

- 321/321 measured layer calls matched;
- 56/56 compositor calls matched;
- 25/25 captured frames were pixel-identical.

The measured performance improvement was substantial, from roughly 6.6 FPS to
35.9 FPS in the tested workload. This confirmed that emulated pixel work — not
all ARM game logic — was the dominant cost.

### v376 — native canonical sprite pixels

Canonical sprite pixel generation was then moved host-side while keeping the
ARM path available as the reference. The measured sprite verification run
matched 819/819 cases with no fallback, and the 25-frame ARM/native comparison
remained pixel-identical.

This did **not** mean that full-region sprites were solved. It meant the
on-screen/canonical sprite pixel path was understood well enough to reproduce.
The distinction becomes important later.

### v377 — variable viewport architecture

The native renderer was changed so that 176 pixels was no longer a structural
assumption. The previously validated 208x208 presentation could now run through
the native graphics path as well.

At this point the remaining widescreen limitation was clearly not the renderer
surface. It was the engine's world/region representation and the source of
entities outside the original OAM viewport.

## 7. v378: the key world-map breakthrough

v378 answered the question that the earlier widescreen experiments could not:
**what exists beyond the N-Gage camera?**

The loaded world was found to be represented as a complete region map rather
than as a stream of tiny screen-sized chunks. A measured outdoor region was
20x26 metatiles. With 4x4 tiles per metatile and 8x8 pixels per tile, that
reconstructs to **640x832 pixels**. A measured interior used 20x16 metatiles,
or **640x512 pixels**.

The region structures expose:

- a layer descriptor;
- world-map metatile IDs;
- a metatile definition table;
- region width/height;
- camera values;
- intermediate layer state.

Using those structures, the project reconstructed an entire currently loaded
region directly to a PNG. This was not framebuffer scaling and not speculative
map stitching: it was the game's authored map data rendered through the
reverse-engineered tile/metatile rules.

This discovery changed the target architecture again. The Android port can
preserve the original region transitions while allowing a camera to show more
or less of the **same loaded region**.

## 8. v379: stop treating OAM as the list of things that exist

The next blocker was obvious in the full-region view: backgrounds could be
rendered outside the original screen, but distant entities were missing because
the old renderer only knew about objects emitted to OAM.

Tracing the sprite pipeline identified:

1. entity/OAM producer `0x4041F4`;
2. slot writer `0x467124`;
3. shadow-to-live copy `0x438774`;
4. list builder `0x449898`.

More importantly, the game maintains region-space entity coordinates directly
in entity records. In one measured frame there were 37 entity records, only
about 11 inside the screen and roughly 12 represented as visible OAM entries.
The remaining entities therefore did not cease to exist simply because the
camera could not see them.

This established the long-term rule for full-region rendering:

> OAM is an oracle for how the original renderer represented visible sprites;
> it must not be the authoritative inventory of world entities.

The entity list plus sprite definitions must ultimately feed the expanded
renderer directly.

This work also showed that region graphics are not simply files inside the
DTRZ DAT. Region data is associated with compressed data embedded in the
executable DATA area. Mapping every region identity to its original embedded
source block remains separate research.

## 9. v380–v383: decode sprite definitions and reproduce producer inputs

An experimental region viewer was added with multiple viewport sizes and zoom.
Its background comes from the v378 region reconstruction. Initially its sprite
source remained OAM, so the tool intentionally could not show entities the
original viewport never emitted.

The sprite-definition format was then progressively decoded:

- frame-offset tables;
- piece count and piece-array location;
- signed 9-bit piece X/Y;
- shape and size;
- tile index/base tile;
- main/simple palette source;
- horizontal and vertical flip behavior;
- alternate/layered sprite records.

Static analysis identified two calls into the same producer from the entity
renderer: a main/simple path and a layered path.

A v383 producer-input verification run observed 189 producer calls. The
main/simple path matched 111 calls. The remaining 78 were all layered calls.
Runtime diagnostics then exposed a parser mistake: the public parser had been
requiring `record.flags & 1`, but valid layered records were observed with
`flags == 0`.

The evidence-based correction is therefore to select the layered record by its
selector without treating bit 0 as an enable gate.

**Current caution:** that source correction still requires a fresh complete
parity run before the project can claim 189/189 producer-input parity. This is
why full-region sprite rendering remains the principal graphics blocker.

## 10. v384–v385: turn region research into a reusable tool

The v378 reconstruction logic was generalized into an active-save region dump
tool. It follows the proven load-game route, takes a temporary copy of the
user's save, waits until gameplay/region state is available, snapshots the
runtime region structures and reconstructs the complete background map.

The tool writes a PNG plus metadata and intentionally excludes HUD and
NPC/Sim/object sprites. This makes its scope unambiguous: it proves complete
background/world reconstruction for the **currently active region**, not the
unfinished full-region entity renderer.

A practical consequence is that regions encountered during normal story
progression can now be archived and compared. A future recorder can detect
region changes by content signatures and log the associated runtime/source
information, which may eventually help solve the embedded region-source map.

## Where the project is now

The project is no longer primarily blocked on "can the game run?" or "can we
see beyond 176x208?".

The current graphics problem is much narrower:

1. re-run v383 producer-input parity after the layered-record correction;
2. compare generated sprite pieces/OAM attributes against the original writer;
3. reach canonical visible sprite framebuffer parity;
4. feed the verified entity-list renderer into expanded/full-region views;
5. prove at least one entity absent from original OAM renders correctly outside
   the original viewport.

Only after that should the remaining graphics integration be considered
complete enough to move the project's main focus to audio and Android product
integration.

See `ROADMAP.md` for the forward plan and `RESEARCH_STATUS.md` for the compact
measurement ledger.