# Project Roadmap

This roadmap describes the path from the current research runtime to a usable
Android port. Status labels are deliberately conservative: a subsystem is
marked **DONE** only when the relevant claim has reproducible evidence behind
it.

## Current position

```text
ARM/Symbian compatibility runtime                 DONE
        |
        v
Canonical gameplay execution                      DONE
        |
        v
Archive/resource understanding                    DONE (core DAT path)
        |
        v
Native tile/layer graphics                        DONE
        |
        v
Native canonical sprite pixel path                DONE
        |
        v
Variable viewport / validated 208x208             DONE
        |
        v
Full loaded-region background reconstruction      DONE
        |
        v
Entity-list / OAM producer understanding          DONE (core path)
        |
        v
Full-region sprite parity                         <-- WE ARE HERE
        |
        v
Complete expanded-region graphics integration
        |
        v
Android frontend / controls / presentation
        |
        v
Audio subsystem
        |
        v
Optimization, compatibility and release hardening
```

## Phase 1 — compatibility foundation — DONE

Goal: execute the original ARM game code in a measurable game-specific runtime.

Completed work includes guest loading/memory, platform imports, input and
asynchronous request modeling, deterministic research routes, frame capture,
and replacement of several early compatibility patches with reproductions of
the underlying platform behavior.

The original ARM path remains the project's behavioral oracle.

## Phase 2 — resource/archive separation — DONE for current needs

Goal: understand the game's archive sufficiently that runtime work is not tied
to opaque archive behavior.

Completed:

- DTRZ archive structure documented;
- all 497 measured records accounted for in the research environment;
- raw and StreamB paths reproduced;
- local directory-provider path validated;
- short-read semantics corrected;
- measured route can run without opening the original DAT when locally
  extracted user-supplied resources are provided.

Later work may still be needed for less-used resource types, but this is not the
current graphics blocker.

## Phase 3 — native canonical graphics — DONE

Goal: remove high-frequency pixel generation from ARM emulation without
changing visual output.

Completed:

- host-side tile/layer renderer;
- host-side compositor;
- host-side canonical sprite pixel generation;
- ARM/native verification modes;
- measured canonical frame parity;
- variable native viewport architecture;
- validated 208x208 clean presentation.

This work demonstrated that the original ARM game logic can remain authoritative
while expensive graphics work migrates to the host.

## Phase 4 — loaded-region renderer — BACKGROUND DONE / SPRITES IN PROGRESS

### 4A. Full-region background — DONE

The currently loaded region can be reconstructed from its world map, metatile
table, descriptors, VRAM and palettes. Measured examples include 640x832 outdoor
and 640x512 interior regions.

The intended product behavior is **not** to stitch every game region into one
continuous world. Original region transitions remain. Once a region is loaded,
the Android camera may pan/zoom over more or less of that region.

### 4B. Full-region entities/sprites — IN PROGRESS — CURRENT BLOCKER

Known:

- region-space entity coordinates are available independently of OAM;
- off-screen entity records exist beyond the original viewport;
- the core OAM producer/writer pipeline is identified;
- main/simple sprite producer inputs matched in the last v383 run;
- layered sprite record selection has a known parser correction;
- sprite piece layout, tile/base tile, palette and flip rules are substantially
  decoded.

Next acceptance gates:

1. **Producer-input parity:** rerun the v383 verifier after removing the invalid
   layered `flags & 1` enable gate. Target is zero unexplained producer-input
   mismatches; 189/189 is expected from the current diagnosis but is **not yet
   claimed**.
2. **Piece/OAM parity:** for every producer call, compare generated piece count,
   X/Y, shape, size, tile, palette and flip attributes against the original OAM
   writer.
3. **Canonical framebuffer parity:** the entity-list renderer must reproduce
   the original visible sprite result with zero unexplained pixel differences.
4. **Expanded-view proof:** demonstrate an entity that is absent from the
   original visible OAM set but correctly appears when the camera/viewport
   includes its region-space position.

Only after these gates pass should full-region sprites be marked DONE.

## Phase 5 — complete graphics integration — NEXT

After sprite parity:

- connect verified entity-list rendering to the expanded region viewer;
- keep HUD/UI in screen space rather than world zoom space;
- finish remaining overlay/fade/UI composition paths as necessary;
- implement dynamic camera pan/zoom without changing world scale or stretching
  source pixels;
- preserve original region transitions and game logic;
- verify interiors, outdoor lots, menus and transitions;
- ensure original 176x208 and clean 208x208 modes remain useful regression
  references.

**Graphics should be closed as a coherent milestone before audio becomes the
main workstream.** This avoids repeatedly switching between unfinished major
subsystems.

## Phase 6 — Android frontend — PARTLY PREPARED / NOT COMPLETE

Target architecture:

```text
original ARM game logic
        |
        +-- game/platform compatibility services
        |
        +-- native world/entity renderer
        |       |
        |       +-- loaded region -> off-screen render target
        |       +-- camera / dynamic zoom
        |       +-- screen-space HUD
        |
        +-- Android presentation + input
```

Planned Android-facing work:

- native/device presentation path;
- touch controls and physical controller mapping;
- N-Gage-inspired optional screen overlay/theme;
- menu/frontend suitable for launching the game and configuring controls;
- user-facing import/selection flow for legally obtained local game data;
- save handling;
- dynamic zoom controls (touch gesture and/or mapped buttons);
- resolution/aspect handling across phones and handhelds.

The public repository must continue to contain **no original game data**. Any
user-facing importer must operate on files supplied locally by the user.

## Phase 7 — audio — LATER, AFTER GRAPHICS

Audio is intentionally deferred until the graphics milestone above is coherent.

Expected work includes tracing the game's audio API/resource paths, reproducing
the required Symbian audio behavior on the host, identifying timing/mixing
requirements, and integrating Android audio output while keeping gameplay
timing stable.

No claim of solved audio is made at the current milestone.

## Phase 8 — performance and Unicorn reduction — ONGOING / LATER

Unicorn is not expected to disappear in one rewrite. The strategy is gradual:

1. identify a high-frequency or platform-specific subsystem;
2. document its contract;
3. implement it host-side;
4. compare it with the ARM oracle;
5. switch the verified host implementation into the normal path;
6. retain the ARM implementation as a regression/reference path where useful.

Graphics has already demonstrated this strategy successfully.

Potential later candidates include additional platform services and other
well-understood hot paths. Game logic, AI, collision and state should not be
rewritten merely for the sake of reducing the Unicorn percentage.

## Phase 9 — release hardening — LATER

Before a user-facing release:

- repeatable clean setup from user-supplied inputs;
- robust error messages for missing/incorrect files;
- save compatibility and corruption testing;
- controller/touch configuration;
- performance profiling on representative Android hardware;
- lifecycle/suspend/resume testing;
- deterministic regression captures;
- license/content/privacy audit of the public tree and release artifacts;
- documentation for contributors and end users.

## Research opportunities for contributors

The highest-value current contribution area is the v383+ sprite pipeline:
layered producer parity, piece/OAM parity and OAM-independent entity rendering.

Other useful parallel research includes mapping loaded region identities back to
the embedded executable DATA source blocks, improving automated region-change
capture, and auditing less-used graphics/UI paths. These should not distract
from the principal acceptance gate: **complete and verified full-region sprite
rendering**.

For the history behind these milestones, see `RESEARCH_JOURNEY.md`. For compact
measured findings and addresses, see `RESEARCH_STATUS.md`.