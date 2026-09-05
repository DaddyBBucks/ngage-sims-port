# N-Gage Sims Compatibility Research

An independent, fan-made interoperability and reverse-engineering research
project studying the ARM/Symbian behavior of the N-Gage edition of *The Sims:
Bustin' Out*.

This repository contains original Python compatibility-layer code,
instrumentation, native rendering experiments, and research tools. It does
**not** contain the game, game assets, firmware, system libraries, save files,
extracted resources, screenshots, or links/instructions for obtaining them.

## Research progress since the initial public source release

The initial public commit (`09f76f0`, 2026-08-26) represented an earlier
compatibility harness. Research has since advanced through the v385 milestone.
The important findings include:

- normal gameplay is reached in the working research runtime while original ARM
  game logic remains the behavior oracle;
- several previously required compatibility patches were measured and retired
  after their underlying platform behavior was reproduced;
- the resource archive layout was documented and user-supplied archives can be
  inspected locally without distributing their contents;
- tile/layer composition and canonical sprite pixel generation have host-side
  native implementations with ARM-path verification modes;
- a validated 208x208 viewport path extends the original 176x208 presentation;
- the currently loaded world region can be reconstructed directly from runtime
  map/metatile data rather than by scaling the N-Gage framebuffer;
- region-space entity coordinates and the OAM producer pipeline have been
  traced, enabling work toward rendering entities beyond the original OAM
  viewport limit;
- an active-save region tool can reconstruct the full currently loaded
  background/world map locally.

See `RESEARCH_STATUS.md` for measured details, addresses, current limitations,
and the next graphics milestone.

## Current public-source scope

The repository is intended for interoperability research and peer review, not
as a finished Android port or a generic N-Gage emulator. Newer v378-v385
research tools and region/sprite components are being published incrementally
so other developers can inspect and reproduce the findings without any game
payload being distributed.

The full-region sprite path is **not yet verified complete**. The v383
layered-sprite parser has an evidence-based source correction, but a fresh
end-to-end parity run is still required before complete full-region sprite
rendering is claimed.

Audio work is not part of this milestone.

## Requirements

Python dependencies are listed in `requirements.txt`. No dependency source is
vendored.

```bash
python -m pip install -r requirements.txt
```

Runtime experiments require user-supplied local game inputs. Keep all such
material outside Git. See `ASSETS_REQUIRED.md`.

## Repository layout

- `run.py` — public compatibility/research harness
- `runtime/` — compatibility services and runtime components
- `patches.py` — named compatibility/experimental patches
- `tools/` — public research utilities
- `research_v385/` — curated source-only v378-v385 research snapshot
- `RESEARCH_STATUS.md` — concise evidence/status ledger through v385
- `PUBLIC_RELEASE_AUDIT.md` — license-clean and identity-clean release checks
- `LEGAL.md` / `ASSETS_REQUIRED.md` — contribution and local-input boundaries

## Research philosophy

The project keeps the original ARM execution path as an oracle while replacing
well-understood high-frequency subsystems one at a time. A host-side
implementation is considered trustworthy only after it is compared against the
original path or otherwise backed by reproducible runtime evidence.

## Legal / contribution boundary

Do not submit game binaries, ROMs, firmware, DLLs, saves, screenshots,
extracted resources, derived cache payloads, or links to them. The MIT license
covers only original project code and documentation. Read `LEGAL.md`,
`ASSETS_REQUIRED.md`, `THIRD_PARTY_NOTICES.md`, and `PRIVACY.md` before
contributing.
