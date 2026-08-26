# N-Gage Sims Compatibility Research

An independent, fan-made interoperability and reverse-engineering research
project for studying the ARM/Symbian behavior of the N-Gage edition of
*The Sims: Bustin' Out*.

This repository contains original Python compatibility-layer, instrumentation,
and research-tool source code. It does **not** contain the game, game assets,
N-Gage firmware, Symbian system libraries, save files, extracted resources, or
instructions/links for obtaining them.

This project is not affiliated with, endorsed by, or sponsored by Electronic
Arts, Nokia, Ideaworks, or any other rights holder. Product names and
trademarks belong to their respective owners.

## Requirements

- Python 3.11+
- Packages listed in `requirements.txt`
- A game binary and resource archive obtained by the user from a lawful copy

Install dependencies:

```bash
python -m pip install -r requirements.txt
```

Run with local files kept outside the repository:

```bash
python run.py \
  --binary-file /path/to/local/game-binary \
  --archive-file /path/to/local/thesims.dat \
  --save-file /path/to/disposable/THESIMS.SAV \
  --research
```

The save argument is optional. Always use a disposable copy because the game
may open it for writing. If the required binary is absent, the program exits
with an explanatory error.

## Repository layout

- `run.py`: command-line entry point and Unicorn orchestration
- `runtime/`: compatibility services, input, graphics, archive I/O, and traces
- `patches.py`: named experimental compatibility patches
- `research_v209.py`: observation probes and reproducible input sequences
- `tools/`: archive-research utilities
- `thunk_map.json`: independently produced import address/ordinal mapping

## Current research status

With locally supplied game data, the harness reaches the name-entry module and
renders its alphabet, digits, panels, and Done control. The current narrow
investigation is why the title raster reaches the live framebuffer's upper rows
but is absent from a later displayed frame: overwrite versus invisible
mask/palette output.

## Legal and contribution notes

Read `LEGAL.md`, `ASSETS_REQUIRED.md`, and `THIRD_PARTY_NOTICES.md` before use
or contribution. Do not submit ROMs, firmware, DLLs, game binaries, saves,
screenshots, extracted assets, or derived databases. The MIT license applies
only to the original source and documentation in this repository; it grants no
rights to third-party games, assets, firmware, trademarks, or libraries.
