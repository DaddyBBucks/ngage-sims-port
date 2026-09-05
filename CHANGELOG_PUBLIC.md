# Public research changelog

Base public commit: `09f76f047c56f7e03a66e178c0bbf53823f3ab13` (`Initial public source release`, 2026-08-26).

## v344-v357

- Identified the expensive language-record decode and developed a verified cache path.
- Implemented a real time source for previously missing Symbian time behavior.
- Retired several experimental compatibility patches after reproducing the underlying behavior.
- Confirmed the framebuffer address is dynamic rather than a fixed allocation.

## v358-v369

- Mapped the original 176x208 rendering geometry and stride assumptions.
- Validated a clean 208x208 horizontal viewport path.
- Determined that simply extending the legacy framebuffer farther does not reveal arbitrary authored world data.
- Separated HUD behavior from world-view assumptions.

## v371-v373

- Mapped the DTRZ resource archive sufficiently for local listing/unpacking tools.
- Added a directory-backed asset-provider path.
- Fixed short-read semantics so local extracted resources can be served without corrupting adjacent guest memory.

## v375-v377

- Added host-side native tile/layer rendering and software composition.
- Added canonical native sprite pixel generation with ARM-path verification.
- Added variable-viewport native-renderer work while retaining the ARM renderer as an oracle.

## v378-v380

- Reconstructed the complete currently loaded region directly from map/metatile data (measured outdoor case 640x832; measured interior 640x512).
- Traced entity region-space coordinates and the OAM producer pipeline.
- Added an experimental region presentation path and began OAM-free sprite-definition work.

## v381-v383

- Refined sprite state, flip, piece, and layered-record research.
- Main/simple producer-state parsing matched measured calls.
- Captured evidence showed layered record byte0 bit0 is not an enable gate; the parser correction requires a fresh complete parity run before full-region sprite rendering is claimed complete.

## v385

- Added a save-driven active-region background/world reconstruction workflow.
- Confirmed coherent full loaded-region reconstruction during an actual gameplay save route.
- Current graphics priority remains sprite producer/piece/OAM parity before moving to audio.
