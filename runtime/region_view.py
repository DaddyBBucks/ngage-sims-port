"""v380 EXPERIMENTAL region viewer -- disabled unless explicitly selected.

The background is reconstructed from the loaded region data instead of the
176x208 N-Gage viewport. Typical observed regions are 640x832 outdoors and
640x512 indoors. Game logic, AI, collision and camera remain in the original
ARM path; this module is a viewer.

Sprite source in this v380 path is live OAM converted to region space using
region = OAM + camera. That source is intentionally documented as incomplete:
off-screen entities not emitted to OAM cannot appear in the expanded view.
"""
import struct
import numpy as np

ENTRY_ARRAY = 0x00990C30
ENTRY_SIZE = 0xA40
G_VRAM_PTR = 0x4B6EB8
G_BGPAL_PTR = 0x4B6EBC
G_OBJPAL_PTR = 0x4B6EC4
G_OAM_PTR = 0x4B6EC8
OBJ_SIZE_TABLE = 0x008D1D38
SPRITE_TILE_BANK = 0x10000
MODULE_INDEX_VA = 0xA16AF4

VIEWS = [("176x208 canonical", 176, 208),
         ("208x208 verified", 208, 208),
         ("352x288 expanded", 352, 288),
         ("full region", 0, 0)]


def _u32(uc, va):
    return struct.unpack("<I", uc.mem_read(va, 4))[0]


def _i32(uc, va):
    return struct.unpack("<i", uc.mem_read(va, 4))[0]


def _u16(uc, va):
    return struct.unpack("<H", uc.mem_read(va, 2))[0]


def _decode_tiles(chars, ids, pal):
    th, tw = ids.shape
    out = np.zeros((th * 8, tw * 8), dtype=np.uint16)
    msk = np.zeros((th * 8, tw * 8), dtype=bool)
    cache = {}
    shifts = (4 * np.arange(8, dtype=np.uint32))[None, :]
    for ty in range(th):
        for tx in range(tw):
            ent = int(ids[ty, tx])
            got = cache.get(ent)
            if got is None:
                tid = ent & 0x3FF
                raw = chars[tid * 32:tid * 32 + 32]
                if len(raw) < 32:
                    cache[ent] = None
                    continue
                idx = ((np.frombuffer(raw, dtype="<u4")[:, None] >> shifts)
                       & 0xF).astype(np.uint8)
                if (ent >> 10) & 1:
                    idx = idx[:, ::-1]
                if (ent >> 11) & 1:
                    idx = idx[::-1, :]
                p = (ent >> 12) & 0xF
                got = (pal[p * 16:(p + 1) * 16][idx], idx != 0)
                cache[ent] = got
            if got is None:
                continue
            out[ty * 8:ty * 8 + 8, tx * 8:tx * 8 + 8] = got[0]
            msk[ty * 8:ty * 8 + 8, tx * 8:tx * 8 + 8] = got[1]
    return out, msk


class RegionRenderer:
    def __init__(self):
        self.key = None
        self.image = None
        self.size = (0, 0)
        self.layers = 0

    def region_key(self, uc):
        try:
            ks = []
            for i in range(4):
                E = ENTRY_ARRAY + i * ENTRY_SIZE + 4
                ks.append((_u32(uc, E + 4), _u16(uc, E + 0x14),
                           _u16(uc, E + 0x16)))
            return tuple(ks)
        except Exception:
            return None

    def camera(self, uc):
        E = ENTRY_ARRAY + 4
        return (_i32(uc, E + 0x18), _i32(uc, E + 0x1C))

    def build(self, uc):
        key = self.region_key(uc)
        if key is None:
            return False
        if key == self.key and self.image is not None:
            return True
        vram = _u32(uc, G_VRAM_PTR)
        pal = np.frombuffer(bytes(uc.mem_read(_u32(uc, G_BGPAL_PTR), 512)),
                            dtype="<u2")
        banks = {}
        layers = []
        for i in range(4):
            base = ENTRY_ARRAY + i * ENTRY_SIZE
            E = base + 4
            mapptr = _u32(uc, E + 4)
            tabptr = _u32(uc, E + 8)
            W, H = _u16(uc, E + 0x14), _u16(uc, E + 0x16)
            e0 = _u32(uc, E)
            if not (mapptr and tabptr and 0 < W <= 256 and 0 < H <= 256):
                continue
            d = bytes(uc.mem_read(e0, 2))
            bank = (d[0] << 12) & 0xC000
            if bank not in banks:
                banks[bank] = bytes(uc.mem_read(vram + bank, 0x8000))
            cells = np.frombuffer(bytes(uc.mem_read(mapptr + 4, W * H * 2)),
                                  dtype="<u2").reshape(H, W)
            nmax = int(cells.max())
            table = np.frombuffer(
                bytes(uc.mem_read(tabptr + 4, (nmax + 1) * 32)), dtype="<u2")
            tw, th = W * 4, H * 4
            ids = np.zeros((th, tw), dtype="<u2")
            for my in range(H):
                for mx in range(W):
                    rec = int(cells[my, mx]) * 16
                    blk = table[rec:rec + 16]
                    if blk.size == 16:
                        ids[my * 4:my * 4 + 4,
                            mx * 4:mx * 4 + 4] = blk.reshape(4, 4)
            col, msk = _decode_tiles(banks[bank], ids, pal)
            layers.append((d[1] & 0x1F, col, msk))
        if not layers:
            return False
        layers.sort(key=lambda L: -L[0])
        h, w = layers[0][1].shape
        comp = np.zeros((h, w), dtype=np.uint16)
        for _blk, col, msk in layers:
            comp[msk] = col[msk]
        self.image = comp
        self.size = (w, h)
        self.layers = len(layers)
        self.key = key
        return True

    def draw_sprites(self, uc, canvas, ox, oy):
        try:
            oam_base = _u32(uc, G_OAM_PTR)
            oam = bytes(uc.mem_read(oam_base, 1024))
            vram = _u32(uc, G_VRAM_PTR)
            objpal = bytes(uc.mem_read(_u32(uc, G_OBJPAL_PTR), 512))
            sizes = bytes(uc.mem_read(OBJ_SIZE_TABLE, 64))
        except Exception:
            return 0
        cam = self.camera(uc)
        ch, cw = canvas.shape
        shifts = (4 * np.arange(8, dtype=np.uint32))[None, :]
        drawn = 0
        for s in range(128):
            e = oam[s * 8:s * 8 + 8]
            mode = e[1] & 3
            if mode != 0 or (e[1] & 0x20):
                continue
            shape = (e[1] >> 6) & 3
            size = (e[3] >> 6) & 3
            v = struct.unpack_from("<I", sizes, 4 * (shape * 4 + size))[0]
            W, H = v & 0xFFFF, (v >> 16) & 0xFFFF
            if not W or not H:
                continue
            xr = (e[2] | (e[3] << 8)) & 0x1FF
            X = xr - 0x200 if (xr & 0x100) else xr
            Y = e[0] - 0x100 if e[0] > 0xD0 else e[0]
            fx, fy = (e[3] >> 4) & 1, (e[3] >> 5) & 1
            tile0 = struct.unpack_from("<H", e, 4)[0] & 0x3FF
            palno = e[5] >> 4
            pal = np.frombuffer(objpal[palno * 32:palno * 32 + 32],
                                dtype="<u2")
            rx, ry = X + cam[0], Y + cam[1]
            for row in range(H):
                dy = (((H - 1 - row) if fy else row) * 8) + ry - oy
                sl = (tile0 + row * W) & 0xFFFF
                for col in range(W):
                    dx = (((W - 1 - col) if fx else col) * 8) + rx - ox
                    tid = (sl + col) & 0xFFFF
                    if dx + 8 <= 0 or dx >= cw or dy + 8 <= 0 or dy >= ch:
                        continue
                    try:
                        raw = bytes(uc.mem_read(
                            vram + SPRITE_TILE_BANK + (tid << 5), 32))
                    except Exception:
                        continue
                    idx = ((np.frombuffer(raw, dtype="<u4")[:, None] >> shifts)
                           & 0xF).astype(np.uint8)
                    if fx:
                        idx = idx[:, ::-1]
                    if fy:
                        idx = idx[::-1, :]
                    x0, x1 = max(dx, 0), min(dx + 8, cw)
                    y0, y1 = max(dy, 0), min(dy + 8, ch)
                    sub = idx[y0 - dy:y1 - dy, x0 - dx:x1 - dx]
                    m = sub != 0
                    if not m.any():
                        continue
                    canvas[y0:y1, x0:x1][m] = pal[sub][m]
                    drawn += 1
        return drawn

    def oam_visible(self, uc):
        try:
            oam = bytes(uc.mem_read(_u32(uc, G_OAM_PTR), 1024))
        except Exception:
            return 0
        return sum(1 for s in range(128) if (oam[s * 8 + 1] & 3) == 0)

    def entity_count(self, uc, head=0x0093CCB8):
        n, cur, seen = 0, head, set()
        while cur and cur not in seen and n < 512:
            seen.add(cur)
            try:
                cur = _u32(uc, cur)
            except Exception:
                break
            n += 1
        return n


def make_presenter(base_cls, scale=3, max_frames=0):
    import pygame

    class RegionViewPresenter(base_cls):
        kind = "region-view"

        def __init__(self, **kw):
            super().__init__(**kw)
            self.rr = RegionRenderer()
            self.view = 2
            self.zoom = 1.0
            self.debug = True
            self.win_w, self.win_h = 704, 576
            self.window = pygame.display.set_mode((self.win_w, self.win_h))
            pygame.display.set_caption(
                "N-Gage Sims -- experimental region view (F1-F4, +/-, F10)")
            try:
                self.font = pygame.font.SysFont("consolas,monospace", 14)
            except Exception:
                self.font = pygame.font.Font(None, 16)
            self._uc = None
            self._info = {}
            import os as _os
            self._shot = _os.environ.get("REGION_VIEW_SHOT")
            self._shot_at = int(_os.environ.get("REGION_VIEW_SHOT_AT", "60"))

        def poll_input(self):
            evts = super().poll_input()
            keys = pygame.key.get_pressed()
            for k, idx in ((pygame.K_F1, 0), (pygame.K_F2, 1),
                           (pygame.K_F3, 2), (pygame.K_F4, 3)):
                if keys[k]:
                    self.view = idx
            if keys[pygame.K_KP_PLUS] or keys[pygame.K_EQUALS]:
                self.zoom = min(4.0, self.zoom * 1.03)
            if keys[pygame.K_KP_MINUS] or keys[pygame.K_MINUS]:
                self.zoom = max(0.25, self.zoom / 1.03)
            if keys[pygame.K_F10]:
                self._dbg_edge = True
            elif getattr(self, "_dbg_edge", False):
                self._dbg_edge = False
                self.debug = not self.debug
            return evts

        def present(self, uc, insn, module, boundary_pc):
            self._uc = uc
            self.frames_seen += 1
            if self.closed:
                return False
            try:
                ok = module == 1 and self.rr.build(uc)
            except Exception:
                ok = False
            if not ok:
                return super().present(uc, insn, module, boundary_pc)
            self.frames_presented += 1
            self._draw(uc)
            return True

        def _draw(self, uc):
            rr = self.rr
            rw, rh = rr.size
            cam = rr.camera(uc)
            name, vw, vh = VIEWS[self.view]
            if vw == 0:
                vw, vh = rw, rh
            vw = max(32, min(rw, int(vw / self.zoom)))
            vh = max(32, min(rh, int(vh / self.zoom)))
            ox = int(cam[0] + 88 - vw // 2)
            oy = int(cam[1] + 104 - vh // 2)
            ox = max(0, min(rw - vw, ox))
            oy = max(0, min(rh - vh, oy))
            canvas = rr.image[oy:oy + vh, ox:ox + vw].copy()
            sprites = rr.draw_sprites(uc, canvas, ox, oy)
            v = canvas.astype(np.uint32)
            rgb = np.stack([((v >> 8) & 15) * 17,
                            ((v >> 4) & 15) * 17,
                            (v & 15) * 17], axis=-1).astype(np.uint8)
            surf = pygame.image.frombuffer(
                np.ascontiguousarray(rgb).tobytes(), (vw, vh), "RGB")
            k = min(self.win_w / vw, self.win_h / vh)
            dw, dh = max(1, int(vw * k)), max(1, int(vh * k))
            surf = pygame.transform.scale(surf, (dw, dh))
            self.window.fill((16, 16, 20))
            self.window.blit(surf, ((self.win_w - dw) // 2,
                                    (self.win_h - dh) // 2))
            self._info = {
                "REGION": "%dx%d (%d layers)" % (rw, rh, rr.layers),
                "CAMERA": "%d,%d" % cam,
                "VIEW": "%s -> %dx%d world px" % (name, vw, vh),
                "ZOOM": "%.2f" % self.zoom,
                "ENTITIES": str(rr.entity_count(uc)),
                "OAM": str(rr.oam_visible(uc)),
                "SPRITE BLIT": str(sprites),
                "SPRITE SOURCE": "OAM fallback; off-screen entities omitted",
                "HUD": "disabled in experimental region view",
            }
            if self.debug:
                y = 6
                for kk, vv in self._info.items():
                    img = self.font.render("%-13s %s" % (kk + ":", vv), True,
                                           (235, 235, 240), (16, 16, 20))
                    self.window.blit(img, (8, y))
                    y += 17
            pygame.display.flip()
            if self._shot and self.frames_presented == self._shot_at:
                try:
                    pygame.image.save(self.window, self._shot)
                    print("[region] screenshot saved: %s" % self._shot,
                          flush=True)
                except Exception as exc:
                    print("[region] screenshot failed: %r" % (exc,),
                          flush=True)

    return RegionViewPresenter(scale=scale, max_frames=max_frames)
