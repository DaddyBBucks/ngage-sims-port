"""v382: REGION-SPACE NATIVE SPRITE RENDERER.

Sprite'lari OAM'dan DEGIL, dogrudan nesne listesinden ve sprite
tanimindan uretir. Boylece motorun OAM'a hic koymadigi (ekran disindaki)
nesneler de cizilebilir -- OAM'in 9 bitlik koordinat siniri devre disi
kalir.

KANITLANMIS GIRDILER (degistirilmedi, yalnizca uygulandi)
---------------------------------------------------------
v379  nesne listesi: 0x140 baytlik kayitlar, cift yonlu bagli liste
        +0x00 sonraki   +0x04 onceki
        +0x18 region X (16.16)   +0x1C region Y (16.16)
v381  +0xDB  animasyon karesi
      +0xDC -> yapinin +0x04'u = sprite_def
      +0xFE  u16 taban kiremit
      +0x105 bayt & 0x0F = palet   <-- v382'de YANLIS oldugu olculdu
      +0x0D3 bit4 = flipX      (10.350/10.350 gozlemde %100)
v380  sprite_def:
        +0x0A A, +0x0B B, +0x0C kare ofset tablosu (u16/kare)
        kare_taban  = sprite_def + 0x0C + u16[sprite_def+0x0C+kare*2]
        parca_sayisi= byte[kare_taban] & 0x1F
        parca_dizisi= kare_taban + 6*B + 10 + 2*A
v382  DUZELTME: palet nesnenin +0x105'inde DEGIL, +0xD5'inin UST
      nibble'indadir:  palet = byte[nesne+0xD5] >> 4
      (10.350/10.350 gozlemde %100; kayittaki tek aday). v381 paleti
      cagirandaki BASKA bir nesnenin (`r4`) +0x105'inde bulmustu ve
      onu bagli listedeki nesneyle ayni sanmisti -- olculdu: yalnizca
      %31,7 tutuyor.
v382  parcanin 4 bayti TAM olarak cozuldu (0x404360 ve 0x4044A0'den):
        p[0]          X bit0-7
        p[1] bit0     X bit8            -> X = isaretli 9 bit
        p[1] bit1-7   Y bit0-6
        p[2] bit0-1   Y bit7-8          -> Y = isaretli 9 bit
        p[2] bit2-3   boyut (size)
        p[2] bit4-5   sekil (shape)
        p[2] bit6-7   kiremit bit0-1
        p[3]          kiremit bit2-9    -> kiremit += taban_kiremit

KONUMLANDIRMA (v379 §2 ile sayisal olarak dogrulanmis)
------------------------------------------------------
    parca_region_x = nesne_region_x + parca.x
    parca_region_y = nesne_region_y + parca.y
Ekran konumu icin kamera CIKARILIR. Hicbir OAM koordinati kullanilmaz.

VARSAYIM (acikca isaretli)
--------------------------
flip_y = 0. Kanonik oynanista 10.350 gozlemin 10.350'sinde OAM flipY
biti 0 cikti (v381) ve besleyen nesne alani olculemedi. Bu bir
OLCUME DAYALI VARSAYIMDIR, kanit degildir.
"""
import struct

import numpy as np

ENTITY_HEAD_GLOBAL = 0x008D700C
ENTITY_HEAD_FALLBACK = 0x0093CCB8
ENT_NEXT = 0x00
ENT_PREV = 0x04
ENT_RX = 0x18
ENT_RY = 0x1C
ENT_FLIPX = 0x0D3
ENT_FLIPY = 0x0D3
ENT_FRAME = 0x0DB
ENT_SPRDEF_PTR = 0x0DC
ENT_BASETILE = 0x0FE
ENT_PALETTE = 0x0D5
ENT_RENDER_KIND = 0x100
ENT_RENDER_FLAGS = 0x101
ENT_LAYER_BASE = 0x104
ENT_LAYER_STRIDE = 12
ENT_LAYER_SEL_X = 0x134
ENT_LAYER_SEL_Y = 0x135

G_VRAM_PTR = 0x4B6EB8
G_OBJPAL_PTR = 0x4B6EC4
OBJ_SIZE_TABLE = 0x008D1D38
SPRITE_TILE_BANK = 0x10000


def _u8(uc, va):
    return bytes(uc.mem_read(va, 1))[0]


def _u16(uc, va):
    return struct.unpack("<H", uc.mem_read(va, 2))[0]


def _u32(uc, va):
    return struct.unpack("<I", uc.mem_read(va, 4))[0]


def _i32(uc, va):
    return struct.unpack("<i", uc.mem_read(va, 4))[0]


def _sext9(v):
    v &= 0x1FF
    return v - 0x200 if v & 0x100 else v


class RenderSpriteState(object):
    __slots__ = ("va", "region_x", "region_y", "sprite_def", "frame",
                 "base_tile", "palette", "flip_x", "flip_y", "source",
                 "slot", "producer_flags")

    def __init__(self, va, rx, ry, sd, fr, bt, pal, fx, fy=0,
                 source="main", slot=-1, producer_flags=0):
        self.va = va
        self.region_x = rx
        self.region_y = ry
        self.sprite_def = sd
        self.frame = fr
        self.base_tile = bt
        self.palette = pal
        self.flip_x = fx
        self.flip_y = fy
        self.source = source
        self.slot = slot
        self.producer_flags = producer_flags


def _valid_ptr(v):
    return 0x400000 <= v < 0xB00000


def _s8(v):
    return v - 256 if v & 0x80 else v


def _base_xy_flip(uc, va):
    rf = _u8(uc, va + ENT_RENDER_FLAGS)
    fx = (_u8(uc, va + ENT_FLIPX) >> 4) & 1
    fy = ((_u8(uc, va + ENT_FLIPY) >> 5) & 1) | ((rf >> 7) & 1)
    pf = ((rf >> 5) & 1) | (((rf >> 7) & 1) << 1)
    return (_i32(uc, va + ENT_RX) >> 16,
            _i32(uc, va + ENT_RY) >> 16, fx, fy, pf)


def _main_state(uc, va):
    rx, ry, fx, fy, pf = _base_xy_flip(uc, va)
    sdp = _u32(uc, va + ENT_SPRDEF_PTR)
    if not _valid_ptr(sdp):
        return None
    sd = _u32(uc, sdp + 4)
    if not _valid_ptr(sd):
        return None
    bt = _u16(uc, va + ENT_BASETILE)
    if bt == 0xFFFF:
        return None
    return RenderSpriteState(va, rx, ry, sd, _u8(uc, va + ENT_FRAME), bt,
                             _u8(uc, va + ENT_PALETTE) >> 4, fx, fy,
                             "main", -1, pf)


def _layered_states(uc, va):
    rx, ry, fx, fy, pf = _base_xy_flip(uc, va)
    sx = _s8(_u8(uc, va + ENT_LAYER_SEL_X))
    sy = _s8(_u8(uc, va + ENT_LAYER_SEL_Y))
    ent_frame = _u8(uc, va + ENT_FRAME)
    out = []
    for selector in range(7, -1, -1):
        for slot in range(4):
            rec = va + ENT_LAYER_BASE + slot * ENT_LAYER_STRIDE
            flags = _u8(uc, rec)
            # v383 runtime evidence: record+0 bit0 is not an enable gate.
            if _u8(uc, rec + 2) != selector:
                continue
            bt = _u16(uc, rec + 6)
            if bt == 0xFFFF:
                continue
            table = _u32(uc, rec + 8)
            if not _valid_ptr(table):
                continue
            row = _u32(uc, table + sx * 4)
            if not _valid_ptr(row):
                continue
            sd = _u32(uc, row + sy * 16 + 4)
            if not _valid_ptr(sd):
                continue
            fr = ent_frame
            if flags & 0x0C:
                if fr > 0:
                    fr -= 1
                elif flags & 0x04:
                    nfr = _u16(uc, sd + 6)
                    fr = max(0, nfr - 1)
                else:
                    fr = 0
            pal = _u8(uc, rec + 1) & 0x0F
            out.append(RenderSpriteState(va, rx, ry, sd, fr, bt, pal,
                                         fx, fy, "layer", slot, pf))
    return out


def read_states(uc, va):
    """v383: reproduce both 0x4040B4 main and 0x404010 layered callers."""
    try:
        if _u8(uc, va + ENT_RENDER_KIND) != 0:
            return ([], "direct_state@4040C0")
        try:
            if _u32(uc, va + 0x0C) & 0x100:
                return ([], "manual_builder@403B04")
        except Exception:
            pass
        rf = _u8(uc, va + ENT_RENDER_FLAGS)
        if rf & 0x40:
            ss = _layered_states(uc, va)
            return (ss, None if ss else "layered_no_state")
        st = _main_state(uc, va)
        return ([st], None) if st is not None else ([], "main_no_state")
    except Exception:
        return ([], "read_exception")


def read_state(uc, va):
    ss, _ = read_states(uc, va)
    return ss[0] if ss else None


def pieces(uc, st, size_table):
    sd = st.sprite_def
    try:
        A = _u8(uc, sd + 0x0A)
        B = _u8(uc, sd + 0x0B)
        fo = _u16(uc, sd + 0x0C + st.frame * 2)
        fb = sd + 0x0C + fo
        n = _u8(uc, fb) & 0x1F
        if n == 0:
            return []
        base = fb + 6 * B + 10 + 2 * A
        raw = bytes(uc.mem_read(base, 4 * n))
    except Exception:
        return []
    out = []
    for i in range(n):
        p = raw[i * 4:i * 4 + 4]
        if len(p) < 4:
            break
        x = _sext9(((p[1] & 1) << 8) | p[0])
        y = _sext9(((p[2] & 3) << 7) | (p[1] >> 1))
        size = (p[2] >> 2) & 3
        shape = (p[2] >> 4) & 3
        tile = (((p[3] << 2) | (p[2] >> 6)) & 0x3FF) + st.base_tile
        v = struct.unpack_from("<I", size_table, 4 * (shape * 4 + size))[0]
        W, H = v & 0xFFFF, (v >> 16) & 0xFFFF
        if W == 0 or H == 0:
            continue
        out.append((x, y, tile & 0xFFFF, shape, size, W, H))
    return out


class RegionSpriteRenderer:
    def __init__(self):
        self._tile_cache = {}
        self.stats = {}

    def _tile(self, raw, pal_raw, fx, fy):
        key = (raw, pal_raw, fx, fy)
        got = self._tile_cache.get(key)
        if got is not None:
            return got
        words = np.frombuffer(raw, dtype="<u4")
        idx = ((words[:, None] >>
                (4 * np.arange(8, dtype=np.uint32))[None, :]) & 0xF
               ).astype(np.uint8)
        if fx:
            idx = idx[:, ::-1]
        if fy:
            idx = idx[::-1, :]
        pal = np.frombuffer(pal_raw, dtype="<u2")
        got = (pal[idx].astype(np.uint16), idx != 0)
        if len(self._tile_cache) > 8192:
            self._tile_cache.clear()
        self._tile_cache[key] = got
        return got

    def draw(self, uc, canvas, ox, oy, head=None, only=None):
        try:
            vram = _u32(uc, G_VRAM_PTR)
            objpal = bytes(uc.mem_read(_u32(uc, G_OBJPAL_PTR), 512))
            sizes = bytes(uc.mem_read(OBJ_SIZE_TABLE, 64))
        except Exception:
            return (0, 0, 0)
        ch, cw = canvas.shape
        ents = entity_list(uc, head=head)
        drawn_e = drawn_p = in_view = 0
        for va in ents:
            if only is not None and va not in only:
                continue
            states, why = read_states(uc, va)
            if not states:
                continue
            hit = False
            for st in states:
                ps = pieces(uc, st, sizes)
                if not ps:
                    continue
                pal_raw = objpal[st.palette * 32:st.palette * 32 + 32]
                for (px, py, tile, shape, size, W, H) in ps:
                    pw, ph = W * 8, H * 8
                    bx = (-(pw + px)) if st.flip_x else px
                    by = (-(ph + py)) if st.flip_y else py
                    dx0 = st.region_x + bx - ox
                    dy0 = st.region_y + by - oy
                    if dx0 + pw <= 0 or dx0 >= cw or dy0 + ph <= 0 or dy0 >= ch:
                        continue
                    hit = True
                    for row in range(H):
                        ty = dy0 + (((H - 1 - row) if st.flip_y else row) * 8)
                        sl = (tile + row * W) & 0xFFFF
                        for col in range(W):
                            tx = dx0 + (((W - 1 - col) if st.flip_x else col) * 8)
                            if tx + 8 <= 0 or tx >= cw or ty + 8 <= 0 or ty >= ch:
                                continue
                            tid = (sl + col) & 0xFFFF
                            try:
                                raw = bytes(uc.mem_read(
                                    vram + SPRITE_TILE_BANK + (tid << 5), 32))
                            except Exception:
                                continue
                            colors, mask = self._tile(raw, pal_raw,
                                                      st.flip_x, st.flip_y)
                            x0, x1 = max(tx, 0), min(tx + 8, cw)
                            y0, y1 = max(ty, 0), min(ty + 8, ch)
                            m = mask[y0 - ty:y1 - ty, x0 - tx:x1 - tx]
                            if not m.any():
                                continue
                            c = colors[y0 - ty:y1 - ty, x0 - tx:x1 - tx]
                            canvas[y0:y1, x0:x1][m] = c[m]
                            drawn_p += 1
            if hit:
                drawn_e += 1
                in_view += 1
        self.stats = {"entities": len(ents), "drawn_entities": drawn_e,
                      "drawn_pieces": drawn_p, "in_view": in_view}
        return (drawn_e, drawn_p, in_view)
