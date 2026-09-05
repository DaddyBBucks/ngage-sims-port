"""v378: BOLGENIN TAMAMINI runtime verisinden yeniden kur ve PNG'ye dok.

Motorun bolge temsili (v378'de cozuldu):

    0x00990C30  katman girdisi dizisi, girdi basina 2624 bayt (0xA40)
    E = girdi + 4
      E+0x00 -> ? (0x40F658 buradan VRAM harita blogunu aliyor)
      E+0x04 -> DUNYA HARITASI nesnesi: u32 baslik, sonra W*H adet u16
                "super kiremit" (metatile) kimligi
      E+0x08 -> METATILE TABLOSU: u32 baslik, sonra kayit basina 32 bayt
                = 4x4 kiremit (16 x u16 harita girdisi)
      E+0x14 -> W  (metatile cinsinden)      E+0x16 -> H
      E+0x18 + i*8 -> kamera X  (sabit nokta; /32 = metatile)
      E+0x1C + i*8 -> kamera Y
      E+0x40 -> 40x32 kiremitlik ARA TAMPON (satir atlamasi 0x50 = 40 girdi)

    0x40F3F4  ara tamponu her karede metatile'lardan kurar (10x8 metatile)
    0x40F658  ara tampondan VRAM'e 27x22 kiremitlik pencereyi kopyalar

Bu arac hicbir seyi degistirmez; yalnizca okur ve PNG uretir.
"""
import argparse, contextlib, io, os, pickle, struct, sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.chdir(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import numpy as np
from unicorn import UC_HOOK_CODE
from unicorn.arm_const import UC_ARM_REG_R1
import run as R

ENTRY_ARRAY = 0x00990C30
ENTRY_SIZE = 0xA40
FRAME_BOUNDARY = 0x448740
LAYER_FN = 0x448A8C
MODULE_INDEX_VA = 0xA16AF4
G_VRAM_PTR = 0x4B6EB8
G_PAL_PTR = 0x4B6EBC


def u32(uc, va):
    return struct.unpack("<I", uc.mem_read(va, 4))[0]


def u16(uc, va):
    return struct.unpack("<H", uc.mem_read(va, 2))[0]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--max-insn", type=int, default=130000000)
    ap.add_argument("--frame", type=int, default=60)
    ap.add_argument("--out", default="v378_region_map.png")
    ap.add_argument("--dump", default="/tmp/v378_region_dump.pkl")
    ap.add_argument("--scale", type=int, default=1)
    a = ap.parse_args()
    import shutil
    shutil.copyfile("/tmp/sav_c42", "/tmp/v378_rd.sav")
    sys.argv = ["run.py", "--max-insn", str(a.max_insn),
                "--save-file", "/tmp/v378_rd.sav",
                "--archive-file", "thesims.dat", "--out-dir", "/tmp/v378_rd",
                "--async-request-model", "--sync-key-injector",
                "--menu-choice", "load_game", "--sync-nav-mode", "none",
                "--sync-min-gap-insn", "300000",
                "--sync-key-hold-insn", "4000000",
                "--sync-release-on-game-scan", "--ranged-hooks",
                "--native-renderer", "on"]
    st = {"f": 0, "snap": None, "descs": []}
    _orig = R.build

    def build(args):
        o = _orig(args)
        uc = o[0]

        def on_layer(uc_, addr, size, ud):
            if st["snap"] is not None:
                return
            try:
                if u32(uc_, MODULE_INDEX_VA) != 1:
                    return
                d = bytes(uc_.mem_read(uc_.reg_read(UC_ARM_REG_R1), 2))
            except Exception:
                return
            if d not in st["descs"]:
                st["descs"].append(d)

        def on_frame(uc_, addr, size, ud):
            if st["snap"] is not None:
                return
            try:
                if u32(uc_, MODULE_INDEX_VA) != 1:
                    return
            except Exception:
                return
            st["f"] += 1
            if st["f"] < a.frame:
                return
            entries = []
            for i in range(4):
                base = ENTRY_ARRAY + i * ENTRY_SIZE
                E = base + 4
                try:
                    raw = bytes(uc_.mem_read(base, 0x60))
                    mapptr = u32(uc_, E + 4)
                    tabptr = u32(uc_, E + 8)
                    W = u16(uc_, E + 0x14)
                    H = u16(uc_, E + 0x16)
                    e0 = u32(uc_, E + 0)
                    cams = [(struct.unpack("<i", uc_.mem_read(E + 0x18 + k * 8, 4))[0],
                             struct.unpack("<i", uc_.mem_read(E + 0x1C + k * 8, 4))[0])
                            for k in range(2)]
                except Exception:
                    continue
                desc = None
                try:
                    desc = list(bytes(uc_.mem_read(e0, 2))) if e0 else None
                except Exception:
                    pass
                aux = u32(uc_, E + 0x0C)
                ent = {"i": i, "base": base, "raw": raw, "e0": e0,
                       "desc": desc, "aux": aux,
                       "map": mapptr, "tab": tabptr, "W": W, "H": H,
                       "cams": cams}
                if aux and 0 < W <= 512 and 0 < H <= 512:
                    try:
                        ent["auxdata"] = bytes(uc_.mem_read(aux, W * H * 2 + 8))
                    except Exception:
                        pass
                if mapptr and 0 < W <= 512 and 0 < H <= 512:
                    try:
                        ent["hdr"] = u32(uc_, mapptr)
                        ent["cells"] = bytes(uc_.mem_read(mapptr + 4, W * H * 2))
                        ids = np.frombuffer(ent["cells"], dtype="<u2")
                        nmax = int(ids.max()) if ids.size else 0
                        ent["tabhdr"] = u32(uc_, tabptr) if tabptr else None
                        ent["table"] = bytes(uc_.mem_read(
                            tabptr + 4, (nmax + 1) * 32)) if tabptr else b""
                    except Exception as exc:
                        ent["err"] = repr(exc)
                entries.append(ent)
            st["snap"] = {"entries": entries,
                          "vram": u32(uc_, G_VRAM_PTR),
                          "pal": bytes(uc_.mem_read(u32(uc_, G_PAL_PTR), 512)),
                          "banks": {}}
            for b in (0x0000, 0x4000, 0x8000, 0xC000):
                st["snap"]["banks"][b] = bytes(
                    uc_.mem_read(st["snap"]["vram"] + b, 0x8000))
        uc.hook_add(UC_HOOK_CODE, on_layer, begin=LAYER_FN, end=LAYER_FN)
        uc.hook_add(UC_HOOK_CODE, on_frame,
                    begin=FRAME_BOUNDARY, end=FRAME_BOUNDARY)
        return o

    R.build = build
    with contextlib.redirect_stdout(io.StringIO()):
        try:
            R.main()
        except SystemExit:
            pass
        except Exception as exc:
            print("[EXC] %r" % (exc,))
    snap = st["snap"]
    if not snap:
        print("kare yakalanamadi")
        return
    print("gorulen katman tanimlayicilari:", [list(d) for d in st["descs"]])
    for e in snap["entries"]:
        print("girdi %d @0x%08x  desc=%s  map=0x%08x tab=0x%08x aux=0x%08x "
              "W=%d H=%d (= %d x %d kiremit = %d x %d piksel)  kamera=%s"
              % (e["i"], e["base"], e.get("desc"), e["map"], e["tab"],
                 e.get("aux", 0), e["W"], e["H"], e["W"] * 4, e["H"] * 4,
                 e["W"] * 32, e["H"] * 32, e["cams"]))
        if "cells" in e:
            ids = np.frombuffer(e["cells"], dtype="<u2")
            print("      metatile kimlikleri: %d adet, max=%d, farkli=%d"
                  % (ids.size, ids.max(), len(set(ids.tolist()))))
    pickle.dump(snap, open(a.dump, "wb"))
    print("ham dokum -> %s" % a.dump)

    from PIL import Image
    pal = np.frombuffer(snap["pal"], dtype="<u2")
    layers = []
    for e in snap["entries"]:
        if "cells" not in e or not e.get("table"):
            continue
        d = e.get("desc") or (0, 0)
        bank = (d[0] << 12) & 0xC000
        chars = snap["banks"][bank]
        W, H = e["W"], e["H"]
        ids = np.frombuffer(e["cells"], dtype="<u2").reshape(H, W)
        table = np.frombuffer(e["table"], dtype="<u2")
        tw, th = W * 4, H * 4
        tiles = np.zeros((th, tw), dtype="<u2")
        for my in range(H):
            for mx in range(W):
                rec = int(ids[my, mx]) * 16
                blk = table[rec:rec + 16]
                if blk.size < 16:
                    continue
                tiles[my * 4:my * 4 + 4, mx * 4:mx * 4 + 4] = blk.reshape(4, 4)
        col = np.zeros((th * 8, tw * 8), dtype="<u2")
        msk = np.zeros((th * 8, tw * 8), dtype=bool)
        for ty in range(th):
            for tx in range(tw):
                ent = int(tiles[ty, tx])
                tid = ent & 0x3FF
                fx = (ent >> 10) & 1
                fy = (ent >> 11) & 1
                pno = (ent >> 12) & 0xF
                raw = chars[tid * 32:tid * 32 + 32]
                if len(raw) < 32:
                    continue
                wds = np.frombuffer(raw, dtype="<u4")
                idx = ((wds[:, None] >>
                        (4 * np.arange(8, dtype=np.uint32))[None, :])
                       & 0xF).astype(np.uint8)
                if fx:
                    idx = idx[:, ::-1]
                if fy:
                    idx = idx[::-1, :]
                col[ty * 8:ty * 8 + 8, tx * 8:tx * 8 + 8] = \
                    pal[pno * 16:(pno + 1) * 16][idx]
                msk[ty * 8:ty * 8 + 8, tx * 8:tx * 8 + 8] = idx != 0
        layers.append({"i": e["i"], "block": d[1] & 0x1F, "col": col,
                       "msk": msk, "tw": tw, "th": th})
        print("girdi %d desc=%s banka=0x%04x  %dx%d kiremit = %dx%d piksel  "
              "dolu piksel=%d"
              % (e["i"], list(d), bank, tw, th, tw * 8, th * 8, int(msk.sum())))
    if not layers:
        print("cizilecek katman yok")
        return
    layers.sort(key=lambda L: -L["block"])
    H8, W8 = layers[0]["col"].shape
    comp = np.zeros((H8, W8), dtype="<u2")
    for L in layers:
        comp[L["msk"]] = L["col"][L["msk"]]
    v = comp.astype(np.uint32)
    rgb = np.stack([((v >> 8) & 15) * 17, ((v >> 4) & 15) * 17,
                    (v & 15) * 17], axis=-1).astype(np.uint8)
    out = Image.fromarray(rgb, "RGB")
    if a.scale != 1:
        out = out.resize((out.width * a.scale, out.height * a.scale),
                         Image.NEAREST)
    out.save(a.out)
    print("-> %s (%dx%d piksel)" % (a.out, out.width, out.height))


if __name__ == "__main__":
    main()
