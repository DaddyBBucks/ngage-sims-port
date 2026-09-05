#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
v385 - Save'den yuklenen AKTIF bolgenin tam arka-plan haritasini PNG olarak cikarir.

Varsayilan olarak proje kokundeki:
  THESIMS.SAV
  thesims.dat
  lxce_candidate.bin
dosyalarini kullanir.

Cikti:
  outputs/aktif_bolge.png
  outputs/aktif_bolge.json

Bu arac v378'de dogrulanan region veri modelini kullanir:
  0x00990C30 region layer entry array
  E+0x04 world metatile map
  E+0x08 metatile table
  E+0x14/+0x16 W/H

NPC/Sim/sprite/HUD dahil degildir; tam world/background haritasidir.
"""
import argparse
import contextlib
import io
import json
import os
import shutil
import struct
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve()
ROOT = HERE.parent.parent if HERE.parent.name.lower() == "tools" else HERE.parent
sys.path.insert(0, str(ROOT))
os.chdir(str(ROOT))

import numpy as np
from PIL import Image
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

PROVEN_ROUTE = [
    "--async-request-model",
    "--sync-key-injector",
    "--menu-choice", "load_game",
    "--sync-nav-mode", "none",
    "--sync-min-gap-insn", "300000",
    "--sync-key-hold-insn", "4000000",
    "--sync-release-on-game-scan",
]

def u32(uc, va):
    return struct.unpack("<I", bytes(uc.mem_read(va, 4)))[0]

def u16(uc, va):
    return struct.unpack("<H", bytes(uc.mem_read(va, 2)))[0]

def find_default(name):
    p = ROOT / name
    return str(p) if p.exists() else None

def capture_and_render(args):
    save = Path(args.save or find_default("THESIMS.SAV") or "")
    archive = Path(args.archive or find_default("thesims.dat") or "")
    rom = Path(args.rom or find_default("lxce_candidate.bin") or "")

    for label, p in (("save", save), ("archive", archive), ("rom", rom)):
        if not p or not p.exists():
            raise FileNotFoundError("%s dosyasi bulunamadi: %s" % (label, p))

    out = Path(args.out)
    if not out.is_absolute():
        out = ROOT / out
    out.parent.mkdir(parents=True, exist_ok=True)
    meta_out = out.with_suffix(".json")

    # Orijinal save'e dokunma; oyna.py ile ayni guvenli davranis.
    tmpdir = Path(tempfile.mkdtemp(prefix="ngsims_region_"))
    work_save = tmpdir / "THESIMS.SAV.work"
    shutil.copy2(str(save), str(work_save))
    runtime_out = tmpdir / "runtime_out"
    runtime_out.mkdir(parents=True, exist_ok=True)

    R.BINARY_PATH = str(rom)
    sys.argv = [
        "run.py",
        "--max-insn", str(args.max_insn),
        "--archive-file", str(archive),
        "--save-file", str(work_save),
        "--out-dir", str(runtime_out),
        "--presenter", "none",
    ] + PROVEN_ROUTE + [
        "--ranged-hooks",
        "--clock", "real",
        "--native-renderer", "on",
    ]

    st = {"frames": 0, "snap": None, "descs": []}
    orig_build = R.build

    def wrapped_build(run_args):
        built = orig_build(run_args)
        uc = built[0]

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

            st["frames"] += 1
            if st["frames"] < args.frame:
                return

            entries = []
            for i in range(4):
                base = ENTRY_ARRAY + i * ENTRY_SIZE
                E = base + 4
                try:
                    mapptr = u32(uc_, E + 4)
                    tabptr = u32(uc_, E + 8)
                    W = u16(uc_, E + 0x14)
                    H = u16(uc_, E + 0x16)
                    e0 = u32(uc_, E)
                    aux = u32(uc_, E + 0x0C)
                    cams = [
                        (struct.unpack("<i", bytes(uc_.mem_read(E + 0x18 + k*8, 4)))[0],
                         struct.unpack("<i", bytes(uc_.mem_read(E + 0x1C + k*8, 4)))[0])
                        for k in range(2)
                    ]
                except Exception:
                    continue

                desc = None
                try:
                    desc = list(bytes(uc_.mem_read(e0, 2))) if e0 else None
                except Exception:
                    pass

                ent = {
                    "i": i, "base": base, "e0": e0, "desc": desc, "aux": aux,
                    "map": mapptr, "tab": tabptr, "W": W, "H": H, "cams": cams,
                }
                if mapptr and tabptr and 0 < W <= 512 and 0 < H <= 512:
                    try:
                        ent["hdr"] = u32(uc_, mapptr)
                        ent["cells"] = bytes(uc_.mem_read(mapptr + 4, W * H * 2))
                        ids = np.frombuffer(ent["cells"], dtype="<u2")
                        nmax = int(ids.max()) if ids.size else 0
                        ent["tabhdr"] = u32(uc_, tabptr)
                        ent["table"] = bytes(uc_.mem_read(tabptr + 4, (nmax + 1) * 32))
                    except Exception as exc:
                        ent["err"] = repr(exc)
                entries.append(ent)

            vram = u32(uc_, G_VRAM_PTR)
            palptr = u32(uc_, G_PAL_PTR)
            snap = {
                "entries": entries,
                "vram": vram,
                "palptr": palptr,
                "pal": bytes(uc_.mem_read(palptr, 512)),
                "banks": {},
            }
            for b in (0x0000, 0x4000, 0x8000, 0xC000):
                snap["banks"][b] = bytes(uc_.mem_read(vram + b, 0x8000))
            st["snap"] = snap
            uc_.emu_stop()

        uc.hook_add(UC_HOOK_CODE, on_layer, begin=LAYER_FN, end=LAYER_FN)
        uc.hook_add(UC_HOOK_CODE, on_frame, begin=FRAME_BOUNDARY, end=FRAME_BOUNDARY)
        return built

    R.build = wrapped_build
    captured_stdout = io.StringIO()
    try:
        with contextlib.redirect_stdout(captured_stdout):
            try:
                R.main()
            except SystemExit:
                pass
    finally:
        R.build = orig_build
        shutil.rmtree(tmpdir, ignore_errors=True)

    snap = st["snap"]
    if not snap:
        tail = captured_stdout.getvalue()[-4000:]
        raise RuntimeError(
            "Aktif Module-1 region yakalanamadi. Son runtime ciktisi:\n" + tail
        )

    pal = np.frombuffer(snap["pal"], dtype="<u2")
    layers = []
    entry_meta = []

    for e in snap["entries"]:
        entry_meta.append({
            "index": e["i"],
            "base": "0x%08X" % e["base"],
            "desc": e.get("desc"),
            "map": "0x%08X" % e.get("map", 0),
            "metatile_table": "0x%08X" % e.get("tab", 0),
            "aux": "0x%08X" % e.get("aux", 0),
            "metatile_w": e.get("W"),
            "metatile_h": e.get("H"),
            "camera": e.get("cams"),
            "error": e.get("err"),
        })

        if "cells" not in e or not e.get("table"):
            continue
        d = e.get("desc") or [0, 0]
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
                if blk.size == 16:
                    tiles[my*4:my*4+4, mx*4:mx*4+4] = blk.reshape(4, 4)

        col = np.zeros((th * 8, tw * 8), dtype="<u2")
        msk = np.zeros((th * 8, tw * 8), dtype=bool)
        for ty in range(th):
            for tx in range(tw):
                ent = int(tiles[ty, tx])
                tid = ent & 0x3FF
                fx = (ent >> 10) & 1
                fy = (ent >> 11) & 1
                pno = (ent >> 12) & 0xF
                raw = chars[tid*32:tid*32+32]
                if len(raw) < 32:
                    continue
                wds = np.frombuffer(raw, dtype="<u4")
                idx = ((wds[:, None] >>
                        (4 * np.arange(8, dtype=np.uint32))[None, :]) & 0xF).astype(np.uint8)
                if fx:
                    idx = idx[:, ::-1]
                if fy:
                    idx = idx[::-1, :]
                col[ty*8:ty*8+8, tx*8:tx*8+8] = pal[pno*16:(pno+1)*16][idx]
                msk[ty*8:ty*8+8, tx*8:tx*8+8] = idx != 0

        layers.append({
            "i": e["i"],
            "block": d[1] & 0x1F,
            "col": col,
            "msk": msk,
            "W": W,
            "H": H,
            "bank": bank,
            "desc": d,
        })

    if not layers:
        raise RuntimeError("Region yakalandi fakat cizilebilir world layer bulunamadi.")

    # v378: yuksek block arkada, dusuk block ustte.
    layers.sort(key=lambda L: -L["block"])

    # Farkli boyuttaki entry'ler varsa ana world boyutunu en buyuk alan belirlesin.
    main_layer = max(layers, key=lambda L: L["col"].shape[0] * L["col"].shape[1])
    H8, W8 = main_layer["col"].shape
    comp = np.zeros((H8, W8), dtype="<u2")
    for L in layers:
        if L["col"].shape != (H8, W8):
            continue
        comp[L["msk"]] = L["col"][L["msk"]]

    v = comp.astype(np.uint32)
    rgb = np.stack([
        ((v >> 8) & 15) * 17,
        ((v >> 4) & 15) * 17,
        (v & 15) * 17,
    ], axis=-1).astype(np.uint8)

    img = Image.fromarray(rgb, "RGB")
    if args.scale != 1:
        img = img.resize((img.width * args.scale, img.height * args.scale), Image.NEAREST)
    img.save(str(out))

    meta = {
        "tool": "active_region_png_v385",
        # Keep generated metadata safe to share: do not record host paths.
        "source_save": save.name,
        "output": out.name,
        "pixels": [img.width, img.height],
        "native_pixels": [W8, H8],
        "captured_module1_frames": st["frames"],
        "seen_layer_descriptors": [list(x) for x in st["descs"]],
        "vram": "0x%08X" % snap["vram"],
        "palette": "0x%08X" % snap["palptr"],
        "entries": entry_meta,
        "rendered_layers": [
            {"index": L["i"], "block": L["block"], "desc": L["desc"],
             "bank": "0x%04X" % L["bank"], "metatile_w": L["W"], "metatile_h": L["H"]}
            for L in layers
        ],
    }
    meta_out.write_text(json.dumps(meta, indent=2, ensure_ascii=False), encoding="utf-8")
    return meta

def main():
    ap = argparse.ArgumentParser(description="Aktif save region'ini tam PNG olarak cikar.")
    ap.add_argument("--save", default=None, help="Varsayilan: proje kokunde THESIMS.SAV")
    ap.add_argument("--archive", default=None, help="Varsayilan: proje kokunde thesims.dat")
    ap.add_argument("--rom", default=None, help="Varsayilan: proje kokunde lxce_candidate.bin")
    ap.add_argument("--out", default="outputs/aktif_bolge.png")
    ap.add_argument("--frame", type=int, default=20,
                    help="Module 1'e girdikten sonra kac frame beklenir (varsayilan 20)")
    ap.add_argument("--max-insn", type=int, default=300_000_000)
    ap.add_argument("--scale", type=int, default=1)
    args = ap.parse_args()

    print("=" * 64)
    print(" N-Gage Sims - AKTIF REGION PNG v385")
    print("=" * 64)
    try:
        meta = capture_and_render(args)
    except Exception as exc:
        print("\nHATA:", exc)
        return 1

    print("\nBASARILI")
    print(" PNG  :", meta["output"])
    print(" Boyut: %dx%d" % tuple(meta["pixels"]))
    print(" JSON :", str(Path(meta["output"]).with_suffix(".json")))
    print(" Layer:", ", ".join(
        "#%d block=%d %dx%d" % (x["index"], x["block"],
                                x["metatile_w"], x["metatile_h"])
        for x in meta["rendered_layers"]))
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
