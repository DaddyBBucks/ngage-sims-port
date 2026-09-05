"""v379: bolge yapisi (W/H + metatile haritasi + metatile tablosu) HANGI
DAT kaydindan uretiliyor?

Arsiv okumalarini (0x40EC9C: kayit indeksi, hedef, boyut) ve grafik
cozucusunun (0x472708) cikti araliklarini kaydeder; sonra modul 1'de
bolge girdisinin isaretcilerini (E+4 harita, E+8 metatile tablosu) bu
araliklarla esler.  SALT GOZLEM.
"""
import argparse, contextlib, io, os, pickle, struct, sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.chdir(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from unicorn import UC_HOOK_CODE
from unicorn.arm_const import (UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2,
                               UC_ARM_REG_R3, UC_ARM_REG_LR)
import run as R

READ_WRAPPER = 0x40EC9C
HANDLE_INDEX_PTR = 0x0C
GFX_CODEC = 0x472708
ALLOC_SITES = ()
ENTRY_ARRAY = 0x00990C30
ENTRY_SIZE = 0xA40
FRAME_BOUNDARY = 0x448740
MODULE_INDEX_VA = 0xA16AF4


def u32(uc, va):
    try:
        return struct.unpack("<I", uc.mem_read(va, 4))[0]
    except Exception:
        return None


def u16(uc, va):
    return struct.unpack("<H", uc.mem_read(va, 2))[0]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--max-insn", type=int, default=110000000)
    ap.add_argument("--out", default="/tmp/v379_regionasset.pkl")
    a = ap.parse_args()
    import shutil
    shutil.copyfile("/tmp/sav_c42", "/tmp/v379_ra.sav")
    sys.argv = ["run.py", "--max-insn", str(a.max_insn),
                "--save-file", "/tmp/v379_ra.sav",
                "--archive-file", "thesims.dat", "--out-dir", "/tmp/v379_ra",
                "--async-request-model", "--sync-key-injector",
                "--menu-choice", "load_game", "--sync-nav-mode", "none",
                "--sync-min-gap-insn", "300000",
                "--sync-key-hold-insn", "4000000",
                "--sync-release-on-game-scan", "--ranged-hooks",
                "--native-renderer", "on"]
    st = {"reads": [], "codec": [], "snap": None, "f": 0}
    _orig = R.build

    def build(args):
        o = _orig(args)
        uc = o[0]

        def on_read(uc_, addr, size, ud):
            dst = uc_.reg_read(UC_ARM_REG_R0)
            n = uc_.reg_read(UC_ARM_REG_R1) * uc_.reg_read(UC_ARM_REG_R2)
            h = uc_.reg_read(UC_ARM_REG_R3)
            idx = None
            ip = u32(uc_, h + HANDLE_INDEX_PTR)
            if ip:
                try:
                    idx = struct.unpack("<H", uc_.mem_read(ip, 2))[0]
                except Exception:
                    pass
            st["reads"].append({"dst": dst, "n": n, "index": idx,
                                "module": u32(uc_, MODULE_INDEX_VA)})

        def on_codec(uc_, addr, size, ud):
            st["codec"].append({"r0": uc_.reg_read(UC_ARM_REG_R0),
                                "r1": uc_.reg_read(UC_ARM_REG_R1),
                                "r2": uc_.reg_read(UC_ARM_REG_R2),
                                "r3": uc_.reg_read(UC_ARM_REG_R3),
                                "lr": uc_.reg_read(UC_ARM_REG_LR),
                                "module": u32(uc_, MODULE_INDEX_VA)})

        def on_frame(uc_, addr, size, ud):
            if st["snap"] is not None:
                return
            try:
                if u32(uc_, MODULE_INDEX_VA) != 1:
                    return
            except Exception:
                return
            st["f"] += 1
            if st["f"] < 40:
                return
            ents = []
            for i in range(4):
                E = ENTRY_ARRAY + i * ENTRY_SIZE + 4
                ents.append({"i": i, "map": u32(uc_, E + 4),
                             "tab": u32(uc_, E + 8), "aux": u32(uc_, E + 0x0C),
                             "W": u16(uc_, E + 0x14), "H": u16(uc_, E + 0x16)})
            st["snap"] = ents

        uc.hook_add(UC_HOOK_CODE, on_read, begin=READ_WRAPPER, end=READ_WRAPPER)
        uc.hook_add(UC_HOOK_CODE, on_codec, begin=GFX_CODEC, end=GFX_CODEC)
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
    pickle.dump(st, open(a.out, "wb"))
    print("arsiv okumasi=%d  kodek cagrisi=%d" % (len(st["reads"]), len(st["codec"])))
    if not st["snap"]:
        print("bolge girdisi yakalanamadi")
        return

    def owner(addr):
        for r in st["reads"]:
            if r["dst"] and r["dst"] <= addr < r["dst"] + max(r["n"], 1):
                return "READ kayit=%s dst=0x%08x n=%d modul=%s" % (
                    r["index"], r["dst"], r["n"], r["module"])
        best = None
        for c in st["codec"]:
            for reg in ("r0", "r1", "r2", "r3"):
                v = c[reg]
                if v and v <= addr < v + 0x40000:
                    d = addr - v
                    if best is None or d < best[0]:
                        best = (d, "CODEC %s=0x%08x (+%d) lr=0x%08x modul=%s"
                                % (reg, v, d, c["lr"], c["module"]))
        return best[1] if best else None

    for e in st["snap"]:
        if not e["map"]:
            continue
        print("\ngirdi %d  W=%d H=%d" % (e["i"], e["W"], e["H"]))
        for name in ("map", "tab", "aux"):
            print("   %-4s 0x%08x  <- %s" % (name, e[name], owner(e[name])))
    print("\nkodek cagrilari (modul, r0..r3, lr):")
    seen = set()
    for c in st["codec"]:
        k = (c["module"], c["lr"])
        if k in seen:
            continue
        seen.add(k)
        print("   modul %s r0=0x%08x r1=0x%08x r2=0x%x r3=0x%x lr=0x%08x"
              % (c["module"], c["r0"], c["r1"], c["r2"], c["r3"], c["lr"]))


if __name__ == "__main__":
    main()
