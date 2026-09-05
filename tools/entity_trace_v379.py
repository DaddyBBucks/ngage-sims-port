"""v379: nesne (entity) kayitlarini dokumler ve region X/Y alanlarini bulur.

v379'da OLCULDU:  OAM_X = regionX - kameraX ,  OAM_Y = regionY - kameraY
(sabit ofset YOK).  Statik nesnelerde `OAM + kamera` toplami %94-99,6
oraninda tek bir degerde kaliyor; bu degerler nesnenin region-space
konumudur.

Bu arac o bilinen degerleri kullanarak nesne kaydinin ICINDE region X/Y
alanlarini arar ve tum nesne dizisini dokumler.  SALT GOZLEM.
"""
import argparse, contextlib, io, os, pickle, struct, sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.chdir(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from unicorn import UC_HOOK_CODE
import run as R

FRAME_BOUNDARY = 0x448740
MODULE_INDEX_VA = 0xA16AF4
ENTRY_ARRAY = 0x00990C30
REC = 0x140


def u32(uc, va):
    return struct.unpack("<I", uc.mem_read(va, 4))[0]


def i32(uc, va):
    return struct.unpack("<i", uc.mem_read(va, 4))[0]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--max-insn", type=int, default=110000000)
    ap.add_argument("--frame", type=int, default=45)
    ap.add_argument("--lo", default="0x93c000")
    ap.add_argument("--hi", default="0x940000")
    ap.add_argument("--out", default="/tmp/v379_entities.pkl")
    a = ap.parse_args()
    import shutil
    shutil.copyfile("/tmp/sav_c42", "/tmp/v379_e.sav")
    sys.argv = ["run.py", "--max-insn", str(a.max_insn),
                "--save-file", "/tmp/v379_e.sav",
                "--archive-file", "thesims.dat", "--out-dir", "/tmp/v379_e",
                "--async-request-model", "--sync-key-injector",
                "--menu-choice", "load_game", "--sync-nav-mode", "none",
                "--sync-min-gap-insn", "300000",
                "--sync-key-hold-insn", "4000000",
                "--sync-release-on-game-scan", "--ranged-hooks",
                "--native-renderer", "on"]
    lo, hi = int(a.lo, 0), int(a.hi, 0)
    st = {"f": 0, "snap": None}
    _orig = R.build

    def build(args):
        o = _orig(args)
        uc = o[0]

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
            E = ENTRY_ARRAY + 4
            st["snap"] = {"cam": (i32(uc_, E + 0x18), i32(uc_, E + 0x1C)),
                          "lo": lo, "blob": bytes(uc_.mem_read(lo, hi - lo)),
                          "frame": st["f"]}
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
    if not st["snap"]:
        print("kare yakalanamadi")
        return
    pickle.dump(st["snap"], open(a.out, "wb"))
    print("kare %d  kamera=%s  blob 0x%08x..0x%08x (%d bayt) -> %s"
          % (st["snap"]["frame"], st["snap"]["cam"], lo, hi, hi - lo, a.out))


if __name__ == "__main__":
    main()
