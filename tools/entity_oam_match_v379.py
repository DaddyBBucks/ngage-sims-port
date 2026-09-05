"""v379: ENTITY -> KAMERA -> OAM zincirini SAYISAL olarak cikar.

Kancalar (salt gozlem):
  0x4041F4  OAM uretici girisi  -> r0 (sprite tanimi), r1 (kare),
                                   [sp+0x60] (nesne isaretcisi) ve
                                   nesnenin ilk 0x40 bayti
  0x467124  OAM yuvasina yazma  -> yuva no + 8 baytlik kayit
  0x448740  kare siniri         -> bolge kamerasi (E+0x18 / E+0x1C)

Cikti: her (kare, nesne) icin
    nesne isaretcisi | nesne alanlari | kamera X/Y | OAM X/Y | yuva
Sonra cevrimdisi olarak, kamera hareket ederken sabit kalan
"nesne alani - OAM" farki aranarak REGION X/Y alani bulunur.
"""
import argparse, contextlib, io, os, pickle, struct, sys
from collections import defaultdict

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.chdir(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from unicorn import UC_HOOK_CODE
from unicorn.arm_const import (UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_SP)
import run as R
from runtime.input import (SCANCODE_UP, SCANCODE_DOWN, SCANCODE_LEFT,
                           SCANCODE_RIGHT)

PRODUCER = 0x4041F4
OAM_SET = 0x467124
FRAME_BOUNDARY = 0x448740
MODULE_INDEX_VA = 0xA16AF4
ENTRY_ARRAY = 0x00990C30
KEYS = {"left": SCANCODE_LEFT, "right": SCANCODE_RIGHT,
        "up": SCANCODE_UP, "down": SCANCODE_DOWN}
ENT_DUMP = 0x40


def u32(uc, va):
    return struct.unpack("<I", uc.mem_read(va, 4))[0]


def i32(uc, va):
    return struct.unpack("<i", uc.mem_read(va, 4))[0]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--max-insn", type=int, default=250000000)
    ap.add_argument("--hold", type=int, default=250)
    ap.add_argument("--plan", default="none,right,right,left,left,down,down")
    ap.add_argument("--out", default="/tmp/v379_match.pkl")
    a = ap.parse_args()
    import shutil
    shutil.copyfile("/tmp/sav_c42", "/tmp/v379_m.sav")
    sys.argv = ["run.py", "--max-insn", str(a.max_insn),
                "--save-file", "/tmp/v379_m.sav",
                "--archive-file", "thesims.dat", "--out-dir", "/tmp/v379_m",
                "--async-request-model", "--sync-key-injector",
                "--menu-choice", "load_game", "--sync-nav-mode", "none",
                "--sync-min-gap-insn", "300000",
                "--sync-key-hold-insn", "4000000",
                "--sync-release-on-game-scan", "--ranged-hooks",
                "--native-renderer", "on"]
    plan = [p for p in a.plan.split(",") if p]
    st = {"f": 0, "phase": -1, "end": None, "held": None,
          "pend": None, "rows": [], "cam": (0, 0), "producer_calls": 0,
          "oam_writes": 0}
    _orig = R.build

    def build(args):
        o = _orig(args)
        uc, ctx = o[0], o[1]

        def press(name):
            if st["held"] == name:
                return
            if st["held"]:
                ctx.event_queue.push_host_keyup(KEYS[st["held"]])
            if name and name != "none":
                ctx.event_queue.push_host_keydown(KEYS[name])
                st["held"] = name
            else:
                st["held"] = None

        def on_prod(uc_, addr, size, ud):
            try:
                if u32(uc_, MODULE_INDEX_VA) != 1:
                    return
            except Exception:
                return
            st["producer_calls"] += 1
            sp = uc_.reg_read(UC_ARM_REG_SP)
            try:
                ent = u32(uc_, sp + 0x60 - 0x38 - 32)
            except Exception:
                ent = 0
            try:
                args8 = list(struct.unpack("<8I", uc_.mem_read(sp, 32)))
            except Exception:
                args8 = []
            st["pend"] = {"f": st["f"], "sprdef": uc_.reg_read(UC_ARM_REG_R0),
                          "frame": uc_.reg_read(UC_ARM_REG_R1),
                          "args": args8, "cam": st["cam"],
                          "key": st["held"], "phase": st["phase"]}

        def on_oam(uc_, addr, size, ud):
            p = st["pend"]
            if p is None:
                return
            st["oam_writes"] += 1
            slot = uc_.reg_read(UC_ARM_REG_R0) & 0xFF
            rec = uc_.reg_read(UC_ARM_REG_R1)
            try:
                raw = bytes(uc_.mem_read(rec, 8))
            except Exception:
                raw = b""
            if len(raw) == 8:
                xr = (raw[2] | (raw[3] << 8)) & 0x1FF
                X = xr - 0x200 if (xr & 0x100) else xr
                Y = raw[0] - 0x100 if raw[0] > 0xD0 else raw[0]
                q = dict(p)
                q.update({"slot": slot, "raw": raw, "oam_x": X, "oam_y": Y})
                ents = {}
                for i, v in enumerate(p["args"]):
                    if 0x800000 <= v < 0xB00000:
                        try:
                            ents[i] = bytes(uc_.mem_read(v, ENT_DUMP))
                        except Exception:
                            pass
                q["entdumps"] = ents
                if len(st["rows"]) < 20000:
                    st["rows"].append(q)
            st["pend"] = None

        def on_frame(uc_, addr, size, ud):
            try:
                if u32(uc_, MODULE_INDEX_VA) != 1:
                    return
            except Exception:
                return
            st["f"] += 1
            E = ENTRY_ARRAY + 4
            try:
                st["cam"] = (i32(uc_, E + 0x18), i32(uc_, E + 0x1C))
            except Exception:
                pass
            if st["end"] is None:
                st["end"] = st["f"] + 40
            if st["f"] >= st["end"]:
                st["phase"] += 1
                if st["phase"] < len(plan):
                    press(plan[st["phase"]])
                    st["end"] = st["f"] + a.hold
                else:
                    press(None)
                    st["end"] = st["f"] + 10 ** 9

        uc.hook_add(UC_HOOK_CODE, on_prod, begin=PRODUCER, end=PRODUCER)
        uc.hook_add(UC_HOOK_CODE, on_oam, begin=OAM_SET, end=OAM_SET)
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
    print("kare=%d  uretici cagrisi=%d  OAM yazmasi=%d  eslesen satir=%d"
          % (st["f"], st["producer_calls"], st["oam_writes"], len(st["rows"])))
    cams = sorted({r["cam"] for r in st["rows"]})
    print("gorulen kamera degerleri: %d farkli, ornek %s" % (len(cams), cams[:6]))
    for r in st["rows"][:5]:
        print("  kare %d yuva %3d  OAM=(%4d,%4d)  kamera=%s  sprdef=0x%08x "
              "kare_no=%d  yigin=%s"
              % (r["f"], r["slot"], r["oam_x"], r["oam_y"], r["cam"],
                 r["sprdef"], r["frame"],
                 [hex(v) for v in r["args"][:6]]))


if __name__ == "__main__":
    main()
