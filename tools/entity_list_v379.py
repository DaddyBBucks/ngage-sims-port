"""v379: region-space NESNE LISTESI -- OAM'a ihtiyac duymadan enumerate.

v379'da bulundu: nesneler 320 (0x140) baytlik kayitlarda, CIFT YONLU
BAGLI LISTE halinde duruyor:
    +0x00 sonraki   +0x04 onceki
    +0x18 region X  (16.16 sabit nokta; >>16 = piksel)
    +0x1C region Y
    +0x20/+0x24 ayni degerlerin ikinci kopyasi

Bu arac listeyi bastan sona yurur, her nesnenin region konumunu ve
o karedeki OAM durumunu yan yana koyar; ayrica liste basini tutan
globali bellekte arar.  SALT GOZLEM.
"""
import argparse, contextlib, io, os, pickle, struct, sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.chdir(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from unicorn import UC_HOOK_CODE
import run as R

FRAME_BOUNDARY = 0x448740
MODULE_INDEX_VA = 0xA16AF4
ENTRY_ARRAY = 0x00990C30
OAM_PTR = 0x4B6EC8
LIST_HEAD_GUESS = 0x0093CCB8
SCAN_RANGES = ((0x008D7000, 0x00A20000), (0x004AC000, 0x004D0000))


def u32(uc, va):
    return struct.unpack("<I", uc.mem_read(va, 4))[0]


def i32(uc, va):
    return struct.unpack("<i", uc.mem_read(va, 4))[0]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--max-insn", type=int, default=110000000)
    ap.add_argument("--frame", type=int, default=45)
    ap.add_argument("--head", default=None,
                    help="liste basi (verilmezse bellekte aranir)")
    ap.add_argument("--out", default="/tmp/v379_list.pkl")
    a = ap.parse_args()
    import shutil
    shutil.copyfile("/tmp/sav_c42", "/tmp/v379_l.sav")
    sys.argv = ["run.py", "--max-insn", str(a.max_insn),
                "--save-file", "/tmp/v379_l.sav",
                "--archive-file", "thesims.dat", "--out-dir", "/tmp/v379_l",
                "--async-request-model", "--sync-key-injector",
                "--menu-choice", "load_game", "--sync-nav-mode", "none",
                "--sync-min-gap-insn", "300000",
                "--sync-key-hold-insn", "4000000",
                "--sync-release-on-game-scan", "--ranged-hooks",
                "--native-renderer", "on"]
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
            cam = (i32(uc_, E + 0x18), i32(uc_, E + 0x1C))
            head = int(a.head, 0) if a.head else LIST_HEAD_GUESS
            ents = []
            cur = head
            seen = set()
            while cur and cur not in seen and len(ents) < 512:
                seen.add(cur)
                try:
                    rec = bytes(uc_.mem_read(cur, 0x140))
                except Exception:
                    break
                nxt = struct.unpack_from("<I", rec, 0)[0]
                ents.append({"va": cur, "rec": rec})
                cur = nxt
            oam_base = u32(uc_, OAM_PTR)
            oam = bytes(uc_.mem_read(oam_base, 1024))
            heads = []
            for lo, hi in SCAN_RANGES:
                try:
                    blob = bytes(uc_.mem_read(lo, hi - lo))
                except Exception:
                    continue
                tgt = struct.pack("<I", head)
                i = blob.find(tgt)
                while i != -1 and len(heads) < 24:
                    heads.append(lo + i)
                    i = blob.find(tgt, i + 4)
            st["snap"] = {"cam": cam, "ents": ents, "oam": oam,
                          "heads": heads, "frame": st["f"]}
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
    s = st["snap"]
    if not s:
        print("kare yakalanamadi")
        return
    pickle.dump(s, open(a.out, "wb"))
    cam = s["cam"]
    oam_pos = set()
    for i in range(128):
        e = s["oam"][i * 8:i * 8 + 8]
        if (e[1] & 3) == 2:
            continue
        xr = (e[2] | (e[3] << 8)) & 0x1FF
        X = xr - 0x200 if (xr & 0x100) else xr
        Y = e[0] - 0x100 if e[0] > 0xD0 else e[0]
        oam_pos.add((X + cam[0], Y + cam[1]))
    print("kare %d  kamera=%s  liste uzunlugu=%d  OAM'da gorunur girdi=%d"
          % (s["frame"], cam, len(s["ents"]), len(oam_pos)))
    print("liste basini tutan aday globaller: %s"
          % [hex(h) for h in s["heads"][:12]])
    print("\nNESNE          REGION XY      KAMERA XY     EKRAN XY       DURUM")
    onscreen = offscreen = 0
    for e in s["ents"]:
        rx = struct.unpack_from("<i", e["rec"], 0x18)[0] >> 16
        ry = struct.unpack_from("<i", e["rec"], 0x1C)[0] >> 16
        sx, sy = rx - cam[0], ry - cam[1]
        near = any(abs(sx - (px - cam[0])) <= 64 and abs(sy - (py - cam[1])) <= 64
                   for px, py in oam_pos)
        vis = -64 <= sx <= 240 and -64 <= sy <= 208
        if vis:
            onscreen += 1
        else:
            offscreen += 1
        print("0x%08x  %5d,%-5d   %4d,%-4d    %6d,%-6d  %s%s"
              % (e["va"], rx, ry, cam[0], cam[1], sx, sy,
                 "gorunur" if vis else "EKRAN DISI",
                 "  (OAM'da benzer konum yok)" if not near and vis else ""))
    print("\ntoplam %d nesne: %d ekran icinde, %d EKRAN DISINDA"
          % (len(s["ents"]), onscreen, offscreen))


if __name__ == "__main__":
    main()
