"""4 bit/piksel kiremit blitter'inin yuksek seviyeli karsiligi (v345).

The model was verified against 200 captured calls from the original ARM path;
all modeled memory writes matched address/size/value for those samples.

Modes:
    off     disabled
    verify  original path runs and writes are compared
    on      host model writes the result and skips the hot loop
"""
import struct

from unicorn import UC_HOOK_CODE, UC_HOOK_MEM_WRITE
from unicorn.arm_const import (UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2,
                               UC_ARM_REG_R3, UC_ARM_REG_R4, UC_ARM_REG_R5,
                               UC_ARM_REG_R6, UC_ARM_REG_R7, UC_ARM_REG_PC)

SETUP_VA = 0x463CC4
EXIT_VA = 0x463DE4
_M32 = 0xFFFFFFFF


def _row_bytes_general(v, r4, pal):
    out = []
    base = 4 * (8 - r4)
    for j in range(r4):
        out.append(pal[(v >> (base + 4 * j)) & 0xF])
    return b"".join(out)


def install(uc, ctx, mode="on", verbose=True):
    if mode == "off":
        return None
    st = {"calls": 0, "fast": 0, "slow": 0, "skipped": 0,
          "mismatch": 0, "checked": 0, "pend": None, "hook": None,
          "mode": mode}
    pal_cache = {}

    def palette_for(praw):
        ent = pal_cache.get(praw)
        if ent is None:
            pal = [struct.pack("<H", struct.unpack_from("<H", praw, i * 2)[0] | 0x8000)
                   for i in range(16)]
            ent = (pal, [pal[b & 0xF] + pal[b >> 4] for b in range(256)])
            if len(pal_cache) > 64:
                pal_cache.clear()
            pal_cache[praw] = ent
        return ent

    def _log(m):
        if verbose:
            print("[blit4] " + m, flush=True)

    def compute(uc_):
        r1 = uc_.reg_read(UC_ARM_REG_R1)
        r2 = uc_.reg_read(UC_ARM_REG_R2)
        r3 = uc_.reg_read(UC_ARM_REG_R3)
        r4 = uc_.reg_read(UC_ARM_REG_R4)
        r5 = uc_.reg_read(UC_ARM_REG_R5)
        r6 = uc_.reg_read(UC_ARM_REG_R6)
        r7 = uc_.reg_read(UC_ARM_REG_R7)
        rows = r5 - r7
        if rows <= 0 or r4 > 8 or r1 > 31:
            return None
        r0 = uc_.reg_read(UC_ARM_REG_R0)
        pal, p2 = palette_for(bytes(uc_.mem_read(r0, 32)))
        src = uc_.mem_read(r2 & ~3, 4 * rows)
        step = (r6 - (1 << 32) if r6 >= (1 << 31) else r6) * 2
        dst = (r3 + 2 * r4 - 0x10 + 2 * (8 - r4)) & _M32
        writes = []
        if r1 == 0 and r4 == 8:
            for i in range(rows):
                o = i * 4
                if src[o] or src[o + 1] or src[o + 2] or src[o + 3]:
                    writes.append((dst, p2[src[o]] + p2[src[o + 1]]
                                   + p2[src[o + 2]] + p2[src[o + 3]]))
                dst = (dst + step) & _M32
        else:
            for i in range(rows):
                w = struct.unpack_from("<I", src, i * 4)[0]
                v = (w << r1) & _M32
                if v:
                    writes.append((dst, _row_bytes_general(v, r4, pal)))
                dst = (dst + step) & _M32
        return writes

    def on_setup(uc_, address, size, ud):
        st["calls"] += 1
        w = compute(uc_)
        if w is None:
            st["skipped"] += 1
            return
        if st["mode"] == "on":
            for a, b in w:
                uc_.mem_write(a, b)
            uc_.reg_write(UC_ARM_REG_PC, EXIT_VA)
            st["fast"] += 1
            return
        exp = []
        for a, b in w:
            for k in range(0, len(b), 2):
                exp.append((a + k, struct.unpack_from("<H", b, k)[0]))
        st["pend"] = (exp, [])

    def on_write(uc_, access, address, size, value, ud):
        p = st["pend"]
        if p is not None and len(p[1]) < 8000:
            p[1].append((address, value & 0xFFFF))

    def on_exit(uc_, address, size, ud):
        p = st["pend"]
        if p is None:
            return
        st["pend"] = None
        exp, got = p
        st["checked"] += 1
        if exp != got:
            st["mismatch"] += 1
            if st["mismatch"] <= 3:
                _log("UYUSMAZLIK #%d: beklenen %d yazma, gercek %d"
                     % (st["mismatch"], len(exp), len(got)))
                for i, (x, y) in enumerate(zip(exp, got)):
                    if x != y:
                        _log("   ilk fark #%d model=%s motor=%s"
                             % (i, (hex(x[0]), hex(x[1])), (hex(y[0]), hex(y[1]))))
                        break

    uc.hook_add(UC_HOOK_CODE, on_setup, begin=SETUP_VA, end=SETUP_VA)
    if mode == "verify":
        uc.hook_add(UC_HOOK_CODE, on_exit, begin=EXIT_VA, end=EXIT_VA)
        uc.hook_add(UC_HOOK_MEM_WRITE, on_write)
    return st


def report(st):
    if not st:
        return "blit4: kapali"
    if st["mode"] == "verify":
        return ("blit4 dogrulama: %d cagri kontrol edildi, %d uyusmazlik  %s"
                % (st["checked"], st["mismatch"],
                   "TEMIZ" if st["mismatch"] == 0 else "!!! HATA"))
    return ("blit4: %d cagri, %d HLE ile cozuldu, %d motora birakildi"
            % (st["calls"], st["fast"], st["skipped"]))
