"""Oyunun zaman kaynagi (v348).

KOK NEDEN
---------
`TTime::HomeTime()` (EUSER ordinal 0x213, thunk 0x496254) hic
uygulanmamisti. Oyunun milisaniye saati:

    0x488ff8  GetTimeMs():
        sub sp, #8
        mov r0, sp
        bl  0x496254
        ldr r0, [r4, #4]
        ldr r3, [sp]
        lsl r0, r0, #0x16
        orr r0, r0, r3, lsr #10

HomeTime hicbir sey yazmadigi icin o 8 bayt YIGIN COPUYDU. Olculdu
(tools/clock_probe_v348.py, 200M talimatlik kosum): 279 cagri, yalnizca
8 farkli deger ve monoton degil.

KIPLER
------
    frozen   eski davranis
    virtual  talimat sayacindan turetilir, determinist
    real     duvar saati, etkilesimli oyun icin
"""
import time

_DAYS_TO_2003_11_01 = 731_885
BASE_US = _DAYS_TO_2003_11_01 * 86_400 * 1_000_000
INSN_PER_US = 104


class Clock:
    def __init__(self, mode="virtual", ctx=None, insn_per_us=INSN_PER_US):
        self.mode = mode
        self.ctx = ctx
        self.insn_per_us = insn_per_us
        self._t0 = time.perf_counter()
        self.calls = 0
        self.after_calls = 0
        self.after_us = 0

    def now_us(self):
        self.calls += 1
        if self.mode == "real":
            return BASE_US + int((time.perf_counter() - self._t0) * 1_000_000) + self.after_us
        if self.mode == "virtual":
            n = self.ctx.insn_count[0] if self.ctx is not None else 0
            return BASE_US + n // self.insn_per_us + self.after_us
        return BASE_US

    def note_after(self, us):
        self.after_calls += 1
        if self.mode == "virtual" and 0 < us < 5_000_000:
            self.after_us += us

    def summary(self):
        return {"mode": self.mode, "hometime_calls": self.calls,
                "after_calls": self.after_calls, "after_us": self.after_us}
