"""v372: varlik saglayici katmani -- thesims.dat'i calisma zamaninda
OPSIYONEL hale getirir.

Oyun kayitlari arsiv Read sarmalayicisi uzerinden ister:

    0x40ec9c  push {r3,lr}          ; r0=hedef, r1=boyut, r2=adet, r3=TUTAMAK
    0x40eca8  ldr r0,[r3,#0x20]     ; arsiv nesnesi
    0x40ecb8  bl  0x40ea44          ; asil okuma
    0x40ecbc  pop {ip,pc}           ; donus r0 = OKUNAN BAYT SAYISI

v372'de olculdu (dordu de dogrulandi):
  tutamak +0x00  kayit ICI imlec; cagri sonunda `total` kadar ilerliyor
  tutamak +0x0c  DIZIN TABLOSU girisine isaretci; oradaki u16 = KAYIT INDEKSI
  tutamak +0x20  arsiv nesnesi
  donus r0       = total = boyut * adet   (10/10 cagride)

Kimlik dogrulamasi: indeks 0 -> "0100", 114 -> "0500", 265 -> "1900"
(manifest sirasiyla birebir).

Bu yuzden bir DirectoryProvider su sekilde calisir: cagrinin BASINDA
kaydin cozulmus baytlarindan [imlec, imlec+total) dilimini hedefe yazar,
imleci ilerletir, r0'a total koyar ve PC'yi LR yaparak motorun okumasini
tamamen ATLAR. Klasorde kayit yoksa mudahale edilmez -- motor eskisi gibi
DAT'tan okur (DatProvider geri dusme yolu).
"""

import json
import os
import struct

READ_WRAPPER_VA = 0x40EC9C
HANDLE_CURSOR = 0x00
HANDLE_INDEX_PTR = 0x0C


class DatProvider:
    """Geri dusme: hicbir kaydi saglamaz, motor DAT'tan okur."""

    name = "DatProvider"

    def has(self, index):
        return False

    def get(self, index):
        return None


class DirectoryProvider:
    """unpacked/manifest.json + records/<ad>.bin klasorunden servis eder."""

    name = "DirectoryProvider"

    def __init__(self, root):
        self.root = root
        man_path = os.path.join(root, "manifest.json")
        with open(man_path) as f:
            man = json.load(f)
        self.records = man["records"]
        self.by_index = {}
        for i, r in enumerate(self.records):
            self.by_index[r.get("index", i)] = r
        self._cache = {}
        self.toc_path = os.path.join(root, "toc.bin")

    def has(self, index):
        r = self.by_index.get(index)
        if r is None:
            return False
        return os.path.exists(os.path.join(self.root, r["file"]))

    def get(self, index):
        if index in self._cache:
            return self._cache[index]
        r = self.by_index.get(index)
        if r is None:
            return None
        p = os.path.join(self.root, r["file"])
        if not os.path.exists(p):
            return None
        with open(p, "rb") as f:
            blob = f.read()
        self._cache[index] = blob
        return blob

    def record_name(self, index):
        r = self.by_index.get(index)
        return r["name"] if r else None


RET_VA = 0x40ECBC


def install(uc, ctx, provider, log=print, mode="skip"):
    """Read sarmalayicisina kanca kur; saglayicidan gelen kayitlari servis et.

    mode="skip"      motorun okumasini tamamen atla (DAT gerekmez)
    mode="overwrite" motor okusun, DONUSTE ciktiyi klasor baytlariyla ez
                     (DAT hala gerekir; yan etki hipotezini ayirt etmek icin)
    """
    from unicorn import UC_HOOK_CODE
    from unicorn.arm_const import (UC_ARM_REG_R0, UC_ARM_REG_R1,
                                   UC_ARM_REG_R2, UC_ARM_REG_R3,
                                   UC_ARM_REG_PC, UC_ARM_REG_LR)
    stats = {"served": 0, "fallback": 0, "bytes": 0, "names": {}, "mode": mode}

    def on_read(uc_, address, size, ud):
        dst = uc_.reg_read(UC_ARM_REG_R0)
        n1 = uc_.reg_read(UC_ARM_REG_R1)
        n2 = uc_.reg_read(UC_ARM_REG_R2)
        handle = uc_.reg_read(UC_ARM_REG_R3)
        total = n1 * n2
        if total <= 0:
            return
        try:
            idx_ptr = struct.unpack(
                "<I", uc_.mem_read(handle + HANDLE_INDEX_PTR, 4))[0]
            index = struct.unpack("<H", uc_.mem_read(idx_ptr, 2))[0]
            cursor = struct.unpack(
                "<I", uc_.mem_read(handle + HANDLE_CURSOR, 4))[0]
        except Exception:
            stats["fallback"] += 1
            return
        blob = provider.get(index)
        if blob is None:
            stats["fallback"] += 1
            return
        chunk = blob[cursor:cursor + total]
        n = len(chunk)
        if mode == "skip":
            if n:
                uc_.mem_write(dst, chunk)
            uc_.mem_write(handle + HANDLE_CURSOR,
                          struct.pack("<I", cursor + n))
            uc_.reg_write(UC_ARM_REG_R0, n)
            uc_.reg_write(UC_ARM_REG_PC, uc_.reg_read(UC_ARM_REG_LR))
        else:
            pending[0] = (dst, chunk)
        stats["served"] += 1
        stats["bytes"] += n
        if n < total:
            stats["short"] = stats.get("short", 0) + 1
        nm = getattr(provider, "record_name", lambda i: None)(index)
        if nm:
            stats["names"][nm] = stats["names"].get(nm, 0) + 1

    pending = [None]

    def on_ret(uc_, address, size, ud):
        if pending[0] is not None:
            d, c = pending[0]
            uc_.mem_write(d, c)
            pending[0] = None

    uc.hook_add(UC_HOOK_CODE, on_read,
                begin=READ_WRAPPER_VA, end=READ_WRAPPER_VA)
    if mode == "overwrite":
        uc.hook_add(UC_HOOK_CODE, on_ret, begin=RET_VA, end=RET_VA)
    ctx.asset_provider_stats = stats
    log("[assets] %s kuruldu (kanca 0x%08x)" % (provider.name, READ_WRAPPER_VA))
    return stats
