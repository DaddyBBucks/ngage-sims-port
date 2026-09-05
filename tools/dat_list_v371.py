"""v371: thesims.dat arsiv kayitlarini BAGIMSIZ listeler.

Salt okunur. Arsivi asla degistirmez.

Bicim v265'te cozuldu ve dogrulandi (bkz. tools/dtrz_codec_v265.py); bu arac
o belgelenmis duzeni bagimsiz olarak yeniden uygular ve her adimi DOGRULAR:
kayit uzantilarinin veri bolgesini bosluksuz/ortusmesiz doseyip dosemedigi,
adet/ad tablosu/dizin tablosu sinirlarinin tutup tutmadigi.

    0x0000  baslik, 9 bayt: "DTRZ", dosya_sayisi u16, dizin_sayisi u16,
                            surum u8
    0x0009  ad tablosu: dosya_sayisi adet NUL sonlu ASCII ad
    0x0B76  dizin tablosu: 4 sifir bayt + dosya_sayisi * 6 bayt
                            (FF FF <son:u8> 00 <indeks:u16 LE>)
    0x1720  KAYIT TABLOSU (5920), dosya_sayisi * 16 bayt:
              +0x00  offset     u32  dosyadaki mutlak konum
              +0x04  stored     u32  dosyada kapladigi bayt
              +0x08  size       u32  acilmis boyut
              +0x0c  type_flag  u32  256=ham, 4=Stream B sikistirilmis,
                                     128=sifir uzunluklu ozel
    0x3630  KODEK PARAMETRE BASLIGI, 10 bayt (motor 0x475004'te
            codec_obj+0x24..0x2d'ye birebir kopyalar)
    0x363A  veri bolgesi .. EOF

Kullanim:
    python3 tools/dat_list_v371.py thesims.dat            # ozet + dogrulama
    python3 tools/dat_list_v371.py thesims.dat --all      # butun kayitlar
    python3 tools/dat_list_v371.py thesims.dat --name 0100
"""
import os
import struct
import sys

HDR = 0
NAME_TABLE = 9
RECORD_TABLE = 5920
RECORD_SIZE = 16
CODEC_HDR_LEN = 10
TYPE_NAMES = {256: "ham (stored)", 4: "Stream B (sikistirilmis)",
              128: "sifir uzunluklu ozel"}


def read_archive(path):
    d = open(path, "rb").read()
    if d[:4] != b"DTRZ":
        raise SystemExit("DTRZ sihirli sozcugu yok: %r" % d[:4])
    count, dircount = struct.unpack_from("<HH", d, 4)
    version = d[8]

    names, p = [], NAME_TABLE
    for _ in range(count):
        e = d.index(b"\0", p)
        names.append(d[p:e].decode("ascii", "replace"))
        p = e + 1
    name_end = p

    index_start = name_end
    index_end = index_start + 4 + count * 6

    recs = []
    for i in range(count):
        off, stored, size, tf = struct.unpack_from(
            "<4I", d, RECORD_TABLE + i * RECORD_SIZE)
        recs.append({"i": i, "name": names[i], "offset": off,
                     "stored": stored, "size": size, "type_flag": tf})
    rec_end = RECORD_TABLE + count * RECORD_SIZE
    codec = d[rec_end:rec_end + CODEC_HDR_LEN]
    data_start = rec_end + CODEC_HDR_LEN
    return {"raw": d, "count": count, "dircount": dircount, "version": version,
            "names": names, "name_end": name_end, "index_start": index_start,
            "index_end": index_end, "records": recs, "rec_end": rec_end,
            "codec": codec, "data_start": data_start}


def verify(a):
    """Belgelenmis duzeni bu dosya uzerinde DOGRULA."""
    out, ok = [], True
    d = a["raw"]

    def chk(cond, msg):
        nonlocal ok
        ok &= bool(cond)
        out.append("  [%s] %s" % ("OK " if cond else "HATA", msg))

    chk(a["index_start"] == 2934,
        "ad tablosu 2934'te bitiyor (bulunan %d)" % a["index_start"])
    chk(a["index_end"] == RECORD_TABLE,
        "dizin tablosu %d'te bitiyor = kayit tablosu basi (bulunan %d)"
        % (RECORD_TABLE, a["index_end"]))
    chk(d[a["index_start"]:a["index_start"] + 4] == b"\0\0\0\0",
        "dizin tablosu 4 sifir baytla basliyor")
    # type_flag 128 ("sifir uzunluklu ozel") GERCEK bir uzanti tanimlamaz:
    # v371'de olculdu -- tek ornegi `thesims.dzs`, size=0 ve offset/stored
    # cifti baska bir kaydin (GOTAN.S3M) uzantisinin ICINE dusuyor.
    # Doseme kontrolunden bu yuzden cikarilir.
    live = [r for r in a["records"] if r["stored"] > 0 and r["type_flag"] != 128]
    chk(min(r["offset"] for r in live) == a["data_start"],
        "ilk kayit veri bolgesinin basinda (%d)" % a["data_start"])
    ext = sorted((r["offset"], r["offset"] + r["stored"]) for r in live)
    gaps = overlaps = 0
    cur = a["data_start"]
    for s, e in ext:
        if s > cur:
            gaps += 1
        elif s < cur:
            overlaps += 1
        cur = max(cur, e)
    chk(gaps == 0, "kayit uzantilari arasinda BOSLUK yok (%d)" % gaps)
    chk(overlaps == 0, "kayit uzantilari ORTUSMUYOR (%d)" % overlaps)
    chk(cur == len(d), "son kayit EOF'ta bitiyor (%d / %d)" % (cur, len(d)))
    chk(len(set(a["names"])) == a["count"], "adlar benzersiz")
    special = [r for r in a["records"] if r["type_flag"] == 128]
    chk(all(r["size"] == 0 for r in special),
        "type_flag=128 kayitlarinin hepsinde size==0 (%d kayit)" % len(special))
    return ok, out


def main(argv):
    if len(argv) < 2:
        raise SystemExit(__doc__)
    path = argv[1]
    a = read_archive(path)
    print("=== %s ===" % os.path.basename(path))
    print("  sihirli sozcuk : DTRZ")
    print("  dosya sayisi   : %d" % a["count"])
    print("  dizin sayisi   : %d" % a["dircount"])
    print("  surum          : %d" % a["version"])
    print("  ad tablosu     : %d .. %d" % (NAME_TABLE, a["name_end"]))
    print("  dizin tablosu  : %d .. %d" % (a["index_start"], a["index_end"]))
    print("  kayit tablosu  : %d .. %d  (%d x %d bayt)"
          % (RECORD_TABLE, a["rec_end"], a["count"], RECORD_SIZE))
    print("  kodek basligi  : %s" % a["codec"].hex(" "))
    print("  veri bolgesi   : %d .. %d" % (a["data_start"], len(a["raw"])))

    print("\n=== duzen dogrulamasi ===")
    ok, lines = verify(a)
    print("\n".join(lines))

    import collections
    tc = collections.Counter(r["type_flag"] for r in a["records"])
    print("\n=== type_flag dagilimi ===")
    for t, n in sorted(tc.items()):
        print("  %-5d %-28s %d kayit" % (t, TYPE_NAMES.get(t, "BILINMIYOR"), n))

    want = None
    if "--name" in argv:
        want = argv[argv.index("--name") + 1]
    show_all = "--all" in argv
    rows = [r for r in a["records"] if (want is None or r["name"] == want)]
    if not show_all and want is None:
        rows = rows[:12]
    print("\n=== kayitlar%s ===" % ("" if (show_all or want) else " (ilk 12)"))
    print("  %-4s %-8s %-10s %-9s %-9s %s" %
          ("#", "ad", "offset", "stored", "size", "type"))
    for r in rows:
        print("  %-4d %-8s %-10d %-9d %-9d %d" %
              (r["i"], r["name"], r["offset"], r["stored"], r["size"],
               r["type_flag"]))
    print("\nSONUC: %s" % ("duzen dogrulandi" if ok else "DOGRULAMA KALDI"))
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
