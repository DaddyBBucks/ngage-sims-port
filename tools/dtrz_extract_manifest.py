"""DTRZ (thesims.dat) archive-format manifest extractor -- v226.

Read-only analysis tool. NEVER writes to the original thesims.dat; only
reads a caller-supplied copy path. Produces a CSV manifest of all 497
entries (name, declared size, type flag, stream classification, and
on-disk offset where it is directly resolvable).

Format summary (fully reverse-engineered and validated this round,
against the real archive + the pre-existing 496-file extractor output;
see NGage_Sims_Bustin_Out_Android_Port_Bulgular_v226.md for full
derivation and evidence):

  Header (9 bytes, offset 0):
    0x00  "DTRZ"           4-byte magic
    0x04  file_count       uint16 LE  (0x01F1 = 497)
    0x06  directory_count  uint16 LE  (0x0001)
    0x08  version          uint8      (0x00)

  Section 1 -- Name table (offset 9..2933, 2924 bytes):
    497 back-to-back NUL-terminated ASCII names, zero gaps.

  Section 2 -- Index table (offset 2934..5913, 2980 bytes):
    entry 0: 4 bytes, all zero.
    entries 1..496: 6 bytes each, `FF FF 00 00 <index:uint16 LE>`.
    Purpose of the `FFFF0000` constant is NOT determined (hash-bucket
    marker or sentinel are plausible guesses, unconfirmed).

  Section 3 -- Per-entry fixed record table (offset 5928..13879,
  497 * 16 = 7952 bytes; note there are 14 header/alignment bytes
  between the end of Section 2 at 5914 and the first record at 5928):
    +0x00  size       uint32 LE  -- validated byte-exact against all
                                    496 non-empty files already produced
                                    by the pre-existing extractor
                                    (`thesims_extracted/`), 496/496 match.
    +0x04  type_flag  uint32 LE  -- 256 = stored/raw (459 entries),
                                    4   = compressed (37 entries),
                                    128 = zero-length special (1 entry,
                                          "thesims.dzs").
    +0x08  8 bytes    unidentified. Contains a slowly-incrementing
           byte-pair sub-field for some entries; not decoded, not
           needed for the manifest.

  Data region:
    Stream A (type_flag == 256): a SINGLE contiguous, zero-gap blob
    in name-table order, starting at absolute offset 13882. Verified
    for 429/430 checkable entries by exact byte-content search against
    the extractor's output (the one exception, entry 397 "02216", is
    explained by duplicate/identical content with a neighboring entry,
    not a real structural gap).

    Stream B (type_flag == 4, "compressed"): occupies the remaining
    file space after Stream A ends (absolute offset 8,936,178 through
    end of file, 2,300,300 bytes total for 37 entries whose *declared*
    (decompressed) size sums to 3,048,257 bytes). Individual per-entry
    offsets/compressed sizes and the compression algorithm are NOT
    resolved by this tool -- open follow-up item.

    thesims.dzs (type_flag == 128, size 0): no data at all.
"""

import csv
import hashlib
import os
import re
import struct
import sys

HEADER_LEN = 9
NAME_TABLE_START = 9
NAME_TABLE_END = 2934
RECORD_TABLE_START = 5928
RECORD_WIDTH = 16
FILE_COUNT = 497
STREAM_A_START = 13882


def parse_names(data):
    names = []
    pos = NAME_TABLE_START
    cur = bytearray()
    while pos < NAME_TABLE_END:
        b = data[pos]
        if b == 0:
            names.append(cur.decode('ascii'))
            cur = bytearray()
        else:
            cur.append(b)
        pos += 1
    assert len(names) == FILE_COUNT, f"expected {FILE_COUNT} names, got {len(names)}"
    return names


def classify(name):
    lname = name.lower()
    if lname.endswith('.s3m'):
        return 'audio (Scream Tracker 3 module)'
    if lname.endswith('.gif'):
        return 'image (GIF - splash/loading screen candidate)'
    if lname.endswith('.dzs'):
        return 'special/placeholder (designer script?)'
    if re.fullmatch(r'\d+', name):
        return 'sprite/graphic (numeric resource ID)'
    return 'other/unclassified'


def build_manifest(dat_path):
    with open(dat_path, 'rb') as f:
        data = f.read()

    assert data[0:4] == b'DTRZ', "not a DTRZ archive (bad magic)"
    file_count = struct.unpack_from('<H', data, 4)[0]
    assert file_count == FILE_COUNT, f"unexpected file_count={file_count}"

    names = parse_names(data)
    sizes = [struct.unpack_from('<I', data, RECORD_TABLE_START + i * RECORD_WIDTH)[0]
              for i in range(FILE_COUNT)]
    types = [struct.unpack_from('<I', data, RECORD_TABLE_START + i * RECORD_WIDTH + 4)[0]
              for i in range(FILE_COUNT)]

    cum = STREAM_A_START
    rows = []
    for i, name in enumerate(names):
        t = types[i]
        sz = sizes[i]
        if t == 256:
            stream = 'A_RAW'
            offset = cum
            cum += sz
        elif t == 4:
            stream = 'B_COMPRESSED'
            offset = None
        else:
            stream = 'SPECIAL_ZEROLEN'
            offset = None
        rows.append({
            'index': i, 'name': name, 'size': sz, 'type_flag': t,
            'stream': stream, 'offset': offset if offset is not None else '',
            'category': classify(name),
        })
    return data, rows


def compare_with_existing_extractor(rows, ext_dir):
    """Cross-check declared sizes against the pre-existing 496-file
    extractor output. Returns (checked_count, mismatch_list)."""
    def ext_name(n):
        return n if '.' in n else n + '.bin'

    ext_files = set(os.listdir(ext_dir))
    checked = 0
    mismatches = []
    for r in rows:
        fn = ext_name(r['name'])
        if fn not in ext_files:
            continue
        checked += 1
        actual = os.path.getsize(os.path.join(ext_dir, fn))
        if actual != r['size']:
            mismatches.append((r['index'], r['name'], r['size'], actual))
    return checked, mismatches


def main():
    if len(sys.argv) < 2:
        print("usage: dtrz_extract_manifest.py <path-to-thesims.dat-COPY> "
              "[extracted-dir-for-comparison] [out.csv]")
        sys.exit(1)

    dat_path = sys.argv[1]
    ext_dir = sys.argv[2] if len(sys.argv) > 2 else None
    out_csv = sys.argv[3] if len(sys.argv) > 3 else 'dtrz_manifest.csv'

    with open(dat_path, 'rb') as f:
        sha = hashlib.sha256(f.read()).hexdigest()
    print(f"input: {dat_path}")
    print(f"sha256: {sha}")

    data, rows = build_manifest(dat_path)

    with open(out_csv, 'w', newline='') as f:
        w = csv.DictWriter(f, fieldnames=['index', 'name', 'size', 'type_flag',
                                            'stream', 'offset', 'category'])
        w.writeheader()
        w.writerows(rows)
    print(f"manifest written: {out_csv} ({len(rows)} rows)")

    from collections import Counter
    print("category counts:", dict(Counter(r['category'] for r in rows)))
    print("stream counts:", dict(Counter(r['stream'] for r in rows)))

    if ext_dir:
        checked, mismatches = compare_with_existing_extractor(rows, ext_dir)
        print(f"compared against existing extractor: {checked} files checked, "
              f"{len(mismatches)} mismatches")
        for m in mismatches:
            print("  MISMATCH:", m)


if __name__ == '__main__':
    main()
