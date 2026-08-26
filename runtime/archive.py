"""thesims.dat archive I/O.

The game's resource archive layer (Open/Close/FindByName/Read/New at
0x40e164 and friends) is a CUSTOM format on top of a real ANSI-C-style
stdio layer exposed through ESTLIB ordinals -- NOT EFSRV (confirmed: EFSRV
is never called). Confirmed signatures, by direct disassembly:

  ESTLIB:0x3a  fopen(path, mode)                 -- mode literal "rb"
  ESTLIB:0x31  fclose(stream)
  ESTLIB:0x3e  fread(ptr, size, nmemb, stream)
  ESTLIB:0x41  fseek(stream, offset, whence)
  ESTLIB:0x44  fwrite(ptr, size, nmemb, stream)
  ESTLIB:0x45  fgetc(stream)
  ESTLIB:0xae  memcmp(a, b, n)                    -- magic literal "DTRZ"
  ESTLIB:0xaf  memcpy(dest, src, n)
  ESTLIB:0x07  memmove(dest, src, n)               -- overlap-safe

Backing every fopen() with the REAL thesims.dat file gives the archive's
own TOC-loading/lookup logic real bytes to parse, instead of a stub.
"""

THESIMS_DAT_PATH = None

FILEIO_ORDINALS = {0x07, 0x31, 0x3A, 0x3E, 0x41, 0x44, 0x45, 0xAE, 0xAF}


def _read_c_string(uc, address, limit=512):
    raw = bytearray()
    for i in range(limit):
        b = uc.mem_read(address + i, 1)[0]
        if b == 0:
            break
        raw.append(b)
    return raw.decode("latin-1", errors="replace")


def handle_fopen(ctx, uc):
    from unicorn.arm_const import UC_ARM_REG_R0, UC_ARM_REG_R1
    try:
        requested = _read_c_string(uc, uc.reg_read(UC_ARM_REG_R0))
        mode = _read_c_string(uc, uc.reg_read(UC_ARM_REG_R1), limit=16)
        normalized = requested.replace("/", "\\").upper()
        if normalized.endswith("\\THESIMS.SAV"):
            if not ctx.save_file_path:
                uc.reg_write(UC_ARM_REG_R0, 0)
                return
            backing_path = ctx.save_file_path
        else:
            # Preserve the confirmed resource-archive behavior for all
            # historical callers. v233 only separates the newly proven SAV
            # pathname instead of handing it thesims.dat by mistake.
            backing_path = ctx.archive_file_path or THESIMS_DAT_PATH
            if not backing_path:
                uc.reg_write(UC_ARM_REG_R0, 0)
                return
        py_mode = mode if mode in ("rb", "r+b", "wb", "w+b", "ab", "a+b") else "rb"
        fh = open(backing_path, py_mode)
        handle = ctx.estlib_next_handle[0]
        ctx.estlib_next_handle[0] += 1
        ctx.estlib_files[handle] = fh
        uc.reg_write(UC_ARM_REG_R0, handle)
    except Exception:
        uc.reg_write(UC_ARM_REG_R0, 0)


def handle_fclose(ctx, uc):
    from unicorn.arm_const import UC_ARM_REG_R0
    stream = uc.reg_read(UC_ARM_REG_R0)
    fh = ctx.estlib_files.pop(stream, None)
    if fh is None:
        uc.reg_write(UC_ARM_REG_R0, 0xFFFFFFFF)
        return
    try:
        fh.close()
        uc.reg_write(UC_ARM_REG_R0, 0)
    except Exception:
        uc.reg_write(UC_ARM_REG_R0, 0xFFFFFFFF)


def handle_fread(ctx, uc):
    from unicorn.arm_const import UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2, UC_ARM_REG_R3, UC_ARM_REG_LR
    ptr = uc.reg_read(UC_ARM_REG_R0)
    size = uc.reg_read(UC_ARM_REG_R1)
    nmemb = uc.reg_read(UC_ARM_REG_R2)
    stream = uc.reg_read(UC_ARM_REG_R3)
    fh = ctx.estlib_files.get(stream)
    if fh is None or size == 0 or nmemb == 0:
        uc.reg_write(UC_ARM_REG_R0, 0)
        return
    offset_before = fh.tell()
    raw = fh.read(size * nmemb)
    if raw:
        uc.mem_write(ptr, raw)
    # v227 (DTRZ Stream B research) -- read-only observation, never affects
    # the actual read/return behavior above.
    if ctx.archive_read_log is not None:
        ctx.archive_read_log.append({
            'insn': ctx.insn_count[0],
            'offset': offset_before,
            'length_requested': size * nmemb,
            'length_returned': len(raw),
            'lr': uc.reg_read(UC_ARM_REG_LR),
        })
    uc.reg_write(UC_ARM_REG_R0, len(raw) // size)


def handle_fseek(ctx, uc):
    from unicorn.arm_const import UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2
    stream = uc.reg_read(UC_ARM_REG_R0)
    offset = uc.reg_read(UC_ARM_REG_R1)
    whence = uc.reg_read(UC_ARM_REG_R2)
    if offset >= 0x80000000:
        offset -= 0x100000000
    fh = ctx.estlib_files.get(stream)
    if fh is None:
        uc.reg_write(UC_ARM_REG_R0, 0xFFFFFFFF)
        return
    try:
        fh.seek(offset, whence)
        uc.reg_write(UC_ARM_REG_R0, 0)
    except Exception:
        uc.reg_write(UC_ARM_REG_R0, 0xFFFFFFFF)


def handle_fwrite(ctx, uc):
    from unicorn.arm_const import UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2, UC_ARM_REG_R3
    ptr = uc.reg_read(UC_ARM_REG_R0)
    size = uc.reg_read(UC_ARM_REG_R1)
    nmemb = uc.reg_read(UC_ARM_REG_R2)
    stream = uc.reg_read(UC_ARM_REG_R3)
    fh = ctx.estlib_files.get(stream)
    if fh is None or size == 0 or nmemb == 0:
        uc.reg_write(UC_ARM_REG_R0, 0)
        return
    try:
        raw = bytes(uc.mem_read(ptr, size * nmemb))
        written = fh.write(raw)
        fh.flush()
        uc.reg_write(UC_ARM_REG_R0, written // size)
    except Exception:
        uc.reg_write(UC_ARM_REG_R0, 0)


def handle_fgetc(ctx, uc):
    from unicorn.arm_const import UC_ARM_REG_R0
    stream = uc.reg_read(UC_ARM_REG_R0)
    fh = ctx.estlib_files.get(stream)
    if fh is None:
        uc.reg_write(UC_ARM_REG_R0, 0xFFFFFFFF)
        return
    b = fh.read(1)
    uc.reg_write(UC_ARM_REG_R0, b[0] if b else 0xFFFFFFFF)


def handle_memcmp(ctx, uc):
    from unicorn.arm_const import UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2
    a = uc.reg_read(UC_ARM_REG_R0)
    b = uc.reg_read(UC_ARM_REG_R1)
    n = uc.reg_read(UC_ARM_REG_R2)
    try:
        ba = uc.mem_read(a, n)
        bb = uc.mem_read(b, n)
        uc.reg_write(UC_ARM_REG_R0, 0 if bytes(ba) == bytes(bb) else 1)
    except Exception:
        uc.reg_write(UC_ARM_REG_R0, 1)


def handle_memcpy(ctx, uc):
    from unicorn.arm_const import UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2
    dest = uc.reg_read(UC_ARM_REG_R0)
    src = uc.reg_read(UC_ARM_REG_R1)
    n = uc.reg_read(UC_ARM_REG_R2)
    try:
        uc.mem_write(dest, bytes(uc.mem_read(src, n)))
    except Exception:
        pass
    uc.reg_write(UC_ARM_REG_R0, dest)


def handle_memmove(ctx, uc):
    """ESTLIB:0x07 -- overlap-safe byte move.

    The identity is established by four static call sites.  In particular,
    0x473c38 calls it with dest=src+4 and n=12, which rules out memcpy's
    non-overlap contract and matches memmove exactly.  DZIP's Huffman table
    builder also depends on the two overlapping rearrangements at
    0x4740d4/0x4740e8.
    """
    from unicorn.arm_const import UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2
    dest = uc.reg_read(UC_ARM_REG_R0)
    src = uc.reg_read(UC_ARM_REG_R1)
    n = uc.reg_read(UC_ARM_REG_R2)
    try:
        data = bytes(uc.mem_read(src, n))
        uc.mem_write(dest, data)
    except Exception:
        pass
    uc.reg_write(UC_ARM_REG_R0, dest)


_ORDINAL_HANDLERS = {
    0x07: handle_memmove,
    0x31: handle_fclose,
    0x3A: handle_fopen,
    0x3E: handle_fread,
    0x41: handle_fseek,
    0x44: handle_fwrite,
    0x45: handle_fgetc,
    0xAE: handle_memcmp,
    0xAF: handle_memcpy,
}


def handle_fileio(ctx, uc, ordv):
    _ORDINAL_HANDLERS[ordv](ctx, uc)
