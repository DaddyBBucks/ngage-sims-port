"""ESTLIB (C runtime) ordinal implementations.

File-I/O ordinals (fopen/fread/fseek/fgetc/memcmp/memcpy) delegate to
runtime/archive.py, which backs them with the real thesims.dat file.
Everything below is a small, confirmed C-library primitive the archive
lookup code (FindByName() and friends) depends on -- each diagnosed from a
direct crash/mismatch trace, not guessed.
"""

from .. import archive


def handle_strlen(ctx, uc):
    # ESTLIB:0x9 -- confirmed via trace: called on the resource-name
    # 8-bit->16-bit widening helper's source string. Cap at 4096 to avoid
    # runaway on a garbage pointer.
    from unicorn.arm_const import UC_ARM_REG_R0
    str_ptr = uc.reg_read(UC_ARM_REG_R0)
    length = 0
    try:
        while length < 4096:
            if uc.mem_read(str_ptr + length, 1) == b"\x00":
                break
            length += 1
    except Exception:
        pass
    uc.reg_write(UC_ARM_REG_R0, length)


def handle_toupper(ctx, uc):
    # ESTLIB:0xaa -- FindByName()'s case-insensitive comparison loops call
    # this on both sides of every byte compare.
    from unicorn.arm_const import UC_ARM_REG_R0
    c = uc.reg_read(UC_ARM_REG_R0) & 0xFF
    if 0x61 <= c <= 0x7A:
        c -= 0x20
    uc.reg_write(UC_ARM_REG_R0, c)


def handle_strcpy(ctx, uc):
    # ESTLIB:0xb5 -- FindByName() copies the caller's (already-narrowed,
    # 8-bit) search name into a local stack buffer via this call.
    from unicorn.arm_const import UC_ARM_REG_R0, UC_ARM_REG_R1
    dest = uc.reg_read(UC_ARM_REG_R0)
    src = uc.reg_read(UC_ARM_REG_R1)
    try:
        i = 0
        while i < 260:
            ch = uc.mem_read(src + i, 1)[0]
            uc.mem_write(dest + i, bytes([ch]))
            if ch == 0:
                break
            i += 1
    except Exception:
        pass
    uc.reg_write(UC_ARM_REG_R0, dest)


def handle_sprintf_2digit(ctx, uc):
    # ESTLIB:0x52 -- confirmed by reading the format literal at the call
    # site: "%02d%02d" (category, sub-item), not a flat 4-digit index.
    from unicorn.arm_const import UC_ARM_REG_R0, UC_ARM_REG_R2, UC_ARM_REG_R3
    dest = uc.reg_read(UC_ARM_REG_R0)
    value1 = uc.reg_read(UC_ARM_REG_R2)
    value2 = uc.reg_read(UC_ARM_REG_R3)
    formatted = f"{value1 % 100:02d}{value2 % 100:02d}".encode() + b"\x00"
    try:
        uc.mem_write(dest, formatted)
    except Exception:
        pass
    uc.reg_write(UC_ARM_REG_R0, dest)


def handle_strchr(ctx, uc):
    # ESTLIB:0xbe -- used by FindByName()/Open() to split "dir\name" on the
    # '\' separator.
    from unicorn.arm_const import UC_ARM_REG_R0, UC_ARM_REG_R1
    s = uc.reg_read(UC_ARM_REG_R0)
    ch = uc.reg_read(UC_ARM_REG_R1) & 0xFF
    found = 0
    try:
        i = 0
        while i < 512:
            b = uc.mem_read(s + i, 1)[0]
            if b == ch:
                found = s + i
                break
            if b == 0:
                break
            i += 1
    except Exception:
        pass
    uc.reg_write(UC_ARM_REG_R0, found)


_ORDINAL_HANDLERS = {
    0x9: handle_strlen,
    0xAA: handle_toupper,
    0xB5: handle_strcpy,
    0x52: handle_sprintf_2digit,
    0xBE: handle_strchr,
}


def build_thunks(thunk_map):
    thunks = {}
    for va, (dll, ordv) in thunk_map.items():
        if dll != "ESTLIB":
            continue
        if ordv in _ORDINAL_HANDLERS:
            thunks[va] = _ORDINAL_HANDLERS[ordv]
        elif ordv in archive.FILEIO_ORDINALS:
            thunks[va] = (lambda ctx, uc, _ordv=ordv: archive.handle_fileio(ctx, uc, _ordv))
    return thunks
