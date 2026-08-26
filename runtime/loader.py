"""LXCE binary loader.

Maps the static ARM32 LXCE image ("The Sims: Bustin' Out", N-Gage/Symbian)
into a Unicorn address space, plus the stack. This is pure, confirmed
mechanical fact about the file format (segment table verified against the
LXCE header and cross-checked by successful execution) -- nothing here is a
guess or a workaround, so it belongs in runtime/, not patches.py.
"""

import struct

# Segment layout: (name, file_offset, file_size, virtual_address).
# file_offset=None means zero-filled (BSS), not backed by file bytes.
SEGMENTS = [
    ("CODE",   0x38,      0xAAC00,  0x401000),
    ("DATA",   0xAAC38,   0x42A800, 0x4AC000),
    ("BSS",    None,      0x255E00, 0x8D7000),
    ("EXTRA1", 0x4D5438,  0x1200,   0xB2D000),
    ("EXTRA2", 0x4D6638,  0x9C00,   0xB2F000),
]

STACK_VA = 0x10000000
STACK_SIZE = 0x100000

# Unicorn defaults LR to 0 at start, so a top-level `bx lr` eventually lands
# on PC=0 -- an ambiguous unmapped-fetch fault. Seed LR with a page we map
# and recognize instead, so "the whole call tree returned" becomes a clean,
# identifiable stop condition (see runtime/loader.RETURN_SENTINEL_VA).
RETURN_SENTINEL_VA = 0x30000008


def align_up(x, page=0x1000):
    return (x + page - 1) & ~(page - 1)


def load_binary(uc, binary_path):
    """Map CODE/DATA/BSS/EXTRA segments and the stack. Returns a dict of the
    addresses callers need (stack pointer, return sentinel)."""
    data = open(binary_path, "rb").read()

    for name, foff, fsize, va in SEGMENTS:
        msize = align_up(fsize)
        uc.mem_map(va, msize)
        if foff is not None:
            uc.mem_write(va, data[foff:foff + fsize])

    uc.mem_map(STACK_VA, STACK_SIZE)
    sp = STACK_VA + STACK_SIZE - 0x1000

    from unicorn.arm_const import UC_ARM_REG_SP, UC_ARM_REG_LR
    uc.reg_write(UC_ARM_REG_SP, sp)
    uc.reg_write(UC_ARM_REG_LR, RETURN_SENTINEL_VA)

    return {
        "sp": sp,
        "stack_va": STACK_VA,
        "stack_size": STACK_SIZE,
        "return_sentinel_va": RETURN_SENTINEL_VA,
        "raw_data": data,
    }


def va_to_off(va):
    """Convert a runtime virtual address back to a file offset, for static
    (offline, non-emulated) disassembly/inspection of the CODE segment."""
    return va - 0x401000 + 0x38
