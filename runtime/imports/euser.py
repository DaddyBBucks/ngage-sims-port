"""EUSER ordinal implementations.

Each entry below is a CONFIRMED-necessary behavior (diagnosed from an actual
crash trace, not a guess) -- if the game reaches these calls at all, it
cannot proceed correctly without a real implementation. Experimental /
unconfirmed overrides belong in patches.py instead.
"""

import math
import struct

# Symbian exports several distinct heap-alloc entry points (Alloc/AllocZ/
# AllocL/AllocLC/...) as separate ordinals. Each confirmed by crash trace to
# be "size in R0, pointer out" and used unconditionally afterwards (the
# original code relies on Symbian's "leave on failure", which never
# triggers in this stub environment).
ALLOC_ORDINALS = {0x3, 0x62E, 0x5E1, 0x23}

# EUSER:0x5e3 is __builtin_vec_new (confirmed by the ROM/IDA symbol table).
# It allocates raw array storage.  Stamping ctx.vtable_va into byte zero, as
# the old generic allocator did, corrupts the first array element.  This was
# directly observed in DZIP's Huffman-weight array as 0x30001000 split into
# the bogus first two u16 weights 0x1000/0x3000, causing validation error 5.
RAW_ALLOC_ORDINALS = {0x5E3}

# EUSER:0x357 (thunk 0x495d34): called with R0 = pointer to a small
# stack-local object, result dereferenced with no null check right after --
# a descriptor accessor (TDes::Ptr()-style) that returns a pointer at/near
# the object itself. Must return R0 unchanged, not zero it.
IDENTITY_PASSTHROUGH_VAS = {0x495D34}

# EUSER:0x83 (thunk 0x495fd4): called as R0=self (an object pointer, not a
# byte count) but both consumers of its return treat it as a valid pointer
# to a >=0x100-byte buffer -- reads as a Grow()-style call. We can't
# replicate its internal size math, so hand back a fixed generous buffer.
FIXED_SIZE_ALLOC_VAS = {0x495FD4: 0x200}

# GCC EABI runtime helpers the compiler emits for plain 32-bit '%' and '/'
# wherever no hardware divide instruction is used. NOT Symbian APIs, but
# they arrive as unresolved imports the same way -- our generic
# "unimplemented thunk returns 0" default was silently zeroing every
# modulo/division in the game.
MODSI3_VA = 0x495C94  # EUSER:0x621  __modsi3(a, b) -> a % b
DIVSI3_VA = 0x495C14  # EUSER:0x5EA  __divsi3(a, b) -> a / b


def _to_signed(u32):
    return struct.unpack("<i", struct.pack("<I", u32))[0]


def _to_unsigned(i32):
    return struct.unpack("<I", struct.pack("<i", i32))[0]


def handle_alloc(ctx, uc):
    from unicorn.arm_const import UC_ARM_REG_R0
    req_size = uc.reg_read(UC_ARM_REG_R0)
    ptr = ctx.allocator.alloc(req_size)
    if ptr != 0 and req_size >= 4 and ctx.vtable_va is not None:
        uc.mem_write(ptr, struct.pack("<I", ctx.vtable_va))
    uc.reg_write(UC_ARM_REG_R0, ptr)


def handle_raw_alloc(ctx, uc):
    """Allocate array storage without manufacturing an object vtable."""
    from unicorn.arm_const import UC_ARM_REG_R0
    req_size = uc.reg_read(UC_ARM_REG_R0)
    uc.reg_write(UC_ARM_REG_R0, ctx.allocator.alloc(req_size))


def handle_identity_passthrough(ctx, uc):
    pass  # R0 already holds the caller's object pointer -- leave it alone


def handle_fixed_size_alloc(ctx, uc, size):
    from unicorn.arm_const import UC_ARM_REG_R0
    ptr = ctx.allocator.alloc(size)
    if ptr != 0 and ctx.vtable_va is not None:
        uc.mem_write(ptr, struct.pack("<I", ctx.vtable_va))
    uc.reg_write(UC_ARM_REG_R0, ptr)


def handle_modsi3(ctx, uc):
    from unicorn.arm_const import UC_ARM_REG_R0, UC_ARM_REG_R1
    a = _to_signed(uc.reg_read(UC_ARM_REG_R0))
    b = _to_signed(uc.reg_read(UC_ARM_REG_R1))
    result = 0 if b == 0 else int(math.fmod(a, b))  # C semantics: sign of dividend
    uc.reg_write(UC_ARM_REG_R0, _to_unsigned(result))


def handle_divsi3(ctx, uc):
    from unicorn.arm_const import UC_ARM_REG_R0, UC_ARM_REG_R1
    a = _to_signed(uc.reg_read(UC_ARM_REG_R0))
    b = _to_signed(uc.reg_read(UC_ARM_REG_R1))
    result = 0 if b == 0 else int(math.trunc(a / b))  # truncate toward zero
    uc.reg_write(UC_ARM_REG_R0, _to_unsigned(result))


def build_thunks(thunk_map):
    """Return {va: handler(ctx, uc)} for every confirmed EUSER ordinal."""
    thunks = {}
    for va, (dll, ordv) in thunk_map.items():
        if dll != "EUSER":
            continue
        if ordv in RAW_ALLOC_ORDINALS:
            thunks[va] = handle_raw_alloc
        elif ordv in ALLOC_ORDINALS:
            thunks[va] = handle_alloc
        elif va in IDENTITY_PASSTHROUGH_VAS:
            thunks[va] = handle_identity_passthrough
        elif va in FIXED_SIZE_ALLOC_VAS:
            size = FIXED_SIZE_ALLOC_VAS[va]
            thunks[va] = (lambda ctx, uc, _size=size: handle_fixed_size_alloc(ctx, uc, _size))
    thunks[MODSI3_VA] = handle_modsi3
    thunks[DIVSI3_VA] = handle_divsi3
    return thunks
