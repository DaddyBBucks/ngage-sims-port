"""WS32 (window server) ordinal implementations.

WS32:0x76 (GetEvent) is delegated to runtime/input.py, which owns the real
TWsEvent-filling logic. Everything else here is a small, confirmed-correct
fact about a specific ordinal.
"""

import struct

from .. import input as input_mod

# WS32:0x114 (thunk 0x4965c4): called right after an EUSER alloc, result
# stored into the same object slot as the alloc'd pointer -- a
# constructor/ConstructL idiom. Must return R0 unchanged.
IDENTITY_PASSTHROUGH_VAS = {0x4965C4}

# WS32:0x12c (thunk 0x496724): a TDisplayMode query, compared against 7
# (EColor64K) / 0xa (EColor4K). Cross-checked against the official SDL
# N-Gage port: the real hardware display mode is EColor4K (0xa) -- this is
# a confirmed fact about the target device, not a guess.
FIXED_RETURN_VAS = {0x496724: 0xA}


def handle_identity_passthrough(ctx, uc):
    pass


def handle_fixed_return(ctx, uc, value):
    from unicorn.arm_const import UC_ARM_REG_R0
    uc.reg_write(UC_ARM_REG_R0, value)


def build_thunks(thunk_map, on_key_injected=None):
    thunks = {}
    for va in IDENTITY_PASSTHROUGH_VAS:
        thunks[va] = handle_identity_passthrough
    for va, value in FIXED_RETURN_VAS.items():
        thunks[va] = (lambda ctx, uc, _v=value: handle_fixed_return(ctx, uc, _v))
    thunks[input_mod.GETEVENT_THUNK_VA] = (
        lambda ctx, uc: input_mod.handle_get_event(ctx, uc, on_injected=on_key_injected)
    )
    return thunks
