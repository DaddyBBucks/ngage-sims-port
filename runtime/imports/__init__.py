"""Symbian DLL import dispatch.

Assembles every confirmed per-ordinal implementation (euser/ws32/fbscli/
estlib/mediaclientaudiostream) into one {thunk_va: handler(ctx, uc)} table,
plus the default fallback policy for every OTHER (unimplemented) import.
"""

from . import euser, ws32, fbscli, estlib, mediaclientaudiostream


def default_stub(ctx, uc):
    """Default policy for any DLL import we have no specific handler for:
    return 0 ("failure"/"no object"). Matches the extremely common Symbian
    idiom of `cmp r0,#0; bne ...` null-checks guarding optional behavior.
    An untested identity-passthrough default was tried in an earlier
    session and found WORSE (it feeds stale/garbage register contents into
    pointer dereferences for ordinals that really do use the 0/nonzero
    convention) -- only ordinals specifically diagnosed to need passthrough
    semantics get their own handler above."""
    from unicorn.arm_const import UC_ARM_REG_R0
    uc.reg_write(UC_ARM_REG_R0, 0)


def build_dispatch(thunk_map, on_key_injected=None):
    """Returns {thunk_va: handler(ctx, uc)}. Any thunk_va present in
    thunk_map but not in the returned dict should use default_stub."""
    thunks = {}
    thunks.update(euser.build_thunks(thunk_map))
    thunks.update(ws32.build_thunks(thunk_map, on_key_injected=on_key_injected))
    thunks.update(fbscli.build_thunks(thunk_map))
    thunks.update(estlib.build_thunks(thunk_map))
    thunks.update(mediaclientaudiostream.build_thunks(thunk_map))
    return thunks
