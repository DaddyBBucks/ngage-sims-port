"""MEDIACLIENTAUDIOSTREAM ordinal implementations.

MEDIACLIENTAUDIOSTREAM:0x2 (thunk 0x496304) is an audio-stream object
factory. Confirmed by crash trace: its result is used unconditionally
afterwards (a real caller relies on Symbian's "leave on failure", which
never triggers in this stub environment), so it must return a valid,
method-callable object rather than null.
"""

FACTORY_VA = 0x496304


def handle_factory(ctx, uc):
    from unicorn.arm_const import UC_ARM_REG_R0
    ptr = ctx.allocator.alloc_with_vtable(ctx.vtable_va) if ctx.vtable_va is not None else 0
    uc.reg_write(UC_ARM_REG_R0, ptr)


def build_thunks(thunk_map):
    return {FACTORY_VA: handle_factory}
