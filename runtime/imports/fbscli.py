"""FBSCLI (font & bitmap server client) ordinal implementations.

Delegates entirely to runtime/graphics.py, which owns the DataAddress /
TBitmapUtil behavior.
"""

from .. import graphics


def build_thunks(thunk_map):
    return {
        graphics.DATAADDRESS_THUNK_VA: graphics.handle_dataaddress,
        graphics.TBITMAPUTIL_CTOR_VA: graphics.handle_tbitmaputil_ctor,
        graphics.TBITMAPUTIL_BEGIN_VA: graphics.handle_tbitmaputil_begin,
        graphics.TBITMAPUTIL_END_VA: graphics.handle_tbitmaputil_end,
    }
