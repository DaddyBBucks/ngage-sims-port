"""Heap / bump allocator.

Symbian's EUSER exports several heap-alloc entry points (Alloc/AllocZ/
AllocL/AllocLC/... are separate ordinals under the hood, see
runtime/imports/euser.py's EUSER_ALLOC_ORDINALS). All of them need a real
backing store -- returning 0 (our generic "unimplemented thunk" default)
poisons every object built from the result and cascades into null-deref
faults downstream. This is confirmed necessary runtime behavior (Symbian
code cannot function without a working allocator), not a workaround, so it
lives here rather than in patches.py.
"""

import struct

HEAP_VA = 0x20000000
HEAP_SIZE = 0x1000000  # 16 MB


class BumpAllocator:
    """A simple bump allocator: never frees, 8-byte aligned, backed by one
    fixed-size mapped region. Sufficient because our emulation runs are
    bounded (tens of millions of instructions, not a long-lived device) --
    a real allocator's free-list bookkeeping isn't needed."""

    def __init__(self, uc, base=HEAP_VA, size=HEAP_SIZE):
        self.uc = uc
        self.base = base
        self.size = size
        self.next = base
        uc.mem_map(base, size)

    def alloc(self, size):
        size = (size + 7) & ~7
        if size == 0:
            size = 8
        ptr = self.next
        if ptr + size > self.base + self.size:
            return 0  # fake heap exhausted
        self.next += size
        return ptr

    def alloc_with_vtable(self, vtable_va, min_size=64):
        """Bump-allocate a block and stamp its first word with a vtable
        pointer, so the result is safe to use as a C++-style object (many
        Symbian call sites dereference [obj+0]->vtable immediately)."""
        ptr = self.alloc(min_size)
        if ptr != 0:
            self.uc.mem_write(ptr, struct.pack("<I", vtable_va))
        return ptr
