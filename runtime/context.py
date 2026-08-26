"""Shared runtime context.

A small bag of the live objects the import implementations (runtime/imports/)
and the subsystem modules (graphics/input/archive) all need access to. Built
once in run.py and threaded through every hook.
"""


class RuntimeContext:
    def __init__(self, uc, allocator):
        self.uc = uc
        self.allocator = allocator

        # Filled in by patches.setup_fake_vtable_trap() -- the shared
        # "unimplemented vtable method" trap address. Import handlers that
        # hand back freshly-allocated objects (factories, fixed-size allocs)
        # stamp this vtable into them so a later virtual call on an object we
        # couldn't fully construct lands on a harmless trap instead of a
        # garbage/null pointer.
        self.vtable_va = None

        # runtime/graphics.py state
        self.dataaddress_cache = {}
        self.tbitmaputil_bitmap_of = {}

        # runtime/input.py state
        self.event_queue = None       # collections.deque, set by input.py
        self.refill_event_queue = None  # callback, set by the caller (research/run)

        # runtime/archive.py state
        self.estlib_files = {}
        self.estlib_next_handle = [0x60000000]
        self.archive_file_path = None
        self.save_file_path = None
        # v227 (DTRZ Stream B research): when not None, a list that
        # handle_fread() appends {offset, length_requested, length_returned}
        # dicts to -- lets us observe, from a REAL emulator run, exactly
        # which byte ranges of thesims.dat the game itself reads. Read-only
        # instrumentation; never affects file contents or control flow.
        self.archive_read_log = None
        self.text35_fallback_hits = 0

        # Diagnostics counters that runtime code itself relies on for
        # correctness (not just logging) -- e.g. instruction counter used by
        # snapshotting. Research hooks read this too.
        self.insn_count = [0]
