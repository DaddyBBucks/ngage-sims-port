"""Experimental / forced bypasses -- EVERYTHING here is a workaround for a
gap in our emulation harness (a missing active-scheduler tick, a missing
capability probe, a missing animation-attach step, etc.), NOT a confirmed
fact about real Symbian/game behavior. runtime/ should keep working, in
some possibly-degraded form, if any single patch here is switched off; the
"patch-free success test" (tools/patch_necessity_test.py) exists precisely
to find out which ones actually are load-bearing for reaching a given
milestone (e.g. module 19) and which are leftover from old debugging that
no longer matters.

Each Patch is keyed by the single PC address where it intervenes (the
"one decision point, nothing upstream touched" technique used throughout
this project's history) so enabling/disabling it is a one-line toggle with
an obvious blast radius.
"""

import struct

from unicorn import UC_PROT_READ, UC_PROT_EXEC


class Patch:
    def __init__(self, name, description, address, on_hit, setup=None, default_enabled=True,
                 address_range=None):
        self.name = name
        self.description = description
        self.address = address          # PC this patch triggers on (exact
                                          # match) -- mutually exclusive with
                                          # address_range, leave None if using it
        self.address_range = address_range  # (lo, hi) half-open [lo, hi) --
                                              # for patches that need to catch
                                              # ANY PC in a region (e.g. a
                                              # whole guard page), not one
                                              # exact instruction address
        self.on_hit = on_hit            # fn(ctx, uc) -> bool (True = stop
                                          # further dispatch for this instr)
        self.setup = setup              # optional fn(ctx, uc) called once
        self.default_enabled = default_enabled
        self.hit_count = 0


# --- individual patches --------------------------------------------------

def _gate1_force(ctx, uc):
    # 0x4353d8: second (final) call site of the readiness-helper 0x436180
    # inside 0x43538c. Natural state is R0!=0 (state==5) here, which the
    # NEXT instruction turns into "capability probe failed". Forcing R0=0
    # only at this exact point (not touching 0x436180 itself, or anything
    # upstream) reaches the per-frame loop's success path.
    from unicorn.arm_const import UC_ARM_REG_R0
    uc.reg_write(UC_ARM_REG_R0, 0)
    return False


def _gate2_force(ctx, uc):
    # 0x4355e8: a second, separate readiness check right after gate1
    # (opposite polarity: caller treats NONZERO as "abort"). Same technique.
    from unicorn.arm_const import UC_ARM_REG_R0
    uc.reg_write(UC_ARM_REG_R0, 0)
    return False


def _make_tick_escape(state):
    def _on_hit(ctx, uc):
        # 0x444838: the active-object tick dispatcher. Its own per-tick
        # "housekeeping" branch fires on ~every pass, so the event-dispatch
        # path (which leads to the real GetEvent/key-input handler) is
        # essentially never reached naturally. Force a "nothing ready"
        # return (R0=0, PC=LR) once every 100 hits instead of permanently
        # killing the tick -- an intermittent escape valve rather than a
        # wholesale bypass.
        from unicorn.arm_const import UC_ARM_REG_R0, UC_ARM_REG_PC, UC_ARM_REG_LR
        state["count"] += 1
        if state["count"] % 100 == 0:
            lr = uc.reg_read(UC_ARM_REG_LR)
            uc.reg_write(UC_ARM_REG_R0, 0)
            uc.reg_write(UC_ARM_REG_PC, lr)
            return True
        return False
    return _on_hit


def _make_event_alt_escape(state):
    def _on_hit(ctx, uc):
        # 0x444838's FIRST readiness check (a different sub-object than the
        # tick escape above) resolves true almost every pass, so the SECOND
        # check (the one event_poll_gate patches) is never reached. Force
        # R3=KRequestPending here 1 time in 15 so the branch immediately
        # following becomes a no-op and PC falls through toward the real
        # event-dispatch path.
        from unicorn.arm_const import UC_ARM_REG_R3
        state["count"] += 1
        if state["count"] % 15 == 0:
            uc.reg_write(UC_ARM_REG_R3, 0x80000001)
        return False
    return _on_hit


def _event_poll_gate(ctx, uc):
    # 0x444870: `cmp r3,#0` right after the active-object's "request ready"
    # gate flag is loaded. That flag is never armed in our stub
    # environment (no real WS32:0x80 EventReady completion), so this branch
    # always skips the real event-dispatch call. Force R3=1 so it falls
    # through instead.
    from unicorn.arm_const import UC_ARM_REG_R3
    uc.reg_write(UC_ARM_REG_R3, 1)
    return False


def _animframe_bypass(ctx, uc):
    # 0x402444: entry of a wrapper whose next few instructions dereference
    # [this+0xdc] (a per-frame animation-frame-table pointer attached by a
    # SEPARATE subsystem, on a schedule our uninterrupted instruction
    # stream doesn't reproduce). When that field is still null -- a real,
    # benign timing gap, not corruption -- simulate this ONE call
    # returning "0 width, 0 height" (an empty/invisible sprite for this
    # frame) instead of faulting.
    from unicorn.arm_const import UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_SP, UC_ARM_REG_PC
    r0 = uc.reg_read(UC_ARM_REG_R0)
    try:
        field_dc = struct.unpack("<I", uc.mem_read(r0 + 0xDC, 4))[0]
    except Exception:
        return False
    if field_dc != 0:
        return False
    r1 = uc.reg_read(UC_ARM_REG_R1)
    sp = uc.reg_read(UC_ARM_REG_SP)
    try:
        ret_addr = struct.unpack("<I", uc.mem_read(sp, 4))[0]
        uc.mem_write(r1, struct.pack("<I", 0))
        uc.mem_write(r1 + 4, struct.pack("<I", 0))
        uc.reg_write(UC_ARM_REG_SP, sp + 4)
        uc.reg_write(UC_ARM_REG_PC, ret_addr)
        return True
    except Exception:
        return False


MODULE_INDEX_GLOBAL = 0xA16AF4       # confirmed: current module/screen index
MODULE_SUBSTATE_GLOBAL = 0xA16B04    # confirmed: shared module sub-state field


def _make_module4_fastforward(state):
    def _on_hit(ctx, uc):
        # 0x438cd4: module 4's internal sub-state switch. Substates 0/1/2
        # are a pure countdown/retry loop (redraw progress bar, reset
        # inactivity timer, clear a bitmap) with no dependency created or
        # consumed -- confirmed by trace. Force straight to substate 3, the
        # exact code the game itself runs once attempts==4 (unconditional
        # request to transition to module 5). Skips a wait loop with no
        # behavioral difference; fires once.
        if state["done"]:
            return False
        uc.mem_write(MODULE_SUBSTATE_GLOBAL, struct.pack("<I", 3))
        state["done"] = True
        return False
    return _on_hit


def _make_module19_sweep(state, dwell=3_000_000, max_state=12, module_index=19):
    def _on_hit(ctx, uc):
        # 0x422794: module 19's Update() entry, a 15-way jump table keyed
        # off MODULE_SUBSTATE_GLOBAL. Waiting for each state's own natural
        # timer left the letter-grid case unreached even after tens of
        # millions of extra instructions. Force the substate forward on a
        # fixed schedule (dwell instructions per state) instead -- each
        # state's own setup code still runs normally, we only skip the
        # waiting. Only ever pushes FORWARD: the game's own logic (driven
        # by real key input) can legitimately advance this state past our
        # target on its own, and forcing it backward was confirmed (an
        # earlier session) to break widget setup.
        if state["reached_insn"] is None:
            try:
                cur_module = struct.unpack("<I", uc.mem_read(MODULE_INDEX_GLOBAL, 4))[0]
            except Exception:
                return False
            if cur_module != module_index:
                return False
            state["reached_insn"] = ctx.insn_count[0]
        elapsed = ctx.insn_count[0] - state["reached_insn"]
        target_state = min(elapsed // dwell, max_state)
        try:
            cur_state = struct.unpack("<I", uc.mem_read(MODULE_SUBSTATE_GLOBAL, 4))[0]
        except Exception:
            return False
        if target_state > cur_state:
            uc.mem_write(MODULE_SUBSTATE_GLOBAL, struct.pack("<I", target_state))
        return False
    return _on_hit


def _make_skip_close_handler():
    def _on_hit(ctx, uc):
        # 0x4446f4: fully disassembled -- its entire body is "mark this
        # view as closing, release one refcount, tail-call the app-wide
        # exit-request setter". Reached from the WS32 event-dispatch chain,
        # almost certainly firing on a stubbed/default event code from our
        # incomplete window-server event queue rather than a real close
        # request. A true no-op here means "this spurious close event
        # never happened", not "skip real work" -- its own disassembly
        # shows nothing else in the function.
        from unicorn.arm_const import UC_ARM_REG_PC, UC_ARM_REG_LR
        uc.reg_write(UC_ARM_REG_PC, uc.reg_read(UC_ARM_REG_LR))
        return True
    return _on_hit


def _r7_zero_experiment(ctx, uc):
    # 0x40e6e4 (`add r7,sp,#4` inside FindByName()): fires whenever our
    # search name starts with '\'. A non-zero R7 here signals "caller wants
    # extension-filtered matching", which rejects our archive's numeric
    # ("0100"-style, no registered extension) entries. Forcing R7=0
    # suppresses that signal. Explicitly a probe, not a confirmed real
    # hardware behavior -- flagged as such since it was first added.
    from unicorn.arm_const import UC_ARM_REG_R7
    uc.reg_write(UC_ARM_REG_R7, 0)
    return False


def _make_hal33_force_success():
    def _on_hit(ctx, uc):
        # WS32:0x33, a HAL capability query. Our generic "unimplemented
        # thunk returns 0" default made downstream code treat the query as
        # failed; forcing success (R0=1) tests whether that unblocks the
        # scancode->logical-key table population. NOT a confirmed real HAL
        # response value.
        from unicorn.arm_const import UC_ARM_REG_R0, UC_ARM_REG_PC, UC_ARM_REG_LR
        lr = uc.reg_read(UC_ARM_REG_LR)
        uc.reg_write(UC_ARM_REG_R0, 1)
        uc.reg_write(UC_ARM_REG_PC, lr)
        return True
    return _on_hit


GLOBAL_BUFFER_SEEDS = {
    # 0x448790 (a zero-fill loop over 0x4780 words) reads its target buffer
    # pointer from this fixed DATA slot, normally populated by an
    # allocation we haven't traced/implemented. Native page zero-init
    # leaves it 0, so the loop's first store faults. Pre-seed it with a
    # real bump-allocated buffer sized from 0x448790's own disassembly
    # (loop count * word size).
    0x4BDCE8: 0x4780 * 4,
}


def _setup_global_buffer_seeds(ctx, uc):
    for slot_va, size in GLOBAL_BUFFER_SEEDS.items():
        ptr = ctx.allocator.alloc(size)
        uc.mem_write(slot_va, struct.pack("<I", ptr))


NULLGUARD_VA = 0x0
NULLGUARD_SIZE = 0x10000


def _setup_nullguard(ctx, uc):
    # A whole FAMILY of small accessor functions read [this+0xdc]-derived
    # pointers with small offsets; when the base is still null (a real,
    # benign construction-order timing gap), the offset read lands on a
    # tiny near-zero address and faults. Map a small all-zero region at
    # VA 0 so any such READ returns zero bytes (an empty/invisible sprite
    # for that object) instead of crashing. Deliberately narrow (only
    # 0x0-0xFFFF) so it shouldn't mask unrelated bugs at real addresses
    # elsewhere.
    #
    # v202 FIX (user-directed harness correction): this page used to be
    # mapped READ+WRITE+EXEC (Unicorn's mem_map default). That let a
    # write through a still-null "this" pointer succeed SILENTLY,
    # poisoning the shared zero page with real data -- which is exactly
    # how the v199/v200 0x4af28c crash happened (a completely unrelated,
    # legitimately-null object later misread that poisoned byte as a
    # real vtable slot). A write through a null pointer is a genuine bug
    # signal and must be treated as a hard, logged fault -- never
    # silently tolerated the way a benign near-null READ is. The page is
    # now mapped READ+EXEC only:
    #   - READ  stays on, so the benign near-null accessor reads above
    #     keep returning clean zero bytes (unchanged behavior).
    #   - EXEC  stays on, so null_pc_trap's code-hook (PatchManager's
    #     address-range dispatch in hook_code) still gets a chance to
    #     intercept PC landing anywhere in this range -- that dispatch
    #     is pure address comparison and never depended on memory
    #     contents, so this is unaffected by the permission change.
    #   - WRITE is now OFF, unconditionally. Any store into 0x0-0xFFFF
    #     now raises UC_ERR_WRITE_PROT, caught by hook_mem_invalid,
    #     logged as a real [FAULT], and left UNHANDLED (emulation stops)
    #     -- exactly like real hardware would fault on a write through a
    #     null/near-null pointer. There is no flag to re-enable writes
    #     here: a write through null is never something to paper over.
    uc.mem_map(NULLGUARD_VA, NULLGUARD_SIZE, UC_PROT_READ | UC_PROT_EXEC)
    uc.mem_write(NULLGUARD_VA, bytes(NULLGUARD_SIZE))


TRAP_VA = 0x30000000
VTABLE_VA = 0x30001000
VTABLE_SLOTS = 256


def _setup_fake_vtable_trap(ctx, uc):
    # Freshly allocated objects are often immediately used as C++-style
    # objects (first word = vtable pointer, methods called via
    # `ldr ip,[r3,#offset]; bx ip`). Prefill every allocation this harness
    # hands out with a pointer to one shared FAKE vtable whose slots all
    # point at TRAP_VA, so a method call through an object we couldn't
    # fully construct lands on a harmless, logged trap instead of a
    # garbage/null-pointer fault. Caveat (not hidden): this also stamps a
    # vtable pointer into allocations that are actually plain data
    # buffers -- watch for that if a crash pattern looks like corrupted
    # data rather than a genuine null-vtable fault.
    uc.mem_map(TRAP_VA, 0x1000)
    uc.mem_write(TRAP_VA, (b"\x1e\xff\x2f\xe1") * (0x1000 // 4))  # ARM `bx lr`
    uc.mem_map(VTABLE_VA, ((VTABLE_SLOTS * 4 + 0xFFF) // 0x1000) * 0x1000)
    uc.mem_write(VTABLE_VA, struct.pack(f"<{VTABLE_SLOTS}I", *([TRAP_VA] * VTABLE_SLOTS)))
    ctx.vtable_va = VTABLE_VA


def _trap_hit(ctx, uc):
    from unicorn.arm_const import UC_ARM_REG_R0, UC_ARM_REG_PC, UC_ARM_REG_LR
    lr = uc.reg_read(UC_ARM_REG_LR)
    uc.reg_write(UC_ARM_REG_R0, 0)
    uc.reg_write(UC_ARM_REG_PC, lr)
    return True


def build_registry(thunk_map):
    """Construct every Patch. Some need thunk_map to resolve a (dll, ordv)
    pair to its thunk VA."""
    registry = {}

    def add(p):
        registry[p.name] = p

    add(Patch("gate1_force",
              "0x4353d8: force the per-frame loop's first capability gate to pass.",
              0x4353D8, _gate1_force))
    add(Patch("gate2_force",
              "0x4355e8: force the per-frame loop's second capability gate to pass.",
              0x4355E8, _gate2_force))
    add(Patch("tick_escape",
              "0x444838: 1-in-100 escape from the active-object tick so the event dispatcher is ever reached.",
              0x444838, _make_tick_escape({"count": 0})))
    add(Patch("event_alt_escape",
              "0x444858: 1-in-15 force so the event-poll-gate decision point is ever reached.",
              0x444858, _make_event_alt_escape({"count": 0})))
    add(Patch("event_poll_gate",
              "0x444870: force the event-ready gate flag so GetEvent's real dispatch path is taken.",
              0x444870, _event_poll_gate))
    add(Patch("animframe_bypass",
              "0x402444: return an empty sprite instead of faulting when [this+0xdc] is still null.",
              0x402444, _animframe_bypass))
    add(Patch("module4_fastforward",
              "0x438cd4: skip module 4's countdown/retry wait loop (fires once).",
              0x438CD4, _make_module4_fastforward({"done": False})))
    add(Patch("module19_sweep",
              "0x422794: force module 19's sub-state forward on a fixed schedule instead of waiting.",
              0x422794, _make_module19_sweep({"reached_insn": None})))
    add(Patch("skip_close_handler",
              "0x4446f4: no-op a spurious view-close handler reached via an incomplete event queue.",
              0x4446F4, _make_skip_close_handler()))
    add(Patch("r7_zero_experiment",
              "0x40e6e4: suppress extension-filtered matching in FindByName() (probe, not confirmed).",
              0x40E6E4, _r7_zero_experiment))
    add(Patch("nullguard_page",
              "Map a zero page at VA 0 so near-null small-offset reads return 0 instead of faulting.",
              None, None, setup=_setup_nullguard))
    add(Patch("null_pc_trap",
              "0x0-0xFFFF: a call through a still-null/partly-null vtable slot (this=0, slot=0, or "
              "this+small-offset) resolves to a PC somewhere in the nullguard page -- nullguard_page "
              "maps that whole page as valid zeroed DATA, so without this the fetch succeeds and the "
              "CPU starts executing zero bytes (ANDEQ) instead of faulting. Treat reaching ANY PC in "
              "this range exactly like fake_vtable_trap's TRAP_VA: a harmless logged no-op return, "
              "not a crash. (v197: originally only trapped PC==0x0 exactly, found via the refactor's "
              "parity run -- earlier monolithic-script runs passing `until=0` to emu_start never "
              "surfaced this because unicorn silently STOPS emulation the instant PC hits the "
              "`until` address, so a null-vtable call landing on PC=0 looked like a clean finish, "
              "not a bug. v198: widened from a single address to the whole nullguard range after "
              "finding a second, structurally identical case landing on PC=0xfffe -- a this+offset "
              "computation into the same zeroed page rather than a bare null vtable, so it doesn't "
              "land on exactly 0x0. This patch plus using an unreachable `until` sentinel is what "
              "exposed both. v202: nullguard_page is READ+EXEC only now (write permission removed), "
              "so this trap's job is unchanged (it only ever cared about PC, a pure address compare "
              "in hook_code, never about memory contents) but a write landing in this range is no "
              "longer silently tolerated elsewhere -- see hook_mem_invalid's [NULL-WRITE-BLOCKED].)",
              None, _trap_hit, address_range=(NULLGUARD_VA, NULLGUARD_VA + NULLGUARD_SIZE)))
    add(Patch("fake_vtable_trap",
              "Shared fallback vtable for objects we couldn't fully construct.",
              TRAP_VA, _trap_hit, setup=_setup_fake_vtable_trap))
    add(Patch("global_buffer_seed",
              "Pre-seed the 0x4bdce8 zero-fill-loop buffer pointer (never allocated by traced code).",
              None, None, setup=_setup_global_buffer_seeds))

    hal33_va = next((va for va, (dll, ordv) in thunk_map.items() if dll == "WS32" and ordv == 0x33), None)
    if hal33_va is not None:
        add(Patch("hal33_force_success",
                  "WS32:0x33 HAL query: force success (R0=1); not a confirmed real response.",
                  hal33_va, _make_hal33_force_success()))

    return registry


class PatchManager:
    """Owns the enabled/disabled state and dispatches per-instruction hits.
    Usage: pm = PatchManager(build_registry(thunk_map)); pm.disable("name");
    pm.setup(ctx, uc); ... in hook_code: if pm.dispatch(ctx, uc, address): return
    """

    def __init__(self, registry):
        self.registry = registry
        self.enabled = {name: p.default_enabled for name, p in registry.items()}
        self._rebuild_index()

    def _rebuild_index(self):
        self._by_address = {}
        self._range_patches = []
        for name, p in self.registry.items():
            if not self.enabled.get(name, False):
                continue
            if p.address is not None:
                self._by_address.setdefault(p.address, []).append(p)
            if p.address_range is not None:
                self._range_patches.append(p)

    def enable(self, name):
        self.enabled[name] = True
        self._rebuild_index()

    def disable(self, name):
        self.enabled[name] = False
        self._rebuild_index()

    def setup(self, ctx, uc):
        for name, p in self.registry.items():
            if self.enabled.get(name, False) and p.setup is not None:
                p.setup(ctx, uc)

    def dispatch(self, ctx, uc, address):
        patches = self._by_address.get(address)
        stop = False
        if patches:
            for p in patches:
                p.hit_count += 1
                if p.on_hit(ctx, uc):
                    stop = True
        # Range patches are checked separately -- expected to be a very
        # short list (one or two guard-page-style patches), so a linear
        # scan per instruction is cheap; avoids building a huge per-address
        # dict for a page-sized range.
        for p in self._range_patches:
            lo, hi = p.address_range
            if lo <= address < hi:
                p.hit_count += 1
                if p.on_hit(ctx, uc):
                    stop = True
        return stop

    def summary(self):
        return {name: {"enabled": self.enabled.get(name, False), "hits": p.hit_count,
                        "description": p.description}
                for name, p in self.registry.items()}
