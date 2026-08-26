"""Research harness: tracing hooks + the confirmed test key sequence.

Everything in this file is OBSERVATION or TEST INPUT -- nothing here should
change what the game itself does (that's patches.py's job). It layers on
top of a fully-configured runtime + patches.PatchManager.

Scope note (v215 cleanup): the pre-refactor monolithic scripts
(boot_extend_test_v137..v215, still on disk under work/) accumulated ~80
one-off diagnostic hooks over many sessions, most superseded by later
findings. Rather than dragging all of that dead weight into the new
structure verbatim, this file carries forward the CURRENTLY ACTIVE
diagnostics (the module19 input-mechanism investigation) plus a simple
registry so new probes are cheap to add. The old scripts remain on disk as
the historical record if a past probe needs to be resurrected.
"""

import struct
from collections import Counter, deque

from runtime import input as input_mod
from runtime import graphics
from runtime.input import (
    EEVENT_NULL, EEVENT_KEY, EEVENT_KEY_UP, EEVENT_KEY_DOWN,
    SCANCODE_5, SCANCODE_2, SCANCODE_3, SCANCODE_UP, SCANCODE_DOWN,
    SCANCODE_LEFT, SCANCODE_RIGHT, KEYNAME_TO_SCANCODE,
)
from patches import MODULE_INDEX_GLOBAL
from unicorn import UC_HOOK_MEM_READ


# --- v215 NEW: short, bounded (item 5: "ONLY in short controlled windows")
# dynamic read-watch infrastructure. A watch is a scoped UC_HOOK_MEM_READ
# added/removed at runtime (not a full-run global hook) over a single
# object's field range, so we can see who reads a specific slot 7/11
# object's memory during a subsequent render pass without the cost of
# instrumenting all reads for the whole 115M-instruction run. Pure
# observation -- no memory is written, no call is forced (item 12).
READ_WATCH_DURATION = 3_000_000
_active_read_watches = {}   # this_ptr -> {"handle":.., "end_insn":.., "stats":..}
read_watch_registry = {}    # this_ptr -> stats dict, kept permanently (incl. after removal)


def register_read_watch(uc, ctx, this_ptr, size=0x140, duration=READ_WATCH_DURATION):
    if this_ptr in _active_read_watches:
        return  # already being watched, let the existing window run out
    stats = {"total": 0, "by_pc": Counter(), "examples": []}

    def _on_read(uc, access, address, size_, value, user_data, _stats=stats, _this=this_ptr):
        from unicorn.arm_const import UC_ARM_REG_PC, UC_ARM_REG_LR
        pc = uc.reg_read(UC_ARM_REG_PC)
        lr = uc.reg_read(UC_ARM_REG_LR)
        _stats["total"] += 1
        _stats["by_pc"][pc] += 1
        if len(_stats["examples"]) < 300:
            _stats["examples"].append((pc, lr, hex(address - _this), size_))
        return False

    handle = uc.hook_add(UC_HOOK_MEM_READ, _on_read, begin=this_ptr, end=this_ptr + size)
    end_insn = ctx.insn_count[0] + duration
    _active_read_watches[this_ptr] = {"handle": handle, "end_insn": end_insn, "stats": stats}
    read_watch_registry[this_ptr] = stats
    print(f"[READ-WATCH-START] insn#{ctx.insn_count[0]} this={hex(this_ptr)} "
          f"window=[{hex(this_ptr)},{hex(this_ptr + size)}) duration={duration} until_insn={end_insn}",
          flush=True)


def expire_read_watches(uc, ctx):
    """Call once per instruction (cheap: list is at most a few entries) --
    removes any read-watch whose bounded window has elapsed."""
    if not _active_read_watches:
        return
    done = [tp for tp, w in _active_read_watches.items() if ctx.insn_count[0] >= w["end_insn"]]
    for tp in done:
        w = _active_read_watches.pop(tp)
        try:
            uc.hook_del(w["handle"])
        except Exception:
            pass
        s = w["stats"]
        top = dict(sorted(s["by_pc"].items(), key=lambda kv: -kv[1])[:15])
        print(f"[READ-WATCH-END] insn#{ctx.insn_count[0]} this={hex(tp)} total_reads={s['total']} "
              f"unique_reader_pcs={len(s['by_pc'])} top_reader_pcs={ {hex(k): v for k, v in top.items()} }",
              flush=True)

# --- confirmed real key sequences (user-verified against a real playthrough)

# Gets from boot to module 5 (the real menu): user-confirmed exact sequence.
MENU_NAVIGATION_SEQUENCE = (
    ["5"] * 3 + ["down"] * 3 + ["5"] * 2 + ["right"] * 11 + ["down"] * 1 +
    ["right"] * 11 + ["down"] * 1 + ["right"] * 6 + ["5"] * 3
)

# v198 fix attempt: the two singleton ["down"]*1 entries above (originally
# meant, per old timing, to navigate a DIFFERENT/earlier submenu) now land
# on the live end-of-menu selector list instead and increment its
# selection field (confirmed via a live write-watch on 0xa16afc: those two
# "down" presses drive it 0 -> 1 -> 2 -> 3). That field is read by a 4-way
# switch right as module 5 hands off: 0 -> module 19 (name entry, our
# target), 1 -> module 7, 2 -> module 6, anything else (default, what we've
# been hitting) -> module 28. Dropping the two later downs should leave the
# field at its natural 0 and route to module 19 instead.
MENU_NAVIGATION_SEQUENCE_NO_STRAY_DOWNS = (
    ["5"] * 3 + ["down"] * 3 + ["5"] * 2 + ["right"] * 11 +
    ["right"] * 11 + ["right"] * 6 + ["5"] * 3
)

# Padding: net-motion-neutral filler that burns queue-drain time without
# changing game state, so later test keys land after module19's letter
# panel has actually finished materializing (confirmed: needs ~18-23M
# elapsed instructions after module19 is reached, independent of substate).
PANEL_SETTLE_FILLER = ["right", "left"] * 20

# Name-entry (letter-select) screen test sequences, by investigation phase:
NAME_SCREEN_SEQUENCES = {
    # Open the panel and probe the corrected "5" key plus D-pad/case-toggle.
    "full_probe": ["3"] + ["5"] + ["right"] * 3 + ["5"] + ["2"] + ["5"],
    # Isolate: does "5" alone (no D-pad at all) reproduce the panel collapse?
    "isolate_5": ["3"] + ["5"],
    # Isolate further: does the panel collapse with ZERO further input?
    "isolate_open_only": ["3"],
    # Mitigation probe: does periodically re-opening keep the panel alive?
    "periodic_reopen": ["3"] * 12,
    # v208 (user-directed follow-up to v207): v207 found phase 1/3
    # advancement in module 19 is gated on a per-grid-cell flag table
    # indexed by a cursor object's +0x31 byte, not a timer -- our previous
    # idle-wait tests never moved the cursor at all, so the flag condition
    # was never exercised. This is a real, snake-pattern 2D sweep of the
    # letter grid (not just left/right like PANEL_SETTLE_FILLER) intended
    # to visit as many distinct cursor positions as practical, with
    # periodic "5" (select) taps, ending with extra "down"+"right" moves
    # toward where a Done/confirm control is typically placed (below/after
    # the letter grid) plus a final "5" to confirm. Exploratory -- we do
    # NOT yet know the real grid layout or Done's true position; the run's
    # new [CURSOR-FLAG-DUMP] log is what tells us which positions are
    # "special" (non-zero flag) empirically.
    "letter_grid_wander": (
        (["right"] * 8 + ["down"] + ["left"] * 8 + ["down"]) * 3 +
        ["5"] + ["down"] * 3 + ["right"] * 3 + ["5"]
    ),
    # v210 (user-directed, ground truth from real gameplay): the user
    # confirmed the actual required flow is simple -- type ANY one letter,
    # then press Done, and character creation follows. v209 found the
    # phase-1 "flag" signal that drives SELECTOR is a mostly-zero, only
    # occasionally-pulsing pending-input value sampled by a handler that
    # runs roughly once per ~1M instructions (~1Hz) -- our previous
    # single-tap key sends mostly landed on a "silent" poll and were lost.
    # This sequence keeps the same simple real-world action (pick a letter,
    # navigate to Done, confirm) but sends each direction as a BURST of many
    # repeated taps instead of one, on the theory that more repetitions
    # raise the odds that at least one lands within a live ~1Hz sampling
    # window. Exploratory -- we still don't know the real grid layout.
    "letter_then_done_burst": (
        ["5"] * 5 +
        ["down"] * 15 + ["right"] * 15 + ["5"] * 5 +
        ["down"] * 15 + ["right"] * 15 + ["5"] * 5
    ),
    # v210 CORRECTED (live-traced, not guessed): letter_then_done_burst's
    # own log revealed WHY repeating the same key is wasted effort --
    # 0x9e3cb4 (the value phase-1's poll reads) is EDGE-TRIGGERED, not
    # level-held. Tracing its actual writer (0x4305d8 -> 0x9e3cd4, then
    # 0x43062c -> 0x9e3cb4, found via a brand new [FLAG-TABLE-WRITE] watch)
    # against real key names showed a clean 1:1 mapping (down=0x80,
    # right=0x10, '5'=0x1) -- but ONLY the FIRST press after a key change
    # writes a nonzero value; every repeated press of the SAME key
    # afterward writes 0x0. So a 15-press "down" burst wastes 14 of its 15
    # presses -- only the leading edge matters, and even that edge only
    # "counts" if phase-1's own ~1M-instruction poll happens to run before
    # the very next tick clears it back to 0 (a race between two
    # independent ~1Hz-ish loops; empirically ~1-in-2 in the burst test).
    # This sequence swaps repetition for ALTERNATION so every "down" is a
    # fresh edge: interleaves down/right to rack up several independent
    # SELECTOR+1 attempts (need 3 successful catches, 0->1->2->3), then
    # interleaves '5'/right to get a fresh "confirm" edge once SELECTOR is
    # likely at 3.
    "letter_then_done_edges": (
        (["down", "right"] * 15) +
        (["5", "right"] * 10)
    ),
    # v210b: the _edges run above showed the edge-catch itself works
    # (down=0x80 landed cleanly in phase-1's poll once) but the CATCH RATE
    # is low -- 6 distinct "down" edges reached module 19's phase-1 window,
    # only 1 was caught before the very next tick overwrote it (~17%, not
    # the ~50% guessed from the smaller _burst sample). Two ~1Hz-ish loops
    # (the input writer at 0x43062c and phase-1's poll at 0x424c68) both
    # dispatch off the SAME master ticker (0x44b8c0) as separate registered
    # callbacks with slightly different periods -- if that's a beat-
    # frequency effect rather than a coin flip, persistence should still
    # get there, just needing more attempts. This quadruples the edge count
    # (need ~3 successful SELECTOR+1 catches; at ~17%/attempt, ~18 attempts
    # is the statistical expectation, so budget well above that) and widens
    # the final confirm burst accordingly.
    "letter_then_done_edges_v2": (
        (["down", "right"] * 60) +
        (["5", "right"] * 30)
    ),
    # v210c: user-confirmed EXACT real-gameplay sequence for this screen --
    # "5, down, down, down, 5" (select, then down x3, then confirm). Test
    # this literally, with the harness's default (unmodified) key timing,
    # before assuming our own edge-alternation guess is the right model.
    "letter_then_done_user_sequence": ["5", "down", "down", "down", "5"],
    # v210d: the literal user sequence, run once, did NOT reach PHASE=2 in
    # this emulation -- its single "down" edge (2 of the 3 "down" presses
    # are wasted repeats, per the edge-triggered finding above) landed on
    # cb4=0x80 but was not caught by phase-1's poll before the next tick
    # cleared it (the same ~1-in-6 race documented above). On real
    # hardware this sequence presumably works reliably every time, which
    # points at an emulation TIMING-FIDELITY gap (our approximation of the
    # master ticker's callback ordering/cadence doesn't exactly match real
    # hardware) rather than a game-logic subtlety. Repeating the user's
    # exact pattern several times over is the practical way to get through
    # despite that gap, without guessing at a different key sequence than
    # the one the user actually confirmed.
    "letter_then_done_user_sequence_repeated": (
        ["5", "down", "down", "down", "5"] * 8
    ),
    # v211: the 8-repeat run reached phase 0->1->2->6->3 (deepest ever) but
    # ran out of scripted input while stuck in phase 3. Static analysis
    # found phase 4 (0x4238dc) reveals ONE letter/digit grid cell per
    # successful edge-catch (via 0x4234fc) -- a SEPARATE, per-cell reveal
    # loop layered on top of the same edge-triggered flag mechanism as
    # phase 1's SELECTOR. Getting there (and revealing enough cells to
    # matter) needs many more edges than 8 reps provide. This extends the
    # user's exact confirmed pattern well beyond what's been tried, on the
    # theory that persistence (not a different key) is what's needed.
    "letter_then_done_user_sequence_long": (
        ["5", "down", "down", "down", "5"] * 20
    ),
}

# v197 finding: with the null_pc_trap fix in place, MENU_NAVIGATION_SEQUENCE's
# final ["5"]*3 lands on a real, live 5-item vertical list menu (confirmed by
# framebuffer snapshot at insn~33.1M) -- NOT already inside module 19 as
# earlier sessions assumed. The list's bottom (5th) item is pre-highlighted
# when we arrive. PANEL_SETTLE_FILLER's right/left taps don't move a
# vertical list's selection, so the bottom item just sits highlighted for
# ~37M more instructions, at which point something (looks like an idle/
# attract-mode timeout, not a deliberate confirm) auto-transitions to a
# different screen (module 28) -- never module 19. Nothing in
# MENU_NAVIGATION_SEQUENCE ever explicitly confirms a SELECTION in this
# list; its trailing 5s were apparently only needed to get past preceding
# splash/logo screens, not to pick a menu item.
#
# This probe tests the fix: move the highlighted item from the bottom back
# up to the top (assumed "New Game" -- the item that should lead into
# character/name creation, i.e. toward module 19) before confirming.
MENU_SELECT_PROBES = {
    # Up x4 to walk a 5-item list from the bottom entry back to the top,
    # then confirm. Untested guess at both the item count and that "up"
    # is the right axis for this list -- that's exactly what this probe
    # is for.
    "select_top_item": ["up"] * 4 + ["5"],
}


def build_pre_idle_sequence(menu_select_probe=None, nav_variant="no_stray_downs"):
    """v204: same nav+tail prefix as build_key_sequence, but WITHOUT
    PANEL_SETTLE_FILLER or the name_screen_mode tail -- for the idle-wait
    experiment, which replaces those with a pure-EEVENT_NULL wait (see
    make_idle_then_key_refill)."""
    tail = MENU_SELECT_PROBES[menu_select_probe] if menu_select_probe else []
    nav = (MENU_NAVIGATION_SEQUENCE_NO_STRAY_DOWNS if nav_variant == "no_stray_downs"
           else MENU_NAVIGATION_SEQUENCE)
    return nav + tail


def build_key_sequence(name_screen_mode="isolate_open_only", menu_select_probe=None, nav_variant="default"):
    tail = MENU_SELECT_PROBES[menu_select_probe] if menu_select_probe else []
    nav = (MENU_NAVIGATION_SEQUENCE_NO_STRAY_DOWNS if nav_variant == "no_stray_downs"
           else MENU_NAVIGATION_SEQUENCE)
    return (
        nav + tail + PANEL_SETTLE_FILLER +
        NAME_SCREEN_SEQUENCES[name_screen_mode]
    )


def make_scripted_refill(key_sequence, hold_nulls=10, gap_nulls=3, ready_flag=None):
    """Returns a `refill(deque)` callable for runtime.input.EventQueue.
    `ready_flag`, if given, is a 1-element list; the scripted sequence is
    held back (idles on NULL) until ready_flag[0] is True -- mirrors the
    confirmed-necessary "don't spend scripted keys during boot/loading"
    gating from the original harness."""
    remaining = deque()
    for key in key_sequence:
        remaining.append(KEYNAME_TO_SCANCODE[key])
    state = {"drained": False}

    def refill(q):
        if ready_flag is not None and not ready_flag[0]:
            q.append((EEVENT_NULL, 0))
            return
        if remaining:
            sc = remaining.popleft()
            q.append((EEVENT_NULL, 0))
            q.append((EEVENT_KEY_DOWN, sc))
            for _ in range(3):
                q.append((EEVENT_NULL, 0))
            q.append((EEVENT_KEY, sc))
            for _ in range(hold_nulls):
                q.append((EEVENT_NULL, 0))
            q.append((EEVENT_KEY_UP, sc))
            for _ in range(gap_nulls):
                q.append((EEVENT_NULL, 0))
            return
        if not state["drained"]:
            state["drained"] = True
            print(f"[research] scripted key sequence exhausted -- idling from here on")
        q.append((EEVENT_NULL, 0))

    return refill


def make_idle_then_key_refill(pre_sequence, idle_until_insn, ctx, post_key=None,
                               ready_flag=None, hold_nulls=10, gap_nulls=3):
    """v204 experiment (user-directed): like make_scripted_refill, but once
    `pre_sequence` drains, sends PURE EEVENT_NULL (no synthetic key taps at
    all -- unlike PANEL_SETTLE_FILLER, which turned out to send real
    right/left key events that themselves drive the 0x422b28 crash chain,
    undermining its own "net-motion-neutral padding" assumption) until
    ctx.insn_count[0] reaches `idle_until_insn`. Then sends exactly ONE
    `post_key` (if given) and idles forever after.

    This tests the "harness sends real input too early, before the screen
    has finished materializing" hypothesis head-on: if slots 0-10 of the
    0xA16B3C table (or the 0x9e3548 guard field) get populated purely from
    waiting -- no key needed -- that's a timing bug in OUR test, not a
    missing constructor in the game. If they never populate no matter how
    long we wait, that points the other way (a genuinely missing
    subsequent construction step in the emulated environment)."""
    remaining = deque(KEYNAME_TO_SCANCODE[k] for k in pre_sequence)
    state = {"phase": "pre", "post_sent": False, "announced_idle": False}

    def _send_key(q, sc):
        q.append((EEVENT_NULL, 0))
        q.append((EEVENT_KEY_DOWN, sc))
        for _ in range(3):
            q.append((EEVENT_NULL, 0))
        q.append((EEVENT_KEY, sc))
        for _ in range(hold_nulls):
            q.append((EEVENT_NULL, 0))
        q.append((EEVENT_KEY_UP, sc))
        for _ in range(gap_nulls):
            q.append((EEVENT_NULL, 0))

    def refill(q):
        if ready_flag is not None and not ready_flag[0]:
            q.append((EEVENT_NULL, 0))
            return
        if state["phase"] == "pre":
            if remaining:
                _send_key(q, remaining.popleft())
                return
            state["phase"] = "idle_wait"
        if state["phase"] == "idle_wait":
            if not state["announced_idle"]:
                state["announced_idle"] = True
                print(f"[research] pre-sequence drained at insn#{ctx.insn_count[0]} -- "
                      f"idling on pure EEVENT_NULL until insn#{idle_until_insn}", flush=True)
            if ctx.insn_count[0] >= idle_until_insn:
                state["phase"] = "post"
            else:
                q.append((EEVENT_NULL, 0))
                return
        if state["phase"] == "post":
            if post_key is not None and not state["post_sent"]:
                state["post_sent"] = True
                print(f"[research] idle wait complete -- sending single post-idle key "
                      f"{post_key!r} at insn#{ctx.insn_count[0]}", flush=True)
                _send_key(q, KEYNAME_TO_SCANCODE[post_key])
                return
            q.append((EEVENT_NULL, 0))

    return refill


# --- diagnostics registry -------------------------------------------------

class Probe:
    def __init__(self, name, address, on_hit, default_enabled=False, max_prints=30):
        self.name = name
        self.address = address
        self.on_hit = on_hit
        self.default_enabled = default_enabled
        self.max_prints = max_prints
        self.hit_count = 0


def _print_cap(probe):
    probe.hit_count += 1
    return probe.hit_count <= probe.max_prints


# Confirmed reader/writer addresses for the module19 input-mechanism
# investigation (see NGage_Sims_Bustin_Out_Android_Port_Bulgular_v190-v196
# for how each was found):
KEYMASK_RINGBUF_LO = 0x9E3C90
KEYMASK_RINGBUF_IDX = 0x9E3CE4 + 0x31
ICODE5_BODY_VA = 0x444E6C          # fires when OfferKeyEventL-style iCode==5 check passes
NAME_PANEL_VTABLE_SLOTS = (0x462DD4, 0x462E10, 0x462E50, 0x444A0C, 0x444E8C)


def build_probes():
    probes = {}

    def add(p):
        probes[p.name] = p

    def _icode5_fired(ctx, uc):
        try:
            modidx = struct.unpack("<I", uc.mem_read(MODULE_INDEX_GLOBAL, 4))[0]
        except Exception:
            modidx = None
        print(f"[ICODE5-BODY-FIRED] insn#{ctx.insn_count[0]} module_index_now={modidx}")
        return False

    add(Probe("icode5_body_fired", ICODE5_BODY_VA, _icode5_fired, default_enabled=True))

    def _make_vtable_slot_probe():
        counts = Counter()

        def _on_hit(ctx, uc, _counts=counts):
            from unicorn.arm_const import UC_ARM_REG_R0, UC_ARM_REG_LR, UC_ARM_REG_PC
            pc = uc.reg_read(UC_ARM_REG_PC)
            r0 = uc.reg_read(UC_ARM_REG_R0)
            lr = uc.reg_read(UC_ARM_REG_LR)
            try:
                modidx = struct.unpack("<I", uc.mem_read(MODULE_INDEX_GLOBAL, 4))[0]
            except Exception:
                modidx = None
            _counts[pc] += 1
            if _counts[pc] <= 20 or modidx == 19:
                print(f"[VTABLESLOT-DIAG] insn#{ctx.insn_count[0]} pc={hex(pc)} this(r0)={hex(r0)} "
                      f"lr={hex(lr)} module_index_now={modidx}")
            return False
        return _on_hit

    slot_hit = _make_vtable_slot_probe()
    for va in NAME_PANEL_VTABLE_SLOTS:
        add(Probe(f"vtable_slot_{hex(va)}", va, slot_hit, default_enabled=True))

    # v199 crash-context finding: the object dispatch chain
    # `mov r0,r7; bl 0x445304 (this = *(*(r7+0x20)+0x68)); ldr r1,[r0];
    #  ldr ip,[r1,#0xdc]; bx ip` faults with r0==r1==0 at insn#57182248
    # (PC=0x445824 is where the `ldr r1,[r0]` sits -- the first read of a
    # potentially-null "this"). This probe watches EVERY hit of that
    # dispatch setup (not just the one that crashed) across a full run, to
    # tell apart "this object is always null here" from "usually fine,
    # this one iteration was null" -- the "healthy vs unhealthy examples of
    # the same call site" comparison needed to root-cause the 0x4af28c
    # jump-table fault rather than assume a cause.
    R7_DISPATCH_R0_CHECK_VA = 0x445824

    def _make_r7_dispatch_probe():
        stats = {"total": 0, "null": 0, "nonnull_examples": [], "null_examples": []}

        def _on_hit(ctx, uc, _stats=stats):
            from unicorn.arm_const import UC_ARM_REG_R0, UC_ARM_REG_R7
            r0 = uc.reg_read(UC_ARM_REG_R0)
            r7 = uc.reg_read(UC_ARM_REG_R7)
            try:
                modidx = struct.unpack("<I", uc.mem_read(MODULE_INDEX_GLOBAL, 4))[0]
            except Exception:
                modidx = None
            _stats["total"] += 1
            is_null = (r0 == 0)
            if is_null:
                _stats["null"] += 1
                bucket = _stats["null_examples"]
            else:
                bucket = _stats["nonnull_examples"]
            if len(bucket) < 10:
                bucket.append((ctx.insn_count[0], modidx, hex(r7), hex(r0)))
            if is_null:
                print(f"[R7-DISPATCH-NULL] insn#{ctx.insn_count[0]} module_index_now={modidx} "
                      f"r7(iter_obj)={hex(r7)} r0(this)={hex(r0)} "
                      f"[running total: {_stats['null']}/{_stats['total']} null]")
            return False
        return _on_hit, stats

    r7_hit, r7_stats = _make_r7_dispatch_probe()
    p = Probe("r7_dispatch_null_check", R7_DISPATCH_R0_CHECK_VA, r7_hit, default_enabled=True)
    p.stats = r7_stats  # exposed for end-of-run summary printing
    add(p)

    # v213 NEW (user-directed: is the missing title/name-field/A-Z text
    # ever DRAWN, or never even dispatched?). 0x44bc68 is the shared
    # per-widget vtable/dispatcher stored at [widget+0x88] by BOTH the
    # generic 0x44b974 factory and the 0x44bac8 text-label constructor
    # (confirmed identical literal, 0x44bc68, at both sites -- text and
    # generic widgets share one base class). It reads [this+0x4d] (major
    # state) and, when that's 0xe(14) -- the value EVERY widget we've seen
    # constructed gets stamped with after construction -- indexes a
    # 58-entry jump table with [this+0x4e] (minor state/sub-type, set
    # individually per call site: text labels get 0, corners get
    # 0x39/0x3a, etc). This is the closest thing to a "process/draw this
    # widget" entry point we've found. Watching every call tells us WHICH
    # widgets actually get ticked during real play -- if slot 7's pointer
    # (the twice-built "Name Your Sim" title candidate) never shows up
    # here, its text is never even attempting to draw, independent of any
    # pixel-format/color question.
    WIDGET_DISPATCH_VA = 0x44BC68

    def _make_widget_dispatch_probe():
        stats = {"total": 0, "by_this": Counter(), "by_majorminor": Counter(),
                  "examples": []}

        def _on_hit(ctx, uc, _stats=stats):
            from unicorn.arm_const import UC_ARM_REG_R0
            this_ptr = uc.reg_read(UC_ARM_REG_R0)
            try:
                major = struct.unpack("<B", uc.mem_read(this_ptr + 0x4d, 1))[0]
                minor = struct.unpack("<B", uc.mem_read(this_ptr + 0x4e, 1))[0]
                typ = struct.unpack("<H", uc.mem_read(this_ptr + 8, 2))[0]
            except Exception:
                major = minor = typ = None
            try:
                modidx = struct.unpack("<I", uc.mem_read(MODULE_INDEX_GLOBAL, 4))[0]
            except Exception:
                modidx = None
            _stats["total"] += 1
            _stats["by_this"][this_ptr] += 1
            _stats["by_majorminor"][(major, minor)] += 1
            if len(_stats["examples"]) < 500:
                _stats["examples"].append((ctx.insn_count[0], this_ptr, major, minor, typ, modidx))
            if _stats["by_this"][this_ptr] == 1:
                # first time we see THIS widget object dispatched -- always
                # worth a line, so we get first-hit timing even after the
                # print cap silences the flood of subsequent per-tick hits.
                print(f"[WIDGET-DISPATCH-FIRST-HIT] insn#{ctx.insn_count[0]} this={hex(this_ptr)} "
                      f"major(+0x4d)={major} minor(+0x4e)={minor} type(+8)={hex(typ) if typ is not None else None} "
                      f"module_index_now={modidx}")
            return False
        return _on_hit, stats

    wd_hit, wd_stats = _make_widget_dispatch_probe()
    p = Probe("widget_dispatch_entry", WIDGET_DISPATCH_VA, wd_hit, default_enabled=True, max_prints=0)
    p.stats = wd_stats
    add(p)

    # v213 NEW: 0x48dee0 is the call made ONLY on the [this+0xa]==0x148
    # branch inside 0x44bd8c (jump-table[0] of the shared dispatcher --
    # the specific sub-routine text-label widgets route to, since
    # 0x44bac8 always sets [this+0xa]=0x148). This looks like the
    # text-specific drawing/measuring step (uses ASR where the generic
    # 0x402118 positioning path uses LSL -- consistent with signed
    # baseline/ascent math). If this NEVER fires while slot 7's widget IS
    # being dispatched (see widget_dispatch_entry above), that pinpoints
    # the break to "text never reaches its draw step" rather than a
    # pixel-format/color problem downstream of a real draw.
    TEXT_DRAW_CANDIDATE_VA = 0x48DEE0

    def _make_text_draw_probe():
        stats = {"total": 0, "examples": []}

        def _on_hit(ctx, uc, _stats=stats):
            from unicorn.arm_const import UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2, UC_ARM_REG_R3, UC_ARM_REG_LR
            r0 = uc.reg_read(UC_ARM_REG_R0)
            r1 = uc.reg_read(UC_ARM_REG_R1)
            r2 = uc.reg_read(UC_ARM_REG_R2)
            r3 = uc.reg_read(UC_ARM_REG_R3)
            lr = uc.reg_read(UC_ARM_REG_LR)
            _stats["total"] += 1
            _stats["examples"].append((ctx.insn_count[0], hex(r0), hex(r1), hex(r2), hex(r3), hex(lr)))
            print(f"[TEXT-DRAW-CANDIDATE-CALL] insn#{ctx.insn_count[0]} r0={hex(r0)} r1={hex(r1)} "
                  f"r2={hex(r2)} r3={hex(r3)} lr={hex(lr)}")
            return False
        return _on_hit, stats

    td_hit, td_stats = _make_text_draw_probe()
    p = Probe("text_draw_candidate", TEXT_DRAW_CANDIDATE_VA, td_hit, default_enabled=True)
    p.stats = td_stats
    add(p)

    # v228: narrow text-raster pipeline tracer. 0x44bac8's text-widget
    # constructor calls 0x48ddbc, which in turn calls 0x48e09c with the
    # string descriptor. Unlike 0x48dee0 (positioning only), 0x48e09c
    # allocates temporary pixel storage and copies glyph rows from the
    # atlas rooted at *(0x4b6eb8). This is therefore the first proven
    # raster-data path for type 0x85/0x09 labels. Observe it without
    # changing registers or memory.
    text_raster_stats = {"entries": [], "prepared": [], "copies": [], "atlas_watches": []}

    def _text_raster_entry(ctx, uc, _s=text_raster_stats):
        from unicorn.arm_const import UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_LR
        obj = uc.reg_read(UC_ARM_REG_R0)
        desc = uc.reg_read(UC_ARM_REG_R1)
        lr = uc.reg_read(UC_ARM_REG_LR)
        text_ptr = 0
        text_preview = b""
        try:
            text_ptr = struct.unpack("<I", uc.mem_read(desc, 4))[0]
            text_preview = bytes(uc.mem_read(text_ptr, 48)).split(b"\0", 1)[0]
        except Exception:
            pass
        try:
            modidx = struct.unpack("<I", uc.mem_read(MODULE_INDEX_GLOBAL, 4))[0]
        except Exception:
            modidx = None
        rec = (ctx.insn_count[0], obj, desc, text_ptr, text_preview.hex(), lr, modidx)
        _s["entries"].append(rec)
        print(f"[TEXT-RASTER-ENTRY] insn#{rec[0]} obj={hex(obj)} desc={hex(desc)} "
              f"text_ptr={hex(text_ptr)} text_hex={text_preview.hex()} lr={hex(lr)} module={modidx}",
              flush=True)
        return False

    def _text_raster_prepared(ctx, uc, _s=text_raster_stats):
        from unicorn.arm_const import UC_ARM_REG_R8, UC_ARM_REG_SL, UC_ARM_REG_SP
        obj = uc.reg_read(UC_ARM_REG_R8)
        pixel_buf = uc.reg_read(UC_ARM_REG_SL)
        sp = uc.reg_read(UC_ARM_REG_SP)
        atlas = 0
        fields = b""
        try:
            atlas = struct.unpack("<I", uc.mem_read(0x4b6eb8, 4))[0]
            fields = bytes(uc.mem_read(obj + 0xd0, 0x10))
        except Exception:
            pass
        rec = (ctx.insn_count[0], obj, pixel_buf, atlas, fields.hex(), sp)
        _s["prepared"].append(rec)
        print(f"[TEXT-RASTER-PREPARED] insn#{rec[0]} obj={hex(obj)} pixel_buf={hex(pixel_buf)} "
              f"atlas_root={hex(atlas)} fields_d0_df={fields.hex()} sp={hex(sp)}", flush=True)
        # pixel_buf is only a staging surface.  The persistent atlas target
        # is known at the 0x417ec8 copy below and is the useful read-watch.
        return False

    def _text_raster_copy(ctx, uc, _s=text_raster_stats):
        from unicorn.arm_const import UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2, UC_ARM_REG_LR
        lr = uc.reg_read(UC_ARM_REG_LR)
        # Only the memcpy-like calls made by 0x48e09c itself.
        if lr not in (0x48e17c, 0x48e1f0, 0x48e204):
            return False
        # 0x417ec8 is not conventional memcpy(dst, src, size): its loop is
        #   ldrh [r0],#2 ; strh [r1],#2
        # so r0 is the source and r1 is the destination.  v228 labelled
        # these backwards, which made the temporary staging bitmap look as
        # though it was discarded without ever reaching persistent storage.
        src = uc.reg_read(UC_ARM_REG_R0)
        dst = uc.reg_read(UC_ARM_REG_R1)
        size = uc.reg_read(UC_ARM_REG_R2)
        sample = b""
        try:
            sample = bytes(uc.mem_read(src, min(size, 32)))
        except Exception:
            pass
        rec = (ctx.insn_count[0], src, dst, size, sample.hex(), lr)
        _s["copies"].append(rec)
        print(f"[TEXT-RASTER-COPY] insn#{rec[0]} src={hex(src)} dst={hex(dst)} size={size} "
              f"src_hex={sample.hex()} lr={hex(lr)}", flush=True)
        # r1 points into the persistent shared glyph/texture atlas.  Follow
        # that destination after the staging copy; readers of this range are
        # the real atlas-to-compositor path, unlike readers of the temporary
        # allocation (which mostly consisted of this copy and allocator
        # teardown).  De-duplicate the two/four row copies that can target
        # adjacent pieces of the same texture.
        if dst and size and not any(base <= dst < base + span
                                    for base, span in _s["atlas_watches"]):
            span = max(size, 0x100)
            _s["atlas_watches"].append((dst, span))
            print(f"[TEXT-ATLAS-WATCH] insn#{rec[0]} base={hex(dst)} size={span}", flush=True)
            register_read_watch(uc, ctx, dst, size=span, duration=20_000_000)
        return False

    p = Probe("text_raster_entry", 0x48E09C, _text_raster_entry, default_enabled=True, max_prints=0)
    p.stats = text_raster_stats
    add(p)
    add(Probe("text_raster_prepared", 0x48E128, _text_raster_prepared,
              default_enabled=True, max_prints=0))
    add(Probe("text_raster_copy", 0x417EC8, _text_raster_copy,
              default_enabled=True, max_prints=0))

    # v234: 0x4638b4 is the only instruction observed reading the persistent
    # title-atlas ranges.  It expands packed mask bits to 16-bit destination
    # pixels.  Record the destination cursor and geometry registers only
    # when its source word belongs to one of the ranges created above; this
    # distinguishes correct composition, off-screen positioning and later
    # overwrite without touching game state.
    atlas_compose_stats = {"hits": 0, "examples": []}

    def _title_atlas_compose(ctx, uc, _s=atlas_compose_stats,
                             _trs=text_raster_stats):
        from unicorn.arm_const import (UC_ARM_REG_R0, UC_ARM_REG_R1,
                                       UC_ARM_REG_R2, UC_ARM_REG_R4,
                                       UC_ARM_REG_R5, UC_ARM_REG_R6,
                                       UC_ARM_REG_R7, UC_ARM_REG_R8)
        source_word = uc.reg_read(UC_ARM_REG_R2) & ~3
        if not any(base <= source_word < base + span
                   for base, span in _trs["atlas_watches"]):
            return False
        rec = (ctx.insn_count[0], source_word,
               uc.reg_read(UC_ARM_REG_R8), uc.reg_read(UC_ARM_REG_R0),
               uc.reg_read(UC_ARM_REG_R1), uc.reg_read(UC_ARM_REG_R4),
               uc.reg_read(UC_ARM_REG_R5), uc.reg_read(UC_ARM_REG_R6),
               uc.reg_read(UC_ARM_REG_R7))
        _s["hits"] += 1
        if len(_s["examples"]) < 80:
            _s["examples"].append(rec)
            print(f"[TEXT-ATLAS-COMPOSE] insn#{rec[0]} src_word={hex(rec[1])} "
                  f"dst_cursor={hex(rec[2])} palette={hex(rec[3])} "
                  f"bit_shift={rec[4]} mode={rec[5]} rows={rec[6]} "
                  f"dst_stride={rec[7]} row={rec[8]}", flush=True)
        return False

    p = Probe("title_atlas_compose", 0x4638B4, _title_atlas_compose,
              default_enabled=True, max_prints=0)
    p.stats = atlas_compose_stats
    add(p)

    # v228 follow-up: 0x48d924 obtains text id 0x35 through the game's own
    # bit-packed string decoder at 0x434f94. The raster trace above proved
    # that this specific result is an empty C string. Capture the three
    # decoder tables and encoded source bytes for id 0x35 to distinguish a
    # genuinely empty archive entry from an uninitialised/wrong table.
    string35_stats = {"entries": [], "returns": []}
    _string35_active = []

    def _string35_entry(ctx, uc, _s=string35_stats):
        from unicorn.arm_const import UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2, UC_ARM_REG_LR
        string_id = uc.reg_read(UC_ARM_REG_R0)
        if string_id != 0x35:
            return False
        out = uc.reg_read(UC_ARM_REG_R1)
        cap = uc.reg_read(UC_ARM_REG_R2)
        lr = uc.reg_read(UC_ARM_REG_LR)
        base = index = alphabet = offset = 0
        encoded = b""
        try:
            base = struct.unpack("<I", uc.mem_read(0x8d7c04, 4))[0]
            index = struct.unpack("<I", uc.mem_read(0x8d7c08, 4))[0]
            alphabet = struct.unpack("<I", uc.mem_read(0x8d7c0c, 4))[0]
            offset = struct.unpack("<I", uc.mem_read(index + string_id * 4, 4))[0]
            encoded = bytes(uc.mem_read(base + offset, 24))
        except Exception:
            pass
        rec = (ctx.insn_count[0], out, cap, lr, base, index, alphabet, offset, encoded.hex())
        _s["entries"].append(rec)
        _string35_active.append(out)
        print(f"[STRING35-DECODE-ENTRY] insn#{rec[0]} out={hex(out)} cap={cap} lr={hex(lr)} "
              f"base={hex(base)} index={hex(index)} alphabet={hex(alphabet)} offset={hex(offset)} "
              f"encoded_hex={encoded.hex()}", flush=True)
        return False

    def _string35_return(ctx, uc, _s=string35_stats):
        from unicorn.arm_const import UC_ARM_REG_R0
        if not _string35_active:
            return False
        out = _string35_active.pop()
        status = uc.reg_read(UC_ARM_REG_R0)
        decoded = b""
        try:
            decoded = bytes(uc.mem_read(out, 96)).split(b"\0", 1)[0]
        except Exception:
            pass
        rec = (ctx.insn_count[0], status, out, decoded.hex())
        _s["returns"].append(rec)
        print(f"[STRING35-DECODE-RETURN] insn#{rec[0]} status={status} out={hex(out)} "
              f"decoded_hex={decoded.hex()}", flush=True)
        return False

    p = Probe("string35_decode_entry", 0x434F94, _string35_entry,
              default_enabled=True, max_prints=0)
    p.stats = string35_stats
    add(p)
    add(Probe("string35_decode_return", 0x435090, _string35_return,
              default_enabled=True, max_prints=0))

    def _fopen_path_probe(ctx, uc):
        from unicorn.arm_const import UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_LR
        path_ptr = uc.reg_read(UC_ARM_REG_R0)
        mode_ptr = uc.reg_read(UC_ARM_REG_R1)
        lr = uc.reg_read(UC_ARM_REG_LR)
        def _cstr(ptr, cap=260):
            try:
                return bytes(uc.mem_read(ptr, cap)).split(b"\0", 1)[0]
            except Exception:
                return b""
        path = _cstr(path_ptr)
        mode = _cstr(mode_ptr, 16)
        print(f"[ESTLIB-FOPEN-PATH] insn#{ctx.insn_count[0]} path_hex={path.hex()} "
              f"path_ascii={path!r} mode={mode!r} lr={hex(lr)}", flush=True)
        return False

    add(Probe("estlib_fopen_path", 0x4959C4, _fopen_path_probe,
              default_enabled=True, max_prints=0))

    def _resource_open_probe(ctx, uc):
        from unicorn.arm_const import UC_ARM_REG_R0, UC_ARM_REG_LR
        desc = uc.reg_read(UC_ARM_REG_R0)
        lr = uc.reg_read(UC_ARM_REG_LR)
        if lr != 0x462FC4:
            return False
        raw = b""
        candidates = []
        try:
            raw = bytes(uc.mem_read(desc, 64))
            for off in range(0, 32, 4):
                ptr = struct.unpack("<I", raw[off:off + 4])[0]
                if ptr:
                    try:
                        val = bytes(uc.mem_read(ptr, 128)).split(b"\0", 1)[0]
                        if val:
                            candidates.append((off, ptr, val.hex()))
                    except Exception:
                        pass
        except Exception:
            pass
        print(f"[LANG-RESOURCE-OPEN] insn#{ctx.insn_count[0]} desc={hex(desc)} raw={raw.hex()} "
              f"pointer_strings={candidates}", flush=True)
        return False

    add(Probe("language_resource_open", 0x44D2E4, _resource_open_probe,
              default_enabled=True, max_prints=0))

    def _resource_open_return_probe(ctx, uc):
        from unicorn.arm_const import UC_ARM_REG_R0
        result = uc.reg_read(UC_ARM_REG_R0)
        signed = result - 0x100000000 if result >= 0x80000000 else result
        print(f"[LANG-RESOURCE-OPEN-RETURN] insn#{ctx.insn_count[0]} result={hex(result)} signed={signed}",
              flush=True)
        return False

    add(Probe("language_resource_open_return", 0x462FC4,
              _resource_open_return_probe, default_enabled=True, max_prints=0))

    def _resource_size_probe(ctx, uc):
        from unicorn.arm_const import UC_ARM_REG_R0, UC_ARM_REG_PC
        pc = uc.reg_read(UC_ARM_REG_PC)
        result = uc.reg_read(UC_ARM_REG_R0)
        signed = result - 0x100000000 if result >= 0x80000000 else result
        print(f"[LANG-RESOURCE-SEEK-RETURN] insn#{ctx.insn_count[0]} pc={hex(pc)} "
              f"result={hex(result)} signed={signed}", flush=True)
        return False

    add(Probe("language_resource_size_return", 0x462FDC,
              _resource_size_probe, default_enabled=True, max_prints=0))
    add(Probe("language_resource_rewind_return", 0x462FF0,
              _resource_size_probe, default_enabled=True, max_prints=0))

    _lang_read_count = [0]
    def _resource_read_return_probe(ctx, uc):
        from unicorn.arm_const import UC_ARM_REG_R0, UC_ARM_REG_R4, UC_ARM_REG_R8
        _lang_read_count[0] += 1
        returned = uc.reg_read(UC_ARM_REG_R0)
        requested = uc.reg_read(UC_ARM_REG_R4)
        dest = uc.reg_read(UC_ARM_REG_R8)
        sample = b""
        try:
            sample = bytes(uc.mem_read(dest, min(requested, 32)))
        except Exception:
            pass
        if _lang_read_count[0] <= 4 or returned != requested:
            print(f"[LANG-RESOURCE-READ-RETURN] insn#{ctx.insn_count[0]} n={_lang_read_count[0]} "
                  f"dest={hex(dest)} requested={requested} returned={returned} data={sample.hex()}",
                  flush=True)
        return False

    add(Probe("language_resource_read_return", 0x463048,
              _resource_read_return_probe, default_enabled=True, max_prints=0))

    def _compressed_read_probe(ctx, uc):
        from unicorn.arm_const import (UC_ARM_REG_PC, UC_ARM_REG_R0, UC_ARM_REG_R1,
                                       UC_ARM_REG_R2, UC_ARM_REG_R3, UC_ARM_REG_R4,
                                       UC_ARM_REG_R5, UC_ARM_REG_R6)
        pc = uc.reg_read(UC_ARM_REG_PC)
        regs = [uc.reg_read(x) for x in (UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2,
                                         UC_ARM_REG_R3, UC_ARM_REG_R4, UC_ARM_REG_R5,
                                         UC_ARM_REG_R6)]
        r4raw = b""
        if regs[4]:
            try: r4raw = bytes(uc.mem_read(regs[4], 0x24))
            except Exception: pass
        print(f"[COMPRESSED-READ-PATH] insn#{ctx.insn_count[0]} pc={hex(pc)} "
              f"regs={[hex(x) for x in regs]} stream_fields={r4raw.hex()}", flush=True)
        return False

    for _va, _name in ((0x40EA44, "entry"), (0x40EB10, "early_zero"),
                       (0x40EBAC, "copy"), (0x40EC84, "error")):
        add(Probe(f"compressed_read_{_name}", _va, _compressed_read_probe,
                  default_enabled=True, max_prints=0))

    # v229: follow the compressed-stream codec registry itself.  The selector
    # (0x41c038) scans up to 16 provider objects stored at manager+0x18 and
    # writes the chosen one to manager+4; 0x41c020 then dispatches through it.
    # Dumping the same manager at registration, selection and dispatch lets us
    # distinguish "nothing was registered" from "providers rejected this
    # stream" without patching either outcome.
    _codec_manager = {"last": 0}

    def _dump_codec_manager(ctx, uc, label, manager):
        from unicorn.arm_const import UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2
        _codec_manager["last"] = manager
        raw = b""
        try:
            raw = bytes(uc.mem_read(manager, 0x60))
        except Exception:
            pass
        chosen = count = 0
        entries = []
        if len(raw) >= 0x5c:
            import struct
            chosen = struct.unpack_from("<I", raw, 4)[0]
            count = struct.unpack_from("<I", raw, 0x58)[0]
            entries = [struct.unpack_from("<I", raw, 0x18 + i * 4)[0]
                       for i in range(min(count, 16))]
        print(f"[CODEC-{label}] insn#{ctx.insn_count[0]} manager={hex(manager)} "
              f"chosen={hex(chosen)} count={count} entries={[hex(x) for x in entries]} "
              f"r0={hex(uc.reg_read(UC_ARM_REG_R0))} "
              f"r1={hex(uc.reg_read(UC_ARM_REG_R1))} "
              f"r2={hex(uc.reg_read(UC_ARM_REG_R2))}", flush=True)

    def _codec_select_entry(ctx, uc):
        from unicorn.arm_const import UC_ARM_REG_R0
        _dump_codec_manager(ctx, uc, "SELECT-ENTRY", uc.reg_read(UC_ARM_REG_R0))
        return False

    def _codec_select_return(ctx, uc):
        from unicorn.arm_const import UC_ARM_REG_R0
        manager = _codec_manager["last"]
        if manager:
            _dump_codec_manager(ctx, uc, "SELECT-RETURN", manager)
        return False

    def _codec_dispatch_entry(ctx, uc):
        from unicorn.arm_const import UC_ARM_REG_R0
        _dump_codec_manager(ctx, uc, "DISPATCH", uc.reg_read(UC_ARM_REG_R0))
        return False

    def _codec_register_entry(ctx, uc):
        from unicorn.arm_const import UC_ARM_REG_R0
        _dump_codec_manager(ctx, uc, "REGISTER", uc.reg_read(UC_ARM_REG_R0))
        return False

    def _codec_candidate(ctx, uc):
        from unicorn.arm_const import (UC_ARM_REG_R0, UC_ARM_REG_R1,
                                       UC_ARM_REG_R2, UC_ARM_REG_R4,
                                       UC_ARM_REG_R5)
        manager = uc.reg_read(UC_ARM_REG_R4)
        slot_addr = uc.reg_read(UC_ARM_REG_R5)
        provider = uc.reg_read(UC_ARM_REG_R0)
        raw = b""
        try:
            raw = bytes(uc.mem_read(provider, 0x20))
        except Exception:
            pass
        print(f"[CODEC-CANDIDATE] insn#{ctx.insn_count[0]} manager={hex(manager)} "
              f"slot_addr={hex(slot_addr)} provider={hex(provider)} object={raw.hex()} "
              f"codec_id={hex(uc.reg_read(UC_ARM_REG_R1))} "
              f"init_fn={hex(uc.reg_read(UC_ARM_REG_R2))}", flush=True)
        return False

    def _codec_candidate_return(ctx, uc):
        from unicorn.arm_const import (UC_ARM_REG_R0, UC_ARM_REG_R4,
                                       UC_ARM_REG_R5)
        print(f"[CODEC-CANDIDATE-RETURN] insn#{ctx.insn_count[0]} "
              f"manager={hex(uc.reg_read(UC_ARM_REG_R4))} "
              f"slot_addr={hex(uc.reg_read(UC_ARM_REG_R5))} "
              f"result={hex(uc.reg_read(UC_ARM_REG_R0))}",
              flush=True)
        return False

    add(Probe("codec_select_entry", 0x41C038, _codec_select_entry,
              default_enabled=True, max_prints=0))
    add(Probe("codec_select_success", 0x41C0B0, _codec_select_return,
              default_enabled=True, max_prints=0))
    add(Probe("codec_select_failure", 0x41C0C8, _codec_select_return,
              default_enabled=True, max_prints=0))
    add(Probe("codec_dispatch_entry", 0x41C020, _codec_dispatch_entry,
              default_enabled=True, max_prints=0))
    add(Probe("codec_register_entry", 0x41C0CC, _codec_register_entry,
              default_enabled=True, max_prints=0))
    add(Probe("codec_candidate", 0x41C094, _codec_candidate,
              default_enabled=True, max_prints=0))
    add(Probe("codec_candidate_return", 0x41C09C, _codec_candidate_return,
              default_enabled=True, max_prints=0))

    def _codec0_stage(ctx, uc):
        from unicorn.arm_const import (UC_ARM_REG_PC, UC_ARM_REG_R0,
                                       UC_ARM_REG_R1, UC_ARM_REG_R2,
                                       UC_ARM_REG_R3, UC_ARM_REG_R4,
                                       UC_ARM_REG_R5, UC_ARM_REG_R6)
        regs = [uc.reg_read(x) for x in (UC_ARM_REG_R0, UC_ARM_REG_R1,
                                         UC_ARM_REG_R2, UC_ARM_REG_R3,
                                         UC_ARM_REG_R4, UC_ARM_REG_R5,
                                         UC_ARM_REG_R6)]
        print(f"[CODEC0-STAGE] insn#{ctx.insn_count[0]} "
              f"pc={hex(uc.reg_read(UC_ARM_REG_PC))} regs={[hex(x) for x in regs]}",
              flush=True)
        return False

    for _va, _name in ((0x474D44, "init_entry"),
                       (0x474D58, "chunk_lookup_return"),
                       (0x474D88, "tables_init_return"),
                       (0x474B70, "main_table_return"),
                       (0x474BDC, "plane_table_return"),
                       (0x474C4C, "aux_e4_return"),
                       (0x474CAC, "aux_e0_return"),
                       (0x474CFC, "aux_e8_return"),
                       (0x474D34, "aux_130_return")):
        add(Probe(f"codec0_{_name}", _va, _codec0_stage,
                  default_enabled=True, max_prints=0))

    def _codec_table_entry(ctx, uc):
        from unicorn.arm_const import (UC_ARM_REG_R0, UC_ARM_REG_R1,
                                       UC_ARM_REG_R2, UC_ARM_REG_R3,
                                       UC_ARM_REG_SP)
        regs = [uc.reg_read(x) for x in (UC_ARM_REG_R0, UC_ARM_REG_R1,
                                         UC_ARM_REG_R2, UC_ARM_REG_R3,
                                         UC_ARM_REG_SP)]
        provider_raw = source_raw = stack_raw = b""
        try: provider_raw = bytes(uc.mem_read(regs[0], 0x80))
        except Exception: pass
        try: source_raw = bytes(uc.mem_read(regs[3], min(regs[2] * 2, 0x80)))
        except Exception: pass
        try: stack_raw = bytes(uc.mem_read(regs[4], 0x30))
        except Exception: pass
        print(f"[CODEC-TABLE-ENTRY] insn#{ctx.insn_count[0]} "
              f"r0-r3-sp={[hex(x) for x in regs]} provider={provider_raw.hex()} "
              f"source={source_raw.hex()} stack={stack_raw.hex()}", flush=True)
        return False

    add(Probe("codec_table_entry", 0x473FEC, _codec_table_entry,
              default_enabled=True, max_prints=0))

    def _codec0_constructor_state(ctx, uc):
        from unicorn.arm_const import (UC_ARM_REG_PC, UC_ARM_REG_R0,
                                       UC_ARM_REG_R1, UC_ARM_REG_R4,
                                       UC_ARM_REG_R5)
        pc = uc.reg_read(UC_ARM_REG_PC)
        descriptor = (uc.reg_read(UC_ARM_REG_R1) if pc == 0x474FEC
                      else uc.reg_read(UC_ARM_REG_R5))
        raw = table = b""
        try: raw = bytes(uc.mem_read(descriptor, 0x30))
        except Exception: pass
        if len(raw) >= 12:
            import struct
            table_ptr = struct.unpack_from("<I", raw, 8)[0]
            try: table = bytes(uc.mem_read(table_ptr, 0x80))
            except Exception: pass
        print(f"[CODEC0-CONSTRUCTOR] insn#{ctx.insn_count[0]} pc={hex(pc)} "
              f"descriptor={hex(descriptor)} r0={hex(uc.reg_read(UC_ARM_REG_R0))} "
              f"raw={raw.hex()} table={table.hex()}", flush=True)
        return False

    add(Probe("codec0_constructor_entry", 0x474FEC, _codec0_constructor_state,
              default_enabled=True, max_prints=0))
    add(Probe("codec0_flag_scan_done", 0x4750AC, _codec0_constructor_state,
              default_enabled=True, max_prints=0))

    # v213 NEW: 0x402118 is the generic widget positioning call used by
    # EVERY widget path we've disassembled so far (both working ones --
    # panel/tabs/frame -- and the text-label path). A pure counter (no
    # per-call print, this fires constantly) gives a baseline: if it fires
    # thousands of times but text_draw_candidate above fires zero times,
    # that's a strong differential signal that positioning/generic-bitmap
    # blit works fine while the text-specific step is the one that never
    # runs.
    POSITION_CALL_VA = 0x402118

    def _make_position_counter_probe():
        stats = {"total": 0}

        def _on_hit(ctx, uc, _stats=stats):
            _stats["total"] += 1
            return False
        return _on_hit, stats

    pc_hit, pc_stats = _make_position_counter_probe()
    p = Probe("position_call_count", POSITION_CALL_VA, pc_hit, default_enabled=True, max_prints=0)
    p.stats = pc_stats
    add(p)

    # v213b NEW: the [FB-WRITE-PC] ground-truth watch (added directly in
    # run.py's hook_mem_write) found two real pixel-blit functions --
    # 0x463a38 (4bpp nibble-indexed palette blit, no colorkey, always
    # opaque -- matches an unmasked background/tile bitmap format) and
    # 0x464dc8 (8bpp byte-indexed palette blit WITH colorkey: index 0 is
    # skipped/transparent -- matches a masked glyph/sprite bitmap format).
    # Both do: pixel = *(u16*)(palette_base + index*2) | 0x8000, then
    # strh to the framebuffer. A static xref scan (linear ARM-mode BL/B
    # scan across 0x401000-0x900000) found ZERO direct callers, and a raw
    # byte search for these two VAs as 4-byte little-endian literals
    # found no function-pointer table either -- so the caller must be an
    # INDIRECT (register) call, e.g. a per-bpp blit-function-pointer
    # array (matches Symbian BITGDI's internal per-format blit dispatch
    # pattern). Reading LR deep inside the loop is useless -- by the
    # first strh, LR has long since been reused as a scratch register
    # (confirmed by disassembly: `str lr,[sp]` then `movs lr,sl` etc.
    # right after entry). This probe instead fires at the function's
    # FIRST instruction (before LR is touched at all), so LR here is
    # guaranteed to be the genuine, uncorrupted return address -- this is
    # the only reliable way to find the real (indirect) caller site.
    BLIT_4BPP_ENTRY_VA = 0x463A38
    BLIT_8BPP_ENTRY_VA = 0x464DC8

    def _make_blit_entry_probe(tag):
        stats = {"total": 0, "by_lr": Counter(), "examples": []}

        def _on_hit(ctx, uc, _stats=stats, _tag=tag):
            from unicorn.arm_const import UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2, UC_ARM_REG_R3, UC_ARM_REG_LR
            r0 = uc.reg_read(UC_ARM_REG_R0)
            r1 = uc.reg_read(UC_ARM_REG_R1)
            r2 = uc.reg_read(UC_ARM_REG_R2)
            r3 = uc.reg_read(UC_ARM_REG_R3)
            lr = uc.reg_read(UC_ARM_REG_LR)
            try:
                modidx = struct.unpack("<I", uc.mem_read(MODULE_INDEX_GLOBAL, 4))[0]
            except Exception:
                modidx = None
            _stats["total"] += 1
            _stats["by_lr"][lr] += 1
            is_late = ctx.insn_count[0] >= 90_000_000
            late_key = (lr, "late")
            if is_late:
                _stats["by_lr"][late_key] += 1
            if len(_stats["examples"]) < 300 or is_late:
                _stats["examples"].append((ctx.insn_count[0], hex(r0), hex(r1), hex(r2), hex(r3), hex(lr), modidx))
            # v213d NEW: the cap is per-LR, but the LR is nearly always the
            # SAME shared dispatcher tail regardless of WHICH screen/widget
            # is being drawn -- so the very first two hits (early boot/menu
            # screens, insn~5-10M) used up the whole budget and NO palette
            # dump would ever be captured from module19's actual slot7/11
            # text draws (insn~95-115M). Give the late (insn>=90M) window
            # its OWN small budget so we get ground-truth palette data from
            # the actual name-entry screen, not just early menus.
            if _stats["by_lr"][lr] <= 2 or (is_late and _stats["by_lr"][late_key] <= 8):
                # v213c NEW: dump the actual palette table (r0, 16 entries
                # x 2 bytes = the max a 4-bit index can select) and the
                # first 40 bytes of the r3 struct (bitmap/clip descriptor)
                # as raw hex, so the REAL on-device color values feeding
                # these blits are captured directly -- ground truth for
                # the RGB565 vs RGB555 vs BGR pixel-format question,
                # rather than guessing from a possibly-stale snapshot.
                try:
                    pal_bytes = uc.mem_read(r0, 32)
                    pal_words = struct.unpack("<16H", pal_bytes)
                except Exception as e:
                    pal_words = f"<read failed: {e}>"
                try:
                    bmp_bytes = uc.mem_read(r3, 40)
                    bmp_hex = bmp_bytes.hex()
                except Exception as e:
                    bmp_hex = f"<read failed: {e}>"
                print(f"[BLIT-ENTRY-{_tag}] insn#{ctx.insn_count[0]} r0(palette?)={hex(r0)} r1(x?)={hex(r1)} "
                      f"r2(y?)={hex(r2)} r3(clip/bmp?)={hex(r3)} lr(REAL-CALLER)={hex(lr)} module_index_now={modidx} "
                      f"palette16={[hex(w) for w in pal_words] if not isinstance(pal_words, str) else pal_words} "
                      f"r3_struct_hex={bmp_hex}")
            return False
        return _on_hit, stats

    b4_hit, b4_stats = _make_blit_entry_probe("4BPP")
    p = Probe("blit_4bpp_entry", BLIT_4BPP_ENTRY_VA, b4_hit, default_enabled=True, max_prints=0)
    p.stats = b4_stats
    add(p)

    b8_hit, b8_stats = _make_blit_entry_probe("8BPP")
    p = Probe("blit_8bpp_entry", BLIT_8BPP_ENTRY_VA, b8_hit, default_enabled=True, max_prints=0)
    p.stats = b8_stats
    add(p)

    # v214 NEW: 0x464bf8 is the "fast path" twin entry of the 8bpp
    # colorkeyed glyph/sprite blit -- disassembly confirmed it falls
    # through into the EXACT SAME inner loop as 0x464dc8 (starting at
    # 0x464cb4), just via a shorter prologue (no extra clip-rect stack
    # param). v213's negative finding ("text_draw_candidate fires for
    # slot7/11 but blit_8bpp_entry never fires in that window") was
    # explicitly flagged as INCOMPLETE because calls entering through
    # THIS door would have been invisible to that probe. This closes
    # that gap -- same probe factory/shape as blit_8bpp_entry so the
    # results are directly comparable.
    BLIT_8BPP_FASTPATH_ENTRY_VA = 0x464BF8

    b8f_hit, b8f_stats = _make_blit_entry_probe("8BPP-FASTPATH")
    p = Probe("blit_8bpp_fastpath_entry", BLIT_8BPP_FASTPATH_ENTRY_VA, b8f_hit, default_enabled=True, max_prints=0)
    p.stats = b8f_stats
    add(p)

    # v214 NEW: while hunting for the caller of the dispatcher (~0x448a8c),
    # found it has (at least) 6 sibling call sites, not 4 -- 0x448e54
    # calls 0x463318, 0x448e88 calls 0x46359c, both also converging on the
    # shared 0x448f84 tail. 0x463318 is HISTORICALLY SIGNIFICANT: an
    # ancient (pre-v190s) investigation already flagged it (MASTER.md
    # section 7 item 4) as the suspected drawer of the letter panel that
    # was observed to go blank ~500-600K instructions after opening, tied
    # to a counter field at [struct+0x20] going to zero -- a DIFFERENT,
    # long-deferred bug from this round's color/missing-glyph one. Disas-
    # sembly this round confirms: 0x463318 IS a 4bpp nibble-indexed blit
    # WITH colorkey (index 0 skipped -- `ands sb,r2,#0xf; beq <skip>`),
    # a THIRD bpp/colorkey combination distinct from both 0x463a38 (4bpp,
    # no colorkey) and 0x464dc8 (8bpp, colorkey) -- and it reads exactly
    # the [struct+0x20] counter the old note described, confirming the
    # two investigations found the same real mechanism from different
    # angles. Instrumenting its entry (same technique as the others) lets
    # us watch this specific, previously-only-suspected function live.
    BLIT_4BPP_COLORKEY_ENTRY_VA = 0x463318
    BLIT_UNKNOWN_SIBLING_VA = 0x46359C

    bk_hit, bk_stats = _make_blit_entry_probe("4BPP-COLORKEY")
    p = Probe("blit_4bpp_colorkey_entry", BLIT_4BPP_COLORKEY_ENTRY_VA, bk_hit, default_enabled=True, max_prints=0)
    p.stats = bk_stats
    add(p)

    us_hit, us_stats = _make_blit_entry_probe("UNKNOWN-SIBLING-46359C")
    p = Probe("blit_unknown_sibling_entry", BLIT_UNKNOWN_SIBLING_VA, us_hit, default_enabled=True, max_prints=0)
    p.stats = us_stats
    add(p)

    # v214b NEW: 0x463dec is the LAST uninstrumented sibling in the main
    # 0x448a8c panel/tile dispatcher family (v213 section 1.1-C: heaviest
    # FB-WRITE-PC volume of all siblings, ~420-460K writes/run, likely
    # the repeating wallpaper-icon blitter) -- adding it closes out full
    # coverage of that dispatcher's known call sites (0x463dec, 0x463a38,
    # 0x463318, 0x464bf8, 0x464dc8, 0x46359c -- 6 confirmed so far).
    BLIT_UNCHARACTERIZED_SIBLING_VA = 0x463DEC

    uc_hit, uc_stats = _make_blit_entry_probe("UNCHARACTERIZED-463DEC")
    p = Probe("blit_uncharacterized_463dec_entry", BLIT_UNCHARACTERIZED_SIBLING_VA, uc_hit, default_enabled=True, max_prints=0)
    p.stats = uc_stats
    add(p)

    # v215 NEW (user's 12-item directive, item 10): 0x487cb8/0x487cbc is the
    # CALL SITE of the second "masked bitmap" dispatcher found in v214; its
    # own enclosing function's true prologue was not previously located.
    # Static backward-scan-for-push this session found it: 0x4879f8
    # (`push {r4,r5,r6,r7,r8,sb,sl,lr}`), immediately followed by a double
    # nested loop (y then x) whose body reaches 0x487cb8/0x487d04 -- no
    # other push exists between 0x4879f8 and 0x487cb8, so this is the real
    # function start. Hooking its FIRST instruction (before LR gets reused
    # as scratch, same technique as the six blit-entry probes) captures the
    # genuine caller LR -- answering "who calls the masked-bitmap
    # dispatcher" directly, without forcing any call.
    MASKED_BITMAP_DISPATCHER_VA = 0x4879F8

    mb_hit, mb_stats = _make_blit_entry_probe("MASKED-BITMAP-DISPATCHER-4879F8")
    p = Probe("masked_bitmap_dispatcher_entry", MASKED_BITMAP_DISPATCHER_VA, mb_hit, default_enabled=True, max_prints=0)
    p.stats = mb_stats
    add(p)

    # v215 NEW (user's 12-item directive, item 6): 0x4484c8 (384,048 FB
    # writes/run, NOT one of the six known blit entries) was only
    # preliminarily looked at in v214. Full static disassembly this session
    # found its TRUE enclosing function starts at 0x448424
    # (`push {r4,r5,lr}`) and ends at 0x4484e4 (`pop {r4,r5,lr}; bx lr`).
    # Structurally it is NOT a discrete sprite/glyph blit: it reads a FIXED
    # global pointer-to-pointer (literal pool @0x4484d8 -> 0x4bdce8), loops
    # exactly 0x4780=18304 times, and on each iteration reads ONE 32-bit
    # word from [r5], unpacks it into 3 nibble/byte-ish channel groups via
    # bic-chains, rescales each via multiply-by-(16-n)-and-shift (the
    # standard low-bit-depth-to-8-bit channel expansion idiom), repacks,
    # and writes the result back to the SAME address [r5],#4 (in-place,
    # post-increment) -- i.e. a whole-buffer, 2-pixels-per-word, in-place
    # bit-depth/gamma conversion pass, not a positioned sprite draw.
    # 18304 words x 2 pixels/word = 36608 = exactly 176x208 (the whole
    # screen) -- so its high FB-write volume (384,048 = ~21 full-screen
    # sweeps across the run) reflects FRAME COUNT, not per-widget content,
    # unlike the six positioned blit functions. A full-binary xref scan
    # found zero static callers (same indirect-call pattern as the six
    # blits), so this probe hooks its true first instruction to capture the
    # real caller LR live, plus reads the fixed global pointer at runtime
    # to identify the actual buffer being converted (item 6's remaining
    # open question: is this the SAME window as FRAMEBUFFER_WATCH_LO, i.e.
    # a true in-place hardware-framebuffer pass, or a separate intermediate
    # buffer that merely aliases the same address range).
    WHOLE_SCREEN_CONVERSION_VA = 0x448424

    wsc_hit, wsc_stats = _make_blit_entry_probe("WHOLE-SCREEN-CONVERSION-448424")
    p = Probe("whole_screen_conversion_entry", WHOLE_SCREEN_CONVERSION_VA, wsc_hit, default_enabled=True, max_prints=0)
    p.stats = wsc_stats
    add(p)

    # v215 NEW (user's 12-item directive, items 1/2/5/11): on every
    # TEXT-DRAW-CANDIDATE-CALL hit (0x48dee0, r0=this), do three things for
    # each DISTINCT object pointer the very first time it's seen:
    #   1. Dump a wide (0x140-byte) field snapshot: vtable ptr, type/flag
    #      fields, the animation counter at +0x5e (found this session --
    #      see 0x405104 below), alignment bytes, position fields.
    #   2. Dump 64 raw vtable entries (code pointers) for later static
    #      classification (item 2) -- vtables are read-only/static, so one
    #      live read of the pointer is enough; the entries themselves can
    #      be disassembled offline from the same binary.
    #   3. Register a SHORT, bounded (not full-run) memory-READ watch over
    #      the object [this,this+0x140) -- item 5's explicit requirement
    #      ("only in short controlled windows") -- so we can see which
    #      function(s), if any, read this object's fields during a
    #      subsequent render pass, without the cost of watching arbitrary
    #      heap addresses for the whole 115M-instruction run.
    # On REPEAT hits for an already-dumped object (this object's position
    # call recurring later, e.g. after re-entering module 19), we do NOT
    # re-dump fields, but DO restart a fresh read-watch if none is active
    # any more -- this is what extends item 11's tracking beyond a single
    # fixed window: the object is re-watched every time it resurfaces,
    # across the whole run, not just once.
    _dumped_objects = set()

    def _make_slot_deepdump_probe():
        stats = {"dumped": [], "rewatch_count": 0}

        def _on_hit(ctx, uc, _stats=stats):
            from unicorn.arm_const import UC_ARM_REG_R0
            this_ptr = uc.reg_read(UC_ARM_REG_R0)
            if this_ptr in _dumped_objects:
                _stats["rewatch_count"] += 1
                register_read_watch(uc, ctx, this_ptr)
                return False
            _dumped_objects.add(this_ptr)
            try:
                raw = uc.mem_read(this_ptr, 0x140)
            except Exception as e:
                print(f"[SLOT-DEEPDUMP-FAIL] insn#{ctx.insn_count[0]} this={hex(this_ptr)} err={e}",
                      flush=True)
                return False
            vtable_ptr = struct.unpack("<I", raw[0:4])[0]
            fields = {
                "vtable(+0x0)": hex(vtable_ptr),
                "type(+0x8)": hex(struct.unpack("<H", raw[8:10])[0]),
                "+0xa": hex(struct.unpack("<H", raw[0xa:0xc])[0]),
                "major(+0x4d)": raw[0x4d],
                "minor(+0x4e)": raw[0x4e],
                "flags(+0x4f)": hex(raw[0x4f]),
                "anim_counter(+0x5e)": struct.unpack("<H", raw[0x5e:0x60])[0],
                "align_x(+0xd8)": raw[0xd8],
                "align_y(+0xd9)": raw[0xd9],
                "pos_field(+0x18)": hex(struct.unpack("<i", raw[0x18:0x1c])[0] & 0xffffffff),
                "pos_field(+0x1c)": hex(struct.unpack("<i", raw[0x1c:0x20])[0] & 0xffffffff),
                "pos_field(+0x20)": hex(struct.unpack("<i", raw[0x20:0x24])[0] & 0xffffffff),
                "pos_field(+0x24)": hex(struct.unpack("<i", raw[0x24:0x28])[0] & 0xffffffff),
            }
            _stats["dumped"].append((ctx.insn_count[0], this_ptr, vtable_ptr, dict(fields)))
            print(f"[SLOT-DEEPDUMP] insn#{ctx.insn_count[0]} this={hex(this_ptr)} fields={fields}", flush=True)
            print(f"[SLOT-DEEPDUMP-RAW] this={hex(this_ptr)} bytes_0x00_0x140={raw.hex()}", flush=True)
            try:
                vt_raw = uc.mem_read(vtable_ptr, 64 * 4)
                vt_entries = struct.unpack("<64I", vt_raw)
                print(f"[SLOT-VTABLE-DUMP] this={hex(this_ptr)} vtable={hex(vtable_ptr)} "
                      f"entries={[hex(e) for e in vt_entries]}", flush=True)
            except Exception as e:
                print(f"[SLOT-VTABLE-DUMP-FAIL] this={hex(this_ptr)} vtable={hex(vtable_ptr)} err={e}",
                      flush=True)
            register_read_watch(uc, ctx, this_ptr)
            return False
        return _on_hit, stats

    sd_hit, sd_stats = _make_slot_deepdump_probe()
    p = Probe("slot_text_object_deepdump", TEXT_DRAW_CANDIDATE_VA, sd_hit, default_enabled=True, max_prints=0)
    p.stats = sd_stats
    add(p)

    # v216 NEW (continuing madde 10): v215 found 0x4497f0's enclosing "draw
    # N items" loop (0x4497e0-0x4497fc) is 0x4879f8's ONLY real caller, with
    # r3=[r7+0x214] items during module 19 (insn~90.3M, matching v214's
    # x=1-25,y=141/149 window) vs 128 items during module 5 (menu). This
    # probe hooks 0x4497e4 (right after `ldr r1,[r5,r4,lsl#2]` at 0x4497e0
    # has loaded the CURRENT item pointer into r1, before LR/r0/r2 get
    # clobbered for the 0x4879f8 call) to capture, for EVERY item drawn:
    # the container object (r7), the loop index (r4), the item pointer
    # itself (r1), and a raw field dump of the item (structure unknown --
    # dumped for offline analysis, same spirit as slot_text_object_deepdump).
    NITEM_LOOP_ENTRY_VA = 0x4497E4

    def _make_nitem_loop_probe():
        stats = {"total": 0, "by_container": Counter(), "examples": []}

        def _on_hit(ctx, uc, _stats=stats):
            from unicorn.arm_const import UC_ARM_REG_R1, UC_ARM_REG_R4, UC_ARM_REG_R7
            r1 = uc.reg_read(UC_ARM_REG_R1)  # item pointer
            r4 = uc.reg_read(UC_ARM_REG_R4)  # loop index
            r7 = uc.reg_read(UC_ARM_REG_R7)  # container object
            try:
                modidx = struct.unpack("<I", uc.mem_read(MODULE_INDEX_GLOBAL, 4))[0]
            except Exception:
                modidx = None
            try:
                item_raw = uc.mem_read(r1, 0x40)
            except Exception as e:
                item_raw = None
            _stats["total"] += 1
            _stats["by_container"][r7] += 1
            entry = (ctx.insn_count[0], hex(r7), r4, hex(r1), modidx,
                     item_raw.hex() if item_raw is not None else None)
            if len(_stats["examples"]) < 500:
                _stats["examples"].append(entry)
            print(f"[NITEM-LOOP-ENTRY] insn#{ctx.insn_count[0]} container(r7)={hex(r7)} index(r4)={r4} "
                  f"item_ptr(r1)={hex(r1)} module_index={modidx} "
                  f"item_bytes_0x40={item_raw.hex() if item_raw is not None else '<unreadable>'}",
                  flush=True)
            return False
        return _on_hit, stats

    nl_hit, nl_stats = _make_nitem_loop_probe()
    p = Probe("nitem_loop_entry", NITEM_LOOP_ENTRY_VA, nl_hit, default_enabled=True, max_prints=0)
    p.stats = nl_stats
    add(p)

    # v217 NEW (continuing madde 4: who constructs slot 7/11's type=0x85/0x9
    # widgets?). v216 ruled out the two known candidate constructors
    # (0x422904, 0x4257ac) by their exact bl-0x44b974 r0 immediates -- none
    # matched 0x85/0x9. Rather than trust the automated static xref scanner
    # again (v216 showed it desyncs on this binary's literal pools and
    # missed real, confirmed bl 0x44b974 sites), this hooks 0x44b974's own
    # entry point LIVE, for the entire run, capturing (r0=type_index,
    # r1=sub_id, r2/r3=flag args, lr=real caller) for every widget the
    # factory ever builds. Whichever LR shows up paired with r0==0x85 or
    # r0==9 is slot 7/11's true, still-unknown constructor.
    WIDGET_FACTORY_VA = 0x44B974
    SLOT7_11_TYPES = (0x85, 0x9)

    def _make_widget_factory_probe():
        stats = {"total": 0, "by_r0": Counter(), "by_lr": Counter(),
                  "slot7_11_examples": [], "examples": []}

        def _on_hit(ctx, uc, _stats=stats):
            from unicorn.arm_const import (UC_ARM_REG_R0, UC_ARM_REG_R1,
                                            UC_ARM_REG_R2, UC_ARM_REG_R3,
                                            UC_ARM_REG_LR)
            r0 = uc.reg_read(UC_ARM_REG_R0)
            r1 = uc.reg_read(UC_ARM_REG_R1)
            r2 = uc.reg_read(UC_ARM_REG_R2)
            r3 = uc.reg_read(UC_ARM_REG_R3)
            lr = uc.reg_read(UC_ARM_REG_LR)
            try:
                modidx = struct.unpack("<I", uc.mem_read(MODULE_INDEX_GLOBAL, 4))[0]
            except Exception:
                modidx = None
            _stats["total"] += 1
            _stats["by_r0"][r0] += 1
            _stats["by_lr"][hex(lr)] += 1
            entry = (ctx.insn_count[0], hex(r0), hex(r1), hex(r2), hex(r3), hex(lr), modidx)
            if len(_stats["examples"]) < 200:
                _stats["examples"].append(entry)
            if r0 in SLOT7_11_TYPES:
                _stats["slot7_11_examples"].append(entry)
                print(f"[WIDGET-FACTORY-SLOT7-11-TYPE] insn#{ctx.insn_count[0]} type(r0)={hex(r0)} "
                      f"sub_id(r1)={hex(r1)} r2={hex(r2)} r3={hex(r3)} caller(lr)={hex(lr)} "
                      f"module_index={modidx}", flush=True)
            return False
        return _on_hit, stats

    wf_hit, wf_stats = _make_widget_factory_probe()
    p = Probe("widget_factory_entry", WIDGET_FACTORY_VA, wf_hit, default_enabled=True, max_prints=0)
    p.stats = wf_stats
    add(p)

    # v218 NEW: madde 4 SOLVED (see report) -- 0x425278 is the sibling
    # constructor that builds slots 11-16, with slot 11's TEXT widget
    # (type=0x85) built via `mov r0,#0x85; bl 0x44bac8` at 0x425358, stored
    # to [0xa16b3c+0x2c] (17-slot table, slot 11). This probe hooks
    # 0x425278's own entry to capture its real caller (LR), the one
    # remaining unknown -- who dispatches into this function, and under
    # what condition.
    SLOT11_GROUP_CTOR_VA = 0x425278

    def _make_slot11_ctor_probe():
        stats = {"total": 0, "by_lr": Counter(), "examples": []}

        def _on_hit(ctx, uc, _stats=stats):
            from unicorn.arm_const import UC_ARM_REG_LR
            lr = uc.reg_read(UC_ARM_REG_LR)
            try:
                modidx = struct.unpack("<I", uc.mem_read(MODULE_INDEX_GLOBAL, 4))[0]
                substate4 = struct.unpack("<I", uc.mem_read(MODULE_INDEX_GLOBAL + 4, 4))[0]
            except Exception:
                modidx = substate4 = None
            _stats["total"] += 1
            _stats["by_lr"][hex(lr)] += 1
            _stats["examples"].append((ctx.insn_count[0], hex(lr), modidx, substate4))
            print(f"[SLOT11-GROUP-CTOR-ENTRY] insn#{ctx.insn_count[0]} caller(lr)={hex(lr)} "
                  f"module_index={modidx} module_index_global_plus4={substate4}", flush=True)
            return False
        return _on_hit, stats

    s11_hit, s11_stats = _make_slot11_ctor_probe()
    p = Probe("slot11_group_ctor_entry", SLOT11_GROUP_CTOR_VA, s11_hit, default_enabled=True, max_prints=0)
    p.stats = s11_stats
    add(p)

    # v219 NEW: a short read-watch on WS32:0xa7's out-param buffer (v218
    # found this ordinal is unimplemented -- default_stub never writes it)
    # showed code at 0x444838 reading [obj+4] and comparing it against the
    # magic constant 0x80000001, then zeroing [obj+8] when it DOESN'T
    # match. Since our stub leaves that buffer as whatever was already in
    # memory (garbage/zero, never the magic value), this check should
    # almost always take the "invalid" branch. This probe hooks 0x444848
    # (right after `ldr r3,[r2,#8]; cmp r3,#0; beq ...` -- i.e. right before
    # the actual magic-value read) for the FULL run to confirm how often
    # the check passes vs fails in real play, and to grab a handful of
    # observed [obj+4] values (pure observation, nothing is forced).
    MAGIC_CHECK_VA = 0x444854

    def _make_magic_check_probe():
        stats = {"total": 0, "matches_magic": 0, "examples": []}

        def _on_hit(ctx, uc, _stats=stats):
            from unicorn.arm_const import UC_ARM_REG_R2
            r2 = uc.reg_read(UC_ARM_REG_R2)
            try:
                val = struct.unpack("<I", uc.mem_read(r2 + 4, 4))[0]
            except Exception:
                val = None
            _stats["total"] += 1
            if val == 0x80000001:
                _stats["matches_magic"] += 1
            if len(_stats["examples"]) < 30:
                _stats["examples"].append((ctx.insn_count[0], hex(r2), hex(val) if val is not None else None))
            return False
        return _on_hit, stats

    mc_hit, mc_stats = _make_magic_check_probe()
    p = Probe("ws32_magic_check", MAGIC_CHECK_VA, mc_hit, default_enabled=True, max_prints=0)
    p.stats = mc_stats
    add(p)

    # v219 NEW: the magic-check function at 0x444838 was fully disassembled
    # through 0x4448f0. Re-reading the branches carefully: the magic
    # MISMATCH path (which we just proved is 100% of real play, since our
    # WS32:0xa7 stub never writes 0x80000001) is what actually REACHES the
    # vtable dispatch at 0x4448c4-0x4448d0 (`ldr r2,[r0]; ldr ip,[r2,#0x10];
    # blx ip`) -- a magic MATCH instead skips it (returns 0 at 0x4448d8) or
    # takes a different sub-branch. So the mismatch does not necessarily
    # mean "nothing happens"; it may mean this virtual call fires
    # constantly, just on a "this" pointer / vtable that may itself be
    # wrong/uninitialized because of the same missing out-param data. This
    # probe hooks 0x4448d0 (right before `bx ip`, so `ip` already holds the
    # resolved vtable target) to capture: how often this call site is
    # actually reached, what "this" (r0) is, and what function (ip) gets
    # called -- pure observation, nothing is forced or patched.
    VTABLE_CALL_VA = 0x4448d0

    def _make_vtable_call_probe():
        stats = {"total": 0, "by_target": Counter(), "examples": []}

        def _on_hit(ctx, uc, _stats=stats):
            from unicorn.arm_const import UC_ARM_REG_R0, UC_ARM_REG_R2, UC_ARM_REG_IP
            r0 = uc.reg_read(UC_ARM_REG_R0)
            r2 = uc.reg_read(UC_ARM_REG_R2)
            ip = uc.reg_read(UC_ARM_REG_IP)
            _stats["total"] += 1
            _stats["by_target"][hex(ip)] += 1
            if len(_stats["examples"]) < 30:
                _stats["examples"].append((ctx.insn_count[0], hex(r0), hex(r2), hex(ip)))
            return False
        return _on_hit, stats

    vt_hit, vt_stats = _make_vtable_call_probe()
    p = Probe("ws32_vtable_call", VTABLE_CALL_VA, vt_hit, default_enabled=True, max_prints=0)
    p.stats = vt_stats
    add(p)

    # v221 NEW (madde: User::WaitForAnyRequest / TRequestStatus yasam
    # donguesu arastirmasi). fcn.00444750 (tek statik cagirani 0x421d20,
    # bir bitmap-lock temizligi arasinda cagriliyor) ground-truth olarak
    # cozuldu: [this+0x54]=="bitti" kapisi, [this+0x74]/[this+0x80]/
    # [this+0x84] bir TRequestStatus + iki bayrak. Dongu WaitForAnyRequest
    # (EUSER:0x4b9, 0x4960b4) + RunIfReady (EUSER:0x3c3, 0x4960d4) ile
    # scheduler'i "pompaliyor", [this+0x54] gercek disinda BASKA bir
    # RunL() tarafindan set edilene kadar donuyor. Bu problar dongunun
    # HER cagrisinda kac defa dondugunu ve giris/cikis anindaki tum
    # ilgili alanlari canli olarak kaydeder -- hicbir sey zorlanmiyor,
    # sadece gozlemleniyor.
    LOOP_ENTRY_VA = 0x444750
    LOOP_TOP_VA = 0x444768
    LOOP_EXIT_VA = 0x44482C

    def _make_loop_pump_probe():
        stats = {"entries": 0, "exits": 0, "iters_histogram": Counter(),
                  "max_iters": 0, "calls": [], "_stack": []}

        def _on_entry(ctx, uc, _stats=stats):
            from unicorn.arm_const import UC_ARM_REG_R0
            this = uc.reg_read(UC_ARM_REG_R0)
            try:
                f54 = struct.unpack("<I", uc.mem_read(this + 0x54, 4))[0]
            except Exception:
                f54 = None
            _stats["entries"] += 1
            _stats["_stack"].append({"insn": ctx.insn_count[0], "this": this,
                                       "entry_f54": f54, "iters": 0})
            return False

        def _on_loop_top(ctx, uc, _stats=stats):
            if _stats["_stack"]:
                _stats["_stack"][-1]["iters"] += 1
            return False

        def _on_exit(ctx, uc, _stats=stats):
            from unicorn.arm_const import UC_ARM_REG_R4
            _stats["exits"] += 1
            rec = _stats["_stack"].pop() if _stats["_stack"] else None
            this = uc.reg_read(UC_ARM_REG_R4)
            try:
                f54 = struct.unpack("<I", uc.mem_read(this + 0x54, 4))[0]
                f74 = struct.unpack("<I", uc.mem_read(this + 0x74, 4))[0]
                f80 = struct.unpack("<I", uc.mem_read(this + 0x80, 4))[0]
                f84 = struct.unpack("<I", uc.mem_read(this + 0x84, 4))[0]
            except Exception:
                f54 = f74 = f80 = f84 = None
            iters = rec["iters"] if rec else None
            _stats["iters_histogram"][iters] += 1
            if iters is not None and iters > _stats["max_iters"]:
                _stats["max_iters"] = iters
            if len(_stats["calls"]) < 100:
                _stats["calls"].append({
                    "entry_insn": rec["insn"] if rec else None,
                    "exit_insn": ctx.insn_count[0],
                    "this": hex(this), "iters": iters,
                    "entry_f54": rec["entry_f54"] if rec else None,
                    "exit_f54": f54, "exit_f74": f74, "exit_f80": f80, "exit_f84": f84,
                })
            return False

        return _on_entry, _on_loop_top, _on_exit, stats

    lp_entry, lp_top, lp_exit, lp_stats = _make_loop_pump_probe()
    p = Probe("loop_pump_entry", LOOP_ENTRY_VA, lp_entry, default_enabled=True, max_prints=0)
    p.stats = lp_stats
    add(p)
    add(Probe("loop_pump_top", LOOP_TOP_VA, lp_top, default_enabled=True, max_prints=0))
    add(Probe("loop_pump_exit", LOOP_EXIT_VA, lp_exit, default_enabled=True, max_prints=0))

    # RequestComplete(TRequestStatus*&, TInt) call site inside the pump
    # loop's self-resolve path (EUSER:0x39f, thunk 0x4960c4, call site
    # 0x4447d0) -- who completes [this+0x80] and with what reason.
    REQUEST_COMPLETE_CALL_VA = 0x4447D0

    def _make_request_complete_probe():
        stats = {"total": 0, "examples": []}

        def _on_hit(ctx, uc, _stats=stats):
            from unicorn.arm_const import UC_ARM_REG_R1, UC_ARM_REG_R2
            r1 = uc.reg_read(UC_ARM_REG_R1)
            r2 = uc.reg_read(UC_ARM_REG_R2)
            try:
                sts_ptr = struct.unpack("<I", uc.mem_read(r1, 4))[0]
            except Exception:
                sts_ptr = None
            _stats["total"] += 1
            if len(_stats["examples"]) < 30:
                _stats["examples"].append((ctx.insn_count[0], hex(r1),
                                             hex(sts_ptr) if sts_ptr is not None else None,
                                             r2))
            return False
        return _on_hit, stats

    rc_hit, rc_stats = _make_request_complete_probe()
    p = Probe("pump_request_complete_call", REQUEST_COMPLETE_CALL_VA, rc_hit, default_enabled=True, max_prints=0)
    p.stats = rc_stats
    add(p)

    return probes


class ResearchDiagnostics:
    def __init__(self, probes=None):
        self.probes = probes if probes is not None else build_probes()
        self.enabled = {name: p.default_enabled for name, p in self.probes.items()}
        self._rebuild_index()

    def _rebuild_index(self):
        self._by_address = {}
        for name, p in self.probes.items():
            if self.enabled.get(name, False):
                self._by_address.setdefault(p.address, []).append(p)

    def enable(self, name):
        self.enabled[name] = True
        self._rebuild_index()

    def disable(self, name):
        self.enabled[name] = False
        self._rebuild_index()

    def dispatch(self, ctx, uc, address):
        for p in self._by_address.get(address, []):
            p.on_hit(ctx, uc)


# --- framebuffer snapshot timeline ----------------------------------------

class SnapshotRecorder:
    """Dense periodic framebuffer snapshots for later rendering. Cheap:
    each snapshot is 73216 bytes; only insn_count/interval of them are ever
    taken."""

    def __init__(self, watcher, interval=100_000, stream_out_dir=None):
        self.watcher = watcher
        self.interval = interval
        self.next_at = interval
        self.timeline = []  # (insn_count, raw_bytes, nonzero_count)
        # v218 NEW (user asked to capture screenshots "along the way" this
        # time, not just at the very end): if stream_out_dir is set, write
        # each snapshot to disk IMMEDIATELY as it's captured (in addition to
        # keeping it in the in-memory timeline for the old end-of-run
        # dump_to_disk path), so a still-running background job's progress
        # can be rendered and shown mid-run instead of only after it exits.
        self.stream_out_dir = stream_out_dir
        if self.stream_out_dir:
            import os
            os.makedirs(self.stream_out_dir, exist_ok=True)

    def maybe_snapshot(self, insn_count):
        if insn_count < self.next_at:
            return
        snap = self.watcher.snapshot()
        nz = sum(1 for b in snap if b != 0)
        self.timeline.append((insn_count, snap, nz))
        if self.stream_out_dir:
            import os
            fname = os.path.join(self.stream_out_dir, f"framebuffer_timeline_insn{insn_count}.bin")
            tmp_fname = fname + ".tmp"
            with open(tmp_fname, "wb") as f:
                f.write(snap)
            os.replace(tmp_fname, fname)  # atomic: never observe a partial file
        self.next_at += self.interval

    def dump_to_disk(self, out_dir="."):
        import os
        os.makedirs(out_dir, exist_ok=True)
        for insn_count, snap, nz in self.timeline:
            fname = os.path.join(out_dir, f"framebuffer_timeline_insn{insn_count}.bin")
            with open(fname, "wb") as f:
                f.write(snap)
