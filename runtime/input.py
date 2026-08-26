"""Real key-event delivery.

WS32:0x76 (GetEvent, thunk VA below) is the window server's real event-poll
entry point. The dispatch chain that CONSUMES its output
(0x444acc -> 0x444a58 -> 0x438340 for raw Down/Up, or a vtable call through
the focused control for the synthesized EEventKey) is confirmed, real game
code -- fully reverse engineered over many sessions. This module owns the
one piece WE must supply since GetEvent itself is an unimplemented DLL
import: filling in the TWsEvent struct GetEvent is supposed to write.

TWsEvent layout (confirmed by direct disassembly of 0x444acc/0x444a58):
  +0x00  iType       (TEventCode: 0=Null, 1=EEventKey(translated),
                       2=EEventKeyUp, 3=EEventKeyDown)
  +0x10  iCode       (TInt -- the SEMANTIC key code, TKeyEvent)
  +0x14  iScanCode   (TInt for the translated event; a single byte for
                       raw Up/Down -- both confirmed by trace)
  +0x18  iModifiers
  +0x1c  iRepeats

iCode vs iScanCode: v231 corrected a long-standing false inference. The
0x444e58 handler which compares iCode to integer 5 is the application-shell
close command: it calls 0x4446f4, sets [app+0x54]=1 and enters teardown.
Mapping the physical keypad '5' to iCode=5 therefore converted every select
press into Quit; skip_close_handler merely hid the damage. The game itself
receives physical Down/Up scancodes through 0x438340. A translated digit 5
keeps its character code 0x35; only D-pad keys need TKeyCode overrides.
"""

import struct
from collections import deque

GETEVENT_THUNK_VA = 0x496614  # WS32:0x76

EEVENT_NULL = 0
EEVENT_KEY = 1        # synthesized "translated key" -- what most control
                        # navigation (OfferKeyEventL-style handlers) reacts to
EEVENT_KEY_UP = 2
EEVENT_KEY_DOWN = 3

# Confirmed real N-Gage scancodes (matches Symbian's TStdScanCode / ASCII
# digit range, cross-checked against a real played-through session):
SCANCODE_UP = 0x10
SCANCODE_DOWN = 0x11
SCANCODE_LEFT = 0x0E
SCANCODE_RIGHT = 0x0F
SCANCODE_5 = 0x35
SCANCODE_2 = 0x32
SCANCODE_3 = 0x33

KEYNAME_TO_SCANCODE = {
    "5": SCANCODE_5, "up": SCANCODE_UP, "down": SCANCODE_DOWN,
    "left": SCANCODE_LEFT, "right": SCANCODE_RIGHT,
    "2": SCANCODE_2, "3": SCANCODE_3,
}

# TKeyEvent.iCode is a Symbian TKeyCode, not a TStdScanCode.  The D-pad
# values are the platform's EKey*Arrow constants; using raw scan codes here
# made GetEvent visibly consume the events while OfferKeyEvent-style menu
# logic ignored them (v231: three Down events left selector 0 unchanged).
# iScanCode below remains the physical 0x0e..0x11 value.
EKEY_LEFT_ARROW = 0xF807
EKEY_RIGHT_ARROW = 0xF808
EKEY_UP_ARROW = 0xF809
EKEY_DOWN_ARROW = 0xF80A

ICODE_OVERRIDES = {
    SCANCODE_LEFT: EKEY_LEFT_ARROW,
    SCANCODE_RIGHT: EKEY_RIGHT_ARROW,
    SCANCODE_UP: EKEY_UP_ARROW,
    SCANCODE_DOWN: EKEY_DOWN_ARROW,
}


class EventQueue:
    """Wraps the pending-event deque GetEvent drains from. `refill` is
    called whenever the queue runs dry, so callers (research scripts,
    interactive tools) can supply whatever sequence they want without this
    module knowing about test-specific content.

    v222-b: `on_enqueue`, if set (a public, mutable attribute -- not a
    constructor-only param, since run.py wires it up AFTER ctx.event_queue
    is constructed, once ctx.async_registry exists), is called once per
    NEWLY appended (ev_type, ev_scancode) tuple, in order, every time
    `_refill` actually adds items to `_q`. This is the real "the window
    server produced an event" signal the async request-completion model
    needs -- see runtime/async_model.py's "v222-b UPDATE" docstring for why
    this replaced the earlier (circular) GetEvent-triggered-completion
    design. refill() callbacks (e.g. research_v209.py's make_scripted_refill)
    still just append directly to the raw deque handed to them -- they are
    NOT modified; the hook fires centrally in _do_refill() by diffing queue
    length before/after, so every existing refill callback gets this for
    free."""

    # v222-b: cap on how many CONSECUTIVE, un-consumed EEVENT_NULL entries
    # are allowed to sit at the FRONT of the queue after a produce_tick().
    # Only reached once something starts ticking production independent of
    # consumption (see produce_tick()) -- without this, a long "nothing
    # happening yet" stretch (e.g. ~7M instructions of boot before the
    # scripted sequence's ready_flag precondition becomes true) accumulates
    # thousands of stale nulls, none of which anything has ever popped
    # (nothing was calling GetEvent yet -- that's the whole bug). Once a
    # REAL event is finally produced and completion re-opens the game's
    # pump loop, GetEvent has to drain through that entire stale backlog,
    # call by call, before it ever reaches the real event -- confirmed
    # empirically (getevent_called=251, event_consumed=0 in an 8M-run smoke
    # test: GetEvent was running, just still working through ~3600+ stale
    # nulls). Trimming is safe: a NULL delivered via GetEvent is a pure
    # no-op for the game (EEVENT_NULL means "nothing happened this poll"),
    # so discarding EXCESS unconsumed ones changes no game-observable
    # behavior -- it only shrinks how many no-op polls the game has to
    # burn through. Real (non-null) events are NEVER touched by this: the
    # trim only ever removes from a purely-null run at the front, and stops
    # the instant it reaches a non-null entry.
    _STALE_NULL_KEEP = 2
    _STALE_NULL_THRESHOLD = 8

    def __init__(self, refill, on_enqueue=None):
        self._q = deque()
        self._refill = refill
        self.on_enqueue = on_enqueue

    def _trim_stale_nulls(self):
        """Collapse EVERY run of consecutive EEVENT_NULL entries anywhere in
        the queue down to at most _STALE_NULL_KEEP, preserving every
        non-null entry and the overall relative order. Scanning the whole
        queue (not just a leading run) matters: an earlier version only
        trimmed a run at the very FRONT, which meant a single un-consumed
        real event sitting near the front (waiting on GetEvent to reach it)
        permanently disabled trimming for everything produced after it --
        exactly the kind of unbounded-growth case this exists to prevent."""
        if len(self._q) <= self._STALE_NULL_THRESHOLD:
            return
        new_q = deque()
        null_run = 0
        for item in self._q:
            if item[0] == EEVENT_NULL:
                null_run += 1
                if null_run <= self._STALE_NULL_KEEP:
                    new_q.append(item)
                # else: drop -- part of an excess consecutive-null run
            else:
                null_run = 0
                new_q.append(item)
        self._q = new_q

    def _do_refill(self):
        before = len(self._q)
        self._refill(self._q)
        if self.on_enqueue is not None and len(self._q) > before:
            # deque doesn't support slicing; materialize once (queues here
            # are always small -- scripted key sequences, not bulk data).
            for ev_type, ev_scancode in list(self._q)[before:]:
                self.on_enqueue(ev_type, ev_scancode)

    def produce_tick(self):
        """v222-b: unconditionally invoke the refill callback once,
        regardless of current queue depth -- called periodically (on an
        instruction-count cadence, NOT on consumption) by run.py's main
        hook_code loop when --async-request-model is active. This is what
        makes event PRODUCTION independent of whether anything has ever
        popped/peeked: pop()/peek() only refill lazily when the queue is
        EMPTY, which meant that once nothing was draining the queue (the
        exact v222-b bug this fixes -- GetEvent, the only thing that ever
        called pop(), became unreachable), the scripted sequence could
        never advance past its first auto-refilled item, no matter how
        long ready_flag-gated preconditions took to become true. Goes
        through the same _do_refill() path (and therefore the same
        on_enqueue notifications) as the lazy pop()/peek()-triggered
        refill, so the async request-completion model still gets notified
        of every new real event exactly the same way. Also trims any stale
        unconsumed EEVENT_NULL backlog afterwards (see _trim_stale_nulls) --
        only this eager, consumption-independent path can build one up;
        the lazy pop()/peek()-triggered refill only ever fires when the
        queue is already empty, so it never needs trimming."""
        self._do_refill()
        self._trim_stale_nulls()

    def pop(self):
        if not self._q:
            self._do_refill()
        return self._q.popleft()

    def peek(self):
        """Non-destructive look at the next event, refilling if empty (same
        synchronous refill path as pop(), no sleep). Added for the v221
        async request-completion model; kept for diagnostics even though
        v222-b's completion logic no longer calls it (completion is now
        driven by on_enqueue / registration-time queue checks, not by
        peeking from inside WaitForAnyRequest)."""
        if not self._q:
            self._do_refill()
        return self._q[0] if self._q else None

    def push_down_up_pair(self, scancode, hold_nulls=10, gap_nulls=3):
        """Queue a realistic Down -> (translated Key) -> Up -> idle
        sequence for one keypress, matching how a real window server
        delivers a press (confirmed necessary: AVKON-style navigation only
        reacts to the synthesized EEVENT_KEY, not raw Down/Up)."""
        self._q.append((EEVENT_NULL, 0))
        self._q.append((EEVENT_KEY_DOWN, scancode))
        for _ in range(3):
            self._q.append((EEVENT_NULL, 0))
        self._q.append((EEVENT_KEY, scancode))
        for _ in range(hold_nulls):
            self._q.append((EEVENT_NULL, 0))
        self._q.append((EEVENT_KEY_UP, scancode))
        for _ in range(gap_nulls):
            self._q.append((EEVENT_NULL, 0))

    def push_idle(self):
        self._q.append((EEVENT_NULL, 0))


def handle_get_event(ctx, uc, on_injected=None):
    """WS32:0x76 handler. Pops the next event and writes the TWsEvent
    struct at aEvent (R1). `on_injected(insn_count, ev_type, ev_scancode)`
    is an optional callback for logging -- kept as a callback rather than a
    print here, so runtime code stays silent by default and research code
    decides what to log."""
    from unicorn.arm_const import UC_ARM_REG_R0, UC_ARM_REG_R1

    ev_type, ev_scancode = ctx.event_queue.pop()
    # v222-b: expose the just-popped event on ctx as plain attributes,
    # synchronously overwritten every call. Originally added (v222, first
    # attempt) to DRIVE completion from inside GetEvent's wrapper -- that
    # design turned out to be circular (see async_model.py's "v222-b
    # UPDATE") and was replaced by queue-level on_enqueue completion.
    # These attributes are kept because runtime/async_model.py's
    # wrap_get_event() still reads them, now only to track which physical
    # event GetEvent just CONSUMED (for logging / orphan-consumption
    # detection), never to trigger a completion. Plain attributes (not a
    # list/box) are safe here because the read always happens
    # synchronously, in the same call, immediately after this function
    # returns -- no concurrent access.
    ctx.last_get_event_type = ev_type
    ctx.last_get_event_scancode = ev_scancode
    r1 = uc.reg_read(UC_ARM_REG_R1)
    uc.mem_write(r1, struct.pack("<I", ev_type))

    if ev_type == EEVENT_KEY:
        icode_val = ICODE_OVERRIDES.get(ev_scancode, ev_scancode)
        uc.mem_write(r1 + 0x10, struct.pack("<i", icode_val))
        uc.mem_write(r1 + 0x14, struct.pack("<i", ev_scancode))
        uc.mem_write(r1 + 0x18, struct.pack("<I", 0))
        uc.mem_write(r1 + 0x1c, struct.pack("<i", 0))
    elif ev_type != EEVENT_NULL:
        uc.mem_write(r1 + 0x14, struct.pack("<B", ev_scancode))

    uc.reg_write(UC_ARM_REG_R0, 0)  # KErrNone

    if on_injected is not None:
        on_injected(ctx.insn_count[0], ev_type, ev_scancode)
