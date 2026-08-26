"""v223: state-synchronized key sequencer for the FULL real "reach the name
screen, then complete it" key sequence, gated behind --async-request-model
(it is built entirely on top of runtime/async_model.py's RequestRegistry --
without --async-request-model there is no request/event lifecycle to
synchronize against).

Direct response to a user correction: `5, down, down, down, 5` (PHASE 1)
only reaches the name-entry screen -- it does NOT complete it. The real,
device-confirmed sequence to actually finish name entry and progress past
it is TWO phases:

  PHASE 1 (reach the name-entry screen):
    5, down, down, down, 5

  PHASE 2 (complete the name-entry screen):
    5, right x10, down x1, right x10, down x1, right x7, 5, 5

Earlier scripted-refill scenarios (research_v209.py's make_scripted_refill)
send a fixed key list on a BLIND, fixed-interval timer -- no awareness of
whether the game actually processed the previous key before the next one
is queued. The user explicitly asked this NOT be done for phase 2: each
key must be confirmed end-to-end (enqueued -> EventReady completed ->
GetEvent consumed -> a NEW EventReady reaches PENDING again) before the
next one is sent, with a phase boundary check (module==28 AND a request
PENDING) between phase 1 and phase 2, and a stall-and-report (never
blind-continue) if a key doesn't result in a fresh pending registration.

This module owns that state machine. It exposes a refill(q)-compatible
callable (same signature runtime/input.py's EventQueue expects) plus an
on_event_consumed_hook-compatible callable to wire into a RequestRegistry.
No game code is skipped, no slots are pre-filled, no function is force-
called, no visibility patch is applied -- this only decides WHEN to feed
the SAME kind of synthetic key events the existing harness has always fed,
using the async model's own, already-verified request/event lifecycle as
the readiness signal instead of a blind timer.
"""

import struct
from collections import deque

from runtime.input import (
    EEVENT_NULL, EEVENT_KEY, EEVENT_KEY_DOWN, EEVENT_KEY_UP, KEYNAME_TO_SCANCODE,
)
from research_v209 import MENU_NAVIGATION_SEQUENCE_NO_STRAY_DOWNS, PANEL_SETTLE_FILLER

MODULE_INDEX_GLOBAL = 0xA16AF4
SELECTOR_ADDR = 0xA16AFC
CURSOR_ADDR = 0x9E3CE4 + 0x31

# v223: the main-menu navigation + panel-settle padding that gets the game
# from boot to the point where "5, down, down, down, 5" (below) can even be
# sent meaningfully. NOT part of the user's phase1/phase2 correction --
# reused as-is, unchanged, from the already-extensively-validated
# research_v209.py sequences (module reaches 5 automatically at boot,
# independent of these keys -- see WAIT_MODULE5 below; THESE keys are what
# then take the game from module 5's menu through to module 19). Delivered
# with the ORIGINAL blind, one-key-per-refill()-call timing (each repeat is
# still its own independent down/key/up burst, never merged/held -- that
# structural guarantee comes from research_v209.make_scripted_refill's
# design and is preserved here) -- the user's synchronized, confirm-before-
# advancing requirement is specifically scoped to PHASE 1's tail and PHASE
# 2 (see module docstring), not this pre-existing, already-reliable nav.
NAV_KEYS = list(MENU_NAVIGATION_SEQUENCE_NO_STRAY_DOWNS) + list(PANEL_SETTLE_FILLER)

PHASE1_KEYS = ["5", "down", "down", "down", "5"]
PHASE2_KEYS = (
    ["5"] + ["right"] * 10 + ["down"] + ["right"] * 10 + ["down"] + ["right"] * 7 + ["5", "5"]
)

# Instruction-count budget for "no new EventReady registered after a key's
# full down/key/up burst was consumed" before this is treated as a genuine
# stall (point 9) rather than something still in flight. Generous relative
# to the ~2000-70000 instruction spacing observed between pump-loop
# dispatch cycles in v222-b's smoke tests.
# v230: with the corrected one-live-request-per-TRequestStatus model, the
# first synchronized key behind the already-produced NAV tail was proven to
# complete after 1,691,322 instructions.  The old 1.5M diagnostic threshold
# fired ~190K instructions before that real completion.  Three million keeps
# the detector bounded while covering the measured worst case with margin.
STALL_BUDGET_INSN = 3_000_000


def build_full_sequence():
    """Returns the full, phase-tagged, globally-indexed key list:
    [(seq_idx, phase, key_name, scancode), ...] -- PHASE1_KEYS then
    PHASE2_KEYS, 1-indexed seq_idx across both phases."""
    out = []
    seq = 1
    for k in PHASE1_KEYS:
        out.append((seq, 1, k, KEYNAME_TO_SCANCODE[k]))
        seq += 1
    for k in PHASE2_KEYS:
        out.append((seq, 2, k, KEYNAME_TO_SCANCODE[k]))
        seq += 1
    return out


class SyncKeyInjector:
    """Drives the phased sequence above through an EventQueue-compatible
    refill(q) callable, gated on the async model's own request/event
    lifecycle rather than a fixed timer. `uc` and `ctx` are captured at
    construction (both already exist by the time run.py wires this in,
    same as the existing ctx.event_queue.on_enqueue wiring)."""

    def __init__(self, uc, ctx, registry, hold_nulls=10, gap_nulls=3, max_keys=None,
                 lifecycle_tracer=None, wait_tracer=None, nav_mode="full",
                 min_gap_insn=0, key_hold_insn=0, first_key_hold_insn=None):
        self.uc = uc
        self.ctx = ctx
        self.registry = registry
        self.hold_nulls = hold_nulls
        self.gap_nulls = gap_nulls
        # v224 madde 8: when set, NEVER send more than this many keys from
        # self.sequence, no matter what state the game reaches -- once this
        # many have been SENT (not necessarily consumed), refill() idles on
        # EEVENT_NULL forever in the new SINGLE_KEY_HALT state instead of
        # advancing. max_keys=1 is the mode the user's v224 instruction
        # mandates: send phase1's first "5" and NOTHING else, ever, until
        # root cause is found. None (default) preserves the full v223
        # phase1+phase2 behavior for other callers/tests.
        self.max_keys = max_keys
        # v224 madde 1/2: optional runtime/lifecycle_trace.py tracer,
        # additive-only -- when None, behavior is byte-for-byte identical
        # to v223 (no tracer calls made).
        self.lifecycle_tracer = lifecycle_tracer
        # v225: optional runtime/wait_trace.py tracer, additive-only.
        self.wait_tracer = wait_tracer
        self.min_gap_insn = max(0, int(min_gap_insn))
        self.key_hold_insn = max(0, int(key_hold_insn))
        self.first_key_hold_insn = (self.key_hold_insn if first_key_hold_insn is None
                                    else max(0, int(first_key_hold_insn)))
        self.current_hold_insn = self.key_hold_insn
        self.next_key_not_before = 0
        self.release_not_before = 0
        self.release_scancode = None
        self.release_appended = True
        self.require_post_release_scan = False
        self.post_release_scan_seen = True

        self.sequence = build_full_sequence()
        self.idx = 0  # index into self.sequence of the NEXT key to send
        # v231 A/B switch: research_v209 documents NAV_KEYS as the
        # boot-to-module-5 sequence, but this injector starts only after
        # module 5. Replaying it there (plus forty real filler taps) changes
        # the live menu state. Preserve that historical path by default,
        # while allowing the device-confirmed phase sequence to begin at
        # the actual module-5 boundary.
        if nav_mode not in ("full", "menu", "none"):
            raise ValueError(f"invalid nav_mode: {nav_mode!r}")
        self.nav_mode = nav_mode
        if nav_mode == "none":
            nav_keys = []
        elif nav_mode == "menu":
            nav_keys = list(MENU_NAVIGATION_SEQUENCE_NO_STRAY_DOWNS)
        else:
            nav_keys = NAV_KEYS
        self.nav_remaining = deque(nav_keys)
        self.nav_total = len(self.nav_remaining)
        self.nav_sent = 0
        self.state = "WAIT_MODULE5"
        self.current_item = None            # (seq_idx, phase, key_name, scancode) in flight
        self.current_origin = None          # "nav" or "phase"
        self.current_event_ids = {}         # role -> event_id, for the in-flight key
        self.consumed_roles = set()
        self.awaiting_new_pending_since = None
        # v223 FIX (found via a real 40M-insn run, --max-insn exhausted with
        # zero diagnostic output): AWAITING_CONSUMPTION -- waiting for the
        # CURRENT key's down/key/up burst to be consumed for the FIRST time
        # -- had NO stall budget, only AWAITING_NEW_PENDING did. A real run
        # stalled precisely in AWAITING_CONSUMPTION (phase1 seq=1 "5" sent
        # at insn#7,436,000, never confirmed consumed through the full
        # 40,000,000-insn budget) and so never triggered _dump_stall() --
        # exactly the silent-blind-continuation point 9 forbids, just with
        # "continuation" replaced by "silently exhausting the budget with no
        # evidence". Mirrors awaiting_new_pending_since/STALL_BUDGET_INSN.
        self.awaiting_consumption_since = None
        self.phase2_boundary_cleared = False  # one-shot: set once WAIT_PHASE_BOUNDARY is satisfied
        self.stalled = False
        self.stall_dumped = False
        self.last_module_logged = None

        registry.on_event_consumed_hook = self._on_event_consumed

        self._log(f"sequence built: {len(self.sequence)} keys total "
                  f"(phase1={len(PHASE1_KEYS)}, phase2={len(PHASE2_KEYS)})")

    def on_game_key_scan(self, edge_mask):
        """Release the one in-flight physical key after the game's own
        0x4305FC input conversion reports a non-zero press-edge mask.

        This turns key_hold_insn into a safe maximum rather than a guessed
        fixed duration: no key is released before game code has observed a
        press, while fast steady-state scans need not wait the full maximum.
        """
        if (self.state == "AWAITING_CONSUMPTION" and not self.release_appended
                and edge_mask):
            self.release_not_before = min(self.release_not_before,
                                          self.ctx.insn_count[0])
            self._log(f"game scan observed press edge mask={hex(edge_mask)} -- "
                      "KeyUp now eligible on next refill")
        elif self.state == "AWAITING_NEW_PENDING":
            self.post_release_scan_seen = True

    # -- memory snapshot helpers -------------------------------------------
    def _read_module(self):
        try:
            return struct.unpack("<I", self.uc.mem_read(MODULE_INDEX_GLOBAL, 4))[0]
        except Exception:
            return None

    def _read_selector(self):
        try:
            return struct.unpack("<i", self.uc.mem_read(SELECTOR_ADDR, 4))[0]
        except Exception:
            return None

    def _read_cursor(self):
        try:
            return self.uc.mem_read(CURSOR_ADDR, 1)[0]
        except Exception:
            return None

    def _snapshot(self):
        return f"module={self._read_module()} selector={self._read_selector()} cursor={self._read_cursor()}"

    def _log(self, msg):
        print(f"[SYNC-INJECT] insn#{self.ctx.insn_count[0]} {msg}", flush=True)

    def _any_pending(self):
        return any(r["state"] == "PENDING" for r in self.registry._requests.values())

    # -- consumption observer (wired into RequestRegistry) -----------------
    def _on_event_consumed(self, event_id, ev_type, ev_scancode, claimed_by):
        if self.state != "AWAITING_CONSUMPTION" or self.current_item is None:
            return
        role = None
        for r, eid in self.current_event_ids.items():
            if eid == event_id:
                role = r
                break
        if role is None:
            return  # some other, untracked event -- not ours, ignore
        self.consumed_roles.add(role)
        seq_idx, phase, name, sc = self.current_item
        self._log(f"CONSUMED seq={seq_idx} phase={phase} key={name!r} role={role} "
                  f"event_id={event_id} backed_request={claimed_by} {self._snapshot()}")
        if self.lifecycle_tracer is not None:
            self.lifecycle_tracer.on_injector_ack(event_id, role)
        if {"down", "key", "up"} <= self.consumed_roles:
            self._log(f"seq={seq_idx} phase={phase} key={name!r} fully consumed (down+key+up) "
                      f"-- waiting for a NEW EventReady to reach PENDING before sending the next key")
            self.state = "AWAITING_NEW_PENDING"
            self.awaiting_new_pending_since = self.ctx.insn_count[0]
            self.next_key_not_before = self.ctx.insn_count[0] + self.min_gap_insn
            self.post_release_scan_seen = not self.require_post_release_scan

    # -- main entry point: refill(q) ----------------------------------------
    def refill(self, q):
        mod = self._read_module()
        if mod != self.last_module_logged:
            self._log(f"module change observed: {self.last_module_logged} -> {mod}")
            self.last_module_logged = mod

        if self.stalled:
            if not self.stall_dumped:
                self._dump_stall()
                self.stall_dumped = True
            q.append((EEVENT_NULL, 0))
            return

        if self.state == "WAIT_MODULE5":
            if mod == 5:
                self.state = "NAV_READY"
                self._log(f"module==5 reached -- starting NAV ({len(self.nav_remaining)} keys, "
                          f"consumption-synchronized, then PHASE 1) {self._snapshot()}")
            else:
                q.append((EEVENT_NULL, 0))
                return

        if self.state == "NAV_READY":
            if self.nav_remaining:
                name = self.nav_remaining.popleft()
                sc = KEYNAME_TO_SCANCODE[name]
                self.nav_sent += 1
                item = (self.nav_sent, 0, name, sc)
                self._send_tracked_key(q, item, origin="nav")
                return
            self.state = "READY"
            self._log(f"NAV exhausted -- starting PHASE 1 (synchronized) {self._snapshot()}")

        if self.state == "WAIT_PHASE_BOUNDARY":
            pending = self._any_pending()
            if mod == 28 and pending:
                self.state = "READY"
                self.phase2_boundary_cleared = True  # one-shot -- never re-enter WAIT_PHASE_BOUNDARY
                self._log(f"phase boundary satisfied: module==28 AND a request is PENDING "
                          f"-- starting PHASE 2 {self._snapshot()}")
            else:
                q.append((EEVENT_NULL, 0))
                return

        if self.state == "AWAITING_CONSUMPTION":
            if (not self.release_appended and
                    self.ctx.insn_count[0] >= self.release_not_before):
                q.append((EEVENT_KEY_UP, self.release_scancode))
                for _ in range(self.gap_nulls):
                    q.append((EEVENT_NULL, 0))
                self.release_appended = True
                self._log(f"RELEASE appended after {self.current_hold_insn} instruction hold "
                          f"for scancode={hex(self.release_scancode)}")
                return
            # A deliberately long physical hold is not a stalled 3-event
            # lifecycle: KeyUp does not even exist until release_not_before.
            # Give the consumer a full normal budget *after* that scheduled
            # release, otherwise --sync-key-hold-insn > STALL_BUDGET_INSN
            # falsely diagnoses a stall before the harness can enqueue Up.
            consumption_deadline = self.awaiting_consumption_since + STALL_BUDGET_INSN
            if self.current_hold_insn > 0:
                consumption_deadline = max(
                    consumption_deadline, self.release_not_before + STALL_BUDGET_INSN)
            if self.ctx.insn_count[0] > consumption_deadline:
                self._stall("current key's down/key/up burst was never confirmed consumed "
                             "within budget (GetEvent never reached it / real event delivery stalled)")
            q.append((EEVENT_NULL, 0))
            return

        if self.state == "AWAITING_NEW_PENDING":
            if (self._any_pending() and self.ctx.insn_count[0] >= self.next_key_not_before
                    and self.post_release_scan_seen):
                self.state = "NAV_READY" if self.current_origin == "nav" else "READY"
                self._log(f"new EventReady PENDING confirmed -- ready for next "
                          f"{'NAV' if self.current_origin == 'nav' else 'phase'} key {self._snapshot()}")
            else:
                # A configured UI-settle gap is deliberate waiting, not a
                # missing request. Only diagnose a stall once BOTH that gap
                # and the normal pending-registration budget have elapsed.
                deadline = max(self.next_key_not_before,
                               self.awaiting_new_pending_since + STALL_BUDGET_INSN)
                if self.ctx.insn_count[0] > deadline and not self._any_pending():
                    self._stall("no new EventReady registered within budget after previous key's consumption")
                q.append((EEVENT_NULL, 0))
                return

        if self.state == "READY":
            if self.max_keys is not None and self.idx >= self.max_keys:
                self.state = "SINGLE_KEY_HALT"
                self._log(f"max_keys={self.max_keys} reached ({self.idx} key(s) sent) -- "
                          f"HALTING per v224 madde 8, no further key will EVER be sent "
                          f"regardless of game state, until root cause is found {self._snapshot()}")
                q.append((EEVENT_NULL, 0))
                return
            if self.idx >= len(self.sequence):
                self.state = "DONE"
                self._log(f"FULL SEQUENCE CONSUMED ({len(self.sequence)}/{len(self.sequence)} keys) {self._snapshot()}")
                q.append((EEVENT_NULL, 0))
                return
            item = self.sequence[self.idx]
            seq_idx, phase, name, sc = item
            # phase boundary: after the LAST phase-1 key is sent+fully
            # consumed+re-pending (i.e. we are about to send the FIRST
            # phase-2 key), verify the observed natural module-28 boundary
            # and a request PENDING first.
            # phase2_boundary_cleared is a ONE-SHOT latch -- without it,
            # this check would re-trigger every time this READY block is
            # reached (e.g. right after WAIT_PHASE_BOUNDARY itself resolves
            # and falls through to here in the SAME refill() call, before
            # current_item has been updated to a phase-2 item), which would
            # bounce straight back into WAIT_PHASE_BOUNDARY forever and the
            # first phase-2 key would never actually be sent.
            if phase == 2 and not self.phase2_boundary_cleared:
                self.state = "WAIT_PHASE_BOUNDARY"
                q.append((EEVENT_NULL, 0))
                return
            self._send_tracked_key(q, item, origin="phase")
            return

        if self.state == "SINGLE_KEY_HALT":
            q.append((EEVENT_NULL, 0))
            return

        if self.state == "DONE":
            q.append((EEVENT_NULL, 0))
            return

    def _append_burst(self, q, sc, hold_insn=None):
        """Raw down/key/up burst, identical in shape to
        research_v209.make_scripted_refill's -- shared by NAV (blind,
        unsynchronized) and _send_key (phase1/phase2, synchronized)."""
        q.append((EEVENT_NULL, 0))
        q.append((EEVENT_KEY_DOWN, sc))
        for _ in range(self.gap_nulls):
            q.append((EEVENT_NULL, 0))
        q.append((EEVENT_KEY, sc))
        for _ in range(self.hold_nulls):
            q.append((EEVENT_NULL, 0))
        if hold_insn is None:
            hold_insn = self.key_hold_insn
        self.current_hold_insn = hold_insn
        if hold_insn == 0:
            q.append((EEVENT_KEY_UP, sc))
            for _ in range(self.gap_nulls):
                q.append((EEVENT_NULL, 0))
            self.release_appended = True
        else:
            # Keep the physical key state visible to the game's polling
            # loop. The Up event is produced later by refill(), not queued
            # back-to-back with Down/Key as in the historical harness.
            self.release_scancode = sc
            self.release_not_before = self.ctx.insn_count[0] + hold_insn
            self.release_appended = False

    def _send_tracked_key(self, q, item, origin):
        """Send one NAV or phase key and wait for its complete lifecycle.

        v231 removes the last blind producer: NAV now uses the same
        down/key/up-consumed + fresh-EventReady barrier as phases 1/2.  This
        prevents the hundreds-of-events backlog that made phase-1 keys land
        in the wrong menu context.  `max_keys` and LifecycleTracer remain
        phase-only, preserving their v224 diagnostic meaning.
        """
        seq_idx, phase, name, sc = item
        before_id = self.registry._next_event_id
        event_ids = {"down": before_id, "key": before_id + 1, "up": before_id + 2}
        if origin == "phase" and self.lifecycle_tracer is not None:
            # v224 madde 1: "generated" is logged HERE, at the instant the
            # harness decides to append this burst to q -- distinct from
            # "enqueued", which the tracer logs separately (via
            # RequestRegistry.lifecycle_hook) once run.py's EventQueue.
            # _do_refill() actually reports it to the registry and an
            # event_id is assigned. The two are almost always the same
            # instruction in this harness, but are proven separately
            # rather than assumed identical.
            # arm() BEFORE the burst is appended -- explicit correlation by
            # exact event_id, NOT by scancode alone (NAV also sends '5',
            # see lifecycle_trace.py's class docstring note). First-call-
            # wins, so with the default max_keys=1 config this always locks
            # onto exactly phase1's first "5".
            self.lifecycle_tracer.arm(event_ids, sc)
            for role in ("down", "key", "up"):
                self.lifecycle_tracer.on_key_generated(role, sc)
        hold_insn = (self.first_key_hold_insn
                     if origin == "phase" and seq_idx == 1
                     else self.key_hold_insn)
        self._append_burst(q, sc, hold_insn=hold_insn)
        self.current_event_ids = event_ids
        self.consumed_roles = set()
        self.current_item = item
        self.current_origin = origin
        self.state = "AWAITING_CONSUMPTION"
        self.awaiting_consumption_since = self.ctx.insn_count[0]
        if origin == "phase":
            self.idx += 1
        total = self.nav_total if origin == "nav" else len(self.sequence)
        label = "NAV" if origin == "nav" else f"phase={phase}"
        self._log(f"SENT {label} seq={seq_idx}/{total} key={name!r} "
                  f"scancode={hex(sc)} event_ids(down/key/up)="
                  f"({before_id},{before_id+1},{before_id+2}) {self._snapshot()}")

    def _stall(self, reason):
        self.stalled = True
        self.stall_reason = reason
        self._log(f"STALL: {reason}")

    def _dump_stall(self):
        seq_idx, phase, name, sc = self.current_item if self.current_item else (None, None, None, None)
        pc = None
        lr = None
        try:
            from unicorn.arm_const import UC_ARM_REG_PC, UC_ARM_REG_LR
            pc = hex(self.uc.reg_read(UC_ARM_REG_PC))
            lr = hex(self.uc.reg_read(UC_ARM_REG_LR))
        except Exception:
            pass
        trace_tail = None
        if getattr(self.ctx, "trace", None) is not None:
            try:
                trace_tail = [(n, hex(a)) for n, a in list(self.ctx.trace)[-30:]]
            except Exception:
                trace_tail = None
        requests_snapshot = {rid: dict(r) for rid, r in self.registry._requests.items()}
        event_fifo_snapshot = list(self.registry._event_fifo)
        queue_snapshot = list(self.ctx.event_queue._q) if getattr(self.ctx, "event_queue", None) else None
        self._log("=== STALL DIAGNOSTIC DUMP ===")
        self._log(f"reason: {self.stall_reason}")
        self._log(f"stuck after seq={seq_idx} phase={phase} key={name!r} scancode={hex(sc) if sc else None}")
        self._log(f"PC={pc} LR={lr}")
        self._log(f"{self._snapshot()}")
        self._log(f"requests: {requests_snapshot}")
        self._log(f"event_fifo: {event_fifo_snapshot}")
        self._log(f"event_queue._q (raw, unconsumed): {queue_snapshot}")
        self._log(f"trace tail (last 30 executed addrs, insn#,pc): {trace_tail}")
        self._log("=== END STALL DIAGNOSTIC DUMP ===")
        if self.lifecycle_tracer is not None:
            self.lifecycle_tracer.print_summary()
        if self.wait_tracer is not None:
            self.wait_tracer.print_summary()
            tracked_ids = list(self.current_event_ids.values()) if self.current_event_ids else []
            full_waits = self.wait_tracer.find_waits_for_event_ids(tracked_ids)
            self._log(f"=== v225 FULL WAIT EVIDENCE for tracked event_ids {tracked_ids} "
                      f"({len(full_waits)} matching wait(s)) ===")
            for w in full_waits:
                self._log(f"wait_id={w['wait_id']} full_record: {w}")
            self._log("=== END v225 FULL WAIT EVIDENCE ===")
