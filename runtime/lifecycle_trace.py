"""v224: per-event, stage-by-stage lifecycle tracer for the FIRST tracked
key event (scancode 0x35 == "5"), built in direct response to the user's
explicit rejection of v223's "CPU was in a bitmap routine" stall-PC-sample
finding as an unproven root cause. That finding was a SINGLE PC sample at
the moment of stall -- this module instead proves or disproves, with
distinct evidence for each stage, exactly how far the FIRST "5" key's
generated/enqueued/completed/consumed lifecycle actually got, and captures
enough live disassembly-anchored evidence (per-call bitmap-function
records, periodic PC/SP/LR samples during the wait) to tell a genuine
deadlock from a merely slow-but-progressing loop.

Ground truth this module is built on (v224 r2 disassembly, this session):
  fcn.00444acc (GetEvent caller + iType dispatch cascade):
    0x444ae8  bl fcn.00496614          (GETEVENT_THUNK_VA -- the real call)
    0x444aec  ldr r2,[r7,0x10]         (r2 = iType of the just-filled
                                         TWsEvent; TWsEvent base = r7+0x10)
    -- this is "GetEvent returned" AND "handler entered" in one place: the
    cascade that follows IS the handler.
    r2==1 (EEventKey, translated key) branch:
      0x444b7c  ldr r3,[r7]            ("this" / focused control ptr)
      0x444b8c  ldr ip,[r3,0x10]; mov lr,pc
      0x444b90  bx ip                  -- VTABLE CALL: the actual dispatch
                                          of a translated "5" key into game
                                          logic. This is "key interpreted".
      0x444b94  (return point)
    r2 in {2,3} (raw Down/Up) branch:
      0x444b98-0x444ba0  bl fcn.00444a58
      0x444ba4  (return point)
  fcn.00444a58 (raw Down/Up handler):
    0x444ab4  bl fcn.00438340          -- the real down/up consumer. This
                                          is "key interpreted" for the raw
                                          Down/Up events (down/up bursts of
                                          our tracked key use ev_type 2/3,
                                          NOT ev_type 1 -- only the middle
                                          "key" (EEVENT_KEY) burst item is
                                          type 1 and takes the vtable path
                                          above).
    0x444ac4-0x444ac8  pop {r4,r5,r6,lr}; bx lr   (return)

  fcn.00448424 / fcn.004484e8 (nibble/pixel bitmap-unpack routines, the
  v223 stall-PC-sample location): single-caller, non-recursive, called
  from fcn.004485cc (itself reached from fcn.00448370). Loop-top/exit/
  return addresses confirmed by r2 in v223/v224 disassembly:
    fcn.00448424: entry 0x448424, loop-top 0x448444, loop-exit
                  0x4484d4/0x4484dc (bgt back to loop-top), return via
                  `pop {r4,r5,lr}` @ 0x4484e0 then `bx lr` @ 0x4484e4.
    fcn.004484e8: entry 0x4484e8, loop-top 0x448504, loop-exit
                  0x4485b4/0x4485b8/0x4485c0, return via
                  `pop {r4,r5,r6,r7,lr}` @ 0x4485c4 then `bx lr` @ 0x4485c8.

TRACKED_SCANCODE = 0x35 ("5") is unique among everything this harness ever
enqueues (NAV never sends "5"), so any real (non-null) event carrying this
scancode, anywhere in the pipeline, is unambiguously one of the three
bursts (down/key/up) of the FIRST tracked "5" -- no event_id confusion is
possible even before an id is assigned.

This module does NOT skip any bitmap call, does NOT force a function to
return, does NOT change screens, does NOT pre-fill slots, and does NOT
alter what counts as "consumed" -- it is purely observational (memory
reads and PC/register reads only), wired in via run.py's existing
hook_code dispatch and runtime/async_model.py's existing hook slots.
"""

import struct
from collections import deque

TRACKED_SCANCODE = 0x35  # "5" -- see KEYNAME_TO_SCANCODE in runtime/input.py

# -- fcn.00444acc / fcn.00444a58 dispatch-chain PCs (v224 r2 disassembly) --
GETEVENT_RETURN_PC = 0x444aec        # r2 = iType, right after the real GetEvent thunk call returns
EEVENTKEY_BRANCH_PC = 0x444b7c       # r2==1 (EEventKey) branch entered
EEVENTKEY_VTABLE_CALL_PC = 0x444b8c  # bx ip -- the vtable dispatch itself ("key interpreted", translated path)
EEVENTKEY_RETURN_PC = 0x444b94       # vtable call returned
RAWKEY_BRANCH_PC = 0x444b98          # r2 in {2,3} (raw Down/Up) branch entered
RAWKEY_HANDLER_ENTRY_PC = 0x444a58   # fcn.00444a58 entry
RAWKEY_CONSUMER_CALL_PC = 0x444ab4   # bl fcn.00438340 -- "key interpreted", raw Down/Up path
RAWKEY_HANDLER_RETURN_PC = 0x444ba4  # back in fcn.00444acc after fcn.00444a58 returns

# -- bitmap routines (v223/v224 r2 disassembly) -----------------------------
BITMAP_A_ENTRY = 0x448424
BITMAP_A_LOOP_TOP = 0x448444
BITMAP_A_RETURN = 0x4484e4  # bx lr
BITMAP_B_ENTRY = 0x4484e8
BITMAP_B_LOOP_TOP = 0x448504
BITMAP_B_RETURN = 0x4485c8  # bx lr

PC_SAMPLE_INTERVAL_INSN = 200_000  # periodic sampling cadence during any wait


class LifecycleTracer:
    """Stage-by-stage tracer for the FIRST occurrence of TRACKED_SCANCODE.
    Wired in by run.py (behind --lifecycle-trace) and additively by
    runtime/async_model.py's RequestRegistry (a second hook slot,
    `lifecycle_hook`, added alongside the existing on_event_consumed_hook
    so runtime/sync_injector.py's own consumption tracking is untouched)."""

    def __init__(self, uc, ctx):
        self.uc = uc
        self.ctx = ctx

        # event_id -> role ("down"/"key"/"up"). NOTE (v224, found via this
        # module's own isolated sanity test before ANY real emulator run):
        # scancode 0x35 ("5") is NOT actually unique to phase1's first "5"
        # -- runtime/sync_injector.py's NAV_KEYS (the pre-existing,
        # already-validated main-menu navigation burst) sends "5" EIGHT
        # separate times before phase1 even starts (confirmed by reading
        # NAV_KEYS's contents directly: 8 occurrences). Auto-detecting
        # "our" event purely by scancode at enqueue time would therefore
        # wrongly track all 8 NAV "5" bursts too (24 events) in addition to
        # the real target -- caught by the isolated test in this window
        # (tracer.stage_counts['enqueued'] came back 27, not 3, before this
        # fix). Correlation is therefore EXPLICIT: runtime/sync_injector.py
        # calls self.arm(...) with the exact three event_ids it just
        # computed for the SPECIFIC burst it is about to send (first-call-
        # wins -- only the very first armed call is ever honored, so even
        # if SyncKeyInjector is reused for a config that sends more than
        # one key, this tracer stays locked onto the FIRST one, per the
        # user's explicit requirement). TRACKED_SCANCODE is kept only as a
        # secondary sanity check (self._log a warning on mismatch), not the
        # primary correlation mechanism.
        self.tracked_event_ids = {}
        self.armed = False

        # madde 3: four DISTINCT counters, incremented independently, never
        # inferred from one another.
        self.stage_counts = {
            "generated": 0,
            "enqueued": 0,
            "eventready_completed": 0,
            "wait_woken": 0,
            "dequeued_by_getevent": 0,     # event popped from the internal ledger by GetEvent
            "delivered_to_handler": 0,     # fcn.00444acc's cascade actually loaded THIS event's iType/scancode
            "interpreted_by_module": 0,    # the vtable call / fcn.00438340 call for THIS event actually executed
            "injector_acknowledged": 0,    # SyncKeyInjector's OWN "CONSUMED" bookkeeping fired for this role
        }
        self.stage_log = []  # [(insn, event_id_or_role, stage, extra_str)]

        # per-event last-known request id (for wait_woken attribution) and
        # a one-shot "currently dispatching THIS event's iType" latch so
        # 0x444b8c/0x444ab4 hits get attributed to the right burst instead
        # of a later, unrelated GetEvent call.
        self._active_dispatch_event_id = None
        self._active_dispatch_role = None

        # madde 6: periodic PC/SP/LR/module sampling, independent of any
        # specific event -- lets a post-hoc read tell "PC keeps moving,
        # still executing SOMETHING" apart from "PC frozen, truly stuck".
        self.pc_samples = deque(maxlen=20000)
        self._last_sample_insn = 0

        # madde 4: bitmap-function call records. Keyed by entry insn count.
        self.bitmap_calls = []           # list of dicts, one per entry/return pair
        self._bitmap_stack = []          # active (unreturned) calls, LIFO by entry PC seen

        self.done_reported = False

    # -- helpers -------------------------------------------------------------
    def _insn(self):
        return self.ctx.insn_count[0]

    def _log(self, stage, subject, extra=""):
        insn = self._insn()
        self.stage_log.append((insn, subject, stage, extra))
        print(f"[LIFECYCLE] insn#{insn} stage={stage} subject={subject} {extra}", flush=True)

    def _regs(self):
        from unicorn.arm_const import UC_ARM_REG_PC, UC_ARM_REG_LR, UC_ARM_REG_SP
        try:
            pc = self.uc.reg_read(UC_ARM_REG_PC)
            lr = self.uc.reg_read(UC_ARM_REG_LR)
            sp = self.uc.reg_read(UC_ARM_REG_SP)
            return pc, lr, sp
        except Exception:
            return None, None, None

    # -- explicit arming (called from SyncKeyInjector, first-call-wins) -----
    def arm(self, event_ids_by_role, scancode):
        """Explicitly designates the three event_ids (down/key/up) of the
        SPECIFIC burst being sent as "the tracked event" -- called by
        runtime/sync_injector.py's SyncKeyInjector._send_key() right after
        it computes those ids, BEFORE the actual enqueue happens. Only the
        first call is ever honored (locks onto the FIRST key sent, per the
        user's explicit requirement to trace only phase1's first '5')."""
        if self.armed:
            return
        if scancode != TRACKED_SCANCODE:
            self._log("arm_scancode_mismatch", str(event_ids_by_role),
                       f"expected scancode={hex(TRACKED_SCANCODE)} got={hex(scancode)}")
            return
        self.armed = True
        # event_ids_by_role is {role: event_id} (how SyncKeyInjector computes
        # it) -- store the INVERSE, {event_id: role}, since every downstream
        # lookup here is by event_id (the id RequestRegistry actually hands
        # back at each stage).
        self.tracked_event_ids = {eid: role for role, eid in event_ids_by_role.items()}
        self._log("armed", str(self.tracked_event_ids), "")

    # -- madde 1/2: generation + enqueue (called from SyncKeyInjector) -------
    def on_key_generated(self, role, scancode):
        if scancode != TRACKED_SCANCODE:
            return
        self.stage_counts["generated"] += 1
        self._log("generated", role)

    def on_event_enqueued(self, event_id, ev_type, scancode):
        """RequestRegistry.lifecycle_hook interface method -- called for
        EVERY real event enqueued. Only acts on event_ids explicitly armed
        via arm() above (see the class-level note on why scancode alone is
        NOT a safe correlation key -- NAV also sends '5')."""
        if event_id not in self.tracked_event_ids:
            return
        role = self.tracked_event_ids[event_id]
        if scancode != TRACKED_SCANCODE:
            self._log("enqueued_scancode_mismatch", f"event_id={event_id} role={role}",
                       f"expected={hex(TRACKED_SCANCODE)} got={hex(scancode)}")
        self.stage_counts["enqueued"] += 1
        self._log("enqueued", f"event_id={event_id} role={role}", f"ev_type={ev_type}")

    def on_eventready_completed(self, req_id, event_id):
        """RequestRegistry.lifecycle_hook interface method."""
        if event_id not in self.tracked_event_ids:
            return
        role = self.tracked_event_ids[event_id]
        self.stage_counts["eventready_completed"] += 1
        self._log("eventready_completed", f"event_id={event_id} role={role}", f"request_id={req_id}")

    def on_wait_woken(self, req_id, event_id):
        """RequestRegistry.lifecycle_hook interface method. event_id may be
        None (a self-managed wake, unrelated to any EventReady completion)
        -- only counted/logged when it demonstrably corresponds to one of
        OUR tracked events, never inferred from an untracked wake."""
        if event_id is None or event_id not in self.tracked_event_ids:
            return
        role = self.tracked_event_ids[event_id]
        self.stage_counts["wait_woken"] += 1
        self._log("wait_woken", f"event_id={event_id} role={role}", f"request_id={req_id}")

    def on_event_consumed(self, event_id, ev_type, ev_scancode, claimed_by):
        """RequestRegistry.lifecycle_hook interface method -- fires when
        GetEvent's wrapper (async_model.wrap_get_event) pops a real event
        off the internal ledger, i.e. the moment the harness's own model
        believes GetEvent delivered this specific event to the game."""
        if event_id not in self.tracked_event_ids:
            return
        role = self.tracked_event_ids[event_id]
        self.stage_counts["dequeued_by_getevent"] += 1
        self._active_dispatch_event_id = event_id
        self._active_dispatch_role = role
        self._log("dequeued_by_getevent", f"event_id={event_id} role={role}", f"claimed_by={claimed_by}")

    def on_injector_ack(self, event_id, role):
        if event_id not in self.tracked_event_ids:
            return
        self.stage_counts["injector_acknowledged"] += 1
        self._log("injector_acknowledged", f"event_id={event_id} role={role}", "")

    # -- PC-based hooks (called every instruction from run.py's hook_code) --
    def on_pc(self, address):
        if address == GETEVENT_RETURN_PC:
            self._on_getevent_return()
        elif address in (EEVENTKEY_VTABLE_CALL_PC, RAWKEY_CONSUMER_CALL_PC):
            self._on_interpreted(address)
        elif address in (BITMAP_A_ENTRY, BITMAP_B_ENTRY):
            self._on_bitmap_entry(address)
        elif address in (BITMAP_A_LOOP_TOP, BITMAP_B_LOOP_TOP):
            self._on_bitmap_loop_iter(address)
        elif address in (BITMAP_A_RETURN, BITMAP_B_RETURN):
            self._on_bitmap_return(address)

        self.maybe_sample()

    def _on_getevent_return(self):
        # r7+0x10 = TWsEvent base (confirmed layout: +0x00 iType, +0x14 iScanCode)
        from unicorn.arm_const import UC_ARM_REG_R7
        try:
            r7 = self.uc.reg_read(UC_ARM_REG_R7)
            base = r7 + 0x10
            i_type = struct.unpack("<i", self.uc.mem_read(base + 0x00, 4))[0]
            i_scancode = struct.unpack("<i", self.uc.mem_read(base + 0x14, 4))[0]
        except Exception:
            return
        if i_scancode != TRACKED_SCANCODE:
            self._active_dispatch_event_id = None
            self._active_dispatch_role = None
            return
        role = self._active_dispatch_role or "?"
        event_id = self._active_dispatch_event_id
        self.stage_counts["delivered_to_handler"] += 1
        self._log("delivered_to_handler", f"event_id={event_id} role={role}", f"iType={i_type}")

    def _on_interpreted(self, address):
        if self._active_dispatch_role is None:
            return  # not currently dispatching one of our tracked events
        role = self._active_dispatch_role
        event_id = self._active_dispatch_event_id
        which = "vtable(EEventKey)" if address == EEVENTKEY_VTABLE_CALL_PC else "fcn.00438340(raw Down/Up)"
        self.stage_counts["interpreted_by_module"] += 1
        self._log("interpreted_by_module", f"event_id={event_id} role={role}", f"via={which}")
        # one-shot per dispatch: clear so a later, unrelated GetEvent call
        # doesn't get mis-attributed to this same tracked event.
        self._active_dispatch_event_id = None
        self._active_dispatch_role = None

    # -- madde 4: bitmap function instrumentation ----------------------------
    def _on_bitmap_entry(self, address):
        from unicorn.arm_const import UC_ARM_REG_LR, UC_ARM_REG_R0, UC_ARM_REG_R1
        pc, lr, sp = self._regs()
        try:
            r0 = self.uc.reg_read(UC_ARM_REG_R0)
            r1 = self.uc.reg_read(UC_ARM_REG_R1)
        except Exception:
            r0 = r1 = None
        which = "A(fcn.00448424)" if address == BITMAP_A_ENTRY else "B(fcn.004484e8)"
        rec = {
            "which": which, "entry_insn": self._insn(), "lr": lr,
            "r0": r0, "r1": r1, "iterations": 0, "return_insn": None,
        }
        self._bitmap_stack.append(rec)
        self.bitmap_calls.append(rec)
        self._log("bitmap_entry", which, f"lr={hex(lr) if lr else lr} r0={hex(r0) if r0 else r0} "
                                           f"r1={hex(r1) if r1 else r1} total_calls={len(self.bitmap_calls)}")

    def _on_bitmap_loop_iter(self, address):
        if not self._bitmap_stack:
            return
        self._bitmap_stack[-1]["iterations"] += 1

    def _on_bitmap_return(self, address):
        if not self._bitmap_stack:
            return
        rec = self._bitmap_stack.pop()
        rec["return_insn"] = self._insn()
        span = rec["return_insn"] - rec["entry_insn"]
        self._log("bitmap_return", rec["which"],
                   f"iterations={rec['iterations']} insn_span={span} lr={hex(rec['lr']) if rec['lr'] else rec['lr']}")

    # -- madde 6: periodic PC/SP/LR/module sampling --------------------------
    def maybe_sample(self):
        insn = self._insn()
        if insn - self._last_sample_insn < PC_SAMPLE_INTERVAL_INSN:
            return
        self._last_sample_insn = insn
        pc, lr, sp = self._regs()
        mod = None
        try:
            mod = struct.unpack("<I", self.uc.mem_read(0xA16AF4, 4))[0]
        except Exception:
            pass
        in_bitmap = self._bitmap_stack[-1]["which"] if self._bitmap_stack else None
        sample = (insn, pc, lr, sp, mod, in_bitmap,
                  len(self.bitmap_calls), self._bitmap_stack[-1]["iterations"] if self._bitmap_stack else 0)
        self.pc_samples.append(sample)
        print(f"[LIFECYCLE-SAMPLE] insn#{insn} PC={hex(pc) if pc else pc} LR={hex(lr) if lr else lr} "
              f"SP={hex(sp) if sp else sp} module={mod} in_bitmap={in_bitmap} "
              f"bitmap_calls_total={len(self.bitmap_calls)} "
              f"cur_bitmap_iterations={sample[7]}", flush=True)

    # -- final report ----------------------------------------------------------
    def summary(self):
        return {
            "tracked_event_ids": dict(self.tracked_event_ids),
            "stage_counts": dict(self.stage_counts),
            "bitmap_calls_total": len(self.bitmap_calls),
            "bitmap_calls_unreturned": len(self._bitmap_stack),
            "bitmap_calls_detail": self.bitmap_calls[-20:],  # last 20, avoid unbounded log spam
            "pc_samples_tail": list(self.pc_samples)[-30:],
            "pc_samples_total": len(self.pc_samples),
        }

    def print_summary(self):
        s = self.summary()
        print("\n--- v224 lifecycle tracer summary (first tracked \"5\" event, scancode=0x35) ---", flush=True)
        print(f"tracked_event_ids: {s['tracked_event_ids']}", flush=True)
        print(f"stage_counts: {s['stage_counts']}", flush=True)
        print(f"bitmap_calls_total: {s['bitmap_calls_total']} unreturned: {s['bitmap_calls_unreturned']}", flush=True)
        for rec in s["bitmap_calls_detail"]:
            print(f"  bitmap_call: {rec}", flush=True)
        print(f"pc_samples_total: {s['pc_samples_total']}", flush=True)
        for smp in s["pc_samples_tail"]:
            insn, pc, lr, sp, mod, in_bitmap, n_calls, cur_iter = smp
            print(f"  sample insn#{insn} PC={hex(pc) if pc else pc} LR={hex(lr) if lr else lr} "
                  f"SP={hex(sp) if sp else sp} module={mod} in_bitmap={in_bitmap} "
                  f"bitmap_calls={n_calls} cur_iter={cur_iter}", flush=True)
