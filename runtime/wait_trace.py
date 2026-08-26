"""v225: per-call, ID-correlated tracer for the control flow between
`WaitForAnyRequest`'s return and the `GetEvent`-dispatch call inside
`fcn.00444750` (the pump loop) -- direct response to a user instruction
that explicitly rejects `wait_entered=241 / getevent_called=239` as a
sufficient root cause on its own, and demands the EXACT branch, with real
CPSR flags and register/memory values, that explains why `GetEvent` stops
being reached.

Ground truth this module is built on (v225 r2 disassembly of
fcn.00444750, this session -- full function, single caller
`fcn.00421cf0 @ 0x421d20`):

    0x444750  push {r4,lr}; sub sp,sp,0xc; mov r4,r0        ; r4 = this
    0x44475c  ldr r3,[r4,0x54]          ; EventReady TRequestStatus.iStatus
    0x444760  cmp r3,0
    0x444764  bne 0x44482c              ; ENTRY GATE: still PENDING -> EXIT
                                          ; immediately, without even
                                          ; entering the loop body once.
  0x444768: <- LOOP TOP
    0x444768  ldr r3,[r4,0x54]
    0x44476c  cmp r3,0
    0x444770  beq 0x444798              ; status==0 (COMPLETED) -> 0x444798
    0x444774  ldr r3,[r4,0x84]          ; own-flag check
    0x444778  cmp r3,0
    0x44477c  beq 0x44482c              ; [this+0x84]==0 -> EXIT
    0x444780  bl WaitForAnyRequest      ; WFAR CALL SITE A
    0x444784  ldr r3,[r4,0x80]          ; pump's OWN status (RequestComplete target)
    0x444788  cmp r3,0x80000001
    0x44478c  movne r3,0
    0x444790  strne r3,[r4,0x84]
    0x444794  b 0x44482c                ; ALWAYS exits after call-site-A's wait
  0x444798:
    0x444798  ldr r3,[r4,0x74]
    0x44479c  cmp r3,0
    0x4447a0  bne 0x4447dc              ; [this+0x74]!=0 -> skip straight to WFAR call site B
    0x4447a4  ldr ip,[r4,0x84]
    0x4447a8  cmp ip,0
    0x4447ac  bne 0x4447dc              ; [this+0x84]!=0 -> also skip to call site B
    0x4447b0-0x4447d8  (self-managed RequestComplete on [this+0x80], sets [this+0x84]=1)
  0x4447dc:
    0x4447dc  bl WaitForAnyRequest      ; WFAR CALL SITE B (the "main" path)
    0x4447e0  mov r0,r4
    0x4447e4  bl fcn.00444838           ; GETEVENT-DISPATCH CALL
    0x4447e8  tst r0,0xff
    0x4447ec  bne 0x444768              ; dispatch returned nonzero -> LOOP again
    0x4447f0-0x4447f8  bl RunIfReady (EUSER:0x3c3, UNIMPLEMENTED -- always returns 0 here)
    0x4447fc  cmp r0,0
    0x444800  bne 0x444768
    0x444804  ldr r3,[r4,0x84]; cmp r3,0;    beq 0x444768
    0x444810  ldr r3,[r4,0x80]; cmp r3,0x80000001; beq 0x444768
    0x44481c  str r0,[r4,0x84]
    0x444820  ldr r3,[r4,0x74]; cmp r3,0;    bne 0x444768
  0x44482c: <- EXIT (pop {r4,lr}; bx lr, back to fcn.00421cf0)

Only ONE call to WaitForAnyRequest's real thunk handler happens per
fcn.00444750 invocation (either site A -- which ALWAYS exits right after,
never reaching GetEvent-dispatch in the SAME call -- or site B, which is
the ONLY call site that can reach the GetEvent-dispatch call at 0x4447e4).
This module hooks BOTH the handler-level wrap (entry/return, wired from
runtime/async_model.py's `_handle_wait_for_any_request`) and a bounded
per-instruction post-return capture window (wired from run.py's
`_hook_code_body`) to record the REAL branch outcomes with real CPSR/
register/memory evidence, not just "GetEvent wasn't called".

fcn.00444838 (the callee at 0x4447e4) is a genuine 3-slot active-object
scanner (matches the user's real-Symbian CActiveScheduler description):
  Slot 1: [this+0xc] -> double-indirection to an object's [obj+8]
          (IsActive-like) / [obj+4] (iStatus-like, vs 0x80000001);
          on success calls RunL via VTABLE (ldr r2,[r0]; ldr ip,[r2,0x10]; bx ip).
  Slot 2: [this+0x4c] (flag) / [this+0x50] (status, vs 0x80000001) --
          DIRECT field reads on `this` itself, NO double-indirection; on
          success calls fcn.00444acc DIRECTLY (bl, not vtable). This is
          the EventReady-equivalent path -- and note `this` here is the
          SAME pointer fcn.00444750 passes as r0 (mov r0,r4 @ 0x4447e0),
          i.e. there is no separate CActive sub-object for this slot; the
          pump object itself doubles as the "active object".
  Slot 3: [this+8] -> same double-indirection pattern as slot 1, vtable RunL.

Purely observational: no branch is patched, no PC is forced, no function
is skipped, GetEvent is never force-called, and the event queue is never
drained by this module.
"""

import struct

FCN_PUMP_ENTRY = 0x444750
ENTRY_GATE_CMP = 0x444760        # cmp r3,0 (r3 == status_0x54, right after ldr)
ENTRY_GATE_BRANCH = 0x444764     # bne 0x44482c (still PENDING -> exit before loop)
LOOP_TOP = 0x444768
LOOP_STATUS_BRANCH = 0x444770    # beq 0x444798
OWNFLAG_BRANCH_1 = 0x44477c      # beq 0x44482c
WFAR_CALL_SITE_A = 0x444780
OWNSTATUS_CMP_A = 0x444788
EXIT_AFTER_A = 0x444794          # unconditional b 0x44482c
FLAG074_BRANCH = 0x4447a0        # bne 0x4447dc
OWNFLAG_BRANCH_2 = 0x4447ac      # bne 0x4447dc
SELFCOMPLETE_CALL = 0x4447d0     # bl RequestComplete (self-managed [this+0x80])
WFAR_CALL_SITE_B = 0x4447dc
GETEVENT_DISPATCH_CALL = 0x4447e4   # bl fcn.00444838
GETEVENT_DISPATCH_TST = 0x4447e8    # tst r0,0xff
GETEVENT_DISPATCH_BRANCH = 0x4447ec  # bne 0x444768 (dispatch found something -> loop again)
RUNIFREADY_CALL = 0x4447f8
RUNIFREADY_BRANCH = 0x444800     # bne 0x444768
FLAG084_BRANCH_FINAL = 0x44480c  # beq 0x444768
OWNSTATUS_BRANCH_FINAL = 0x444818  # beq 0x444768
FLAG074_BRANCH_FINAL = 0x444828  # bne 0x444768
EXIT_PC = 0x44482c

WFAR_THUNK_VA = 0x4960B4
GETEVENT_DISPATCH_FCN = 0x444838   # the callee at 0x4447e4
GETEVENT_THUNK_VA = 0x496614       # the REAL WS32 GetEvent thunk (called from inside 0x444838)

POST_WAIT_CAPTURE_LIMIT = 50   # "dönüşten sonraki ilk 20-50 ARM komutu"

CPSR_N, CPSR_Z, CPSR_C, CPSR_V = (1 << 31), (1 << 30), (1 << 29), (1 << 28)


def decode_cpsr(v):
    if v is None:
        return None
    return {"N": bool(v & CPSR_N), "Z": bool(v & CPSR_Z), "C": bool(v & CPSR_C), "V": bool(v & CPSR_V)}


class WaitTracer:
    """Wired via ctx.wait_tracer. `on_wait_enter`/`on_wait_return` are
    called directly from async_model.py's `_handle_wait_for_any_request`
    (mirrors how wrap_get_event wraps the GetEvent handler). `on_pc` is
    called from run.py's `_hook_code_body` for EVERY instruction -- it
    only does work while a post-wait capture window is open (plus the
    always-on pump-entry counters below), so the steady-state cost is a
    single None-check."""

    def __init__(self, uc, ctx, registry):
        self.uc = uc
        self.ctx = ctx
        self.registry = registry
        self.next_wait_id = 1
        self.waits = []            # completed + in-flight wait records, in order
        self.current = None        # in-flight record (post-return capture window open)
        self._genuine_before = 0

        # madde: EventReady tek-seferlik yaşam döngüsü doğrulaması --
        # independent of registry.stats["duplicate_completion"] (which
        # already guards this at the state-machine level); this is a
        # SEPARATE, tracer-owned check using only what the hook interface
        # hands us, so a real double-signal would show up here even if
        # there were ever a bug in the registry's own guard.
        self._completed_request_ids_seen = set()
        self.duplicate_completion_detected = []  # list of req_ids seen completed >1x

        # madde: "GetEvent çağrılmadığı halde yeni EventReady kayıtları
        # oluşuyorsa bunların çağrı yerlerini çıkar" -- every registration,
        # with its real ARM call-site (LR), in order.
        self.registration_log = []   # [{insn, req_id, kind, lr}]

        # v225 follow-up (found live, this run): wait_entered froze at a
        # hard count with ZERO further WaitForAnyRequest calls for the
        # rest of a 20M-instruction run -- meaning fcn.00444750 itself
        # either stopped being invoked by its single caller
        # (fcn.00421cf0 @ 0x421d20), or is still being invoked but ALWAYS
        # takes the entry-gate immediate-exit path (0x444764, status_0x54
        # still PENDING) without ever reaching the loop body again. These
        # two ALWAYS-ON (not gated by any wait window) counters distinguish
        # the two: pump_entry_count increments on EVERY call to
        # fcn.00444750 (hooked at the entry-gate cmp, 0x444760, where r3
        # already holds status_0x54); pump_loop_body_entered_count
        # increments only when LOOP_TOP (0x444768) is reached, i.e. the
        # entry gate did NOT exit. NOTE: LOOP_TOP can be revisited MULTIPLE
        # times within a single fcn.00444750 invocation (dispatch found
        # something -> 0x4447ec loops back) -- so pump_entry_count and
        # pump_loop_body_entered_count do NOT measure the same unit; do not
        # naively subtract one from the other (see print_summary note).
        self.pump_entry_count = 0
        self.pump_loop_body_entered_count = 0
        self.pump_entry_log = []  # ring buffer, last N: (insn, status_0x54, scan fields)
        self._PUMP_ENTRY_LOG_MAX = 30

    # -- registration (called from async_model.py's ws32 notify handler) --
    def on_registration(self, req_id, kind, lr):
        self.registration_log.append({
            "insn": self.ctx.insn_count[0], "req_id": req_id, "kind": kind,
            "lr": lr, "getevent_called_so_far": self.registry.stats["getevent_called"],
        })

    # -- lifecycle_hook interface (shared with LifecycleTracer via a
    # MultiHook combinator in run.py) --------------------------------------
    def on_event_enqueued(self, event_id, ev_type, ev_scancode):
        pass  # not needed by this tracer; present only to satisfy the shared interface

    def on_eventready_completed(self, req_id, event_id):
        if req_id in self._completed_request_ids_seen:
            self.duplicate_completion_detected.append(req_id)
        else:
            self._completed_request_ids_seen.add(req_id)

    def on_wait_woken(self, req_id, event_id):
        if self.current is not None and self.current.get("wake_req_id") is None:
            self.current["wake_req_id"] = req_id
            self.current["wake_event_id"] = event_id

    def on_event_consumed(self, event_id, ev_type, ev_scancode, claimed_by):
        pass

    # -- regs/mem helpers -----------------------------------------------
    def _regs(self):
        from unicorn.arm_const import (UC_ARM_REG_PC, UC_ARM_REG_LR, UC_ARM_REG_SP,
                                        UC_ARM_REG_R0, UC_ARM_REG_R3, UC_ARM_REG_R4,
                                        UC_ARM_REG_R12, UC_ARM_REG_CPSR)
        out = {}
        for name, reg in (("pc", UC_ARM_REG_PC), ("lr", UC_ARM_REG_LR), ("sp", UC_ARM_REG_SP),
                          ("r0", UC_ARM_REG_R0), ("r3", UC_ARM_REG_R3), ("r4", UC_ARM_REG_R4),
                          ("ip", UC_ARM_REG_R12)):
            try:
                out[name] = self.uc.reg_read(reg)
            except Exception:
                out[name] = None
        try:
            out["cpsr"] = self.uc.reg_read(UC_ARM_REG_CPSR)
        except Exception:
            out["cpsr"] = None
        return out

    def _read_u32(self, addr):
        if not addr:
            return None
        try:
            return struct.unpack("<I", self.uc.mem_read(addr, 4))[0]
        except Exception:
            return None

    def _tracked_status_addr(self):
        """The single, fixed TRequestStatus address EventReady/
        PriorityKeyReady registrations reuse (confirmed in v223/v224:
        every request's status_addr == the same 0x2000fdb4-style address).
        Prefer a currently-PENDING or COMPLETED-not-yet-consumed request's
        address; fall back to any request in the registry."""
        for req in self.registry._requests.values():
            return req["status_addr"]
        return None

    # -- entry (called from async_model.py, BEFORE registry.wait_for_any_request()) --
    def on_wait_enter(self):
        regs = self._regs()
        wait_id = self.next_wait_id
        self.next_wait_id += 1
        r4 = regs["r4"]
        status_addr = self._tracked_status_addr()
        rec = {
            "wait_id": wait_id,
            "enter_insn": self.ctx.insn_count[0],
            "call_site_lr": regs["lr"],
            "sp": regs["sp"],
            "this_ptr": r4,
            "status_0x54": self._read_u32(r4 + 0x54) if r4 else None,
            "status_0x80": self._read_u32(r4 + 0x80) if r4 else None,
            "flag_0x84": self._read_u32(r4 + 0x84) if r4 else None,
            "flag_0x74": self._read_u32(r4 + 0x74) if r4 else None,
            # v225 follow-up (user's Active-Scheduler mesajı, madde: "EventReady
            # completion sirasinda yazilan status adresiyle scheduler'in
            # okudugu iStatus adresini birebir karsilastir"): fcn.00444838's
            # Slot 2 (the EventReady-equivalent scan slot) directly reads
            # [this+0x4c] (its own IsActive-like flag) and [this+0x50]
            # (compared against KRequestPending) on the SAME "this" pointer
            # fcn.00444750 passes it (r0=r4 at the 0x4447e0 call site) --
            # captured here, every wait entry, to compare against this+0x54
            # (the address EventReady completion itself writes to, confirmed
            # == tracked_status_addr via address arithmetic).
            "scan_flag_0x4c": self._read_u32(r4 + 0x4c) if r4 else None,
            "scan_status_0x50": self._read_u32(r4 + 0x50) if r4 else None,
            "tracked_status_addr": status_addr,
            "tracked_status_value_at_entry": self._read_u32(status_addr) if status_addr else None,
            "pending_request_ids_at_entry": list(self.registry._pending_order),
            "event_queue_len_at_entry": (len(self.ctx.event_queue._q)
                                          if getattr(self.ctx, "event_queue", None) is not None else None),
            "event_fifo_len_at_entry": len(self.registry._event_fifo),
            "signal_count_at_entry": self.registry.signal_count,
            "eventready_registered_at_entry": self.registry.stats["eventready_registered"],
            "getevent_called_at_entry": self.registry.stats["getevent_called"],
            "wake_req_id": None, "wake_event_id": None, "genuine_wake": None,
            "return_pc": None,
            "post_trace": [],
            "reached_getevent_dispatch_call": False,
            "reached_real_getevent_thunk": False,
            "getevent_dispatch_result_r0": None,
            "reentered_wait_within_window": False,
            "exited_function_within_window": False,
            "window_truncated": False,
        }
        self.waits.append(rec)
        self.current = rec
        self._genuine_before = self.registry.stats["wfar_genuine_returns"]
        return wait_id

    # -- return (called right after registry.wait_for_any_request() returns) --
    def on_wait_return(self):
        if self.current is None:
            return
        rec = self.current
        genuine_after = self.registry.stats["wfar_genuine_returns"]
        rec["genuine_wake"] = genuine_after > self._genuine_before
        regs = self._regs()
        rec["return_pc"] = regs["pc"]
        rec["eventready_registered_at_return"] = self.registry.stats["eventready_registered"]
        rec["getevent_called_at_return"] = self.registry.stats["getevent_called"]
        self._capture_count = 0

    # -- per-instruction post-return capture window (called from run.py) --
    def on_pc(self, address):
        # ALWAYS-ON (independent of any wait window): is fcn.00444750
        # still being invoked at all, and does it still reach its own
        # loop body (as opposed to exiting immediately at the entry gate)?
        if address == ENTRY_GATE_CMP:
            regs = self._regs()
            r4 = regs["r4"]
            self.pump_entry_count += 1
            self.pump_entry_log.append({
                "insn": self.ctx.insn_count[0], "status_0x54": regs["r3"],
                "scan_flag_0x4c": self._read_u32(r4 + 0x4c) if r4 else None,
                "scan_status_0x50": self._read_u32(r4 + 0x50) if r4 else None,
                "flag_0x84": self._read_u32(r4 + 0x84) if r4 else None,
            })
            if len(self.pump_entry_log) > self._PUMP_ENTRY_LOG_MAX:
                self.pump_entry_log.pop(0)
        elif address == LOOP_TOP:
            self.pump_loop_body_entered_count += 1

        if self.current is None or self.current["return_pc"] is None:
            return
        rec = self.current
        if address == WFAR_THUNK_VA and self._capture_count > 0:
            # a NEW wait started (on_wait_enter will fire separately for
            # it, via async_model.py's handler wrap) -- close this window.
            rec["reentered_wait_within_window"] = True
            self.current = None
            return
        if self._capture_count >= POST_WAIT_CAPTURE_LIMIT:
            rec["window_truncated"] = True
            self.current = None
            return
        regs = self._regs()
        rec["post_trace"].append({
            "insn": self.ctx.insn_count[0], "pc": address, "cpsr": decode_cpsr(regs["cpsr"]),
            "r0": regs["r0"], "r3": regs["r3"], "ip": regs["ip"],
        })
        self._capture_count += 1
        if address in (GETEVENT_DISPATCH_CALL,):
            rec["reached_getevent_dispatch_call"] = True
        if address == GETEVENT_THUNK_VA:
            rec["reached_real_getevent_thunk"] = True
        if address == GETEVENT_DISPATCH_TST:
            rec["getevent_dispatch_result_r0"] = regs["r0"]
        if address == EXIT_PC:
            rec["exited_function_within_window"] = True
            self.current = None

    # -- report -----------------------------------------------------------
    def summary(self):
        return {
            "total_waits": len(self.waits),
            "duplicate_completion_detected": list(self.duplicate_completion_detected),
            "registration_log_tail": self.registration_log[-20:],
            "registration_log_total": len(self.registration_log),
            "waits_tail": self.waits[-10:],
            "pump_entry_count": self.pump_entry_count,
            "pump_loop_body_entered_count": self.pump_loop_body_entered_count,
            "pump_entry_log_tail": list(self.pump_entry_log),
        }

    def print_summary(self):
        s = self.summary()
        print(f"\n--- v225 WaitTracer summary ---", flush=True)
        print(f"total_waits: {s['total_waits']}", flush=True)
        print(f"pump_entry_count (fcn.00444750 invocations, ALWAYS-ON): {s['pump_entry_count']}  "
              f"pump_loop_body_entered_count (LOOP_TOP reached, can exceed pump_entry_count -- "
              f"see class docstring): {s['pump_loop_body_entered_count']}", flush=True)
        print(f"pump_entry_log_tail (last {len(s['pump_entry_log_tail'])} calls, insn+status_0x54+scan fields at entry): "
              f"{s['pump_entry_log_tail']}", flush=True)
        print(f"duplicate_completion_detected (tracer-independent check): {s['duplicate_completion_detected']}", flush=True)
        print(f"registration_log_total: {s['registration_log_total']}", flush=True)
        for r in s["registration_log_tail"]:
            print(f"  registration: {r}", flush=True)
        for w in s["waits_tail"]:
            print(f"  wait_id={w['wait_id']} enter_insn={w['enter_insn']} call_site_lr={hex(w['call_site_lr']) if w['call_site_lr'] else w['call_site_lr']} "
                  f"status_0x54={w['status_0x54']} scan_flag_0x4c={w.get('scan_flag_0x4c')} scan_status_0x50={w.get('scan_status_0x50')} "
                  f"flag_0x84={w.get('flag_0x84')} genuine_wake={w['genuine_wake']} wake_req_id={w['wake_req_id']} "
                  f"reached_getevent_dispatch_call={w['reached_getevent_dispatch_call']} "
                  f"reached_real_getevent_thunk={w['reached_real_getevent_thunk']} "
                  f"reentered_wait_within_window={w['reentered_wait_within_window']} "
                  f"exited_function_within_window={w['exited_function_within_window']}", flush=True)

    def find_waits_for_event_ids(self, event_ids):
        """Return the full records (including post_trace) for every wait
        that woke on one of the given event_ids -- used to pull the exact
        evidence chain for a specific tracked key (e.g. the three
        down/key/up event_ids of FAZ 1's first "5")."""
        wanted = set(event_ids)
        return [w for w in self.waits if w.get("wake_event_id") in wanted]

    def dump_wait_full(self, wait_id):
        """Full detail (including the complete post_trace) for one wait_id
        -- used by the stall dump / final report generation, not printed
        by default (too verbose for routine summaries)."""
        for w in self.waits:
            if w["wait_id"] == wait_id:
                return w
        return None
