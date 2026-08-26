"""v221/v222 EXPERIMENTAL cooperative request/completion model for
User::WaitForAnyRequest() / TRequestStatus, gated behind the
--async-request-model CLI flag. NOT a default-enabled patch, and NOT
marked as a final solution -- see NGage_Sims_Bustin_Out_Android_Port_
Bulgular_v221.md and _v222.md for the full design writeups, ground-truth
evidence (real euser.dll disassembly + EKA2L1 source cross-check), and the
test matrices this was validated against.

Ground truth this module implements (v221 findings):
  - EUSER:0x4b9 User::WaitForAnyRequest() (thunk 0x4960b4): real firmware
    is a 2-instruction veneer (B -> bare SVC #0x4D); EKA2L1's HLE
    (src/emu/kernel/src/thread.cpp) implements it as
    `request_sema->wait(0)` -- block on a per-thread COUNTING semaphore.
    No return value.
  - EUSER:0x39f RThread::RequestComplete(TRequestStatus*&, TInt) const
    (thunk 0x4960c4): EKA2L1's notify_info::complete()/session.cpp both
    show the same shape -- write the reason into the real TRequestStatus,
    null the caller's local TRequestStatus* variable, then
    `requester->signal_request()` (bumps the SAME per-thread semaphore,
    unconditionally, regardless of which status just completed).
  - epoc::request_status::pending_status == 0x80000001 (EKA2L1
    src/emu/utils/include/utils/reqsts.h) -- exact match to the game's
    own magic-value checks (v219/v220) and to Symbian's real KRequestPending.
  - CORRECTED this session vs. an earlier draft: the real ordinal names
    (resolved_symbols_euser_ws32.json, from the actual ws32.idb) are
    WS32:0xa7 (thunk 0x4966a4) = RWsSession::PriorityKeyReady(TRequestStatus*)
    and WS32:0x69 (thunk 0x496604) = RWsSession::EventReady(TRequestStatus*)
    -- BOTH take a real TRequestStatus* directly, so both are genuine
    async request-registration calls. WS32:0x80 (thunk 0x4966c4) is
    RWsSession::GetPriorityKey(TWsPriorityKeyEvent&) -- a synchronous
    GETTER of a *different* struct type, NOT a TRequestStatus registration.
    Real Symbian TRequestStatus layout is `{TInt iFlags; TInt iStatus;}`
    (iFlags public at +0, iStatus at +4) -- matches the existing
    ws32_magic_check probe's independent finding (hooked at 0x444854,
    reads [r2+4]) exactly: for both PriorityKeyReady and EventReady, R1 IS
    the TRequestStatus* itself, and the pending/complete int lives at R1+4
    (iStatus), not R1+0.

Deliberately OUT of scope for this prototype (per the user's own task
spec, item 13): EUSER:0x3c3 CActiveScheduler::RunIfReady() is left
UNIMPLEMENTED (falls through to default_stub, returns "nothing ready").
Reasoning: RunIfReady would require reimplementing the real Active Object
linked list, which no disassembly/EKA2L1 work has covered. The pump loop
(fcn.00444750) calls its own inner dispatcher (0x444838, gated by the
pre-existing event_poll_gate/event_alt_escape patches) BEFORE ever
reaching RunIfReady, so the real GetEvent-driven chain does not depend on
RunIfReady succeeding -- only on WaitForAnyRequest/RequestComplete being
modeled correctly. This is an explicit, disclosed scope decision, not an
oversight.

v222 UPDATE (first attempt, SUPERSEDED by v222-b below) -- root cause of
the v221 "0-iteration early exit" finding, evidence-backed via a
whole-binary radare2 xref scan (`axt @ 0x4960c4`, RequestComplete's thunk
VA): EXACTLY ONE call site to RequestComplete exists in the ENTIRE game
executable -- inside fcn.00444750 itself (0x4447d0), targeting its OWN
internal [this+0x80] status. NOTHING in this binary ever completes the
TRequestStatus registered via EventReady/PriorityKeyReady ([this+0x50]/
[this+0x54]) -- this is not a missing-code bug in the game, it is a
genuine Symbian client->server async request whose real completer (the
window server's own code) is not present in this client binary. The first
attempt at a fix wired opportunistic completion into wrap_get_event(),
completing a pending EventReady request whenever GetEvent delivered a
real event.

v222-b UPDATE -- the v222 (first attempt) fix above was ITSELF WRONG,
caught before being reported as working (per the project's standing
"root cause first, no patch until evidence-backed" rule) via a combination
of static and dynamic verification:
  - STATIC: a fresh, complete r2 disassembly of fcn.00444750 (the pump
    loop) shows its ENTRY GATE (0x44475c ldr r3,[r4,0x54]; 0x444760 cmp
    r3,0; 0x444764 bne 0x44482c) is the ONLY branch controlling entry to
    the rest of the function -- and "the rest of the function" includes
    BOTH WaitForAnyRequest call sites (0x444780, 0x4447dc) AND the
    dispatch call that reaches GetEvent (0x4447e4 bl fcn.00444838). Once
    EventReady sets [this+0x54] = KRequestPending (0x80000001, non-zero),
    EVERY subsequent call to fcn.00444750 exits at 0x444764 without ever
    reaching WaitForAnyRequest or the GetEvent-dispatch call again.
  - DYNAMIC: V222_GETEVENT_DIAG instrumentation (a call counter placed in
    wrap_get_event, independent of the completion logic it was validating)
    confirmed GetEvent's thunk (0x496614) was invoked ZERO times across an
    8,000,000-instruction run with a pending EventReady request -- matching
    the static finding exactly, not just plausible from it.
  - CONCLUSION: "complete EventReady when GetEvent delivers a real event"
    is circular and can never bootstrap -- GetEvent is only reachable
    through the same gate that EventReady's own pending flag blocks, so
    nothing could ever produce the completion the wrapper was waiting to
    react to. This is exactly the failure mode predicted before re-testing
    (do not force a model to fit evidence that contradicts it -- re-derive
    the root cause instead).
  - THE FIX: a whole-binary xref scan of WaitForAnyRequest's thunk
    (0x4960b4) found FOUR call sites, not two -- fcn.00444750 (0x444780,
    0x4447dc, both gated as above) AND a SECOND, independent function,
    fcn.004448f0 (0x444914, 0x444948), which gates on [this+0x74]/
    [this+0x84] -- NOT [this+0x54] -- and is therefore NOT blocked by
    EventReady's pending state. This proves the real architecture does not
    require fcn.00444750 to ever re-enter its loop body for progress to be
    possible in principle. More importantly: completion does not need to
    depend on ANY game code running at all. The correct trigger is at the
    EVENT QUEUE level: EventReady(status) registers a pending request; the
    moment a REAL (non-EEVENT_NULL) event is produced -- by our test
    harness's own scripted refill, entirely independent of whether the
    game ever calls GetEvent or WaitForAnyRequest again -- that is when a
    real window server would resolve the outstanding EventReady request.
    Completing it means writing KErrNone into the SAME address
    (this+0x54) the pump loop's entry gate checks -- so the harness's own
    event production is what re-opens fcn.00444750's entry gate for its
    NEXT invocation (from its own outer caller, fcn.00421cf0), without any
    dependency on GetEvent having run first. GetEvent, once reached, then
    consumes that same event normally through the EXISTING, unmodified
    handle_get_event() in runtime/input.py -- wrap_get_event() here is now
    ONLY a consumption/verification tap (registry.on_event_consumed), not
    a completion trigger. See runtime/input.py's EventQueue.on_enqueue for
    the actual hook point, and RequestRegistry.on_event_enqueued/
    register_request/_try_match/_complete below for the completion logic.
  - Full request/event lifecycle now modeled explicitly with a state
    machine (IDLE is implicit/pre-registration) and its own request/event
    IDs, matching the task spec's required transitions:
      request #N registered -> request #N pending
      event #M enqueued
      request #N completed: KErrNone   (paired with backing event #M)
      WaitForAnyRequest woke on request #N
      GetEvent consumed event #M
      request #N consumed
    Registration-time and enqueue-time are BOTH completion triggers (case
    A: event arrives while a request is already pending; case B: request
    registers while an unclaimed event is already queued) -- see
    _try_match(). Gated behind V222_STATE_LOG for full per-transition
    logging (silent by default to avoid flooding long runs); summary
    counters (see RequestRegistry.stats) are always collected and always
    printed by run.py regardless of the log flag.
  - Deliberately NOT done, per the task spec: no forced function calls, no
    slot/state pre-filling, no visibility patches, and the old blind
    100-iteration escape patches (tick_escape/event_alt_escape/
    event_poll_gate in patches.py) are NOT used by or folded into this
    model -- they remain available only as a separate, disabled-by-default
    control group for comparison (--disable-patch to turn them off when
    testing this model, so the model's own effect is isolated).
"""

import os
import struct
from collections import deque

KREQUEST_PENDING = 0x80000001
KERRNONE = 0

# WS32 ordinals this model treats as genuine TRequestStatus* async
# notification registrations, confirmed via resolved_symbols_euser_ws32.json
# (the real ws32.idb names). WS32:0x80 (GetPriorityKey, a TWsPriorityKeyEvent&
# getter, NOT a TRequestStatus registration) is deliberately NOT in this
# table -- see the module docstring's "CORRECTED this session" note.
# Keyed by thunk VA -> a short kind label used only for metrics/labeling.
WS32_NOTIFY_THUNKS = {
    0x4966A4: "priority_key",    # WS32:0xa7 RWsSession::PriorityKeyReady(TRequestStatus*)
    0x496604: "event_ready",     # WS32:0x69 RWsSession::EventReady(TRequestStatus*)
}

EUSER_WAIT_FOR_ANY_REQUEST_VA = 0x4960B4  # EUSER:0x4b9
EUSER_REQUEST_COMPLETE_VA = 0x4960C4      # EUSER:0x39f

# The translated "real key" event type (matches runtime/input.py's
# EEVENT_KEY = 1). Duplicated here as a literal (not imported) to avoid a
# runtime<->runtime circular import; input.py's module docstring is the
# authority on TWsEvent/TEventCode semantics.
_EEVENT_KEY = 1


def _state_log_enabled():
    return bool(os.environ.get("V222_STATE_LOG"))


class RequestRegistry:
    """v222-b: explicit request/event lifecycle state machine.

    Requests (one per EventReady/PriorityKeyReady registration) move
    PENDING -> COMPLETED -> CONSUMED (then removed). Events (one per real,
    non-EEVENT_NULL item appended to the harness's event queue) move
    QUEUED (implicit -- just present in _event_fifo unclaimed) -> CLAIMED
    (claimed_by set to a request id, once matched) -> removed (once
    GetEvent actually consumes it). Completion is triggered from exactly
    two places, both funneling through _try_match(): register_request()
    (case B: event already queued when the request registers) and
    on_event_enqueued() (case A: request already pending when an event
    arrives). WaitForAnyRequest is driven purely by signal_count, which is
    ONLY ever incremented by an actual completion (_complete(), or the
    unrelated self-managed on_request_complete() path for the pump loop's
    own internal [this+0x80] status) -- never by a heuristic/opportunistic
    peek. This directly implements the task spec's required lifecycle."""

    def __init__(self):
        self.signal_count = 0
        self._ctx = None  # set by install(); used only for insn# in logs

        self._requests = {}            # request_id -> record
        self._pending_order = deque()  # request_ids awaiting a match, FIFO
        self._event_fifo = deque()     # {'id','ev_type','ev_scancode','claimed_by'}
        self._completion_wake_log = deque()  # request ids completed, not yet attributed to a wake
        self._next_request_id = 1
        self._next_event_id = 1

        # v223: optional external observer, called as on_event_consumed_hook
        # (event_id, ev_type, ev_scancode, claimed_by_request_id_or_None)
        # every time on_event_consumed() actually pops+processes a REAL
        # event -- lets a caller (e.g. runtime/sync_injector.py's
        # key-by-key sequencer) know precisely WHEN a specific event id it
        # produced has been delivered to the game via GetEvent, and which
        # request (if any) it closed out, without polling or guessing from
        # aggregate counters. None by default (no observer).
        self.on_event_consumed_hook = None

        # v224: a SECOND, ADDITIVE observer slot, separate from
        # on_event_consumed_hook above (which runtime/sync_injector.py's
        # SyncKeyInjector already occupies for its own down/key/up
        # consumption bookkeeping -- this does NOT replace or interfere
        # with that). If set, must expose four methods:
        #   on_event_enqueued(event_id, ev_type, ev_scancode)
        #   on_eventready_completed(req_id, event_id)
        #   on_wait_woken(req_id, event_id_or_None)
        #   on_event_consumed(event_id, ev_type, ev_scancode, claimed_by)
        # Used by runtime/lifecycle_trace.py's LifecycleTracer to log each
        # of these stages independently, for a single tracked scancode,
        # without touching or depending on SyncKeyInjector's own state.
        self.lifecycle_hook = None

        # Legacy view kept for report-writing convenience / back-compat:
        # status_addr -> kind, mirrors requests in PENDING or COMPLETED
        # (i.e. "still outstanding from the game's point of view" -- CONSUMED
        # ones are fully closed out and removed from both this and _requests).
        self.pending = {}

        self.stats = {
            # -- v222-b lifecycle counters (task-spec required set) -------
            "real_key_generated": 0,       # a translated EEVENT_KEY was enqueued
            "event_enqueued": 0,           # any non-null event appended to the queue
            "eventready_registered": 0,    # EventReady/PriorityKeyReady registrations
            "duplicate_registration_ignored": 0,  # same live TRequestStatus registered again
            "eventready_completed": 0,     # requests that reached COMPLETED
            "wait_entered": 0,             # WaitForAnyRequest call count
            "wait_woken": 0,               # of those, returned via a genuine signal
            "getevent_called": 0,          # GetEvent thunk call count
            "event_consumed": 0,           # real events popped via GetEvent
            "duplicate_completion": 0,     # attempted to complete an already-completed/consumed request
            "orphan_completion": 0,        # completed a request with no backing event (should stay 0 by construction)
            "getevent_without_completion": 0,  # GetEvent consumed a real event that never backed any completion
            "cancellations": 0,
            "max_pending": 0,

            # -- retained from v221 for report/back-compat -----------------
            "registrations": {},              # kind -> count
            "ws32_genuine_completions": {},   # kind -> count (unused by the new path; kept at 0/empty)
            "request_complete_calls": 0,      # EUSER:0x39f thunk hits (self-managed [this+0x80] path only)
            "request_complete_tracked": 0,
            "request_complete_untracked": 0,
            "wfar_calls": 0,
            "wfar_genuine_returns": 0,
            "wfar_wasted_returns": 0,
            "get_event_triggered_completions": 0,  # v222 (first attempt) mechanism -- superseded, stays 0
        }

    # -- logging ----------------------------------------------------------
    def _log(self, msg):
        if not _state_log_enabled():
            return
        insn = self._ctx.insn_count[0] if self._ctx is not None else "?"
        print(f"[V222-STATE] insn#{insn} {msg}", flush=True)

    # -- registration (WS32:0xa7 / WS32:0x69) ------------------------------
    def register_request(self, uc, status_addr, kind):
        # v230: TRequestStatus is the identity of an asynchronous request.
        # A client cannot have several simultaneous EventReady requests
        # backed by the same status object.  The older harness created a
        # fresh record on every repeated thunk call even while the prior
        # request was still PENDING/COMPLETED.  During blind NAV production
        # this let future queue entries be pre-claimed by hundreds of
        # impossible duplicate requests, so a later registration could not
        # observe that the server queue was already non-empty.  Preserve the
        # one outstanding request and, crucially, do not overwrite an
        # already-completed KErrNone status with KRequestPending again.
        existing = next((r for r in self._requests.values()
                         if r["status_addr"] == status_addr
                         and r["state"] in ("PENDING", "COMPLETED")), None)
        if existing is not None:
            self.stats["duplicate_registration_ignored"] += 1
            self._log(f"duplicate registration ignored for live request #{existing['id']} "
                      f"({existing['state']}, status_addr={hex(status_addr)})")
            return existing["id"]
        req_id = self._next_request_id
        self._next_request_id += 1
        uc.mem_write(status_addr, struct.pack("<I", KREQUEST_PENDING))
        req = {"id": req_id, "status_addr": status_addr, "kind": kind, "state": "PENDING", "claimed_event": None}
        self._requests[req_id] = req
        self._pending_order.append(req_id)
        self.stats["eventready_registered"] += 1
        self.stats["registrations"][kind] = self.stats["registrations"].get(kind, 0) + 1
        self.pending[status_addr] = kind
        if len(self.pending) > self.stats["max_pending"]:
            self.stats["max_pending"] = len(self.pending)
        self._log(f"request #{req_id} registered ({kind}, status_addr={hex(status_addr)})")
        self._log(f"request #{req_id} pending")
        # Case B: an unclaimed real event may already be sitting in the
        # queue from before this request even registered.
        self._try_match(uc)
        return req_id

    # -- event production (runtime/input.py EventQueue.on_enqueue) --------
    def on_event_enqueued(self, uc, ev_type, ev_scancode):
        self.stats["event_enqueued"] += 1
        if ev_type == _EEVENT_KEY:
            self.stats["real_key_generated"] += 1
        if ev_type == 0:  # EEVENT_NULL -- harness idle filler, not a real WS32 event
            return
        ev_id = self._next_event_id
        self._next_event_id += 1
        self._event_fifo.append({"id": ev_id, "ev_type": ev_type, "ev_scancode": ev_scancode, "claimed_by": None})
        self._log(f"event #{ev_id} enqueued (ev_type={ev_type} scancode={hex(ev_scancode)})")
        if self.lifecycle_hook is not None:
            self.lifecycle_hook.on_event_enqueued(ev_id, ev_type, ev_scancode)
        # Case A: a request may already be pending, waiting for exactly this.
        self._try_match(uc)

    def _try_match(self, uc):
        while self._pending_order:
            unclaimed = next((e for e in self._event_fifo if e["claimed_by"] is None), None)
            if unclaimed is None:
                break
            req_id = self._pending_order.popleft()
            req = self._requests.get(req_id)
            if req is None or req["state"] != "PENDING":
                continue  # stale entry (shouldn't happen; guarded defensively)
            self._complete(uc, req, unclaimed)

    def _complete(self, uc, req, event_entry):
        if req["state"] != "PENDING":
            self.stats["duplicate_completion"] += 1
            self._log(f"DUPLICATE-COMPLETION-BLOCKED request #{req['id']} was already {req['state']}")
            return
        uc.mem_write(req["status_addr"], struct.pack("<i", KERRNONE))
        event_entry["claimed_by"] = req["id"]
        req["state"] = "COMPLETED"
        req["claimed_event"] = event_entry["id"]
        self.stats["eventready_completed"] += 1
        self.signal_count += 1
        self._completion_wake_log.append(req["id"])
        self.pending.pop(req["status_addr"], None)
        self._log(f"request #{req['id']} completed: KErrNone (backed by event #{event_entry['id']})")
        if self.lifecycle_hook is not None:
            self.lifecycle_hook.on_eventready_completed(req["id"], event_entry["id"])

    # -- consumption (runtime/async_model.wrap_get_event, tap-only) -------
    def on_event_consumed(self, uc, ev_type, ev_scancode):
        self.stats["getevent_called"] += 1
        if ev_type in (0, None):
            return
        if not self._event_fifo:
            self._log(f"GetEvent consumed a real event (type={ev_type}) with an EMPTY internal ledger -- untracked source")
            return
        ev = self._event_fifo.popleft()
        self.stats["event_consumed"] += 1
        self._log(f"GetEvent consumed event #{ev['id']}")
        if ev["claimed_by"] is not None:
            req = self._requests.get(ev["claimed_by"])
            if req is not None and req["state"] == "COMPLETED":
                req["state"] = "CONSUMED"
                self._log(f"request #{req['id']} consumed")
                del self._requests[ev["claimed_by"]]
        else:
            self.stats["getevent_without_completion"] += 1
            self._log(f"GetEvent consumed event #{ev['id']} WITHOUT a completed request (orphan consumption)")
        if self.on_event_consumed_hook is not None:
            self.on_event_consumed_hook(ev["id"], ev["ev_type"], ev["ev_scancode"], ev["claimed_by"])
        if self.lifecycle_hook is not None:
            self.lifecycle_hook.on_event_consumed(ev["id"], ev["ev_type"], ev["ev_scancode"], ev["claimed_by"])

    # -- completion, from EUSER:0x39f RequestComplete ----------------------
    def on_request_complete(self, uc, status_addr, reason):
        """UNCHANGED from v221: this is the pump loop's own SELF-MANAGED
        completion of its internal [this+0x80] status (confirmed, v222 xref
        scan, to be the ONLY call site of RequestComplete in the whole
        binary) -- entirely separate from the EventReady/PriorityKeyReady
        requests this registry tracks via register_request(). Kept so the
        real side effect (memory write + semaphore signal) still happens
        exactly as real RThread::RequestComplete / EKA2L1's notify_info::
        complete() do, unconditionally, regardless of whether OUR registry
        happens to be tracking this particular status_addr."""
        self.stats["request_complete_calls"] += 1
        if status_addr == 0:
            return
        uc.mem_write(status_addr, struct.pack("<i", reason))
        if status_addr in self.pending:
            # Would indicate an EventReady/PriorityKeyReady status got
            # completed via the OTHER (self-managed) path -- not expected
            # under the v222-b design, but handled rather than asserted.
            kind = self.pending.pop(status_addr)
            self.stats["ws32_genuine_completions"][kind] = (
                self.stats["ws32_genuine_completions"].get(kind, 0) + 1)
            self.stats["request_complete_tracked"] += 1
        else:
            self.stats["request_complete_untracked"] += 1
        self.signal_count += 1

    def cancel(self, status_addr):
        """Drop a still-PENDING request without touching memory again. Not
        wired to any confirmed EUSER Cancel-* call site this session (none
        was reached in tested scenarios) -- provided as a ready, testable
        API rather than a guess bolted onto an unconfirmed thunk."""
        for req_id, req in list(self._requests.items()):
            if req["status_addr"] == status_addr and req["state"] == "PENDING":
                del self._requests[req_id]
                try:
                    self._pending_order.remove(req_id)
                except ValueError:
                    pass
                self.pending.pop(status_addr, None)
                self.stats["cancellations"] += 1
                self._log(f"request #{req_id} cancelled")
                return True
        return False

    # -- WaitForAnyRequest ----------------------------------------------
    def wait_for_any_request(self, ctx, uc):
        self.stats["wfar_calls"] += 1
        self.stats["wait_entered"] += 1
        if self.signal_count > 0:
            self.signal_count -= 1
            self.stats["wfar_genuine_returns"] += 1
            self.stats["wait_woken"] += 1
            if self._completion_wake_log:
                req_id = self._completion_wake_log.popleft()
                self._log(f"WaitForAnyRequest woke on request #{req_id}")
                if self.lifecycle_hook is not None:
                    req = self._requests.get(req_id)
                    ev_id = req["claimed_event"] if req is not None else None
                    self.lifecycle_hook.on_wait_woken(req_id, ev_id)
            else:
                self._log("WaitForAnyRequest woke (signal from self-managed RequestComplete, not an EventReady completion)")
                if self.lifecycle_hook is not None:
                    self.lifecycle_hook.on_wait_woken(None, None)
            return
        # Nothing completed. Unicorn's hook_code model is fully synchronous
        # -- there is no way for this handler to suspend stepping and later
        # resume, so we cannot literally block the host thread here (the
        # task spec explicitly forbids permanently blocking the host
        # thread). We return anyway, WITHOUT fabricating a completion, and
        # count it as a wasted/spurious return.
        self.stats["wfar_wasted_returns"] += 1


def install(ctx):
    """Attach a fresh RequestRegistry to the runtime context and return
    the {thunk_va: handler(ctx, uc)} overlay to merge OVER the default
    dispatch table (only for the ordinals this model actually
    implements -- WaitForAnyRequest, RequestComplete, and the two WS32
    hw-key notify registrations). RunIfReady is intentionally absent.
    Does NOT wire ctx.event_queue.on_enqueue -- that happens in run.py,
    after ctx.event_queue is constructed (install() runs before it)."""
    from unicorn.arm_const import UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2

    registry = RequestRegistry()
    registry._ctx = ctx
    ctx.async_registry = registry

    def _handle_wait_for_any_request(ctx, uc):
        tracer = getattr(ctx, "wait_tracer", None)
        if tracer is not None:
            tracer.on_wait_enter()
        registry.wait_for_any_request(ctx, uc)
        if tracer is not None:
            tracer.on_wait_return()
        uc.reg_write(UC_ARM_REG_R0, 0)

    def _handle_request_complete(ctx, uc):
        r1 = uc.reg_read(UC_ARM_REG_R1)  # &(TRequestStatus* local var)
        reason = struct.unpack("<i", struct.pack("<I", uc.reg_read(UC_ARM_REG_R2) & 0xFFFFFFFF))[0]
        try:
            status_addr = struct.unpack("<I", uc.mem_read(r1, 4))[0]
        except Exception:
            status_addr = 0
        registry.on_request_complete(uc, status_addr, reason)
        if status_addr != 0:
            try:
                uc.mem_write(r1, struct.pack("<I", 0))  # null the caller's local pointer
            except Exception:
                pass
        uc.reg_write(UC_ARM_REG_R0, 0)

    def _make_ws32_notify_handler(kind):
        def _handler(ctx, uc):
            from unicorn.arm_const import UC_ARM_REG_LR
            r1 = uc.reg_read(UC_ARM_REG_R1)
            lr = uc.reg_read(UC_ARM_REG_LR)
            if os.environ.get("V221_EVENTREADY_DIAG") and kind == "event_ready":
                print(f"[EVENTREADY-DIAG] insn#{ctx.insn_count[0]} lr={hex(lr)} r1={hex(r1)}", flush=True)
            if r1 != 0:
                req_id = registry.register_request(uc, r1 + 4, kind)
                tracer = getattr(ctx, "wait_tracer", None)
                if tracer is not None:
                    tracer.on_registration(req_id, kind, lr)
            uc.reg_write(UC_ARM_REG_R0, 0)
        return _handler

    overlay = {
        EUSER_WAIT_FOR_ANY_REQUEST_VA: _handle_wait_for_any_request,
        EUSER_REQUEST_COMPLETE_VA: _handle_request_complete,
    }
    for va, kind in WS32_NOTIFY_THUNKS.items():
        overlay[va] = _make_ws32_notify_handler(kind)
    return overlay


def wrap_get_event(ctx, base_handler):
    """v222-b: wrap the EXISTING, confirmed-correct GetEvent (WS32:0x76)
    handler (runtime/input.py's handle_get_event) so that, AFTER it does
    its real job unchanged, the async model gets a chance to record which
    event was just CONSUMED -- for logging and orphan-consumption
    detection only. Does NOT complete anything here anymore (see the
    module docstring's "v222-b UPDATE" for why the earlier, v222-first-
    attempt design that completed requests from this hook was circular and
    had to be replaced). Does not change what GetEvent returns or writes
    for the real caller."""
    registry = ctx.async_registry

    def _wrapped(ctx, uc):
        base_handler(ctx, uc)
        # runtime/input.py's handle_get_event() sets these plain attributes,
        # synchronously, right before returning -- read them back here,
        # immediately after base_handler runs, in the same call.
        ev_type = getattr(ctx, "last_get_event_type", None)
        ev_scancode = getattr(ctx, "last_get_event_scancode", None)
        registry.on_event_consumed(uc, ev_type, ev_scancode)

    return _wrapped
