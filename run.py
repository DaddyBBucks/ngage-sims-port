#!/usr/bin/env python3
"""Entry point: wires runtime/ + patches.py (+ optional research_v209.py)
into one Unicorn run.

Examples:
  # Full run, all patches on, research diagnostics + scripted keys on
  # (equivalent to the pre-refactor v215 script's default behavior):
  python3 run.py --research --name-screen-mode isolate_open_only

  # Patch-free success test: is patch X actually needed to reach module 19?
  python3 run.py --research --disable-patch module19_sweep --max-insn 40000000
"""

import argparse
import collections
import json
import os
import struct
import sys

from unicorn import (Uc, UC_ARCH_ARM, UC_MODE_ARM, UC_HOOK_CODE,
                     UC_HOOK_MEM_INVALID, UC_HOOK_MEM_READ, UC_HOOK_MEM_WRITE)
from unicorn.arm_const import (
    UC_ARM_REG_PC, UC_ARM_REG_LR, UC_ARM_REG_SP, UC_ARM_REG_CPSR, UC_ARM_REG_IP,
    UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2, UC_ARM_REG_R3, UC_ARM_REG_R4,
    UC_ARM_REG_R5, UC_ARM_REG_R6, UC_ARM_REG_R7, UC_ARM_REG_R8, UC_ARM_REG_R9,
    UC_ARM_REG_R10, UC_ARM_REG_R11, UC_ARM_REG_R12,
)

from runtime import loader, imports as runtime_imports
from runtime.context import RuntimeContext
from runtime.memory import BumpAllocator
from runtime import input as input_mod
from runtime import async_model as async_model_mod
import patches as patches_mod

BINARY_PATH = os.path.join(os.path.dirname(__file__), "lxce_candidate.bin")
THUNK_MAP_PATH = os.path.join(os.path.dirname(__file__), "thunk_map.json")


def load_thunk_map():
    raw = json.load(open(THUNK_MAP_PATH))
    return {int(k, 16): (v[0], int(v[1], 16)) for k, v in raw.items()}


REG_NAMES = [
    ("r0", UC_ARM_REG_R0), ("r1", UC_ARM_REG_R1), ("r2", UC_ARM_REG_R2),
    ("r3", UC_ARM_REG_R3), ("r4", UC_ARM_REG_R4), ("r5", UC_ARM_REG_R5),
    ("r6", UC_ARM_REG_R6), ("r7", UC_ARM_REG_R7), ("r8", UC_ARM_REG_R8),
    ("r9", UC_ARM_REG_R9), ("r10", UC_ARM_REG_R10), ("r11", UC_ARM_REG_R11),
    ("r12/ip", UC_ARM_REG_R12), ("sp", UC_ARM_REG_SP), ("lr", UC_ARM_REG_LR),
    ("pc", UC_ARM_REG_PC), ("cpsr", UC_ARM_REG_CPSR),
]


def dump_crash_context(uc, trace, binary_path, thunk_map, out_path=None):
    """On an unhandled emulation exception, print (and optionally write to
    out_path) everything needed to root-cause it WITHOUT guessing:
      - full r0-r12/sp/lr/pc/cpsr dump
      - the last N instructions actually executed (disassembled from the
        static binary, not the live trace addresses, so it's readable even
        though the faulting PC itself may be mid-data)
      - the previous instruction's raw bytes/operands (the actual indirect
        jump), so it's clear whether it's bx/ldr-pc/mov-pc and which
        register/memory location supplied the target
      - a raw hex dump of the object the crash-site code was operating on
        (best-effort: the register most recently used as a base pointer in
        the trace window), so "is the object real, half-null, or garbage"
        can be answered by eye rather than assumed.
    This deliberately does NOT interpret the fault (e.g. does not assert
    "wrong index" or "missing vtable") -- it only assembles evidence; the
    classification is a separate step done by a human/agent reading this.
    """
    from capstone import Cs, CS_ARCH_ARM, CS_MODE_ARM
    lines = []

    def out(s=""):
        lines.append(s)

    regs = {name: uc.reg_read(const) for name, const in REG_NAMES}
    out("=== REGISTER STATE AT FAULT ===")
    for name, _ in REG_NAMES:
        out(f"  {name:8s} = {hex(regs[name])}")

    with open(binary_path, "rb") as f:
        binary = f.read()

    def va_to_off(va):
        return loader.va_to_off(va)

    def disasm_one(va):
        try:
            off = va_to_off(va)
        except Exception as e:
            return f"0x{va:x}:\t<va_to_off failed: {e}>"
        buf = binary[off:off + 4]
        md = Cs(CS_ARCH_ARM, CS_MODE_ARM)
        insns = list(md.disasm(buf, va))
        if not insns:
            return f"0x{va:x}:\t<does not decode as ARM -- raw bytes {buf.hex()}>"
        i = insns[0]
        tag = ""
        if va in thunk_map:
            dll, ordv = thunk_map[va]
            tag = f"   [THUNK {dll}:{hex(ordv)}]"
        return f"0x{i.address:x}:\t{i.mnemonic}\t{i.op_str}{tag}"

    out("\n=== LAST %d EXECUTED ADDRESSES (oldest first) ===" % len(trace))
    trace_list = list(trace)
    for insn_count, va in trace_list:
        out(f"  insn#{insn_count:<12d} {disasm_one(va)}")

    out("\n=== FAULT PC ITSELF ===")
    out(f"  {disasm_one(regs['pc'])}")

    # The instruction that actually redirected control flow into the fault
    # PC is the second-to-last trace entry (trace[-1] is the fault address
    # itself if hook_code fired for it, otherwise trace[-1] IS the jump).
    if len(trace_list) >= 2:
        prev_insn_count, prev_va = trace_list[-2] if trace_list[-1][1] == regs['pc'] else trace_list[-1]
        out(f"\n=== LIKELY INDIRECT-JUMP INSTRUCTION (insn#{prev_insn_count}) ===")
        out(f"  {disasm_one(prev_va)}")

    out("\n=== OBJECT DUMP (0x100 bytes at each of r0,r4,r5,r6,r7 -- common 'this'/base regs) ===")
    for name in ("r0", "r4", "r5", "r6", "r7"):
        base = regs[name]
        out(f"\n  --- {name} = {hex(base)} ---")
        try:
            data = uc.mem_read(base, 0x100)
            for i in range(0, 0x100, 16):
                chunk = data[i:i + 16]
                hexs = " ".join(f"{b:02x}" for b in chunk)
                out(f"    +0x{i:02x}: {hexs}")
        except Exception as e:
            out(f"    <unreadable: {e}>")

    text = "\n".join(lines)
    print(text)
    if out_path:
        with open(out_path, "w") as f:
            f.write(text)
        print(f"\n[crash-dump] full context written to {out_path}")
    return text


def build(args):
    uc = Uc(UC_ARCH_ARM, UC_MODE_ARM)
    load_info = loader.load_binary(uc, args.binary_file)
    allocator = BumpAllocator(uc)
    ctx = RuntimeContext(uc, allocator)
    ctx.archive_file_path = getattr(args, "archive_file", None)
    ctx.save_file_path = getattr(args, "save_file", None)

    thunk_map = load_thunk_map()
    thunk_set = set(thunk_map.keys())

    registry = patches_mod.build_registry(thunk_map)
    pm = patches_mod.PatchManager(registry)
    for name in args.disable_patch:
        if name not in registry:
            print(f"WARNING: unknown patch '{name}', ignoring", file=sys.stderr)
            continue
        pm.disable(name)
    pm.setup(ctx, uc)

    key_injected_log = []
    key_dispatch_trace_count = [0]
    key_state_watch_addrs = set()
    key_state_read_stats = collections.Counter()
    key_state_read_examples = []
    module4_trace_stats = collections.Counter()
    module4_trace_examples = []
    module5_input_stats = collections.Counter()
    module5_input_examples = []
    module5_action_trace_count = [0]
    ctx.key_state_watch_addrs = key_state_watch_addrs
    ctx.key_state_read_stats = key_state_read_stats
    ctx.key_state_read_examples = key_state_read_examples
    ctx.module4_trace_stats = module4_trace_stats
    ctx.module4_trace_examples = module4_trace_examples
    ctx.module5_input_stats = module5_input_stats
    ctx.module5_input_examples = module5_input_examples

    def install_key_state_watch(address, label):
        """Watch one byte of the real input manager without changing it."""
        if address in key_state_watch_addrs:
            return
        key_state_watch_addrs.add(address)

        def on_read(uc, access, watched_addr, size, value, user_data):
            pc = uc.reg_read(UC_ARM_REG_PC)
            try:
                observed = uc.mem_read(address, 1)[0]
            except Exception:
                observed = None
            key = (address, label, pc)
            key_state_read_stats[key] += 1
            if len(key_state_read_examples) < 300:
                rec = (ctx.insn_count[0], address, label, pc, size, observed)
                key_state_read_examples.append(rec)
                print(f"[KEY-STATE-READ] insn#{rec[0]} addr={hex(address)} "
                      f"label={label} pc={hex(pc)} size={size} value={observed}", flush=True)

        uc.hook_add(UC_HOOK_MEM_READ, on_read, begin=address, end=address)
        print(f"[KEY-STATE-WATCH] installed addr={hex(address)} label={label}", flush=True)
    seen_cursor_positions = set()
    SCANCODE_NAMES = {v: k for k, v in input_mod.KEYNAME_TO_SCANCODE.items()}

    def on_key_injected(insn_count, ev_type, ev_scancode):
        key_injected_log.append((insn_count, ev_type, ev_scancode))
        # Only the synthesized "translated" event is what real
        # OfferKeyEventL-style navigation handlers react to (see
        # runtime/input.py docstring) -- DOWN/UP/NULL are noise for this
        # log's purpose (seeing which logical key landed on which screen).
        if ev_type == input_mod.EEVENT_KEY:
            try:
                cur = struct.unpack("<I", uc.mem_read(patches_mod.MODULE_INDEX_GLOBAL, 4))[0]
            except Exception:
                cur = None
            name = SCANCODE_NAMES.get(ev_scancode, hex(ev_scancode))
            cursor_pos = None
            if cur == 19:
                # v208 (user-directed): v207 found phase 1/3 advancement is
                # gated on a flag table indexed by a cursor object's +0x31
                # byte (0x9e3ce4+0x31), not a timer. Log that byte on every
                # REAL key so we can see whether/how D-pad navigation moves
                # it, correlated with which key was pressed. The first time
                # we see each distinct position, also dump both candidate
                # flag tables' halfword at that position (phase1 uses
                # 0x9e3cb4, phase3 uses 0x9e3c90 -- both BSS, populated at
                # runtime, so a static dump from the file is meaningless;
                # this is the only way to see real values).
                try:
                    cursor_pos = uc.mem_read(0x9E3CE4 + 0x31, 1)[0]
                    if cursor_pos not in seen_cursor_positions:
                        seen_cursor_positions.add(cursor_pos)
                        flag1 = struct.unpack("<H", uc.mem_read(0x9E3CB4 + cursor_pos * 2, 2))[0]
                        flag2 = struct.unpack("<H", uc.mem_read(0x9E3C90 + cursor_pos * 2, 2))[0]
                        print(f"[CURSOR-FLAG-DUMP] insn#{insn_count} pos={cursor_pos} "
                              f"phase1_table[pos]={hex(flag1)} phase3_table[pos]={hex(flag2)}",
                              flush=True)
                except Exception:
                    cursor_pos = None
            print(f"[REAL-KEY] insn#{insn_count} key={name!r} scancode={hex(ev_scancode)} "
                  f"module_index_now={cur} cursor_pos_0x31={cursor_pos}", flush=True)

    thunk_dispatch = runtime_imports.build_dispatch(thunk_map, on_key_injected=on_key_injected)
    ctx.async_registry = None
    if getattr(args, "async_request_model", False):
        # v221 EXPERIMENTAL: opt-in cooperative WaitForAnyRequest/
        # RequestComplete/TRequestStatus model, behind its OWN flag (not
        # folded into any default-enabled patch -- see runtime/
        # async_model.py's module docstring for the full design and
        # ground-truth evidence). Overlaying AFTER build_dispatch() means
        # this only ever ADDS coverage for the 3 ordinals it implements
        # (WaitForAnyRequest, RequestComplete, WS32:0xa7/0x80 hw-key
        # notify) -- everything else keeps using the existing confirmed
        # handlers untouched.
        thunk_dispatch.update(async_model_mod.install(ctx))
        # v222-b: wrap the EXISTING GetEvent (WS32:0x76) handler purely as a
        # CONSUMPTION/VERIFICATION tap -- NOT a completion trigger anymore.
        # v222 (first attempt) completed EventReady requests from inside
        # this wrapper, which turned out to be circular: GetEvent is only
        # reachable through fcn.00444750's dispatch call, which is itself
        # gated behind the SAME [this+0x54] pending flag EventReady sets --
        # so "complete when GetEvent fires" could never bootstrap (confirmed
        # both statically, via a fresh r2 disassembly of fcn.00444750 showing
        # the 0x444764 entry-gate bne skips BOTH WaitForAnyRequest call sites
        # AND the 0x4447e4 dispatch-to-GetEvent call, and dynamically, via
        # V222_GETEVENT_DIAG instrumentation showing GetEvent's thunk was
        # invoked ZERO times in an 8M-instruction run with a pending
        # EventReady request). The real completion path is now
        # ctx.event_queue.on_enqueue -> registry.on_event_enqueued (wired
        # below, after ctx.event_queue exists) -- driven by the HARNESS
        # producing an event, not by game code reaching GetEvent. This
        # wrapper now only tracks event CONSUMPTION (which physical event
        # GetEvent just popped) for logging/orphan-detection -- see
        # async_model.py's "v222-b UPDATE" docstring.
        if input_mod.GETEVENT_THUNK_VA in thunk_dispatch:
            thunk_dispatch[input_mod.GETEVENT_THUNK_VA] = async_model_mod.wrap_get_event(
                ctx, thunk_dispatch[input_mod.GETEVENT_THUNK_VA])
    # v218 NEW: rizin/r2-assisted investigation found that ~41 of 44 WS32
    # (window server) thunked ordinals fall through to default_stub (always
    # returns R0=0) -- i.e. we have NO real implementation for whatever the
    # game calls to invalidate/flush/redraw a window. This tracks exactly
    # which (dll, ordinal) pairs actually hit the unimplemented default_stub
    # path during a real run, and how often, so we can prioritize which
    # ones are worth reverse-engineering first instead of guessing.
    unimplemented_thunk_hits = collections.Counter()
    unimplemented_thunk_first_lr = {}
    ws32_outparam_watch_count = collections.Counter()

    research = None
    diagnostics = None
    snapshot_recorder = None
    if args.research:
        import research_v209 as research
        ready_flag = [False]
        if args.idle_wait_experiment:
            # v204 (user-directed experiment): reach module 19 via the
            # normal nav sequence, then send PURE EEVENT_NULL (no synthetic
            # right/left taps -- unlike PANEL_SETTLE_FILLER) until
            # --idle-wait-until-insn, then exactly one --idle-wait-post-key.
            # Tests whether slots 0-10 of the 0xA16B3C table populate given
            # enough idle time (a harness-timing artifact) or never do (a
            # genuinely missing construction step).
            pre_sequence = research.build_pre_idle_sequence(args.menu_select_probe, args.nav_variant)
            refill = research.make_idle_then_key_refill(
                pre_sequence, args.idle_wait_until_insn, ctx,
                post_key=args.idle_wait_post_key, ready_flag=ready_flag)
        else:
            sequence = research.build_key_sequence(args.name_screen_mode, args.menu_select_probe, args.nav_variant)
            refill = research.make_scripted_refill(sequence, ready_flag=ready_flag)
        ctx.event_queue = input_mod.EventQueue(refill)

        diagnostics = research.ResearchDiagnostics()

        from runtime.graphics import FramebufferWatcher, FRAMEBUFFER_WATCH_LO, FRAMEBUFFER_WATCH_HI
        fb_watcher = FramebufferWatcher()
        snapshot_recorder = research.SnapshotRecorder(fb_watcher, interval=args.snapshot_interval,
                                                        stream_out_dir=args.out_dir)
        fb_write_pc_counts = {}  # v213 NEW: PC -> hit count, for [FB-WRITE-PC]
        late_fb_write_counter = [0]  # v213b NEW: uncapped-window print budget
        fb_write_region_stats = {}  # v215 NEW: PC -> {n,xmin,xmax,ymin,ymax,sumx,sumy}
        # v216 NEW: targeted before/during/after snapshots bracketing the
        # insn~90.3M "7-item masked-bitmap draw" window found in v215
        # (madde 10). Wide, multi-point bracket so the burst is visible even
        # with run-to-run insn drift, without snapshotting the whole run.
        TARGETED_SNAPSHOT_INSNS = {90_280_000, 90_300_000, 90_310_000, 90_315_000,
                                    90_320_000, 90_325_000, 90_330_000, 90_340_000,
                                    90_360_000, 90_400_000, 90_450_000}
    else:
        # Non-research runs still need SOME event source: idle forever.
        def idle_refill(q):
            q.append((input_mod.EEVENT_NULL, 0))
        ctx.event_queue = input_mod.EventQueue(idle_refill)
        fb_watcher = None
        FRAMEBUFFER_WATCH_LO = FRAMEBUFFER_WATCH_HI = 0
        fb_write_pc_counts = {}
        late_fb_write_counter = [0]
        fb_write_region_stats = {}
        TARGETED_SNAPSHOT_INSNS = set()
        ready_flag = None

    if ctx.async_registry is not None:
        # v222-b: wire the event queue's enqueue notification to the async
        # registry AFTER ctx.event_queue exists (it's constructed inside the
        # research/non-research branches above, both of which converge
        # here). This is what lets EventReady/PriorityKeyReady completion
        # be driven by the HARNESS producing a real event, independent of
        # whether game code (WaitForAnyRequest / GetEvent) ever runs again
        # -- see async_model.py's "v222-b UPDATE" docstring section for why
        # the earlier wrap_get_event-only design was circular and had to be
        # replaced with this enqueue-time / registration-time model.
        ctx.event_queue.on_enqueue = (
            lambda ev_type, ev_scancode, _uc=uc: ctx.async_registry.on_event_enqueued(_uc, ev_type, ev_scancode))

    module_index_seen = [None]
    trace = collections.deque(maxlen=args.trace_depth) if args.trace_depth > 0 else None
    ctx.trace = trace  # exposed so runtime/sync_injector.py's stall dump can read the trailing PC trace

    ctx.lifecycle_tracer = None
    if ctx.async_registry is not None and getattr(args, "lifecycle_trace", False):
        # v224: attach the per-event, stage-by-stage tracer BEFORE
        # constructing SyncKeyInjector below, so the injector can report
        # "generated" at burst-append time and "injector_acknowledged" at
        # its own consumption-confirmation time. Wired into RequestRegistry
        # via the SECOND, additive lifecycle_hook slot (async_model.py) --
        # does not touch or replace on_event_consumed_hook, which
        # SyncKeyInjector still owns for its own bookkeeping.
        import runtime.lifecycle_trace as lifecycle_trace_mod
        ctx.lifecycle_tracer = lifecycle_trace_mod.LifecycleTracer(uc, ctx)

    ctx.wait_tracer = None
    if ctx.async_registry is not None and getattr(args, "wait_trace", False):
        # v225: attach the WaitForAnyRequest<->GetEvent-dispatch control-flow
        # tracer. Shares the SAME lifecycle_hook slot as ctx.lifecycle_tracer
        # (async_model.py's RequestRegistry only exposes one), so when BOTH
        # are active a small fan-out combinator (_MultiLifecycleHook, below)
        # forwards every call to both.
        import runtime.wait_trace as wait_trace_mod
        ctx.wait_tracer = wait_trace_mod.WaitTracer(uc, ctx, ctx.async_registry)

    if ctx.async_registry is not None and (ctx.lifecycle_tracer is not None or ctx.wait_tracer is not None):
        class _MultiLifecycleHook:
            def __init__(self, targets):
                self._targets = [t for t in targets if t is not None]

            def on_event_enqueued(self, *a):
                for t in self._targets:
                    t.on_event_enqueued(*a)

            def on_eventready_completed(self, *a):
                for t in self._targets:
                    t.on_eventready_completed(*a)

            def on_wait_woken(self, *a):
                for t in self._targets:
                    t.on_wait_woken(*a)

            def on_event_consumed(self, *a):
                for t in self._targets:
                    t.on_event_consumed(*a)

        ctx.async_registry.lifecycle_hook = _MultiLifecycleHook([ctx.lifecycle_tracer, ctx.wait_tracer])

    # v227: DTRZ Stream B research -- read-only log of every real
    # ESTLIB:fread(thesims.dat) call the GAME ITSELF makes (offset, length,
    # calling LR). Lets us observe live which byte ranges of the archive get
    # read, instead of guessing. Never affects file contents or control flow
    # (see runtime/archive.py handle_fread).
    if getattr(args, "archive_read_log", False):
        ctx.archive_read_log = []

    if ctx.async_registry is not None and getattr(args, "sync_key_injector", False):
        # v223: replace whatever refill() the research/non-research branch
        # above just set up with the fully state-synchronized phase1+phase2
        # sequencer (runtime/sync_injector.py) -- driven by the async
        # model's own request/event lifecycle, not a fixed timer. Requires
        # --async-request-model (the sequencer is built on RequestRegistry).
        import runtime.sync_injector as sync_injector_mod
        injector = sync_injector_mod.SyncKeyInjector(
            uc, ctx, ctx.async_registry,
            max_keys=getattr(args, "max_keys", None),
            lifecycle_tracer=ctx.lifecycle_tracer,
            wait_tracer=ctx.wait_tracer,
            nav_mode=("none" if getattr(args, "sync_skip_nav", False)
                      else getattr(args, "sync_nav_mode", "full")),
            min_gap_insn=getattr(args, "sync_min_gap_insn", 0),
            key_hold_insn=getattr(args, "sync_key_hold_insn", 0),
            first_key_hold_insn=getattr(args, "sync_first_key_hold_insn", None))
        ctx.event_queue._refill = injector.refill
        ctx.sync_injector = injector
        injector.require_post_release_scan = getattr(args, "sync_release_on_game_scan", False)

    # v222-b: cadence for the independent event-producer tick (see
    # hook_code below). 2000 instructions keeps total produced items
    # bounded (~max_insn/2000) while being far more frequent than the pump
    # loop's own observed call spacing (tens of thousands of instructions
    # apart, per loop_pump summaries), so production is never the
    # bottleneck once a request is actually pending.
    EVENT_PRODUCE_INTERVAL = 2000

    def hook_code(uc, address, size, user_data):
        ctx.insn_count[0] += 1
        if trace is not None:
            trace.append((ctx.insn_count[0], address))
        if getattr(args, "module4_lifecycle_trace", False) and address in (
                0x438CC0, 0x438CF4, 0x438D3C, 0x438D5C, 0x438D94,
                0x438DAC, 0x438DB0, 0x438FCC, 0x438FD8):
            labels = {
                0x438CC0: "update_entry", 0x438CF4: "state0", 0x438D3C: "state1",
                0x438D5C: "state2", 0x438D94: "state2_timer_expired",
                0x438DAC: "call_443e28", 0x438DB0: "call_44d6e0",
                0x438FCC: "attempts_eq_4", 0x438FD8: "state3_request_module5",
            }
            label = labels[address]
            try:
                base = patches_mod.MODULE_INDEX_GLOBAL
                mod = struct.unpack("<I", uc.mem_read(base, 4))[0]
                attempts = struct.unpack("<I", uc.mem_read(base + 8, 4))[0]
                substate = struct.unpack("<I", uc.mem_read(base + 0x10, 4))[0]
                timer = struct.unpack("<I", uc.mem_read(base + 0x14, 4))[0]
            except Exception:
                mod = attempts = substate = timer = None
            module4_trace_stats[label] += 1
            if len(module4_trace_examples) < 300:
                example = (ctx.insn_count[0], address, label, mod, attempts, substate, timer)
                module4_trace_examples.append(example)
                print(f"[MODULE4-LIFECYCLE] insn#{ctx.insn_count[0]} pc={hex(address)} "
                      f"point={label} module={mod} attempts={attempts} "
                      f"substate={substate} timer={timer}", flush=True)
        if getattr(args, "module5_input_trace", False) and address == 0x48EDFC:
            try:
                selected = uc.mem_read(0x9E3D15, 1)[0]
                mask = struct.unpack("<H", uc.mem_read(0x9E3C90 + selected * 2, 2))[0]
                substate = struct.unpack("<I", uc.mem_read(0xA16B04, 4))[0]
            except Exception:
                selected = mask = substate = None
            module5_input_stats["update"] += 1
            if len(module5_input_examples) < 300:
                module5_input_examples.append(
                    (ctx.insn_count[0], "update", selected, mask, substate))
                print(f"[MODULE5-INPUT] insn#{ctx.insn_count[0]} update "
                      f"selected={selected} mask={hex(mask) if mask is not None else None} "
                      f"substate={substate}", flush=True)
        if getattr(args, "module5_action_trace", False) and address in (
                0x48EE80, 0x48F064, 0x48F09C, 0x48F0A0, 0x48F0E8,
                0x48F0F0, 0x48F104, 0x48EE84, 0x48EF98, 0x48EF9C,
                0x44B7E4, 0x44B7E8):
            if module5_action_trace_count[0] < 200:
                module5_action_trace_count[0] += 1
                regs = [uc.reg_read(r) for r in (UC_ARM_REG_R0, UC_ARM_REG_R1,
                                                  UC_ARM_REG_R2, UC_ARM_REG_R3,
                                                  UC_ARM_REG_SP, UC_ARM_REG_LR)]
                print(f"[MODULE5-ACTION] insn#{ctx.insn_count[0]} pc={hex(address)} "
                      f"r0={hex(regs[0])} r1={hex(regs[1])} r2={hex(regs[2])} "
                      f"r3={hex(regs[3])} sp={hex(regs[4])} lr={hex(regs[5])}", flush=True)
        if (getattr(args, "sync_release_on_game_scan", False)
                and address == 0x4305FC and getattr(ctx, "sync_injector", None) is not None):
            ctx.sync_injector.on_game_key_scan(uc.reg_read(UC_ARM_REG_R3) & 0xffff)
        # v231: distinguish "GetEvent popped it" from "the focused
        # control's translated-key handler was actually invoked".  Purely
        # observational; 0x444b8c is the confirmed `bx ip` dispatch site.
        if getattr(args, "key_dispatch_trace", False) and address == 0x444B8C:
            if key_dispatch_trace_count[0] < 200:
                r0 = uc.reg_read(UC_ARM_REG_R0)
                r1 = uc.reg_read(UC_ARM_REG_R1)
                r7 = uc.reg_read(UC_ARM_REG_R7)
                ip = uc.reg_read(UC_ARM_REG_IP)
                base = r7 + 0x10
                try:
                    itype, icode, scan = struct.unpack(
                        "<IiI", uc.mem_read(base, 0x18)[0:4] +
                        uc.mem_read(base + 0x10, 8))
                except Exception:
                    itype = icode = scan = None
                key_dispatch_trace_count[0] += 1
                print(f"[KEY-DISPATCH] insn#{ctx.insn_count[0]} r0={hex(r0)} "
                      f"r1={hex(r1)} r7={hex(r7)} target_ip={hex(ip)} "
                      f"iType={itype} iCode={hex(icode) if icode is not None else None} "
                      f"iScanCode={hex(scan) if scan is not None else None}", flush=True)
        if getattr(args, "key_dispatch_trace", False) and address == 0x438340:
            if key_dispatch_trace_count[0] < 200:
                mgr = uc.reg_read(UC_ARM_REG_R0)
                scan = uc.reg_read(UC_ARM_REG_R1) & 0xff
                pressed = uc.reg_read(UC_ARM_REG_R2)
                try:
                    mapped = uc.mem_read(mgr + 4 + scan, 1)[0]
                except Exception:
                    mapped = None
                try:
                    vtable = struct.unpack("<I", uc.mem_read(mgr, 4))[0]
                    vslots = struct.unpack("<16I", uc.mem_read(vtable, 0x40))
                    vslots_text = [hex(v) for v in vslots]
                    key_callback = struct.unpack("<I", uc.mem_read(0x4B6D64, 4))[0]
                except Exception:
                    vtable = None
                    vslots_text = None
                    key_callback = None
                key_dispatch_trace_count[0] += 1
                print(f"[RAW-KEY-MAP] insn#{ctx.insn_count[0]} manager={hex(mgr)} "
                      f"scan={hex(scan)} pressed={pressed} mapped_game_key={mapped} "
                      f"vtable={hex(vtable) if vtable is not None else None} "
                      f"key_callback={hex(key_callback) if key_callback is not None else None} "
                      f"vslots={vslots_text}", flush=True)
                if getattr(args, "key_state_read_trace", False) and mapped is not None:
                    # 0x438340's disassembly proves these layouts:
                    # manager+0x105+2*mapped = current per-game-key flags;
                    # manager+0x104+2*mapped = sibling/previous flags;
                    # manager+0x304+scan = raw physical pressed state.
                    install_key_state_watch(mgr + 0x105 + 2 * mapped,
                                            f"game_key_{mapped}_current")
                    install_key_state_watch(mgr + 0x104 + 2 * mapped,
                                            f"game_key_{mapped}_sibling")
                    install_key_state_watch(mgr + 0x304 + scan,
                                            f"scan_{hex(scan)}_pressed")
        if ctx.async_registry is not None and ctx.insn_count[0] % EVENT_PRODUCE_INTERVAL == 0:
            # v222-b: tick the harness's own simulated "window server" event
            # producer on a fixed INSTRUCTION-COUNT cadence, independent of
            # whether the game ever calls GetEvent. This is the fix for a
            # second, one-level-removed circularity found after the
            # enqueue-time completion model was wired in: EventQueue's
            # refill() (research_v209.py's make_scripted_refill) only ran
            # lazily, as a side effect of pop()/peek() being called -- and
            # the ONLY caller of pop()/peek() was GetEvent's handler.
            # Confirmed empirically (event_enqueued stayed 0 across an
            # entire 8M-instruction run with getevent_called also 0): if
            # GetEvent never runs, the scripted key sequence could never
            # advance past its very first auto-refilled item (pop()/peek()
            # only refill when the queue is EMPTY, and nothing was ever
            # popping it) -- a second circular dependency, this time in OUR
            # harness infrastructure, not the game's. A first attempt used
            # peek() (non-destructive) on every instruction, but peek()
            # still only refills when empty -- since nothing pops, the
            # queue fills to exactly one lingering item and STAYS there
            # forever, so it never actually solved this. produce_tick()
            # unconditionally invokes the SAME refill() callback used
            # everywhere else, on its own clock -- this models the window
            # server's independent event-production timing (real hardware
            # events accumulate server-side whether or not the client is
            # polling), touches no game code or game memory, and is bounded
            # (EVENT_PRODUCE_INTERVAL caps total items produced over the
            # whole run to roughly max_insn/EVENT_PRODUCE_INTERVAL).
            try:
                ctx.event_queue.produce_tick()
            except Exception:
                pass
        try:
            _hook_code_body(uc, address, size, user_data)
        except Exception:
            import traceback
            print(f"[HOOK-EXCEPTION] insn#{ctx.insn_count[0]} address={hex(address)}", flush=True)
            traceback.print_exc()
            raise

    def _hook_code_body(uc, address, size, user_data):
        if ctx.lifecycle_tracer is not None:
            ctx.lifecycle_tracer.on_pc(address)
        if ctx.wait_tracer is not None:
            ctx.wait_tracer.on_pc(address)

        if address == 0:
            lr = uc.reg_read(UC_ARM_REG_LR)
            print(f"[NULL-JUMP] insn#{ctx.insn_count[0]} PC hit 0x0, called from LR={hex(lr)} "
                  f"module_index_seen={module_index_seen[0]}", flush=True)

        if address == 0x4254a0:
            # v205 CORRECTION: a careful re-disassembly (literal pool
            # resolved) shows this is NOT a construction pass. It reads
            # module substate *(0xA16AF4+0x14) == *(0xA16B08); if it is
            # NOT 0x1e (30) it returns immediately (bne 0x425694, never
            # observed to be taken as anything else in our runs -- all 4
            # hits had module_index=19 with substate==0x1e). If it IS
            # 0x1e, it CLEARS the busy-bit (bic ...,#1) on table slots 14,
            # 13, 12 (0xA16B3C+0x38/+0x34/+0x30) -- a finalize/cleanup step,
            # the mirror image of 0x425278's construction. It does NOT
            # touch 0xA16B30/0xA16B34 (those are earlier fields inside
            # 0x425278 itself, r5-relative there -- see the corrected
            # v205 report). The REAL "count *(0x8d7a34) / table
            # *(0x8d7a14)" second-population loop lives INSIDE 0x425278
            # (block 0x4253a0-0x425444), not here -- keeping this watch
            # for now since it's still useful confirmation of the
            # substate==0x1e gate firing correctly.
            lr = uc.reg_read(UC_ARM_REG_LR)
            try:
                cur_mod = struct.unpack("<I", uc.mem_read(patches_mod.MODULE_INDEX_GLOBAL, 4))[0]
                cur_substate = struct.unpack("<I", uc.mem_read(0xA16B08, 4))[0]
            except Exception:
                cur_mod = None
                cur_substate = None
            print(f"[FN-4254A0-ENTRY] insn#{ctx.insn_count[0]} lr={hex(lr)} module_index={cur_mod} "
                  f"substate={cur_substate}", flush=True)

        if address == 0x422794:
            # v206 NEW: entry of the master phase dispatcher itself. Logs
            # the phase index (0xA16B04) about to be dispatched on, so we
            # can see the call frequency/ordering independent of the
            # PHASE-INDEX-WRITE watch (which only fires on writes, not
            # reads/dispatches).
            try:
                cur_phase = struct.unpack("<I", uc.mem_read(0xA16B04, 4))[0]
                cur_mod = struct.unpack("<I", uc.mem_read(patches_mod.MODULE_INDEX_GLOBAL, 4))[0]
            except Exception:
                cur_phase = None
                cur_mod = None
            print(f"[PHASE-DISPATCH-ENTRY] insn#{ctx.insn_count[0]} module_index={cur_mod} phase={cur_phase}",
                  flush=True)

        if address in (0x4247f8, 0x424c68, 0x422ec8, 0x4238dc, 0x4244d4, 0x422ff4, 0x42321c, 0x424558, 0x424654):
            # v206 NEW: the 9 still-unexplored phase handlers from the
            # 0x422794 jump table (indices 0,1,3,4,5,6,8,11,12). Any one
            # of these could be the still-missing "construct table slots
            # 0-10" step. Logging every entry (with LR) shows which ones
            # actually run in our traced sequence, and in what order --
            # the next static-disassembly target is whichever of these
            # fires BEFORE the first slot-1/slot-7 crash.
            lr = uc.reg_read(UC_ARM_REG_LR)
            try:
                cur_phase = struct.unpack("<I", uc.mem_read(0xA16B04, 4))[0]
            except Exception:
                cur_phase = None
            print(f"[UNEXPLORED-PHASE-HANDLER-ENTRY] insn#{ctx.insn_count[0]} fn={hex(address)} "
                  f"phase={cur_phase} lr={hex(lr)}", flush=True)

        if address in (0x423b38, 0x423e74):
            # v205 NEW: static trace found these are per-substate "reveal
            # widget N" handlers for the SAME countdown field 0xA16B08
            # (0xA16AF4+0x14). 0x423b38 handles substate==0x1e (slot 7,
            # writes value 0x1c/28 then 0xf/15 into obj+0x5e) and
            # substate==0xf (after a helper loop over indices 8..14, an
            # UNGUARDED write of 0xf/15 into TABLE SLOT 1 +0x5e -- this is
            # the exact v204 crash). 0x423e74 handles substate==0x1e too,
            # but writes 0x10/16 into slot 1 +0x5e via a different call
            # site. Crucially, 0x423b38's epilogue (0x423e5c) DECREMENTS
            # 0xA16B08 by 1 after running -- so this looks like a scripted,
            # countdown-driven sequential reveal (one widget activated per
            # tick/step), not a one-shot "screen ready" event. Logging the
            # substate value and slot targeted on every entry, across a
            # full run, will show the complete substate->slot schedule and
            # whether it EVER reaches slots that are known-populated
            # (11-16) vs. only known-empty ones (0-10) -- direct evidence
            # for the "genuinely missing constructor" vs. "wrong index"
            # question.
            r4_state = uc.reg_read(UC_ARM_REG_R4) if address == 0x423e74 else None
            try:
                cur_mod = struct.unpack("<I", uc.mem_read(patches_mod.MODULE_INDEX_GLOBAL, 4))[0]
                cur_substate = struct.unpack("<I", uc.mem_read(0xA16B08, 4))[0]
            except Exception:
                cur_mod = None
                cur_substate = None
            print(f"[SUBSTATE-DISPATCH-ENTRY] insn#{ctx.insn_count[0]} fn={hex(address)} "
                  f"module_index={cur_mod} substate={cur_substate}", flush=True)

        if address == 0x422c38:
            # v203 follow-up (user hypothesis 5): this is the TRUE entry of
            # the function that eventually calls 0x422b28. Its body reads
            # r4 = 0xA16AF4 (MODULE_INDEX_GLOBAL, the SAME 24-byte
            # module-state struct known since v197/v198) and calls
            # 0x4307b4 (the bounds-checked cursor-increment helper
            # responsible for the v198 module-28-vs-19 stray-down-key bug)
            # directly on r4+8 == 0xA16AFC, the SELECTOR field. That is a
            # main-menu-cursor operation, not anything module-19/name-
            # screen specific. Logging every call (LR + current module
            # index) across a FULL run answers: does this same function
            # also fire during module 5 (confirming it's shared/reused
            # code), and is it still firing -- unexpectedly -- once we're
            # already in module 19 (the "stale input handler" hypothesis)?
            lr = uc.reg_read(UC_ARM_REG_LR)
            try:
                cur_mod = struct.unpack("<I", uc.mem_read(patches_mod.MODULE_INDEX_GLOBAL, 4))[0]
            except Exception:
                cur_mod = None
            print(f"[FN-422C38-ENTRY] insn#{ctx.insn_count[0]} lr={hex(lr)} module_index={cur_mod}",
                  flush=True)

        if address == 0x423650:
            # v211 NEW (user-directed, priority: find the natural
            # construction chain, not skip-Done): 0x4234fc, called from
            # PHASE 4's (0x4238dc) handler, "reveals" ONE letter/digit grid
            # cell per successful call -- it pulls a pre-built cell object
            # out of a table at [*(0x8d7a10)+0x68 + geometry(pos)] and
            # pushes it onto a GROWING list at [*(0x8d7a10)+4 + count*4]
            # (count itself lives at [*(0x8d7a10)+0]). This is a SEPARATE
            # dynamic array, NOT the 0xA16B3C 17-slot table -- so the
            # individual A-Z/0-9 cells are not slots 8/9/10 of that table.
            # 0x423650 is the exact instruction that pushes a newly
            # revealed cell's pointer onto that list; r4=index (the running
            # reveal count before increment), r5=the cell object pointer.
            # Logging every hit gives a direct, cumulative count of how
            # many grid cells have been revealed so far.
            r4v = uc.reg_read(UC_ARM_REG_R4)
            r5v = uc.reg_read(UC_ARM_REG_R5)
            print(f"[GRIDCELL-REVEAL] insn#{ctx.insn_count[0]} index={r4v} cell_ptr={hex(r5v)}",
                  flush=True)

        if address == 0x423900:
            # v211 NEW: PHASE 4's (0x4238dc) entry into the "reveal next
            # cell or advance phase" dispatch -- logs the counter object's
            # current state ([*(0x8d7a10)]) each time phase 4 runs, so we
            # can see the reveal count's progression over the whole run
            # independent of whether a reveal or a phase transition fires.
            try:
                obj_ptr = struct.unpack("<I", uc.mem_read(0x8D7A10, 4))[0]
                counter = struct.unpack("<I", uc.mem_read(obj_ptr, 4))[0] if obj_ptr else None
            except Exception:
                obj_ptr = None
                counter = None
            print(f"[PHASE4-ENTRY] insn#{ctx.insn_count[0]} obj_ptr={hex(obj_ptr) if obj_ptr else None} "
                  f"reveal_counter={counter}", flush=True)

        if address in (0x410668, 0x48a0e8, 0x476bac, 0x432c18, 0x43e7b4, 0x43b098, 0x41b210):
            # v212 NEW (user-directed): purely OBSERVATIONAL entry-hit
            # watch for the 7 candidate slot-8/9/10 constructors Ghidra's
            # xref scan surfaced. Ghidra's own function-boundary detection
            # placed FUN_ entries at exactly these addresses; manual
            # Capstone (ARM mode) confirms a real `push {..,lr}` prologue
            # at every one of them, cross-validating Ghidra did NOT
            # mis-decode this region as Thumb. This hook does not alter
            # any state -- it only records whether/when the game's own
            # code calls these functions, so we can tell whether they are
            # reachable from module 19's live state machine or belong to
            # a different module entirely. NOT a forced call.
            try:
                cur_mod = struct.unpack("<I", uc.mem_read(patches_mod.MODULE_INDEX_GLOBAL, 4))[0]
            except Exception:
                cur_mod = None
            lr = uc.reg_read(UC_ARM_REG_LR)
            print(f"[SLOT8-9-10-CANDIDATE-ENTRY] insn#{ctx.insn_count[0]} fn={hex(address)} "
                  f"lr={hex(lr)} module_index={cur_mod}", flush=True)

        if address in (0x4106dc, 0x48a2cc, 0x48a2f0, 0x48a3d8, 0x476c70, 0x432c3c,
                       0x43e8ac, 0x43e8c4, 0x43e8e0, 0x43b1d8, 0x43b228, 0x41b2f0, 0x41b330):
            # v212 NEW: OBSERVATIONAL watch on the exact `str r0,[table+off]`
            # instruction addresses (found via Ghidra xref, cross-checked
            # against manual Capstone ARM disassembly) inside each of the
            # 7 candidate functions above that target slot 8, 9, or 10
            # specifically. Fires only if that exact instruction executes
            # live -- the strongest possible confirmation short of a full
            # decompiler trace. r0 = the value about to be written (a real
            # widget pointer in every case checked statically, never a
            # bare 0 for these specific offsets).
            r0v = uc.reg_read(UC_ARM_REG_R0)
            try:
                cur_mod = struct.unpack("<I", uc.mem_read(patches_mod.MODULE_INDEX_GLOBAL, 4))[0]
            except Exception:
                cur_mod = None
            print(f"[SLOT8-9-10-CANDIDATE-WRITE] insn#{ctx.insn_count[0]} pc={hex(address)} "
                  f"r0={hex(r0v)} module_index={cur_mod}", flush=True)

        if address == 0x424c84:
            # v209 NEW: phase 1's handler (0x424c68) top -- right at the
            # `tst r3,#1` instruction, r3 holds the freshly-loaded
            # flag_table[cursor_pos] halfword (0x9e3cb4[cursor*2], per the
            # v207/v208 static trace). Full disassembly of the whole
            # function (0x424c68-0x4250f4) this session showed r3 is NOT a
            # simple boolean -- if bit0 is clear, execution falls through to
            # a SECOND bit-test chain (0x424e9c) that reuses the SAME r3 as
            # a multi-bit flags value: bit1 drives an independent countdown
            # at 0x8d7a34 that can jump straight to PHASE=2 bypassing
            # SELECTOR entirely; bits 6/7 (0x40/0x80) inc/dec SELECTOR;
            # bits 4/5 (0x10/0x20) adjust a column counter; bits 8/9
            # (0x100/0x200) toggle a case/shift flag at 0x8d7a35. The ONE
            # observed SELECTOR-WRITE in v208's run (0->1 at insn#85963403,
            # pc=0x42500c) happened inside a 0x424c68 dispatch that started
            # only 25 instructions earlier (insn#85963378) -- meaning r3
            # must have had bit0 CLEAR and bit 0x80 SET at that specific
            # tick, which contradicts the ONE [CURSOR-FLAG-DUMP] sample
            # (pos=0, table value=0x1, bit0 only) taken ~42M instructions
            # earlier. This watch logs r3's ACTUAL value plus the live
            # cursor position on EVERY entry, across a full run, to settle
            # whether the flag table is genuinely static per-cell data (and
            # our cursor-position read is wrong/stale) or is being mutated
            # dynamically by other game code as the user interacts.
            r3 = uc.reg_read(UC_ARM_REG_R3)
            try:
                cursor_pos = uc.mem_read(0x9E3CE4 + 0x31, 1)[0]
            except Exception:
                cursor_pos = None
            print(f"[PHASE1-FLAGVAL] insn#{ctx.insn_count[0]} r3(flag_table[pos])={hex(r3)} "
                  f"cursor_pos={cursor_pos}", flush=True)

        if address == 0x424fec:
            # v209 NEW: entry of the secondary bit-test chain's SELECTOR
            # inc/dec/column-adjust block. r3 here should be the SAME value
            # logged by the 0x424c84 watch above (no intervening `bl`
            # between the two, per static trace) -- logging it again here,
            # right before the bit-0x80/0x40/0x10/0x20 tests actually fire,
            # is a cheap cross-check that nothing clobbers r3 in between.
            r3 = uc.reg_read(UC_ARM_REG_R3)
            print(f"[PHASE1-SELECTOR-DISPATCH] insn#{ctx.insn_count[0]} r3={hex(r3)}", flush=True)

        if address == 0x422b40:
            # v202 follow-up: 0x422b28's body has ONE guard (`cmp r2,r3;
            # beq 0x422b70`) that, if taken, SKIPS the slot-7-touching
            # block (0x422b48-0x422b6c) entirely. r2 = *(0x9e3528+0x20),
            # r3 = *(0x8d79d4). Log both to see whether this guard's
            # inputs are themselves still-uninitialized globals -- if so,
            # that may be a third, upstream piece of this same puzzle.
            r2 = uc.reg_read(UC_ARM_REG_R2)
            r3 = uc.reg_read(UC_ARM_REG_R3)
            print(f"[FN-422B28-GUARD] insn#{ctx.insn_count[0]} r2(*[0x9e3528+0x20])={hex(r2)} "
                  f"r3(*[0x8d79d4])={hex(r3)} branch_taken={r2 == r3}", flush=True)

        if address == 0x422b28:
            # v202 follow-up: no direct `bl 0x422b28` and no raw vtable-slot
            # literal exist anywhere in the static image -- this function is
            # reached some other way (indirect dispatch through a relocated/
            # runtime-computed pointer, or a jump table with relative
            # entries). Log LR (caller's return address, i.e. roughly where
            # the call site is) and r0 (candidate "this" if this is a
            # virtual call) every time this function is entered, to find
            # the call site empirically instead of via a static literal
            # search that came up empty.
            lr = uc.reg_read(UC_ARM_REG_LR)
            r0 = uc.reg_read(UC_ARM_REG_R0)
            print(f"[FN-422B28-ENTRY] insn#{ctx.insn_count[0]} lr={hex(lr)} r0={hex(r0)} "
                  f"module_index_seen={module_index_seen[0]}", flush=True)

        # v228 opt-in A/B diagnostic. Supply one known label without
        # altering the widget, rasterizer, atlas, or blit pipeline.
        if args.text35_fallback and address == 0x48D924:
            if uc.reg_read(UC_ARM_REG_R0) == 0x35:
                try:
                    holder = struct.unpack("<I", uc.mem_read(0x9933DC, 4))[0]
                    if holder:
                        uc.mem_write(holder, b"Name Your Sim\0")
                        uc.reg_write(UC_ARM_REG_R0, holder)
                        uc.reg_write(UC_ARM_REG_PC, uc.reg_read(UC_ARM_REG_LR))
                        ctx.text35_fallback_hits += 1
                        print(f"[TEXT35-FALLBACK] insn#{ctx.insn_count[0]} buffer={hex(holder)}", flush=True)
                        return
                except Exception as exc:
                    print(f"[TEXT35-FALLBACK-FAIL] {exc}", flush=True)

        if pm.dispatch(ctx, uc, address):
            return

        if address in thunk_set:
            dll, ordv = thunk_map[address]
            lr = uc.reg_read(UC_ARM_REG_LR)
            handler = thunk_dispatch.get(address, None)
            if handler is None:
                unimplemented_thunk_hits[(dll, ordv)] += 1
                if (dll, ordv) not in unimplemented_thunk_first_lr:
                    unimplemented_thunk_first_lr[(dll, ordv)] = (ctx.insn_count[0], hex(lr))
                handler = runtime_imports.default_stub
                # v219 NEW (madde: WS32:0x80/0xa7 out-param characterization):
                # these two are the highest-impact unimplemented ordinals with
                # a confirmed out-parameter pointer in R1 (v218). Watch a
                # short window of reads on that exact buffer right as the
                # (currently no-op) call returns, so we can see WHO reads it
                # next and at WHICH byte offsets -- revealing the buffer's
                # real size/shape without guessing. Pure observation.
                if research is not None and address in (0x4966C4, 0x4966A4) and ws32_outparam_watch_count[address] < 8:
                    r1 = uc.reg_read(UC_ARM_REG_R1)
                    if r1 != 0:
                        ws32_outparam_watch_count[address] += 1
                        research.register_read_watch(uc, ctx, r1, size=0x20, duration=5000)
            handler(ctx, uc)
            uc.reg_write(UC_ARM_REG_PC, lr)
            return

        if address == load_info["return_sentinel_va"]:
            print(f"[STOPPED] execution returned past the top-level call frame "
                  f"after {ctx.insn_count[0]} instructions.", flush=True)
            uc.emu_stop()
            return

        if diagnostics is not None:
            diagnostics.dispatch(ctx, uc, address)
            research.expire_read_watches(uc, ctx)

        try:
            cur = struct.unpack("<I", uc.mem_read(patches_mod.MODULE_INDEX_GLOBAL, 4))[0]
        except Exception:
            cur = None
        if ready_flag is not None and not ready_flag[0] and cur == 5:
            ready_flag[0] = True
            print(f"[research] module 5 reached at insn#{ctx.insn_count[0]} -- releasing scripted key sequence", flush=True)
        if cur != module_index_seen[0]:
            print(f"[MODULE-INDEX-CHANGE] insn#{ctx.insn_count[0]} {module_index_seen[0]} -> {cur}", flush=True)
            module_index_seen[0] = cur

        if snapshot_recorder is not None:
            snapshot_recorder.maybe_snapshot(ctx.insn_count[0])

        # v216 NEW (madde 10 continuation): targeted before/after framebuffer
        # snapshots bracketing the insn~90.3M window where v215 found the
        # masked-bitmap "N-item draw" loop fires with 7 items during module
        # 19 (matching v214's x=1-25,y=141/149 write cluster). Bracket is
        # wide (90.30M/90.45M) to safely cover the whole burst regardless of
        # small run-to-run insn drift. Pure observation -- writes a .bin
        # snapshot to out_dir, no game state touched.
        if fb_watcher is not None and TARGETED_SNAPSHOT_INSNS and ctx.insn_count[0] in TARGETED_SNAPSHOT_INSNS:
            TARGETED_SNAPSHOT_INSNS.discard(ctx.insn_count[0])
            try:
                snap = fb_watcher.snapshot()
                import os
                os.makedirs(args.out_dir, exist_ok=True)
                fname = os.path.join(args.out_dir, f"targeted_snapshot_insn{ctx.insn_count[0]}.bin")
                with open(fname, "wb") as f:
                    f.write(snap)
                print(f"[TARGETED-SNAPSHOT] insn#{ctx.insn_count[0]} written to {fname}", flush=True)
            except Exception as e:
                print(f"[TARGETED-SNAPSHOT-FAIL] insn#{ctx.insn_count[0]} err={e}", flush=True)

        if ctx.insn_count[0] % 1_000_000 == 0:
            print(f"[heartbeat] insn#{ctx.insn_count[0]} module_index={cur}", flush=True)

        if ctx.insn_count[0] >= args.max_insn:
            print(f"[STOPPED] reached --max-insn={args.max_insn} at insn#{ctx.insn_count[0]}", flush=True)
            uc.emu_stop()

    def hook_mem_write(uc, access, address, size, value, user_data):
        if fb_watcher is not None:
            fb_watcher.on_write(address, size, value)
        if fb_watcher is not None and FRAMEBUFFER_WATCH_LO <= address < FRAMEBUFFER_WATCH_HI:
            # v213 NEW (user-directed): 0x402118/0x48dee0 turned out to be
            # position-SETTERS (str r1,[this+0x18/0x1c/0x20/0x24]; bx lr --
            # no memory write anywhere near the framebuffer), not the
            # actual pixel blit. This watch instead looks at the FRAMEBUFFER
            # region directly and records the PC of every distinct
            # instruction address that ever writes there -- this is the
            # only reliable way to find the real draw/blit routine(s),
            # since we were tracing the wrong call chain. Capped per-PC to
            # avoid flooding (the panel/wallpaper writes constantly).
            pc = uc.reg_read(UC_ARM_REG_PC)
            lr = uc.reg_read(UC_ARM_REG_LR)
            cnt = fb_write_pc_counts.get(pc, 0)
            fb_write_pc_counts[pc] = cnt + 1
            # v215 NEW (user's item 8: convert every real FB write to x/y and
            # bucket by region). CORRECTED x/y: the old approx_xy below has a
            # bug -- it takes (byte_offset % 176) instead of
            # ((byte_offset // 2) % 176), which for 16bpp pixels silently
            # doubles x and wraps it at x=88 instead of x=176 (y happens to
            # come out right by coincidence of the /176//2 order). This is a
            # log-accuracy fix only (diagnostic code, not game behavior) --
            # per-PC running bounding box + centroid, O(1)/write, safe to
            # keep for the FULL run (not capped/gated like the prints below).
            pix_off = (address - FRAMEBUFFER_WATCH_LO) // 2
            x_true = pix_off % 176
            y_true = pix_off // 176
            rs = fb_write_region_stats.get(pc)
            if rs is None:
                rs = {"n": 0, "xmin": x_true, "xmax": x_true, "ymin": y_true, "ymax": y_true,
                      "sumx": 0, "sumy": 0}
                fb_write_region_stats[pc] = rs
            rs["n"] += 1
            rs["sumx"] += x_true
            rs["sumy"] += y_true
            if x_true < rs["xmin"]:
                rs["xmin"] = x_true
            if x_true > rs["xmax"]:
                rs["xmax"] = x_true
            if y_true < rs["ymin"]:
                rs["ymin"] = y_true
            if y_true > rs["ymax"]:
                rs["ymax"] = y_true
            # v213b NEW: the original cap<3 (per unique PC) meant every one
            # of the 178 distinct writer PCs got its budget used up by
            # insn~9.8M (early boot/other-screen writes), leaving ZERO
            # [FB-WRITE-PC] visibility during the insn~95-115M window where
            # widget_dispatch_entry/text_draw_candidate showed slot7/slot11
            # actually firing. Fix: once past LATE_WINDOW_INSN, log
            # uncapped (bounded only by a generous sanity ceiling) so we can
            # see exactly which PCs write during real text-widget activity.
            late = ctx.insn_count[0] >= 85_000_000
            if cnt < 3 or (late and late_fb_write_counter[0] < 20000):
                if late and cnt >= 3:
                    late_fb_write_counter[0] += 1
                x = (address - FRAMEBUFFER_WATCH_LO) % 176
                y = (address - FRAMEBUFFER_WATCH_LO) // 176 // 2
                tag = " LATE" if late else ""
                print(f"[FB-WRITE-PC]{tag} insn#{ctx.insn_count[0]} pc={hex(pc)} lr={hex(lr)} "
                      f"addr={hex(address)} approx_xy=({x},{y}) true_xy=({x_true},{y_true}) "
                      f"value={hex(value)} size={size}",
                      flush=True)
        if address == patches_mod.MODULE_INDEX_GLOBAL:
            pc = uc.reg_read(UC_ARM_REG_PC)
            lr = uc.reg_read(UC_ARM_REG_LR)
            print(f"[MODULE-INDEX-WRITE] insn#{ctx.insn_count[0]} value={value} pc={hex(pc)} lr={hex(lr)}",
                  flush=True)
        if address == 0xA16B24:
            pc = uc.reg_read(UC_ARM_REG_PC)
            lr = uc.reg_read(UC_ARM_REG_LR)
            print(f"[PENDING-STATE-WRITE] insn#{ctx.insn_count[0]} value={value} pc={hex(pc)} lr={hex(lr)}",
                  flush=True)
        if address == 0xA16AFC:
            pc = uc.reg_read(UC_ARM_REG_PC)
            lr = uc.reg_read(UC_ARM_REG_LR)
            print(f"[SELECTOR-WRITE] insn#{ctx.insn_count[0]} value={value} pc={hex(pc)} lr={hex(lr)}",
                  flush=True)
        if address == 0xA16B04:
            # v206 NEW: static trace of module 19's entry constructor
            # (0x4225ec) and the function right after it (0x422794) found
            # that 0x422794 is a MASTER PHASE DISPATCHER -- it reads
            # *(MODULE_INDEX_GLOBAL+0x10) == *(0xA16B04) (zeroed to 0 by
            # the constructor) and, via a 15-entry jump table (indices
            # 0-14), tail-calls one of 15 "phase handler" functions. Index
            # 9 -> 0x423b38 and index 10 -> 0x423e74 are EXACTLY the two
            # functions that (via the SEPARATE 0xA16B08 countdown) crash
            # on table slots 1/7. Index 2 -> 0x4254a0 (the slot 12-14
            # cleanup). Indices 0,1,3,4,5,6,8,11,12 point to UNEXPLORED
            # handlers (0x4247f8, 0x424c68, 0x422ec8, 0x4238dc, 0x4244d4,
            # 0x422ff4, 0x42321c, 0x424558, 0x424654) -- any one of these
            # could be the real "construct slots 0-10" step. Watching this
            # phase index's writes shows the FULL progression (0->1->...->9)
            # and lets us correlate each phase with what it does/doesn't
            # construct.
            pc = uc.reg_read(UC_ARM_REG_PC)
            lr = uc.reg_read(UC_ARM_REG_LR)
            print(f"[PHASE-INDEX-WRITE] insn#{ctx.insn_count[0]} value={value} pc={hex(pc)} lr={hex(lr)}",
                  flush=True)

        if patches_mod.MODULE_INDEX_GLOBAL <= address < patches_mod.MODULE_INDEX_GLOBAL + 0x20 \
                and address != 0xA16B04:
            # v207 NEW (user-directed): the exact-address 0xA16B04 watch
            # above never fires between phase-0 and phase-1 dispatch in
            # live testing (phase reads as 0 at 0x422794's entry, but the
            # very next handler entered is phase-1's 0x424c68, only 7
            # instructions later) -- yet 0x4247f8's own body only writes
            # +0x10 when substate(+0x14)==0, which never happens in our
            # traces (substate stays in 15-31). So SOMETHING ELSE, at some
            # OTHER address, is setting the phase field -- possibly via a
            # multi-register store (stm) whose reported base address
            # isn't exactly 0xA16B04, or via a completely different call
            # site we haven't found yet. This widened window watch (the
            # whole MODULE_INDEX_GLOBAL struct minus the already-covered
            # exact fields) is a blunt but reliable way to catch it,
            # exactly like the 0x8d79d4/window-vs-exact-address lesson
            # from v205/v206.
            pc = uc.reg_read(UC_ARM_REG_PC)
            lr = uc.reg_read(UC_ARM_REG_LR)
            off = address - patches_mod.MODULE_INDEX_GLOBAL
            print(f"[MODIDX-STRUCT-WRITE] insn#{ctx.insn_count[0]} off={hex(off)} addr={hex(address)} "
                  f"value={hex(value)} size={size} pc={hex(pc)} lr={hex(lr)}", flush=True)

        if address == 0xA16B08:
            # v205 NEW: 0xA16AF4+0x14, the field read/decremented by the
            # 0x423b38/0x423e74 family of per-substate "reveal widget N"
            # handlers (see the SUBSTATE-DISPATCH-ENTRY watch above).
            # Watching every write shows both the INITIAL value this
            # countdown starts at (which handler/constructor sets it, and
            # when relative to the module 5->19 transition) and each
            # decrement step, so we can reconstruct the full scripted
            # sequence length and confirm/refute the "counts down once per
            # tick, one widget revealed per step" theory.
            pc = uc.reg_read(UC_ARM_REG_PC)
            lr = uc.reg_read(UC_ARM_REG_LR)
            print(f"[SUBSTATE-WRITE] insn#{ctx.insn_count[0]} value={value} pc={hex(pc)} lr={hex(lr)}",
                  flush=True)

        if 0x9E3CB0 <= address < 0x9E3D00:
            # v210 NEW (user-directed follow-up to v209): the user confirmed
            # the REAL required flow is simple -- type any one letter, then
            # press Done -- which reframes our job as finding what actually
            # WRITES the phase1/phase3 "flag" halfwords (0x9e3cb4/0x9e3c90)
            # that v209 found are a dynamic, mostly-zero, occasionally-
            # pulsing pending-input signal rather than a static per-cell
            # table. No watch has ever fired on this address range before --
            # this pins down the producer (who, how often, under what
            # condition) so we can finally align our key-injection timing
            # with its actual write cadence instead of guessing.
            pc = uc.reg_read(UC_ARM_REG_PC)
            lr = uc.reg_read(UC_ARM_REG_LR)
            print(f"[FLAG-TABLE-WRITE] insn#{ctx.insn_count[0]} addr={hex(address)} "
                  f"value={hex(value)} size={size} pc={hex(pc)} lr={hex(lr)}", flush=True)

        if address in (0xA16B30, 0xA16B34, 0x8D7A14, 0x8D7A34):
            # v205: two more fields adjacent to (but not part of) the
            # 0xA16B3C table -- 0xA16B30/0xA16B34 -- get resource IDs
            # 0x87/0x88 stamped by function 0x4254a0 (immediately after
            # 0x425278's slot 11-16 construction), and a separate pair
            # 0x8d7a14/0x8d7a34 (count + table-base pointer) drive a loop
            # inside that same function that looks like a second
            # construction pass. Watching writes to all four pins down
            # exactly when (if ever) that second pass populates anything.
            pc = uc.reg_read(UC_ARM_REG_PC)
            lr = uc.reg_read(UC_ARM_REG_LR)
            print(f"[PHASE2-FIELD-WRITE] insn#{ctx.insn_count[0]} addr={hex(address)} "
                  f"value={hex(value)} size={size} pc={hex(pc)} lr={hex(lr)}", flush=True)

        if address == 0x8D79D4:
            # v205 NEW: explicit, direct watch on 0x8d79d4 itself (the
            # user asked for this specifically). It's the r3 side of
            # 0x422b28's guard condition (r2=*(0x9e3548), r3=*(0x8d79d4));
            # live-measured as r3=1 in v203/v204 but its WRITER was never
            # found. This pins down exactly when/where/by what code it is
            # ever set, across the whole run.
            pc = uc.reg_read(UC_ARM_REG_PC)
            lr = uc.reg_read(UC_ARM_REG_LR)
            try:
                cur_mod = struct.unpack("<I", uc.mem_read(patches_mod.MODULE_INDEX_GLOBAL, 4))[0]
            except Exception:
                cur_mod = None
            print(f"[8D79D4-WRITE] insn#{ctx.insn_count[0]} value={value} pc={hex(pc)} lr={hex(lr)} "
                  f"module_index={cur_mod}", flush=True)

        if 0x9E3510 <= address < 0x9E3560:
            # v203 follow-up: 0x422b28's guard condition compares
            # *(0x9e3528+0x20) == *(0x8d79d4). 0x9e3528 sits in BSS
            # (zero-init at load, confirmed via runtime/loader.py's BSS
            # segment range 0x8D7000-0xB2CE00), so it's a legitimate
            # global struct/singleton, not a stray heap address. Watching
            # a generous window around it (not just the one +0x20 field)
            # shows the object's full construction/update history --
            # who writes it, when, and whether +0x20 specifically is ever
            # touched anywhere in the whole run.
            pc = uc.reg_read(UC_ARM_REG_PC)
            lr = uc.reg_read(UC_ARM_REG_LR)
            try:
                cur_mod = struct.unpack("<I", uc.mem_read(patches_mod.MODULE_INDEX_GLOBAL, 4))[0]
            except Exception:
                cur_mod = None
            off = address - 0x9E3528
            print(f"[GUARDOBJ-WRITE] insn#{ctx.insn_count[0]} obj_off={hex(off)} addr={hex(address)} "
                  f"value={hex(value)} size={size} pc={hex(pc)} lr={hex(lr)} module_index={cur_mod}",
                  flush=True)

        if 0xA16B3C <= address < 0xA16B80:
            # v200 follow-up: static trace of the 0x422b28 function shows
            # 0xA16B3C holds a POINTER to the object whose method chain
            # (0x422c0c -> 0x401dbc -> 0x401e50) performs the poisoning
            # write at addr=0xdc when that pointer is still NULL. Further
            # static analysis (0x44c0ec) showed 0xA16B3C is slot 0 of a
            # 17-slot global "active screen widget" table (0xA16B3C ..
            # 0xA16B80), all zeroed together on every screen transition.
            # Watching the WHOLE table (not just slot 0) shows whether
            # ANY slot gets repopulated after the module 5->19 transition,
            # and if so, whether slot 0 specifically is the one being
            # skipped (index confusion) or the whole table stays empty
            # (nothing re-constructs module 19's widgets at all).
            pc = uc.reg_read(UC_ARM_REG_PC)
            lr = uc.reg_read(UC_ARM_REG_LR)
            slot = (address - 0xA16B3C) // 4
            print(f"[SCREEN19-TABLE-WRITE] insn#{ctx.insn_count[0]} slot={slot} addr={hex(address)} "
                  f"value={hex(value)} pc={hex(pc)} lr={hex(lr)}", flush=True)
        if 0 <= address < 0x10000:
            # v199: this branch is how a stray write of 0x4af288 to address
            # 0xdc silently poisoned the shared zero page, later misread as
            # a vtable slot by a different, unrelated null "this" -- this
            # is the exact bug that produced the 0x4af28c crash.
            # v202 FIX: nullguard_page is no longer mapped WRITABLE (see
            # patches.py::_setup_nullguard), so a write here can no longer
            # actually succeed -- Unicorn now raises UC_ERR_WRITE_PROT
            # *before* UC_HOOK_MEM_WRITE would fire, which routes it to
            # hook_mem_invalid below (logged as [NULL-WRITE-BLOCKED]) and
            # then a genuine, unhandled emulation-stopping exception,
            # instead of a silent, undetectable memory corruption. This
            # branch is kept as a defense-in-depth trip-wire: if it EVER
            # fires again, something re-granted write permission on the
            # nullguard page and that itself is a bug to investigate.
            pc = uc.reg_read(UC_ARM_REG_PC)
            lr = uc.reg_read(UC_ARM_REG_LR)
            print(f"[NULLGUARD-POISON-WRITE] insn#{ctx.insn_count[0]} addr={hex(address)} "
                  f"value={hex(value)} size={size} pc={hex(pc)} lr={hex(lr)} "
                  f"UNEXPECTED-this-should-be-unreachable-since-v202", flush=True)

    def hook_module5_input_mem(uc, access, address, size, value, user_data):
        pc = uc.reg_read(UC_ARM_REG_PC)
        kind = "write" if access == 17 else "read"  # UC_MEM_WRITE == 17
        module5_input_stats[(kind, address, pc)] += 1
        module5_input_stats[kind] += 1
        if len(module5_input_examples) < 300:
            try:
                observed = bytes(uc.mem_read(address, size)).hex()
            except Exception:
                observed = None
            example = (ctx.insn_count[0], kind, address, size, value, pc, observed)
            module5_input_examples.append(example)
            print(f"[MODULE5-INPUT-MEM] insn#{ctx.insn_count[0]} {kind} "
                  f"addr={hex(address)} size={size} value={hex(value)} "
                  f"pc={hex(pc)} observed={observed}", flush=True)

    def hook_mem_invalid(uc, access, address, size, value, user_data):
        pc = uc.reg_read(UC_ARM_REG_PC)
        lr = uc.reg_read(UC_ARM_REG_LR)
        if 0 <= address < 0x10000:
            # v202: this is now the PRIMARY, expected way a write-through-
            # null in the 0x0-0xFFFF nullguard page shows up -- treated as
            # a real, hard fault (this callback returns False below, so
            # unicorn raises and emulation stops here, matching what real
            # hardware would do on a null-pointer write).
            print(f"[NULL-WRITE-BLOCKED] insn#{ctx.insn_count[0]} pc={hex(pc)} lr={hex(lr)} "
                  f"access={access} addr={hex(address)} size={size} value={value}", flush=True)
        print(f"[FAULT] insn#{ctx.insn_count[0]} pc={hex(pc)} lr={hex(lr)} access={access} addr={hex(address)} size={size}")
        return False

    uc.hook_add(UC_HOOK_CODE, hook_code)
    uc.hook_add(UC_HOOK_MEM_INVALID, hook_mem_invalid)
    if fb_watcher is not None:
        uc.hook_add(UC_HOOK_MEM_WRITE, hook_mem_write)
    if getattr(args, "module5_input_trace", False):
        uc.hook_add(UC_HOOK_MEM_READ | UC_HOOK_MEM_WRITE, hook_module5_input_mem,
                    begin=0x9E3C90, end=0x9E3D1F)

    return uc, ctx, pm, thunk_map, snapshot_recorder, module_index_seen, trace, diagnostics, fb_write_pc_counts, fb_write_region_stats, unimplemented_thunk_hits, unimplemented_thunk_first_lr


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--binary-file", default=BINARY_PATH,
                    help="Path to a locally supplied, legally obtained game binary. "
                         "The binary is not distributed with this project.")
    ap.add_argument("--max-insn", type=int, default=40_000_000)
    ap.add_argument("--disable-patch", action="append", default=[])
    ap.add_argument("--research", action="store_true")
    ap.add_argument("--name-screen-mode", default="isolate_open_only",
                     choices=["full_probe", "isolate_5", "isolate_open_only", "periodic_reopen",
                              "letter_grid_wander", "letter_then_done_burst",
                              "letter_then_done_edges", "letter_then_done_edges_v2",
                              "letter_then_done_user_sequence",
                              "letter_then_done_user_sequence_repeated",
                              "letter_then_done_user_sequence_long"])
    ap.add_argument("--menu-select-probe", default=None,
                     choices=["select_top_item"])
    ap.add_argument("--nav-variant", default="no_stray_downs",
                     choices=["default", "no_stray_downs"])
    ap.add_argument("--snapshot-interval", type=int, default=100_000)
    ap.add_argument("--out-dir", default=".")
    ap.add_argument("--trace-depth", type=int, default=64,
                     help="Keep a rolling window of the last N executed addresses "
                          "for a full crash dump on an unhandled fault (0 disables).")
    ap.add_argument("--crash-dump-path", default=None,
                     help="If set, also write the full crash-context dump to this file.")
    ap.add_argument("--idle-wait-experiment", action="store_true",
                     help="v204: after reaching module 19, idle on pure EEVENT_NULL "
                          "(no synthetic keys) until --idle-wait-until-insn, then send "
                          "exactly one --idle-wait-post-key. Tests whether table slots "
                          "0-10 populate given enough idle time.")
    ap.add_argument("--idle-wait-until-insn", type=int, default=56_000_000,
                     help="Instruction count to idle-wait until, when --idle-wait-experiment is set.")
    ap.add_argument("--idle-wait-post-key", default="right",
                     help="Single key to send after the idle wait, when --idle-wait-experiment is set.")
    ap.add_argument("--async-request-model", action="store_true",
                     help="v221 EXPERIMENTAL, opt-in (default OFF): cooperative "
                          "WaitForAnyRequest/RequestComplete/TRequestStatus model "
                          "(runtime/async_model.py), separate from and NOT silently "
                          "folded into event_poll_gate/event_alt_escape/tick_escape. "
                          "First prototype, not a final solution -- see v221 report.")
    ap.add_argument("--sync-key-injector", action="store_true",
                     help="v223 EXPERIMENTAL, opt-in (default OFF, requires "
                          "--async-request-model): replaces the fixed-timer scripted "
                          "key refill with runtime/sync_injector.py's state-synchronized "
                          "phase1+phase2 sequencer (5,down,down,down,5 then "
                          "5,right x10,down,right x10,down,right x7,5,5) -- each key "
                          "is only sent after the previous key's full down/key/up burst "
                          "was confirmed consumed by GetEvent AND a fresh EventReady "
                          "reached PENDING again. --name-screen-mode/--menu-select-probe/ "
                          "--nav-variant are IGNORED when this is set (the injector owns "
                          "the entire key sequence, including the module-5 approach nav).")
    ap.add_argument("--sync-skip-nav", action="store_true",
                     help="v231 A/B mode (requires --sync-key-injector): begin the "
                          "device-confirmed phase-1 sequence immediately when module 5 "
                          "is reached, without replaying the historical boot-to-module-5 "
                          "NAV sequence or its right/left panel filler after that boundary.")
    ap.add_argument("--sync-nav-mode", choices=("full", "menu", "none"), default="full",
                     help="v231 synchronized pre-phase input A/B: 'full' preserves the "
                          "historical menu sequence plus 40 right/left filler taps; 'menu' "
                          "keeps only the menu sequence; 'none' starts phase 1 at module 5. "
                          "--sync-skip-nav is retained as an alias for 'none'.")
    ap.add_argument("--key-dispatch-trace", action="store_true",
                     help="v231 observation: log the first 200 translated-key vtable "
                          "dispatches at 0x444b8c, including target and TWsEvent fields.")
    ap.add_argument("--key-state-read-trace", action="store_true",
                     help="v232 observation (use with --key-dispatch-trace): install "
                          "byte-precise read watchpoints on the live mapped-game-key and "
                          "raw pressed-state fields discovered at 0x438340.")
    ap.add_argument("--module4-lifecycle-trace", action="store_true",
                    help="v232 observation: trace module 4's natural state machine, "
                         "attempt counter, timer expiry, helper calls and module-5 request.")
    ap.add_argument("--module5-input-trace", action="store_true",
                    help="v232 observation: trace module 5's real global key-mask table "
                         "(0x9E3C90..0x9E3D1F), selected key and update-loop reads/writes.")
    ap.add_argument("--module5-action-trace", action="store_true",
                    help="v233 observation: trace the first module-5 Select action through "
                         "0x48F064 and back to the shared module dispatcher.")
    ap.add_argument("--sync-min-gap-insn", type=int, default=0,
                     help="v231: after a key is fully consumed, require this many "
                          "instructions of UI processing in addition to a fresh pending "
                          "EventReady before sending the next synchronized key.")
    ap.add_argument("--sync-key-hold-insn", type=int, default=0,
                     help="v231: delay production of each raw KeyUp by this many "
                          "instructions after Down/translated-Key are queued, allowing "
                          "the game's polling loop to observe the pressed state.")
    ap.add_argument("--sync-first-key-hold-insn", type=int, default=None,
                    help="v233: optional hold duration only for phase-1 key #1. "
                         "The first module-5 input scan occurs much later than steady-state; "
                         "subsequent keys continue using --sync-key-hold-insn.")
    ap.add_argument("--sync-release-on-game-scan", action="store_true",
                    help="v233: treat --sync-key-hold-insn as a maximum; release the "
                         "current key as soon as game code at 0x4305FC produces a "
                         "non-zero press-edge mask.")
    ap.add_argument("--max-keys", type=int, default=None,
                     help="v224: hard cap on how many keys runtime/sync_injector.py's "
                          "SyncKeyInjector will EVER send from its phase1+phase2 sequence, "
                          "regardless of game state (requires --sync-key-injector). "
                          "max-keys=1 sends ONLY phase1's first '5' and then permanently "
                          "idles (SINGLE_KEY_HALT state) -- the mode the user's v224 "
                          "instruction (madde 8) mandates for root-cause isolation: never "
                          "send a second key until the first key's lifecycle break point "
                          "is proven. Default None preserves v223's full-sequence behavior.")
    ap.add_argument("--lifecycle-trace", action="store_true",
                     help="v224 EXPERIMENTAL, opt-in (default OFF, requires "
                          "--async-request-model): attach runtime/lifecycle_trace.py's "
                          "LifecycleTracer, which independently logs each stage of the "
                          "FIRST scancode=0x35 ('5') key's lifecycle (generated -> "
                          "enqueued -> EventReady completed -> WaitForAnyRequest woke -> "
                          "GetEvent called -> GetEvent returned -> handler entered -> "
                          "key interpreted -> injector-acknowledged), using distinct "
                          "counters for each stage, plus periodic PC/SP/LR/module "
                          "sampling and full fcn.00448424/fcn.004484e8 bitmap-call "
                          "instrumentation (entry/loop-iterations/return, LR, params). "
                          "Purely observational -- adds no patch, skips nothing, forces "
                          "no return, and does not change what counts as consumed.")
    ap.add_argument("--wait-trace", action="store_true",
                     help="v225 EXPERIMENTAL, opt-in (default OFF, requires "
                          "--async-request-model): attach runtime/wait_trace.py's "
                          "WaitTracer, which gives every WaitForAnyRequest call a "
                          "monotonic wait_id and records: entry PC/LR/SP, the TRequestStatus "
                          "address+value at entry, pending request ids, event queue/FIFO "
                          "length, whether the wake was genuine, the return PC, the first "
                          "up to 50 ARM instructions after return (PC + decoded CPSR N/Z/C/V "
                          "+ r0/r3/ip), whether GetEvent-dispatch (fcn.00444838) and the "
                          "real GetEvent thunk were reached, and whether a new Wait was "
                          "re-entered within the capture window. Also keeps ALWAYS-ON "
                          "pump_entry_count/pump_loop_body_entered_count counters (is "
                          "fcn.00444750 still being invoked at all, and does it still "
                          "reach its own loop body) plus per-entry this+0x4c/this+0x50 "
                          "snapshots (fcn.00444838 Slot 2's own gating fields, for direct "
                          "comparison against this+0x54, the address EventReady completion "
                          "itself writes). Purely observational -- no branch patch, no PC "
                          "skip, no forced GetEvent call, no queue drain.")
    ap.add_argument("--archive-read-log", action="store_true",
                     help="v227 EXPERIMENTAL, opt-in (default OFF): log every real "
                          "ESTLIB:fread(thesims.dat) call the game makes (insn count, "
                          "file offset, requested/returned length, calling LR) to "
                          "runtime/archive.py's ctx.archive_read_log. DTRZ Stream B "
                          "(compressed-entry) research -- lets us see live which byte "
                          "ranges of the archive the game actually reads, instead of "
                          "guessing. Purely observational, read-only.")
    ap.add_argument("--archive-file", default=None,
                    help="v234: explicit local backing path for thesims.dat. "
                         "Avoids relying on the historical transient /tmp/ngage path.")
    ap.add_argument("--save-file", default=None,
                    help="v233: local backing file for the game's proven "
                         "C:\\SYSTEM\\APPS\\6RAK\\THESIMS.SAV path. The game may "
                         "open this file r+b, so use a disposable test copy.")
    ap.add_argument("--text35-fallback", action="store_true",
                    help="v228 EXPERIMENTAL A/B, opt-in (default OFF): return "
                         "'Name Your Sim' for empty language string id 0x35. "
                         "Tests the existing widget/raster/blit path; this is "
                         "not a replacement for the missing codec provider.")
    args = ap.parse_args()
    print(f"[run] parsed args: {vars(args)}", flush=True)

    if not os.path.isfile(args.binary_file):
        ap.error("required local game binary not found; pass --binary-file PATH "
                 "to a legally obtained copy")

    uc, ctx, pm, thunk_map, snapshot_recorder, module_index_seen, trace, diagnostics, fb_write_pc_counts, fb_write_region_stats, unimplemented_thunk_hits, unimplemented_thunk_first_lr = build(args)

    try:
        # NOTE: `until` is the address where uc_emu_start() STOPS THE
        # EMULATION THE MOMENT IT'S HIT (per unicorn.h) -- it is not a
        # harmless "don't care" sentinel. Passing 0 here silently ends the
        # run, with a clean UC_ERR_OK, the instant the emulated PC becomes
        # exactly 0x0 (e.g. a null function/vtable-pointer call) -- no
        # fault, no exception, nothing for our hooks to see. That is
        # exactly what was happening: runs were stopping at insn#2420633
        # with zero [FAULT]/[STOPPED]/[HOOK-EXCEPTION] output because PC
        # hit 0 and unicorn considered that "done", not "crashed" -- worse,
        # the nullguard_page patch maps VA 0 as valid zeroed memory, so a
        # jump to null no longer even faults on FETCH; it just silently
        # satisfies `until`. Use an address that can never legitimately be
        # a real PC value so a genuine jump-to-null instead falls through
        # to hook_code/hook_mem_invalid like every other instruction.
        uc.emu_start(0x401000, 0xFFFFFFFF, timeout=0, count=0)
    except Exception as e:
        pc = uc.reg_read(UC_ARM_REG_PC)
        lr = uc.reg_read(UC_ARM_REG_LR)
        print(f"[STOPPED] {e} at PC={hex(pc)} LR={hex(lr)} after {ctx.insn_count[0]} instructions")
        if trace is not None:
            dump_crash_context(uc, trace, args.binary_file, thunk_map, out_path=args.crash_dump_path)

    print(f"\n=== RUN SUMMARY ===")
    print(f"instructions executed: {ctx.insn_count[0]}")
    print(f"final module index: {module_index_seen[0]}")
    print(f"patches: {json.dumps(pm.summary(), indent=1)}")
    print(f"text35 fallback hits: {ctx.text35_fallback_hits}")
    if args.module4_lifecycle_trace:
        print("\n=== module4_lifecycle_trace summary (v232) ===")
        print(f"counts: {dict(ctx.module4_trace_stats)}")
        print("examples (insn, pc, point, module, attempts, substate, timer): "
              f"{ctx.module4_trace_examples}")
    if args.module5_input_trace:
        print("\n=== module5_input_trace summary (v232) ===")
        print(f"counts: {dict(ctx.module5_input_stats)}")
        print(f"examples: {ctx.module5_input_examples}")

    if snapshot_recorder is not None:
        snapshot_recorder.dump_to_disk(args.out_dir)
        print(f"snapshots taken: {len(snapshot_recorder.timeline)}")

    if diagnostics is not None:
        r7_probe = diagnostics.probes.get("r7_dispatch_null_check")
        if r7_probe is not None and hasattr(r7_probe, "stats"):
            s = r7_probe.stats
            print(f"\n=== r7_dispatch_null_check summary ===")
            print(f"total hits: {s['total']}, null: {s['null']}, non-null: {s['total'] - s['null']}")
            print(f"non-null examples (insn, module_index, r7, r0): {s['nonnull_examples']}")
            print(f"null examples (insn, module_index, r7, r0): {s['null_examples']}")

        wd_probe = diagnostics.probes.get("widget_dispatch_entry")
        if wd_probe is not None and hasattr(wd_probe, "stats"):
            s = wd_probe.stats
            print(f"\n=== widget_dispatch_entry summary (v213) ===")
            print(f"total dispatch calls: {s['total']}")
            print(f"unique widget 'this' pointers dispatched: {len(s['by_this'])}")
            print(f"(major=[+0x4d], minor=[+0x4e]) combo counts: {dict(s['by_majorminor'])}")
            print(f"first-500 examples (insn, this, major, minor, type, module_index): {s['examples'][:50]}")

        td_probe = diagnostics.probes.get("text_draw_candidate")
        if td_probe is not None and hasattr(td_probe, "stats"):
            s = td_probe.stats
            print(f"\n=== text_draw_candidate (0x48dee0) summary (v213) ===")
            print(f"total calls: {s['total']}")
            print(f"examples: {s['examples'][:20]}")

        pc_probe = diagnostics.probes.get("position_call_count")
        if pc_probe is not None and hasattr(pc_probe, "stats"):
            print(f"\n=== position_call_count (0x402118) summary (v213) ===")
            print(f"total calls: {pc_probe.stats['total']}")

        for probe_name, label in (("blit_4bpp_entry", "0x463a38 4bpp"), ("blit_8bpp_entry", "0x464dc8 8bpp"),
                                   ("blit_8bpp_fastpath_entry", "0x464bf8 8bpp-fastpath"),
                                   ("blit_4bpp_colorkey_entry", "0x463318 4bpp-colorkey (historic panel-fade suspect)"),
                                   ("blit_unknown_sibling_entry", "0x46359c unknown sibling"),
                                   ("blit_uncharacterized_463dec_entry", "0x463dec heaviest-volume sibling")):
            bl_probe = diagnostics.probes.get(probe_name)
            if bl_probe is not None and hasattr(bl_probe, "stats"):
                s = bl_probe.stats
                print(f"\n=== {probe_name} ({label} blit) entry summary (v213b) ===")
                print(f"total calls: {s['total']}")
                print(f"unique real caller LRs: {len(s['by_lr'])}")
                print(f"by_lr counts (top 20): {dict(sorted(s['by_lr'].items(), key=lambda kv: -kv[1])[:20])}")
                print(f"first-300 examples (insn, r0, r1, r2, r3, lr, module_index): {s['examples'][:80]}")

    print(f"\n=== fb_write_pc_counts summary (v213, real framebuffer writers) ===")
    for pc, cnt in sorted(fb_write_pc_counts.items(), key=lambda kv: -kv[1]):
        print(f"  pc={hex(pc)}: {cnt} writes")

    print(f"\n=== fb_write_region_stats summary (v215, item-8 x/y footprint per writer PC, CORRECTED xy) ===")
    for pc, rs in sorted(fb_write_region_stats.items(), key=lambda kv: -kv[1]["n"]):
        cx = rs["sumx"] / rs["n"]
        cy = rs["sumy"] / rs["n"]
        print(f"  pc={hex(pc)}: n={rs['n']} bbox=x[{rs['xmin']},{rs['xmax']}] y[{rs['ymin']},{rs['ymax']}] "
              f"centroid=({cx:.1f},{cy:.1f})")

    print(f"\n=== v215 new-probe summaries ===")
    for probe_name in ("masked_bitmap_dispatcher_entry", "whole_screen_conversion_entry"):
        bl_probe = diagnostics.probes.get(probe_name) if diagnostics is not None else None
        if bl_probe is not None and hasattr(bl_probe, "stats"):
            s = bl_probe.stats
            print(f"\n--- {probe_name} (0x4879f8, real caller of the 0x487cb8 masked-bitmap dispatcher) ---")
            print(f"total calls: {s['total']}")
            print(f"unique real caller LRs: {len(s['by_lr'])}")
            print(f"by_lr counts (top 20): {dict(sorted(s['by_lr'].items(), key=lambda kv: -kv[1])[:20])}")
            print(f"first examples (insn, r0, r1, r2, r3, lr, module_index): {s['examples'][:80]}")

    sd_probe = diagnostics.probes.get("slot_text_object_deepdump") if diagnostics is not None else None
    if sd_probe is not None and hasattr(sd_probe, "stats"):
        print(f"\n--- slot_text_object_deepdump summary ---")
        print(f"objects dumped: {len(sd_probe.stats['dumped'])}  rewatch_count: {sd_probe.stats['rewatch_count']}")

    nl_probe = diagnostics.probes.get("nitem_loop_entry") if diagnostics is not None else None
    if nl_probe is not None and hasattr(nl_probe, "stats"):
        s = nl_probe.stats
        print(f"\n--- nitem_loop_entry summary (madde 10: N-item draw loop, container->count) ---")
        print(f"total items drawn (all calls): {s['total']}")
        print(f"by_container (container_ptr -> item count): "
              f"{ {hex(k): v for k, v in s['by_container'].items()} }")
        print(f"examples (insn, container, index, item_ptr, module_index, item_bytes_hex) (first 500): {s['examples']}")

    print(f"\n--- unimplemented_thunk_hits summary (r2-assisted lead: which unimplemented Symbian "
          f"imports, esp. WS32, does the game actually call during real play?) ---")
    print(f"total hits (all unimplemented ordinals, all calls): {sum(unimplemented_thunk_hits.values())}")
    print(f"by (dll, ordinal) -> count: "
          f"{ {f'{dll}:{hex(ordv)}': n for (dll, ordv), n in unimplemented_thunk_hits.most_common()} }")
    print(f"first-hit (insn, caller_lr) per (dll,ordinal): "
          f"{ {f'{dll}:{hex(ordv)}': v for (dll, ordv), v in unimplemented_thunk_first_lr.items()} }")

    wf_probe = diagnostics.probes.get("widget_factory_entry") if diagnostics is not None else None
    if wf_probe is not None and hasattr(wf_probe, "stats"):
        s = wf_probe.stats
        print(f"\n--- widget_factory_entry summary (madde 4: who builds type=0x85/0x9 slot 7/11 widgets) ---")
        print(f"total widgets built (all types, all calls): {s['total']}")
        print(f"by_r0 (type_index -> count): {dict(sorted(s['by_r0'].items(), key=lambda kv: -kv[1]))}")
        print(f"unique caller LRs (all types): {len(s['by_lr'])}")
        print(f"slot7/11 (type 0x85 or 0x9) examples (insn, r0, r1, r2, r3, lr, module_index): {s['slot7_11_examples']}")
        print(f"first examples, any type (insn, r0, r1, r2, r3, lr, module_index) (first 200): {s['examples'][:200]}")

    s11_probe = diagnostics.probes.get("slot11_group_ctor_entry") if diagnostics is not None else None
    if s11_probe is not None and hasattr(s11_probe, "stats"):
        s = s11_probe.stats
        print(f"\n--- slot11_group_ctor_entry summary (madde 4: real caller of 0x425278, slot 11 text-widget builder) ---")
        print(f"total calls: {s['total']}")
        print(f"by_lr: {dict(s['by_lr'])}")
        print(f"examples (insn, lr, module_index, module_index_global_plus4): {s['examples']}")

    mc_probe = diagnostics.probes.get("ws32_magic_check") if diagnostics is not None else None
    if mc_probe is not None and hasattr(mc_probe, "stats"):
        s = mc_probe.stats
        print(f"\n--- ws32_magic_check summary (WS32:0xa7 out-param [obj+4]==0x80000001 check, whole run) ---")
        print(f"total checks: {s['total']}  matches_magic: {s['matches_magic']}  "
              f"mismatch_rate: {(s['total']-s['matches_magic'])/s['total'] if s['total'] else 'n/a'}")
        print(f"examples (insn, obj_ptr, observed_val_at_plus4) (first 30): {s['examples']}")

    vt_probe = diagnostics.probes.get("ws32_vtable_call") if diagnostics is not None else None
    if vt_probe is not None and hasattr(vt_probe, "stats"):
        s = vt_probe.stats
        print(f"\n--- ws32_vtable_call summary (the vtable+0x10 call gated by the magic check, whole run) ---")
        print(f"total calls reached: {s['total']}")
        print(f"by_target (vtable slot value -> count): {dict(s['by_target'])}")
        print(f"examples (insn, this=r0, vtable_ptr=r2, target=ip) (first 30): {s['examples']}")

    lp_probe = diagnostics.probes.get("loop_pump_entry") if diagnostics is not None else None
    if lp_probe is not None and hasattr(lp_probe, "stats"):
        s = lp_probe.stats
        print(f"\n--- loop_pump summary (fcn.00444750: WaitForAnyRequest+RunIfReady pump loop, whole run) ---")
        print(f"entries: {s['entries']}  exits: {s['exits']}  max_iters_in_one_call: {s['max_iters']}")
        print(f"iters_histogram (iters -> how many calls took that many loop passes): {dict(s['iters_histogram'])}")
        print(f"per-call examples (first 100): {s['calls']}")

    rc_probe = diagnostics.probes.get("pump_request_complete_call") if diagnostics is not None else None
    if rc_probe is not None and hasattr(rc_probe, "stats"):
        s = rc_probe.stats
        print(f"\n--- pump_request_complete_call summary (RThread::RequestComplete self-resolve inside the pump loop) ---")
        print(f"total calls: {s['total']}")
        print(f"examples (insn, &statusptr=r1, statusptr_value, reason=r2) (first 30): {s['examples']}")

    if getattr(ctx, "key_state_watch_addrs", None):
        print(f"\n--- v232 key_state_read_trace summary ---")
        print(f"watched addresses: {[hex(a) for a in sorted(ctx.key_state_watch_addrs)]}")
        print(f"total reads: {sum(ctx.key_state_read_stats.values())}")
        by_site = sorted(ctx.key_state_read_stats.items(), key=lambda kv: -kv[1])
        for (address, label, pc), count in by_site[:100]:
            origin = "writer/helper" if 0x438340 <= pc <= 0x4384A8 else "external consumer"
            print(f"  addr={hex(address)} label={label} reader_pc={hex(pc)} "
                  f"count={count} class={origin}")
        print(f"first examples (insn,addr,label,pc,size,value): {ctx.key_state_read_examples[:100]}")

    if getattr(ctx, "async_registry", None) is not None:
        s = ctx.async_registry.stats
        print(f"\n--- async_request_model summary (v222-b EXPERIMENTAL, --async-request-model) ---")
        print(f"WaitForAnyRequest calls: {s['wfar_calls']}  "
              f"genuine returns: {s['wfar_genuine_returns']}  "
              f"wasted/spurious returns (bosuna donus): {s['wfar_wasted_returns']}")
        print(f"WS32 hw-key registrations by kind: {s['registrations']}")
        print(f"WS32 hw-key genuine completions by kind (via v222-b enqueue/registration-time match): {s['ws32_genuine_completions']} "
              f"(NOTE: v222-b completions normally do NOT go through this legacy per-kind counter -- "
              f"see eventready_completed below for the real count)")
        print(f"RequestComplete (EUSER:0x39f) total calls: {s['request_complete_calls']}  "
              f"tracked(ws32-registered, unexpected under v222-b): {s['request_complete_tracked']}  "
              f"untracked(self-managed, e.g. pump-loop internal [this+0x80]): {s['request_complete_untracked']}")
        print(f"cancellations: {s['cancellations']}  max_concurrent_pending: {s['max_pending']}  "
              f"pending_at_end: {len(ctx.async_registry.pending)}")
        print(f"\n--- v222-b lifecycle counters (EventReady/PriorityKeyReady request <-> real-event lifecycle) ---")
        print(f"real_key_generated: {s['real_key_generated']}  event_enqueued: {s['event_enqueued']}  "
              f"event_consumed: {s['event_consumed']}")
        print(f"eventready_registered: {s['eventready_registered']}  eventready_completed: {s['eventready_completed']}")
        print(f"wait_entered: {s['wait_entered']}  wait_woken: {s['wait_woken']}  getevent_called: {s['getevent_called']}")
        print(f"duplicate_completion: {s['duplicate_completion']}  orphan_completion: {s['orphan_completion']}  "
              f"getevent_without_completion: {s['getevent_without_completion']}")
        print(f"(v222 first-attempt GetEvent-triggered-completion mechanism, superseded by v222-b: "
              f"{s['get_event_triggered_completions']} -- expected to stay 0, see async_model.py 'v222-b UPDATE')")
        print(f"(set V222_STATE_LOG=1 for full per-transition [V222-STATE] request/event logs)")

    if getattr(ctx, "lifecycle_tracer", None) is not None:
        ctx.lifecycle_tracer.print_summary()

    if getattr(ctx, "wait_tracer", None) is not None:
        ctx.wait_tracer.print_summary()

    if getattr(ctx, "archive_read_log", None) is not None:
        log = ctx.archive_read_log
        print(f"\n--- v227 archive_read_log summary (real thesims.dat fread() calls) ---")
        print(f"total fread calls: {len(log)}")
        for rec in log:
            print(f"  insn={rec['insn']} offset={rec['offset']} "
                  f"len_req={rec['length_requested']} len_ret={rec['length_returned']} "
                  f"lr={hex(rec['lr'])}")
        dump_path = os.path.join(args.out_dir, "archive_read_log.json")
        with open(dump_path, "w") as f:
            json.dump(log, f, indent=2)
        print(f"(full log written to {dump_path})")

    print(f"\n--- read_watch_registry summary (item 5: short-window reads of slot 7/11 objects) ---")
    import research_v209 as research  # local import: only meaningful for --research runs
    for this_ptr, s in research.read_watch_registry.items():
        top = dict(sorted(s["by_pc"].items(), key=lambda kv: -kv[1])[:20])
        print(f"  this={hex(this_ptr)}: total_reads={s['total']} unique_reader_pcs={len(s['by_pc'])} "
              f"top_reader_pcs={ {hex(k): v for k, v in top.items()} }")
        print(f"    examples(pc,lr,offset,size) (first 40): {s['examples'][:40]}")


if __name__ == "__main__":
    main()
