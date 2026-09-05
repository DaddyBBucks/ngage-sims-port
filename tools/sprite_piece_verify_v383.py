#!/usr/bin/env python3
"""v383: 0x4041F4 producer calls vs region_sprites parser.

Read-only diagnostic. It captures every real producer call and every OAM slot
write generated while that call is active, then checks whether the entity-side
parser can reproduce the exact producer *input state* (sprite_def/frame/
base_tile/flags). This isolates caller/state reconstruction errors before any
framebuffer/pixel comparison.

It deliberately does not patch game state or OAM.
"""
import argparse, collections, contextlib, io, os, shutil, struct, sys, tempfile
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.chdir(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from unicorn import UC_HOOK_CODE
from unicorn.arm_const import (UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2,
                               UC_ARM_REG_R3, UC_ARM_REG_SP, UC_ARM_REG_LR)
import run as R
from runtime import region_sprites as RS

PRODUCER = 0x4041F4
PRODUCER_RET_LAYER = 0x404014
PRODUCER_RET_MAIN = 0x4040B8
OAM_WRITER = 0x467124
FRAME_BOUNDARY = 0x448740
MODULE_INDEX_VA = 0xA16AF4


def u8(uc, va): return bytes(uc.mem_read(va, 1))[0]
def u16(uc, va): return struct.unpack('<H', uc.mem_read(va, 2))[0]
def u32(uc, va): return struct.unpack('<I', uc.mem_read(va, 4))[0]


def state_sig(st):
    return (st.sprite_def & 0xffffffff, st.frame & 0xffff,
            st.base_tile & 0xffff, st.producer_flags & 0xff)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--max-insn', type=int, default=220000000)
    ap.add_argument('--frames', type=int, default=25)
    ap.add_argument('--save', default='THESIMS.SAV')
    ap.add_argument('--archive', default='thesims.dat')
    a = ap.parse_args()

    tmp_dir = os.path.join(tempfile.gettempdir(), 'ngage_v383_piece')
    os.makedirs(tmp_dir, exist_ok=True)
    tmp_save = os.path.join(tmp_dir, 'v383_piece.sav')
    src_save = os.path.abspath(a.save)
    if not os.path.isfile(src_save):
        raise FileNotFoundError('Save file not found: %s' % src_save)
    shutil.copyfile(src_save, tmp_save)
    sys.argv = ['run.py', '--max-insn', str(a.max_insn),
                '--save-file', tmp_save, '--archive-file', a.archive,
                '--out-dir', os.path.join(tmp_dir, 'out'), '--async-request-model',
                '--sync-key-injector', '--menu-choice', 'load_game',
                '--sync-nav-mode', 'none', '--sync-min-gap-insn', '300000',
                '--sync-key-hold-insn', '4000000',
                '--sync-release-on-game-scan', '--ranged-hooks',
                '--native-renderer', 'on']

    st = {'frame': 0, 'game_frames': 0, 'frame_boundary_total': 0, 'active': [], 'calls': [],
          'writer_orphans': 0, 'entities_seen': set(), 'frame_entities': [],
          'probe_hits': collections.Counter(), 'modules_at_frame': collections.Counter()}
    orig = R.build

    def build(args):
        out = orig(args)
        uc = out[0]

        def hook(uc_, addr, size, ud):
            if addr in (PRODUCER, PRODUCER_RET_LAYER, PRODUCER_RET_MAIN, OAM_WRITER, 0x4879F8, FRAME_BOUNDARY):
                st['probe_hits'][addr] += 1
            if addr == FRAME_BOUNDARY:
                st['frame_boundary_total'] += 1
                try:
                    _mod = u32(uc_, MODULE_INDEX_VA)
                    st['modules_at_frame'][_mod] += 1
                    if _mod != 1:
                        return
                except Exception:
                    return
                st['game_frames'] += 1
                if st['game_frames'] >= 30:
                    ents = RS.entity_list(uc_)
                    reasons = collections.Counter()
                    state_n = 0
                    for e in ents:
                        ss, why = RS.read_states(uc_, e)
                        state_n += len(ss)
                        if not ss: reasons[why or 'no_state'] += 1
                    st['frame_entities'].append((len(ents), state_n, dict(reasons)))
                    st['frame'] += 1
                    if st['frame'] >= a.frames:
                        uc_.emu_stop()
                return

            if addr == PRODUCER:
                sp = uc_.reg_read(UC_ARM_REG_SP)
                lr = uc_.reg_read(UC_ARM_REG_LR)
                rec = {'frame': st['frame'], 'lr': lr,
                       'sd': uc_.reg_read(UC_ARM_REG_R0),
                       'fr': uc_.reg_read(UC_ARM_REG_R1) & 0xffff,
                       'flags': uc_.reg_read(UC_ARM_REG_R2) & 0xff,
                       'arg3': uc_.reg_read(UC_ARM_REG_R3), 'oam': []}
                try: rec['bt'] = u16(uc_, sp)
                except Exception: rec['bt'] = None
                try: rec['entity'] = u32(uc_, sp + 8)
                except Exception: rec['entity'] = None
                e = rec['entity']
                if e: st['entities_seen'].add(e)
                rec['parser'] = []
                rec['match'] = False
                if e:
                    ss, why = RS.read_states(uc_, e)
                    rec['reason'] = why
                    want = (rec['sd'], rec['fr'], rec['bt'], rec['flags'])
                    for x in ss:
                        sg = state_sig(x)
                        rec['parser'].append((sg, x.source, x.slot,
                                              x.palette, x.flip_x, x.flip_y))
                        if sg == want: rec['match'] = True
                st['calls'].append(rec)
                st['active'].append(rec)
                return

            if addr == OAM_WRITER:
                if not st['active']:
                    st['writer_orphans'] += 1
                    return
                slot = uc_.reg_read(UC_ARM_REG_R0) & 0xff
                ptr = uc_.reg_read(UC_ARM_REG_R1)
                try: raw = bytes(uc_.mem_read(ptr, 8))
                except Exception: raw = b''
                st['active'][-1]['oam'].append((slot, raw.hex()))
                return

            if addr in (PRODUCER_RET_LAYER, PRODUCER_RET_MAIN):
                if st['active']:
                    st['active'].pop()

        for x in (PRODUCER, PRODUCER_RET_LAYER, PRODUCER_RET_MAIN,
                  OAM_WRITER, 0x4879F8, FRAME_BOUNDARY):
            uc.hook_add(UC_HOOK_CODE, hook, begin=x, end=x)
        return out

    R.build = build
    with contextlib.redirect_stdout(io.StringIO()):
        try: R.main()
        except SystemExit: pass
        except Exception as exc: print('[EXC] %r' % (exc,))

    calls = st['calls']
    by_lr = collections.Counter(c['lr'] for c in calls)
    matched = sum(c['match'] for c in calls)
    print('=== v383 PRODUCER/PARSER INPUT PARITY ===')
    print('producer_calls=%d matched=%d mismatch=%d writer_orphans=%d' %
          (len(calls), matched, len(calls)-matched, st['writer_orphans']))
    print('callers:', ' '.join('%#x=%d' % kv for kv in sorted(by_lr.items())))
    print('frame_boundary_total=%d module1_game_frames=%d sampled_frames=%d' % (st['frame_boundary_total'], st['game_frames'], st['frame']))
    print('module_at_frame:', ' '.join('%s=%d' % kv for kv in sorted(st['modules_at_frame'].items())))
    print('probe_hits:', ' '.join('%#x=%d' % kv for kv in sorted(st['probe_hits'].items())))
    if st['frame_entities']:
        ec = collections.Counter()
        for _,_,r in st['frame_entities']:
            ec.update(r)
        print('entity snapshots (first 5):')
        for row in st['frame_entities'][:5]: print(' ', row)
        print('aggregate skip reasons:', dict(ec))
    print('\nfirst mismatches:')
    n = 0
    for c in calls:
        if c['match']: continue
        print(' frame=%d lr=%#x entity=%s sd=%#x fr=%d bt=%s flags=%#x oam_pieces=%d' %
              (c['frame'], c['lr'], ('%#x'%c['entity']) if c['entity'] else None,
               c['sd'], c['fr'], ('%#x'%c['bt']) if c['bt'] is not None else None,
               c['flags'], len(c['oam'])))
        print('   parser_reason=%s parser_states=%s' % (c.get('reason'), c['parser']))
        if c['oam'][:4]: print('   oam=', c['oam'][:4])
        n += 1
        if n >= 20: break

    print('\nfirst matched samples:')
    n = 0
    for c in calls:
        if not c['match']: continue
        print(' frame=%d lr=%#x entity=%#x sd=%#x fr=%d bt=%#x flags=%#x pieces=%d' %
              (c['frame'], c['lr'], c['entity'], c['sd'], c['fr'], c['bt'],
               c['flags'], len(c['oam'])))
        n += 1
        if n >= 10: break

if __name__ == '__main__':
    main()
