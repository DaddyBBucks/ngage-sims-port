"""v382: REGION-SPACE NATIVE SPRITE RENDERER.

Sprite'lari OAM'dan DEGIL, dogrudan nesne listesinden ve sprite
tanimindan uretir. Boylece motorun OAM'a hic koymadigi (ekran disindaki)
nesneler de cizilebilir -- OAM'in 9 bitlik koordinat siniri devre disi
kalir.

This public copy includes the v383 layered-record correction: record+0 bit0 is
not treated as an enable gate because valid layered records were observed with
flags == 0. A fresh end-to-end parity run is still required before full-region
sprite parity is claimed.
"""
import struct
import numpy as np

ENTITY_HEAD_GLOBAL = 0x008D700C
ENTITY_HEAD_FALLBACK = 0x0093CCB8
ENT_NEXT=0x00; ENT_PREV=0x04; ENT_RX=0x18; ENT_RY=0x1C
ENT_FLIPX=0x0D3; ENT_FLIPY=0x0D3; ENT_FRAME=0x0DB; ENT_SPRDEF_PTR=0x0DC
ENT_BASETILE=0x0FE; ENT_PALETTE=0x0D5; ENT_RENDER_KIND=0x100; ENT_RENDER_FLAGS=0x101
ENT_LAYER_BASE=0x104; ENT_LAYER_STRIDE=12; ENT_LAYER_SEL_X=0x134; ENT_LAYER_SEL_Y=0x135
G_VRAM_PTR=0x4B6EB8; G_OBJPAL_PTR=0x4B6EC4; OBJ_SIZE_TABLE=0x008D1D38; SPRITE_TILE_BANK=0x10000

def _u8(uc,va): return bytes(uc.mem_read(va,1))[0]
def _u16(uc,va): return struct.unpack('<H',uc.mem_read(va,2))[0]
def _u32(uc,va): return struct.unpack('<I',uc.mem_read(va,4))[0]
def _i32(uc,va): return struct.unpack('<i',uc.mem_read(va,4))[0]
def _sext9(v):
    v &= 0x1FF
    return v-0x200 if v&0x100 else v

def _valid_ptr(v): return 0x400000 <= v < 0xB00000
def _s8(v): return v-256 if v&0x80 else v

class RenderSpriteState(object):
    __slots__=('va','region_x','region_y','sprite_def','frame','base_tile','palette','flip_x','flip_y','source','slot','producer_flags')
    def __init__(self,va,rx,ry,sd,fr,bt,pal,fx,fy=0,source='main',slot=-1,producer_flags=0):
        self.va=va; self.region_x=rx; self.region_y=ry; self.sprite_def=sd; self.frame=fr
        self.base_tile=bt; self.palette=pal; self.flip_x=fx; self.flip_y=fy; self.source=source
        self.slot=slot; self.producer_flags=producer_flags

def _base_xy_flip(uc,va):
    rf=_u8(uc,va+ENT_RENDER_FLAGS); fx=(_u8(uc,va+ENT_FLIPX)>>4)&1
    fy=((_u8(uc,va+ENT_FLIPY)>>5)&1)|((rf>>7)&1); pf=((rf>>5)&1)|(((rf>>7)&1)<<1)
    return (_i32(uc,va+ENT_RX)>>16,_i32(uc,va+ENT_RY)>>16,fx,fy,pf)

def _main_state(uc,va):
    rx,ry,fx,fy,pf=_base_xy_flip(uc,va); sdp=_u32(uc,va+ENT_SPRDEF_PTR)
    if not _valid_ptr(sdp): return None
    sd=_u32(uc,sdp+4)
    if not _valid_ptr(sd): return None
    bt=_u16(uc,va+ENT_BASETILE)
    if bt==0xFFFF: return None
    return RenderSpriteState(va,rx,ry,sd,_u8(uc,va+ENT_FRAME),bt,_u8(uc,va+ENT_PALETTE)>>4,fx,fy,'main',-1,pf)

def _layered_states(uc,va):
    rx,ry,fx,fy,pf=_base_xy_flip(uc,va); sx=_s8(_u8(uc,va+ENT_LAYER_SEL_X)); sy=_s8(_u8(uc,va+ENT_LAYER_SEL_Y))
    ent_frame=_u8(uc,va+ENT_FRAME); out=[]
    for selector in range(7,-1,-1):
        for slot in range(4):
            rec=va+ENT_LAYER_BASE+slot*ENT_LAYER_STRIDE; flags=_u8(uc,rec)
            # v383 evidence: record+0 bit0 is NOT an enable gate.
            if _u8(uc,rec+2)!=selector: continue
            bt=_u16(uc,rec+6)
            if bt==0xFFFF: continue
            table=_u32(uc,rec+8)
            if not _valid_ptr(table): continue
            row=_u32(uc,table+sx*4)
            if not _valid_ptr(row): continue
            sd=_u32(uc,row+sy*16+4)
            if not _valid_ptr(sd): continue
            fr=ent_frame
            if flags&0x0C:
                if fr>0: fr-=1
                elif flags&0x04: fr=max(0,_u16(uc,sd+6)-1)
                else: fr=0
            out.append(RenderSpriteState(va,rx,ry,sd,fr,bt,_u8(uc,rec+1)&0x0F,fx,fy,'layer',slot,pf))
    return out

def read_states(uc,va):
    try:
        if _u8(uc,va+ENT_RENDER_KIND)!=0: return ([], 'direct_state@4040C0')
        try:
            if _u32(uc,va+0x0C)&0x100: return ([], 'manual_builder@403B04')
        except Exception: pass
        rf=_u8(uc,va+ENT_RENDER_FLAGS)
        if rf&0x40:
            ss=_layered_states(uc,va); return (ss,None if ss else 'layered_no_state')
        st=_main_state(uc,va); return ([st],None) if st is not None else ([], 'main_no_state')
    except Exception: return ([], 'read_exception')

def read_state(uc,va):
    ss,_=read_states(uc,va); return ss[0] if ss else None

def pieces(uc,st,size_table):
    sd=st.sprite_def
    try:
        A=_u8(uc,sd+0x0A); B=_u8(uc,sd+0x0B); fo=_u16(uc,sd+0x0C+st.frame*2); fb=sd+0x0C+fo
        n=_u8(uc,fb)&0x1F
        if n==0: return []
        raw=bytes(uc.mem_read(fb+6*B+10+2*A,4*n))
    except Exception: return []
    out=[]
    for i in range(n):
        p=raw[i*4:i*4+4]
        if len(p)<4: break
        x=_sext9(((p[1]&1)<<8)|p[0]); y=_sext9(((p[2]&3)<<7)|(p[1]>>1)); size=(p[2]>>2)&3; shape=(p[2]>>4)&3
        tile=((((p[3]<<2)|(p[2]>>6))&0x3FF)+st.base_tile)&0xFFFF
        v=struct.unpack_from('<I',size_table,4*(shape*4+size))[0]; W,H=v&0xFFFF,(v>>16)&0xFFFF
        if W and H: out.append((x,y,tile,shape,size,W,H))
    return out
