"""Bitmap / framebuffer handling.

Covers two confirmed-real Symbian FBSCLI mechanisms:

- CFbsBitmap::DataAddress() (FBSCLI:0x11): returns a stable pointer to a
  bitmap's raw pixel buffer. Real behavior (confirmed by trace): the SAME
  bitmap object gets the SAME address back on repeat calls -- callers rely
  on that to detect "did the bitmap relocate". We back it with a real
  176x208x16bpp buffer, cached per bitmap-object pointer so repeat calls are
  stable instead of leaking a fresh buffer (and exhausting the fake heap)
  every call.
- TBitmapUtil (FBSCLI:0x89 ctor, 0x6 Begin, 0x19 End): a real Symbian
  pixel-cursor helper. Layout confirmed via the SDK header (fbs.h):
  CFbsBitmap* iFbsBitmap @+0, TUint32* iWordPos @+4. Begin() computes
  iWordPos from the bitmap's own DataAddress() buffer plus (x,y) -- routed
  through the SAME per-bitmap cache above so pixel writes land in the
  correct isolated buffer instead of colliding with unrelated memory.

Also owns the framebuffer watch/snapshot infrastructure used to render what
the emulated screen actually looks like at a given instruction count.
"""

import struct

DATAADDRESS_THUNK_VA = 0x4962c4   # FBSCLI:0x11  CFbsBitmap::DataAddress()
TBITMAPUTIL_CTOR_VA = 0x4962f4    # FBSCLI:0x89  TBitmapUtil::TBitmapUtil()
TBITMAPUTIL_BEGIN_VA = 0x4962a4   # FBSCLI:0x6   TBitmapUtil::Begin()
TBITMAPUTIL_END_VA = 0x496294     # FBSCLI:0x19  TBitmapUtil::End()

SCREEN_WIDTH = 176
SCREEN_HEIGHT = 208
BPP = 2
DATAADDRESS_SIZE = SCREEN_WIDTH * SCREEN_HEIGHT * BPP  # 0x11E00

# The live N-Gage framebuffer's runtime address, confirmed by trace.
FRAMEBUFFER_WATCH_LO = 0x20012078
FRAMEBUFFER_WATCH_HI = FRAMEBUFFER_WATCH_LO + SCREEN_WIDTH * SCREEN_HEIGHT * BPP


def get_or_make_dataaddress_buffer(ctx, bitmap_this):
    cache = ctx.dataaddress_cache
    if bitmap_this in cache:
        return cache[bitmap_this]
    ptr = ctx.allocator.alloc(DATAADDRESS_SIZE)
    if ptr != 0 and ctx.vtable_va is not None:
        ctx.uc.mem_write(ptr, struct.pack("<I", ctx.vtable_va))
    cache[bitmap_this] = ptr
    return ptr


def handle_dataaddress(ctx, uc):
    from unicorn.arm_const import UC_ARM_REG_R0
    this_ptr = uc.reg_read(UC_ARM_REG_R0)
    ptr = get_or_make_dataaddress_buffer(ctx, this_ptr)
    uc.reg_write(UC_ARM_REG_R0, ptr)


def handle_tbitmaputil_ctor(ctx, uc):
    from unicorn.arm_const import UC_ARM_REG_R0, UC_ARM_REG_R1
    this_ptr = uc.reg_read(UC_ARM_REG_R0)
    bitmap_ptr = uc.reg_read(UC_ARM_REG_R1)
    if this_ptr != 0:
        uc.mem_write(this_ptr, struct.pack("<I", bitmap_ptr))     # iFbsBitmap
        uc.mem_write(this_ptr + 4, struct.pack("<I", 0))          # iWordPos
        ctx.tbitmaputil_bitmap_of[this_ptr] = bitmap_ptr


def handle_tbitmaputil_begin(ctx, uc):
    from unicorn.arm_const import UC_ARM_REG_R0, UC_ARM_REG_R1
    this_ptr = uc.reg_read(UC_ARM_REG_R0)
    pos_ptr = uc.reg_read(UC_ARM_REG_R1)
    bitmap_ptr = ctx.tbitmaputil_bitmap_of.get(this_ptr, 0)
    if bitmap_ptr == 0 and this_ptr != 0:
        try:
            bitmap_ptr = struct.unpack("<I", uc.mem_read(this_ptr, 4))[0]
        except Exception:
            bitmap_ptr = 0
    buf = get_or_make_dataaddress_buffer(ctx, bitmap_ptr) if bitmap_ptr else 0
    x = y = 0
    if pos_ptr != 0:
        try:
            x = struct.unpack("<i", uc.mem_read(pos_ptr, 4))[0]
            y = struct.unpack("<i", uc.mem_read(pos_ptr + 4, 4))[0]
        except Exception:
            x = y = 0
    word_pos = 0
    if buf != 0 and 0 <= x < SCREEN_WIDTH and y >= 0:
        offset = (y * SCREEN_WIDTH + x) * BPP
        if offset < DATAADDRESS_SIZE:
            word_pos = buf + offset
    if word_pos == 0 and buf != 0:
        word_pos = buf  # clamp out-of-range positions into the buffer
    if this_ptr != 0:
        uc.mem_write(this_ptr + 4, struct.pack("<I", word_pos))


def handle_tbitmaputil_end(ctx, uc):
    pass  # no persistent state to flush in our fake-buffer model


# --- Framebuffer snapshot / timeline -----------------------------------

class FramebufferWatcher:
    """Tracks the live framebuffer region and can take point-in-time
    snapshots for later rendering (see tools/render_snapshot.py)."""

    def __init__(self):
        self.shadow = bytearray(FRAMEBUFFER_WATCH_HI - FRAMEBUFFER_WATCH_LO)

    def on_write(self, address, size, value):
        if not (FRAMEBUFFER_WATCH_LO <= address < FRAMEBUFFER_WATCH_HI):
            return
        off = address - FRAMEBUFFER_WATCH_LO
        try:
            self.shadow[off:off + size] = value.to_bytes(size, "little")
        except OverflowError:
            pass

    def snapshot(self):
        return bytes(self.shadow)

    def nonzero_count(self):
        return sum(1 for b in self.shadow if b != 0)


def render_snapshot_to_png(raw_bytes, out_path, scale=3):
    """Render a raw RGB565 framebuffer snapshot to a PNG. Requires Pillow."""
    from PIL import Image
    img = Image.new("RGB", (SCREEN_WIDTH, SCREEN_HEIGHT))
    px = img.load()
    for y in range(SCREEN_HEIGHT):
        for x in range(SCREEN_WIDTH):
            off = (y * SCREEN_WIDTH + x) * 2
            val = struct.unpack_from("<H", raw_bytes, off)[0]
            r = (val >> 11) & 0x1F
            g = (val >> 5) & 0x3F
            b = val & 0x1F
            px[x, y] = ((r * 255) // 31, (g * 255) // 63, (b * 255) // 31)
    img = img.resize((SCREEN_WIDTH * scale, SCREEN_HEIGHT * scale), Image.NEAREST)
    img.save(out_path)
