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

DATAADDRESS_THUNK_VA = 0x4962c4
TBITMAPUTIL_CTOR_VA = 0x4962f4
TBITMAPUTIL_BEGIN_VA = 0x4962a4
TBITMAPUTIL_END_VA = 0x496294

SCREEN_WIDTH = 176
SCREEN_HEIGHT = 208
BPP = 2
DATAADDRESS_SIZE = SCREEN_WIDTH * SCREEN_HEIGHT * BPP


def set_screen_width(width):
    """v358 experimental viewport width override.

    The canonical path never calls this. The host-side buffer size is updated;
    guest-side constants are handled by runtime/widescreen.py.
    """
    global SCREEN_WIDTH, DATAADDRESS_SIZE, FRAMEBUFFER_WATCH_HI
    SCREEN_WIDTH = int(width)
    DATAADDRESS_SIZE = SCREEN_WIDTH * SCREEN_HEIGHT * BPP
    FRAMEBUFFER_WATCH_HI = FRAMEBUFFER_WATCH_LO + DATAADDRESS_SIZE
    return DATAADDRESS_SIZE


FRAMEBUFFER_WATCH_LO = 0x20012038
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
        uc.mem_write(this_ptr, struct.pack("<I", bitmap_ptr))
        uc.mem_write(this_ptr + 4, struct.pack("<I", 0))
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
        word_pos = buf
    if this_ptr != 0:
        uc.mem_write(this_ptr + 4, struct.pack("<I", word_pos))


def handle_tbitmaputil_end(ctx, uc):
    pass


class FramebufferWatcher:
    """Tracks the live framebuffer region and can take point-in-time snapshots."""

    def __init__(self, base=None):
        self.base = FRAMEBUFFER_WATCH_LO if base is None else base
        self.span = FRAMEBUFFER_WATCH_HI - FRAMEBUFFER_WATCH_LO
        self.shadow = bytearray(self.span)

    def rebase(self, base):
        self.base = base

    def on_write(self, address, size, value):
        if not (self.base <= address < self.base + self.span):
            return
        off = address - self.base
        try:
            self.shadow[off:off + size] = value.to_bytes(size, "little")
        except OverflowError:
            pass

    def snapshot(self):
        return bytes(self.shadow)

    def nonzero_count(self):
        return sum(1 for b in self.shadow if b != 0)


def render_snapshot_to_png(raw_bytes, out_path, scale=3):
    """Render a raw framebuffer snapshot to PNG. Requires Pillow."""
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
