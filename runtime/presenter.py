"""Complete-frame presentation backends.

v320 proved that the logical 176x208 frame is complete immediately before
the engine calls its final RGB444/RGB555 conversion at 0x44872c/0x44873c.
These presenters only read that buffer. They never modify Unicorn memory,
registers, timing, or control flow.
"""
import array
import hashlib
import json
import os

from .graphics import FRAMEBUFFER_WATCH_LO

FRAME_BOUNDARY_PCS = {0x44872C: "rgb444", 0x44873C: "rgb555"}
DISPATCH_BOUNDARY_PCS = {0x448740: "dispatch"}
BOUNDARY_SETS = {"conversion": FRAME_BOUNDARY_PCS,
                 "dispatch": DISPATCH_BOUNDARY_PCS}


def _frame_bytes():
    from . import graphics as _g
    return _g.DATAADDRESS_SIZE


def _screen_size():
    from . import graphics as _g
    return _g.SCREEN_WIDTH, _g.SCREEN_HEIGHT


def _build_rgb444_lut():
    lut = bytearray(4096 * 3)
    for v in range(4096):
        lut[v * 3] = ((v >> 8) & 15) * 17
        lut[v * 3 + 1] = ((v >> 4) & 15) * 17
        lut[v * 3 + 2] = (v & 15) * 17
    return bytes(lut)


_RGB444_LUT = _build_rgb444_lut()
try:
    import numpy as _np
    _LUT_NP = _np.frombuffer(_RGB444_LUT, dtype=_np.uint8).reshape(4096, 3)
except Exception:
    _np = None
    _LUT_NP = None
    _LUT_LIST = [_RGB444_LUT[i * 3:i * 3 + 3] for i in range(4096)]


def rgb444_to_rgb24(raw):
    if len(raw) != _frame_bytes():
        raise ValueError("expected %d framebuffer bytes, got %d" %
                         (_frame_bytes(), len(raw)))
    if _np is not None:
        words = _np.frombuffer(raw, dtype="<u2") & 0x0FFF
        return _LUT_NP[words].tobytes()
    lut = _LUT_LIST
    return b"".join([lut[v & 0x0FFF] for v in array.array("H", raw)])


class FramePresenter:
    kind = "base"
    compute_digest = True
    max_records = 0
    framebuffer_va = None

    def __init__(self, max_frames=0):
        self.max_frames = max(0, int(max_frames))
        self.frames_seen = 0
        self.frames_presented = 0
        self.closed = False
        self.records = []

    def _read(self, uc):
        base = self.framebuffer_va
        if base is None:
            base = FRAMEBUFFER_WATCH_LO
        return bytes(uc.mem_read(base, _frame_bytes()))

    def present(self, uc, insn, module, boundary_pc):
        self.frames_seen += 1
        if self.closed or (self.max_frames and
                           self.frames_presented >= self.max_frames):
            return False
        raw = self._read(uc)
        record = {
            "frame": self.frames_presented,
            "insn": insn,
            "module": module,
            "boundary_pc": hex(boundary_pc),
            "conversion": (FRAME_BOUNDARY_PCS.get(boundary_pc)
                           or DISPATCH_BOUNDARY_PCS.get(boundary_pc)
                           or hex(boundary_pc)),
            "sha256": hashlib.sha256(raw).hexdigest()
            if self.compute_digest else None,
        }
        if self._present(raw, record) is False:
            return False
        self.records.append(record)
        if self.max_records and len(self.records) > self.max_records:
            del self.records[:len(self.records) - self.max_records]
        self.frames_presented += 1
        return True

    def _present(self, raw, record):
        raise NotImplementedError

    def poll_input(self):
        return []

    def close(self):
        self.closed = True

    def summary(self):
        return {"kind": self.kind,
                "frames_seen": self.frames_seen,
                "frames_presented": self.frames_presented,
                "closed": self.closed}


class RawFramePresenter(FramePresenter):
    kind = "raw"

    def __init__(self, output_dir, max_frames=0):
        super().__init__(max_frames=max_frames)
        self.output_dir = os.path.abspath(output_dir)
        os.makedirs(self.output_dir, exist_ok=True)

    def _present(self, raw, record):
        name = "frame_%04d_insn%d_mod%s_rgb444.bin" % (
            record["frame"], record["insn"], record["module"])
        with open(os.path.join(self.output_dir, name), "wb") as handle:
            handle.write(raw)
        record["raw_file"] = name
        return True

    def close(self):
        manifest = {
            "format": "N-Gage Sims complete-frame stream v321",
            "framebuffer": {"width": _screen_size()[0],
                            "height": _screen_size()[1],
                            "format": "EColor4K / u16 0RGB",
                            "base": hex(FRAMEBUFFER_WATCH_LO)},
            "frames": self.records,
        }
        with open(os.path.join(self.output_dir, "frames_v321.json"), "w",
                  encoding="utf-8") as handle:
            json.dump(manifest, handle, ensure_ascii=False, indent=2)
        super().close()


class PygameFramePresenter(FramePresenter):
    kind = "pygame"
    compute_digest = False
    max_records = 2048

    def __init__(self, scale=3, max_frames=0,
                 title="N-Gage Sims: Bustin' Out"):
        super().__init__(max_frames=max_frames)
        try:
            import pygame
        except ImportError as exc:
            raise RuntimeError("pygame presenter requires pygame") from exc
        self.pygame = pygame
        self.scale = max(1, int(scale))
        pygame.init()
        pygame.display.set_caption(title)
        self._w, self._h = _screen_size()
        self.window = pygame.display.set_mode(
            (self._w * self.scale, self._h * self.scale))
        self._hat_keys = set()
        self._key_map = {
            pygame.K_UP: "up", pygame.K_DOWN: "down",
            pygame.K_LEFT: "left", pygame.K_RIGHT: "right",
            pygame.K_RETURN: "5", pygame.K_KP_ENTER: "5",
            pygame.K_SPACE: "5",
            pygame.K_0: "0", pygame.K_1: "1", pygame.K_2: "2",
            pygame.K_3: "3", pygame.K_4: "4", pygame.K_5: "5",
            pygame.K_6: "6", pygame.K_7: "7", pygame.K_8: "8",
            pygame.K_9: "9",
            pygame.K_KP0: "0", pygame.K_KP1: "1", pygame.K_KP2: "2",
            pygame.K_KP3: "3", pygame.K_KP4: "4", pygame.K_KP5: "5",
            pygame.K_KP6: "6", pygame.K_KP7: "7", pygame.K_KP8: "8",
            pygame.K_KP9: "9",
            pygame.K_ASTERISK: "star", pygame.K_KP_MULTIPLY: "star",
            pygame.K_F3: "star",
            pygame.K_HASH: "hash", pygame.K_F4: "hash",
            pygame.K_F1: "softleft", pygame.K_q: "softleft",
            pygame.K_F2: "softright", pygame.K_e: "softright",
            pygame.K_BACKSPACE: "clear", pygame.K_ESCAPE: "clear",
        }
        self._button_map = {0: "5", 1: "clear",
                            2: "softleft", 3: "softright"}
        pygame.joystick.init()
        self.joysticks = []
        for index in range(pygame.joystick.get_count()):
            joystick = pygame.joystick.Joystick(index)
            joystick.init()
            self.joysticks.append(joystick)

    def poll_input(self):
        pygame = self.pygame
        translated = []
        for event in pygame.event.get():
            if event.type == pygame.QUIT:
                self.closed = True
            elif event.type in (pygame.KEYDOWN, pygame.KEYUP):
                name = self._key_map.get(event.key)
                if name is not None:
                    translated.append(("down" if event.type == pygame.KEYDOWN
                                       else "up", name))
            elif event.type in (pygame.JOYBUTTONDOWN, pygame.JOYBUTTONUP):
                name = self._button_map.get(event.button)
                if name is not None:
                    translated.append(("down" if event.type ==
                                       pygame.JOYBUTTONDOWN else "up", name))
            elif event.type == pygame.JOYHATMOTION:
                x, y = event.value
                current = set()
                if x < 0: current.add("left")
                elif x > 0: current.add("right")
                if y < 0: current.add("down")
                elif y > 0: current.add("up")
                for name in sorted(self._hat_keys - current):
                    translated.append(("up", name))
                for name in sorted(current - self._hat_keys):
                    translated.append(("down", name))
                self._hat_keys = current
        return translated

    def _present(self, raw, record):
        pygame = self.pygame
        if self.closed:
            return False
        rgb = rgb444_to_rgb24(raw)
        surface = pygame.image.frombuffer(rgb, (self._w, self._h), "RGB")
        if self.scale != 1:
            surface = pygame.transform.scale(
                surface, (self._w * self.scale, self._h * self.scale))
        self.window.blit(surface, (0, 0))
        pygame.display.flip()
        return True

    def close(self):
        self.pygame.quit()
        super().close()


def create_presenter(kind="none", output_dir="presented_frames", scale=3,
                     max_frames=0):
    if kind == "none":
        return None
    if kind == "raw":
        return RawFramePresenter(output_dir, max_frames=max_frames)
    if kind == "pygame":
        return PygameFramePresenter(scale=scale, max_frames=max_frames)
    if kind == "region-view":
        from . import region_view as _rv
        return _rv.make_presenter(PygameFramePresenter, scale=scale,
                                  max_frames=max_frames)
    raise ValueError("unknown presenter: %s" % kind)
