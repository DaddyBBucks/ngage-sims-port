import ctypes
import platform
import sys

ARM_CODE = bytes.fromhex("0100a0e30210a0e3")  # mov r0,#1 ; mov r1,#2 (ARM32 LE)

def _basic():
    return {
        "python": sys.version.split()[0],
        "platform": platform.platform(),
        "machine": platform.machine(),
        "host_is_arm64": platform.machine().lower() in ("aarch64", "arm64"),
    }

def probe():
    result = _basic()
    try:
        import unicorn
        from unicorn import Uc, UC_ARCH_ARM, UC_MODE_ARM
        from unicorn.arm_const import UC_ARM_REG_R0, UC_ARM_REG_R1

        result["unicorn"] = getattr(unicorn, "__version__", "present")
        uc = Uc(UC_ARCH_ARM, UC_MODE_ARM)
        base = 0x10000
        uc.mem_map(base, 0x1000)
        uc.mem_write(base, ARM_CODE)
        uc.emu_start(base, base + len(ARM_CODE))
        r0 = uc.reg_read(UC_ARM_REG_R0)
        r1 = uc.reg_read(UC_ARM_REG_R1)
        result["arm32_guest"] = f"r0={r0}, r1={r1}"
        result["runtime_ready"] = (r0 == 1 and r1 == 2)
    except Exception as exc:
        result["unicorn"] = "not linked yet"
        result["runtime_ready"] = False
        result["unicorn_error"] = f"{type(exc).__name__}: {exc}"
        for name in ("libunicorn.so", "unicorn"):
            try:
                ctypes.CDLL(name)
                result["native_library"] = f"{name}: loadable"
                break
            except Exception as lib_exc:
                result["native_library"] = f"not loadable ({type(lib_exc).__name__})"
    return result
