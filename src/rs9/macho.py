"""Bounded Mach-O arm64 deployment-target readback for immutable release bytes."""
import struct
from typing import Any

from rs9.errors import ContractError

_MACHO_MAGIC_64_LE = 0xFEEDFACF
_CPU_TYPE_ARM64 = 0x0100000C
_LC_BUILD_VERSION = 0x32
_LC_VERSION_MIN_MACOSX = 0x24
_PLATFORM_MACOS = 1


def parse_macho_arm64(data: bytes) -> dict[str, Any]:
    """Bounded parser for 64-bit Mach-O arm64 binaries, checking deployment minimum."""
    if len(data) < 32:
        raise ContractError("APGR7_PYTHON_MACHO", "Mach-O binary too short for 64-bit header")
    magic = struct.unpack_from("<I", data, 0)[0]
    if magic != _MACHO_MAGIC_64_LE:
        raise ContractError("APGR7_PYTHON_MACHO", f"Unsupported Mach-O magic: {hex(magic)}")

    cputype, cpusubtype, filetype, ncmds, sizeofcmds, flags, reserved = struct.unpack_from("<iiIIIII", data, 4)
    if cputype != _CPU_TYPE_ARM64:
        raise ContractError("APGR7_PYTHON_MACHO", f"Mach-O cputype must be arm64, got {hex(cputype)}")

    if 32 + sizeofcmds > len(data) or ncmds > sizeofcmds // 8:
        raise ContractError("APGR7_PYTHON_MACHO", "Mach-O load commands extend beyond file length")

    offset = 32
    deployment_minimum = None
    for _ in range(ncmds):
        if offset + 8 > 32 + sizeofcmds:
            raise ContractError("APGR7_PYTHON_MACHO", "Truncated Mach-O load command")
        cmd, cmdsize = struct.unpack_from("<II", data, offset)
        if cmdsize < 8 or cmdsize % 8 or offset + cmdsize > 32 + sizeofcmds:
            raise ContractError("APGR7_PYTHON_MACHO", "Invalid load command size")

        if cmd == _LC_BUILD_VERSION:
            if cmdsize < 24:
                raise ContractError("APGR7_PYTHON_MACHO", "Truncated LC_BUILD_VERSION command")
            platform, minos, sdk, ntools = struct.unpack_from("<IIII", data, offset + 8)
            if platform != _PLATFORM_MACOS:
                raise ContractError("APGR7_PYTHON_MACHO", f"Expected macOS platform (1), got {platform}")
            major = (minos >> 16) & 0xFFFF
            minor = (minos >> 8) & 0xFF
            deployment_minimum = (major, minor)
        elif cmd == _LC_VERSION_MIN_MACOSX:
            if cmdsize < 16:
                raise ContractError("APGR7_PYTHON_MACHO", "Truncated LC_VERSION_MIN_MACOSX command")
            version, sdk = struct.unpack_from("<II", data, offset + 8)
            major = (version >> 16) & 0xFFFF
            minor = (version >> 8) & 0xFF
            deployment_minimum = (major, minor)
        offset += cmdsize

    if deployment_minimum is None:
        raise ContractError("APGR7_PYTHON_MACHO", "Missing deployment minimum load command in Mach-O binary")

    return {
        "arch": "arm64",
        "deployment_minimum": deployment_minimum,
    }


