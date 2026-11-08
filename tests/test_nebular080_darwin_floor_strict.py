"""Portable regression coverage for the Nebular 0.8 Darwin floor gate."""
from __future__ import annotations

import io
import plistlib
import struct
import tarfile
import unittest

from rs9.errors import ContractError
from rs9.nebular080_consumer_core import _nebular_floor_evidence
from rs9.tf_pypi_archive import AdmissionError
from rs9.wheel_native import (
    _extract_darwin_minimum_version_triple,
    extract_darwin_minimum_version,
    extract_macho_build_version,
    validate_darwin_payload_floor,
)


def _macho(
    version: tuple[int, int, int] = (13, 3, 0),
    *,
    platform: int = 1,
) -> bytes:
    """Build one bounded 64-bit Mach-O with a caller-selected build platform."""
    minimum = (version[0] << 16) | (version[1] << 8) | version[2]
    header = struct.pack("<IIIIIIII", 0xFEEDFACF, 0x0100000C, 0, 2, 1, 24, 0, 0)
    command = struct.pack("<IIIIII", 0x32, 24, platform, minimum, minimum, 0)
    return header + command


def _fat(*slices: bytes) -> bytes:
    """Build a deterministic 32-bit big-endian FAT image for parser coverage."""
    if not slices:
        raise ValueError("at least one slice is required")
    table_end = 8 + (20 * len(slices))
    offset = (table_end + 0xFFF) & ~0xFFF
    rows: list[bytes] = []
    body = bytearray(b"\0" * (offset - table_end))
    for index, image in enumerate(slices):
        rows.append(struct.pack(">IIIII", 0x0100000C + index, 0, offset, len(image), 12))
        body.extend(b"\0" * (offset - (table_end + len(body))))
        body.extend(image)
        offset = (offset + len(image) + 0xFFF) & ~0xFFF
    return struct.pack(">II", 0xCAFEBABE, len(rows)) + b"".join(rows) + bytes(body)


def _payload(
    *,
    plist_floor: str = "13.3.0",
    executable: bytes | None = None,
    embedded: bytes | None = None,
) -> bytes:
    root = "Theme Forge Nebular Fusion.app"
    entries = {
        f"{root}/Contents/Info.plist": (
            plistlib.dumps({"LSMinimumSystemVersion": plist_floor}, fmt=plistlib.FMT_BINARY),
            0o644,
        ),
        f"{root}/Contents/MacOS/theme-forge-nebular-fusion": (executable or _macho(), 0o755),
        f"{root}/Contents/Frameworks/libnative.dylib": (embedded or _fat(_macho(), _macho()), 0o644),
        f"{root}/Contents/Resources/launch.sh": (b"#!/bin/sh\nexit 0\n", 0o755),
    }
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w:gz") as archive:
        for path, (body, mode) in entries.items():
            info = tarfile.TarInfo(path)
            info.mode = mode
            info.size = len(body)
            archive.addfile(info, io.BytesIO(body))
    return output.getvalue()


def _evidence(*patches: int) -> dict[str, object]:
    return {
        "schema": "rs9.darwin-floor-evidence.v1alpha1",
        "required_floor": {"major": 13, "minor": 3},
        "info_plist": {"major": 13, "minor": 3},
        "macho": [
            {
                "path": f"Theme Forge Nebular Fusion.app/Contents/MacOS/member-{index}",
                "role": "macos-executable",
                "major": 13,
                "minor": 3,
                "patch": patch,
            }
            for index, patch in enumerate(patches)
        ],
        "scripts": [{"path": "Theme Forge Nebular Fusion.app/Contents/Resources/launch.sh", "role": "script"}],
        "status": "cross-checked",
    }


class Nebular080DarwinFloorStrictTests(unittest.TestCase):
    def test_legacy_parser_keeps_two_key_abi_and_strict_floor_rejects_patch(self) -> None:
        plist = plistlib.dumps({"LSMinimumSystemVersion": "13.3.1"})
        self.assertEqual(extract_darwin_minimum_version(plist), (13, 3))
        self.assertEqual(_extract_darwin_minimum_version_triple(plist), (13, 3, 1))
        self.assertEqual(
            extract_darwin_minimum_version(
                plistlib.dumps({"LSMinimumSystemVersion": "13.3.0"})
            ),
            (13, 3),
        )
        with self.assertRaisesRegex(ContractError, "INVALID_PLIST"):
            validate_darwin_payload_floor(
                _payload(plist_floor="13.3.1"),
                required_floor=(13, 3),
            )

    def test_foreign_build_platform_is_rejected_even_below_floor(self) -> None:
        with self.assertRaisesRegex(ContractError, "INVALID_MACHO"):
            validate_darwin_payload_floor(
                _payload(executable=_macho((13, 2, 0), platform=2)),
                required_floor=(13, 3),
            )

    def test_full_patch_comparison_rejects_macho_above_declared_floor(self) -> None:
        image = _macho((13, 3, 1))
        self.assertEqual(extract_macho_build_version(image), (13, 3, 1))
        with self.assertRaisesRegex(ContractError, "DARWIN_FLOOR_MISMATCH"):
            validate_darwin_payload_floor(
                _payload(executable=image),
                required_floor=(13, 3),
            )

    def test_all_native_members_and_fat_slices_accept_exact_floor(self) -> None:
        evidence = validate_darwin_payload_floor(_payload(), required_floor=(13, 3))
        self.assertEqual(evidence["info_plist"], {"major": 13, "minor": 3})
        self.assertEqual(len(evidence["macho"]), 2)
        self.assertEqual(
            {row["patch"] for row in evidence["macho"]},
            {0},
        )
        self.assertEqual(evidence["scripts"][0]["role"], "script")

    def test_readback_compares_patch_not_only_major_and_minor(self) -> None:
        with self.assertRaisesRegex(AdmissionError, "NEBULAR_FLOOR_BINDING"):
            _nebular_floor_evidence(_evidence(1))
        self.assertEqual(_nebular_floor_evidence(_evidence(0))["macho"][0]["patch"], 0)


if __name__ == "__main__":
    unittest.main()
