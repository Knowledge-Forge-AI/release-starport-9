"""Darwin component-floor compatibility tests for the 0.7 Gate1 path."""
from __future__ import annotations

import io
import plistlib
import struct
import tarfile
import unittest

from rs9.errors import ContractError
from rs9.tf_pypi_archive import AdmissionError
from rs9.tf_pypi_consumer import _nebular_floor_evidence
from rs9.wheel_native import extract_darwin_minimum_version, validate_darwin_payload_floor


def _macho(minimum: tuple[int, int, int]) -> bytes:
    minos = (minimum[0] << 16) | (minimum[1] << 8) | minimum[2]
    header = struct.pack("<IIIIIIII", 0xFEEDFACF, 0x0100000C, 0, 2, 1, 24, 0, 0)
    command = struct.pack("<IIIIII", 0x32, 24, 1, minos, minos, 0)
    return header + command


def _darwin_bundle(
    binaries: dict[str, tuple[int, int, int] | bytes],
    *,
    plist_floor: str = "13.0",
) -> bytes:
    root = "Theme Forge Nebular Fusion.app"
    entries: list[tuple[str, bytes, int, bytes]] = [
        (root, b"", 0o755, tarfile.DIRTYPE),
        (f"{root}/Contents", b"", 0o755, tarfile.DIRTYPE),
        (
            f"{root}/Contents/Info.plist",
            plistlib.dumps({"LSMinimumSystemVersion": plist_floor}),
            0o644,
            tarfile.REGTYPE,
        ),
        (f"{root}/Contents/MacOS", b"", 0o755, tarfile.DIRTYPE),
    ]
    for path, value in binaries.items():
        data = _macho(value) if isinstance(value, tuple) else value
        entries.append((f"{root}/{path}", data, 0o755, tarfile.REGTYPE))
    out = io.BytesIO()
    with tarfile.open(fileobj=out, mode="w:gz") as archive:
        for path, data, mode, kind in entries:
            info = tarfile.TarInfo(path)
            info.mode = mode
            info.type = kind
            info.size = len(data) if kind == tarfile.REGTYPE else 0
            archive.addfile(info, io.BytesIO(data) if kind == tarfile.REGTYPE else None)
    return out.getvalue()


def _floor_evidence(*rows: tuple[str, int, int]) -> dict[str, object]:
    return {
        "schema": "rs9.darwin-floor-evidence.v1alpha1",
        "required_floor": {"major": 13, "minor": 0},
        "info_plist": {"major": 13, "minor": 0},
        "macho": [
            {"path": path, "role": "macos-executable", "major": major, "minor": minor, "patch": 0}
            for path, major, minor in rows
        ],
        "scripts": [{"path": "Theme Forge Nebular Fusion.app/Contents/Resources/bin/tfnf", "role": "script"}],
        "status": "cross-checked",
    }


class DarwinFloorCompatibilityTests(unittest.TestCase):
    def test_mac13_bundle_accepts_legacy_11_sidecar_and_13_components(self) -> None:
        payload = _darwin_bundle(
            {
                "Contents/MacOS/theme-forge-nebular-fusion": (13, 0, 0),
                "Contents/MacOS/tfsb-studio-service": (11, 0, 0),
                "Contents/Resources/native/addon.node": (13, 0, 0),
            }
        )
        evidence = validate_darwin_payload_floor(payload)
        rows = {row["path"]: row for row in evidence["macho"]}
        service = rows["Theme Forge Nebular Fusion.app/Contents/MacOS/tfsb-studio-service"]
        self.assertEqual((service["major"], service["minor"]), (11, 0))
        self.assertEqual(len(rows), 3)

    def test_mac13_bundle_accepts_all_components_at_advertised_floor(self) -> None:
        evidence = validate_darwin_payload_floor(
            _darwin_bundle(
                {
                    "Contents/MacOS/theme-forge-nebular-fusion": (13, 0, 0),
                    "Contents/MacOS/tfsb-studio-service": (13, 0, 0),
                    "Contents/Resources/native/addon.node": (13, 0, 0),
                }
            )
        )
        self.assertTrue(all(row["major"] == 13 and row["minor"] == 0 for row in evidence["macho"]))

    def test_component_above_advertised_floor_is_rejected(self) -> None:
        with self.assertRaises(ContractError) as ctx:
            validate_darwin_payload_floor(
                _darwin_bundle(
                    {
                        "Contents/MacOS/theme-forge-nebular-fusion": (13, 0, 0),
                        "Contents/MacOS/tfsb-studio-service": (14, 0, 0),
                    }
                )
            )
        self.assertIn("DARWIN_FLOOR_MISMATCH", str(ctx.exception))

    def test_info_plist_below_gate1_floor_is_rejected(self) -> None:
        for plist_floor, component_floor in (("11.0", (11, 0, 0)), ("12.0", (12, 0, 0))):
            with self.subTest(plist_floor=plist_floor), self.assertRaises(ContractError) as ctx:
                validate_darwin_payload_floor(
                    _darwin_bundle(
                        {
                            "Contents/MacOS/theme-forge-nebular-fusion": component_floor,
                            "Contents/MacOS/tfsb-studio-service": component_floor,
                            "Contents/Resources/native/addon.node": component_floor,
                        },
                        plist_floor=plist_floor,
                    )
                )
            self.assertEqual(ctx.exception.code, "DARWIN_FLOOR")

    def test_required_floor_above_advertised_floor_is_rejected(self) -> None:
        with self.assertRaises(ContractError) as ctx:
            validate_darwin_payload_floor(
                _darwin_bundle(
                    {
                        "Contents/MacOS/theme-forge-nebular-fusion": (13, 0, 0),
                        "Contents/MacOS/tfsb-studio-service": (13, 0, 0),
                    }
                ),
                required_floor=(14, 0),
            )
        self.assertEqual(ctx.exception.code, "DARWIN_FLOOR")

    def test_malformed_macho_is_rejected(self) -> None:
        with self.assertRaises(ContractError) as ctx:
            validate_darwin_payload_floor(
                _darwin_bundle({"Contents/MacOS/theme-forge-nebular-fusion": b"not-a-mach-o"})
            )
        self.assertIn("INVALID_MACHO", str(ctx.exception))

    def test_consumer_accepts_observed_lower_component(self) -> None:
        evidence = _nebular_floor_evidence(
            _floor_evidence(
                ("Theme Forge Nebular Fusion.app/Contents/MacOS/theme-forge-nebular-fusion", 13, 0),
                ("Theme Forge Nebular Fusion.app/Contents/MacOS/tfsb-studio-service", 11, 0),
                ("Theme Forge Nebular Fusion.app/Contents/Resources/native/addon.node", 13, 0),
            )
        )
        self.assertEqual(evidence["macho"][1]["major"], 11)

    def test_consumer_rejects_above_floor_and_malformed_component_rows(self) -> None:
        with self.assertRaises(AdmissionError) as ctx:
            _nebular_floor_evidence(
                _floor_evidence(
                    ("Theme Forge Nebular Fusion.app/Contents/MacOS/theme-forge-nebular-fusion", 13, 0),
                    ("Theme Forge Nebular Fusion.app/Contents/MacOS/tfsb-studio-service", 14, 0),
                )
            )
        self.assertIn("NEBULAR_FLOOR_BINDING", str(ctx.exception))
        malformed = _floor_evidence(
            ("Theme Forge Nebular Fusion.app/Contents/MacOS/theme-forge-nebular-fusion", 13, 0),
        )
        malformed["macho"][0]["major"] = "13"
        with self.assertRaises(AdmissionError) as ctx:
            _nebular_floor_evidence(malformed)
        self.assertIn("NEBULAR_FLOOR_BINDING", str(ctx.exception))

    def test_consumer_rejects_negative_boolean_and_out_of_range_versions(self) -> None:
        for field, value in (
            ("major", -1),
            ("minor", -1),
            ("patch", -1),
            ("patch", 256),
            ("major", True),
        ):
            malformed = _floor_evidence(
                ("Theme Forge Nebular Fusion.app/Contents/MacOS/tfsb-studio-service", 11, 0),
            )
            malformed["macho"][0][field] = value
            with self.subTest(field=field, value=value), self.assertRaises(AdmissionError) as ctx:
                _nebular_floor_evidence(malformed)
            self.assertIn("NEBULAR_FLOOR_BINDING", str(ctx.exception))

    def test_legacy_info_plist_parser_still_reports_its_declared_floor(self) -> None:
        self.assertEqual(
            extract_darwin_minimum_version(plistlib.dumps({"LSMinimumSystemVersion": "11.0"})),
            (11, 0),
        )


if __name__ == "__main__":
    unittest.main()
