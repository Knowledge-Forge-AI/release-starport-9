"""Focused Gate1 profile, lineage, metadata, and native-floor contracts."""
from __future__ import annotations

import io
import json
import plistlib
import struct
import tarfile
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import rs9.nebular_lineage as lineage
from rs9.errors import ContractError
from rs9.release_core import ReleaseCapture, digest
from rs9.scratch import canonical
from rs9.operator import release_bindings, validate_release_binding
from rs9.wheel_native import extract_macho_build_version, validate_darwin_payload_floor
from rs9.wheel_nebular_successor import (
    GATE1_PROFILE,
    _successor_metadata_bytes,
    gate1_profile_record,
)


def _macho(minimum: tuple[int, int, int]) -> bytes:
    """Build a bounded synthetic 64-bit little-endian Mach-O image."""
    minos = (minimum[0] << 16) | (minimum[1] << 8) | minimum[2]
    header = struct.pack("<IIIIIIII", 0xFEEDFACF, 0x0100000C, 0, 2, 1, 24, 0, 0)
    command = struct.pack("<IIIIII", 0x32, 24, 1, minos, minos, 0)
    return header + command


def _darwin_payload(minimum: tuple[int, int, int], plist_floor: str = "13.0") -> bytes:
    root = "Theme Forge Nebular Fusion.app"
    plist = plistlib.dumps({"LSMinimumSystemVersion": plist_floor})
    entries = [
        (root, b"", 0o755, tarfile.DIRTYPE),
        (f"{root}/Contents", b"", 0o755, tarfile.DIRTYPE),
        (f"{root}/Contents/Info.plist", plist, 0o644, tarfile.REGTYPE),
        (f"{root}/Contents/MacOS", b"", 0o755, tarfile.DIRTYPE),
        (f"{root}/Contents/MacOS/tfnf", _macho(minimum), 0o755, tarfile.REGTYPE),
    ]
    out = io.BytesIO()
    with tarfile.open(fileobj=out, mode="w:gz") as archive:
        for path, data, mode, kind in entries:
            info = tarfile.TarInfo(path)
            info.mode = mode
            info.type = kind
            info.size = len(data) if kind == tarfile.REGTYPE else 0
            archive.addfile(info, io.BytesIO(data) if kind == tarfile.REGTYPE else None)
    return out.getvalue()


class Nebular070Gate1Tests(unittest.TestCase):
    def test_release_binding_is_pending_without_fabricated_hashes(self) -> None:
        binding = release_bindings("0.7.0")
        self.assertEqual(binding["status"], "pending-release-inputs")
        self.assertNotIn("expected", binding)
        self.assertEqual(validate_release_binding(binding), binding)
        with self.assertRaises(ContractError) as ctx:
            validate_release_binding({**binding, "status": "ready"})
        self.assertIn("RELEASE_BINDING", str(ctx.exception))

    def test_direct_lineage_uses_authenticated_asset_provenance(self) -> None:
        commit = "a" * 40
        tree = "b" * 40
        binding = release_bindings("0.7.0")
        binding.update({
            "status": "ready",
            "expected": {
                "repository_id": 123,
                "release_id": 456,
                "tag_commit": commit,
                "tag_tree": tree,
                "bootstrap_sha256": "c" * 64,
                "expectations_sha256": "d" * 64,
            },
        })
        provenance = canonical({"release": {"tagCommit": commit, "tagTree": tree}})
        root = Path(tempfile.mkdtemp(prefix="gate1-lineage-"))
        self.addCleanup(lambda: __import__("shutil").rmtree(root, ignore_errors=True))
        capture = ReleaseCapture(
            {
                "repository": {"full_name": binding["repository"], "id": 123},
                "release": {"id": 456, "tag": "v0.7.0"},
                "tag": {"commit": commit, "tree": tree},
            },
            {}, {}, {}, {}, {"PROVENANCE.json": provenance}, root,
        )
        metadata = {"id": 456, "tag_name": "v0.7.0", "draft": False, "prerelease": False}
        tree_record = {"sha": tree, "truncated": False}
        with patch.object(lineage, "authenticated_record_hash", return_value="e" * 64), \
                patch.object(lineage, "authenticated_release_metadata", return_value=metadata), \
                patch.object(lineage, "authenticated_tree", return_value=tree_record):
            facts = lineage.verify_direct_release_lineage(capture, binding)
        self.assertEqual(facts["mode"], "direct-tag-provenance-equality")
        self.assertEqual(facts["provenance_source_kind"], "asset")
        self.assertEqual(facts["provenance_sha256"], digest(provenance))
        self.assertFalse(facts["author_rewrite_required"])

    def test_gate1_metadata_declares_agpl_required_files_only(self) -> None:
        description = b"# Gate1\n"
        metadata = _successor_metadata_bytes(
            description,
            distribution_version="0.7.0",
            license_expression=GATE1_PROFILE.license_expression,
            legal_files=GATE1_PROFILE.required_legal_files,
        ).decode()
        self.assertIn("License-Expression: AGPL-3.0-or-later\n", metadata)
        self.assertNotIn("LicenseRef-Commercial", metadata)
        self.assertEqual(metadata.count("License-File:"), 2)
        profile = gate1_profile_record()
        self.assertEqual(profile["darwin_floor"], {"major": 13, "minor": 0})
        self.assertFalse(profile["linux_runtime_policy"]["manylinux_claim"])

    def test_darwin_floor_cross_checks_macho_and_info_plist(self) -> None:
        evidence = validate_darwin_payload_floor(_darwin_payload((13, 0, 0)))
        self.assertEqual(evidence["status"], "cross-checked")
        self.assertEqual(evidence["info_plist"], {"major": 13, "minor": 0})
        self.assertEqual(extract_macho_build_version(_macho((13, 0, 0))), (13, 0, 0))
        with self.assertRaises(ContractError) as ctx:
            validate_darwin_payload_floor(_darwin_payload((12, 0, 0)))
        self.assertIn("DARWIN_FLOOR", str(ctx.exception))
        with self.assertRaises(ContractError) as ctx:
            validate_darwin_payload_floor(_darwin_payload((13, 0, 0), plist_floor="12.0"))
        self.assertIn("DARWIN_FLOOR", str(ctx.exception))


if __name__ == "__main__":
    unittest.main()
