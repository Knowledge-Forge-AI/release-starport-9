"""Comprehensive tests for native Nebular Darwin compressed-archive wheel builder."""
from __future__ import annotations

import gzip
import hashlib
import io
import json
import os
from pathlib import Path
import plistlib
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import MagicMock
import zipfile

from rs9.errors import ContractError
from rs9.release_core import digest
from rs9.scratch import canonical
from rs9.verify_wheel import (
    verify_double_build,
    verify_offline_venv_lifecycle,
    verify_wheel_record_bidirectional,
)
from rs9.wheel import WheelWithheldError
from rs9.wheel_native import (
    REVIEWED_HELPERS,
    build_native_wheel as _build_native_wheel,
    extract_darwin_minimum_version,
    resolve_native_darwin_tag,
)


def build_native_wheel(*args, **kwargs):
    return _build_native_wheel(*args, fixture_only=True, **kwargs)


def make_darwin_archive(
    entries: list[tuple[str, bytes, int, int, str]],
) -> bytes:
    """Build a synthetic tar.gz archive with specified members (path, data, mode, type, linkname)."""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        for path, data, mode, kind, linkname in entries:
            ti = tarfile.TarInfo(path)
            ti.mode = mode
            ti.type = kind
            ti.linkname = linkname
            ti.size = len(data) if kind == tarfile.REGTYPE else 0
            tf.addfile(ti, io.BytesIO(data) if kind == tarfile.REGTYPE else None)
    return buf.getvalue()


def make_standard_darwin_entries(
    *,
    min_os: str = "11.0.0",
    launcher_script: bytes = b"#!/bin/sh\necho 'nebular 0.6.1 native'\nexit 0\n",
    extra_entries: list[tuple[str, bytes, int, int, str]] | None = None,
) -> list[tuple[str, bytes, int, int, str]]:
    plist = plistlib.dumps({"LSMinimumSystemVersion": min_os, "CFBundleIdentifier": "ai.knowledgeforge.nebular"})
    root = "Theme Forge Nebular Fusion.app"
    entries = [
        (root, b"", 0o755, tarfile.DIRTYPE, ""),
        (f"{root}/Contents", b"", 0o755, tarfile.DIRTYPE, ""),
        (f"{root}/Contents/Info.plist", plist, 0o644, tarfile.REGTYPE, ""),
        (f"{root}/Contents/MacOS", b"", 0o755, tarfile.DIRTYPE, ""),
        (f"{root}/Contents/MacOS/theme-forge-nebular-fusion", b"#!/bin/sh\nexit 0\n", 0o755, tarfile.REGTYPE, ""),
        (f"{root}/Contents/Resources", b"", 0o755, tarfile.DIRTYPE, ""),
        (f"{root}/Contents/Resources/bin", b"", 0o755, tarfile.DIRTYPE, ""),
        (f"{root}/Contents/Resources/bin/tfnf", launcher_script, 0o755, tarfile.REGTYPE, ""),
        (f"{root}/Contents/Resources/LICENSE", b"Synthetic AGPL-3.0-or-later license text.\n", 0o644, tarfile.REGTYPE, ""),
        (f"{root}/Contents/Resources/NOTICE", b"Synthetic notice.\n", 0o644, tarfile.REGTYPE, ""),
    ]
    if extra_entries:
        entries.extend(extra_entries)
    return entries


class WheelNativeTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name).resolve()

    def test_darwin_minimum_arm64_from_plist(self) -> None:
        # Valid macOS 11.0, 11.3, 12.0
        for ver_str, exp_major, exp_minor in (("11.0", 11, 0), ("11.3.1", 11, 3), ("12.0", 12, 0), ("14.5", 14, 5)):
            plist = plistlib.dumps({"LSMinimumSystemVersion": ver_str})
            major, minor = extract_darwin_minimum_version(plist)
            self.assertEqual((major, minor), (exp_major, exp_minor))
            tag = resolve_native_darwin_tag(plist)
            self.assertEqual(tag, f"py3-none-macosx_{exp_major}_{exp_minor}_arm64")

        # Refusal for Darwin arm64 < 11.0 (e.g. 10.15)
        plist_old = plistlib.dumps({"LSMinimumSystemVersion": "10.15.7"})
        self.assertEqual(extract_darwin_minimum_version(plist_old), (11, 0))

        # Refusal for missing or malformed plist
        with self.assertRaises(ContractError) as ctx:
            extract_darwin_minimum_version(b"not a valid plist")
        self.assertIn("INVALID_PLIST", str(ctx.exception))

        with self.assertRaises(ContractError) as ctx:
            extract_darwin_minimum_version(plistlib.dumps({}))
        self.assertIn("INVALID_PLIST", str(ctx.exception))

    def test_linux_manylinux_and_fake_universal_withholding(self) -> None:
        plist = plistlib.dumps({"LSMinimumSystemVersion": "11.0"})
        # 1. Linux wheel tags must NOT claim manylinux compliance with external GTK/WebKit dependencies
        for linux_tag in ("manylinux_2_34_x86_64", "manylinux2014_x86_64", "linux_x86_64", "musllinux_1_2_x86_64"):
            with self.assertRaises(WheelWithheldError) as ctx:
                resolve_native_darwin_tag(plist, platform_tag=linux_tag)
            self.assertEqual(ctx.exception.code, "MANYLINUX_UNPROVEN")
            self.assertEqual(ctx.exception.reason, "manylinux_unproven")

        # 2. Fake universal 'any' tag must be rejected
        with self.assertRaises(ContractError) as ctx:
            resolve_native_darwin_tag(plist, platform_tag="any")
        self.assertIn("UNSUPPORTED_PLATFORM", str(ctx.exception))

        # 3. Builder also withholds when target_platform is linux
        arc = make_darwin_archive(make_standard_darwin_entries())
        with self.assertRaises(WheelWithheldError) as ctx:
            build_native_wheel(
                "theme-forge-nebular-fusion",
                "0.6.1",
                archive_bytes=arc,
                target_platform="x86_64-unknown-linux-gnu",
                output_dir=self.root / "out",
            )
        self.assertEqual(ctx.exception.code, "MANYLINUX_UNPROVEN")

    def test_candidate_only_linux_wheels_build_and_fail_closed(self) -> None:
        arc = make_darwin_archive(make_standard_darwin_entries())
        # Default candidate_only=False withholds
        with self.assertRaises(WheelWithheldError) as ctx:
            build_native_wheel(
                "theme-forge-nebular-fusion",
                "0.6.1",
                archive_bytes=arc,
                target_platform="x86_64-unknown-linux-gnu",
                output_dir=self.root / "withheld",
            )
        self.assertEqual(ctx.exception.code, "MANYLINUX_UNPROVEN")

        # candidate_only=True builds honest Linux candidate wheel
        res_x86 = build_native_wheel(
            "theme-forge-nebular-fusion",
            "0.6.1",
            archive_bytes=arc,
            target_platform="x86_64-unknown-linux-gnu",
            candidate_only=True,
            output_dir=self.root / "cand_x86",
        )
        self.assertEqual(res_x86.filename, "theme_forge_nebular_fusion-0.6.1-py3-none-linux_x86_64.whl")
        self.assertFalse(res_x86.can_publish)
        self.assertTrue(res_x86.record["candidate_only"])
        self.assertEqual(res_x86.record["promotability"], "policy-pending")
        self.assertFalse(res_x86.record["manylinux_proven"])

        # aarch64 linux candidate
        res_arm = build_native_wheel(
            "theme-forge-nebular-fusion",
            "0.6.1",
            archive_bytes=arc,
            target_platform="aarch64-unknown-linux-gnu",
            candidate_only=True,
            output_dir=self.root / "cand_arm",
        )
        self.assertEqual(res_arm.filename, "theme_forge_nebular_fusion-0.6.1-py3-none-linux_aarch64.whl")

        # Deterministic double build and strict RECORD
        res_a, res_b = verify_double_build(
            build_native_wheel,
            "theme-forge-nebular-fusion",
            "0.6.1",
            archive_bytes=arc,
            target_platform="x86_64-unknown-linux-gnu",
            candidate_only=True,
            output_dir_a=self.root / "cand_db_a",
            output_dir_b=self.root / "cand_db_b",
        )
        self.assertEqual(res_a.wheel_bytes, res_b.wheel_bytes)
        inv = verify_wheel_record_bidirectional(res_a.wheel_path)
        self.assertTrue(inv["record_valid"])

        # Even with candidate_only=True, fake manylinux claim is strictly refused
        with self.assertRaises(WheelWithheldError):
            build_native_wheel(
                "theme-forge-nebular-fusion",
                "0.6.1",
                archive_bytes=arc,
                target_platform="x86_64-unknown-linux-gnu",
                platform_tag="manylinux_2_34_x86_64",
                candidate_only=True,
                output_dir=self.root / "fake_manylinux",
            )

    def test_raw_archive_cannot_claim_authenticated_release(self):
        archive = make_darwin_archive(make_standard_darwin_entries())
        with self.assertRaises(ContractError) as raised:
            _build_native_wheel("theme-forge-nebular-fusion", "0.6.1", archive_bytes=archive, output_dir=self.root / "out")
        self.assertEqual(raised.exception.code, "PROVENANCE_REQUIRED")

    def test_embedded_unchanged_helpers_and_exact_payload(self) -> None:
        arc_bytes = make_darwin_archive(make_standard_darwin_entries())
        res = build_native_wheel(
            "theme-forge-nebular-fusion",
            "0.6.1",
            archive_bytes=arc_bytes,
            output_dir=self.root / "out",
        )
        self.assertEqual(res.filename, "theme_forge_nebular_fusion-0.6.1-py3-none-macosx_11_0_arm64.whl")

        with zipfile.ZipFile(res.wheel_path) as zf:
            names = set(zf.namelist())
            # Check embedded helpers under isolated package namespace
            rs9_src = Path("src/rs9")
            for helper in REVIEWED_HELPERS:
                member_name = f"theme_forge_nebular_fusion/_isolated/rs9/{helper}"
                self.assertIn(member_name, names)
                actual_bytes = zf.read(member_name)
                expected_bytes = (rs9_src / helper).read_bytes()
                self.assertEqual(actual_bytes, expected_bytes, f"Helper {helper} bytes must be unchanged")

            # Check exact compressed released payload bytes
            payload_name = "theme_forge_nebular_fusion/payload/theme-forge-nebular-fusion-v0.6.1-aarch64-apple-darwin.app.tar.gz"
            self.assertIn(payload_name, names)
            self.assertEqual(zf.read(payload_name), arc_bytes)

            # Check manifest and provenance
            self.assertIn("theme_forge_nebular_fusion/payload/manifest.json", names)
            prov = json.loads(zf.read("theme_forge_nebular_fusion/_rs9/provenance.json").decode("utf-8"))
            self.assertFalse(prov["can_publish"])
            self.assertEqual(prov["payload_archive_sha256"], digest(arc_bytes))

    def test_fail_closed_on_unsafe_archive_modes_and_symlinks(self) -> None:
        root = "Theme Forge Nebular Fusion.app"
        # 1. Privileged mode (setuid 0o4755)
        bad_mode_entries = make_standard_darwin_entries(
            extra_entries=[(f"{root}/Contents/MacOS/evil", b"evil", 0o4755, tarfile.REGTYPE, "")]
        )
        bad_arc = make_darwin_archive(bad_mode_entries)
        with self.assertRaises(ContractError) as ctx:
            build_native_wheel("theme-forge-nebular-fusion", "0.6.1", archive_bytes=bad_arc, output_dir=self.root / "out")
        self.assertIn("UNSAFE_MODE", str(ctx.exception))

        # 2. Escaping symlink
        bad_link_entries = make_standard_darwin_entries(
            extra_entries=[(f"{root}/Contents/Resources/escape", b"", 0o755, tarfile.SYMTYPE, "../../../etc/passwd")]
        )
        bad_link_arc = make_darwin_archive(bad_link_entries)
        with self.assertRaises(ContractError) as ctx:
            build_native_wheel("theme-forge-nebular-fusion", "0.6.1", archive_bytes=bad_link_arc, output_dir=self.root / "out")
        self.assertIn("UNSAFE_LINK", str(ctx.exception))

        # 3. Hard link
        bad_hardlink_entries = make_standard_darwin_entries(
            extra_entries=[(f"{root}/Contents/MacOS/hardlink", b"", 0o755, tarfile.LNKTYPE, f"{root}/Contents/MacOS/theme-forge-nebular-fusion")]
        )
        bad_hardlink_arc = make_darwin_archive(bad_hardlink_entries)
        with self.assertRaises(ContractError) as ctx:
            build_native_wheel("theme-forge-nebular-fusion", "0.6.1", archive_bytes=bad_hardlink_arc, output_dir=self.root / "out")
        self.assertIn("UNSAFE_LINK", str(ctx.exception))

    def test_double_build_determinism_and_record(self) -> None:
        arc_bytes = make_darwin_archive(make_standard_darwin_entries())

        res_a, res_b = verify_double_build(
            build_native_wheel,
            "theme-forge-nebular-fusion",
            "0.6.1",
            archive_bytes=arc_bytes,
            output_dir_a=self.root / "build_a",
            output_dir_b=self.root / "build_b",
        )
        self.assertEqual(res_a.wheel_bytes, res_b.wheel_bytes)
        self.assertEqual(res_a.sha256, res_b.sha256)
        self.assertEqual(res_a.filename, "theme_forge_nebular_fusion-0.6.1-py3-none-macosx_11_0_arm64.whl")

        inv = verify_wheel_record_bidirectional(res_a.wheel_path)
        self.assertTrue(inv["record_valid"])
        self.assertGreater(inv["member_count"], 10)

    @unittest.skipUnless(sys.platform == "darwin", "Darwin native wheel launcher execution requires macOS")
    def test_offline_venv_materialize_and_uninstall_lifecycle(self) -> None:
        arc_bytes = make_darwin_archive(
            make_standard_darwin_entries(launcher_script=b"#!/bin/sh\necho 'nebular live venv'\nexit 0\n")
        )
        res = build_native_wheel(
            "theme-forge-nebular-fusion",
            "0.6.1",
            archive_bytes=arc_bytes,
            output_dir=self.root / "wheel_out",
        )

        venv_dir = self.root / "native_venv"
        cache_dir = self.root / "runtime-cache"
        report = verify_offline_venv_lifecycle(
            res.wheel_path,
            distribution_name="theme-forge-nebular-fusion",
            commands_to_test={
                "tfnf": {"argv": [], "expect_exit": 0, "expect_stdout_contains": "nebular live venv",
                         "env": {"THEME_FORGE_CACHE_DIR": str(cache_dir)}}
            },
            venv_dir=venv_dir,
            cache_dir=cache_dir,
        )
        self.assertTrue(report["clean_uninstall_verified"])
        self.assertEqual(report["venv_residuals"], [])

        # Truthfully verify materialization cache persistence across uninstall without claiming pip removed it
        cache_info = report["materialization_cache"]
        self.assertTrue(cache_info["materialized"])
        self.assertTrue(cache_info["persisted_after_uninstall"])
        self.assertFalse(cache_info["pip_removed"])
        self.assertTrue(cache_info["persistent_cache_documented"])
        self.assertTrue((cache_dir / "entries").exists())

    @unittest.skipUnless(sys.platform == "darwin", "Darwin native wheel launcher execution requires macOS")
    def test_offline_venv_residual_files_rejected(self) -> None:
        arc_bytes = make_darwin_archive(
            make_standard_darwin_entries(launcher_script=b"#!/bin/sh\necho 'nebular live'\nexit 0\n")
        )
        res = build_native_wheel(
            "theme-forge-nebular-fusion",
            "0.6.1",
            archive_bytes=arc_bytes,
            output_dir=self.root / "wheel_res_out",
        )
        venv_dir = self.root / "dirty_venv"
        cache_dir = self.root / "dirty_cache"

        with self.assertRaises(ContractError) as ctx:
            verify_offline_venv_lifecycle(
                res.wheel_path,
                distribution_name="theme-forge-nebular-fusion",
                commands_to_test={
                    "tfnf": {"argv": [], "expect_exit": 0,
                             "env": {"THEME_FORGE_CACHE_DIR": str(cache_dir)}}
                },
                venv_dir=venv_dir,
                cache_dir=cache_dir,
                command_prefix=[
                    "bash", "-c",
                    'touch "$(dirname "$1")/rogue_native_leftover.txt" && exec "$@"',
                    "inline_wrapper",
                ],
            )
        self.assertEqual(ctx.exception.code, "DIRTY_UNINSTALL")
        self.assertIn("rogue_native_leftover.txt", str(ctx.exception))

    @unittest.skipUnless(sys.platform == "darwin", "Darwin native wheel launcher execution requires macOS")
    def test_offline_venv_isolated_cache_lifecycle(self) -> None:
        arc_bytes = make_darwin_archive(
            make_standard_darwin_entries(launcher_script=b"#!/bin/sh\necho 'nebular isolated'\nexit 0\n")
        )
        res = build_native_wheel(
            "theme-forge-nebular-fusion",
            "0.6.1",
            archive_bytes=arc_bytes,
            output_dir=self.root / "wheel_isolated_out",
        )
        venv_dir = self.root / "isolated_venv"
        report = verify_offline_venv_lifecycle(
            res.wheel_path,
            distribution_name="theme-forge-nebular-fusion",
            commands_to_test={
                "tfnf": {"argv": [], "expect_exit": 0, "expect_stdout_contains": "nebular isolated"}
            },
            venv_dir=venv_dir,
        )
        self.assertTrue(report["clean_uninstall_verified"])
        self.assertEqual(report["venv_residuals"], [])
        self.assertTrue(report["materialization_cache"]["materialized"])
        self.assertTrue(report["materialization_cache"]["persisted_after_uninstall"])
        self.assertFalse(report["materialization_cache"]["pip_removed"])

    def test_refusal_on_invalid_version_and_symlink_destination(self) -> None:
        arc_bytes = make_darwin_archive(make_standard_darwin_entries())
        # Invalid product version
        with self.assertRaises(ContractError) as ctx:
            build_native_wheel("theme-forge-nebular-fusion", "0.6.2", archive_bytes=arc_bytes, output_dir=self.root / "out")
        self.assertIn("INVALID_VERSION", str(ctx.exception))

        # Destination ancestry symlink
        link = self.root / "link_dir"
        real = self.root / "real_dir"
        real.mkdir()
        link.symlink_to(real, target_is_directory=True)
        with self.assertRaises(ContractError) as ctx:
            build_native_wheel("theme-forge-nebular-fusion", "0.6.1", archive_bytes=arc_bytes, output_dir=link)
        self.assertIn("UNSAFE_DESTINATION", str(ctx.exception))

    def test_build_native_wheel_with_system_parameter(self) -> None:
        """Verify build_native_wheel respects system parameter across all 3 systems."""
        arc_bytes = make_darwin_archive(make_standard_darwin_entries())

        # 1. Darwin
        res_darwin = build_native_wheel(
            "theme-forge-nebular-fusion",
            "0.6.1",
            archive_bytes=arc_bytes,
            system="aarch64-darwin",
            output_dir=self.root / "out_darwin",
        )
        self.assertEqual(res_darwin.filename, "theme_forge_nebular_fusion-0.6.1-py3-none-macosx_11_0_arm64.whl")
        self.assertFalse(res_darwin.can_publish)

        # 2. Linux x86_64 candidate
        res_x86 = build_native_wheel(
            "theme-forge-nebular-fusion",
            "0.6.1",
            archive_bytes=arc_bytes,
            system="x86_64-linux",
            candidate_only=True,
            output_dir=self.root / "out_x86",
        )
        self.assertEqual(res_x86.filename, "theme_forge_nebular_fusion-0.6.1-py3-none-linux_x86_64.whl")
        self.assertFalse(res_x86.can_publish)
        self.assertTrue(res_x86.record["candidate_only"])
        self.assertEqual(res_x86.record["promotability"], "policy-pending")
        self.assertFalse(res_x86.record["manylinux_proven"])

        # 3. Linux aarch64 candidate
        res_arm = build_native_wheel(
            "theme-forge-nebular-fusion",
            "0.6.1",
            archive_bytes=arc_bytes,
            system="aarch64-linux",
            candidate_only=True,
            output_dir=self.root / "out_arm",
        )
        self.assertEqual(res_arm.filename, "theme_forge_nebular_fusion-0.6.1-py3-none-linux_aarch64.whl")
        self.assertFalse(res_arm.can_publish)
        self.assertTrue(res_arm.record["candidate_only"])
        self.assertEqual(res_arm.record["promotability"], "policy-pending")
        self.assertFalse(res_arm.record["manylinux_proven"])

    def test_build_native_wheel_select_payload_capture_integration(self) -> None:
        """Verify build_native_wheel uses select_payload to resolve capture payload without name guessing."""
        arc_bytes = make_darwin_archive(make_standard_darwin_entries())
        arc_sha = digest(arc_bytes)
        from rs9.archives import inspect_archive
        arc_file = self.root / "darwin.tar.gz"
        arc_file.write_bytes(arc_bytes)
        manifest = inspect_archive(arc_file, commands={})

        mock_capture = MagicMock()
        mock_capture._proof = None
        mock_capture.record = {
            "repository": {"full_name": "Knowledge-Forge-AI/theme-forge-nebular-fusion"},
            "release": {"tag": "v0.6.1"},
            "payloads": [
                {
                    "id": "darwin-arm64",
                    "name": "darwin.tar.gz",
                    "platforms": ["aarch64-darwin"],
                    "size": len(arc_bytes),
                    "sha256": arc_sha,
                    "payload_manifest_sha256": manifest["manifest_sha256"],
                }
            ],
        }
        mock_capture.archives = {"darwin-arm64": arc_file}
        mock_capture.manifests = {"darwin-arm64": manifest}

        # Build with matching system
        res = build_native_wheel(
            "theme-forge-nebular-fusion",
            "0.6.1",
            capture=mock_capture,
            system="aarch64-darwin",
            output_dir=self.root / "out_capture_darwin",
        )
        self.assertEqual(res.filename, "theme_forge_nebular_fusion-0.6.1-py3-none-macosx_11_0_arm64.whl")

        # Build with missing system fails with MISSING_ASSET
        with self.assertRaises(ContractError) as ctx:
            build_native_wheel(
                "theme-forge-nebular-fusion",
                "0.6.1",
                capture=mock_capture,
                system="x86_64-linux",
                candidate_only=True,
                output_dir=self.root / "out_missing",
            )
        self.assertEqual(ctx.exception.code, "MISSING_ASSET")
        self.assertEqual(ctx.exception.details.get("asset_platform"), "x86_64-linux")

    def test_inconsistent_system_and_target_platform_rejected(self) -> None:
        """Explicit inconsistent system and target_platform triple must be rejected."""
        arc_bytes = make_darwin_archive(make_standard_darwin_entries())
        with self.assertRaises(ContractError) as ctx:
            build_native_wheel(
                "theme-forge-nebular-fusion",
                "0.6.1",
                archive_bytes=arc_bytes,
                system="x86_64-linux",
                target_platform="aarch64-apple-darwin",
                candidate_only=True,
                output_dir=self.root / "out_inconsistent",
            )
        self.assertEqual(ctx.exception.code, "INCONSISTENT_PLATFORM")
        self.assertEqual(ctx.exception.details.get("system"), "x86_64-linux")
        self.assertEqual(ctx.exception.details.get("target_triple"), "aarch64-apple-darwin")

        # Consistent system and triple succeeds
        res = build_native_wheel(
            "theme-forge-nebular-fusion",
            "0.6.1",
            archive_bytes=arc_bytes,
            system="x86_64-linux",
            target_platform="x86_64-unknown-linux-gnu",
            candidate_only=True,
            output_dir=self.root / "out_consistent",
        )
        self.assertEqual(res.filename, "theme_forge_nebular_fusion-0.6.1-py3-none-linux_x86_64.whl")

    def test_darwin_wheel_tag_reflects_actual_plist_floor(self) -> None:
        """Darwin wheel tag dynamically reads deployment floor from Info.plist, not hardcoded 11.0."""
        arc_bytes = make_darwin_archive(make_standard_darwin_entries(min_os="13.0.0"))
        res = build_native_wheel(
            "theme-forge-nebular-fusion",
            "0.6.1",
            archive_bytes=arc_bytes,
            system="aarch64-darwin",
            output_dir=self.root / "out_darwin_13",
        )
        self.assertEqual(res.tag, "py3-none-macosx_13_0_arm64")
        self.assertEqual(res.filename, "theme_forge_nebular_fusion-0.6.1-py3-none-macosx_13_0_arm64.whl")

    def test_legacy_target_platform_triple_conversion(self) -> None:
        """Legacy target_platform triple is converted at API boundary; invalid triple rejected."""
        arc_bytes = make_darwin_archive(make_standard_darwin_entries())
        with self.assertRaises(ContractError) as ctx:
            build_native_wheel(
                "theme-forge-nebular-fusion",
                "0.6.1",
                archive_bytes=arc_bytes,
                target_platform="invalid-triple",
                output_dir=self.root / "out_invalid_triple",
            )
        self.assertEqual(ctx.exception.code, "INVALID_ARCHITECTURE")
