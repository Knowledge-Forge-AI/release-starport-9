"""Focused tests for the non-admitted Nebular Python distribution successor."""
from __future__ import annotations

import json
import os
import subprocess
import sys
import tarfile
import tempfile
import unittest
import zipfile
from pathlib import Path

from rs9.archives import inspect_archive
from rs9.errors import ContractError
from rs9.profiles import TAURI_PROFILE, evaluate_profile, selection_for_intent
from rs9.records import record_sha256
from rs9.release_core import ReleaseCapture, authenticate_release, digest
from rs9.scratch import canonical
from rs9.verify_wheel import verify_wheel_record_bidirectional
from rs9.wheel import WheelWithheldError
from rs9.wheel_native import get_embedded_rs9_helpers
from rs9.wheel_nebular_successor import (
    DEFAULT_DESCRIPTION_PATH,
    DESCRIPTION_070_PATH,
    DISTRIBUTION_VERSION,
    LEGAL_FILES,
    LICENSE_EXPRESSION,
    SUCCESSOR_RELEASES,
    _rs9_source_binding,
    build_successor_wheel,
    successor_release,
)
from tests.shadow_fixtures import fixture_evidence
from tests.test_wheel_native import make_darwin_archive, make_standard_darwin_entries


def _archive() -> bytes:
    return make_darwin_archive(
        make_standard_darwin_entries(
            launcher_script=b"#!/bin/sh\nprintf 'argv:%s\\n' \"$*\"\n",
        )
    )


def _linux_archive() -> bytes:
    root = "theme-forge-nebular-fusion"
    return make_darwin_archive([
        (root, b"", 0o755, tarfile.DIRTYPE, ""),
        (f"{root}/bin", b"", 0o755, tarfile.DIRTYPE, ""),
        (f"{root}/bin/tfnf", b"#!/bin/sh\nprintf 'argv:%s\\n' \"$*\"\n", 0o755, tarfile.REGTYPE, ""),
        (f"{root}/bin/theme-forge-nebular-fusion", b"#!/bin/sh\nexit 0\n", 0o755, tarfile.REGTYPE, ""),
    ])


def _legal() -> dict[str, bytes]:
    return {
        "LICENSE": b"AGPL-3.0-or-later\n",
        "NOTICE": b"Theme Forge notice.\n",
        "COMMERCIAL-LICENSE.md": b"Commercial terms apply.\n",
    }


class NebularSuccessorTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory(
            prefix="rs9-successor-test-", dir=str(Path(__file__).resolve().parents[1])
        )
        self.root = Path(self.tmp.name)
        self.archive = _archive()
        self.legal = _legal()
        self.launcher = "Theme Forge Nebular Fusion.app/Contents/Resources/bin/tfnf"
        self.gui = "Theme Forge Nebular Fusion.app/Contents/MacOS/theme-forge-nebular-fusion"

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def _build(self, name: str = "wheel", **kwargs):
        license_files = kwargs.pop("license_files", self.legal)
        archive_bytes = kwargs.pop("archive_bytes", self.archive)
        launcher_path = kwargs.pop("launcher_path", self.launcher)
        gui_path = kwargs.pop("gui_path", self.gui)
        return build_successor_wheel(
            "theme-forge-nebular-fusion",
            archive_bytes=archive_bytes,
            output_dir=self.root / name,
            license_files=license_files,
            launcher_path=launcher_path,
            gui_path=gui_path,
            fixture_only=True,
            **kwargs,
        )

    def _authenticated_capture(self):
        evidence_root = self.root / "authenticated"
        intent = fixture_evidence(evidence_root)
        source = {
            name: (evidence_root / "source" / name).read_bytes()
            for name in ("LICENSE", "NOTICE")
        }
        asset = next(row for row in intent["assets"] if row["id"] == "darwin-arm64")
        entries = make_standard_darwin_entries(
            launcher_script=b"#!/bin/sh\nprintf 'argv:%s\\n' \"$*\"\n",
        )
        entries = [
            (path, source.get(path.rsplit("/", 1)[-1], data), mode, kind, link)
            for path, data, mode, kind, link in entries
        ]
        (evidence_root / "assets" / asset["name"]).write_bytes(make_darwin_archive(entries))
        staged = {
            path.name: path.read_bytes()
            for path in (evidence_root / "assets").iterdir()
            if path.name != "SHA256SUMS"
        }
        (evidence_root / "assets" / "SHA256SUMS").write_bytes(
            "".join(digest(data) + "  " + name + "\n" for name, data in sorted(staged.items())).encode()
        )
        release_path = evidence_root / "api" / "release.json"
        release = json.loads(release_path.read_bytes())
        for row in release["assets"]:
            if row["name"] in (asset["name"], "SHA256SUMS"):
                data = (evidence_root / "assets" / row["name"]).read_bytes()
                row["size"] = len(data)
                row["digest"] = "sha256:" + digest(data)
        release_path.write_bytes(canonical(release))
        capture = authenticate_release(selection_for_intent(intent), evidence_root)
        profile = evaluate_profile(capture, TAURI_PROFILE, intent)
        return capture, profile

    def test_deterministic_build_has_post_version_metadata_and_three_legal_files(self) -> None:
        first = self._build("first")
        second = self._build("second")
        self.assertEqual(first.wheel_bytes, second.wheel_bytes)
        self.assertEqual(first.version, DISTRIBUTION_VERSION)
        self.assertFalse(first.can_publish)
        self.assertEqual(first.record["application_version"], "0.6.1")
        self.assertFalse(first.record["publication_admitted"])
        self.assertEqual(first.record["source_closure"]["admitted"], False)
        self.assertEqual(verify_wheel_record_bidirectional(first.wheel_path)["record_valid"], True)
        with zipfile.ZipFile(first.wheel_path) as archive:
            metadata = archive.read("theme_forge_nebular_fusion-0.6.1.post1.dist-info/METADATA").decode()
            self.assertIn(f"License-Expression: {LICENSE_EXPRESSION}\n", metadata)
            self.assertIn("Description-Content-Type: text/markdown\n", metadata)
            for name in LEGAL_FILES:
                self.assertIn(f"License-File: {name}\n", metadata)
                self.assertEqual(archive.read(f"theme_forge_nebular_fusion-0.6.1.post1.dist-info/licenses/{name}"), self.legal[name])
            provenance = json.loads(archive.read("theme_forge_nebular_fusion/_rs9/provenance.json"))
            self.assertEqual(provenance["distribution_version"], "0.6.1.post1")
            self.assertFalse(provenance["builder_can_publish"])
            self.assertEqual(provenance["payload_archive_sha256"], digest(self.archive))
            self.assertIsNone(provenance["selected_asset_id"])
            self.assertIsNone(provenance["profile_result_sha256"])
            self.assertEqual(provenance["license_facts"], {"status": None, "comparison": None})
            self.assertEqual(provenance["launcher_path"], self.launcher)
            self.assertEqual(provenance["gui_path"], self.gui)
            self.assertEqual(provenance["rs9_source"]["status"], "pending")
            self.assertFalse(provenance["rs9_source"]["verified"])
            self.assertEqual(provenance["readme_authority"]["source"], "rs9-candidate-input")
            self.assertFalse(provenance["readme_authority"]["verified"])
            self.assertEqual(provenance["source_closure"], {
                "status": "pending", "receipt_sha256": None, "admitted": False,
            })
            self.assertEqual(provenance["policy"], {
                "status": "pending", "receipt_sha256": None, "manylinux_proven": False,
            })
            for name in LEGAL_FILES:
                self.assertEqual(provenance["legal_files"][name], {
                    "path": name, "size": len(self.legal[name]), "sha256": digest(self.legal[name]),
                })
            launcher_member = "theme_forge_nebular_fusion/launcher.py"
            metadata_member = "theme_forge_nebular_fusion-0.6.1.post1.dist-info/METADATA"
            self.assertEqual(provenance["launcher_sha256"], digest(archive.read(launcher_member)))
            self.assertEqual(provenance["metadata_sha256"], digest(archive.read(metadata_member)))
            payload_member = (
                "theme_forge_nebular_fusion/payload/"
                "theme-forge-nebular-fusion-v0.6.1-aarch64-apple-darwin.app.tar.gz"
            )
            self.assertEqual(archive.read(payload_member), self.archive)
            observed_payload_members = {
                name for name in archive.namelist()
                if name.startswith((
                    "theme_forge_nebular_fusion/payload/",
                    "theme_forge_nebular_fusion/_isolated/",
                ))
            }
            expected_payload_members = {
                payload_member,
                "theme_forge_nebular_fusion/payload/manifest.json",
                *(f"theme_forge_nebular_fusion/_isolated/{name}" for name in get_embedded_rs9_helpers()),
            }
            self.assertEqual(observed_payload_members, expected_payload_members)
            self.assertIn("theme_forge_nebular_fusion/_isolated/rs9/materialize.py", archive.namelist())

    def test_version_drift_and_incomplete_legal_set_fail_closed(self) -> None:
        with self.assertRaises(ContractError) as raised:
            self._build(application_version="0.6.2")
        self.assertIn("INVALID_VERSION", str(raised.exception))
        with self.assertRaises(ContractError) as raised:
            self._build(license_files={"LICENSE": self.legal["LICENSE"], "NOTICE": self.legal["NOTICE"]})
        self.assertIn("LEGAL_FILES", str(raised.exception))

    def test_fixture_build_rejects_unverified_profile_claims(self) -> None:
        with self.assertRaises(ContractError) as raised:
            self._build(profile_result={"sections": {"license": {"status": "consistent"}}})
        self.assertEqual(raised.exception.code, "FIXTURE_AUTHORITY")

    def test_fixture_manifest_must_match_archive(self) -> None:
        archive_path = self.root / "payload.tar.gz"
        archive_path.write_bytes(self.archive)
        actual = inspect_archive(archive_path, commands={})
        mismatched = json.loads(json.dumps(actual))
        mismatched["members"][0]["size"] += 1
        mismatched["manifest_sha256"] = digest(canonical(mismatched["members"]))
        with self.assertRaises(ContractError) as raised:
            self._build("manifest-mismatch", manifest=mismatched)
        self.assertIn("INPUT_CHANGED", str(raised.exception))

    def test_authenticated_overrides_and_unproofed_capture_fail_closed(self) -> None:
        capture, profile = self._authenticated_capture()
        accepted = build_successor_wheel(
            "theme-forge-nebular-fusion",
            capture=capture,
            profile_result=profile,
            output_dir=self.root / "authenticated-accepted",
            rs9_source_commit="a" * 40,
            rs9_source_tree="b" * 40,
        )
        expected_payload = next(
            row for row in capture.record["payloads"] if "aarch64-darwin" in row["platforms"]
        )
        self.assertEqual(accepted.record["launcher_path"], expected_payload["launchers"]["tfnf"]["path"])
        self.assertEqual(accepted.record["gui_path"], expected_payload["commands"]["tfnf"]["path"])
        self.assertEqual(accepted.record["selected_asset_id"], "darwin-arm64")
        self.assertEqual(accepted.record["profile_result_sha256"], record_sha256(profile))
        self.assertEqual(accepted.record["license_facts"]["status"], "consistent")
        readme = (
            Path(__file__).resolve().parents[1] / "operators/tf-pypi/descriptions/nebular-fusion.md"
        ).read_bytes()
        with zipfile.ZipFile(accepted.wheel_path) as archive:
            metadata = archive.read("theme_forge_nebular_fusion-0.6.1.post1.dist-info/METADATA")
        self.assertTrue(metadata.endswith(readme))
        self.assertEqual(accepted.record["readme_sha256"], digest(readme))
        self.assertEqual(accepted.record["readme_authority"], {
            "source": "rs9-candidate-input",
            "path": "operators/tf-pypi/descriptions/nebular-fusion.md",
            "sha256": digest(readme),
            "rs9_source": {
                "status": "candidate-input",
                "binding": "explicit-reviewed-source-input",
                "commit": "a" * 40,
                "tree": "b" * 40,
                "verified": False,
            },
            "verified": False,
        })
        self.assertFalse(accepted.record["builder_can_publish"])

        with self.assertRaises(ContractError) as raised:
            build_successor_wheel(
                "theme-forge-nebular-fusion",
                capture=capture,
                profile_result=profile,
                output_dir=self.root / "launcher-override",
                launcher_path="Theme Forge Nebular Fusion.app/Contents/Resources/bin/other",
                rs9_source_commit="a" * 40,
                rs9_source_tree="b" * 40,
            )
        self.assertIn("COMMAND_OVERRIDE", str(raised.exception))
        with self.assertRaises(ContractError) as raised:
            build_successor_wheel(
                "theme-forge-nebular-fusion",
                capture=capture,
                profile_result=profile,
                output_dir=self.root / "gui-override",
                gui_path="Theme Forge Nebular Fusion.app/Contents/MacOS/other",
                rs9_source_commit="a" * 40,
                rs9_source_tree="b" * 40,
            )
        self.assertIn("COMMAND_OVERRIDE", str(raised.exception))
        unauthenticated = ReleaseCapture({}, {}, {}, {}, {}, {}, self.root)
        with self.assertRaises(ContractError) as raised:
            build_successor_wheel(
                "theme-forge-nebular-fusion",
                capture=unauthenticated,
                output_dir=self.root / "unproofed",
            )
        self.assertIn("RELEASE_CAPTURE", str(raised.exception))

    def test_rs9_source_binding_requires_explicit_pair(self) -> None:
        with self.assertRaises(ContractError) as raised:
            _rs9_source_binding("a" * 40, None, fixture_only=False)
        self.assertIn("RS9_SOURCE_IDENTITY", str(raised.exception))
        with self.assertRaises(ContractError) as raised:
            _rs9_source_binding("A" * 40, "b" * 40, fixture_only=False)
        self.assertIn("RS9_SOURCE_IDENTITY", str(raised.exception))
        with self.assertRaises(ContractError) as raised:
            _rs9_source_binding(1, "b" * 40, fixture_only=False)
        self.assertIn("RS9_SOURCE_IDENTITY", str(raised.exception))
        binding = _rs9_source_binding("a" * 40, "b" * 40, fixture_only=False)
        self.assertEqual(binding["status"], "candidate-input")
        self.assertFalse(binding["verified"])

    def test_linux_is_candidate_only_and_manylinux_is_withheld(self) -> None:
        with self.assertRaises(WheelWithheldError) as raised:
            self._build(
                archive_bytes=_linux_archive(),
                launcher_path="theme-forge-nebular-fusion/bin/tfnf",
                gui_path="theme-forge-nebular-fusion/bin/theme-forge-nebular-fusion",
                system="x86_64-linux", target_platform="x86_64-unknown-linux-gnu",
            )
        self.assertEqual(raised.exception.code, "MANYLINUX_UNPROVEN")
        candidate = self._build(
            "linux", archive_bytes=_linux_archive(),
            launcher_path="theme-forge-nebular-fusion/bin/tfnf",
            gui_path="theme-forge-nebular-fusion/bin/theme-forge-nebular-fusion",
            system="x86_64-linux", target_platform="x86_64-unknown-linux-gnu", candidate_only=True
        )
        self.assertEqual(candidate.tag, "py3-none-linux_x86_64")
        self.assertFalse(candidate.can_publish)
        arm_candidate = self._build(
            "linux_arm", archive_bytes=_linux_archive(),
            launcher_path="theme-forge-nebular-fusion/bin/tfnf",
            gui_path="theme-forge-nebular-fusion/bin/theme-forge-nebular-fusion",
            system="aarch64-linux", target_platform="aarch64-unknown-linux-gnu", candidate_only=True
        )
        self.assertEqual(arm_candidate.tag, "py3-none-linux_aarch64")
        with self.assertRaises(WheelWithheldError):
            self._build(
                "manylinux", archive_bytes=_linux_archive(),
                launcher_path="theme-forge-nebular-fusion/bin/tfnf",
                gui_path="theme-forge-nebular-fusion/bin/theme-forge-nebular-fusion",
                system="x86_64-linux", target_platform="x86_64-unknown-linux-gnu",
                platform_tag="manylinux_2_28_x86_64", candidate_only=True,
            )

    def test_platform_tag_must_match_exact_supported_system(self) -> None:
        with self.assertRaises(ContractError) as raised:
            self._build("darwin-linux-tag", platform_tag="linux_x86_64")
        self.assertIn("INCONSISTENT_PLATFORM", str(raised.exception))
        with self.assertRaises(ContractError) as raised:
            self._build(
                "linux-wrong-arch", archive_bytes=_linux_archive(),
                launcher_path="theme-forge-nebular-fusion/bin/tfnf",
                gui_path="theme-forge-nebular-fusion/bin/theme-forge-nebular-fusion",
                system="aarch64-linux", target_platform="aarch64-unknown-linux-gnu",
                platform_tag="linux_x86_64", candidate_only=True,
            )
        self.assertIn("INCONSISTENT_PLATFORM", str(raised.exception))
        with self.assertRaises(ContractError) as raised:
            self._build("unsupported-system", system="x86_64-darwin")
        self.assertIn("INVALID_ARCHITECTURE", str(raised.exception))

    def test_record_tamper_is_detected(self) -> None:
        result = self._build()
        tampered = self.root / "tampered.whl"
        with zipfile.ZipFile(result.wheel_path) as source, zipfile.ZipFile(tampered, "w") as destination:
            for info in source.infolist():
                body = source.read(info.filename)
                if info.filename.endswith(("/launcher.py", "/METADATA", "/provenance.json")):
                    body += b"\n# tampered\n"
                destination.writestr(info, body)
        with self.assertRaises(ContractError) as raised:
            verify_wheel_record_bidirectional(tampered)
        self.assertIn("RECORD_MISMATCH", str(raised.exception))

    def test_launcher_flags_path_and_argument_forwarding(self) -> None:
        result = self._build()
        extracted = self.root / "extract"
        with zipfile.ZipFile(result.wheel_path) as archive:
            archive.extractall(extracted)
        runner = self.root / "run.py"
        runner.write_text(
            "import platform, sys\n"
            "platform.machine = lambda: 'arm64'\n"
            "sys.platform = 'darwin'\n"
            "sys.path.insert(0, sys.argv[1])\n"
            "from theme_forge_nebular_fusion.launcher import run_launcher\n"
            "raise SystemExit(run_launcher('tfnf', sys.argv[2:]))\n",
            encoding="utf-8",
        )
        def run(*args: str) -> subprocess.CompletedProcess[str]:
            return subprocess.run(
                [sys.executable, str(runner), str(extracted), *args],
                check=False, capture_output=True, text=True,
                env={**os.environ, "THEME_FORGE_CACHE_DIR": str(self.root / "cache")},
            )
        version = run("--version")
        self.assertEqual(version.returncode, 0)
        self.assertEqual(version.stdout.strip(), "theme-forge-nebular-fusion 0.6.1.post1")
        help_result = run("--help")
        self.assertEqual(help_result.returncode, 0)
        self.assertIn("Usage: tfnf", help_result.stdout)
        path_result = run("--path")
        self.assertEqual(path_result.returncode, 0)
        self.assertTrue(Path(path_result.stdout.strip()).is_absolute())
        self.assertTrue(path_result.stdout.strip().endswith("theme-forge-nebular-fusion"))
        forwarded = run("one", "two")
        self.assertEqual(forwarded.returncode, 0)
        self.assertEqual(forwarded.stdout.strip(), "argv:one two")

    def test_linux_launcher_checks_target_architecture_and_glibc(self) -> None:
        result = self._build(
            "linux-launcher", archive_bytes=_linux_archive(),
            launcher_path="theme-forge-nebular-fusion/bin/tfnf",
            gui_path="theme-forge-nebular-fusion/bin/theme-forge-nebular-fusion",
            system="x86_64-linux", target_platform="x86_64-unknown-linux-gnu",
            candidate_only=True,
        )
        extracted = self.root / "linux-extract"
        with zipfile.ZipFile(result.wheel_path) as archive:
            archive.extractall(extracted)
        runner = self.root / "run-linux.py"
        runner.write_text(
            "import platform, sys\n"
            "machine, libc, package = sys.argv[1:4]\n"
            "platform.machine = lambda: machine\n"
            "platform.libc_ver = lambda: (libc, '2.28')\n"
            "sys.platform = 'linux'\n"
            "sys.path.insert(0, package)\n"
            "from theme_forge_nebular_fusion.launcher import run_launcher\n"
            "raise SystemExit(run_launcher('tfnf', sys.argv[4:]))\n",
            encoding="utf-8",
        )

        def run(
            machine: str,
            libc: str,
            *,
            cache_value: str | None | object = "default",
            xdg: str | None = None,
            home: Path | None = None,
            cwd: Path | None = None,
        ) -> subprocess.CompletedProcess[str]:
            env = dict(os.environ)
            if cache_value == "default":
                env["THEME_FORGE_CACHE_DIR"] = str(self.root / "linux-cache")
            elif cache_value is None:
                env.pop("THEME_FORGE_CACHE_DIR", None)
            else:
                env["THEME_FORGE_CACHE_DIR"] = str(cache_value)
            if xdg is not None:
                env["XDG_CACHE_HOME"] = xdg
            if home is not None:
                env["HOME"] = str(home)
            return subprocess.run(
                [sys.executable, str(runner), machine, libc, str(extracted), "--path"],
                check=False, capture_output=True, text=True,
                cwd=cwd, env=env,
            )

        valid = run("x86_64", "glibc")
        self.assertEqual(valid.returncode, 0, valid.stderr)
        self.assertTrue(Path(valid.stdout.strip()).is_absolute())
        wrong_arch = run("aarch64", "glibc")
        self.assertNotEqual(wrong_arch.returncode, 0)
        self.assertIn("target architecture", wrong_arch.stderr)
        wrong_libc = run("x86_64", "musl")
        self.assertNotEqual(wrong_libc.returncode, 0)
        self.assertIn("GNU glibc", wrong_libc.stderr)
        before = {path.name for path in self.root.iterdir()}
        empty_cache = run("x86_64", "glibc", cache_value="", cwd=self.root)
        self.assertNotEqual(empty_cache.returncode, 0)
        self.assertIn("THEME_FORGE_CACHE_DIR", empty_cache.stderr)
        self.assertEqual(before, {path.name for path in self.root.iterdir()})
        relative_cache = run("x86_64", "glibc", cache_value="relative-cache", cwd=self.root)
        self.assertNotEqual(relative_cache.returncode, 0)
        self.assertIn("THEME_FORGE_CACHE_DIR", relative_cache.stderr)
        self.assertFalse((self.root / "relative-cache").exists())
        home = self.root / "linux-home"
        relative_xdg = run(
            "x86_64", "glibc", cache_value=None, xdg="relative-cache", home=home, cwd=self.root
        )
        self.assertEqual(relative_xdg.returncode, 0, relative_xdg.stderr)
        self.assertTrue(Path(relative_xdg.stdout.strip()).is_absolute())
        self.assertTrue(relative_xdg.stdout.strip().startswith(str(home)))
        self.assertFalse((self.root / "relative-cache").exists())

    def test_selected_070_fixture_build_binds_release_tuple(self) -> None:
        result = self._build(
            "selected-070",
            application_version="0.7.0",
            distribution_version="0.7.0",
        )
        self.assertEqual(result.version, "0.7.0")
        self.assertEqual(
            result.filename,
            "theme_forge_nebular_fusion-0.7.0-py3-none-macosx_11_0_arm64.whl",
        )
        self.assertFalse(result.can_publish)
        self.assertEqual(result.record["application_version"], "0.7.0")
        self.assertEqual(result.record["distribution_version"], "0.7.0")
        self.assertEqual(result.record["legacy_candidate"]["version"], "0.7.0")
        self.assertEqual(result.record["readme_authority"]["path"], DESCRIPTION_070_PATH)
        self.assertEqual(
            result.record["payload_archive_name"],
            "theme-forge-nebular-fusion-v0.7.0-aarch64-apple-darwin.app.tar.gz",
        )
        self.assertTrue(verify_wheel_record_bidirectional(result.wheel_path)["record_valid"])
        readme_070 = (Path(__file__).resolve().parents[1] / DESCRIPTION_070_PATH).read_bytes()
        with zipfile.ZipFile(result.wheel_path) as archive:
            metadata_bytes = archive.read("theme_forge_nebular_fusion-0.7.0.dist-info/METADATA")
            metadata = metadata_bytes.decode("utf-8")
            init_py = archive.read("theme_forge_nebular_fusion/__init__.py").decode("utf-8")
            launcher_py = archive.read("theme_forge_nebular_fusion/launcher.py").decode("utf-8")
            payload_member = (
                "theme_forge_nebular_fusion/payload/"
                "theme-forge-nebular-fusion-v0.7.0-aarch64-apple-darwin.app.tar.gz"
            )
            self.assertEqual(archive.read(payload_member), self.archive)
        self.assertTrue(metadata_bytes.endswith(readme_070))
        self.assertIn("Version: 0.7.0\n", metadata)
        self.assertIn("theme-forge-nebular-fusion==0.7.0", metadata)
        self.assertNotIn("0.6.1.post1", metadata)
        self.assertIn("__version__ = '0.7.0'", init_py)
        self.assertIn("__upstream_version__ = '0.7.0'", init_py)
        self.assertIn("DISTRIBUTION_VERSION = '0.7.0'", launcher_py)
        self.assertIn("APPLICATION_VERSION = '0.7.0'", launcher_py)

    def test_release_pair_and_description_cross_selection_fail_closed(self) -> None:
        self.assertEqual(tuple(SUCCESSOR_RELEASES), ("0.6.1.post1", "0.7.0"))
        for bad_selector in ("0.6.1", "0.8.0"):
            with self.assertRaises(ContractError) as raised:
                successor_release(bad_selector)
            self.assertEqual(raised.exception.code, "RELEASE_SELECTION")

        for app_ver, dist_ver in (("0.7.0", "0.6.1.post1"), ("0.6.1", "0.7.0")):
            with self.assertRaises(ContractError) as raised:
                self._build(
                    f"mismatch-{app_ver}-{dist_ver}",
                    application_version=app_ver,
                    distribution_version=dist_ver,
                )
            self.assertEqual(raised.exception.code, "INVALID_VERSION")

        with self.assertRaises(ContractError) as raised:
            self._build(
                "hist-with-070-desc",
                application_version="0.6.1",
                distribution_version="0.6.1.post1",
                description_path=DESCRIPTION_070_PATH,
            )
        self.assertEqual(raised.exception.code, "DESCRIPTION_VERSION")

        with self.assertRaises(ContractError) as raised:
            self._build(
                "070-with-hist-desc",
                application_version="0.7.0",
                distribution_version="0.7.0",
                description_path=DEFAULT_DESCRIPTION_PATH,
            )
        self.assertEqual(raised.exception.code, "DESCRIPTION_VERSION")

        custom_desc = self.root / "custom-070.md"
        custom_desc.write_text("# Custom 0.7.0\n", encoding="utf-8")
        with self.assertRaises(ContractError) as raised:
            self._build(
                "070-with-custom-desc",
                application_version="0.7.0",
                distribution_version="0.7.0",
                description_path=custom_desc,
            )
        self.assertEqual(raised.exception.code, "DESCRIPTION_VERSION")

        capture, profile = self._authenticated_capture()
        with self.assertRaises(ContractError) as raised:
            build_successor_wheel(
                "theme-forge-nebular-fusion",
                "0.7.0",
                distribution_version="0.7.0",
                capture=capture,
                profile_result=profile,
                output_dir=self.root / "070-against-061-capture",
                rs9_source_commit="a" * 40,
                rs9_source_tree="b" * 40,
            )
        self.assertEqual(raised.exception.code, "TAG_MISMATCH")

    def test_historical_release_rejects_dot_segment_alias_of_070_description(self) -> None:
        with self.assertRaises(ContractError) as raised:
            self._build(
                "dot-alias",
                description_path="operators/tf-pypi/descriptions/../descriptions/nebular-fusion-0.7.0.md",
            )
        self.assertEqual(raised.exception.code, "DESCRIPTION_VERSION")

        custom_readme = self.root / "custom-historical-readme.md"
        custom_bytes = b"# Custom Historical Readme\n"
        custom_readme.write_bytes(custom_bytes)
        accepted = self._build("custom-historical-readme", description_path=custom_readme)
        expected_custom_path = str(custom_readme.relative_to(Path(__file__).resolve().parents[1]))
        self.assertEqual(accepted.record["readme_path"], expected_custom_path)
        self.assertEqual(accepted.record["readme_sha256"], digest(custom_bytes))
        self.assertEqual(accepted.record["readme_authority"]["path"], expected_custom_path)
        self.assertEqual(accepted.record["readme_authority"]["sha256"], digest(custom_bytes))

    def test_selected_070_path_fixture_rejects_historical_archive_name(self) -> None:
        bad_archive = self.root / "theme-forge-nebular-fusion-v0.6.1-aarch64-apple-darwin.app.tar.gz"
        bad_archive.write_bytes(self.archive)
        with self.assertRaises(ContractError) as raised:
            build_successor_wheel(
                "theme-forge-nebular-fusion",
                "0.7.0",
                distribution_version="0.7.0",
                archive_path=bad_archive,
                output_dir=self.root / "bad-070-archive-name",
                license_files=self.legal,
                launcher_path=self.launcher,
                gui_path=self.gui,
                fixture_only=True,
            )
        self.assertEqual(raised.exception.code, "ARCHIVE_VERSION")

        custom_archive = self.root / "custom-fixture.tar.gz"
        custom_archive.write_bytes(self.archive)
        accepted = build_successor_wheel(
            "theme-forge-nebular-fusion",
            archive_path=custom_archive,
            output_dir=self.root / "custom-historical-archive",
            license_files=self.legal,
            launcher_path=self.launcher,
            gui_path=self.gui,
            fixture_only=True,
        )
        self.assertEqual(accepted.record["payload_archive_name"], "custom-fixture.tar.gz")

