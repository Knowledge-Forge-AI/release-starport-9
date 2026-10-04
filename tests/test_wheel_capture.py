"""Comprehensive tests for authenticated-capture CLI wheel builder."""
from __future__ import annotations

import base64
import copy
import hashlib
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tarfile
import tempfile
import unittest

from rs9.errors import ContractError
from rs9.release_core import ReleaseCapture, authenticate_release, digest
from rs9.scratch import canonical
from rs9.verify_wheel import (
    verify_double_build,
    verify_offline_venv_lifecycle,
    verify_raw_vs_wheel_parity,
    verify_wheel_record_bidirectional,
)
from rs9.wheel_capture import build_capture_wheel as _build_capture_wheel


def build_capture_wheel(*args, **kwargs):
    return _build_capture_wheel(*args, fixture_only=True, **kwargs)


def make_synthetic_archive(entries: list[tuple[str, bytes, int, bytes]]) -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        for path, data, mode, kind in entries:
            ti = tarfile.TarInfo(path)
            ti.mode = mode
            ti.type = kind
            ti.size = len(data) if kind == tarfile.REGTYPE else 0
            tf.addfile(ti, io.BytesIO(data) if kind == tarfile.REGTYPE else None)
    return buf.getvalue()


def make_test_loom_capture(
    directory: Path,
    *,
    extra_sources: dict[str, bytes] | None = None,
    extra_tar_entries: list[tuple[str, bytes, int, bytes]] | None = None,
) -> tuple[dict, ReleaseCapture]:
    sources = {
        "LICENSE": b"Synthetic AGPL-3.0-or-later license text.\n",
        "NOTICE": b"Synthetic notice.\n",
        "package.json": canonical({"name": "theme-forge-stellar-loom", "version": "0.4.0", "license": "AGPL-3.0-or-later"}),
        **(extra_sources or {}),
    }
    tree = []
    (directory / "source").mkdir(parents=True, exist_ok=True)
    for p, b in sources.items():
        (directory / "source" / p).write_bytes(b)
        blob = hashlib.sha1(b"blob " + str(len(b)).encode("ascii") + b"\0" + b).hexdigest()
        tree.append({"path": p, "type": "blob", "mode": "100644", "sha": blob})

    tar_entries = [
        ("package", b"", 0o755, tarfile.DIRTYPE),
        ("package/package.json", sources["package.json"], 0o644, tarfile.REGTYPE),
        ("package/bin", b"", 0o755, tarfile.DIRTYPE),
        ("package/bin/tfsl.js", b"console.log('loom 0.4.0');\n", 0o755, tarfile.REGTYPE),
        ("package/bin/tfsl-batch.js", b"console.log(JSON.stringify({error:{code:'EMPTY_INPUT'}})); process.exit(1);\n", 0o755, tarfile.REGTYPE),
        ("package/LICENSE", sources["LICENSE"], 0o644, tarfile.REGTYPE),
        ("package/NOTICE", sources["NOTICE"], 0o644, tarfile.REGTYPE),
    ]
    if extra_tar_entries:
        tar_entries.extend(extra_tar_entries)
    pkg_tgz = make_synthetic_archive(tar_entries)
    archive_name = "knowledge-forge-ai-theme-forge-stellar-loom-0.4.0.tgz"

    assets_raw = {
        archive_name: pkg_tgz,
        "NOTICE": sources["NOTICE"],
        "PROVENANCE.json": canonical({"release": {"repository": "Knowledge-Forge-AI/theme-forge-stellar-loom"}}),
    }
    sums = "".join(f"{digest(b)}  {n}\n" for n, b in sorted(assets_raw.items())).encode()
    assets_raw["SHA256SUMS"] = sums

    (directory / "assets").mkdir(parents=True, exist_ok=True)
    for n, b in assets_raw.items():
        (directory / "assets" / n).write_bytes(b)

    gh_assets = [
        {"id": i + 1, "name": n, "size": len(b), "digest": "sha256:" + digest(b), "state": "uploaded"}
        for i, (n, b) in enumerate(assets_raw.items())
    ]
    meta = {
        "repository": {"id": 101, "full_name": "Knowledge-Forge-AI/theme-forge-stellar-loom"},
        "release": {"id": 201, "tag_name": "v0.4.0", "target_commitish": "a" * 40, "draft": False, "prerelease": False, "assets": gh_assets},
        "ref": {"ref": "refs/tags/v0.4.0", "object": {"type": "commit", "sha": "a" * 40}},
        "tags": [],
        "commit": {"sha": "a" * 40, "tree": {"sha": "b" * 40}},
        "tree": {"sha": "b" * 40, "truncated": False, "tree": tree},
    }
    (directory / "api").mkdir(parents=True, exist_ok=True)
    for n, v in meta.items():
        (directory / "api" / (n + ".json")).write_bytes(canonical(v))

    selection = {
        "schema": "rs9.release-selection.v1alpha1",
        "repository": "Knowledge-Forge-AI/theme-forge-stellar-loom",
        "tag": "v0.4.0",
        "prerelease": "reject",
        "checksums": "SHA256SUMS",
        "payload_assets": [{
            "id": "package",
            "name": archive_name,
            "format": "tar.gz",
            "commands": {},
            "launchers": {},
            "platforms": ["any"],
        }],
        "evidence_assets": [
            {"name": "NOTICE", "role": "notice"},
            {"name": "PROVENANCE.json", "role": "provenance"},
        ],
        "source_paths": sorted(sources.keys()),
    }
    capture = authenticate_release(selection, directory)
    return selection, capture


def make_test_burst_capture(directory: Path, *, extra_sources: dict[str, bytes] | None = None) -> tuple[dict, ReleaseCapture]:
    sources = {
        "LICENSE": b"Synthetic AGPL-3.0-or-later license text.\n",
        "NOTICE": b"Synthetic notice.\n",
        "package.json": canonical({"name": "theme-forge-stellar-burst", "version": "0.6.1", "license": "AGPL-3.0-or-later"}),
        **(extra_sources or {}),
    }
    tree = []
    (directory / "source").mkdir(parents=True, exist_ok=True)
    for p, b in sources.items():
        (directory / "source" / p).write_bytes(b)
        blob = hashlib.sha1(b"blob " + str(len(b)).encode("ascii") + b"\0" + b).hexdigest()
        tree.append({"path": p, "type": "blob", "mode": "100644", "sha": blob})

    tar_entries = [
        ("package", b"", 0o755, tarfile.DIRTYPE),
        ("package/package.json", sources["package.json"], 0o644, tarfile.REGTYPE),
        ("package/dist", b"", 0o755, tarfile.DIRTYPE),
        ("package/dist/cli.js", b"console.log('burst 0.6.1');\n", 0o755, tarfile.REGTYPE),
        ("package/dist/service-protocol", b"", 0o755, tarfile.DIRTYPE),
        ("package/dist/service-protocol/server-cli.js", b"console.log('burst server 0.6.1');\n", 0o755, tarfile.REGTYPE),
        ("package/LICENSE", sources["LICENSE"], 0o644, tarfile.REGTYPE),
        ("package/NOTICE", sources["NOTICE"], 0o644, tarfile.REGTYPE),
    ]
    pkg_tgz = make_synthetic_archive(tar_entries)
    archive_name = "knowledge-forge-ai-theme-forge-stellar-burst-0.6.1.tgz"

    assets_raw = {
        archive_name: pkg_tgz,
        "NOTICE": sources["NOTICE"],
        "PROVENANCE.json": canonical({"release": {"repository": "Knowledge-Forge-AI/theme-forge-stellar-burst"}}),
    }
    sums = "".join(f"{digest(b)}  {n}\n" for n, b in sorted(assets_raw.items())).encode()
    assets_raw["SHA256SUMS"] = sums

    (directory / "assets").mkdir(parents=True, exist_ok=True)
    for n, b in assets_raw.items():
        (directory / "assets" / n).write_bytes(b)

    gh_assets = [
        {"id": i + 1, "name": n, "size": len(b), "digest": "sha256:" + digest(b), "state": "uploaded"}
        for i, (n, b) in enumerate(assets_raw.items())
    ]
    meta = {
        "repository": {"id": 102, "full_name": "Knowledge-Forge-AI/theme-forge-stellar-burst"},
        "release": {"id": 202, "tag_name": "v0.6.1", "target_commitish": "a" * 40, "draft": False, "prerelease": False, "assets": gh_assets},
        "ref": {"ref": "refs/tags/v0.6.1", "object": {"type": "commit", "sha": "a" * 40}},
        "tags": [],
        "commit": {"sha": "a" * 40, "tree": {"sha": "b" * 40}},
        "tree": {"sha": "b" * 40, "truncated": False, "tree": tree},
    }
    (directory / "api").mkdir(parents=True, exist_ok=True)
    for n, v in meta.items():
        (directory / "api" / (n + ".json")).write_bytes(canonical(v))

    selection = {
        "schema": "rs9.release-selection.v1alpha1",
        "repository": "Knowledge-Forge-AI/theme-forge-stellar-burst",
        "tag": "v0.6.1",
        "prerelease": "reject",
        "checksums": "SHA256SUMS",
        "payload_assets": [{
            "id": "package",
            "name": archive_name,
            "format": "tar.gz",
            "commands": {},
            "launchers": {},
            "platforms": ["any"],
        }],
        "evidence_assets": [
            {"name": "NOTICE", "role": "notice"},
            {"name": "PROVENANCE.json", "role": "provenance"},
        ],
        "source_paths": sorted(sources.keys()),
    }
    capture = authenticate_release(selection, directory)
    return selection, capture


class WheelCaptureTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name).resolve()

    def test_double_build_bytes_and_bidirectional_record(self) -> None:
        evidence_dir = self.root / "evidence"
        _, capture = make_test_loom_capture(evidence_dir)

        res_a, res_b = verify_double_build(
            build_capture_wheel,
            "theme-forge-stellar-loom",
            "0.4.0",
            capture,
            output_dir_a=self.root / "build_a",
            output_dir_b=self.root / "build_b",
        )
        self.assertEqual(res_a.wheel_bytes, res_b.wheel_bytes)
        self.assertEqual(res_a.sha256, res_b.sha256)
        self.assertEqual(res_a.filename, "theme_forge_stellar_loom-0.4.0-py3-none-any.whl")

        inv = verify_wheel_record_bidirectional(res_a.wheel_path)
        self.assertTrue(inv["record_valid"])
        self.assertGreater(inv["member_count"], 5)

    def test_default_requires_fresh_profile_and_changed_archive_is_rejected(self):
        _, capture = make_test_loom_capture(self.root / "evidence")
        with self.assertRaises(ContractError) as raised:
            _build_capture_wheel("theme-forge-stellar-loom", "0.4.0", capture, output_dir=self.root / "out")
        self.assertEqual(raised.exception.code, "PROFILE_BINDING")
        capture.archives["package"].write_bytes(b"tampered")
        with self.assertRaises(ContractError) as raised:
            build_capture_wheel("theme-forge-stellar-loom", "0.4.0", capture, output_dir=self.root / "out")
        self.assertEqual(raised.exception.code, "INPUT_CHANGED")

    def test_reauthentication_refusal_when_tampered(self) -> None:
        evidence_dir = self.root / "evidence"
        _, capture = make_test_loom_capture(evidence_dir)

        # Tampering with release record invalidates authenticated record hash
        capture.record["repository"]["id"] = 9999
        with self.assertRaises(ContractError) as ctx:
            build_capture_wheel("theme-forge-stellar-loom", "0.4.0", capture, output_dir=self.root / "out")
        self.assertIn("INPUT_CHANGED", str(ctx.exception))

        # Re-create clean capture then tamper with source file
        evidence_dir2 = self.root / "evidence2"
        _, capture2 = make_test_loom_capture(evidence_dir2)
        capture2.source["LICENSE"] = b"tampered license bytes"
        with self.assertRaises(ContractError) as ctx:
            build_capture_wheel("theme-forge-stellar-loom", "0.4.0", capture2, output_dir=self.root / "out2")
        self.assertIn("INPUT_CHANGED", str(ctx.exception))

    def test_provenance_required_when_inputs_missing(self) -> None:
        with self.assertRaises(ContractError) as ctx:
            build_capture_wheel("theme-forge-stellar-loom", "0.4.0", None, output_dir=self.root / "out")
        self.assertIn("PROVENANCE_REQUIRED", str(ctx.exception))

    def test_license_identity_and_spdx_validation(self) -> None:
        evidence_dir = self.root / "evidence"
        # Malformed SPDX in package.json (invalid syntax with multiple unjoined tokens)
        bad_sources = {"package.json": canonical({"name": "theme-forge-stellar-loom", "version": "0.4.0", "license": "INVALID LICENSE EXPRESSION"})}
        _, capture = make_test_loom_capture(evidence_dir, extra_sources=bad_sources)
        with self.assertRaises(ContractError):
            build_capture_wheel("theme-forge-stellar-loom", "0.4.0", capture, output_dir=self.root / "out")

    def test_burst_closure_refusal_without_exact_real_lock(self) -> None:
        evidence_dir = self.root / "evidence_burst"
        # Burst capture without package-lock.json in source
        _, burst_capture = make_test_burst_capture(evidence_dir)

        # Closure integration must fail because real lock is absent
        with self.assertRaises(ContractError) as ctx:
            build_capture_wheel(
                "theme-forge-stellar-burst",
                "0.6.1",
                burst_capture,
                integrate_closure=True,
                platform_tag="any",
                output_dir=self.root / "out",
            )
        self.assertIn("NPM_LOCK", str(ctx.exception))

    def test_burst_closure_integration_with_exact_real_lock(self) -> None:
        evidence_dir = self.root / "evidence_burst_with_lock"
        dep_package_data = canonical({"name": "simple-dep", "version": "1.0.0", "license": "MIT"})
        # Build dependency archive
        dep_tar = make_synthetic_archive([
            ("package", b"", 0o755, tarfile.DIRTYPE),
            ("package/package.json", dep_package_data, 0o644, tarfile.REGTYPE),
            ("package/index.js", b"module.exports = 'dep';\n", 0o644, tarfile.REGTYPE),
            ("package/LICENSE", b"MIT License\n", 0o644, tarfile.REGTYPE),
        ])
        dep_archive_path = self.root / "simple-dep-1.0.0.tgz"
        dep_archive_path.write_bytes(dep_tar)

        dep_integrity = "sha512-" + base64.b64encode(hashlib.sha512(dep_tar).digest()).decode("ascii")
        dep_rel = "node_modules/simple-dep"

        # package.json and package-lock.json declaring direct dependency
        burst_pkg = canonical({
            "name": "theme-forge-stellar-burst",
            "version": "0.6.1",
            "license": "AGPL-3.0-or-later",
            "dependencies": {"simple-dep": "1.0.0"},
        })
        burst_lock = canonical({
            "lockfileVersion": 3,
            "packages": {
                "": {"dependencies": {"simple-dep": "1.0.0"}},
                dep_rel: {
                    "version": "1.0.0",
                    "resolved": "https://registry.npmjs.org/simple-dep/-/simple-dep-1.0.0.tgz",
                    "integrity": dep_integrity,
                },
            },
        })

        _, burst_capture = make_test_burst_capture(
            evidence_dir,
            extra_sources={"package.json": burst_pkg, "package-lock.json": burst_lock},
        )

        res = build_capture_wheel(
            "theme-forge-stellar-burst",
            "0.6.1",
            burst_capture,
            platform_tag="any",
            dependency_archives={dep_rel: dep_archive_path},
            integrate_closure=True,
            output_dir=self.root / "burst_out",
        )
        self.assertEqual(res.filename, "theme_forge_stellar_burst-0.6.1-py3-none-any.whl")
        inv = verify_wheel_record_bidirectional(res.wheel_path)
        self.assertTrue(inv["record_valid"])
        # Check that dependency file exists in wheel
        self.assertIn("theme_forge_stellar_burst/payload/package/node_modules/simple-dep/index.js", inv["entries"])

    def test_burst_unqualified_platform_refusal(self) -> None:
        evidence_dir = self.root / "evidence_burst"
        _, burst_capture = make_test_burst_capture(evidence_dir)

        # "any" tag or missing tag rejected for Burst
        for bad_tag in (None, "any", "linux_x86_64"):
            with self.assertRaises(ContractError):
                build_capture_wheel(
                    "theme-forge-stellar-burst",
                    "0.6.1",
                    burst_capture,
                    platform_tag=bad_tag,
                    output_dir=self.root / "out",
                )

    def test_unsupported_product_nebular_refused(self) -> None:
        with self.assertRaises(ContractError) as ctx:
            build_capture_wheel("theme-forge-nebular-fusion", "0.6.1", output_dir=self.root / "out")
        self.assertIn("UNSUPPORTED_PRODUCT", str(ctx.exception))

    @unittest.skipUnless(shutil.which("node"), "Node.js required for venv execution and parity verification")
    def test_offline_venv_lifecycle_and_raw_vs_wheel_parity(self) -> None:
        evidence_dir = self.root / "evidence"
        _, capture = make_test_loom_capture(evidence_dir)
        res = build_capture_wheel(
            "theme-forge-stellar-loom",
            "0.4.0",
            capture,
            output_dir=self.root / "wheel_out",
        )

        venv_dir = self.root / "test_venv"
        report = verify_offline_venv_lifecycle(
            res.wheel_path,
            distribution_name="theme-forge-stellar-loom",
            commands_to_test={
                "tfsl": {"argv": [], "expect_exit": 0, "expect_stdout_contains": "loom 0.4.0"},
                "tfsl-batch": {"argv": [], "input": "", "expect_exit": 1, "expect_json_error": "EMPTY_INPUT"},
            },
            venv_dir=venv_dir,
        )
        self.assertTrue(report["clean_uninstall_verified"])

        # Raw vs wheel CLI parity check
        # Install wheel again in a temporary directory to verify parity
        temp_venv = self.root / "temp_venv"
        subprocess.run([sys.executable, "-m", "venv", str(temp_venv)], check=True, capture_output=True)
        env = {**os.environ, "PIP_CONFIG_FILE": os.devnull, "PIP_NO_INDEX": "1", "PIP_DISABLE_PIP_VERSION_CHECK": "1"}
        subprocess.run(
            [str(temp_venv / "bin" / "pip"), "install", "--no-index", "--no-deps", str(res.wheel_path)],
            check=True,
            capture_output=True,
            env=env,
        )

        raw_script = evidence_dir / "assets" / "raw_batch.js"
        raw_script.write_bytes(b"console.log(JSON.stringify({error:{code:'EMPTY_INPUT'}})); process.exit(1);\n")

        parity = verify_raw_vs_wheel_parity(
            ["node", str(raw_script)],
            [str(temp_venv / "bin" / "tfsl-batch")],
            stdin_input="",
        )
        self.assertTrue(parity["parity_confirmed"])
        self.assertEqual(parity["returncode"], 1)

    def test_unqualified_platform_native_member_error_details(self) -> None:
        """Verify UNQUALIFIED_PLATFORM carries required safe error details when native member is found."""
        evidence_dir = self.root / "evidence_native"
        _, capture = make_test_loom_capture(
            evidence_dir,
            extra_tar_entries=[("package/binding.node", b"\x7fELF" + b"\x00" * 32, 0o755, tarfile.REGTYPE)],
        )

        with self.assertRaises(ContractError) as ctx:
            build_capture_wheel(
                "theme-forge-stellar-loom",
                "0.4.0",
                capture,
                output_dir=self.root / "out",
            )
        self.assertEqual(ctx.exception.code, "UNQUALIFIED_PLATFORM")
        details = ctx.exception.details
        self.assertEqual(details["product"], "theme-forge-stellar-loom")
        self.assertEqual(details["substage"], "closure-platform-scan")
        self.assertEqual(details["archive_path"], "package/binding.node")
        self.assertEqual(details["wheel_tag"], "py3-none-any")
        self.assertEqual(details["asset_platform"], "any")

    def test_unqualified_platform_constrained_package_json_error_details(self) -> None:
        """Verify UNQUALIFIED_PLATFORM carries required safe error details when platform-constrained package.json is found."""
        evidence_dir = self.root / "evidence_constrained"
        _, capture = make_test_loom_capture(
            evidence_dir,
            extra_tar_entries=[(
                "package/node_modules/arch_dep/package.json",
                json.dumps({"name": "arch_dep", "os": ["linux"]}).encode("utf-8"),
                0o644,
                tarfile.REGTYPE,
            )],
        )

        with self.assertRaises(ContractError) as ctx:
            build_capture_wheel(
                "theme-forge-stellar-loom",
                "0.4.0",
                capture,
                output_dir=self.root / "out",
            )
        self.assertEqual(ctx.exception.code, "UNQUALIFIED_PLATFORM")
        details = ctx.exception.details
        self.assertEqual(details["product"], "theme-forge-stellar-loom")
        self.assertEqual(details["substage"], "closure-platform-scan")
        self.assertEqual(details["archive_path"], "package/node_modules/arch_dep/package.json")
        self.assertEqual(details["wheel_tag"], "py3-none-any")
        self.assertEqual(details["asset_platform"], "any")

    def test_burst_system_none_retains_global_rejection_when_native_present(self) -> None:
        """When system=None, build_capture_wheel retains global rejection for Burst when native members present."""
        evidence_dir = self.root / "evidence_burst_system_none"
        _, burst_capture = make_test_burst_capture(evidence_dir)

        # Inject native binary into burst archive
        dep_tar = make_synthetic_archive([
            ("package", b"", 0o755, tarfile.DIRTYPE),
            ("package/package.json", canonical({"name": "simple-dep", "version": "1.0.0", "license": "MIT"}), 0o644, tarfile.REGTYPE),
            ("package/index.js", b"module.exports = 'dep';\n", 0o644, tarfile.REGTYPE),
            ("package/LICENSE", b"MIT License\n", 0o644, tarfile.REGTYPE),
            ("package/native/directory-snapshot/prebuilds/linux-x64-gnu/native-addon-posix-openat-v1.node", b"\x7fELF" + b"\x00" * 32, 0o755, tarfile.REGTYPE),
        ])
        dep_archive_path = self.root / "simple-dep-native.tgz"
        dep_archive_path.write_bytes(dep_tar)
        dep_integrity = "sha512-" + base64.b64encode(hashlib.sha512(dep_tar).digest()).decode("ascii")
        dep_rel = "node_modules/simple-dep"

        burst_pkg = canonical({
            "name": "theme-forge-stellar-burst",
            "version": "0.6.1",
            "license": "AGPL-3.0-or-later",
            "dependencies": {"simple-dep": "1.0.0"},
        })
        burst_lock = canonical({
            "lockfileVersion": 3,
            "packages": {
                "": {"dependencies": {"simple-dep": "1.0.0"}},
                dep_rel: {
                    "version": "1.0.0",
                    "resolved": "https://registry.npmjs.org/simple-dep/-/simple-dep-1.0.0.tgz",
                    "integrity": dep_integrity,
                },
            },
        })

        _, burst_capture_with_dep = make_test_burst_capture(
            evidence_dir,
            extra_sources={"package.json": burst_pkg, "package-lock.json": burst_lock},
        )

        with self.assertRaises(ContractError) as ctx:
            build_capture_wheel(
                "theme-forge-stellar-burst",
                "0.6.1",
                burst_capture_with_dep,
                system=None,
                platform_tag="any",
                dependency_archives={dep_rel: dep_archive_path},
                integrate_closure=True,
                output_dir=self.root / "out_none",
            )
        self.assertEqual(ctx.exception.code, "UNQUALIFIED_PLATFORM")
