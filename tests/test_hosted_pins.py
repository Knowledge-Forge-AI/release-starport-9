"""Unit tests for container resolution, single-manifest readback, and target pin validation."""
from __future__ import annotations

import copy
import hashlib
import json
import subprocess
import unittest
from unittest.mock import Mock
from unittest.mock import patch
from pathlib import Path
import re
import tempfile

from rs9.errors import ContractError
from rs9.hosted_pins import INSTALLER_SYSTEMS, execute, resolve_image, resolve_targets


class PinTests(unittest.TestCase):
    def test_exact_architecture_digest_selected(self):
        doc = {
            "manifests": [
                {"digest": "sha256:" + "a" * 64, "platform": {"os": "linux", "architecture": "amd64"}},
                {"digest": "sha256:" + "b" * 64, "platform": {"os": "linux", "architecture": "arm64"}},
            ]
        }
        plat_doc = {
            "schemaVersion": 2,
            "mediaType": "application/vnd.oci.image.manifest.v1+json",
            "config": {"digest": "sha256:" + "c" * 64, "size": 123},
        }
        plat_bytes = json.dumps(plat_doc).encode()
        plat_digest = "sha256:" + hashlib.sha256(plat_bytes).hexdigest()
        doc["manifests"][1]["digest"] = plat_digest
        cfg_doc = {"os": "linux", "architecture": "arm64"}

        def runner_impl(cmd, **kwargs):
            if "--raw" in cmd and "26.04" in cmd[-1]:
                return subprocess.CompletedProcess(cmd, 0, json.dumps(doc).encode(), b"")
            if "--raw" in cmd and plat_digest in cmd[-1]:
                return subprocess.CompletedProcess(cmd, 0, plat_bytes, b"")
            if "--format" in cmd:
                return subprocess.CompletedProcess(cmd, 0, json.dumps(cfg_doc).encode(), b"")
            raise ValueError(f"Unexpected inspect cmd: {cmd}")

        runner = Mock(side_effect=runner_impl)
        image = resolve_image("docker.io/library/ubuntu", "26.04", "arm64", runner)
        self.assertEqual(image, f"docker.io/library/ubuntu@{plat_digest}")

    def test_missing_architecture_and_transport_fail_closed(self):
        runner = Mock(return_value=subprocess.CompletedProcess([], 0, b'{"manifests":[]}', b""))
        with self.assertRaises(ContractError):
            resolve_image("registry.fedoraproject.org/fedora", "43", "aarch64", runner)

    def test_manifest_without_platform_proof_is_not_a_pin(self):
        runner = Mock(return_value=subprocess.CompletedProcess([], 0, b'{"schemaVersion":2,"config":{"digest":"sha256:unbound"}}', b""))
        with self.assertRaises(ContractError) as error:
            resolve_image("docker.io/library/ubuntu", "26.04", "arm64", runner)
        self.assertEqual(error.exception.code, "IMAGE_PLATFORM")

        # Narrowed subprocess failure: CalledProcessError -> ContractError with safe hashes
        runner.side_effect = subprocess.CalledProcessError(1, ["docker"], output=b"error-out", stderr=b"error-err")
        with self.assertRaises(ContractError) as error:
            resolve_image("registry.fedoraproject.org/fedora", "43", "aarch64", runner)
        self.assertEqual(error.exception.code, "IMAGE_INSPECT_FAILED")
        self.assertIn("stdout_sha256", error.exception.details)
        self.assertIn("stderr_sha256", error.exception.details)
        self.assertEqual(error.exception.details["exit_code"], 1)

    def test_raw_manifest_digest_mismatch_fails_closed(self):
        # When ref is sha256:..., raw bytes must match the digest
        manifest_doc = {"schemaVersion": 2, "config": {"digest": "sha256:" + "2" * 64}}
        runner = Mock(return_value=subprocess.CompletedProcess([], 0, json.dumps(manifest_doc).encode(), b""))
        with self.assertRaises(ContractError) as ctx:
            resolve_image("docker.io/library/ubuntu", "sha256:" + "9" * 64, "amd64", runner)
        self.assertEqual(ctx.exception.code, "IMAGE_DIGEST")

    def test_single_manifest_architecture_readback_proven_by_config(self):
        cfg_digest = "sha256:" + "2" * 64
        manifest_doc = {
            "schemaVersion": 2,
            "mediaType": "application/vnd.oci.image.manifest.v1+json",
            "config": {"mediaType": "application/vnd.oci.image.config.v1+json", "digest": cfg_digest, "size": 1234},
            "layers": [{"mediaType": "application/vnd.oci.image.layer.v1.tar+gzip", "digest": "sha256:" + "3" * 64, "size": 5678}],
        }
        raw_manifest_bytes = json.dumps(manifest_doc).encode()
        manifest_digest = "sha256:" + hashlib.sha256(raw_manifest_bytes).hexdigest()
        cfg_doc = {"os": "linux", "architecture": "amd64", "config": {}}

        def runner_impl(cmd, **kwargs):
            ref = cmd[-1]
            if "--raw" in cmd and (manifest_digest in ref or "base" in ref):
                return subprocess.CompletedProcess(cmd, 0, raw_manifest_bytes, b"")
            if "--format" in cmd and manifest_digest in ref:
                return subprocess.CompletedProcess(cmd, 0, json.dumps(cfg_doc).encode(), b"")
            raise ValueError(f"Unexpected inspect cmd: {cmd}")

        runner = Mock(side_effect=runner_impl)
        image = resolve_image("docker.io/library/archlinux", manifest_digest, "x86_64", runner)
        self.assertEqual(image, f"docker.io/library/archlinux@{manifest_digest}")
        self.assertEqual(runner.call_count, 2)

    def test_single_manifest_config_architecture_mismatch_fails_closed(self):
        cfg_digest = "sha256:" + "5" * 64
        manifest_doc = {
            "schemaVersion": 2,
            "config": {"digest": cfg_digest},
        }
        raw_bytes = json.dumps(manifest_doc).encode()
        manifest_digest = "sha256:" + hashlib.sha256(raw_bytes).hexdigest()
        # Config says arm64, but caller requested amd64
        cfg_doc = {"os": "linux", "architecture": "arm64"}

        def runner_impl(cmd, **kwargs):
            if "--raw" in cmd:
                return subprocess.CompletedProcess(cmd, 0, raw_bytes, b"")
            if "--format" in cmd:
                return subprocess.CompletedProcess(cmd, 0, json.dumps(cfg_doc).encode(), b"")
            raise ValueError(f"Unexpected inspect cmd: {cmd}")

        runner = Mock(side_effect=runner_impl)
        with self.assertRaises(ContractError) as ctx:
            resolve_image("docker.io/library/ubuntu", manifest_digest, "amd64", runner)
        self.assertEqual(ctx.exception.code, "IMAGE_PLATFORM")

    def test_single_manifest_config_os_mismatch_fails_closed(self):
        cfg_digest = "sha256:" + "7" * 64
        manifest_doc = {
            "schemaVersion": 2,
            "config": {"digest": cfg_digest},
        }
        raw_bytes = json.dumps(manifest_doc).encode()
        manifest_digest = "sha256:" + hashlib.sha256(raw_bytes).hexdigest()
        # Config says windows instead of linux
        cfg_doc = {"os": "windows", "architecture": "amd64"}

        def runner_impl(cmd, **kwargs):
            if "--raw" in cmd:
                return subprocess.CompletedProcess(cmd, 0, raw_bytes, b"")
            if "--format" in cmd:
                return subprocess.CompletedProcess(cmd, 0, json.dumps(cfg_doc).encode(), b"")
            raise ValueError(f"Unexpected inspect cmd: {cmd}")

        runner = Mock(side_effect=runner_impl)
        with self.assertRaises(ContractError) as ctx:
            resolve_image("docker.io/library/ubuntu", manifest_digest, "amd64", runner)
        self.assertEqual(ctx.exception.code, "IMAGE_PLATFORM")

    def test_single_manifest_missing_config_digest_fails_closed(self):
        manifest_doc = {"schemaVersion": 2, "config": {}}
        raw_bytes = json.dumps(manifest_doc).encode()
        manifest_digest = "sha256:" + hashlib.sha256(raw_bytes).hexdigest()
        runner = Mock(return_value=subprocess.CompletedProcess([], 0, raw_bytes, b""))
        with self.assertRaises(ContractError) as ctx:
            resolve_image("docker.io/library/ubuntu", manifest_digest, "amd64", runner)
        self.assertEqual(ctx.exception.code, "IMAGE_PLATFORM")

    def test_subprocess_timeout_narrowed_to_contract_error(self):
        runner = Mock(side_effect=subprocess.TimeoutExpired(["docker"], 120, output=b"out", stderr=b"err"))
        with self.assertRaises(ContractError) as ctx:
            resolve_image("docker.io/library/ubuntu", "26.04", "amd64", runner)
        self.assertEqual(ctx.exception.code, "TOOL_TIMEOUT")
        self.assertIn("stdout_sha256", ctx.exception.details)
        self.assertIn("stderr_sha256", ctx.exception.details)


class TargetResolutionPinTests(unittest.TestCase):
    def setUp(self):
        self.valid_targets = {
            "schema": "rs9.live1-candidate-targets.v1alpha1",
            "pacman": {
                "architectures": ["x86_64"],
                "container_repository": "docker.io/library/archlinux",
                "container_tag": "base",
                "container_digest": "sha256:" + "1" * 64,
            },
            "rpm": {
                "architectures": ["x86_64", "aarch64"],
                "container_repository": "registry.fedoraproject.org/fedora",
                "container_tag": "43",
                "container_digests": {
                    "x86_64": "sha256:" + "2" * 64,
                    "aarch64": "sha256:" + "3" * 64,
                },
            },
            "deb": {
                "architectures": ["amd64", "arm64"],
                "container_repository": "docker.io/library/ubuntu",
                "container_tag": "26.04",
                "container_digests": {
                    "amd64": "sha256:" + "4" * 64,
                    "arm64": "sha256:" + "5" * 64,
                },
            },
            "nix": {
                "nixpkgs_revision": "0921fdb3e13e40fe25fbc52b89661a9d6d32ac68",
                "nixpkgs_nar_hash": "sha256-ESJ4VgytmAt+98YLM8466luln4HyEZ9Q36b9+Bb4P5w=",
                "installer_version": "2.31.2",
                "installer_sha256_by_system": {
                    "aarch64-darwin": "3baa0af88a1ef4e2cc82cb64cd384b1805ecc3771b574e97277ae213d52711d8",
                    "x86_64-linux": "d1f67c86eed016214864ba08bfb9529c307aea7e8fafb74853f96fcc3bfd8a60",
                    "aarch64-linux": "64db528412096d718b4bf8f78f85e5ac2b714b774e5005500dee37d23f560456",
                },
            },
        }

    def test_resolve_targets_all_source_pinned_covers_three_installer_systems(self):
        pins = resolve_targets(self.valid_targets)
        self.assertTrue(pins["all_source_pinned"])
        prov = pins["pin_provenance"]
        for sys_name in INSTALLER_SYSTEMS:
            self.assertEqual(prov[f"nix.{sys_name}"], "source-pinned")
        self.assertEqual(prov["pacman.x86_64"], "source-pinned")
        self.assertEqual(prov["rpm.x86_64"], "source-pinned")
        self.assertEqual(prov["rpm.aarch64"], "source-pinned")
        self.assertEqual(prov["deb.amd64"], "source-pinned")
        self.assertEqual(prov["deb.arm64"], "source-pinned")
        self.assertNotIn("installer_sha256", pins["nix"])

    def test_missing_installer_system_pin_fails_closed(self):
        incomplete = copy.deepcopy(self.valid_targets)
        del incomplete["nix"]["installer_sha256_by_system"]["aarch64-darwin"]
        with self.assertRaises(ContractError) as ctx:
            resolve_targets(incomplete)
        self.assertEqual(ctx.exception.code, "NIX_PIN")

    def test_extra_installer_system_pin_fails_closed(self):
        extra = copy.deepcopy(self.valid_targets)
        extra["nix"]["installer_sha256_by_system"]["i686-linux"] = "a" * 64
        with self.assertRaises(ContractError) as ctx:
            resolve_targets(extra)
        self.assertEqual(ctx.exception.code, "NIX_PIN")

    def test_legacy_installer_sha256_removed(self):
        with_legacy = copy.deepcopy(self.valid_targets)
        with_legacy["nix"]["installer_sha256"] = {"legacy": "val"}
        pins = resolve_targets(with_legacy)
        self.assertNotIn("installer_sha256", pins["nix"])
        self.assertIn("installer_sha256_by_system", pins["nix"])

    def test_missing_container_pins_never_resolve_floating_tags(self):
        for family in ("pacman", "rpm", "deb"):
            for arch in self.valid_targets[family]["architectures"]:
                with self.subTest(family=family, arch=arch):
                    targets = copy.deepcopy(self.valid_targets)
                    if family == "pacman":
                        targets[family]["container_digest"] = None
                    else:
                        targets[family]["container_digests"].pop(arch)
                    runner = Mock()
                    with self.assertRaises(ContractError) as caught:
                        resolve_targets(targets, runner=runner)
                    self.assertEqual(caught.exception.code, "IMAGE_PIN_MISSING")
                    runner.assert_not_called()

    def test_invalid_nar_hash_fails_closed(self):
        for value in (None, "not-a-nar-hash", "sha256-short=", "sha512-" + "a" * 43 + "="):
            targets = copy.deepcopy(self.valid_targets)
            targets["nix"]["nixpkgs_nar_hash"] = value
            with self.assertRaises(ContractError) as caught:
                resolve_targets(targets)
            self.assertEqual(caught.exception.code, "NIX_PIN")

    def test_real_targets_and_nix_pin_projection_agree(self):
        root = Path(__file__).resolve().parents[1]
        targets = json.loads((root / "operators/live1/targets.json").read_bytes())
        pins = resolve_targets(targets)
        self.assertTrue(pins["all_source_pinned"])
        self.assertEqual(pins["pin_provenance"]["nix.nixpkgs"], "source-pinned")
        projection = (root / "nix/pins.nix").read_text()
        for key in ("nixpkgs_revision", "nixpkgs_nar_hash", "installer_version"):
            self.assertEqual(re.search(key + r'\s*=\s*"([^"]+)"', projection).group(1), targets["nix"][key])
        for system, sha in targets["nix"]["installer_sha256_by_system"].items():
            self.assertEqual(re.search(system + r'\s*=\s*"([^"]+)"', projection).group(1), sha)
        with tempfile.TemporaryDirectory() as tmp, patch("rs9.hosted_pins.resolve_image") as readback:
            readback.side_effect = lambda repository, sha, arch, runner: repository + "@" + sha
            result = execute({"repository": root, "scratch": Path(tmp), "runner": Mock()})
        self.assertEqual(readback.call_count, 5)
        self.assertEqual(result["details"]["reproducibility"], "source-pinned")
        self.assertTrue(result["details"]["pins"]["all_source_pinned"])


if __name__ == "__main__":
    unittest.main()
