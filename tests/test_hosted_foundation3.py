"""Unit tests for rs9.hosted_foundation3 candidate verification and plan assembly."""

import hashlib
import json
from pathlib import Path
import tempfile
import unittest

from rs9.errors import ContractError
from rs9.hosted_foundation3 import execute, verify_candidate_files, wheel_architecture_set, publication_policy
from rs9.profiles import evaluate_profile, PACKAGE_PROFILE
from rs9.scratch import canonical
from rs9.wheel import build_wheel
from tests.test_build_native import create_cli_fixture


class HostedFoundation3Tests(unittest.TestCase):
    def test_packaging_policy_is_verified_by_fresh_planner(self):
        from rs9.planner import adapter_output, plan, destination_policy
        from rs9.gates import derive_gates
        from rs9.records import build_semantic_content_identity, record_sha256
        from rs9.release_core import authenticated_record_hash
        from tests.publication_fixtures import observation, T0
        capture, intent, profile = self._make_loom_capture()
        policy = publication_policy(intent["project"]["id"], {"any"})
        def output_for(packaging_policy, claimed_hash=None):
            identity = build_semantic_content_identity(intent["project"]["id"], intent["version"], intent["project"]["id"], "pypi",
                {p["name"]: p["sha256"] for p in capture.record["payloads"]},
                {"configuration": record_sha256(intent), "packaging_policy": claimed_hash or record_sha256(packaging_policy)})
            return adapter_output({"id": "pypi", "adapter": "pypi", "mode": "direct"},
                {"package": intent["project"]["id"], "version": intent["version"], "revision": None}, identity,
                [{"path": "candidate.whl", "size": 10, "sha256": "a" * 64}],
                {"release_record_sha256": authenticated_record_hash(capture), **packaging_policy},
                implementation={"id": "fixture", "version": "1"}, source_version="fixture")
        output = output_for(policy)
        result = plan(intent, capture, profile, output, derive_gates(intent, capture, profile, output),
                      destination_policy(enabled=False), observation(output), evaluated_at=T0)
        self.assertEqual(result["outcome"], "block")
        for changed in (output_for({**policy, "package_class": "native-node-cli"}), output_for(policy, "0" * 64)):
            with self.assertRaises(ContractError) as caught:
                plan(intent, capture, profile, changed, derive_gates(intent, capture, profile, changed),
                     destination_policy(enabled=False), observation(changed), evaluated_at=T0)
            self.assertEqual(caught.exception.code, "OUTPUT_BINDING")

    def test_burst_wheel_custody_rejects_universal_and_unproven_linux_tags(self):
        product = "theme-forge-stellar-burst"
        for tag in ("any", "manylinux_2_17_x86_64", "macosx_13_0_x86_64"):
            with self.subTest(tag=tag), self.assertRaises(ContractError) as caught:
                wheel_architecture_set(product, [f"theme_forge_stellar_burst-0.6.1-py3-none-{tag}.whl"])
            self.assertEqual(caught.exception.code, "CUSTODY_ARCHITECTURE")
        tags = {"linux_x86_64", "linux_aarch64", "macosx_13_0_arm64"}
        self.assertEqual(wheel_architecture_set(product, [f"theme_forge_stellar_burst-0.6.1-py3-none-{tag}.whl" for tag in tags]), tags)
        self.assertEqual(publication_policy(product, tags), {"package_class": "native-node-cli", "qualified_architectures": sorted(tags)})

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name).resolve()
        self.scratch = self.root / "scratch"
        self.scratch.mkdir()

    def _make_burst_capture(self):
        fix_root = self.root / "burst_fixture"
        capture, intent, offline_npm = create_cli_fixture(fix_root, product="theme-forge-stellar-burst")
        profile = evaluate_profile(capture, PACKAGE_PROFILE, intent)
        return capture, intent, profile

    def _make_loom_capture(self):
        fix_root = self.root / "loom_fixture"
        capture, intent, offline_npm = create_cli_fixture(fix_root, product="theme-forge-stellar-loom")
        profile = evaluate_profile(capture, PACKAGE_PROFILE, intent)
        return capture, intent, profile

    def _build_burst_wheel(self, dest_dir):
        payload = {
            "package/dist/cli.js": b"console.log('burst')\n",
            "package/dist/service-protocol/server-cli.js": b"console.log('srv')\n",
        }
        licenses = {"LICENSE": b"MIT\n", "NOTICE": b"Notice\n"}
        return build_wheel(
            "theme-forge-stellar-burst",
            "0.6.1",
            payload,
            {k: 0o755 for k in payload},
            output_dir=dest_dir,
            release_hash=hashlib.sha256(b"dummy-release").hexdigest(),
            license_files=licenses,
            platform_tag="linux_x86_64",
        )

    def test_missing_inputs_directory_reports_candidate_custody_inputs(self):
        capture, intent, profile = self._make_burst_capture()
        context = {
            "inputs": None,
            "scratch": self.scratch,
            "captures": [(capture, intent, profile)],
        }
        result = execute(context)
        self.assertIn("candidate-custody-inputs", result["details"]["missing_inputs"])
        self.assertEqual(result["gates"][0]["name"], "foundation3-plan-assembly")
        self.assertEqual(result["gates"][0]["status"], "fail")
        self.assertEqual(result["gates"][0]["reason"], "missing-custody-inputs")

    def test_missing_wheel_custody_per_product(self):
        inputs_dir = self.root / "inputs"
        inputs_dir.mkdir()
        capture, intent, profile = self._make_burst_capture()
        context = {
            "inputs": str(inputs_dir),
            "scratch": self.scratch,
            "captures": [(capture, intent, profile)],
        }
        result = execute(context)
        self.assertIn("theme-forge-stellar-burst:wheel-custody", result["details"]["missing_inputs"])
        self.assertEqual(result["gates"][0]["status"], "fail")

    def test_missing_native_custody_when_wheel_present(self):
        inputs_dir = self.root / "inputs"
        inputs_dir.mkdir()
        self._build_burst_wheel(inputs_dir)

        capture, intent, profile = self._make_burst_capture()
        context = {
            "inputs": str(inputs_dir),
            "scratch": self.scratch,
            "captures": [(capture, intent, profile)],
        }
        result = execute(context)
        missing = result["details"]["missing_inputs"]
        self.assertNotIn("theme-forge-stellar-burst:wheel-custody", missing)
        self.assertIn("deb:theme-forge-stellar-burst:custody", missing)
        self.assertIn("rpm:theme-forge-stellar-burst:custody", missing)
        self.assertIn("pacman:theme-forge-stellar-burst:custody", missing)

    def test_missing_architectures_in_custody_reported_explicitly(self):
        inputs_dir = self.root / "inputs"
        inputs_dir.mkdir()
        self._build_burst_wheel(inputs_dir)

        # Create deb artifact manifest with only amd64 (missing arm64 for Burst)
        deb_dir = inputs_dir / "candidate-deb-amd64"
        deb_dir.mkdir()
        deb_pkg_name = "theme-forge-stellar-burst_0.6.1-1_amd64.deb"
        deb_pkg_path = deb_dir / "objects" / "custody" / deb_pkg_name
        deb_pkg_path.parent.mkdir(parents=True)
        deb_pkg_bytes = b"dummy-deb-bytes"
        deb_pkg_path.write_bytes(deb_pkg_bytes)
        deb_pkg_sha = hashlib.sha256(deb_pkg_bytes).hexdigest()

        receipt_raw = canonical({"schema": "rs9.hosted-receipt.v1alpha1", "lane": "deb", "system": "amd64"})
        (deb_dir / "deb-amd64.json").write_bytes(receipt_raw)

        manifest = {
            "schema": "rs9.hosted-artifact-set.v1alpha2",
            "lane": "deb",
            "system": "amd64",
            "production_enabled": False,
            "publication_authority": False,
            "runner": "ubuntu-24.04",
            "files": [
                {
                    "path": f"objects/custody/{deb_pkg_name}",
                    "size": len(deb_pkg_bytes),
                    "sha256": deb_pkg_sha,
                    "kind": "custody",
                    "promotion": "candidate-only",
                }
            ],
            "qualification_receipt_hashes": {
                "deb-amd64.json": hashlib.sha256(receipt_raw).hexdigest()
            },
        }
        (deb_dir / "artifact-manifest.json").write_bytes(canonical(manifest))

        capture, intent, profile = self._make_burst_capture()
        context = {
            "inputs": str(inputs_dir),
            "scratch": self.scratch,
            "captures": [(capture, intent, profile)],
        }
        result = execute(context)
        missing = result["details"]["missing_inputs"]
        # deb arm64 is missing for burst
        self.assertIn("deb:theme-forge-stellar-burst:arm64:custody", missing)
        self.assertNotIn("deb:theme-forge-stellar-burst:amd64:custody", missing)

    def test_verify_candidate_files_validation(self):
        cand_root = self.root / "candidate"
        cand_root.mkdir()

        # 1. Non-existent file
        inv_data = [{"path": "nonexistent.deb", "size": 10, "sha256": "0" * 64}]
        (cand_root / "inventory.json").write_bytes(canonical(inv_data))
        with self.assertRaises(ContractError) as caught:
            verify_candidate_files(cand_root)
        self.assertEqual(caught.exception.code, "FOUNDATION_INVENTORY")

        # 2. Duplicate paths
        file1 = cand_root / "pkg1.deb"
        file1.write_bytes(b"content")
        inv_dup = [
            {"path": "pkg1.deb", "size": 7, "sha256": hashlib.sha256(b"content").hexdigest()},
            {"path": "pkg1.deb", "size": 7, "sha256": hashlib.sha256(b"content").hexdigest()},
        ]
        (cand_root / "inventory.json").write_bytes(canonical(inv_dup))
        with self.assertRaises(ContractError) as caught:
            verify_candidate_files(cand_root)
        self.assertEqual(caught.exception.code, "FOUNDATION_INVENTORY")

        # 3. Hash mismatch
        inv_mismatch = [{"path": "pkg1.deb", "size": 7, "sha256": "f" * 64}]
        (cand_root / "inventory.json").write_bytes(canonical(inv_mismatch))
        with self.assertRaises(ContractError) as caught:
            verify_candidate_files(cand_root)
        self.assertEqual(caught.exception.code, "FOUNDATION_INVENTORY")

    def test_duplicate_wheel_custody_raises(self):
        inputs_dir = self.root / "inputs_dup"
        inputs_dir.mkdir()
        sub1 = inputs_dir / "sub1"
        sub2 = inputs_dir / "sub2"
        sub1.mkdir()
        sub2.mkdir()
        (sub1 / "theme_forge_stellar_loom-0.4.0-py3-none-any.whl").write_bytes(b"content-a")
        (sub2 / "theme_forge_stellar_loom-0.4.0-py3-none-any.whl").write_bytes(b"content-b-different")

        capture, intent, profile = self._make_loom_capture()
        context = {
            "inputs": str(inputs_dir),
            "scratch": self.scratch,
            "captures": [(capture, intent, profile)],
        }
        with self.assertRaises(ContractError) as caught:
            execute(context)
        self.assertEqual(caught.exception.code, "FOUNDATION_CUSTODY")
