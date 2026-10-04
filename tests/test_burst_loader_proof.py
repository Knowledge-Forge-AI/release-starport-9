"""Behavioral tests for Burst loader proof, generalized payload verifier, and contract readbacks."""
from __future__ import annotations

import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from rs9.burst_loader_proof import (
    BURST_LOADER_SHA256,
    BURST_PAYLOAD_SHA256,
    BURST_PREBUILD_IDENTITIES,
    BURST_VERSION,
    REAL_LOADER_CONTRACT,
    probe_local_node,
    prove_burst_loader,
)
from rs9.burst_native import BURST_CLOSED_PREBUILDS
from rs9.errors import ContractError
from rs9.hosted_burst import validate_load_receipt, verify_burst_payload
from rs9.release_core import digest
from tests.elf_builder import build_elf
from tests.test_burst_platform_wheel import make_synthetic_macho


class BurstLoaderProofTests(unittest.TestCase):
    """Qualification tests for Burst 0.6.1 loader proof and generalized payload verifier."""

    def test_explicit_scratch_root_required_before_any_runtime_probe(self):
        with patch("rs9.burst_loader_proof.probe_local_node") as probe:
            with self.assertRaises(ContractError) as caught:
                prove_burst_loader()
        self.assertEqual(caught.exception.code, "SCRATCH_REQUIRED")
        probe.assert_not_called()

    def test_explicit_scratch_root_must_be_physical_before_runtime_probe(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            link = root / "linked"
            link.symlink_to(root, target_is_directory=True)
            for scratch, code in ((root / "missing", "INVALID_DIRECTORY"), (link, "SYMLINK_REJECTED")):
                with self.subTest(code=code), patch("rs9.burst_loader_proof.probe_local_node") as probe:
                    with self.assertRaises(ContractError) as caught:
                        prove_burst_loader(scratch_root=scratch)
                self.assertEqual(caught.exception.code, code)
                probe.assert_not_called()

    def test_real_loader_contract_constants(self) -> None:
        """Verify discovered real released contract identities and export definitions."""
        self.assertEqual(BURST_VERSION, "0.6.1")
        self.assertEqual(BURST_PAYLOAD_SHA256, "53ef41a3de3335e042f2c4b1d299b1155b64bfc6556a84baf6a62cb28bcca209")
        self.assertEqual(BURST_LOADER_SHA256, "23a3bf942fa1f92fbf686b4cedc0ec2a9f6653ded6fd2df7ef9d3c58d6591e69")
        self.assertEqual(REAL_LOADER_CONTRACT["loader_module"], "package/dist/directory-snapshot-native.js")
        self.assertEqual(REAL_LOADER_CONTRACT["loader_export"], "loadDirectorySnapshotNative()")
        self.assertEqual(REAL_LOADER_CONTRACT["backend_name"], "native-addon-posix-openat-v1")
        self.assertEqual(REAL_LOADER_CONTRACT["backend_abi"], 1)
        self.assertIn("DIRECTORY_SNAPSHOT_BACKEND", REAL_LOADER_CONTRACT["exported_symbols"])
        self.assertIn("loadDirectorySnapshotNative", REAL_LOADER_CONTRACT["exported_symbols"])

        # Check all 4 prebuild identities
        darwin_arm64 = BURST_PREBUILD_IDENTITIES["darwin-arm64"]
        self.assertEqual(darwin_arm64["sha256"], "2f842ce43f62c76b04884a92980037067c8e55dfd183c86e788f1c3ac8a533c8")
        self.assertEqual(darwin_arm64["format"], "Mach-O 64-bit arm64")
        self.assertEqual(darwin_arm64["arch"], "arm64")
        self.assertEqual(darwin_arm64["deployment_minimum"], [13, 0])

        linux_x64 = BURST_PREBUILD_IDENTITIES["linux-x64-gnu"]
        self.assertEqual(linux_x64["sha256"], "a2999fc9ac1b1f0a31600595f7069e10aadb032f01059b4d7e64ed80cd8a38a8")
        self.assertEqual(linux_x64["format"], "ELF 64-bit x86_64")
        self.assertEqual(linux_x64["arch"], "x86_64")

    def test_synthetic_payload_root_verifier_with_layout_prefix(self) -> None:
        """[SYNTHETIC] Verify verify_burst_payload on synthetic payload root with layout_prefix='package'."""
        with tempfile.TemporaryDirectory() as td:
            root = Path(td).resolve()
            payload = root / "payload"
            key = "darwin-arm64"
            expected_rel = BURST_CLOSED_PREBUILDS[key]  # starts with 'package/'
            addon = payload / expected_rel
            addon.parent.mkdir(parents=True)
            addon.write_bytes(make_synthetic_macho())

            loader = payload / "package/dist/directory-snapshot-native.js"
            loader.parent.mkdir(parents=True)
            loader.write_bytes(b"synthetic-loader-code")

            expected = {
                "path": expected_rel,
                "sha256": digest(addon.read_bytes()),
            }
            record = {
                "platform_specific": True,
                "target_system": "aarch64-darwin",
                "target_native_addon": expected,
                "native_loader": {
                    "path": "package/dist/directory-snapshot-native.js",
                    "sha256": digest(loader.read_bytes()),
                },
            }

            receipt = {
                "loaded": True,
                "artifact": key,
                "loads": [expected_rel],
                "sha256": expected["sha256"],
                "node_version": "v22.20.0",
                "node_abi": "127",
                "platform": "darwin",
                "architecture": "arm64",
            }

            called_commands = []

            def mock_runner(cmd, env=None):
                called_commands.append(cmd)
                return 0, json.dumps(receipt).encode("utf-8"), b""

            probe_scratch = root / "probe"
            res = verify_burst_payload(
                payload,
                record,
                "aarch64-darwin",
                probe_scratch,
                layout_prefix="package",
                runner=mock_runner,
            )
            self.assertEqual(res["status"], "pass")
            self.assertEqual(res["artifact"], "darwin-arm64")
            self.assertEqual(len(called_commands), 1)
            self.assertIn("node", called_commands[0])

    def test_synthetic_payload_root_verifier_without_layout_prefix(self) -> None:
        """[SYNTHETIC] Verify verify_burst_payload on synthetic payload root with layout_prefix='' (unprefixed)."""
        with tempfile.TemporaryDirectory() as td:
            root = Path(td).resolve()
            payload = root / "unprefixed_pkg"
            key = "linux-x64-gnu"
            expected_rel = BURST_CLOSED_PREBUILDS[key].removeprefix("package/")
            addon = payload / expected_rel
            addon.parent.mkdir(parents=True)
            addon.write_bytes(build_elf())

            loader = payload / "dist/directory-snapshot-native.js"
            loader.parent.mkdir(parents=True)
            loader.write_bytes(b"synthetic-loader-code")

            expected = {
                "path": BURST_CLOSED_PREBUILDS[key],
                "sha256": digest(addon.read_bytes()),
            }
            record = {
                "platform_specific": True,
                "target_system": "x86_64-linux",
                "target_native_addon": expected,
                "native_loader": {
                    "path": "package/dist/directory-snapshot-native.js",
                    "sha256": digest(loader.read_bytes()),
                },
            }

            receipt = {
                "loaded": True,
                "artifact": key,
                "loads": [expected_rel],
                "sha256": expected["sha256"],
                "node_version": "v22.20.0",
                "node_abi": "127",
                "platform": "linux",
                "architecture": "x64",
            }

            def mock_runner(cmd, env=None):
                return 0, json.dumps(receipt).encode("utf-8"), b""

            probe_scratch = root / "probe"
            res = verify_burst_payload(
                payload,
                record,
                "x86_64-linux",
                probe_scratch,
                layout_prefix="",
                runner=mock_runner,
            )
            self.assertEqual(res["status"], "pass")
            self.assertEqual(res["artifact"], "linux-x64-gnu")

    def test_synthetic_dlopen_count_more_than_one_fails_closed(self) -> None:
        """[SYNTHETIC] dlopen count > 1 raises BURST_NATIVE_LOAD_COUNT."""
        expected = {
            "path": BURST_CLOSED_PREBUILDS["darwin-arm64"],
            "sha256": digest(b"binary"),
        }
        receipt = {
            "loaded": True,
            "artifact": "darwin-arm64",
            "loads": [expected["path"], expected["path"]],  # multiple loads
            "sha256": expected["sha256"],
            "node_version": "v22.20.0",
            "node_abi": "127",
            "platform": "darwin",
            "architecture": "arm64",
        }
        with self.assertRaises(ContractError) as ctx:
            validate_load_receipt(receipt, expected, "aarch64-darwin")
        self.assertEqual(ctx.exception.code, "BURST_NATIVE_LOAD_COUNT")

    def test_synthetic_dlopen_foreign_addon_fails_closed(self) -> None:
        """[SYNTHETIC] Loading foreign target prebuild raises BURST_NATIVE_LOAD_TARGET."""
        expected = {
            "path": BURST_CLOSED_PREBUILDS["darwin-arm64"],
            "sha256": digest(b"binary"),
        }
        receipt = {
            "loaded": True,
            "artifact": "darwin-arm64",
            "loads": [BURST_CLOSED_PREBUILDS["linux-x64-gnu"]],  # foreign
            "sha256": expected["sha256"],
            "node_version": "v22.20.0",
            "node_abi": "127",
            "platform": "darwin",
            "architecture": "arm64",
        }
        with self.assertRaises(ContractError) as ctx:
            validate_load_receipt(receipt, expected, "aarch64-darwin")
        self.assertEqual(ctx.exception.code, "BURST_NATIVE_LOAD_TARGET")

    def test_synthetic_node_version_and_abi_requirements(self) -> None:
        """[SYNTHETIC] Node version < 22 or malformed ABI fails closed with BURST_NATIVE_NODE."""
        expected = {
            "path": BURST_CLOSED_PREBUILDS["darwin-arm64"],
            "sha256": digest(b"binary"),
        }
        base_receipt = {
            "loaded": True,
            "artifact": "darwin-arm64",
            "loads": [expected["path"]],
            "sha256": expected["sha256"],
            "node_version": "v20.18.0",  # < 22
            "node_abi": "115",
            "platform": "darwin",
            "architecture": "arm64",
        }
        with self.assertRaises(ContractError) as ctx:
            validate_load_receipt(base_receipt, expected, "aarch64-darwin")
        self.assertEqual(ctx.exception.code, "BURST_NATIVE_NODE")

        # Non-numeric ABI
        bad_abi = dict(base_receipt, node_version="v22.0.0", node_abi="invalid_abi")
        with self.assertRaises(ContractError) as ctx:
            validate_load_receipt(bad_abi, expected, "aarch64-darwin")
        self.assertEqual(ctx.exception.code, "BURST_NATIVE_NODE")

    def test_synthetic_loader_sha_mismatch_fails_closed(self) -> None:
        """[SYNTHETIC] Loader bytes differing from authenticated record raises BURST_NATIVE_LOAD_BYTES."""
        with tempfile.TemporaryDirectory() as td:
            root = Path(td).resolve()
            payload = root / "payload"
            key = "darwin-arm64"
            expected_rel = BURST_CLOSED_PREBUILDS[key]
            addon = payload / expected_rel
            addon.parent.mkdir(parents=True)
            addon.write_bytes(make_synthetic_macho())

            loader = payload / "package/dist/directory-snapshot-native.js"
            loader.parent.mkdir(parents=True)
            loader.write_bytes(b"tampered-loader")

            expected = {"path": expected_rel, "sha256": digest(addon.read_bytes())}
            record = {
                "platform_specific": True,
                "target_system": "aarch64-darwin",
                "target_native_addon": expected,
                "native_loader": {
                    "path": "package/dist/directory-snapshot-native.js",
                    "sha256": digest(b"original-loader"),
                },
            }

            with self.assertRaises(ContractError) as ctx:
                verify_burst_payload(
                    payload,
                    record,
                    "aarch64-darwin",
                    root / "probe",
                    layout_prefix="package",
                )
            self.assertEqual(ctx.exception.code, "BURST_NATIVE_LOAD_BYTES")

    def test_real_burst_loader_proof_evidence_readback(self) -> None:
        """Verify authentic generated Darwin arm64 evidence record bounds and hygiene."""
        evidence_path = Path(__file__).resolve().parents[1] / "evidence/live1/burst-loader-darwin-arm64.json"
        self.assertTrue(evidence_path.is_file(), f"Evidence file missing: {evidence_path}")

        raw = evidence_path.read_text(encoding="utf-8")
        data = json.loads(raw)

        # Strict privacy hygiene: NO private host path markers
        for forbidden in ("/" + "Users" + "/", "/private/"):
            self.assertNotIn(forbidden, raw, f"Private marker {forbidden!r} detected in evidence")

        # Schema and status
        self.assertEqual(data["schema"], "rs9.burst-loader-proof.v1alpha1")
        self.assertEqual(data["status"], "pass")
        self.assertEqual(data["system"], "aarch64-darwin")
        self.assertEqual(data["product"], "theme-forge-stellar-burst")
        self.assertEqual(data["version"], "0.6.1")
        self.assertRegex(data["release_record_sha256"], r"^[0-9a-f]{64}$")
        self.assertEqual(set(data["probe"]), {"exit_code", "preload_sha256", "harness_sha256", "stdout_sha256", "stderr_sha256"})
        self.assertEqual(data["probe"]["exit_code"], 0)
        for key, value in data["probe"].items():
            if key.endswith("_sha256"):
                self.assertRegex(value, r"^[0-9a-f]{64}$")

        # Release & Loader hashes
        self.assertEqual(data["release"]["payload_sha256"], BURST_PAYLOAD_SHA256)
        self.assertEqual(data["loader_contract"]["sha256"], BURST_LOADER_SHA256)
        self.assertEqual(data["loader_contract"]["dlopen_behavior"], "exactly-once-memoized")

        # Target Prebuild
        target = data["target_prebuild"]
        self.assertEqual(target["key"], "darwin-arm64")
        self.assertEqual(target["architecture"], "arm64")
        self.assertEqual(target["format"], "Mach-O 64-bit arm64")
        self.assertEqual(target["sha256"], "2f842ce43f62c76b04884a92980037067c8e55dfd183c86e788f1c3ac8a533c8")
        self.assertEqual(target["deployment_minimum"], [13, 0])

        # Preserved Foreign Prebuilds
        foreign = data["foreign_prebuilds"]
        self.assertEqual(len(foreign), 3)
        self.assertTrue(all(fp["disposition"] == "retained-inert" for fp in foreign))

        # Preserved Offline Closure
        closure = data["offline_closure"]
        self.assertEqual(len(closure), 3)
        self.assertEqual({c["package"] for c in closure}, {"@xmldom/xmldom", "fflate", "smol-toml"})

        # Observed Load Receipt
        receipt = data["observed_load_receipt"]
        self.assertTrue(receipt["loaded"])
        self.assertEqual(receipt["artifact"], "darwin-arm64")
        self.assertEqual(receipt["loads_count"], 1)
        self.assertEqual(receipt["loaded_sha256"], target["sha256"])
        self.assertTrue(receipt["node_version"].startswith("v"))
        major = int(receipt["node_version"].split(".")[0][1:])
        self.assertGreaterEqual(major, 22)
        self.assertEqual(receipt["platform"], "darwin")
        self.assertEqual(receipt["architecture"], "arm64")


if __name__ == "__main__":
    unittest.main()
