"""Synthetic seams prove client execution and authenticated loader record binding."""
import json
from pathlib import Path
from types import SimpleNamespace
import tempfile
import unittest
from unittest.mock import Mock

from rs9.burst_native import BURST_CLOSED_PREBUILDS
from rs9.errors import ContractError
from rs9.hosted_burst_clients import release_load_record, verify_client_burst
from rs9.release_core import digest


class BurstClientTests(unittest.TestCase):
    def record(self):
        addon = BURST_CLOSED_PREBUILDS["linux-x64-gnu"]
        capture = SimpleNamespace(record={"repository": {"full_name": "Knowledge-Forge-AI/theme-forge-stellar-burst"},
                                          "payloads": [{"id": "payload"}]},
                                  manifests={"payload": {"members": [
                                      {"path": addon, "type": "file", "sha256": digest(b"addon")},
                                      {"path": "package/dist/directory-snapshot-native.js", "type": "file", "sha256": digest(b"loader")} ]}})
        return capture, release_load_record(capture, "x86_64-linux")

    def test_record_requires_authenticated_regular_loader_and_target(self):
        capture, record = self.record()
        self.assertEqual(record["target_system"], "x86_64-linux")
        for field in ("sha256", "type"):
            original = capture.manifests["payload"]["members"][0][field]
            capture.manifests["payload"]["members"][0][field] = "invalid"
            with self.assertRaises(ContractError):
                release_load_record(capture, "x86_64-linux")
            capture.manifests["payload"]["members"][0][field] = original
        with self.assertRaises(ContractError):
            release_load_record(capture, "aarch64-linux")

    def test_client_runs_proof_unprivileged_inside_installed_payload(self):
        _, record = self.record()
        receipt = {"status": "pass", "proof": "installed-released-loader-self-test", "loaded": True,
                   "artifact": "linux-x64-gnu", "loads": [record["target_native_addon"]["path"].removeprefix("package/")],
                   "sha256": record["target_native_addon"]["sha256"], "node_version": "v22.22.2",
                   "node_abi": "127", "platform": "linux", "architecture": "x64"}
        result = SimpleNamespace(exit_code=0, executed=True, stdout_bytes=json.dumps(receipt).encode(),
                                 stdout_sha256="a" * 64, stderr_sha256="b" * 64)
        client = Mock()
        client.exec.return_value = result
        with tempfile.TemporaryDirectory() as td:
            probe = Path(td).resolve() / "probe"
            self.assertEqual(verify_client_burst(client, record, "x86_64-linux", probe, user="65534:65534")["status"], "pass")
            args, kwargs = client.exec.call_args
            self.assertEqual(kwargs["user"], "65534:65534")
            self.assertIn("verify_burst_payload('/usr/lib/theme-forge-stellar-burst'", args[0][2])
            self.assertEqual(json.loads(args[0][3]), record)
            self.assertEqual(args[0][4], "x86_64-linux")
            result.executed = False
            with self.assertRaises(ContractError):
                verify_client_burst(client, record, "x86_64-linux", probe.parent / "other", user="65534:65534")
