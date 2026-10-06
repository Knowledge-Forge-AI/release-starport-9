"""Tests for hosted Linux clean-client qualification, explicit configs, and manifest authentication."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import MagicMock, patch

from rs9.errors import ContractError
from rs9.hosted_wheel_clients import build_client_prepared_config, child, qualify
from rs9.release_core import ReleaseCapture
from rs9.scratch import canonical, validate_safe_json


class HostedWheelClientsTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name).resolve()
        self.scratch = self.root / "scratch"
        self.scratch.mkdir()
        self.repo = self.root / "repo"
        self.repo.mkdir()

    def test_objective_failure_b_defect_and_remediation(self):
        """Prove Objective Failure B: ReleaseCapture in prepared causes json.dumps TypeError.

        With explicit producer config, ReleaseCapture is excluded and only JSON-safe fields
        plus authenticated expected_members and bound manifest_sha256 are emitted.
        """
        members = [
            {"path": "lib/sidecar-payload/manifest.json", "sha256": "1" * 64, "type": "file"},
            {"path": "bin/tfsb-studio-service", "sha256": "2" * 64, "type": "file"},
        ]
        manifest_hash = hashlib.sha256(canonical(members)).hexdigest()

        capture = ReleaseCapture(
            {"payloads": [
                {"id": "tfnf-linux-x86_64", "platforms": ["x86_64-linux"], "payload_manifest_sha256": manifest_hash}
            ]}, {}, {}, {
                "tfnf-linux-x86_64": {"manifest_sha256": manifest_hash, "members": members}
            }, {}, {}, self.root,
        )

        prepared = {
            "source": self.root / "source",
            "tools": self.root / "tools",
            "scratch": self.root / "scratch",
            "records": [{"path": "tools/native-rc-smoke.mjs"}],
            "label": "smoke-test",
            "capture": capture,
        }

        # 1. Proving Failure B defect: direct naive serialization fails with TypeError
        naive_prepared = {k: str(v) if isinstance(v, Path) else v for k, v in prepared.items()}
        naive_config = {"prepared": naive_prepared}
        with self.assertRaises(TypeError) as type_err_ctx:
            canonical(naive_config)
        self.assertIn("not JSON serializable", str(type_err_ctx.exception))

        # 2. Privacy-safe validator catches the un-serializable ReleaseCapture
        with self.assertRaises(ContractError) as contract_ctx:
            validate_safe_json(naive_config, lane="wheels", product="theme-forge-nebular-fusion")
        self.assertEqual(contract_ctx.exception.code, "INVALID_JSON")
        self.assertEqual(contract_ctx.exception.details.get("exception_type"), "ReleaseCapture")
        self.assertEqual(contract_ctx.exception.details.get("origin"), "root.prepared.capture")

        # 3. Explicit producer config produces clean, JSON-serializable output
        clean_prepared = build_client_prepared_config(prepared, "x86_64-linux")
        self.assertNotIn("capture", clean_prepared)
        self.assertIsInstance(clean_prepared["source"], str)
        self.assertIsInstance(clean_prepared["tools"], str)
        self.assertIsInstance(clean_prepared["scratch"], str)
        self.assertEqual(clean_prepared["expected_members"], members)
        self.assertEqual(clean_prepared["manifest_sha256"], manifest_hash)
        self.assertEqual(clean_prepared["label"], "smoke-test")

        # Validate that clean config passes privacy-safe validator and serializes
        clean_config = {"prepared": clean_prepared}
        validate_safe_json(clean_config, lane="wheels", product="theme-forge-nebular-fusion")
        serialized = canonical(clean_config)
        self.assertIsInstance(serialized, bytes)
        decoded = json.loads(serialized)
        self.assertEqual(decoded["prepared"]["manifest_sha256"], manifest_hash)

    @patch("rs9.hosted_wheel_clients.provision_image")
    @patch("rs9.hosted_wheel_clients.ContainerRunner")
    @patch("rs9.hosted_wheel_clients.RecordingRunner")
    def test_qualify_independent_client_gates_deb_fail_rpm_pass(self, mock_rec, mock_runner_cls, mock_prov):
        """When Debian clean client fails, RPM clean client still runs and evaluates independently."""
        context = {
            "system": "x86_64-linux",
            "repository": self.repo,
            "scratch": self.scratch,
            "pins": {
                "deb": {"container_digests": {"amd64": "sha256:" + "d" * 64}},
                "rpm": {"container_digests": {"x86_64": "sha256:" + "r" * 64}},
            },
        }
        wheels = {"theme-forge-stellar-burst": self.scratch / "wheel.whl"}
        prepared = {
            "source": self.scratch / "source",
            "tools": self.scratch / "tools",
            "scratch": self.scratch / "native-smoke",
            "records": [],
        }

        deb_receipt = MagicMock(exit_code=1, executed=True)
        rpm_receipt = MagicMock(exit_code=0, executed=True)

        call_count = 0
        def runner_instance_factory(*args, **kwargs):
            nonlocal call_count
            runner = MagicMock()
            if call_count == 0:
                runner.run.return_value = deb_receipt
            else:
                runner.run.return_value = rpm_receipt
                (self.scratch / "wheel-client-rpm-receipt.json").write_bytes(b"{}")
            call_count += 1
            return runner

        mock_runner_cls.side_effect = runner_instance_factory

        gates, files = qualify(context, wheels, prepared)
        gate_map = {g["name"]: g for g in gates}

        self.assertEqual(gate_map["wheel-client-deb"]["status"], "fail")
        self.assertEqual(gate_map["wheel-client-deb"]["reason"], "clean-client-lifecycle-failed")

        self.assertEqual(gate_map["wheel-client-rpm"]["status"], "pass")
        self.assertEqual(len(files), 1)
        self.assertEqual(files[0].name, "wheel-client-rpm-receipt.json")

    @patch("socket.socket")
    @patch("os.getuid", return_value=1000)
    def test_child_manifest_sha256_authentication_tamper_rejected(self, mock_getuid, mock_socket):
        """Client checks expected members against manifest_sha256 before verifier and rejects mismatch."""
        mock_sock_inst = MagicMock()
        mock_sock_inst.connect_ex.return_value = 1  # No external network
        mock_socket.return_value = mock_sock_inst

        members = [{"path": "payload/manifest.json", "sha256": "0" * 64, "type": "file"}]
        tampered_members = [{"path": "payload/manifest.json", "sha256": "f" * 64, "type": "file"}]
        manifest_hash = hashlib.sha256(canonical(members)).hexdigest()

        config = {
            "system": "x86_64-linux",
            "root": str(self.scratch / "client-root"),
            "repository": str(self.repo),
            "output": str(self.scratch / "client-receipt.json"),
            "bindings": {},
            "wheels": {
                "theme-forge-nebular-fusion": str(self.scratch / "dummy.whl"),
            },
            "prepared": {
                "source": str(self.scratch / "source"),
                "tools": str(self.scratch / "tools"),
                "scratch": str(self.scratch / "smoke"),
                "expected_members": tampered_members,  # Tampered!
                "manifest_sha256": manifest_hash,
            },
        }

        def fake_lifecycle(wheel_path, distribution_name, commands_to_test, venv_dir, cache_dir):
            # Simulate the commands_to_test execution that runs verify
            verifier = commands_to_test["tfnf"]["verifier"]
            # Setup payload structure for probe
            payload_dir = self.scratch / "cache/entries/entry1/payload/sidecar-payload"
            payload_dir.mkdir(parents=True, exist_ok=True)
            elf_file = payload_dir / "bin/tfsb-studio-service"
            elf_file.parent.mkdir(parents=True, exist_ok=True)
            elf_file.write_bytes(bytes([127]) + b"ELF" + b"\x00" * 100)

            env = {"THEME_FORGE_CACHE_DIR": str(self.scratch / "cache")}
            verifier(elf_file, [], env)
            return {"installed": True}

        with patch("rs9.hosted_wheel_clients.run_probes", return_value=[{"name": "tfnf", "status": "pass"}]), \
             patch("subprocess.run", return_value=MagicMock(returncode=0, stdout=b"statically linked", stderr=b"")), \
             patch("rs9.hosted_wheel_clients.verify_offline_venv_lifecycle", side_effect=fake_lifecycle):
            with self.assertRaises(ContractError) as ctx:
                child(config)

        self.assertEqual(ctx.exception.code, "MANIFEST_AUTHENTICATION")
        self.assertIn("Expected members hash does not match manifest SHA256", str(ctx.exception))
        self.assertEqual(ctx.exception.details.get("expected_digest"), manifest_hash)

    @patch("socket.socket")
    @patch("os.getuid", return_value=1000)
    def test_child_manifest_sha256_authentication_success(self, mock_getuid, mock_socket):
        """When expected members hash matches manifest_sha256, child proceeds to verify_nebular_runtime."""
        mock_sock_inst = MagicMock()
        mock_sock_inst.connect_ex.return_value = 1
        mock_socket.return_value = mock_sock_inst

        members = [{"path": "payload/manifest.json", "sha256": "0" * 64, "type": "file"}]
        manifest_hash = hashlib.sha256(canonical(members)).hexdigest()

        config = {
            "system": "x86_64-linux",
            "root": str(self.scratch / "client-root"),
            "repository": str(self.repo),
            "output": str(self.scratch / "client-receipt.json"),
            "bindings": {},
            "wheels": {
                "theme-forge-nebular-fusion": str(self.scratch / "dummy.whl"),
            },
            "prepared": {
                "source": str(self.scratch / "source"),
                "tools": str(self.scratch / "tools"),
                "scratch": str(self.scratch / "smoke"),
                "expected_members": members,
                "manifest_sha256": manifest_hash,
            },
        }

        def fake_lifecycle(wheel_path, distribution_name, commands_to_test, venv_dir, cache_dir):
            verifier = commands_to_test["tfnf"]["verifier"]
            payload_dir = self.scratch / "cache/entries/entry1/payload/sidecar-payload"
            payload_dir.mkdir(parents=True, exist_ok=True)
            elf_file = payload_dir / "bin/tfsb-studio-service"
            elf_file.parent.mkdir(parents=True, exist_ok=True)
            elf_file.write_bytes(bytes([127]) + b"ELF" + b"\x00" * 100)

            env = {"THEME_FORGE_CACHE_DIR": str(self.scratch / "cache")}
            verifier(elf_file, [], env)
            return {"installed": True}

        with patch("rs9.hosted_wheel_clients.run_probes", return_value=[{"name": "tfnf", "status": "pass"}]), \
             patch("subprocess.run", return_value=MagicMock(returncode=0, stdout=b"statically linked", stderr=b"")), \
             patch("rs9.hosted_wheel_clients.verifier_import_preflight", return_value={"status": "pass"}), \
             patch("rs9.hosted_wheel_clients.verify_nebular_runtime", return_value={"nebular_smoke": "pass"}) as mock_neb_smoke, \
             patch("rs9.hosted_wheel_clients.verify_offline_venv_lifecycle", side_effect=fake_lifecycle):
            child(config)

        mock_neb_smoke.assert_called_once()
        receipt_file = self.scratch / "client-receipt.json"
        self.assertTrue(receipt_file.is_file())
        receipt_data = json.loads(receipt_file.read_bytes())
        self.assertEqual(receipt_data["native_smoke"]["nebular_smoke"], "pass")
        self.assertEqual(receipt_data["native_smoke"]["elf_objects_checked"], 1)


if __name__ == "__main__":
    unittest.main()
