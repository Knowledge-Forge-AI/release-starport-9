"""Focused proof for the bounded Linux wheel-client failure diagnostic."""

from __future__ import annotations

import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import MagicMock, patch

from rs9.build_native import CommandReceipt
from rs9.errors import ContractError
from rs9.hosted_wheel_clients import MAX_CHILD_DIAGNOSTIC_BYTES, _child_diagnostic_details, child, qualify
from rs9.verify_wheel import _command_result_error, _lifecycle_phase


class ClientDiagnosticProposalTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name).resolve()
        self.scratch = self.root / "scratch"
        self.scratch.mkdir()
        self.repo = self.root / "repo"
        self.repo.mkdir()

    def _qualify_context(self):
        return {
            "system": "x86_64-linux",
            "repository": self.repo,
            "scratch": self.scratch,
            "pins": {
                "deb": {"container_digests": {"amd64": "sha256:" + "d" * 64}},
                "rpm": {"container_digests": {"x86_64": "sha256:" + "r" * 64}},
            },
        }

    def _prepared(self):
        return {
            "source": self.scratch / "source",
            "tools": self.scratch / "tools",
            "scratch": self.scratch / "native-smoke",
            "records": [],
        }

    def test_child_exit_two_and_missing_receipt_retain_bounded_failure(self):
        context = self._qualify_context()
        wheels = {"theme-forge-stellar-burst": self.scratch / "burst.whl"}

        deb_receipt = CommandReceipt(
            ["python3", "-m", "rs9.hosted_wheel_clients"],
            2,
            b"",
            b"Traceback: failed child at /private/fixture/venv\nsecret=withheld\n",
            tool_name="python3",
            executed=True,
        )
        rpm_receipt = CommandReceipt(
            ["python3", "-m", "rs9.hosted_wheel_clients"], 0, b"", b"", tool_name="python3", executed=True
        )

        def runner_factory(*args, **kwargs):
            runner = MagicMock()
            if "wheel-client-deb" in args[1]:
                runner.run.return_value = deb_receipt
            else:
                runner.run.return_value = rpm_receipt
                (self.scratch / "wheel-client-rpm-receipt.json").write_bytes(b"{}")
            return runner

        with patch("rs9.hosted_wheel_clients.provision_image"), \
             patch("rs9.hosted_wheel_clients.RecordingRunner"), \
             patch("rs9.hosted_wheel_clients.ContainerRunner", side_effect=runner_factory):
            gates, files = qualify(context, wheels, self._prepared())

        gate_map = {row["name"]: row for row in gates}
        self.assertEqual(gate_map["wheel-client-deb"]["status"], "fail")
        self.assertEqual(gate_map["wheel-client-deb"]["reason"], "clean-client-lifecycle-failed")
        self.assertEqual(gate_map["wheel-client-deb"]["diagnostic"]["failure_category"], "child-exit-nonzero")
        self.assertEqual(gate_map["wheel-client-rpm"]["status"], "pass")

        diagnostic_path = self.scratch / "diagnostics/wheel-client-deb-lifecycle-diagnostic.json"
        self.assertIn(diagnostic_path, files)
        diagnostic = json.loads(diagnostic_path.read_bytes())
        self.assertEqual(diagnostic["schema"], "rs9.hosted-candidate-diagnostic.v1alpha2")
        details = diagnostic["details"]
        self.assertEqual(details["phase"], "client-lifecycle")
        self.assertEqual(details["failure_category"], "child-exit-nonzero")
        self.assertEqual(details["failed_receipt"]["exit_code"], 2)
        self.assertTrue(details["failed_receipt"]["executed"])
        self.assertNotIn("/private/fixture", details["stderr_tail"])
        self.assertNotIn("secret=", details["stderr_tail"])
        self.assertNotIn("command", details["failed_receipt"])
        self.assertFalse((self.scratch / "wheel-client-deb-receipt.json").exists())

    def test_successful_client_receipts_and_gates_are_unchanged(self):
        context = self._qualify_context()
        wheels = {"theme-forge-stellar-burst": self.scratch / "burst.whl"}
        receipts = [
            CommandReceipt(["python3"], 0, b"", b"", tool_name="python3", executed=True),
            CommandReceipt(["python3"], 0, b"", b"", tool_name="python3", executed=True),
        ]

        def runner_factory(*args, **kwargs):
            runner = MagicMock()
            runner.run.return_value = receipts.pop(0)
            family = "deb" if "deb" in args[1] else "rpm"
            (self.scratch / f"wheel-client-{family}-receipt.json").write_bytes(b"{}")
            return runner

        with patch("rs9.hosted_wheel_clients.provision_image"), \
             patch("rs9.hosted_wheel_clients.RecordingRunner"), \
             patch("rs9.hosted_wheel_clients.ContainerRunner", side_effect=runner_factory):
            gates, files = qualify(context, wheels, self._prepared())

        self.assertEqual([row["status"] for row in gates], ["pass", "pass"])
        self.assertEqual(sorted(path.name for path in files), ["wheel-client-deb-receipt.json", "wheel-client-rpm-receipt.json"])
        self.assertFalse((self.scratch / "diagnostics").exists())

    def test_lifecycle_process_failure_keeps_phase_and_hashes_without_argv(self):
        with self.assertRaises(ContractError) as caught:
            with _lifecycle_phase("wheel-install"):
                raise subprocess.CalledProcessError(
                    2, ["python3", "private-argument"], output=b"out", stderr=b"/private/fixture\n"
                )

        details = caught.exception.details
        self.assertEqual(details["phase"], "wheel-install")
        self.assertEqual(details["underlying_code"], "process-exit")
        self.assertEqual(details["exit_code"], 2)
        self.assertIn("stdout_sha256", details)
        self.assertIn("stderr_sha256", details)
        self.assertNotIn("command", details)
        self.assertEqual(caught.exception._diagnostic_stderr_tail, "[PATH]\n")

    def test_completed_process_nonzero_keeps_actual_exit_and_stream_identity(self):
        completed = subprocess.CompletedProcess(
            ["python3", "private-argument"], 2, "out", "stderr from /private/fixture"
        )
        error = _command_result_error(completed, "command:tfnf", 0)
        self.assertEqual(error.code, "COMMAND_EXECUTION_FAILED")
        self.assertEqual(error.details["phase"], "command:tfnf")
        self.assertEqual(error.details["exit_code"], 2)
        self.assertEqual(error.details["expected_exit"], 0)
        self.assertIn("stdout_sha256", error.details)
        self.assertIn("stderr_sha256", error.details)
        self.assertEqual(error._diagnostic_stderr_tail, "stderr from [PATH]")
        self.assertNotIn("command", error.details)

    def test_oversized_child_diagnostic_is_withheld_before_json_parse(self):
        oversized = self.scratch / "diagnostics/child.json"
        oversized.parent.mkdir()
        oversized.write_bytes(b"{" + b"x" * (MAX_CHILD_DIAGNOSTIC_BYTES + 1024))
        self.assertEqual(_child_diagnostic_details(oversized), {})

    @patch("socket.socket")
    @patch("os.getuid", return_value=1000)
    def test_child_phase_is_retained_and_child_still_fails(self, mock_getuid, mock_socket):
        mock_socket.return_value.connect_ex.return_value = 1
        config = {
            "system": "aarch64-linux",
            "root": str(self.scratch / "client-root"),
            "repository": str(self.repo),
            "output": str(self.scratch / "wheel-client-deb-receipt.json"),
            "bindings": {},
            "wheels": {"theme-forge-stellar-burst": str(self.scratch / "burst.whl")},
            "prepared": {
                "source": str(self.scratch / "source"),
                "tools": str(self.scratch / "tools"),
                "scratch": str(self.scratch / "smoke"),
                "family": "wheel-client-deb",
            },
        }
        failure = ContractError(
            "LIFECYCLE_PROCESS_FAILED",
            "synthetic child failure",
            details={"phase": "wheel-install", "exit_code": 2, "stderr_sha256": "a" * 64},
        )

        with patch("rs9.hosted_wheel_clients.verify_offline_venv_lifecycle", side_effect=failure):
            with self.assertRaises(ContractError):
                child(config)

        diagnostic_path = self.scratch / "diagnostics/wheel-client-deb-lifecycle-diagnostic.json"
        diagnostic = json.loads(diagnostic_path.read_bytes())
        self.assertEqual(diagnostic["details"]["phase"], "wheel-install")
        self.assertEqual(diagnostic["details"]["failure_category"], "child-exception")
        self.assertEqual(diagnostic["details"]["exit_code"], 2)
        self.assertNotIn("failed_receipt", diagnostic["details"])
        self.assertFalse((self.scratch / "wheel-client-deb-receipt.json").exists())


if __name__ == "__main__":
    unittest.main()
