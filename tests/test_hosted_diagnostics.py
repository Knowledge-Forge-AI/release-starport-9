"""Hosted diagnostics retain stable identifiers and digests, never raw commands."""
from pathlib import Path
import subprocess
import unittest
from unittest.mock import patch

from rs9.build_native import SubprocessRunner
from rs9.errors import ContractError, safe_details


class SafeDiagnosticTests(unittest.TestCase):
    def test_identity_shapes_and_exit_bounds(self):
        values = {"stage": "rpm", "product": "theme-forge-stellar-burst", "substage": "package-build",
                  "frame": "rs9/hosted_packaging.py:96:execute", "expected_digest": "sha256:" + "a" * 64,
                  "exit_code": -9, "stderr_sha256": "b" * 64, "exception_type": "TypeError"}
        self.assertEqual(safe_details(values), values)
        for bad in (True, 256, -129, "2"):
            self.assertNotIn("exit_code", safe_details({"exit_code": bad}))
        self.assertNotIn("stderr_sha256", safe_details({"stderr_sha256": "raw-error"}))

    def test_private_paths_and_untrusted_exception_names_are_dropped(self):
        self.assertNotIn("frame", safe_details({"frame": str(Path.cwd()) + "/private.py:1:run"}))
        self.assertNotIn("exception_type", safe_details({"exception_type": "TypeError secret=value"}))
        self.assertNotIn("command_line", safe_details({"command_line": "private command"}))

    def test_timeout_is_a_narrow_hashed_tool_failure(self):
        runner = SubprocessRunner(timeout=1800)
        with patch.object(runner, "which", return_value="/usr/bin/docker"), \
             patch("rs9.build_native.subprocess.run", side_effect=subprocess.TimeoutExpired(
                 ["docker", "private-argument"], 1800, output=b"private stdout", stderr=b"private stderr")) as run:
            with self.assertRaises(ContractError) as caught:
                runner.run(["docker", "private-argument"])
        self.assertEqual(caught.exception.code, "TOOL_TIMEOUT")
        self.assertEqual(caught.exception.details["tool"], "docker")
        self.assertEqual(run.call_args.kwargs["timeout"], 1800)
        self.assertNotIn("private", str(caught.exception.details))
        self.assertEqual(len(caught.exception.details["stderr_sha256"]), 64)

    def test_nix_workflow_keeps_diagnostics_after_installer_failure(self):
        workflow = (Path(__file__).resolve().parents[1] / ".github/workflows/rs9-candidate-tests.yml").read_text()
        for step in ("Enable installed Nix", "Execute non-production nix lane"):
            block = workflow.split("- name: " + step, 1)[1].split("- uses:", 1)[0].split("- name:", 1)[0]
            self.assertIn("if: ${{ !cancelled() }}", block)

    def test_sidecar_verifier_diagnostic_shapes_and_phase_bounds(self):
        for raw_phase in ("unavailable", "unknown", "import", "verify", "output", "execution"):
            values = {"phase": raw_phase, "reason_token": "unclassified-released-verifier-error",
                      "exit_code": 2, "stdout_sha256": "0" * 64, "stderr_sha256": "1" * 64}
            self.assertEqual(safe_details(values), values)

        # Untrusted private paths and credentials are dropped
        self.assertNotIn("phase", safe_details({"phase": str(Path.cwd()) + "/node"}))
        self.assertNotIn("reason_token", safe_details({"reason_token": "ghp_" + "A" * 36}))
