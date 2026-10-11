"""Run-17 entry point keeps the existing external-attestation boundary."""
import contextlib
import importlib.util
import io
from pathlib import Path
import subprocess
import sys
import unittest
from unittest.mock import patch

SCRIPT = Path(__file__).resolve().parents[1] / "operators/live1/run-hosted17.py"


def load_operator():
    spec = importlib.util.spec_from_file_location("rs9_run_hosted17", SCRIPT)
    operator = importlib.util.module_from_spec(spec)
    with patch.object(sys, "path", sys.path.copy()):
        spec.loader.exec_module(operator)
    return operator


class Run17Tests(unittest.TestCase):
    def test_import_does_not_start_runtime_or_origin_requests(self):
        with patch("subprocess.Popen") as spawn:
            operator = load_operator()
        spawn.assert_not_called()
        self.assertIn("run 17", operator.DEFAULT_COMMIT_MESSAGE)

    def test_exact_arguments_reach_shared_attended_operator(self):
        operator = load_operator()
        args = ["--reviewed-parent", "a" * 40, "--reviewed-tree", "b" * 40,
                "--manifest-sha256", "c" * 64, "--manager-attestation", "acceptance.json",
                "--manager-attestation-sha256", "d" * 64, "--output", "empty-packet"]
        with patch.object(operator.shared, "main", return_value=2) as shared:
            self.assertEqual(operator.main(args), 2)
        shared.assert_called_once_with(args, root=operator.ROOT, run_label="run17",
                                       commit_message=operator.DEFAULT_COMMIT_MESSAGE)

    def test_unaccepted_call_never_invokes_backend(self):
        operator = load_operator()
        with patch.object(operator.shared.subprocess, "run") as child, \
                contextlib.redirect_stdout(io.StringIO()) as output:
            self.assertEqual(operator.main([]), 2)
        child.assert_not_called()
        self.assertEqual([line.split("=")[0] for line in output.getvalue().splitlines()],
                         ["LOG", "RC", "MANAGER_PACKET", "UPLOAD"])
