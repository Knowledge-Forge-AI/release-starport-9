"""Attended run-14 handoff: real disposable Git, synthetic hosted transport."""
import contextlib
import importlib.util
import io
import json
from pathlib import Path
import subprocess
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from rs9 import adopt_candidate as backend
import tests.test_adoption_scratch as scratch_tests

SCRIPT = Path(__file__).resolve().parents[1] / "operators/live1/run-hosted14.py"
spec = importlib.util.spec_from_file_location("rs9_run_hosted14", SCRIPT)
operator = importlib.util.module_from_spec(spec)
spec.loader.exec_module(operator)


class Run14Tests(unittest.TestCase):
    def args(self, fixture):
        return ["--reviewed-parent", fixture.parent, "--reviewed-tree", fixture.tree,
                "--manifest-sha256", fixture.digest, "--output", str(fixture.output),
                "--manager-attestation", str(fixture.attestation),
                "--manager-attestation-sha256", fixture.attestation_digest]

    def test_one_normal_adoption_push_preserves_scratch_and_four_field_output(self):
        fixture = scratch_tests.AdoptionScratchTests()
        with fixture.fixture() as f:
            before = f.operational_files()
            f.stop_before_add = False
            original = backend.run
            calls = []

            def child(command, **kwargs):
                calls.append(command)
                self.assertEqual(command[2], "adopt")
                self.assertEqual(command[command.index("--commit-message") + 1], operator.DEFAULT_COMMIT_MESSAGE)
                self.assertIn("run 14", operator.DEFAULT_COMMIT_MESSAGE)
                self.assertIs(kwargs["stdout"], kwargs["stderr"])
                return subprocess.CompletedProcess(command, backend.main(command[2:]))

            packet = {"schema": "rs9.hosted-manager-packet.v1alpha1", "status": "not-qualified",
                      "run_id": 999, "production_enabled": False, "publication_authority": False,
                      "validation": {"status": "fail"}}
            stream = io.StringIO()
            with patch.object(operator, "ROOT", f.root), \
                    patch.object(operator, "subprocess", SimpleNamespace(run=child)), \
                    patch.object(sys, "path", sys.path.copy()), \
                    patch.object(backend, "run", side_effect=f.boundary(original)), \
                    patch("rs9.collect_candidate.collect", return_value=packet), \
                    contextlib.redirect_stdout(stream):
                self.assertEqual(operator.main(self.args(f)), 2)
            self.assertEqual(len(calls), 1)
            self.assertEqual([c[1] for c in f.calls].count("commit"), 1)
            self.assertEqual([c[1] for c in f.calls].count("push"), 1)
            self.assertEqual(f.git("rev-parse", "HEAD^"), f.parent)
            self.assertEqual(f.git("rev-parse", "HEAD^{tree}"), f.tree)
            fixture.assert_preserved(f, before)
            metadata = json.loads(f.output.with_name(f.output.name + ".operator.json").read_bytes())
            self.assertEqual(metadata["schema"], "rs9.run14-operator.v1")
            self.assertFalse(metadata["production_enabled"])
            self.assertFalse(metadata["publication_authority"])
            fields = dict(line.split("=", 1) for line in stream.getvalue().splitlines())
            self.assertEqual(list(fields), ["LOG", "RC", "MANAGER_PACKET", "UPLOAD"])
            self.assertEqual(Path(fields["LOG"]).parent, f.output.parent)
            self.assertTrue(Path(fields["UPLOAD"]).is_file())

    def test_collect_only_retains_original_not_before_and_index(self):
        fixture = scratch_tests.AdoptionScratchTests()
        with fixture.fixture() as f:
            f.git("add", "--", *f.manifest["changed_paths"])
            f.git("commit", "-m", "Disposable collection fixture")
            commit = f.git("rev-parse", "HEAD")
            before = scratch_tests.index_state(f.root)
            calls = []

            def child(command, **kwargs):
                calls.append(command)
                return subprocess.CompletedProcess(command, 0)

            with patch.object(operator, "ROOT", f.root), \
                    patch.object(operator, "subprocess", SimpleNamespace(run=child, check_output=subprocess.check_output)), \
                    patch("rs9.collect_candidate.Path.home", return_value=f.base / "home"), \
                    contextlib.redirect_stdout(io.StringIO()):
                rc = operator.main(self.args(f) + ["--collect-only", "--commit", commit, "--run-id", "123",
                                                  "--not-before", "2026-10-10T12:00:00Z"])
            self.assertEqual(rc, 0)
            self.assertEqual(len(calls), 1)
            self.assertEqual(calls[0][2], "collect")
            self.assertEqual(calls[0][calls[0].index("--not-before") + 1], "2026-10-10T12:00:00Z")
            self.assertEqual(scratch_tests.index_state(f.root), before)
            self.assertEqual(list(f.output.iterdir()), [])

    def test_unaccepted_and_incomplete_continuations_do_not_invoke_backend(self):
        for args in ([], ["--collect-only"], ["--run-id", "123"]):
            with self.subTest(args=args), patch.object(operator.subprocess, "run") as child, \
                    contextlib.redirect_stdout(io.StringIO()) as stream:
                self.assertEqual(operator.main(args), 2)
                child.assert_not_called()
                self.assertEqual([line.split("=")[0] for line in stream.getvalue().splitlines()],
                                 ["LOG", "RC", "MANAGER_PACKET", "UPLOAD"])

    def test_packet_must_already_exist_empty_and_physical(self):
        fixture = scratch_tests.AdoptionScratchTests()
        for kind in ("missing", "nonempty", "symlink"):
            with self.subTest(kind=kind), fixture.fixture() as f:
                if kind == "missing":
                    f.output.rmdir()
                elif kind == "nonempty":
                    (f.output / "retained.json").write_text("{}")
                else:
                    f.output.rmdir()
                    f.output.symlink_to(f.root, target_is_directory=True)
                with patch.object(operator, "ROOT", f.root), patch.object(operator.subprocess, "run") as child, \
                        patch("rs9.collect_candidate.Path.home", return_value=f.base / "home"), \
                        contextlib.redirect_stdout(io.StringIO()):
                    self.assertEqual(operator.main(self.args(f)), 2)
                child.assert_not_called()
