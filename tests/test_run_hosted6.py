"""Bounded preflight and output format tests for run-hosted5."""
import contextlib
import hashlib
import importlib.util
import io
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from rs9.candidate_inventory import MANIFEST
from rs9.errors import ContractError

SCRIPT_PATH = Path(__file__).resolve().parents[1] / "operators/live1/run-hosted6.py"
spec = importlib.util.spec_from_file_location("rs9_run_hosted6", SCRIPT_PATH)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class RunHosted6PreflightTests(unittest.TestCase):
    def test_attended_run6_requires_run5_parent(self):
        self.assertEqual(module.PARENT, "a09fcc21c68c292cd526033bb2ecebccf3167b90")
        source = SCRIPT_PATH.read_text()
        self.assertNotIn("workflow_dispatch", source)
        self.assertNotIn("rerun", source.replace("No automatic rerun", "").replace("no automatic rerun", ""))

    def test_argparse_failures_emit_exact_format_without_traceback(self):
        for bad_argv in ([], ["--output", "/tmp/out"], ["--reviewed-tree", "a" * 40], ["--unknown-flag"]):
            with self.subTest(argv=bad_argv):
                stdout = io.StringIO()
                with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(io.StringIO()):
                    code = module.main(bad_argv)
                self.assertEqual(code, 2)
                lines = stdout.getvalue().splitlines()
                self.assertEqual([line.split("=", 1)[0] for line in lines], ["LOG", "RC", "MANAGER_PACKET"])
                self.assertNotIn("Traceback", stdout.getvalue())

    def test_log_collision_preserves_existing_log_and_emits_exact_format(self):
        with tempfile.TemporaryDirectory() as tmp:
            work = Path(tmp).resolve()
            out = work / "outbox_dir"
            out.mkdir()
            log = out.with_name(out.name + ".operator.log")
            log.write_bytes(b"preserved-log-content")
            (out / "manager-packet.json").write_bytes(b"stale-packet")

            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(io.StringIO()):
                code = module.main(["--reviewed-tree", "a" * 40, "--manifest-sha256", "0" * 64, "--output", str(out)])
            self.assertEqual(code, 2)
            self.assertEqual(log.read_bytes(), b"preserved-log-content")
            lines = stdout.getvalue().splitlines()
            self.assertEqual([line.split("=", 1)[0] for line in lines], ["LOG", "RC", "MANAGER_PACKET"])
            self.assertEqual(lines[-1], "MANAGER_PACKET=unavailable")
            self.assertEqual((out / "manager-packet.json").read_bytes(), b"stale-packet")

    def test_output_dir_failure_emits_exact_format(self):
        with tempfile.TemporaryDirectory() as tmp:
            work = Path(tmp).resolve()
            out = work / "non_empty_dir"
            out.mkdir()
            (out / "file.txt").write_bytes(b"data")

            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(io.StringIO()):
                code = module.main(["--reviewed-tree", "a" * 40, "--manifest-sha256", "0" * 64, "--output", str(out)])
            self.assertEqual(code, 2)
            lines = stdout.getvalue().splitlines()
            self.assertEqual([line.split("=", 1)[0] for line in lines], ["LOG", "RC", "MANAGER_PACKET"])
            self.assertEqual(lines[-1], "MANAGER_PACKET=unavailable")
            self.assertFalse(out.with_name(out.name + ".operator.log").exists())

    def test_child_process_sets_internal_root_src_pythonpath(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            (root / MANIFEST).parent.mkdir(parents=True)
            raw = b"{}"
            (root / MANIFEST).write_bytes(raw)
            out = root / "out"
            out.mkdir()
            stdout = io.StringIO()
            with patch.object(module, "ROOT", root), \
                 patch.object(module, "dependencies", return_value=(MANIFEST, lambda *a, **k: "a" * 40, lambda p: out, ContractError)), \
                 patch.object(module.subprocess, "check_output", side_effect=[b"main", module.PARENT.encode(), module.PARENT.encode()]), \
                 patch.object(module.subprocess, "run", return_value=subprocess.CompletedProcess([], 0)) as run, \
                 contextlib.redirect_stdout(stdout):
                code = module.main(["--reviewed-tree", "a" * 40, "--manifest-sha256", hashlib.sha256(raw).hexdigest(), "--output", str(out)])
            self.assertEqual(code, 0)
            child_env = run.call_args.kwargs.get("env", {})
            self.assertIn("PYTHONPATH", child_env)
            self.assertIn(str(root / "src"), child_env["PYTHONPATH"])
            self.assertEqual(child_env["PYTHONDONTWRITEBYTECODE"], "1")
            self.assertEqual(stdout.getvalue().splitlines()[-1], "MANAGER_PACKET=unavailable")

    def test_collision_stops_before_imports_or_child_execution(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp).resolve() / "out"
            out.mkdir()
            out.with_name("out.operator.log").write_bytes(b"existing")
            with patch.object(module, "dependencies") as imports, patch.object(module.subprocess, "run") as child, \
                 contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(module.main(["--reviewed-tree", "a" * 40, "--manifest-sha256", "b" * 64, "--output", str(out)]), 2)
            imports.assert_not_called()
            child.assert_not_called()

    def test_import_failure_is_bounded(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp).resolve() / "out"
            out.mkdir()
            stdout, stderr = io.StringIO(), io.StringIO()
            with patch.object(module, "dependencies", side_effect=ImportError("synthetic-private-error")), \
                 contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                self.assertEqual(module.main(["--reviewed-tree", "a" * 40, "--manifest-sha256", "b" * 64, "--output", str(out)]), 2)
            self.assertEqual(len(stdout.getvalue().splitlines()), 3)
            self.assertEqual(stderr.getvalue(), "")
            self.assertFalse(out.with_name("out.operator.log").exists())
            self.assertEqual(stdout.getvalue().splitlines()[-1], "MANAGER_PACKET=unavailable")

    def test_only_child_created_physical_packet_is_reported(self):
        for symlink in (False, True):
            with self.subTest(symlink=symlink), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp).resolve()
                (root / MANIFEST).parent.mkdir(parents=True)
                raw = b"{}"
                (root / MANIFEST).write_bytes(raw)
                out = root / "out"
                out.mkdir()
                packet = out / "manager-packet.json"

                def child(*args, **kwargs):
                    if symlink:
                        target = root / "stale-packet.json"
                        target.write_bytes(b"{}")
                        packet.symlink_to(target)
                    else:
                        packet.write_bytes(b"{}")
                    return subprocess.CompletedProcess([], 0)

                stdout = io.StringIO()
                with patch.object(module, "ROOT", root), \
                     patch.object(module, "dependencies", return_value=(MANIFEST, lambda *a, **k: "a" * 40, lambda p: out, ContractError)), \
                     patch.object(module.subprocess, "check_output", side_effect=[b"main", module.PARENT.encode(), module.PARENT.encode()]), \
                     patch.object(module.subprocess, "run", side_effect=child), contextlib.redirect_stdout(stdout):
                    code = module.main(["--reviewed-tree", "a" * 40, "--manifest-sha256", hashlib.sha256(raw).hexdigest(), "--output", str(out)])
                self.assertEqual(code, 0)
                expected = "unavailable" if symlink else str(packet)
                self.assertEqual(stdout.getvalue().splitlines()[-1], "MANAGER_PACKET=" + expected)

    def test_help_documents_empty_output_dir_and_no_automatic_rerun(self):
        parser = module.BoundedArgumentParser(description=module.__doc__)
        parser.add_argument("--output", type=Path, required=True,
                            help="Existing empty physical output directory for manager packet; no automatic rerun.")
        help_text = parser.format_help()
        self.assertIn("empty", help_text.lower())
        self.assertIn("no automatic rerun", help_text.lower())
