"""Launch-boundary causality, exact original argv, and measured failure behavior."""
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from rs9.nix_proot import GuestRuntime, Run, observe_native, prepare_layout
from rs9.nix_proot_launch import classify_failure, measure_proot_latency, run_launch_chain
from tests.test_nix_proot import closure_for, make_facts


class LaunchDiagnostics(unittest.TestCase):
    def test_userns_precedes_enoent_and_cwd_warning_is_noncausal(self):
        text = b"proot warning: can't chdir('/host/work'): No such file or directory\nbwrap: creating new namespace: Operation not permitted\n"
        result = classify_failure(Run(1, b"", text, 0.4, None))
        self.assertEqual(result["reason"], "userns-denied")
        self.assertEqual(result["warnings"], ["proot-cwd-fallback"])
        result = classify_failure(Run(7, b"", text.split(b"\n")[0], 0.4, None))
        self.assertEqual(result["reason"], "proot-launch-failed")
        self.assertEqual(result["path_class"], "none")

    def test_specific_helper_and_public_guest_path_are_retained(self):
        text = b"xvfb-run: line 83: getopt: command not found\n"
        result = classify_failure(Run(127, b"", text, 0.2, None), tool_hint="python")
        self.assertEqual((result["tool"], result["role"], result["error_class"]),
                         ("getopt", "argument-parser", "command-not-found"))
        result = classify_failure(Run(1, b"", b"dbus-daemon: cannot open /etc/dbus-1/session.conf: No such file or directory", 0.1, None))
        self.assertEqual(result["path"], "/etc/dbus-1/session.conf")
        self.assertEqual(result["path_class"], "guest-system")

    def test_host_bind_and_unknown_paths_are_only_classes_and_hashes(self):
        for path in ("/bound/work/config", "/unclassified/config"):
            result = classify_failure(Run(1, b"", (path + ": No such file or directory").encode(), 0.1, None),
                                      host_binds=("/bound/work",))
            self.assertNotIn("path", result)
            self.assertEqual(result["path_sha256"], hashlib.sha256(path.encode()).hexdigest())

    def test_only_negative_wait_status_reports_signal_and_127_does_not_invent_a_filename(self):
        for rc, sig in ((255, None), (143, None), (-15, 15), (127, None)):
            result = classify_failure(Run(rc, b"out", b"", 0.2, None))
            self.assertEqual(result["signal"], sig)
            self.assertEqual(result["raw_returncode"], rc)
            self.assertEqual(result["stdout_length"], 3)
            self.assertNotIn("path", result)

    def test_tool_hints_are_distinct_from_stderr_evidence(self):
        result = classify_failure(Run(127, b"", b"No such file or directory", 0.1, None),
                                  tool_hint="xvfb-run", role_hint="display")
        self.assertEqual((result["tool"], result["tool_source"]), ("xvfb-run", "hint"))
        result = classify_failure(Run(127, b"", b"getopt: command not found", 0.1, None),
                                  tool_hint="xvfb-run")
        self.assertEqual((result["tool"], result["tool_source"]), ("getopt", "stderr"))

    def test_generic_display_failure_names_only_the_outer_tool_hint(self):
        with tempfile.TemporaryDirectory() as temp:
            rt = self.runtime(Path(temp), lambda argv, **kw: subprocess.CompletedProcess(
                argv, 127, b"", b"No such file or directory"))
            result = observe_native(rt, "/released/main", label="main", expected=[], root_is_elf=True, display=True)
            cause = result["outer_failure"]
            self.assertEqual((cause["tool"], cause["role"], cause["tool_source"]),
                             ("xvfb-run", "display", "hint"))

    def test_display_error_streams_are_separate_per_stage(self):
        with tempfile.TemporaryDirectory() as temp:
            rt = self.runtime(Path(temp), lambda argv, **kw: subprocess.CompletedProcess(argv, 0, b"", b""))
            paths = []
            def run(probe, command, **kwargs):
                if probe in {"launch-chain-display-only", "launch-chain-combined-pinned-python"}:
                    paths.append(command[command.index("-e") + 1])
                return Run(0, b"", b"", 0.01, None)
            rt.run = run
            with patch("rs9.nix_proot_launch.guest_audit", return_value={"files": [{"error_file_option": True}]}):
                run_launch_chain(rt)
            self.assertEqual(len(paths), 2)
            self.assertEqual(len(set(paths)), 2)

    def test_successful_latency_receipts_have_no_failure_reason(self):
        with tempfile.TemporaryDirectory() as temp:
            rt = self.runtime(Path(temp), lambda argv, **kw: subprocess.CompletedProcess(argv, 0, b"", b""))
            with patch("rs9.nix_proot_launch.platform.system", return_value="Linux"), \
                    patch("rs9.nix_proot_wait.diagnostic_guest_run", return_value=(
                        Run(0, b"", b"", 0.1, None), {"compatible_status": True})):
                result = measure_proot_latency(rt, sample_count=1)
            for arm in result["arms"].values():
                self.assertNotIn("reason", arm["receipts"][0])
                self.assertEqual(arm["receipts"][0]["error_class"], "none")

    def runtime(self, base, runner):
        facts = make_facts()
        return GuestRuntime(facts, prepare_layout(base / "guest", base / "cache"), closure_for(facts), runner=runner)

    def test_failed_outer_observer_retains_streams_and_safe_completion_counts(self):
        with tempfile.TemporaryDirectory() as temp:
            partial = json.dumps({"started": True, "processes": [{"raw_path": "private-data"}],
                                  "root_pid": 42, "early_exit_code": 7}).encode()
            def runner(argv, **kwargs):
                return subprocess.CompletedProcess(argv, 127, partial, b"getopt: command not found")
            rt = self.runtime(Path(temp), runner)
            result = observe_native(rt, "/released/main", label="main", expected=[], root_is_elf=True, display=True)
            self.assertEqual(result["status"], "unobserved")
            self.assertEqual(result["exit_code"], 127)
            self.assertEqual(result["outer_failure"]["tool"], "getopt")
            self.assertEqual(result["process_count"], 1)
            self.assertNotIn("processes", result)
            self.assertNotIn("private-data", json.dumps(result))
            self.assertEqual(result["stdout_sha256"], hashlib.sha256(partial).hexdigest())

    def test_launch_roles_preserve_original_main_and_smoke_prefix_and_cwd(self):
        with tempfile.TemporaryDirectory() as temp:
            calls = []
            def runner(argv, **kwargs):
                calls.append(argv)
                return subprocess.CompletedProcess(argv, 127 if "dbus-run-session" in argv else 0, b"", b"getopt: command not found")
            rt = self.runtime(Path(temp), runner)
            result = run_launch_chain(rt)
            baseline_main = calls[-2]
            baseline_smoke = calls[-1]
            i = baseline_main.index("xvfb-run")
            self.assertEqual(baseline_main[i:i + 4], ["xvfb-run", "-a", "dbus-run-session", "--"])
            self.assertIn("-w", baseline_main)
            self.assertEqual(baseline_smoke[-7:-3], ["xvfb-run", "-a", "dbus-run-session", "--"])
            self.assertEqual(baseline_smoke[-3], "node")
            self.assertNotIn("-w", baseline_smoke)
            self.assertEqual(len(result["stages"]), 5)
            self.assertFalse(result["qualification_authority"])

    def test_latency_same_prefix_and_failed_samples_do_not_become_success(self):
        with tempfile.TemporaryDirectory() as temp:
            calls = []
            def runner(argv, **kwargs):
                calls.append(argv)
                return subprocess.CompletedProcess(argv, 127, b"", b"not found")
            rt = self.runtime(Path(temp), runner)
            rt.prefix = ["offline-test-prefix", "--"]
            with patch("rs9.nix_proot_launch.platform.system", return_value="Linux"), \
                    patch("rs9.nix_proot_wait.diagnostic_guest_run", return_value=(Run(255, b"", b"", 0.1, None), {"compatible_status": False})):
                result = measure_proot_latency(rt)
            self.assertEqual(len(calls), 10)
            self.assertTrue(all(c[:2] == rt.prefix for c in calls))
            for arm in result["arms"].values():
                self.assertEqual(arm["status"], "fail")
                self.assertEqual(arm["successful_samples"], 0)
                self.assertIsNone(arm["median_seconds"])
