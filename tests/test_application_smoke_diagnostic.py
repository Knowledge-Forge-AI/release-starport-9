"""Adverse and boundary tests for application smoke causal diagnostics.

Unit test fixtures are strictly synthetic representations for qualification;
no native hardware claims are made.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import stat
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import MagicMock, patch

from rs9.application_smoke_diagnostic import (
    CAUSE_CATEGORIES,
    SAFE_LOG_CATEGORIES,
    classify_smoke_cause,
    execute_application_smoke,
    extract_log_categories,
    read_and_validate_receipt,
    run_replay,
    sanitize_receipt_summary,
    validate_problem_codes,
    _bounded_run,
)
from rs9.errors import ContractError, safe_details
from rs9.release_core import digest


class ApplicationSmokeDiagnosticAdverseTests(unittest.TestCase):
    """Adverse tests verifying closed cause categories, safe logs, no raw output,

    sanitized problem codes, and exact single replay behavior.
    """

    def setUp(self):
        self.synthetic_tmp = tempfile.TemporaryDirectory()
        self.work = Path(self.synthetic_tmp.name).resolve()
        self.scratch = self.work / "scratch"
        self.scratch.mkdir()
        self.tools = self.work / "tools"
        self.tools.mkdir()
        (self.tools / "native-rc-smoke.mjs").write_text("// synthetic smoke harness fixture\n")

        self.prepared = {
            "scratch": self.scratch,
            "tools": self.tools,
            "source": self.work / "source",
            "checkout": self.work / "source",
            "records": [],
        }
        (self.work / "source").mkdir()
        self.launch_root = self.work / "launch_root"
        self.launch_root.mkdir()

    def tearDown(self):
        self.synthetic_tmp.cleanup()

    def test_adverse_nonzero_exit_triggers_single_replay_and_diagnostic(self):
        """Synthetic nonzero exit failure triggers exactly one replay, classifies cause,

        records failure artifact, and keeps gate fail.
        """
        calls = []

        def fake_run(cmd, **kwargs):
            calls.append(list(cmd))
            return SimpleNamespace(
                returncode=127,
                stdout=b"",
                stderr=b"dbus-run-session: /etc/dbus-1/session.conf: No such file or directory\n",
            )

        with patch("subprocess.run", side_effect=fake_run), \
             patch("rs9.application_smoke_diagnostic._bounded_run", side_effect=fake_run):
            with self.assertRaises(ContractError) as caught:
                execute_application_smoke(
                    prepared=self.prepared,
                    system="x86_64-linux",
                    launch_root=self.launch_root,
                    diagnostic_extras=True,
                )

        self.assertEqual(caught.exception.code, "APPLICATION_SMOKE")
        details = caught.exception.details
        self.assertEqual(details["scenario"], "C")
        self.assertEqual(details["cause"], "dbus-session-failure")
        self.assertEqual(details["exit_code"], 127)
        self.assertIn("diagnostic_sha256", details)

        # Verify exactly 2 calls: initial run of C, and ONE replay of C.
        # "C-signal" must NOT be run!
        self.assertEqual(len(calls), 2)
        self.assertIn("--scenario", calls[0])
        self.assertEqual(calls[0][calls[0].index("--scenario") + 1], "C")
        self.assertIn("--scenario", calls[1])
        self.assertEqual(calls[1][calls[1].index("--scenario") + 1], "C")

        # Verify diagnostic artifact was written to scratch.parent / "diagnostics"
        diag_path = self.work / "diagnostics/application-smoke-diagnostic.json"
        self.assertTrue(diag_path.is_file())
        diag = json.loads(diag_path.read_text())
        self.assertEqual(diag["schema"], "rs9.application-smoke-diagnostic.v1alpha1")
        self.assertEqual(diag["cause"], "dbus-session-failure")
        self.assertEqual(diag["scenarios_not_run"], ["C-signal"])
        self.assertEqual(diag["replay"]["status"], "replay-reproduced")
        self.assertEqual(diag["replay"]["cause"], "dbus-session-failure")
        self.assertIn("dbus-session-conf-missing", diag["initial_run"]["log_categories"])

        # Never-retain-raw-output policy: no raw stderr string in diagnostic
        self.assertNotIn("session.conf: No such file", json.dumps(diag))
        self.assertNotIn(str(self.work), json.dumps(diag))

    def test_adverse_timeout_expired_records_timeout_diagnostic(self):
        """Synthetic timeout triggers single replay, records timeout cause, gate stays fail."""
        calls = []

        def fake_run(cmd, **kwargs):
            calls.append(list(cmd))
            raise subprocess.TimeoutExpired(cmd=cmd, timeout=240, output=b"", stderr=b"hung")

        with patch("subprocess.run", side_effect=fake_run), \
             patch("rs9.application_smoke_diagnostic._bounded_run", side_effect=fake_run):
            with self.assertRaises(ContractError) as caught:
                execute_application_smoke(
                    prepared=self.prepared,
                    system="x86_64-linux",
                    launch_root=self.launch_root,
                    diagnostic_extras=True,
                )

        self.assertEqual(caught.exception.code, "APPLICATION_SMOKE")
        self.assertEqual(caught.exception.details["reason_token"], "process-timeout")
        self.assertEqual(caught.exception.details["cause"], "process-timeout")
        self.assertEqual(len(calls), 2)  # 1 initial + 1 replay

        diag_path = self.work / "diagnostics/application-smoke-diagnostic.json"
        diag = json.loads(diag_path.read_text())
        self.assertEqual(diag["cause"], "process-timeout")
        self.assertEqual(diag["replay"]["status"], "replay-reproduced")

    def test_adverse_missing_display_and_socket(self):
        """Synthetic missing Xvfb display and dbus socket are categorized without raw text."""
        stderr_xvfb = b"Xvfb failed to start, cannot open display :99\n"
        log_cats = extract_log_categories(b"", stderr_xvfb, exit_code=1)
        self.assertIn("xvfb-display-error", log_cats)
        cause = classify_smoke_cause(
            exit_code=1,
            timed_out=False,
            receipt_error=None,
            log_categories=log_cats,
        )
        self.assertEqual(cause, "xvfb-failure")
        self.assertIn(cause, CAUSE_CATEGORIES)

        stderr_dbus = b"dbus-daemon[123]: Failed to start message bus: Failed to bind socket\n"
        log_cats_dbus = extract_log_categories(b"", stderr_dbus, exit_code=127)
        self.assertIn("dbus-daemon-error", log_cats_dbus)
        cause_dbus = classify_smoke_cause(
            exit_code=127,
            timed_out=False,
            receipt_error=None,
            log_categories=log_cats_dbus,
        )
        self.assertEqual(cause_dbus, "dbus-session-failure")

    def test_adverse_corrupt_streams_handled_safely(self):
        """Corrupt non-UTF-8 binary stream bytes compute lengths and digests cleanly."""
        corrupt_bytes = b"\x80\xff\xfe\x00\xaa\xbb\xcc\xdd"
        log_cats = extract_log_categories(corrupt_bytes, corrupt_bytes, exit_code=1)
        self.assertIsInstance(log_cats, list)

        cmd_details = {
            "exit_code": 1,
            "stdout_sha256": digest(corrupt_bytes),
            "stderr_sha256": digest(corrupt_bytes),
        }
        self.assertEqual(len(cmd_details["stdout_sha256"]), 64)

    def test_adverse_corrupt_and_malformed_receipts_parse_into_contract_error(self):
        """Corrupt or malformed receipts parse into ContractError without uncaught exceptions."""
        evidence_dir = self.scratch / "evidence"
        evidence_dir.mkdir(parents=True, exist_ok=True)
        path = evidence_dir / "linux-x64-C.run.json"

        # 1. Corrupt JSON syntax
        path.write_bytes(b"{not valid json")
        rec, rec_err, probs = read_and_validate_receipt(path, {})
        self.assertIsNone(rec)
        self.assertEqual(rec_err, "receipt-corrupt")

        # 2. JSON is not a dict
        path.write_bytes(b"\"just a string\"")
        rec, rec_err, probs = read_and_validate_receipt(path, {})
        self.assertEqual(rec_err, "receipt-malformed")

        # 3. Executable sha256 missing or invalid
        path.write_text(json.dumps({"status": "pass", "executable": {"sha256": "short"}}))
        rec, rec_err, probs = read_and_validate_receipt(path, {})
        self.assertEqual(rec_err, "receipt-malformed")

        # 4. Valid receipt with failure status
        path.write_text(json.dumps({
            "status": "fail",
            "executable": {"sha256": "a" * 64},
            "problems": ["exit-code-mismatch"],
        }))
        rec, rec_err, probs = read_and_validate_receipt(path, {})
        self.assertIsNotNone(rec)
        self.assertEqual(rec_err, "receipt-failed")
        self.assertEqual(probs, ["exit-code-mismatch"])

    def test_adverse_symlink_and_oversize_receipt_rejected(self):
        """Symlinks and oversize files are rejected by nofollow/bounded checks."""
        evidence_dir = self.scratch / "evidence"
        evidence_dir.mkdir(parents=True, exist_ok=True)
        path = evidence_dir / "linux-x64-C.run.json"

        # Symlink
        target = evidence_dir / "real.json"
        target.write_bytes(b"{}")
        if path.exists():
            path.unlink()
        path.symlink_to(target)

        rec, rec_err, probs = read_and_validate_receipt(path, {})
        self.assertIsNone(rec)
        self.assertEqual(rec_err, "receipt-invalid")

        # Oversize
        path.unlink()
        path.write_bytes(b"A" * (1024 * 1024 + 10))
        rec, rec_err, probs = read_and_validate_receipt(path, {})
        self.assertIsNone(rec)
        self.assertEqual(rec_err, "receipt-oversize")

    def test_adverse_fifo_receipt_rejected(self):
        """FIFO/named pipe receipts are rejected as non-regular files."""
        evidence_dir = self.scratch / "evidence"
        evidence_dir.mkdir(parents=True, exist_ok=True)
        path = evidence_dir / "linux-x64-C.run.json"
        if path.exists():
            path.unlink()

        try:
            os.mkfifo(path)
        except (AttributeError, OSError):
            self.skipTest("os.mkfifo not supported on this platform/filesystem")

        rec, rec_err, probs = read_and_validate_receipt(path, {})
        self.assertIsNone(rec)
        self.assertEqual(rec_err, "receipt-invalid")
        path.unlink()

    def test_adverse_credential_and_host_path_withholding(self):
        """Problem codes containing credentials or host paths are withheld."""
        dirty_problems = [
            "valid-problem-code",
            "ghp_" + "1" * 36,  # GitHub token pattern
            "/" + "Users" + "/fixture/secrets/token",                 # Host path
            "C:\\Windows\\system32",                      # Windows path
            "token=secret-token",                         # Credential word
            "problem-with-dots...invalid",                # Invalid chars
            "another_valid_one",
        ]
        validated = validate_problem_codes(dirty_problems)
        self.assertIn("valid-problem-code", validated)
        self.assertIn("another_valid_one", validated)
        self.assertNotIn("ghp_" + "1" * 36, validated)
        self.assertNotIn("/" + "Users" + "/fixture/secrets/token", validated)
        self.assertNotIn("C:\\Windows\\system32", validated)

    def test_adverse_transient_replay_pass_gate_stays_fail(self):
        """If initial run fails but replay passes, gate stays fail always with replay-passed label."""
        evidence_dir = self.scratch / "evidence"
        evidence_dir.mkdir(parents=True, exist_ok=True)
        replay_dir = self.scratch / "evidence-replay-C"

        call_count = 0

        def fake_run(cmd, **kwargs):
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                # Initial run fails with exit 1
                return SimpleNamespace(returncode=1, stdout=b"", stderr=b"temporary flake\n")
            else:
                # Replay succeeds: writes valid passing receipt
                replay_dir.mkdir(parents=True, exist_ok=True)
                receipt_file = replay_dir / "linux-x64-C.run.json"
                receipt_file.write_text(json.dumps({
                    "status": "pass",
                    "executable": {"sha256": "f" * 64},
                }))
                return SimpleNamespace(returncode=0, stdout=b"", stderr=b"")

        with patch("subprocess.run", side_effect=fake_run), \
             patch("rs9.application_smoke_diagnostic._bounded_run", side_effect=fake_run):
            with self.assertRaises(ContractError) as caught:
                execute_application_smoke(
                    prepared=self.prepared,
                    system="x86_64-linux",
                    launch_root=self.launch_root,
                    diagnostic_extras=True,
                )

        # Gate stays fail always!
        self.assertEqual(caught.exception.code, "APPLICATION_SMOKE")
        self.assertEqual(caught.exception.details["scenario"], "C")

        diag_path = self.work / "diagnostics/application-smoke-diagnostic.json"
        diag = json.loads(diag_path.read_text())
        self.assertEqual(diag["replay"]["status"], "replay-passed")
        self.assertEqual(diag["gate_status"], "fail")
        self.assertEqual(diag["status"], "fail")

    def test_other_callers_no_extras(self):
        """When diagnostic_extras is False, no replay is run and no extra diagnostic is written."""
        calls = []

        def fake_run(cmd, **kwargs):
            calls.append(list(cmd))
            return SimpleNamespace(returncode=1, stdout=b"", stderr=b"fail\n")

        with patch("subprocess.run", side_effect=fake_run):
            with self.assertRaises(ContractError) as caught:
                execute_application_smoke(
                    prepared=self.prepared,
                    system="x86_64-linux",
                    launch_root=self.launch_root,
                    diagnostic_extras=False,
                )

        self.assertEqual(caught.exception.code, "APPLICATION_SMOKE")
        # Exactly 1 call (no replay)
        self.assertEqual(len(calls), 1)
        # No extra diagnostic artifact
        diag_path = self.work / "diagnostics/application-smoke-diagnostic.json"
        self.assertFalse(diag_path.is_file())

    def test_nonzero_retains_receipt_problem_and_identity(self):
        evidence = self.scratch / "evidence"
        evidence.mkdir()
        receipt = evidence / "linux-x64-C.run.json"
        raw = json.dumps({"status": "fail", "problems": ["exit-code-mismatch"],
                          "executable": {"sha256": "a" * 64}}).encode()
        receipt.write_bytes(raw)
        with patch("subprocess.run", return_value=SimpleNamespace(returncode=1, stdout=b"reason", stderr=b"")), \
             patch("rs9.application_smoke_diagnostic._bounded_run",
                   return_value=SimpleNamespace(returncode=1, stdout=b"reason", stderr=b"")):
            with self.assertRaises(ContractError):
                execute_application_smoke(prepared=self.prepared, system="x86_64-linux",
                                          launch_root=self.launch_root, diagnostic_extras=True)
        initial = json.loads((self.work / "diagnostics/application-smoke-diagnostic.json").read_bytes())["initial_run"]
        self.assertEqual(initial["receipt"]["sha256"], digest(raw))
        self.assertEqual(initial["receipt"]["problem_count"], 1)
        self.assertEqual(initial["problem_codes"], ["exit-code-mismatch"])

    def test_timeout_retains_corrupt_receipt_and_display_log(self):
        evidence = self.scratch / "evidence"
        evidence.mkdir()
        (evidence / "linux-x64-C.run.json").write_bytes(b"not-json")

        def replay_timeout(cmd, **kwargs):
            replay_evidence = Path(cmd[cmd.index("--evidence") + 1])
            (replay_evidence / "xvfb-error.log").write_bytes(b"\xffXvfb failed to start")
            raise subprocess.TimeoutExpired(cmd, 240, output=b"partial")

        with patch("subprocess.run", side_effect=subprocess.TimeoutExpired([], 240, output=b"partial")), \
             patch("rs9.application_smoke_diagnostic._bounded_run", side_effect=replay_timeout):
            with self.assertRaises(ContractError):
                execute_application_smoke(prepared=self.prepared, system="x86_64-linux",
                                          launch_root=self.launch_root, diagnostic_extras=True)
        diagnostic = json.loads((self.work / "diagnostics/application-smoke-diagnostic.json").read_bytes())
        initial = diagnostic["initial_run"]
        self.assertEqual(initial["cause"], "process-timeout")
        self.assertEqual(initial["receipt_error"], "receipt-corrupt")
        self.assertNotIn("display_log", initial)
        self.assertIn("xvfb-display-error", diagnostic["replay"]["display_log"]["categories"])

    def test_retained_display_log_is_nofollow_and_bounded(self):
        for mode in ("symlink", "oversize", "fifo"):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as temp:
                scratch = Path(temp) / "smoke"
                scratch.mkdir()
                evidence = scratch / "evidence"
                evidence.mkdir()
                prepared = dict(self.prepared, scratch=scratch)

                def replay_with_log(cmd, **kwargs):
                    log = Path(cmd[cmd.index("--evidence") + 1]) / "xvfb-error.log"
                    if mode == "symlink":
                        target = scratch / "private"
                        target.write_text("unrelated-private-data")
                        log.symlink_to(target)
                    elif mode == "oversize":
                        log.write_bytes(b"x" * (64 * 1024 + 1))
                    else:
                        os.mkfifo(log)
                    return SimpleNamespace(returncode=1, stdout=b"", stderr=b"")

                with patch("subprocess.run", return_value=SimpleNamespace(returncode=1, stdout=b"", stderr=b"")), \
                     patch("rs9.application_smoke_diagnostic._bounded_run", side_effect=replay_with_log):
                    with self.assertRaises(ContractError):
                        execute_application_smoke(prepared=prepared, system="x86_64-linux",
                                                  launch_root=self.launch_root, diagnostic_extras=True)
                diag = json.loads((scratch.parent / "diagnostics/application-smoke-diagnostic.json").read_bytes())
                self.assertNotIn("display_log", diag["initial_run"])
                self.assertEqual(diag["replay"]["display_log"]["error"],
                                 "oversize" if mode == "oversize" else "invalid")
                self.assertNotIn("unrelated-private-data", json.dumps(diag))

    def test_replay_preserves_existing_evidence_and_does_not_execute(self):
        old = self.scratch / "evidence-replay-C"
        old.mkdir()
        sentinel = old / "retain"
        sentinel.write_bytes(b"old-evidence")
        with patch("subprocess.run", return_value=SimpleNamespace(returncode=1, stdout=b"", stderr=b"")) as original, \
             patch("rs9.application_smoke_diagnostic._bounded_run",
                   return_value=SimpleNamespace(returncode=1, stdout=b"", stderr=b"")) as run:
            with self.assertRaises(ContractError):
                execute_application_smoke(prepared=self.prepared, system="x86_64-linux",
                                          launch_root=self.launch_root, diagnostic_extras=True)
        self.assertEqual(original.call_count, 1)
        self.assertEqual(run.call_count, 0)
        self.assertEqual(sentinel.read_bytes(), b"old-evidence")
        diag = json.loads((self.work / "diagnostics/application-smoke-diagnostic.json").read_bytes())
        self.assertEqual(diag["replay"]["status"], "replay-not-run")

    def test_generic_127_and_143_do_not_invent_cause_or_signal(self):
        cause = classify_smoke_cause(exit_code=127, timed_out=False, receipt_error=None,
                                     log_categories=extract_log_categories(b"", b"", 127))
        self.assertEqual(cause, "process-nonzero")
        with patch("subprocess.run", return_value=SimpleNamespace(returncode=143, stdout=b"", stderr=b"")), \
             patch("rs9.application_smoke_diagnostic._bounded_run",
                   return_value=SimpleNamespace(returncode=143, stdout=b"", stderr=b"")):
            with self.assertRaises(ContractError):
                execute_application_smoke(prepared=self.prepared, system="x86_64-linux",
                                          launch_root=self.launch_root, diagnostic_extras=True)
        initial = json.loads((self.work / "diagnostics/application-smoke-diagnostic.json").read_bytes())["initial_run"]
        self.assertEqual(initial["exit_code"], 143)
        self.assertIsNone(initial["signal"])

    def test_default_call_preserves_existing_diagnostic(self):
        directory = self.work / "diagnostics"
        directory.mkdir()
        sentinel = directory / "application-smoke-diagnostic.json"
        sentinel.write_bytes(b"retain-existing")
        with patch("subprocess.run", return_value=SimpleNamespace(returncode=1, stdout=b"", stderr=b"")):
            with self.assertRaises(ContractError):
                execute_application_smoke(prepared=self.prepared, system="x86_64-linux",
                                          launch_root=self.launch_root)
        self.assertEqual(sentinel.read_bytes(), b"retain-existing")

    def test_detail_budget_retains_scenario_and_diagnostic_digest(self):
        with patch("subprocess.run", return_value=SimpleNamespace(returncode=1, stdout=b"", stderr=b"")), \
             patch("rs9.application_smoke_diagnostic._bounded_run",
                   return_value=SimpleNamespace(returncode=1, stdout=b"", stderr=b"")):
            with self.assertRaises(ContractError) as failure:
                execute_application_smoke(prepared=self.prepared, system="x86_64-linux",
                                          launch_root=self.launch_root, diagnostic_extras=True)
        combined = {"product": "theme-forge-nebular-fusion", "substage": "lifecycle",
                    "origin": "verify_offline_venv_lifecycle", "system": "x86_64-linux",
                    "target_triple": "x86_64-unknown-linux-gnu", "asset_platform": "x86_64-linux",
                    "wheel_tag": "py3-none-linux_x86_64", **failure.exception.details}
        public = safe_details(combined)
        self.assertLessEqual(len(combined), 16)
        self.assertIn("scenario", public)
        self.assertIn("diagnostic_sha256", public)
        self.assertNotIn("details_truncated", public)

    def test_real_capture_exit_signal_and_timeout(self):
        import signal
        import sys
        result = _bounded_run([sys.executable, "-B", "-c", "print('bounded');raise SystemExit(7)"],
                              env=None, timeout=3)
        self.assertEqual(result.returncode, 7)
        self.assertEqual(result.stdout, b"bounded\n")
        self.assertIsNone(result.capture_error)
        result = _bounded_run([sys.executable, "-B", "-c",
                               "import os,signal;os.kill(os.getpid(),signal.SIGTERM)"],
                              env=None, timeout=3)
        self.assertEqual(result.returncode, -signal.SIGTERM)
        result = _bounded_run([sys.executable, "-B", "-c", "import time;time.sleep(30)"],
                              env=None, timeout=0.1)
        self.assertEqual(result.capture_error, "process-timeout")

    def test_original_x86_attempt_keeps_legacy_argv_and_process_path(self):
        with patch("subprocess.run", return_value=SimpleNamespace(
                returncode=1, stdout=b"original", stderr=b"")) as original, \
             patch("rs9.application_smoke_diagnostic._bounded_run", return_value=SimpleNamespace(
                returncode=1, stdout=b"replay", stderr=b"")) as replay:
            with self.assertRaises(ContractError):
                execute_application_smoke(prepared=self.prepared, system="x86_64-linux",
                                          launch_root=self.launch_root, diagnostic_extras=True)
        self.assertEqual(original.call_count, 1)
        self.assertEqual(original.call_args.args[0][:4], ["xvfb-run", "-a", "dbus-run-session", "--"])
        self.assertNotIn("-e", original.call_args.args[0])
        self.assertEqual(original.call_args.kwargs, {"env": None, "capture_output": True, "timeout": 240})
        self.assertEqual(replay.call_count, 1)
        self.assertIn("-e", replay.call_args.args[0])

    def test_group_permission_failure_preserves_exit_and_reaps_child(self):
        child = MagicMock(pid=123, returncode=7)
        child.poll.return_value = 7
        with patch("subprocess.Popen", return_value=child), \
             patch("os.killpg", side_effect=PermissionError):
            result = _bounded_run(["synthetic-sudo"], env=None, timeout=3)
        child.wait.assert_called_once_with(timeout=10)
        self.assertEqual(result.returncode, 7)
        self.assertIsNone(result.capture_error)
        self.assertEqual(result.cleanup_error, "process-group-permission-denied")
        self.assertTrue(result.child_reaped)

    def test_reap_timeout_is_distinct_from_application_deadline(self):
        child = MagicMock(pid=123, returncode=None)
        child.poll.return_value = None
        child.wait.side_effect = subprocess.TimeoutExpired(["synthetic-sudo"], 10)
        with patch("subprocess.Popen", return_value=child), \
             patch("os.killpg", side_effect=PermissionError):
            result = _bounded_run(["synthetic-sudo"], env=None, timeout=0)
        child.wait.assert_called_once_with(timeout=10)
        self.assertEqual(result.capture_error, "process-timeout")
        self.assertEqual(result.cleanup_error, "process-reap-timeout")
        self.assertFalse(result.child_reaped)

    def test_cleanup_failure_cannot_make_replay_pass(self):
        def replay_result(cmd, **kwargs):
            evidence = Path(cmd[cmd.index("--evidence") + 1])
            (evidence / "linux-x64-C.run.json").write_text(json.dumps({
                "status": "pass", "executable": {"sha256": "a" * 64}}))
            return SimpleNamespace(returncode=0, stdout=b"", stderr=b"", capture_error=None,
                cleanup_error="process-group-permission-denied", child_reaped=True)

        with patch("rs9.application_smoke_diagnostic._bounded_run", side_effect=replay_result):
            label, replay = run_replay(scenario="C", platform="linux-x64", launch_root=self.launch_root,
                checkout=self.prepared["checkout"], tools=self.tools, prefix=["synthetic-sudo"],
                env=None, scratch=self.scratch)
        self.assertEqual(label, "replay-not-run")
        self.assertEqual(replay["raw_returncode"], 0)
        self.assertIsNone(replay["signal"])
        self.assertEqual(replay["cause"], "process-cleanup-failure")
        self.assertTrue(replay["failed"])

    def test_passing_original_attempt_never_uses_replay_supervisor(self):
        def original_result(cmd, **kwargs):
            evidence = Path(cmd[cmd.index("--evidence") + 1])
            scenario = cmd[cmd.index("--scenario") + 1]
            (evidence / ("linux-x64-" + scenario + ".run.json")).write_text(json.dumps({
                "status": "pass", "executable": {"sha256": "a" * 64}}))
            return SimpleNamespace(returncode=0, stdout=b"", stderr=b"")

        with patch("subprocess.run", side_effect=original_result) as original, \
             patch("rs9.application_smoke_diagnostic._bounded_run") as replay:
            runs = execute_application_smoke(prepared=self.prepared, system="x86_64-linux",
                launch_root=self.launch_root, prefix=["synthetic-sudo"], diagnostic_extras=True)
        self.assertEqual([r["scenario"] for r in runs], ["C", "C-signal"])
        self.assertEqual(original.call_count, 2)
        self.assertTrue(all(call.args[0][:5] == ["synthetic-sudo", "xvfb-run", "-a", "dbus-run-session", "--"]
                            for call in original.call_args_list))
        replay.assert_not_called()

    def test_real_capture_output_limit_is_explicit(self):
        import sys
        result = _bounded_run([sys.executable, "-B", "-c", "import os;os.write(1,b'x'*2000000)"],
                              env=None, timeout=3)
        self.assertEqual(result.capture_error, "process-output-limit")
        self.assertLessEqual(len(result.stdout), 1024 * 1024)

    def test_real_capture_cleans_owned_group_descendant(self):
        import sys
        import time
        marker = self.work / "late-descendant"
        child_code = "import time,pathlib;time.sleep(0.3);pathlib.Path(%r).write_text('survived')" % str(marker)
        parent_code = ("import subprocess,sys;subprocess.Popen([sys.executable,'-B','-c',%r]);"
                       "print('parent-completed')") % child_code
        result = _bounded_run([sys.executable, "-B", "-c", parent_code], env=None, timeout=3)
        self.assertEqual(result.returncode, 0)
        time.sleep(0.4)
        self.assertFalse(marker.exists())


if __name__ == "__main__":
    unittest.main()
