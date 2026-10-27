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
    SAFE_FAILURE_ROLES,
    SAFE_LOG_CATEGORIES,
    classify_failure_binding,
    classify_smoke_cause,
    execute_application_smoke,
    extract_log_categories,
    read_and_validate_receipt,
    run_boundary_probes,
    run_replay,
    sanitize_receipt_summary,
    validate_problem_codes,
    _bounded_run,
    _command,
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
        self.assertEqual(details["diagnostic_token"], "dbus-config-resolution")
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

    def test_failure_binding_uses_failed_callee_not_wrapper_prefix(self):
        cases = [
            (b"dbus-run-session: failed to exec 'dbus-daemon': No such file or directory\n", "dbus-daemon", "resolution"),
            (b"dbus-run-session: failed to exec '/nix/store/x-node/node': No such file or directory\n", "node", "resolution"),
            (b"dbus-run-session: failed to exec 'node': Permission denied\n", "node", "resolution"),
            (b"/usr/bin/env: 'node': No such file or directory\n", "node", "resolution"),
            (b"/usr/bin/env: \xe2\x80\x98node\xe2\x80\x99: No such file or directory\n", "node", "resolution"),
            (b"sh: 1: /nix/store/x-node/bin/node: not found\n", "node", "resolution"),
            (b"dbus-run-session: failed to exec '/private/node_modules/native-rc-smoke.mjs': No such file or directory\n", "smoke-script", "resolution"),
        ]
        for stderr, role, phase in cases:
            with self.subTest(stderr=stderr):
                categories = extract_log_categories(b"", stderr, exit_code=127)
                binding = classify_failure_binding(b"", stderr, 127, categories)
                self.assertEqual(binding["role"], role)
                self.assertEqual(binding["phase"], phase)
                self.assertIn(binding["role"], SAFE_FAILURE_ROLES)
                self.assertNotIn(stderr.decode("utf-8", errors="replace").strip(), json.dumps(binding))

        module_stderr = b"Error: Cannot find module '/private/node_modules/native-rc-smoke.mjs'\n"
        module_categories = extract_log_categories(b"", module_stderr, exit_code=1)
        self.assertIn("module-not-found", module_categories)
        module_binding = classify_failure_binding(b"", module_stderr, 1, module_categories)
        self.assertEqual(module_binding, {
            "role": "smoke-script",
            "phase": "module-resolution",
            "evidence": "module-not-found",
        })

    def test_failure_binding_unknown_for_ambiguous_paths_and_non_utf8(self):
        cases = [
            (b"dbus-run-session: failed to exec '/private/secret-node': No such file or directory\n", "resolution"),
            (b"dbus-run-session: failed to exec '/private/secret-node': Permission denied\n", "resolution"),
            (b"dbus-run-session: child process exited with error\n", "startup"),
            (b"/x/bin/node: 3: exec: /x/.node-wrapped: not found\n", "resolution"),
            (b"Error: Cannot find module '/private/node_modules/node-secret.js'\n", "module-resolution"),
            (b"Error [ERR_MODULE_NOT_FOUND]: Cannot find module '/private/pkg/index.mjs' imported from /private/node_modules/native-rc-smoke.mjs\n", "module-resolution"),
            (b"Error: Cannot find module '/private/pkg/index.js'\nRequire stack:\n- /private/node_modules/native-rc-smoke.mjs\n", "module-resolution"),
            (b"dbus-run-session: failed to exec 'dbus-daemon': No such file or directory\ndbus-run-session: failed to exec 'node': No such file or directory\n", "resolution"),
            (b"\x80\xffdbus-run-session\x00\n", "resolution"),
        ]
        for stderr, phase in cases:
            with self.subTest(stderr=stderr):
                categories = extract_log_categories(b"", stderr, exit_code=127)
                binding = classify_failure_binding(b"", stderr, 127, categories)
                self.assertEqual(binding["role"], "unknown")
                self.assertEqual(binding["phase"], phase)
                self.assertNotIn("secret-node", json.dumps(binding))

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

    def test_boundary_probes_follow_failure_and_never_qualify(self):
        root = "/nix/store/00000000000000000000000000001023-dbus-1.14.10"
        pinned_argv = [
            f"{root}/bin/dbus-run-session",
            f"--dbus-daemon={root}/bin/dbus-daemon",
            f"--config-file={root}/share/dbus-1/session.conf",
            "--",
        ]
        original_calls = []

        def original_failure(cmd, **kwargs):
            original_calls.append(list(cmd))
            return SimpleNamespace(returncode=127, stdout=b"",
                                   stderr=b"dbus-run-session: startup failed\n")

        def boundary_success(cmd, **kwargs):
            output = b"22.23.3\n" if "process.versions.node" in cmd else b""
            return SimpleNamespace(returncode=0, stdout=output, stderr=b"",
                                   stream_sizes=(len(output), 0), capture_error=None,
                                   cleanup_error=None, child_reaped=True)

        with patch("subprocess.run", side_effect=original_failure), \
             patch("rs9.application_smoke_diagnostic._bounded_run", side_effect=boundary_success) as bounded:
            with self.assertRaises(ContractError) as caught:
                execute_application_smoke(
                    prepared=self.prepared,
                    system="aarch64-linux",
                    launch_root=self.launch_root,
                    diagnostic_boundary_probes=True,
                    session_bus_argv=pinned_argv,
                )

        self.assertEqual(len(original_calls), 1)
        self.assertEqual(bounded.call_count, 5)
        self.assertEqual(caught.exception.code, "APPLICATION_SMOKE")
        self.assertIn("diagnostic_sha256", caught.exception.details)
        diagnostic = json.loads((self.work / "diagnostics/application-smoke-diagnostic.json").read_bytes())
        probes = diagnostic["boundary_probes"]
        self.assertEqual(probes["schema"], "rs9.application-smoke-boundary-probes.v1")
        self.assertTrue(probes["pinned_argv_available"])
        self.assertTrue(all(row["status"] == "pass" for row in probes["probes"]))
        self.assertEqual(probes["probes"][2]["expected_child"],
                         "dbus-run-session+dbus-daemon+session.conf+sh")
        self.assertEqual(diagnostic["replay"]["status"], "not-run")
        self.assertFalse(probes["qualification_authority"])
        self.assertFalse(probes["application_qualified"])
        self.assertNotIn(str(self.work), json.dumps(diagnostic))
        self.assertNotIn("startup failed", json.dumps(diagnostic))

    def test_boundary_probe_timeout_and_untrusted_pinned_argv_are_bounded(self):
        calls = []

        def timeout_then_failure(cmd, **kwargs):
            calls.append(list(cmd))
            if len(calls) == 1:
                return SimpleNamespace(returncode=None, stdout=b"", stderr=b"secret path\n",
                                       stream_sizes=(0, 12), capture_error="process-timeout",
                                       cleanup_error=None, child_reaped=True)
            return SimpleNamespace(returncode=1, stdout=b"", stderr=b"private path\n",
                                   stream_sizes=(0, 13), capture_error=None,
                                   cleanup_error=None, child_reaped=True)

        with patch("rs9.application_smoke_diagnostic._bounded_run", side_effect=timeout_then_failure):
            report = run_boundary_probes(
                prefix=["same-fhs-prefix"],
                env={"PATH": "same-fhs-path"},
                session_bus_argv=["/private/not-a-store-path"],
            )

        self.assertEqual(len(calls), 4)
        self.assertEqual(report["status"], "complete")
        self.assertFalse(report["pinned_argv_available"])
        self.assertEqual(report["probes"][0]["reason"], "process-timeout")
        self.assertEqual(report["probes"][2]["reason"], "pinned-argv-unavailable")
        self.assertNotIn("secret path", json.dumps(report))
        self.assertNotIn("private path", json.dumps(report))
        self.assertNotIn("same-fhs", json.dumps(report))

    def test_boundary_probe_clamps_remaining_execution_budget(self):
        root = "/nix/store/00000000000000000000000000001023-dbus-1.14.10"
        pinned_argv = [
            f"{root}/bin/dbus-run-session",
            f"--dbus-daemon={root}/bin/dbus-daemon",
            f"--config-file={root}/share/dbus-1/session.conf",
            "--",
        ]
        calls = []
        reads = [0]

        def clock():
            reads[0] += 1
            return 0.0 if reads[0] == 1 else (29.75 if not calls else 30.0)

        def one_probe(cmd, **kwargs):
            calls.append(kwargs)
            return SimpleNamespace(returncode=0, stdout=b"", stderr=b"", stream_sizes=(0, 0),
                                   capture_error=None, cleanup_error=None, child_reaped=True)

        with patch("rs9.application_smoke_diagnostic.time.monotonic", side_effect=clock), \
             patch("rs9.application_smoke_diagnostic._bounded_run", side_effect=one_probe):
            report = run_boundary_probes(session_bus_argv=pinned_argv)

        self.assertEqual(len(calls), 1)
        self.assertAlmostEqual(calls[0]["timeout"], 0.25, places=6)
        self.assertEqual(calls[0]["cleanup_timeout"], 1)
        self.assertEqual(report["status"], "incomplete")
        self.assertTrue(report["execution_budget_exhausted"])
        self.assertEqual(report["stop_reason"], "probe-total-deadline")
        self.assertTrue(all(row.get("not_started") for row in report["probes"][1:]))

    def test_boundary_probe_cleanup_failure_stops_following_probes(self):
        root = "/nix/store/00000000000000000000000000001023-dbus-1.14.10"
        pinned_argv = [
            f"{root}/bin/dbus-run-session",
            f"--dbus-daemon={root}/bin/dbus-daemon",
            f"--config-file={root}/share/dbus-1/session.conf",
            "--",
        ]
        calls = []

        def cleanup_failure(cmd, **kwargs):
            calls.append(list(cmd))
            return SimpleNamespace(returncode=0, stdout=b"", stderr=b"", stream_sizes=(0, 0),
                                   capture_error=None, cleanup_error="process-reap-timeout",
                                   child_reaped=False)

        with patch("rs9.application_smoke_diagnostic._bounded_run", side_effect=cleanup_failure):
            report = run_boundary_probes(session_bus_argv=pinned_argv)

        self.assertEqual(len(calls), 1)
        self.assertEqual(report["status"], "incomplete")
        self.assertEqual(report["stop_reason"], "process-cleanup-failure")
        self.assertEqual(report["probes"][0]["reason"], "process-cleanup-failure")
        self.assertEqual(report["probes"][0]["cleanup_error"], "process-reap-timeout")
        self.assertTrue(all(row.get("not_started") for row in report["probes"][1:]))

    def test_boundary_probe_unreaped_discovery_never_authenticates_pinned_argv(self):
        calls = []
        store_run_session = b"/nix/store/00000000000000000000000000001023-dbus-1.14.10/bin/dbus-run-session\n"

        def unreaped_discovery(cmd, **kwargs):
            calls.append(list(cmd))
            return SimpleNamespace(returncode=0, stdout=store_run_session, stderr=b"",
                                   stream_sizes=(len(store_run_session), 0), capture_error=None,
                                   cleanup_error=None, child_reaped=False)

        with patch("rs9.application_smoke_diagnostic._bounded_run", side_effect=unreaped_discovery):
            report = run_boundary_probes(prefix=["same-fhs-prefix"], env={"PATH": "same-fhs-path"})

        self.assertEqual(len(calls), 1)
        self.assertFalse(report["pinned_argv_available"])
        self.assertEqual(report["status"], "incomplete")
        self.assertEqual(report["stop_reason"], "process-reap-unconfirmed")
        self.assertTrue(all(row.get("not_started") for row in report["probes"]))
        self.assertNotIn(store_run_session.decode().strip(), json.dumps(report))

    def test_boundary_probes_discover_pinned_store_root_inside_same_fhs(self):
        calls = []
        store_run_session = b"/nix/store/00000000000000000000000000001023-dbus-1.14.10/bin/dbus-run-session\n"

        def discovered_success(cmd, **kwargs):
            calls.append(list(cmd))
            if len(calls) == 1:
                return SimpleNamespace(returncode=0, stdout=store_run_session, stderr=b"",
                                       stream_sizes=(len(store_run_session), 0), capture_error=None,
                                       cleanup_error=None, child_reaped=True)
            output = b"22.23.3\n" if "process.versions.node" in cmd else b""
            return SimpleNamespace(returncode=0, stdout=output, stderr=b"",
                                   stream_sizes=(len(output), 0), capture_error=None,
                                   cleanup_error=None, child_reaped=True)

        with patch("rs9.application_smoke_diagnostic._bounded_run", side_effect=discovered_success):
            report = run_boundary_probes(prefix=["same-fhs-prefix"], env={"PATH": "same-fhs-path"})

        self.assertEqual(len(calls), 6)
        self.assertEqual(calls[0][1:4], ["sh", "-c", "command -v dbus-run-session"])
        self.assertEqual(report["pinned_argv_source"], "same-fhs-command-v")
        self.assertTrue(report["pinned_argv_available"])
        self.assertEqual(report["probes"][2]["label"], "dbus-pinned")
        self.assertEqual(report["probes"][2]["status"], "pass")
        self.assertNotIn(store_run_session.decode().strip(), json.dumps(report))
        self.assertNotIn("same-fhs-path", json.dumps(report))

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
    def test_golden_default_command_argv_unchanged_across_platforms(self):
        """Golden test proving default command argv is unchanged for linux-x64, linux-arm64, and darwin."""
        # 1. Linux x64
        cmd_linux_x64 = _command(self.prepared, "linux-x64", "C", self.launch_root, self.scratch, extras=False)
        self.assertEqual(cmd_linux_x64[:4], ["xvfb-run", "-a", "dbus-run-session", "--"])
        self.assertEqual(cmd_linux_x64[4], "node")

        # 2. Linux arm64
        cmd_linux_arm64 = _command(self.prepared, "linux-arm64", "B", self.launch_root, self.scratch, extras=False)
        self.assertEqual(cmd_linux_arm64[:4], ["xvfb-run", "-a", "dbus-run-session", "--"])
        self.assertEqual(cmd_linux_arm64[4], "node")

        # 3. Darwin arm64 (no xvfb, no dbus)
        cmd_darwin = _command(self.prepared, "darwin-arm64", "A", self.launch_root, self.scratch, extras=False)
        self.assertEqual(cmd_darwin[0], "node")
        self.assertNotIn("xvfb-run", cmd_darwin)
        self.assertNotIn("dbus-run-session", cmd_darwin)

    def test_explicit_pinned_dbus_argv_injection_on_linux(self):
        """Optional explicit pinned dbus command replaces dbus-run-session on linux."""
        root = "/nix/store/00000000000000000000000000001023-dbus-1.14.10"
        pinned_argv = [
            f"{root}/bin/dbus-run-session",
            f"--dbus-daemon={root}/bin/dbus-daemon",
            f"--config-file={root}/share/dbus-1/session.conf",
            "--",
        ]
        # Linux x64
        cmd_x64 = _command(self.prepared, "linux-x64", "C", self.launch_root, self.scratch,
                           extras=False, session_bus_argv=pinned_argv)
        self.assertEqual(cmd_x64[:6], ["xvfb-run", "-a", *pinned_argv])
        self.assertEqual(cmd_x64[6], "node")

        # Linux arm64
        cmd_arm64 = _command(self.prepared, "linux-arm64", "B", self.launch_root, self.scratch,
                             extras=False, session_bus_argv=pinned_argv)
        self.assertEqual(cmd_arm64[:6], ["xvfb-run", "-a", *pinned_argv])
        self.assertEqual(cmd_arm64[6], "node")

    def test_explicit_pinned_dbus_argv_injection_on_darwin_remains_unchanged(self):
        """Darwin does not use display/dbus even when valid session_bus_argv is injected."""
        root = "/nix/store/00000000000000000000000000001023-dbus-1.14.10"
        pinned_argv = [
            f"{root}/bin/dbus-run-session",
            f"--dbus-daemon={root}/bin/dbus-daemon",
            f"--config-file={root}/share/dbus-1/session.conf",
            "--",
        ]
        cmd_darwin = _command(self.prepared, "darwin-arm64", "A", self.launch_root, self.scratch,
                              extras=False, session_bus_argv=pinned_argv)
        self.assertEqual(cmd_darwin[0], "node")
        self.assertNotIn("xvfb-run", cmd_darwin)
        self.assertNotIn("dbus-run-session", cmd_darwin)
        self.assertNotIn(root, " ".join(cmd_darwin))

    def test_execute_application_smoke_with_pinned_dbus_and_no_leakage(self):
        """execute_application_smoke uses injected session_bus_argv on linux, and does not leak to subsequent runs."""
        root = "/nix/store/00000000000000000000000000001023-dbus-1.14.10"
        pinned_argv = [
            f"{root}/bin/dbus-run-session",
            f"--dbus-daemon={root}/bin/dbus-daemon",
            f"--config-file={root}/share/dbus-1/session.conf",
            "--",
        ]

        def fake_run(cmd, **kwargs):
            evidence = Path(cmd[cmd.index("--evidence") + 1])
            scenario = cmd[cmd.index("--scenario") + 1]
            (evidence / ("linux-x64-" + scenario + ".run.json")).write_text(json.dumps({
                "status": "pass", "executable": {"sha256": "a" * 64}}))
            return SimpleNamespace(returncode=0, stdout=b"", stderr=b"")

        # Run 1: with explicit pinned argv
        with patch("subprocess.run", side_effect=fake_run) as run_mock:
            runs = execute_application_smoke(
                prepared=self.prepared,
                system="x86_64-linux",
                launch_root=self.launch_root,
                session_bus_argv=pinned_argv,
            )
            self.assertEqual(len(runs), 2)
            self.assertEqual(run_mock.call_args_list[0].args[0][:6], ["xvfb-run", "-a", *pinned_argv])

        # Run 2: without pinned argv (default lane) -> MUST NOT LEAK!
        with patch("subprocess.run", side_effect=fake_run) as run_mock:
            runs = execute_application_smoke(
                prepared=self.prepared,
                system="x86_64-linux",
                launch_root=self.launch_root,
                session_bus_argv=None,
            )
            self.assertEqual(len(runs), 2)
            self.assertEqual(run_mock.call_args_list[0].args[0][:4], ["xvfb-run", "-a", "dbus-run-session", "--"])

    def test_malicious_session_bus_argv_rejected_on_all_platforms(self):
        """Malicious or invalid session_bus_argv is rejected with ContractError across platforms."""
        bad_vectors = [
            ["malicious"],
            ["dbus-run-session", "--"],
            ["/usr/bin/dbus-run-session", "--dbus-daemon=/usr/bin/dbus-daemon", "--config-file=/etc/session.conf", "--"],
            ["/nix/store/00000000000000000000000000001023-dbus-1/bin/dbus-run-session;rm",
             "--dbus-daemon=/nix/store/00000000000000000000000000001023-dbus-1/bin/dbus-daemon",
             "--config-file=/nix/store/00000000000000000000000000001023-dbus-1/share/dbus-1/session.conf", "--"],
        ]
        for system in ("x86_64-linux", "aarch64-linux", "aarch64-darwin"):
            for bad_vec in bad_vectors:
                with self.subTest(system=system, bad_vec=bad_vec):
                    with self.assertRaises(ContractError) as caught:
                        execute_application_smoke(
                            prepared=self.prepared,
                            system=system,
                            launch_root=self.launch_root,
                            session_bus_argv=bad_vec,
                        )
                    self.assertEqual(caught.exception.code, "NIX_PROOT_DBUS")

    def test_replay_propagates_pinned_session_bus_argv(self):
        """Replay receives and uses pinned session_bus_argv with xvfb error log options."""
        root = "/nix/store/00000000000000000000000000001023-dbus-1.14.10"
        pinned_argv = [
            f"{root}/bin/dbus-run-session",
            f"--dbus-daemon={root}/bin/dbus-daemon",
            f"--config-file={root}/share/dbus-1/session.conf",
            "--",
        ]

        def replay_result(cmd, **kwargs):
            evidence = Path(cmd[cmd.index("--evidence") + 1])
            (evidence / "linux-x64-C.run.json").write_text(json.dumps({
                "status": "pass", "executable": {"sha256": "a" * 64}}))
            return SimpleNamespace(returncode=0, stdout=b"", stderr=b"", capture_error=None,
                cleanup_error=None, child_reaped=True)

        with patch("rs9.application_smoke_diagnostic._bounded_run", side_effect=replay_result) as mock_bounded:
            label, replay = run_replay(
                scenario="C",
                platform="linux-x64",
                launch_root=self.launch_root,
                checkout=self.prepared["checkout"],
                tools=self.tools,
                prefix=[],
                env=None,
                scratch=self.scratch,
                session_bus_argv=pinned_argv,
            )
            self.assertEqual(label, "replay-passed")
            called_cmd = mock_bounded.call_args[0][0]
            self.assertEqual(called_cmd[:2], ["xvfb-run", "-a"])
            self.assertEqual(called_cmd[2], "-e")
            self.assertEqual(called_cmd[4:8], pinned_argv)

    def test_exit_code_signal_distinction_143_255_and_negative(self):
        """143 and 255 are classified as exits, negative returncode is outer signal only."""
        for rc, expected_exit, expected_sig, expected_cause in [
            (143, 143, None, "process-nonzero"),
            (255, 255, None, "process-nonzero"),
            (-15, None, 15, "process-signal"),
            (-9, None, 9, "process-signal"),
        ]:
            with self.subTest(rc=rc):
                def fake_run(cmd, **kwargs):
                    return SimpleNamespace(returncode=rc, stdout=b"out", stderr=b"err")

                with patch("subprocess.run", side_effect=fake_run):
                    with self.assertRaises(ContractError) as caught:
                        execute_application_smoke(
                            prepared=self.prepared,
                            system="x86_64-linux",
                            launch_root=self.launch_root,
                            diagnostic_extras=False,
                        )
                obs = getattr(caught.exception, "smoke_observation", None)
                self.assertIsNotNone(obs)
                self.assertEqual(obs["raw_returncode"], rc)
                self.assertEqual(obs["exit_code"], expected_exit)
                self.assertEqual(obs["signal"], expected_sig)
                self.assertEqual(obs["cause"], expected_cause)
                self.assertEqual(obs["stdout_bytes"], 3)
                self.assertEqual(obs["stderr_bytes"], 3)
                self.assertEqual(obs["stdout_sha256"], digest(b"out"))
                self.assertEqual(obs["stderr_sha256"], digest(b"err"))
                self.assertTrue(obs["stream_capture_complete"])

    def test_single_attempt_preserves_original_argv_and_runner(self):
        """Qualification attempt preserves original subprocess.run argv and runner with single attempt."""
        calls = []
        def fake_run(cmd, **kwargs):
            calls.append(list(cmd))
            return SimpleNamespace(returncode=1, stdout=b"", stderr=b"generic error")

        with patch("subprocess.run", side_effect=fake_run) as mock_run, \
             patch("rs9.application_smoke_diagnostic._bounded_run") as mock_bounded:
            with self.assertRaises(ContractError) as caught:
                execute_application_smoke(
                    prepared=self.prepared,
                    system="x86_64-linux",
                    launch_root=self.launch_root,
                    diagnostic_extras=False,
                )

        # Exactly 1 call (single attempt, NO replay)
        self.assertEqual(len(calls), 1)
        mock_bounded.assert_not_called()
        self.assertEqual(mock_run.call_count, 1)

        # Verify argv structure
        cmd = calls[0]
        self.assertEqual(cmd[0], "xvfb-run")
        self.assertEqual(cmd[1], "-a")
        self.assertEqual(cmd[2], "dbus-run-session")
        self.assertEqual(cmd[3], "--")
        self.assertEqual(cmd[4], "node")
        self.assertTrue(cmd[5].endswith("native-rc-smoke.mjs"))
        self.assertIn("--scenario", cmd)
        self.assertEqual(cmd[cmd.index("--scenario") + 1], "C")
        self.assertIn("--platform", cmd)
        self.assertEqual(cmd[cmd.index("--platform") + 1], "linux-x64")

        # Smoke observation is carried on the exception
        obs = caught.exception.smoke_observation
        self.assertEqual(obs["scenario"], "C")
        self.assertEqual(obs["cause"], "process-nonzero")
        self.assertEqual(obs["raw_returncode"], 1)
        self.assertEqual(obs["exit_code"], 1)
        self.assertIsNone(obs["signal"])

    def test_production_non_container_optional_behavior(self):
        """Non-container / production environment without container_client succeeds or records failure cleanly."""
        prepared_non_container = {
            "scratch": self.scratch,
            "tools": self.tools,
            "source": self.work / "source",
            "checkout": self.work / "source",
            "records": [],
            # container_client is intentionally absent
        }

        # Failure without container_client
        with patch("subprocess.run", return_value=SimpleNamespace(returncode=2, stdout=b"", stderr=b"fail")):
            with self.assertRaises(ContractError) as caught:
                execute_application_smoke(
                    prepared=prepared_non_container,
                    system="x86_64-linux",
                    launch_root=self.launch_root,
                    diagnostic_extras=False,
                )
            self.assertEqual(caught.exception.code, "APPLICATION_SMOKE")
            self.assertIsNotNone(caught.exception.smoke_observation)
            self.assertEqual(caught.exception.smoke_observation["exit_code"], 2)

    def test_darwin_scenario_a_projects_original_run_record_and_distinct_inner_stderr_without_replay(self):
        """Darwin Scenario A failure projects the already-read .run.json and inner stderr.log with no replay."""
        outer_stdout = b'{"label":"darwin-arm64-A","status":"fail","problems":[' + b"x" * 370 + b"]}\n"
        self.assertEqual(len(outer_stdout), 427)
        inner_stderr = ("Error: /" + "Users/" + "op/secret-inner-stderr-44b!!!\n").encode("utf-8")
        self.assertEqual(len(inner_stderr), 44)

        run_payload = {
            "schema": "nebular.native-rc-smoke-run-v1",
            "label": "darwin-arm64-A",
            "platform": "darwin-arm64",
            "scenario": "A",
            "status": "fail",
            "executable": {"sha256": "a" * 64, "size": 1000},
            "receipt": {
                "sha256": "b" * 64,
                "status": "fail",
                "steps": [
                    {"id": "app-shell", "ok": True, "via": "ipc", "ms": 12},
                    {"id": "host-start", "ok": True, "via": "ipc", "ms": 15},
                    {"id": "host-status", "ok": True, "via": "ipc", "ms": 4},
                    {"id": "project-open", "ok": False, "via": "ipc", "detail": "SENTINEL_PROJECT_OPEN_DETAIL"},
                    {"id": "brand-read", "ok": 1},
                    {"id": "theme-lab-compile", "ok": True},
                    {"id": "theme-lab-compile", "ok": False},
                    {"id": "unlisted-dynamic-step", "ok": True},
                ],
            },
            # Synthetic 8-problem Scenario A fixture exercising authenticated runSmoke forms
            # (unretained publish2 inner problem strings remain unknown; cause is UNKNOWN).
            "problems": [
                "application exit code 1 signal null",
                "receipt mode 644",
                "receipt status fail: SENTINEL_RECEIPT_FAILURE",
                "receipt target x86_64-apple-darwin",
                "the running executable is not the candidate executable",
                "required step project-open failed: SENTINEL_STEP_PROBLEM",
                "read-only fixture core-minimal was modified",
                "persistent user state changed: /" + "Users/" + "op/Library/Caches/secret",
            ],
            "padding": "",
        }
        base_run_bytes = (json.dumps(run_payload, indent=2) + "\n").encode("utf-8")
        run_payload["padding"] = "p" * (1779 - len(base_run_bytes))
        run_bytes = (json.dumps(run_payload, indent=2) + "\n").encode("utf-8")
        self.assertEqual(len(run_bytes), 1779)
        receipt_bytes = b"{" + b" " * 1711 + b"}"
        self.assertEqual(len(receipt_bytes), 1713)

        def fake_darwin_run(cmd, **kwargs):
            evidence = Path(cmd[cmd.index("--evidence") + 1])
            (evidence / "darwin-arm64-A.receipt.json").write_bytes(receipt_bytes)
            (evidence / "darwin-arm64-A.run.json").write_bytes(run_bytes)
            (evidence / "darwin-arm64-A.stderr.log").write_bytes(inner_stderr)
            (evidence / "darwin-arm64-A.stdout.log").write_bytes(b"")
            return SimpleNamespace(returncode=1, stdout=outer_stdout, stderr=b"")

        with patch("subprocess.run", side_effect=fake_darwin_run) as run_mock, \
             patch("rs9.application_smoke_diagnostic._bounded_run") as bounded_mock, \
             patch("rs9.application_smoke_diagnostic.run_replay") as replay_mock:
            with self.assertRaises(ContractError) as caught:
                execute_application_smoke(
                    prepared=self.prepared,
                    system="aarch64-darwin",
                    launch_root=self.launch_root,
                    diagnostic_extras=True,
                )

        run_mock.assert_called_once()
        bounded_mock.assert_not_called()
        replay_mock.assert_not_called()
        self.assertFalse((self.scratch / "evidence-replay-A").exists())
        self.assertFalse((self.work / "diagnostics").exists())

        err = caught.exception
        self.assertEqual(err.code, "APPLICATION_SMOKE")
        self.assertEqual(err.details["scenario"], "A")
        self.assertEqual(err.details["cause"], "process-nonzero")
        self.assertEqual(err.details["exit_code"], 1)
        self.assertEqual(err.details["stdout_sha256"], digest(outer_stdout))
        self.assertEqual(err.details["stderr_sha256"], digest(b""))

        obs = err.smoke_observation
        self.assertEqual(obs["scenario"], "A")
        self.assertEqual(obs["cause"], "process-nonzero")
        self.assertEqual(obs["stdout_bytes"], 427)
        self.assertEqual(obs["stderr_bytes"], 0)
        self.assertEqual(obs["stderr_sha256"], digest(b""))
        self.assertEqual(obs["problem_codes"], ["withheld-token"] * 8)

        # Outer stderr identity vs inner stderr identity
        self.assertEqual(obs["stderr_diagnostic"]["stage"], "original-smoke-process-stderr")
        self.assertEqual(obs["stderr_diagnostic"]["bytes"], 0)
        self.assertEqual(obs["stderr_diagnostic"]["sha256"], digest(b""))
        self.assertEqual(obs["stderr_diagnostic"]["withheld_reason"], "empty")

        self.assertIn("inner_stderr_diagnostic", obs)
        inner = obs["inner_stderr_diagnostic"]
        self.assertEqual(inner["stage"], "original-inner-application-stderr")
        self.assertEqual(inner["bytes"], 44)
        self.assertEqual(inner["sha256"], digest(inner_stderr))
        self.assertNotEqual(inner["sha256"], obs["stderr_sha256"])
        self.assertTrue(inner["complete"])
        self.assertIsNone(inner["read_error"])
        self.assertEqual(inner["tokens"], [])
        self.assertEqual(inner["withheld_reason"], "private")

        self.assertIn("harness_run_record", obs)
        run_rec = obs["harness_run_record"]
        self.assertEqual(run_rec["stage"], "original-harness-run-record")
        self.assertEqual(run_rec["status"], "observed")
        self.assertIsNone(run_rec["withheld_reason"])
        self.assertEqual(run_rec["bytes"], 1779)
        self.assertEqual(run_rec["sha256"], digest(run_bytes))
        self.assertEqual(run_rec["steps_entries_observed"], 8)
        self.assertEqual(run_rec["steps_unlisted"], 1)
        self.assertEqual(run_rec["steps_omitted"], 0)
        step_map = {s["id"]: s["state"] for s in run_rec["steps"]}
        self.assertEqual(step_map["app-shell"], "pass")
        self.assertEqual(step_map["project-open"], "fail")
        self.assertEqual(step_map["brand-read"], "unknown")
        self.assertEqual(step_map["theme-lab-compile"], "duplicate")
        self.assertEqual(step_map["app-theme-status"], "missing")
        self.assertEqual(run_rec["problems"], {
            "total": 8,
            "scanned": 8,
            "categories": [
                {"category": "application-exit-nonzero", "count": 1},
                {"category": "persistent-user-state-changed", "count": 1},
                {"category": "read-only-fixture-modified", "count": 1},
                {"category": "receipt-mode-mismatch", "count": 1},
                {"category": "receipt-status", "count": 1},
                {"category": "receipt-target-mismatch", "count": 1},
                {"category": "required-step", "count": 1},
                {"category": "running-executable-mismatch", "count": 1},
            ],
            "unrecognized": 0,
            "non_string": 0,
            "unavailable": 0,
        })
        serialized = json.dumps(obs)
        for sentinel in (
            "SENTINEL_PROJECT_OPEN_DETAIL",
            "SENTINEL_RECEIPT_FAILURE",
            "SENTINEL_STEP_PROBLEM",
            "secret-inner-stderr",
            "unlisted-dynamic-step",
        ):
            self.assertNotIn(sentinel, serialized)

    def test_darwin_projector_fault_and_linux_missing_inner_preserve_primary_failure(self):
        """Darwin projector faults and Linux missing files preserve primary failure."""
        from rs9.pages_smoke_diagnostic import validate_smoke_observation
        from rs9.smoke_stream_tokens import INNER_STAGE
        with patch("subprocess.run", return_value=SimpleNamespace(returncode=1, stdout=b"", stderr=b"")), \
             patch("rs9.smoke_stream_tokens.project_run_record", side_effect=RuntimeError("projector boom")):
            with self.assertRaises(ContractError) as caught_darwin:
                execute_application_smoke(
                    prepared=self.prepared,
                    system="aarch64-darwin",
                    launch_root=self.launch_root,
                )
        self.assertEqual(caught_darwin.exception.code, "APPLICATION_SMOKE")
        obs_darwin = caught_darwin.exception.smoke_observation
        self.assertNotIn("harness_run_record", obs_darwin)
        self.assertIn("inner_stderr_diagnostic", obs_darwin)

        for linux_sys in ("x86_64-linux", "aarch64-linux"):
            with self.subTest(system=linux_sys), \
                 patch("subprocess.run", return_value=SimpleNamespace(returncode=1, stdout=b"", stderr=b"")):
                with self.assertRaises(ContractError) as caught_linux:
                    execute_application_smoke(
                        prepared=self.prepared,
                        system=linux_sys,
                        launch_root=self.launch_root,
                    )
            obs_linux = caught_linux.exception.smoke_observation
            self.assertNotIn("harness_run_record", obs_linux)
            self.assertEqual(caught_linux.exception.code, "APPLICATION_SMOKE")
            self.assertEqual(obs_linux["inner_stderr_diagnostic"], {
                "stage": INNER_STAGE, "bytes": None, "sha256": None, "complete": False,
                "read_error": "missing", "line_count": None, "utf8_valid": None,
                "tokens": [], "tokens_omitted": 0, "withheld_reason": "missing",
            })
            self.assertEqual(
                {key: obs_linux[key] for key in (
                    "cause", "reason_token", "raw_returncode", "exit_code", "signal",
                    "receipt_error", "problem_codes", "stream_capture_complete")},
                {"cause": "process-nonzero", "reason_token": "process-nonzero",
                 "raw_returncode": 1, "exit_code": 1, "signal": None,
                 "receipt_error": "receipt-missing", "problem_codes": [],
                 "stream_capture_complete": True},
            )
            p1 = validate_smoke_observation(obs_linux, system=linux_sys)
            p2 = validate_smoke_observation(p1, system=linux_sys)
            p3 = validate_smoke_observation(p2, system=linux_sys)
            self.assertEqual(p1, obs_linux)
            self.assertEqual(p2, p1)
            self.assertEqual(p3, p2)


if __name__ == "__main__":
    unittest.main()
