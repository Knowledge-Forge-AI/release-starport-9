"""Focused tests for the optional replay progress observer.

These tests exercise only the RS9-owned wrapper and Python command selection.
They use synthetic ESM harnesses; no native application, Docker image, or
release asset is executed.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import time
import unittest

import rs9.application_smoke_diagnostic as diagnostic_module
from rs9.application_smoke_diagnostic import (
    RELEASED_NATIVE_RC_SMOKE_SHA256,
    RELEASED_NATIVE_RC_SNAPSHOT_SHA256,
    REPLAY_PROGRESS_MAX_BYTES,
    REPLAY_PROGRESS_SCHEMA,
    _command,
    _read_replay_progress,
    _replay_progress_wrapper,
)
from rs9.errors import ContractError
from unittest.mock import patch


class ReplayProgressObserverTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name).resolve()
        self.tools = self.root / "tools"
        self.tools.mkdir()
        self.source = self.root / "source"
        self.source.mkdir()
        self.scratch = self.root / "scratch"
        self.scratch.mkdir()
        self.checkout = self.source
        self.launch_root = self.root / "launch-root"
        self.launch_root.mkdir()
        self.evidence = self.root / "evidence"
        self.evidence.mkdir()
        self.wrapper = self.root / "replay_progress_wrapper.mjs"
        source_wrapper = (
            Path(__file__).resolve().parents[1]
            / "src"
            / "rs9"
            / "replay_progress_wrapper.mjs"
        )
        self.wrapper.write_bytes(source_wrapper.read_bytes())
        self.node = shutil.which("node")

    def tearDown(self):
        self.tmp.cleanup()

    def _prepared(self):
        harness = self.tools / "native-rc-smoke.mjs"
        harness.write_text("// command-only fixture\n", encoding="utf-8")
        return {
            "scratch": self.scratch,
            "tools": self.tools,
            "source": self.source,
            "checkout": self.checkout,
        }

    def _progress_args(self, harness, progress, closure_members=None):
        args = [
            "--rs9-replay-progress-harness",
            str(harness),
            "--rs9-replay-progress-file",
            str(progress),
            "--rs9-replay-progress-expected-sha256",
            hashlib.sha256(harness.read_bytes()).hexdigest(),
        ]
        args.extend([
            "--rs9-replay-progress-closure-member",
            harness.name + "=" + hashlib.sha256(harness.read_bytes()).hexdigest(),
        ])
        for name, member in sorted((closure_members or {}).items()):
            args.extend([
                "--rs9-replay-progress-closure-member",
                name + "=" + hashlib.sha256(member.read_bytes()).hexdigest(),
            ])
        return args

    def _run_wrapper(self, harness_body, *, closure_members=None, timeout=10):
        if self.node is None:
            self.fail("qualified Node runtime is unavailable")
        harness = self.root / "native-rc-smoke.mjs"
        harness.write_text(harness_body, encoding="utf-8")
        progress = self.root / "replay-progress.jsonl"
        command = [
            self.node,
            str(self.wrapper),
            *self._progress_args(harness, progress, closure_members),
            "--platform",
            "linux-x64",
            "--scenario",
            "C",
            "--launch-root",
            str(self.launch_root),
            "--checkout",
            str(self.checkout),
            "--evidence",
            str(self.evidence),
            "--label",
            "linux-x64-C",
            "--timeout-ms",
            "180000",
        ]
        result = subprocess.run(
            command,
            cwd=self.root,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            timeout=timeout,
            check=False,
        )
        return result, progress

    def _read_events(self, progress):
        return [json.loads(line) for line in progress.read_text(encoding="utf-8").splitlines()]

    def test_required_command_is_unchanged_and_optional_wrapper_only_adds_observer_flags(self):
        prepared = self._prepared()
        required_evidence = self.root / "required-evidence"
        replay_evidence = self.root / "replay-evidence"
        progress = replay_evidence / "replay-progress.jsonl"
        replay_evidence.mkdir()
        required = _command(
            prepared,
            "linux-x64",
            "C",
            self.launch_root,
            required_evidence,
            extras=True,
        )
        optional = _command(
            prepared,
            "linux-x64",
            "C",
            self.launch_root,
            replay_evidence,
            extras=True,
            harness_timeout_ms=180_000,
            replay_progress={
                "wrapper": self.wrapper,
                "harness": self.tools / "native-rc-smoke.mjs",
                "progress": progress,
                "expected_sha256": RELEASED_NATIVE_RC_SMOKE_SHA256,
                "closure": {
                    "native-rc-smoke.mjs": RELEASED_NATIVE_RC_SMOKE_SHA256,
                    "fs-snapshot.mjs": RELEASED_NATIVE_RC_SNAPSHOT_SHA256,
                },
            },
        )
        expected_display_prefix = [
            "xvfb-run",
            "-a",
            "-e",
            str(required_evidence / "xvfb-error.log"),
            "dbus-run-session",
            "--",
        ]
        self.assertEqual(required[:6], expected_display_prefix)
        self.assertEqual(optional[:6], [
            "xvfb-run",
            "-a",
            "-e",
            str(replay_evidence / "xvfb-error.log"),
            "dbus-run-session",
            "--",
        ])
        self.assertNotIn("--timeout-ms", required)
        self.assertNotIn("--rs9-replay-progress-harness", required)
        required_smoke = required[required.index("--platform") :]
        optional_smoke = optional[optional.index("--platform") :]
        required_smoke = required_smoke[: required_smoke.index("--evidence")] + required_smoke[required_smoke.index("--evidence") + 2 :]
        optional_smoke = optional_smoke[: optional_smoke.index("--evidence")] + optional_smoke[optional_smoke.index("--evidence") + 2 :]
        timeout_index = optional_smoke.index("--timeout-ms")
        optional_smoke = optional_smoke[:timeout_index]
        self.assertEqual(optional_smoke, required_smoke)
        self.assertEqual(optional[optional.index("node") + 1], str(self.wrapper))
        self.assertIn("--rs9-replay-progress-harness", optional)
        self.assertIn("--rs9-replay-progress-file", optional)
        self.assertIn("--rs9-replay-progress-expected-sha256", optional)
        self.assertEqual(optional[optional.index("--timeout-ms") + 1], "180000")

    def test_python_enablement_requires_the_authenticated_harness_identity(self):
        helper = Path(diagnostic_module.__file__).with_name("replay_progress_wrapper.mjs")
        prepared = self._prepared()
        harness = self.tools / "native-rc-smoke.mjs"
        snapshot = self.tools / "fs-snapshot.mjs"
        snapshot.write_text("export const syntheticSnapshot = true;\n", encoding="utf-8")
        self.assertIsNone(_replay_progress_wrapper(prepared))
        with patch(
            "rs9.application_smoke_diagnostic.RELEASED_NATIVE_RC_SMOKE_SHA256",
            hashlib.sha256(harness.read_bytes()).hexdigest(),
        ), patch(
            "rs9.application_smoke_diagnostic.RELEASED_NATIVE_RC_SNAPSHOT_SHA256",
            hashlib.sha256(snapshot.read_bytes()).hexdigest(),
        ):
            self.assertEqual(_replay_progress_wrapper(prepared), helper)

    def test_prepare_smoke_shape_uses_module_owned_observer_without_source_layout(self):
        prepared = self._prepared()
        snapshot = self.tools / "fs-snapshot.mjs"
        snapshot.write_text("export const syntheticSnapshot = true;\n", encoding="utf-8")
        helper = Path(diagnostic_module.__file__).with_name("replay_progress_wrapper.mjs")
        self.assertFalse((self.source / "src" / "rs9").exists())
        with patch(
            "rs9.application_smoke_diagnostic.RELEASED_NATIVE_RC_SMOKE_SHA256",
            hashlib.sha256((self.tools / "native-rc-smoke.mjs").read_bytes()).hexdigest(),
        ), patch(
            "rs9.application_smoke_diagnostic.RELEASED_NATIVE_RC_SNAPSHOT_SHA256",
            hashlib.sha256(snapshot.read_bytes()).hexdigest(),
        ):
            selected = _replay_progress_wrapper(prepared)
        self.assertEqual(selected, helper)
        self.assertTrue(selected.is_file())
        self.assertFalse(selected.is_symlink())

    def test_progress_reader_is_bounded_fixed_enum_and_no_follow(self):
        progress = self.root / "progress.jsonl"
        valid = [
            {"schema": REPLAY_PROGRESS_SCHEMA, "seq": 1, "stage": "harness", "event": "imported"},
            {"schema": REPLAY_PROGRESS_SCHEMA, "seq": 2, "stage": "run-smoke", "event": "enter"},
        ]
        progress.write_text("".join(json.dumps(item) + "\n" for item in valid), encoding="utf-8")
        observed = _read_replay_progress(progress)
        self.assertEqual(observed["status"], "observed")
        self.assertEqual(observed["event_count"], 2)
        self.assertEqual(observed["events"], [
            {"seq": 1, "stage": "harness", "event": "imported"},
            {"seq": 2, "stage": "run-smoke", "event": "enter"},
        ])

        duplicate = self.root / "duplicate.jsonl"
        duplicate.write_text(
            json.dumps(valid[0]) + "\n" + json.dumps(valid[0]) + "\n",
            encoding="utf-8",
        )
        self.assertEqual(_read_replay_progress(duplicate), {"status": "unobserved", "reason": "invalid"})

        unknown = self.root / "unknown.jsonl"
        unknown.write_text(
            json.dumps({**valid[0], "event": "argv-leaked"}) + "\n",
            encoding="utf-8",
        )
        self.assertEqual(_read_replay_progress(unknown), {"status": "unobserved", "reason": "invalid"})

        oversized = self.root / "oversized.jsonl"
        oversized.write_bytes(b"x" * (REPLAY_PROGRESS_MAX_BYTES + 1))
        self.assertEqual(_read_replay_progress(oversized), {"status": "unobserved", "reason": "oversize"})

        target = self.root / "private-progress"
        target.write_bytes(progress.read_bytes())
        link = self.root / "linked-progress.jsonl"
        link.symlink_to(target)
        self.assertEqual(_read_replay_progress(link), {"status": "unobserved", "reason": "invalid"})

    def test_wrapper_preserves_return_shape_and_records_launch_and_receipts_without_private_fields(self):
        result, progress = self._run_wrapper(
            """
import { spawn } from 'node:child_process';
import { writeFileSync } from 'node:fs';
import { join } from 'node:path';
export async function runSmoke(options) {
  const child = spawn(process.execPath, ['-e', 'process.exit(0)']);
  await new Promise((resolve, reject) => {
    child.once('error', reject);
    child.once('exit', resolve);
  });
  writeFileSync(join(options.evidenceDir, 'linux-x64-C.receipt.json'), '{}');
  writeFileSync(join(options.evidenceDir, 'linux-x64-C.run.json'), '{}');
  return { label: options.label, status: 'fail', problems: ['synthetic-failure'] };
}
"""
        )
        self.assertEqual(result.returncode, 1, result.stderr.decode())
        self.assertEqual(
            json.loads(result.stdout),
            {"label": "linux-x64-C", "status": "fail", "problems": ["synthetic-failure"]},
        )
        events = self._read_events(progress)
        pairs = [(item["stage"], item["event"]) for item in events]
        for expected in (
            ("harness", "import-start"),
            ("harness", "imported"),
            ("run-smoke", "enter"),
            ("candidate", "launched"),
            ("candidate", "exited"),
            ("receipt", "finalized"),
            ("run-record", "finalized"),
            ("run-smoke", "returned"),
        ):
            self.assertIn(expected, pairs)
        progress_text = progress.read_text(encoding="utf-8")
        self.assertNotIn(str(self.root), progress_text)
        self.assertNotRegex(progress_text, r'"(?:argv|env|path|pid)"')
        self.assertEqual((self.evidence / "linux-x64-C.receipt.json").read_text(), "{}")

    def test_wrapper_loads_only_authenticated_relative_esm_closure(self):
        dependency = self.root / "dependency.mjs"
        dependency.write_text("export const marker = 'held-closure';\n", encoding="utf-8")
        result, progress = self._run_wrapper(
            """
import { marker } from './dependency.mjs';
export function runSmoke(options) {
  if (marker !== 'held-closure') throw new Error('dependency mismatch');
  return { label: options.label, status: 'fail', problems: ['closure-fixture'] };
}
""",
            closure_members={"dependency.mjs": dependency},
        )
        self.assertEqual(result.returncode, 1, result.stderr.decode())
        self.assertEqual(json.loads(result.stdout)["problems"], ["closure-fixture"])
        pairs = [(item["stage"], item["event"]) for item in self._read_events(progress)]
        self.assertIn(("harness", "imported"), pairs)
        self.assertIn(("run-smoke", "returned"), pairs)

        (self.root / "replay-progress.jsonl").unlink()
        rejected, rejected_progress = self._run_wrapper(
            """
import './dependency.mjs';
export function runSmoke() { return { label: 'unused', status: 'pass', problems: [] }; }
"""
        )
        self.assertEqual(rejected.returncode, 1)
        self.assertIn(b"outside its authenticated closure", rejected.stderr)
        self.assertFalse(rejected_progress.exists())

    def test_observer_is_selected_only_for_the_existing_failure_replay(self):
        prepared = self._prepared()
        self.assertFalse((self.source / "src" / "rs9").exists())
        snapshot = self.tools / "fs-snapshot.mjs"
        snapshot.write_text("export const syntheticSnapshot = true;\n", encoding="utf-8")
        calls = []

        def initial_failure(command, **kwargs):
            calls.append(("initial", list(command), kwargs))
            return subprocess.CompletedProcess(command, 1, b"initial failure", b"")

        def replay_failure(command, **kwargs):
            calls.append(("replay", list(command), kwargs))
            progress = Path(command[command.index("--rs9-replay-progress-file") + 1])
            progress.parent.mkdir(parents=True, exist_ok=True)
            progress.write_text(
                json.dumps({
                    "schema": REPLAY_PROGRESS_SCHEMA,
                    "seq": 1,
                    "stage": "harness",
                    "event": "imported",
                }) + "\n",
                encoding="utf-8",
            )
            return subprocess.CompletedProcess(command, 1, b"replay failure", b"")

        with patch(
            "rs9.application_smoke_diagnostic.RELEASED_NATIVE_RC_SMOKE_SHA256",
            hashlib.sha256((self.tools / "native-rc-smoke.mjs").read_bytes()).hexdigest(),
        ), patch(
            "rs9.application_smoke_diagnostic.RELEASED_NATIVE_RC_SNAPSHOT_SHA256",
            hashlib.sha256(snapshot.read_bytes()).hexdigest(),
        ), patch("subprocess.run", side_effect=initial_failure), patch(
            "rs9.application_smoke_diagnostic._bounded_run", side_effect=replay_failure
        ):
            with self.assertRaises(ContractError):
                from rs9.application_smoke_diagnostic import execute_application_smoke

                execute_application_smoke(
                    prepared=prepared,
                    system="x86_64-linux",
                    launch_root=self.launch_root,
                    diagnostic_replay=True,
                )
        self.assertEqual([kind for kind, _command, _kwargs in calls], ["initial", "replay"])
        self.assertNotIn("--rs9-replay-progress-harness", calls[0][1])
        self.assertIn("--rs9-replay-progress-harness", calls[1][1])
        self.assertNotIn("--timeout-ms", calls[0][1])
        self.assertIn("--timeout-ms", calls[1][1])
        diagnostic = json.loads(
            (self.root / "diagnostics" / "application-smoke-diagnostic.json").read_text(
                encoding="utf-8"
            )
        )
        self.assertEqual(diagnostic["gate_status"], "fail")
        self.assertEqual(diagnostic["replay"]["progress"]["status"], "observed")

    def test_wrapper_error_and_killed_timeout_are_distinct_fixed_progress_outcomes(self):
        error_result, error_progress = self._run_wrapper(
            "export function runSmoke() { throw new Error('synthetic-replay-error'); }\n"
        )
        self.assertEqual(error_result.returncode, 1)
        self.assertIn(b"synthetic-replay-error", error_result.stderr)
        error_pairs = [
            (item["stage"], item["event"]) for item in self._read_events(error_progress)
        ]
        self.assertIn(("run-smoke", "enter"), error_pairs)
        self.assertIn(("run-smoke", "error"), error_pairs)
        self.assertNotIn(("run-smoke", "returned"), error_pairs)
        self.assertNotIn(str(self.root), error_progress.read_text(encoding="utf-8"))

        harness = self.root / "native-rc-smoke-timeout.mjs"
        harness.write_text(
            "export async function runSmoke() { await new Promise(() => setInterval(() => {}, 100)); }\n",
            encoding="utf-8",
        )
        progress = self.root / "timeout-progress.jsonl"
        command = [
            self.node,
            str(self.wrapper),
            *self._progress_args(harness, progress),
            "--platform",
            "linux-x64",
            "--scenario",
            "C",
            "--launch-root",
            str(self.launch_root),
            "--checkout",
            str(self.checkout),
            "--evidence",
            str(self.evidence),
            "--label",
            "linux-x64-C",
        ]
        child = subprocess.Popen(
            command,
            cwd=self.root,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        try:
            time.sleep(0.25)
            self.assertIsNone(child.poll())
        finally:
            child.terminate()
            try:
                child.communicate(timeout=2)
            except subprocess.TimeoutExpired:
                child.kill()
                child.communicate(timeout=2)
        timeout_pairs = [
            (item["stage"], item["event"]) for item in self._read_events(progress)
        ]
        self.assertIn(("harness", "imported"), timeout_pairs)
        self.assertIn(("run-smoke", "enter"), timeout_pairs)
        self.assertNotIn(("run-smoke", "returned"), timeout_pairs)


if __name__ == "__main__":
    unittest.main()
