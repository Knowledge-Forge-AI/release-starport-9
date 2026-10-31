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

    def test_current071_required_observation_uses_exact_owner_timeout(self):
        prepared = self._prepared()
        descriptor = {
            "wrapper": self.wrapper,
            "harness": self.tools / "native-rc-smoke.mjs",
            "progress": self.evidence / "initial-progress.jsonl",
            "path": self.evidence / "initial-observation.json",
            "profile": diagnostic_module.CURRENT071_REPLAY_PROGRESS_PROFILE,
            "harness_timeout_ms": diagnostic_module.CURRENT071_REQUIRED_HARNESS_TIMEOUT_MS,
        }
        command = _command(
            prepared, "linux-arm64", "B", self.launch_root, self.evidence,
            extras=False, initial_observation=descriptor,
        )
        self.assertIn("--timeout-ms", command)
        self.assertEqual(command[command.index("--timeout-ms") + 1], "210000")
        with self.assertRaises(ContractError):
            _command(
                prepared, "linux-arm64", "B", self.launch_root, self.evidence,
                extras=False,
                initial_observation={**descriptor, "harness_timeout_ms": 180000},
            )
        legacy = {**descriptor, "profile": diagnostic_module.CURRENT_REPLAY_PROGRESS_PROFILE,
                  "harness_timeout_ms": None}
        legacy_command = _command(
            prepared, "linux-arm64", "B", self.launch_root, self.evidence,
            extras=False, initial_observation=legacy,
        )
        self.assertNotIn("--timeout-ms", legacy_command)

    def test_current071_required_observation_timeout_is_scenario_aware(self):
        prepared = self._prepared()
        cases = (
            ("linux-arm64", "B", 210000),
            ("linux-x64", "C", 210000),
            ("linux-x64", "C-signal", 180000),
        )
        for platform, scenario, expected_timeout in cases:
            with self.subTest(platform=platform, scenario=scenario):
                descriptor = {
                    "wrapper": self.wrapper,
                    "harness": self.tools / "native-rc-smoke.mjs",
                    "progress": self.evidence / (scenario + "-initial-progress.jsonl"),
                    "path": self.evidence / (scenario + "-initial-observation.json"),
                    "profile": diagnostic_module.CURRENT071_REPLAY_PROGRESS_PROFILE,
                    "harness_timeout_ms": expected_timeout,
                }
                command = _command(
                    prepared, platform, scenario, self.launch_root, self.evidence,
                    extras=False, initial_observation=descriptor,
                )
                self.assertEqual(
                    command[command.index("--timeout-ms") + 1], str(expected_timeout)
                )
        with self.assertRaises(ContractError):
            _command(
                prepared, "linux-x64", "C-signal", self.launch_root, self.evidence,
                extras=False,
                initial_observation={
                    "wrapper": self.wrapper,
                    "harness": self.tools / "native-rc-smoke.mjs",
                    "progress": self.evidence / "invalid-progress.jsonl",
                    "path": self.evidence / "invalid-observation.json",
                    "profile": diagnostic_module.CURRENT071_REPLAY_PROGRESS_PROFILE,
                    "harness_timeout_ms": 210000,
                },
            )
        with self.assertRaises(ContractError):
            _command(
                prepared, "linux-x64", "C", self.launch_root, self.evidence,
                extras=False,
                initial_observation={
                    "wrapper": self.wrapper,
                    "harness": self.tools / "native-rc-smoke.mjs",
                    "progress": self.evidence / "missing-budget-progress.jsonl",
                    "path": self.evidence / "missing-budget-observation.json",
                    "profile": diagnostic_module.CURRENT071_REPLAY_PROGRESS_PROFILE,
                    "harness_timeout_ms": None,
                },
            )

    def test_historical070_and_darwin_keep_default_command_paths(self):
        prepared = self._prepared()
        legacy = {
            "wrapper": self.wrapper,
            "harness": self.tools / "native-rc-smoke.mjs",
            "progress": self.evidence / "legacy-progress.jsonl",
            "path": self.evidence / "legacy-observation.json",
            "profile": diagnostic_module.CURRENT_REPLAY_PROGRESS_PROFILE,
            "harness_timeout_ms": None,
        }
        legacy_command = _command(
            prepared, "linux-arm64", "B", self.launch_root, self.evidence,
            extras=False, initial_observation=legacy,
        )
        self.assertNotIn("--timeout-ms", legacy_command)
        darwin_command = _command(
            prepared, "darwin-arm64", "A", self.launch_root, self.evidence,
            extras=False,
        )
        self.assertNotIn("xvfb-run", darwin_command)
        self.assertNotIn("dbus-run-session", darwin_command)
        self.assertNotIn("--timeout-ms", darwin_command)

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


class Current071InitialEnvObservationTests(unittest.TestCase):
    """Focused current071 initial-observation environment-presence and fault-isolation tests."""

    def setUp(self) -> None:
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name).resolve()
        self.source = self.root / "source"
        self.tools = self.source / "tools"
        self.tools.mkdir(parents=True)
        self.evidence = self.root / "evidence"
        self.evidence.mkdir()
        self.node = shutil.which("node")
        self.assertIsNotNone(self.node)
        self.profile = json.loads(json.dumps(diagnostic_module.CURRENT071_REPLAY_PROGRESS_PROFILE))
        for name in self.profile["modules"]:
            (self.tools / name).write_text("export const fixture = true;\n", encoding="utf-8")
        (self.source / "package.json").write_text('{"version":"0.7.1"}\n', encoding="utf-8")
        self.wrapper = self.root / "wrapper071.mjs"

    @staticmethod
    def _pin(data: bytes) -> dict[str, object]:
        return {
            "sha256": hashlib.sha256(data).hexdigest(),
            "blob": hashlib.sha1(b"blob " + str(len(data)).encode() + b"\0" + data).hexdigest(),
            "size": len(data),
        }

    def _seal_harness(self, body: str, *, profile_const: str = "CURRENT071_PROFILE") -> None:
        names = list(self.profile["modules"])
        imports = "".join(
            f"import './{name}';\n" for name in names if name != "native-rc-smoke.mjs"
        )
        (self.tools / "native-rc-smoke.mjs").write_text(imports + body, encoding="utf-8")
        self.profile["modules"] = {
            name: self._pin((self.tools / name).read_bytes()) for name in names
        }
        self.profile["support"] = self._pin((self.source / "package.json").read_bytes())
        original = Path(diagnostic_module.__file__).with_name("replay_progress_wrapper.mjs").read_text(encoding="utf-8")
        marker = f"const {profile_const} = Object.freeze("
        start = original.index(marker)
        end = original.index(");\n", start) + 3
        self.wrapper.write_text(
            original[:start] + marker + json.dumps(self.profile) + ");\n" + original[end:],
            encoding="utf-8",
        )

    def _initial_command(self, observation_path: Path, *, timeout_ms: int = 210000, preload: Path | None = None) -> list[str]:
        p = self.profile
        cmd = [self.node]
        if preload is not None:
            cmd += ["--import", str(preload)]
        cmd += [
            str(self.wrapper),
            "--rs9-replay-progress-harness",
            str(self.tools / "native-rc-smoke.mjs"),
            "--rs9-replay-progress-file",
            str(self.root / "unused-progress.jsonl"),
            "--rs9-replay-progress-expected-sha256",
            p["modules"]["native-rc-smoke.mjs"]["sha256"],
            "--rs9-initial-observation-kind",
            "initial-observation",
            "--rs9-initial-observation-file",
            str(observation_path),
            "--rs9-replay-progress-profile",
            p["id"],
            "--rs9-replay-progress-source-commit",
            p["commit"],
            "--rs9-replay-progress-source-tree",
            p["tree"],
            "--rs9-replay-progress-support-member",
            "package.json=" + p["support"]["sha256"],
        ]
        for name, row in p["modules"].items():
            cmd += ["--rs9-replay-progress-closure-member", f"{name}={row['sha256']}"]
        cmd += [
            "--platform",
            "linux-x64",
            "--scenario",
            "C",
            "--launch-root",
            str(self.root / "launch"),
            "--checkout",
            str(self.source),
            "--evidence",
            str(self.evidence),
            "--label",
            "linux-x64-C",
            "--timeout-ms",
            str(timeout_ms),
        ]
        return cmd

    def test_current071_records_boolean_env_presence_at_entry_and_first_spawn_only(self) -> None:
        secret = "PRIVATE_ENV_SECRET_VALUE_88319"
        preload = self.root / "spy-preload.mjs"
        preload.write_text(
            """import childProcess from 'node:child_process';
const realSpawn = childProcess.spawn;
globalThis.__spawnRecords = [];
childProcess.spawn = function(...args) {
  globalThis.__spawnRecords.push({argCount: args.length, argsRef: args[1], optionsRef: args[2], envRef: args[2]?.env});
  return realSpawn.apply(this, args);
};
""",
            encoding="utf-8",
        )
        self._seal_harness(
            """import {spawn} from 'node:child_process';
import {writeFileSync} from 'node:fs';
import {join} from 'node:path';
export async function runSmoke(options) {
  const spawnArgs = ['-e', "process.stdout.write('CHILD_OUT');process.stderr.write('TFSB Studio release smoke scenario C active\\\\n');"];
  const firstEnv = {
    PATH: process.env.PATH,
    DBUS_SESSION_BUS_ADDRESS: 'unix:path=/tmp/' + 'PRIVATE_ENV_SECRET_VALUE_88319',
    DISPLAY: ':99',
    LD_LIBRARY_PATH: '',
  };
  const spawnOpts = {env: firstEnv, stdio: ['ignore', 'pipe', 'pipe']};
  const child = spawn(process.execPath, spawnArgs, spawnOpts);
  let out = '', err = '';
  child.stdout.on('data', d => out += d);
  child.stderr.on('data', d => err += d);
  await new Promise(r => child.once('exit', r));
  const secondChild = spawn(process.execPath, ['-e', 'process.exit(0)'], {
    env: {PATH: process.env.PATH, LD_LIBRARY_PATH: '/should/not/overwrite'},
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  await new Promise(r => secondChild.once('exit', r));
  const firstRecord = globalThis.__spawnRecords[0];
  writeFileSync(join(options.evidenceDir, 'parity.json'), JSON.stringify({
    sameArgsRef: firstRecord.argsRef === spawnArgs,
    sameOptionsRef: firstRecord.optionsRef === spawnOpts,
    sameEnvRef: firstRecord.envRef === firstEnv,
    out,
    err,
  }));
  return {label: options.label, status: 'fail', problems: ['no receipt was written']};
}
"""
        )
        obs_path = self.root / "initial-observation.json"
        env = dict(os.environ)
        for key in diagnostic_module.INITIAL_ENV_KEYS:
            env[key] = f"/private/{secret}/{key}"
        env["GIO_EXTRA_MODULES"] = ""
        env["FONTCONFIG_FILE"] = ""
        result = subprocess.run(
            self._initial_command(obs_path, preload=preload),
            env=env,
            capture_output=True,
            timeout=10,
            check=False,
        )
        self.assertEqual(result.returncode, 1, result.stderr)
        parity = json.loads((self.evidence / "parity.json").read_bytes())
        self.assertTrue(parity["sameArgsRef"])
        self.assertTrue(parity["sameOptionsRef"])
        self.assertTrue(parity["sameEnvRef"])
        self.assertEqual(parity["out"], "CHILD_OUT")
        self.assertEqual(parity["err"], "TFSB Studio release smoke scenario C active\n")

        raw = obs_path.read_bytes()
        self.assertNotIn(secret.encode("utf-8"), raw)
        self.assertNotIn(b"/private/", raw)
        observed = diagnostic_module._read_initial_observation(obs_path, expected_profile=self.profile)
        self.assertEqual(observed["status"], "failed")
        self.assertEqual(observed["error_counts"], {"observer-fault": 0, "stream-fault": 0, "write-failure": 0})
        self.assertEqual(
            observed["environment_presence"],
            {
                "wrapper_entry": {
                    "LD_LIBRARY_PATH": True,
                    "XDG_DATA_DIRS": True,
                    "GIO_EXTRA_MODULES": False,
                    "GDK_PIXBUF_MODULE_FILE": True,
                    "GSETTINGS_SCHEMA_DIR": True,
                    "FONTCONFIG_FILE": False,
                    "PATH": True,
                    "DBUS_SESSION_BUS_ADDRESS": True,
                    "DISPLAY": True,
                },
                "first_spawn": {
                    "LD_LIBRARY_PATH": False,
                    "XDG_DATA_DIRS": False,
                    "GIO_EXTRA_MODULES": False,
                    "GDK_PIXBUF_MODULE_FILE": False,
                    "GSETTINGS_SCHEMA_DIR": False,
                    "FONTCONFIG_FILE": False,
                    "PATH": True,
                    "DBUS_SESSION_BUS_ADDRESS": True,
                    "DISPLAY": True,
                },
            },
        )

    def test_current071_getter_proxy_and_malformed_cases_isolate_observer_faults(self) -> None:
        secret = "PRIVATE_TRAP_SECRET_77412"
        # 1. Proxy env that throws on observer read after originalSpawn consumes env
        self._seal_harness(
            """import {spawn} from 'node:child_process';
export async function runSmoke(options) {
  let reads = 0;
  const baseEnv = {PATH: process.env.PATH, DISPLAY: ':99'};
  const proxyEnv = new Proxy(baseEnv, {
    get(target, prop, receiver) {
      if (prop === 'LD_LIBRARY_PATH') {
        reads += 1;
        if (reads >= 1) throw new Error('PRIVATE_TRAP_SECRET_77412');
      }
      return Reflect.get(target, prop, receiver);
    },
  });
  const child = spawn(process.execPath, ['-e', 'process.exit(0)'], {
    env: proxyEnv,
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  if (reads !== 0) throw new Error('OBSERVER_PROXY_SIDE_EFFECT');
  await new Promise(r => child.once('exit', r));
  return {label: options.label, status: 'pass', problems: []};
}
"""
        )
        obs_proxy = self.root / "obs-proxy.json"
        res_proxy = subprocess.run(
            self._initial_command(obs_proxy),
            capture_output=True,
            timeout=10,
            check=False,
        )
        self.assertEqual(res_proxy.returncode, 0, res_proxy.stderr)
        self.assertNotIn(secret.encode("utf-8"), obs_proxy.read_bytes())
        self.assertNotIn(secret.encode("utf-8"), res_proxy.stderr)
        parsed_proxy = diagnostic_module._read_initial_observation(obs_proxy, expected_profile=self.profile)
        self.assertEqual(parsed_proxy["status"], "completed")
        self.assertEqual(parsed_proxy["error_counts"]["observer-fault"], 1)
        self.assertIsNotNone(parsed_proxy["environment_presence"]["wrapper_entry"])
        self.assertIsNone(parsed_proxy["environment_presence"]["first_spawn"])

        # 2. Options getter that returns undefined for originalSpawn then throws for observer
        self._seal_harness(
            """import {spawn} from 'node:child_process';
export async function runSmoke(options) {
  let envLookups = 0;
  const opts = {
    stdio: ['ignore', 'pipe', 'pipe'],
    get env() {
      envLookups += 1;
      if (envLookups > 1) throw new Error('PRIVATE_TRAP_SECRET_77412');
      return undefined;
    },
  };
  const child = spawn(process.execPath, ['-e', 'process.exit(0)'], opts);
  if (envLookups !== 1) throw new Error('OBSERVER_GETTER_SIDE_EFFECT');
  await new Promise(r => child.once('exit', r));
  return {label: options.label, status: 'pass', problems: []};
}
"""
        )
        obs_getter = self.root / "obs-getter.json"
        res_getter = subprocess.run(
            self._initial_command(obs_getter),
            capture_output=True,
            timeout=10,
            check=False,
        )
        self.assertEqual(res_getter.returncode, 0, res_getter.stderr)
        parsed_getter = diagnostic_module._read_initial_observation(obs_getter, expected_profile=self.profile)
        self.assertEqual(parsed_getter["error_counts"]["observer-fault"], 1)
        self.assertIsNone(parsed_getter["environment_presence"]["first_spawn"])
        self.assertNotIn(secret.encode("utf-8"), obs_getter.read_bytes())

        # 3. Preload Proxy on process.env that throws on first LD_LIBRARY_PATH lookup at wrapper entry
        entry_preload = self.root / "entry-preload.mjs"
        entry_preload.write_text(
            """let count = 0;
const originalEnv = process.env;
Object.defineProperty(process, 'env', {
  configurable: true,
  enumerable: true,
  value: new Proxy(originalEnv, {
    get(target, prop, receiver) {
      if (prop === 'LD_LIBRARY_PATH') {
        count += 1;
        if (count === 1) throw new Error('PRIVATE_TRAP_SECRET_77412');
      }
      return Reflect.get(target, prop, receiver);
    },
  }),
});
""",
            encoding="utf-8",
        )
        self._seal_harness(
            """import {spawn} from 'node:child_process';
export async function runSmoke(options) {
  const child = spawn(process.execPath, ['-e', 'process.exit(0)'], {
    env: {PATH: process.env.PATH, DISPLAY: ':0'},
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  await new Promise(r => child.once('exit', r));
  return {label: options.label, status: 'pass', problems: []};
}
"""
        )
        obs_entry = self.root / "obs-entry.json"
        res_entry = subprocess.run(
            self._initial_command(obs_entry, preload=entry_preload),
            capture_output=True,
            timeout=10,
            check=False,
        )
        self.assertEqual(res_entry.returncode, 0, res_entry.stderr)
        parsed_entry = diagnostic_module._read_initial_observation(obs_entry, expected_profile=self.profile)
        self.assertEqual(parsed_entry["error_counts"]["observer-fault"], 1)
        self.assertIsNone(parsed_entry["environment_presence"]["wrapper_entry"])
        self.assertTrue(parsed_entry["environment_presence"]["first_spawn"]["DISPLAY"])
        self.assertFalse(parsed_entry["environment_presence"]["first_spawn"]["LD_LIBRARY_PATH"])
        self.assertNotIn(secret.encode("utf-8"), obs_entry.read_bytes())

        # 4. Node normalizeSpawnArguments parity when args[1] is a non-array options object and args.length >= 3
        self._seal_harness(
            """import {spawn} from 'node:child_process';
export async function runSmoke(options) {
  const child = spawn(
    process.execPath,
    {
      env: {PATH: process.env.PATH, DISPLAY: ':77', LD_LIBRARY_PATH: '/opt/lib'},
      stdio: ['ignore', 'pipe', 'pipe'],
    },
    {env: {PATH: process.env.PATH, DISPLAY: ''}},
  );
  await new Promise(r => child.once('exit', r));
  return {label: options.label, status: 'pass', problems: []};
}
"""
        )
        obs_norm = self.root / "obs-norm.json"
        res_norm = subprocess.run(
            self._initial_command(obs_norm),
            capture_output=True,
            timeout=10,
            check=False,
        )
        self.assertEqual(res_norm.returncode, 0, res_norm.stderr)
        parsed_norm = diagnostic_module._read_initial_observation(obs_norm, expected_profile=self.profile)
        self.assertEqual(parsed_norm["error_counts"]["observer-fault"], 0)
        self.assertTrue(parsed_norm["environment_presence"]["first_spawn"]["DISPLAY"])
        self.assertTrue(parsed_norm["environment_presence"]["first_spawn"]["LD_LIBRARY_PATH"])

    def test_current071_observation_does_not_invoke_accessors_or_proxy_traps(self) -> None:
        cases = {
            "env-accessor": ("""
  env = {PATH: process.env.PATH, get DISPLAY() { reads += 1; return ':91'; }};
  options = {env, stdio: 'ignore'};
""", 1, None),
            "options-proxy": ("""
  env = {PATH: process.env.PATH, DISPLAY: ':91'};
  options = new Proxy({env, stdio: 'ignore'}, {
    getOwnPropertyDescriptor(target, key) {
      if (key === 'env') reads += 1;
      return Reflect.getOwnPropertyDescriptor(target, key);
    },
  });
""", 1, None),
            "inherited-options-accessor": ("""
  options = Object.create({get env() { reads += 1; throw Error('OBSERVER_SIDE_EFFECT'); }});
  options.stdio = 'ignore';
""", 0, "default"),
            "nonenumerable-options-accessor": ("""
  options = {stdio: 'ignore'};
  Object.defineProperty(options, 'env', {get() { reads += 1; throw Error('OBSERVER_SIDE_EFFECT'); }});
""", 0, "default"),
            "null-environment-default": ("options = {env: null, stdio: 'ignore'};", 0, "default"),
            "false-environment-default": ("options = {env: false, stdio: 'ignore'};", 0, "default"),
            "zero-environment-default": ("options = {env: 0, stdio: 'ignore'};", 0, "default"),
            "empty-environment-default": ("options = {env: '', stdio: 'ignore'};", 0, "default"),
            "inherited-environment-data": ("""
  env = Object.create({DISPLAY: ':91'});
  env.PATH = process.env.PATH;
  options = {env, stdio: 'ignore'};
""", 0, True),
            "nonenumerable-environment-data": ("""
  env = {PATH: process.env.PATH};
  Object.defineProperty(env, 'DISPLAY', {value: ':91'});
  options = {env, stdio: 'ignore'};
""", 0, False),
        }
        for name, (setup, expected_reads, expected_display) in cases.items():
            with self.subTest(name=name):
                self._seal_harness("""import {spawn} from 'node:child_process';
export async function runSmoke(optionsInput) {
  let reads = 0, env, options;
""" + setup + """
  const child = spawn(process.execPath, ['-e', 'process.exit(0)'], options);
  await new Promise(resolve => child.once('exit', resolve));
  if (reads !== EXPECTED_READS) throw Error('OBSERVER_SIDE_EFFECT');
  return {label: optionsInput.label, status: 'pass', problems: []};
}
""".replace("EXPECTED_READS", str(expected_reads)))
                observed_path = self.root / (name + ".json")
                result = subprocess.run(self._initial_command(observed_path), capture_output=True,
                                        timeout=10, check=False)
                self.assertEqual(result.returncode, 0, result.stderr)
                observed = diagnostic_module._read_initial_observation(observed_path, expected_profile=self.profile)
                first = observed["environment_presence"]["first_spawn"]
                if expected_display is None:
                    self.assertIsNone(first)
                    self.assertEqual(observed["error_counts"]["observer-fault"], 1)
                else:
                    self.assertIsInstance(first, dict)
                    self.assertEqual(observed["error_counts"]["observer-fault"], 0)
                    if expected_display != "default":
                        self.assertIs(first["DISPLAY"], expected_display)


if __name__ == "__main__":
    unittest.main()
