"""Focused unit tests for the current Linux Nix caller and execution-source provenance join."""
import copy
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from rs9 import (
    application_smoke_diagnostic as diagnostic, current_os071 as pins,
    hosted_nix, hosted_smoke, signing_fixture,
)
from rs9.current_generation import CURRENT_GENERATION, HISTORICAL_GENERATION
from rs9.errors import ContractError
from rs9.scratch import canonical

FIXTURE_SMOKE_PATH = Path(__file__).resolve().parent / "fixtures" / "current071-native-rc-smoke.mjs.txt"
EMPTY_SHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
_REAL_SUBPROCESS_RUN = subprocess.run
COMPLETE_PHASE_EVENTS = [
    {"seq": idx, "stage": stage, "event": event}
    for idx, (stage, event) in enumerate([
        ("harness", "import-start"), ("harness", "imported"), ("run-smoke", "enter"),
        ("candidate", "launched"), ("candidate", "exited"), ("receipt", "write-start"),
        ("receipt", "finalized"), ("run-record", "write-start"), ("run-record", "finalized"),
        ("run-smoke", "returned"),
    ], 1)
]


def _pin_bytes(raw):
    blob = hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest()
    return {"sha256": hashlib.sha256(raw).hexdigest(), "blob": blob, "size": len(raw)}


def _full_env_presence(*, entry_ok=True, spawn_ok=True):
    entry = {key: True for key in diagnostic.INITIAL_ENV_KEYS}
    spawn = {key: False for key in diagnostic.INITIAL_ENV_KEYS}
    for key in diagnostic.CURRENT_NIX_RESTORED_ENV_KEYS:
        entry[key] = entry_ok
        spawn[key] = spawn_ok
    return {"wrapper_entry": entry, "first_spawn": spawn}


def _completed_observation_doc(profile=None, *, include_transform=True, status="completed"):
    selected = pins.CURRENT071_REPLAY_PROGRESS_PROFILE if profile is None else profile
    stream = {"bytes_seen": 0, "bytes_hashed": 0, "sha256": EMPTY_SHA256, "truncated": False}
    doc = {
        "schema": diagnostic.INITIAL_OBSERVATION_SCHEMA, "attempt_kind": diagnostic.INITIAL_OBSERVATION_KIND,
        "non_admitting": True, "status": status,
        "source_profile": diagnostic._initial_observation_profile(selected),
        "phase_events": copy.deepcopy(COMPLETE_PHASE_EVENTS),
        "error_counts": {"observer-fault": 0, "stream-fault": 0, "write-failure": 0},
        "error_category_counts": {key: 0 for key in diagnostic.INITIAL_ERROR_CATEGORIES},
        "helper_identifier_counts": {key: 0 for key in diagnostic.INITIAL_HELPER_IDENTIFIERS},
        "streams": {"stdout": dict(stream), "stderr": dict(stream)}, "truncated": False,
        "environment_presence": _full_env_presence(entry_ok=True, spawn_ok=True),
    }
    if include_transform:
        doc["execution_transform"] = copy.deepcopy(diagnostic.EXPECTED_CURRENT_NIX_EXECUTION_TRANSFORM)
    return doc


def _build_node_mock_spawn(probe_path):
    return f"""import childProcess from "node:child_process";
import {{ EventEmitter }} from "node:events";
import fs from "node:fs";
import {{ syncBuiltinESMExports }} from "node:module";
const probePath = {json.dumps(str(probe_path))};
childProcess.spawn = function mockSpawn(_cmd, _args, options = {{}}) {{
  const env = options.env || {{}};
  if (process.env.RS9_TEST_DROP_SPAWN_FONTCONFIG === "1") delete env.FONTCONFIG_FILE;
  fs.writeFileSync(probePath, JSON.stringify({{ xdg: Boolean(env.XDG_DATA_DIRS), fontconfig: Boolean(env.FONTCONFIG_FILE), ld: Boolean(env.LD_LIBRARY_PATH), token: Boolean(env.RS9_GITHUB_READ_TOKEN) }}));
  const exitCode = process.env.RS9_TEST_CHILD_EXIT === "1" ? 1 : 0;
  const child = Object.assign(new EventEmitter(), {{ pid: 424242, exitCode: null, stdout: new EventEmitter(), stderr: new EventEmitter() }});
  queueMicrotask(() => {{ child.exitCode = exitCode; child.emit("exit", exitCode, null); }});
  return child;
}};
childProcess.spawnSync = () => ({{ stdout: "", stderr: "", status: 0 }});
syncBuiltinESMExports();
"""


def _build_node_sibling_sources(sandbox_root):
    b_steps = ["app-shell", "app-theme-status", "app-theme-compile", "theme-lab-compile", "brand-system-view", "host-start", "host-status", "project-open-upper", "brand-read-upper", "project-open-lower", "brand-read-lower", "host-status-final"]
    fs_snapshot = f"""import childProcess from "node:child_process";
import fs from "node:fs";
import {{ syncBuiltinESMExports }} from "node:module";
import os from "node:os";
const sandboxTmp = {json.dumps(str(sandbox_root / "guest-tmp"))}, sandboxHome = {json.dumps(str(sandbox_root / "guest-home"))};
const steps = {json.dumps([{"id": s, "ok": True, "via": "ipc", "ms": 1} for s in b_steps])};
fs.mkdirSync(sandboxTmp, {{ recursive: true }}); fs.mkdirSync(sandboxHome, {{ recursive: true }});
const origMkdirSync = fs.mkdirSync, origReaddirSync = fs.readdirSync, origCpSync = fs.cpSync;
fs.mkdirSync = (t, o) => (typeof t === "string" && t.includes("case-probe-") ? origMkdirSync(t, {{ recursive: true }}) : origMkdirSync(t, o));
fs.readdirSync = (t, o) => (typeof t === "string" && t.includes("case-probe-") ? ["Probe", "probe"] : origReaddirSync(t, o));
fs.cpSync = (s, d, o) => origCpSync(s, d, {{ ...o, errorOnExist: false, force: true }});
os.tmpdir = () => sandboxTmp; os.homedir = () => sandboxHome;
childProcess.spawnSync = () => ({{ stdout: "", stderr: "", status: 0 }});
syncBuiltinESMExports();
export function readRegularSnapshot(filePath) {{
  if (String(filePath).endsWith("receipt.json")) {{
    const bytes = Buffer.from(JSON.stringify({{ schema: "nebular.release-smoke-receipt-v1", scenario: "B", status: process.env.RS9_TEST_CHILD_EXIT === "1" ? "fail" : "pass", pid: 424242, target: "aarch64-unknown-linux-gnu", awaitingSignal: false, executable: {{ sha256: "a".repeat(64) }}, driver: {{ steps }} }}), "utf8");
    return {{ bytes, sha256: "c".repeat(64), size: bytes.length, executable: false, mode: 0o600 }};
  }}
  const bytes = Buffer.from("launcher", "utf8");
  return {{ bytes, sha256: "a".repeat(64), size: bytes.length, executable: true, mode: 0o755 }};
}}
"""
    return {
        "fs-snapshot.mjs": fs_snapshot,
        "native-launcher.mjs": 'export const nativeLauncher = () => "launcher";\n',
        "native-rc-package.mjs": "export const verifyPlatformPackage = () => ({});\n",
        "native-runtime.mjs": 'import "./candidate-provenance.mjs";\nimport "./platform-targets.mjs";\nexport const selectPayloadNativeRuntime = async () => ({ nativeRuntime: "stub" });\n',
        "candidate-provenance.mjs": 'export const provenance = "stub";\n',
        "platform-targets.mjs": 'export const targets = "stub";\n',
    }


class CurrentNixExecutionProvenanceTests(unittest.TestCase):
    def setUp(self):
        gpg_patch = patch.object(signing_fixture, "find_gpg_binary", side_effect=AssertionError("GPG forbidden"))
        gpg_patch.start()
        self.addCleanup(gpg_patch.stop)
        temp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(temp_dir.cleanup)
        self.root = Path(temp_dir.name).resolve()
        self.source = self.root / "source"
        self.tools = self.source / "tools"
        self.tools.mkdir(parents=True)
        self.scratch = self.root / "scratch"
        self.evidence = self.scratch / "evidence"
        self.evidence.mkdir(parents=True)
        self.launch_root = self.root / "launch-root"
        (self.launch_root / "bin").mkdir(parents=True)
        (self.launch_root / "lib/sidecar-payload").mkdir(parents=True)
        (self.launch_root / "bin/tfsb-studio-service").write_bytes(b"sidecar")
        (self.launch_root / "lib/sidecar-payload/manifest.json").write_bytes(b"[]")
        self._install_node_fixture()

    def _install_node_fixture(self):
        (self.tools / "native-rc-smoke.mjs").write_bytes(FIXTURE_SMOKE_PATH.read_bytes())
        (self.tools / "sidecar-common.mjs").write_text("// common\n", encoding="utf-8")
        for name, text in _build_node_sibling_sources(self.root).items():
            (self.tools / name).write_text(text, encoding="utf-8")
        (self.source / "package.json").write_text('{"version":"0.7.1"}\n', encoding="utf-8")
        fixture_dir = self.source / "docs/examples/v0.4/brand-system/core-minimal/.tfsb"
        fixture_dir.mkdir(parents=True, exist_ok=True)
        for name, text in (
            ("project.toml", 'name = "core-fixture"\n'), ("brand.toml", 'name = "Core Fixture Brand"\npackage = true\n'),
            ("brand-package.toml", "schema_version = 1\n"), ("GUIDANCE.md", "guidance\n"),
        ):
            (fixture_dir / name).write_text(text, encoding="utf-8")
        self.profile = copy.deepcopy(pins.CURRENT071_REPLAY_PROGRESS_PROFILE)
        for name in self.profile["modules"]:
            if name != "native-rc-smoke.mjs":
                self.profile["modules"][name] = _pin_bytes((self.tools / name).read_bytes())
        self.profile["support"] = _pin_bytes((self.source / "package.json").read_bytes())
        src_dir = Path(diagnostic.__file__).resolve().parent
        wrapper_text = (src_dir / "replay_progress_wrapper.mjs").read_text(encoding="utf-8")
        marker = "const CURRENT071_PROFILE = Object.freeze("
        start = wrapper_text.index(marker) + len(marker)
        end = wrapper_text.index(");\n", start)
        self.wrapper = self.root / "replay_progress_wrapper.mjs"
        self.wrapper.write_text(wrapper_text[:start] + json.dumps(self.profile) + wrapper_text[end:], encoding="utf-8")
        shutil.copyfile(src_dir / "current_nix_smoke_environment.mjs", self.root / "current_nix_smoke_environment.mjs")
        self.mock_spawn = self.root / "mock-spawn.mjs"
        self.mock_spawn.write_text(_build_node_mock_spawn(self.root / "spawn-probe.json"), encoding="utf-8")
        (self.launch_root / "bin/tfnf").write_text("launcher\n", encoding="utf-8")
        (self.launch_root / "bin/theme-forge-nebular-fusion").write_text("launcher\n", encoding="utf-8")

    def _prepared(self):
        return {
            "source_generation": CURRENT_GENERATION, "source": self.source,
            "checkout": self.source, "tools": self.tools, "scratch": self.scratch,
            "capture": SimpleNamespace(record={"payloads": []}), "fixture_capture": object(),
            "records": [{"id": "nebular071", "harness_sha256": diagnostic.CURRENT071_UPSTREAM_HARNESS_SHA256}],
        }

    def _run_synthetic_smoke(self, obs_writer, *, system="x86_64-linux", transform=True, rc=0, receipt_status="pass"):
        def fake_run(argv, **_kwargs):
            scenario = argv[argv.index("--scenario") + 1]
            platform = argv[argv.index("--platform") + 1]
            raw = canonical({"status": receipt_status, "problems": [] if receipt_status == "pass" else ["exit-code-mismatch"],
                             "executable": {"sha256": "a" * 64}})
            (self.evidence / f"{platform}-{scenario}.run.json").write_bytes(raw)
            if "--rs9-initial-observation-file" in argv:
                obs_path = Path(argv[argv.index("--rs9-initial-observation-file") + 1])
                obs_writer(obs_path, platform, scenario)
            return SimpleNamespace(returncode=rc, stdout=b"", stderr=b"")

        with patch.object(diagnostic, "_replay_progress_wrapper", return_value=self.wrapper), \
             patch.object(diagnostic, "_current_replay_progress_profile", return_value=pins.CURRENT071_REPLAY_PROGRESS_PROFILE), \
             patch.object(diagnostic.subprocess, "run", side_effect=fake_run), \
             patch.object(diagnostic, "_bounded_run", side_effect=AssertionError("Replay must not run")):
            return diagnostic.execute_application_smoke(
                prepared=self._prepared(), system=system, launch_root=self.launch_root,
                diagnostic_initial_observation=True, current_nix_environment_transform=transform,
                diagnostic_replay=True,
            )

    def test_caller_selection_only_authenticated_current_linux_nix_enables_transform(self):
        dbus_facts = {
            "dbus_run_session": "/nix/store/" + "a" * 32 + "-dbus-1/bin/dbus-run-session",
            "dbus_daemon": "/nix/store/" + "a" * 32 + "-dbus-1/bin/dbus-daemon",
            "dbus_session_config": "/nix/store/" + "a" * 32 + "-dbus-1/share/dbus-1/session.conf",
        }
        prepared = self._prepared()
        for system, generation, prep, expected in (
            ("x86_64-linux", CURRENT_GENERATION, prepared, True), ("aarch64-linux", CURRENT_GENERATION, prepared, True),
            ("x86_64-linux", HISTORICAL_GENERATION, prepared, False), ("aarch64-linux", HISTORICAL_GENERATION, prepared, False),
            ("aarch64-darwin", CURRENT_GENERATION, prepared, False),
            ("x86_64-linux", CURRENT_GENERATION, {**prepared, "capture": None}, False),
            ("x86_64-linux", CURRENT_GENERATION, {**prepared, "fixture_capture": None}, False),
            ("x86_64-linux", CURRENT_GENERATION, {**prepared, "source_generation": HISTORICAL_GENERATION}, False),
        ):
            with patch.object(hosted_nix, "verify_nebular_runtime", return_value={"status": "pass"}) as mock_verify:
                hosted_nix._verify_final_nebular_runtime(
                    self.launch_root, prep, system, [], [], {}, None, dbus_facts, generation)
                self.assertEqual((mock_verify.call_args.kwargs["diagnostic_initial_observation"],
                                  mock_verify.call_args.kwargs["current_nix_environment_transform"]), (expected, expected))
        for bad_opt in ("true", 1, None):
            with self.assertRaises(ContractError):
                hosted_smoke.verify_nebular_runtime(self.launch_root, prepared, "x86_64-linux", current_nix_environment_transform=bad_opt)
            with self.assertRaises(ContractError):
                diagnostic.execute_application_smoke(prepared=prepared, system="x86_64-linux", launch_root=self.launch_root,
                                                     diagnostic_initial_observation=True, current_nix_environment_transform=bad_opt)

    def test_untransformed_projection_stays_byte_compatible_and_transformed_retains_provenance(self):
        untransformed = self._run_synthetic_smoke(
            lambda path, _plat, _scen: path.write_text(
                json.dumps(_completed_observation_doc(include_transform=False)), encoding="utf-8"),
            transform=False,
        )
        self.assertEqual([row["scenario"] for row in untransformed], ["C", "C-signal"])
        for row in untransformed:
            self.assertEqual(set(row), {"scenario", "receipt_sha256", "executable_sha256"})
        self.assertIsNone(diagnostic._project_restored_environment_presence(
            {"wrapper_entry": {"XDG_DATA_DIRS": True, "FONTCONFIG_FILE": True},
             "first_spawn": {"XDG_DATA_DIRS": True, "FONTCONFIG_FILE": True}}))
        for bad_src in (None, {}, {"schema": diagnostic.CURRENT_NIX_EXECUTION_SOURCE_SCHEMA}):
            for tx_flag in (False, True):
                if not tx_flag and bad_src is None:
                    continue
                with self.assertRaises(ContractError):
                    diagnostic._scenario_run_projection(
                        "C", {"receipt": {"sha256": "a" * 64, "executable_sha256": "b" * 64}, "execution_source": bad_src},
                        environment_transform=tx_flag,
                    )
        for system, expected_scenarios in (("x86_64-linux", ["C", "C-signal"]), ("aarch64-linux", ["B"])):
            runs = self._run_synthetic_smoke(
                lambda path, _plat, _scen: path.write_text(
                    json.dumps(_completed_observation_doc(include_transform=True)), encoding="utf-8"),
                system=system, transform=True,
            )
            self.assertEqual([row["scenario"] for row in runs], expected_scenarios)
            for row in runs:
                src = row["execution_source"]
                self.assertEqual((src["schema"], src["status"], src["non_admitting"]),
                                 (diagnostic.CURRENT_NIX_EXECUTION_SOURCE_SCHEMA, "verified", True))
                self.assertEqual(src["source_profile"], diagnostic._initial_observation_profile(pins.CURRENT071_REPLAY_PROGRESS_PROFILE))
                self.assertEqual(src["execution_transform"], diagnostic.EXPECTED_CURRENT_NIX_EXECUTION_TRANSFORM)
                self.assertEqual(src["environment_presence"], {
                    "wrapper_entry": {"XDG_DATA_DIRS": True, "FONTCONFIG_FILE": True},
                    "first_spawn": {"XDG_DATA_DIRS": True, "FONTCONFIG_FILE": True},
                })

    def test_transformed_success_fails_closed_on_missing_forged_or_incomplete_provenance(self):
        base = _completed_observation_doc(include_transform=True)
        bad_profile = copy.deepcopy(base)
        bad_profile["source_profile"]["harness_sha256"] = diagnostic.CURRENT071_DERIVED_HARNESS_SHA256
        bad_docs = [
            None, bad_profile,
            _completed_observation_doc(profile=diagnostic.CURRENT_REPLAY_PROGRESS_PROFILE, include_transform=True),
            {**copy.deepcopy(base), "status": "failed"}, {**copy.deepcopy(base), "truncated": True},
            {**copy.deepcopy(base), "phase_events": COMPLETE_PHASE_EVENTS[:-1]},
            {**copy.deepcopy(base), "error_counts": {"observer-fault": 1, "stream-fault": 0, "write-failure": 0}},
            {**copy.deepcopy(base), "environment_presence": _full_env_presence(entry_ok=False, spawn_ok=True)},
            {**copy.deepcopy(base), "environment_presence": _full_env_presence(entry_ok=True, spawn_ok=False)},
            {**copy.deepcopy(base), "environment_presence": {"wrapper_entry": None, "first_spawn": None}},
            _completed_observation_doc(include_transform=False),
        ]
        for patch_tx in (
            {"transform_id": "wrong"}, {"upstream_sha256": diagnostic.CURRENT071_DERIVED_HARNESS_SHA256},
            {"executed_derived_sha256": diagnostic.CURRENT071_UPSTREAM_HARNESS_SHA256},
            {"upstream_bytes": "30732"}, {"restored_env_keys": ["XDG_DATA_DIRS"]},
            {"modified_from_upstream": False}, {"non_admitting": False}, {"fhs_origin_proven": True},
            {"native_qualified": True}, {"causal_attribution_proven": True}, {"extra": 1},
        ):
            doc = copy.deepcopy(base)
            doc["execution_transform"].update(patch_tx)
            bad_docs.append(doc)
        for bad_doc in bad_docs:
            def writer(path, _plat, _scen, payload=bad_doc):
                if payload is not None:
                    path.write_text(json.dumps(payload), encoding="utf-8")
            with self.assertRaises(ContractError) as caught:
                self._run_synthetic_smoke(writer, transform=True, rc=0, receipt_status="pass")
            self.assertEqual((caught.exception.code, caught.exception.details["reason_token"]),
                             ("APPLICATION_SMOKE", "execution-source-unverified"))
            retained = json.loads((self.scratch.parent / "diagnostics/application-smoke-diagnostic.json").read_text(encoding="utf-8"))
            self.assertEqual((retained["gate_status"], retained["replay"]["status"]), ("fail", "not-run"))
            self.assertEqual(retained["initial_run"]["cause"], "execution-source-unverified")
            self.assertEqual(retained["initial_run"]["execution_source"]["status"], "failed")
            if isinstance(bad_doc, dict) and bad_doc.get("status") == "failed":
                self.assertEqual(retained["initial_run"]["execution_source"]["reason"], "initial-observation-not-completed")

    def test_transformed_app_failure_preserves_original_cause_and_suppresses_replay(self):
        untx_obs = {**_completed_observation_doc(include_transform=False, status="completed"), "truncated": True}
        untx_fields = {"error": None, "stream_capture_complete": True, "raw_returncode": 1,
                       "cleanup_error": None, "initial_observation": untx_obs}
        self.assertTrue(diagnostic._original_replay_cleanup_proven(untx_fields))
        self.assertEqual(diagnostic._original_replay_skip_reason(
            {**untx_fields, "initial_observation": {**untx_obs, "status": "failed"}}), "original-harness-not-passed")
        with self.assertRaises(ContractError) as caught:
            self._run_synthetic_smoke(
                lambda path, _plat, _scen: path.write_text(
                    json.dumps(_completed_observation_doc(include_transform=True, status="failed")), encoding="utf-8"),
                transform=True, rc=1, receipt_status="fail",
            )
        self.assertEqual(caught.exception.details["reason_token"], "process-nonzero")
        diag_path = self.scratch.parent / "diagnostics/application-smoke-diagnostic.json"
        retained = json.loads(diag_path.read_text(encoding="utf-8"))
        self.assertEqual(retained["initial_run"]["cause"], "process-nonzero")
        self.assertEqual(retained["initial_run"]["execution_source"]["status"], "verified")
        self.assertEqual((retained["replay"]["status"], retained["replay"]["reason"]), ("not-run", "original-harness-not-passed"))
        incomplete = _completed_observation_doc(include_transform=True, status="partial")
        incomplete["phase_events"] = COMPLETE_PHASE_EVENTS[:4]
        with self.assertRaises(ContractError):
            self._run_synthetic_smoke(
                lambda path, _plat, _scen: path.write_text(json.dumps(incomplete), encoding="utf-8"),
                transform=True, rc=1, receipt_status="fail",
            )
        retained_inc = json.loads(diag_path.read_text(encoding="utf-8"))
        self.assertEqual(retained_inc["initial_run"]["cause"], "process-nonzero")
        self.assertEqual(retained_inc["initial_run"]["execution_source"]["status"], "failed")
        self.assertEqual((retained_inc["replay"]["status"], retained_inc["replay"]["reason"]), ("not-run", "original-cleanup-unproven"))
        no_opt = {**retained_inc, "initial_run": {k: v for k, v in retained_inc["initial_run"].items()
                                                  if k not in ("initial_observation", "harness_problem_categories")}}
        with patch.object(diagnostic, "MAX_DIAGNOSTIC", len(canonical(no_opt)) - 200):
            diagnostic._retain_failure(self._prepared(), "x86_64-linux", "linux-x64", "C", self.launch_root,
                                       (), {}, copy.deepcopy(retained_inc["initial_run"]), ["C-signal"],
                                       include_replay=False, replay_skip_reason="original-cleanup-unproven")
        capped = json.loads(diag_path.read_text(encoding="utf-8"))["initial_run"]["execution_source"]
        self.assertEqual((capped["status"], capped["reason"], capped["omitted"]),
                         ("failed", "initial-observation-incomplete", "diagnostic-size-cap"))

    def test_end_to_end_one_shot_node_custody_through_hosted_nix_and_smoke(self):
        fhs_env = {
            "XDG_DATA_DIRS": "/nix/store/gtk3/share:/nix/store/shared-mime-info/share",
            "FONTCONFIG_FILE": "/nix/store/fontconfig/etc/fonts/fonts.conf",
        }
        drop_spawn = False

        def run_node(argv, **kwargs):
            node_idx = argv.index("node")
            node_argv = [shutil.which("node"), "--import", str(self.mock_spawn), *argv[node_idx + 1:]]
            call_env = {**kwargs.get("env", {}), **fhs_env}
            if drop_spawn:
                call_env["RS9_TEST_DROP_SPAWN_FONTCONFIG"] = "1"
            return _REAL_SUBPROCESS_RUN(node_argv, **{**kwargs, "env": call_env})

        dbus_facts = {
            "dbus_run_session": "/nix/store/" + "a" * 32 + "-dbus-1/bin/dbus-run-session",
            "dbus_daemon": "/nix/store/" + "a" * 32 + "-dbus-1/bin/dbus-daemon",
            "dbus_session_config": "/nix/store/" + "a" * 32 + "-dbus-1/share/dbus-1/session.conf",
        }
        env = {
            "PATH": f"{Path(shutil.which('node')).resolve().parent}{os.pathsep}{os.environ.get('PATH', '')}",
            "DISPLAY": ":99", "DBUS_SESSION_BUS_ADDRESS": "unix:path=/tmp/dbus-test",
            "LD_LIBRARY_PATH": "/nix/store/lib", "RS9_GITHUB_READ_TOKEN": "ghp_synthetic_secret_token_value",
        }
        with patch.object(hosted_smoke, "verifier_import_preflight", return_value={"status": "pass"}), \
             patch.object(hosted_smoke, "_run_verifier", return_value=({"status": "pass"}, {"status": "pass"})), \
             patch.object(hosted_smoke, "expected_runtime_members", return_value=None), \
             patch.object(hosted_smoke, "_control_verifier", return_value={"status": "pass"}), \
             patch.object(diagnostic, "CURRENT071_REPLAY_PROGRESS_PROFILE", self.profile), \
             patch.object(diagnostic, "_replay_progress_wrapper", return_value=self.wrapper), \
             patch.object(diagnostic, "_current_replay_progress_profile", return_value=self.profile), \
             patch.object(diagnostic, "run_boundary_probes", return_value={
                 "schema": diagnostic.PROBE_SCHEMA, "status": "unavailable",
                 "reason": "probe-execution-failed", "qualification_authority": False,
                 "application_qualified": False, "probes": [],
             }), \
             patch.object(diagnostic.subprocess, "run", side_effect=run_node):
            smoke = hosted_nix._verify_final_nebular_runtime(
                self.launch_root, self._prepared(), "aarch64-linux", [], [], env, None, dbus_facts, CURRENT_GENERATION)
            self.assertEqual([row["scenario"] for row in smoke["scenarios"]], ["B"])
            receipt_text = canonical({"schema": "rs9.hosted-nix-output.v1alpha1", "production_enabled": False, "native_smoke": smoke}).decode("utf-8")
            self.assertNotIn("/nix/store/gtk3/share", receipt_text)
            self.assertNotIn("ghp_synthetic_secret_token_value", receipt_text)
            self.assertEqual(smoke["scenarios"][0]["execution_source"]["status"], "verified")
            self.assertEqual(smoke["source_bindings"][0]["harness_sha256"], diagnostic.CURRENT071_UPSTREAM_HARNESS_SHA256)
            drop_spawn = True
            with self.assertRaises(ContractError):
                hosted_nix._verify_final_nebular_runtime(
                    self.launch_root, self._prepared(), "aarch64-linux", [], [], env, None, dbus_facts, CURRENT_GENERATION)


if __name__ == "__main__":
    unittest.main()
