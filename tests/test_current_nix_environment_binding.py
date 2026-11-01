"""Focused unit tests for the inactive current-Nix two-key source derivation seam."""
import copy
import hashlib
import inspect
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from rs9 import (
    application_smoke_diagnostic as diagnostic,
    current_os071 as pins,
    hosted_nix,
    hosted_smoke,
    signing_fixture,
    smoke_source_envelope,
)
from rs9.errors import ContractError

FIXTURE_SMOKE_PATH = Path(__file__).resolve().parent / "fixtures" / "current071-native-rc-smoke.mjs.txt"
EMPTY_SHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
_REAL_SUBPROCESS_RUN = subprocess.run


def _fail_if_gpg_invoked(*_args, **_kwargs):
    raise AssertionError("GPG discovery is forbidden in current-Nix environment binding tests")


signing_fixture.find_gpg_binary = _fail_if_gpg_invoked


def _pin_bytes(raw):
    blob = hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest()
    return {"sha256": hashlib.sha256(raw).hexdigest(), "blob": blob, "size": len(raw)}


def _build_mock_child_spawn_source(probe_path):
    return f"""import childProcess from "node:child_process";
import {{ EventEmitter }} from "node:events";
import fs from "node:fs";
import {{ syncBuiltinESMExports }} from "node:module";
const probePath = {json.dumps(str(probe_path))};
childProcess.spawn = function mockSpawn(_cmd, _args, options = {{}}) {{
  const env = options.env || {{}};
  fs.writeFileSync(probePath, JSON.stringify({{
    xdg: Boolean(env.XDG_DATA_DIRS), fontconfig: Boolean(env.FONTCONFIG_FILE),
    ld: Boolean(env.LD_LIBRARY_PATH), token: Boolean(env.RS9_GITHUB_READ_TOKEN),
  }}));
  const child = Object.assign(new EventEmitter(), {{
    pid: 424242, exitCode: null, stdout: new EventEmitter(), stderr: new EventEmitter(),
  }});
  queueMicrotask(() => {{ child.exitCode = 1; child.emit("exit", 1, null); }});
  return child;
}};
childProcess.spawnSync = () => ({{ stdout: "", stderr: "", status: 0 }});
syncBuiltinESMExports();
"""


def _build_sibling_sources(sandbox_root):
    fs_snapshot = f"""import childProcess from "node:child_process";
import fs from "node:fs";
import {{ syncBuiltinESMExports }} from "node:module";
import os from "node:os";
const sandboxTmp = {json.dumps(str(sandbox_root / "guest-tmp"))};
const sandboxHome = {json.dumps(str(sandbox_root / "guest-home"))};
fs.mkdirSync(sandboxTmp, {{ recursive: true }});
fs.mkdirSync(sandboxHome, {{ recursive: true }});
const origMkdirSync = fs.mkdirSync;
fs.mkdirSync = (t, o) => (typeof t === "string" && t.includes("case-probe-") ? origMkdirSync(t, {{ recursive: true }}) : origMkdirSync(t, o));
const origReaddirSync = fs.readdirSync;
fs.readdirSync = (t, o) => (typeof t === "string" && t.includes("case-probe-") ? ["Probe", "probe"] : origReaddirSync(t, o));
const origCpSync = fs.cpSync;
fs.cpSync = (s, d, o) => origCpSync(s, d, {{ ...o, errorOnExist: false, force: true }});
os.tmpdir = () => sandboxTmp;
os.homedir = () => sandboxHome;
childProcess.spawnSync = () => ({{ stdout: "", stderr: "", status: 0 }});
syncBuiltinESMExports();
export function readRegularSnapshot(filePath) {{
  const isReceipt = String(filePath).endsWith("receipt.json");
  const bytes = Buffer.from(isReceipt ? '{{"status":"fail"}}' : "launcher", "utf8");
  return {{ bytes, sha256: (isReceipt ? "b" : "a").repeat(64), size: bytes.length, executable: !isReceipt, mode: 0o600 }};
}}
"""
    return {
        "fs-snapshot.mjs": fs_snapshot,
        "native-launcher.mjs": 'export const nativeLauncher = () => "launcher";\n',
        "native-rc-package.mjs": "export const verifyPlatformPackage = () => ({});\n",
        "native-runtime.mjs": (
            'import "./candidate-provenance.mjs";\nimport "./platform-targets.mjs";\n'
            'export const selectPayloadNativeRuntime = async () => ({ nativeRuntime: "stub" });\n'
        ),
        "candidate-provenance.mjs": 'export const provenance = "stub";\n',
        "platform-targets.mjs": 'export const targets = "stub";\n',
    }


def _populate_core_fixture(checkout):
    fixture_dir = checkout / "docs/examples/v0.4/brand-system/core-minimal/.tfsb"
    fixture_dir.mkdir(parents=True, exist_ok=True)
    (fixture_dir / "project.toml").write_text('name = "core-fixture"\n', encoding="utf-8")
    (fixture_dir / "brand.toml").write_text('name = "Core Fixture Brand"\npackage = true\n', encoding="utf-8")
    (fixture_dir / "brand-package.toml").write_text("schema_version = 1\n", encoding="utf-8")


def _sample_observation_payload(profile, *, include_transform=False):
    empty_stream = {"bytes_seen": 0, "bytes_hashed": 0, "sha256": EMPTY_SHA256, "truncated": False}
    payload = {
        "schema": diagnostic.INITIAL_OBSERVATION_SCHEMA, "attempt_kind": diagnostic.INITIAL_OBSERVATION_KIND,
        "non_admitting": True, "status": "failed",
        "source_profile": diagnostic._initial_observation_profile(profile),
        "phase_events": [{"seq": 1, "stage": "harness", "event": "import-start"}],
        "error_counts": {"observer-fault": 0, "stream-fault": 0, "write-failure": 0},
        "error_category_counts": {key: 0 for key in diagnostic.INITIAL_ERROR_CATEGORIES},
        "helper_identifier_counts": {key: 0 for key in diagnostic.INITIAL_HELPER_IDENTIFIERS},
        "streams": {"stdout": dict(empty_stream), "stderr": dict(empty_stream)}, "truncated": False,
    }
    if include_transform:
        payload["execution_transform"] = copy.deepcopy(diagnostic.EXPECTED_CURRENT_NIX_EXECUTION_TRANSFORM)
    return payload


class CurrentNixEnvironmentBindingTests(unittest.TestCase):
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
        self._install_closure_sources()
        self._install_wrapper_and_launcher()

    def _install_closure_sources(self):
        (self.tools / "native-rc-smoke.mjs").write_bytes(FIXTURE_SMOKE_PATH.read_bytes())
        for name, text in _build_sibling_sources(self.root).items():
            (self.tools / name).write_text(text, encoding="utf-8")
        (self.source / "package.json").write_text('{"version":"0.7.1"}\n', encoding="utf-8")
        _populate_core_fixture(self.source)
        self.profile = copy.deepcopy(pins.CURRENT071_REPLAY_PROGRESS_PROFILE)
        for name in self.profile["modules"]:
            if name != "native-rc-smoke.mjs":
                self.profile["modules"][name] = _pin_bytes((self.tools / name).read_bytes())
        self.profile["support"] = _pin_bytes((self.source / "package.json").read_bytes())
        self.profile070 = copy.deepcopy(diagnostic.CURRENT_REPLAY_PROGRESS_PROFILE)
        self.profile070["modules"] = copy.deepcopy(self.profile["modules"])
        self.profile070["support"] = _pin_bytes(b'{"version":"0.7.0"}\n')

    def _install_wrapper_and_launcher(self):
        src_dir = Path(diagnostic.__file__).resolve().parent
        wrapper_text = (src_dir / "replay_progress_wrapper.mjs").read_text(encoding="utf-8")
        for marker, profile_obj in (
            ("const CURRENT_PROFILE = Object.freeze(", self.profile070),
            ("const CURRENT071_PROFILE = Object.freeze(", self.profile),
        ):
            start = wrapper_text.index(marker) + len(marker)
            end = wrapper_text.index(");\n", start)
            wrapper_text = wrapper_text[:start] + json.dumps(profile_obj) + wrapper_text[end:]
        self.wrapper = self.root / "replay_progress_wrapper.mjs"
        self.wrapper.write_text(wrapper_text, encoding="utf-8")
        shutil.copyfile(src_dir / "current_nix_smoke_environment.mjs", self.root / "current_nix_smoke_environment.mjs")
        self.mock_child_spawn = self.root / "mock-child-spawn.mjs"
        self.mock_child_spawn.write_text(
            _build_mock_child_spawn_source(self.root / "child-env-presence.json"),
            encoding="utf-8",
        )
        (self.launch_root / "bin" / "tfnf").write_text("placeholder\n", encoding="utf-8")
        (self.launch_root / "bin" / "theme-forge-nebular-fusion").write_text("placeholder\n", encoding="utf-8")

    def _prepared(self):
        return {"source_generation": "theme-forge-current-202610", "source": self.source,
                "checkout": self.source, "tools": self.tools, "scratch": self.scratch}

    def _smoke_env(self):
        node_dir = str(Path(shutil.which("node")).resolve().parent)
        return {
            "PATH": f"{node_dir}{os.pathsep}{os.environ.get('PATH', '')}",
            "DISPLAY": ":99", "DBUS_SESSION_BUS_ADDRESS": "unix:path=/tmp/dbus-test",
            "XDG_DATA_DIRS": "/nix/store/gtk3/share:/nix/store/shared-mime-info/share",
            "FONTCONFIG_FILE": "/nix/store/fontconfig/etc/fonts/fonts.conf",
            "LD_LIBRARY_PATH": "/nix/store/lib", "GIO_EXTRA_MODULES": "/nix/store/gio/modules",
            "GDK_PIXBUF_MODULE_FILE": "/nix/store/loaders.cache", "GSETTINGS_SCHEMA_DIR": "/nix/store/schemas",
            "RS9_GITHUB_READ_TOKEN": "ghp_synthetic_secret_token_value",
        }

    def _base_obs_descriptor(self, **overrides):
        base = {"wrapper": self.wrapper, "harness": self.tools / "native-rc-smoke.mjs",
                "progress": self.evidence / "progress.jsonl", "path": self.evidence / "initial-observation.json",
                "profile": diagnostic.CURRENT071_REPLAY_PROGRESS_PROFILE,
                "harness_timeout_ms": diagnostic.CURRENT071_REQUIRED_HARNESS_TIMEOUT_MS}
        base.update(overrides)
        return base

    def test_upstream_pins_and_hosted_callers_remain_unchanged_and_inactive(self):
        smoke_pin = pins.CURRENT071_REPLAY_PROGRESS_PROFILE["modules"]["native-rc-smoke.mjs"]
        self.assertEqual((smoke_pin["sha256"], smoke_pin["size"]), (diagnostic.CURRENT071_UPSTREAM_HARNESS_SHA256, 30732))
        self.assertEqual(smoke_pin["blob"], "cbf6a2148c11ed1516ba5d7fc2d4dd32dee3ee9f")
        verifier_pin = pins.CURRENT071_VERIFIER_FILES["tools/native-rc-smoke.mjs"]
        self.assertEqual((verifier_pin["sha256"], verifier_pin["size"]), (diagnostic.CURRENT071_UPSTREAM_HARNESS_SHA256, 30732))
        self.assertEqual(smoke_source_envelope.GENERATION, "theme-forge-current-202610")
        sig = inspect.signature(diagnostic.execute_application_smoke)
        self.assertIs(sig.parameters["diagnostic_current_nix_environment_transform"].default, False)
        for module in (hosted_nix, hosted_smoke):
            source_text = inspect.getsource(module)
            self.assertNotIn("diagnostic_current_nix_environment_transform", source_text)
            self.assertNotIn("--rs9-current-nix-environment-transform", source_text)

    def test_command_and_descriptor_gate_transform_strictly(self):
        default_cmd = diagnostic._command(
            self._prepared(), "linux-x64", "C", self.launch_root, self.evidence,
            extras=False, initial_observation=self._base_obs_descriptor(),
        )
        self.assertNotIn("--rs9-current-nix-environment-transform", default_cmd)
        tx_id = diagnostic.CURRENT_NIX_ENVIRONMENT_TRANSFORM_ID
        opt_in_cmd = diagnostic._command(
            self._prepared(), "linux-x64", "C", self.launch_root, self.evidence,
            extras=False, initial_observation=self._base_obs_descriptor(environment_transform=tx_id),
        )
        idx = opt_in_cmd.index("--rs9-current-nix-environment-transform")
        self.assertEqual(opt_in_cmd[idx + 1], tx_id)
        for bad_obs, platform, scenario in (
            (self._base_obs_descriptor(environment_transform=True), "linux-x64", "C"),
            (self._base_obs_descriptor(environment_transform=False), "linux-x64", "C"),
            (self._base_obs_descriptor(environment_transform="wrong-id"), "linux-x64", "C"),
            (self._base_obs_descriptor(profile=diagnostic.CURRENT_REPLAY_PROGRESS_PROFILE,
                                       harness_timeout_ms=None, environment_transform=tx_id), "linux-x64", "C"),
            (self._base_obs_descriptor(environment_transform=tx_id), "linux-arm64", "C"),
        ):
            with self.assertRaises(ContractError):
                diagnostic._command(self._prepared(), platform, scenario, self.launch_root, self.evidence,
                                    extras=False, initial_observation=bad_obs)
        for kwargs in (
            {"diagnostic_initial_observation": False, "diagnostic_current_nix_environment_transform": True},
            {"diagnostic_initial_observation": True, "diagnostic_current_nix_environment_transform": "yes"},
        ):
            with self.assertRaises(ContractError):
                diagnostic.execute_application_smoke(prepared=self._prepared(), system="x86_64-linux",
                                                     launch_root=self.launch_root, **kwargs)

    def test_read_initial_observation_enforces_expected_execution_transform_contract(self):
        obs_path = self.evidence / "obs.json"
        obs_path.write_text(json.dumps(_sample_observation_payload(
            diagnostic.CURRENT071_REPLAY_PROGRESS_PROFILE, include_transform=False)), encoding="utf-8")
        parsed_default = diagnostic._read_initial_observation(
            obs_path, expected_profile=diagnostic.CURRENT071_REPLAY_PROGRESS_PROFILE)
        self.assertEqual(parsed_default["status"], "failed")
        self.assertNotIn("execution_transform", parsed_default)
        missing = diagnostic._read_initial_observation(
            obs_path, expected_profile=diagnostic.CURRENT071_REPLAY_PROGRESS_PROFILE, expected_execution_transform=True)
        self.assertEqual((missing["status"], missing["reason"]), ("unobserved", "invalid"))
        obs_path.write_text(json.dumps(_sample_observation_payload(
            diagnostic.CURRENT071_REPLAY_PROGRESS_PROFILE, include_transform=True)), encoding="utf-8")
        unexpected = diagnostic._read_initial_observation(
            obs_path, expected_profile=diagnostic.CURRENT071_REPLAY_PROGRESS_PROFILE)
        self.assertEqual((unexpected["status"], unexpected["reason"]), ("unobserved", "invalid"))
        accepted = diagnostic._read_initial_observation(
            obs_path, expected_profile=diagnostic.CURRENT071_REPLAY_PROGRESS_PROFILE, expected_execution_transform=True)
        self.assertEqual(accepted["execution_transform"], diagnostic.EXPECTED_CURRENT_NIX_EXECUTION_TRANSFORM)

    def test_read_initial_observation_rejects_forged_or_blessed_transform_fields(self):
        obs_path = self.evidence / "obs-forged.json"
        base = _sample_observation_payload(diagnostic.CURRENT071_REPLAY_PROGRESS_PROFILE, include_transform=True)
        swapped_pin = copy.deepcopy(base)
        swapped_pin["source_profile"]["harness_sha256"] = diagnostic.CURRENT071_DERIVED_HARNESS_SHA256
        obs_path.write_text(json.dumps(swapped_pin), encoding="utf-8")
        mismatch = diagnostic._read_initial_observation(
            obs_path, expected_profile=diagnostic.CURRENT071_REPLAY_PROGRESS_PROFILE, expected_execution_transform=True)
        self.assertEqual((mismatch["status"], mismatch["reason"]), ("unobserved", "source-binding-mismatch"))
        for patch_fields in (
            {"modified_from_upstream": False}, {"non_admitting": False}, {"fhs_origin_proven": True},
            {"native_qualified": True}, {"causal_attribution_proven": True},
            {"upstream_sha256": diagnostic.CURRENT071_DERIVED_HARNESS_SHA256},
            {"executed_derived_sha256": diagnostic.CURRENT071_UPSTREAM_HARNESS_SHA256},
            {"restored_env_keys": ["XDG_DATA_DIRS"]}, {"extra_field": True},
        ):
            forged = copy.deepcopy(base)
            forged["execution_transform"].update(patch_fields)
            obs_path.write_text(json.dumps(forged), encoding="utf-8")
            result = diagnostic._read_initial_observation(
                obs_path, expected_profile=diagnostic.CURRENT071_REPLAY_PROGRESS_PROFILE, expected_execution_transform=True)
            self.assertEqual((result["status"], result["reason"]), ("unobserved", "invalid"))

    def _run_one_shot_node_wrapper(self, argv, **kwargs):
        self.assertEqual(argv[:5], ["xvfb-run", "-a", "dbus-run-session", "--", "node"])
        self.assertEqual(argv[5], str(self.wrapper))
        node_argv = [shutil.which("node"), "--import", str(self.mock_child_spawn), *argv[5:]]
        return _REAL_SUBPROCESS_RUN(node_argv, **kwargs)

    def _run_smoke_under_profile(self, *, transform_enabled):
        with patch.object(diagnostic, "CURRENT071_REPLAY_PROGRESS_PROFILE", self.profile), \
             patch.object(diagnostic, "_replay_progress_wrapper", return_value=self.wrapper), \
             patch.object(diagnostic, "_current_replay_progress_profile", return_value=self.profile), \
             patch.object(diagnostic.subprocess, "run", side_effect=self._run_one_shot_node_wrapper), \
             self.assertRaises(ContractError):
            diagnostic.execute_application_smoke(
                prepared=self._prepared(), system="x86_64-linux",
                launch_root=self.launch_root, env=self._smoke_env(),
                diagnostic_initial_observation=True,
                diagnostic_current_nix_environment_transform=transform_enabled,
                diagnostic_replay=True,
            )
        raw = (self.scratch.parent / "diagnostics/application-smoke-diagnostic.json").read_text(encoding="utf-8")
        child = json.loads((self.root / "child-env-presence.json").read_bytes())
        return raw, json.loads(raw), child

    def test_end_to_end_wrapper_and_execute_application_smoke_default_vs_transform(self):
        _, default_diag, default_child = self._run_smoke_under_profile(transform_enabled=False)
        default_obs = default_diag["initial_run"]["initial_observation"]
        self.assertNotIn("execution_transform", default_obs)
        self.assertTrue(default_obs["environment_presence"]["wrapper_entry"]["XDG_DATA_DIRS"])
        self.assertFalse(default_obs["environment_presence"]["first_spawn"]["XDG_DATA_DIRS"])
        self.assertFalse(default_obs["environment_presence"]["first_spawn"]["FONTCONFIG_FILE"])
        self.assertEqual(default_child, {"xdg": False, "fontconfig": False, "ld": False, "token": False})
        expected_gate = ("fail", "not-run", "original-harness-not-passed")
        self.assertEqual(
            (default_diag["gate_status"], default_diag["replay"]["status"], default_diag["replay"]["reason"]),
            expected_gate,
        )
        tx_raw, tx_diag, tx_child = self._run_smoke_under_profile(transform_enabled=True)
        tx_obs = tx_diag["initial_run"]["initial_observation"]
        self.assertEqual(tx_obs["source_profile"]["harness_sha256"], diagnostic.CURRENT071_UPSTREAM_HARNESS_SHA256)
        self.assertEqual(tx_obs["execution_transform"], diagnostic.EXPECTED_CURRENT_NIX_EXECUTION_TRANSFORM)
        self.assertEqual(
            (tx_obs["environment_presence"]["first_spawn"]["XDG_DATA_DIRS"],
             tx_obs["environment_presence"]["first_spawn"]["FONTCONFIG_FILE"],
             tx_obs["environment_presence"]["first_spawn"]["LD_LIBRARY_PATH"]),
            (True, True, False),
        )
        self.assertEqual(tx_child, {"xdg": True, "fontconfig": True, "ld": False, "token": False})
        self.assertEqual(
            (tx_diag["gate_status"], tx_diag["replay"]["status"], tx_diag["replay"]["reason"]),
            expected_gate,
        )
        self.assertNotIn("/nix/store/gtk3/share", tx_raw)
        self.assertNotIn("ghp_synthetic_secret_token_value", tx_raw)
        self.assertEqual((self.tools / "native-rc-smoke.mjs").read_bytes(), FIXTURE_SMOKE_PATH.read_bytes())

    def _wrapper_argv_for_profile(self, profile, obs_file, *, transform=None, timeout_ms="default"):
        timeout = (diagnostic.CURRENT071_REQUIRED_HARNESS_TIMEOUT_MS
                   if timeout_ms == "default" else timeout_ms)
        descriptor = self._base_obs_descriptor(profile=profile, path=obs_file, harness_timeout_ms=timeout)
        if transform is not None:
            descriptor["environment_transform"] = transform
        with patch.object(diagnostic, "CURRENT071_REPLAY_PROGRESS_PROFILE", self.profile), \
             patch.object(diagnostic, "CURRENT_REPLAY_PROGRESS_PROFILE", self.profile070):
            cmd = diagnostic._command(
                self._prepared(), "linux-x64", "C", self.launch_root, self.evidence,
                extras=False, initial_observation=descriptor,
            )
        return [shutil.which("node"), *cmd[cmd.index(str(self.wrapper)):]]

    def _assert_wrapper_rejects(self, argv, obs_file):
        completed = _REAL_SUBPROCESS_RUN(argv, capture_output=True, timeout=5, check=False)
        self.assertNotEqual(completed.returncode, 0)
        self.assertFalse(obs_file.exists())

    def test_wrapper_rejects_invalid_transform_cli_or_tampered_closure_before_import(self):
        obs_file = self.evidence / "preimport-obs.json"
        tx_id = diagnostic.CURRENT_NIX_ENVIRONMENT_TRANSFORM_ID
        node_argv = self._wrapper_argv_for_profile(self.profile, obs_file, transform=tx_id)
        flag_at = node_argv.index("--rs9-current-nix-environment-transform")
        bad_id = [*node_argv[:flag_at + 1], "wrong-transform-id", *node_argv[flag_at + 2:]]
        duplicated = [*node_argv, "--rs9-current-nix-environment-transform", tx_id]
        kind_at = node_argv.index("--rs9-initial-observation-kind")
        without_initial = [*node_argv[:kind_at], *node_argv[kind_at + 4:]]
        plat_at = node_argv.index("--platform")
        darwin_argv = [*node_argv[:plat_at + 1], "darwin-arm64", "--scenario", "A", *node_argv[plat_at + 4:]]
        bad_lane_argv = [*node_argv[:plat_at + 1], "linux-arm64", "--scenario", "C", *node_argv[plat_at + 4:]]
        for argv in (bad_id, duplicated, without_initial, darwin_argv, bad_lane_argv):
            self._assert_wrapper_rejects(argv, obs_file)
        argv070 = [*self._wrapper_argv_for_profile(self.profile070, obs_file, timeout_ms=None),
                   "--rs9-current-nix-environment-transform", tx_id]
        (self.source / "package.json").write_bytes(b'{"version":"0.7.0"}\n')
        self._assert_wrapper_rejects(argv070, obs_file)
        (self.source / "package.json").write_text('{"version":"0.7.1"}\n', encoding="utf-8")
        smoke_path = self.tools / "native-rc-smoke.mjs"
        smoke_path.write_bytes(b"// tampered\n" + FIXTURE_SMOKE_PATH.read_bytes())
        self._assert_wrapper_rejects(node_argv, obs_file)
        smoke_path.write_bytes(FIXTURE_SMOKE_PATH.read_bytes())


if __name__ == "__main__":
    unittest.main()
