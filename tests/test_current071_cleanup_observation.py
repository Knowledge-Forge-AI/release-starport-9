"""Tests for bounded current071 Linux APT cleanup-error observer and step projection."""
from __future__ import annotations

import copy
import hashlib
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
    current071_cleanup_observation as cleanup_obs,
    current_os071 as pins,
    hosted_smoke as smoke,
    pages_smoke_diagnostic as pages_diag,
    signing_fixture,
    smoke_source_envelope as source_envelope,
)
from rs9.errors import ContractError
from rs9.release_core import digest
from rs9.scratch import canonical
from tests.test_sidecar_harness_closure import current_import_fixture

FIXTURE_SMOKE_PATH = Path(__file__).resolve().parent / "fixtures" / "current071-native-rc-smoke.mjs.txt"
CLEANUP_PROBLEM = "harness cleanup of the owned scratch directory failed"
EXPECTED_B_CLEANUP_STDOUT_SHA256 = "4c01e0ee066068fba7bb6f3bee1ec7c6afc82cba982193c284d0f0b87efd7a9a"


def _pin_bytes(raw: bytes) -> dict[str, object]:
    blob = hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest()
    return {"sha256": digest(raw), "blob": blob, "size": len(raw)}


def _populate_core_fixture(checkout: Path) -> None:
    fixture_dir = checkout / "docs/examples/v0.4/brand-system/core-minimal/.tfsb"
    fixture_dir.mkdir(parents=True, exist_ok=True)
    (fixture_dir / "project.toml").write_text('name = "core-fixture"\n', encoding="utf-8")
    (fixture_dir / "brand.toml").write_text('name = "Core Fixture Brand"\npackage = true\n', encoding="utf-8")
    (fixture_dir / "brand-package.toml").write_text("schema_version = 1\n", encoding="utf-8")


def _build_inert_sibling_modules(sandbox_root: Path, *, rm_fault_mode: str = "none", scenario_steps: str = "pass") -> dict[str, str]:
    """Build inert sibling modules so real current071-native-rc-smoke.mjs runs under Node22 without GUI/product."""
    fs_snapshot = f"""import childProcess from "node:child_process";
import {{ EventEmitter }} from "node:events";
import fs from "node:fs";
import {{ syncBuiltinESMExports }} from "node:module";
import os from "node:os";
import {{ basename, dirname, join, relative, sep }} from "node:path";

const sandboxTmp = {json.dumps(str(sandbox_root / "guest-tmp"))};
const sandboxHome = {json.dumps(str(sandbox_root / "guest-home"))};
const faultMode = {json.dumps(rm_fault_mode)};
const stepMode = {json.dumps(scenario_steps)};

fs.mkdirSync(sandboxTmp, {{ recursive: true }});
fs.mkdirSync(sandboxHome, {{ recursive: true }});
os.tmpdir = () => sandboxTmp;
os.homedir = () => sandboxHome;

// Model Linux case-distinct fixture names only inside this fresh owned smoke
// tree. This is a native-filesystem test adapter, not Linux qualification.
function fixturePath(target) {{
  if (typeof target !== "string") return target;
  const parts = relative(sandboxTmp, target).split(sep);
  if (!parts[0]?.startsWith("nebular-rc-smoke-")) return target;
  const aliases = {{ "project Ω": "fixture-lower-project Ω", "case": "fixture-lower-case", "probe": "fixture-lower-probe" }};
  return join(sandboxTmp, ...parts.map((part) => aliases[part] ?? part));
}}
for (const name of ["readFileSync", "writeFileSync", "existsSync", "lstatSync", "readlinkSync", "realpathSync", "readdirSync", "chmodSync", "mkdirSync", "rmSync"]) {{
  const original = fs[name];
  fs[name] = function(target, ...args) {{
    return Reflect.apply(original, this, [fixturePath(target), ...args]);
  }};
}}
const originalCpSync = fs.cpSync;
fs.cpSync = function(source, destination, ...args) {{
  return Reflect.apply(originalCpSync, this, [fixturePath(source), fixturePath(destination), ...args]);
}};

const origReadFileSync = fs.readFileSync;
fs.readFileSync = function(target, options) {{
  const res = origReadFileSync(target, options);
  if (typeof target === "string" && options === "utf8" && typeof res === "string" && res.startsWith("controlled fixture ")) {{
    if (target.endsWith(".tfsb/project.toml")) return 'name = "core-fixture"\\n';
    if (target.endsWith(".tfsb/brand.toml")) return 'name = "Core Fixture Brand"\\npackage = true\\n';
  }}
  return res;
}};

const baseRmSync = fs.rmSync;
fs.rmSync = function simulatedRmSync(target, options) {{
  if (typeof target === "string" && basename(target).startsWith("nebular-rc-smoke-")) {{
    if (faultMode === "ENOTEMPTY" || faultMode === "EBUSY" || faultMode === "EACCES" || faultMode === "EPERM") {{
      const err = new Error(`${{faultMode}}: simulated cleanup failure on '/private/secret-user/${{basename(target)}}'`);
      err.code = faultMode;
      err.syscall = "rmdir";
      err.path = target;
      throw err;
    }}
    if (faultMode === "UNKNOWN_CODE") {{
      const err = new Error("Simulated non-whitelisted errno with secret ghp_" + "x".repeat(36));
      err.code = "ENOTSUP_CUSTOM_PRIVATE";
      throw err;
    }}
    if (faultMode === "STRING_THROW") {{
      throw "raw-string-cleanup-exception-/Users/private/secret";
    }}
  }}
  return baseRmSync(target, options);
}};

let activeSidecarLaunchRoot = null;
childProcess.spawnSync = () => {{
  if (activeSidecarLaunchRoot) {{
    return {{ stdout: `424243 ${{activeSidecarLaunchRoot}}/bin/tfsb-studio-service\\n`, stderr: "", status: 0 }};
  }}
  return {{ stdout: "", stderr: "", status: 0 }};
}};

const origKill = process.kill;
process.kill = function(pid, sig) {{
  if (pid === 424242 || pid === -424242 || pid === 424243) {{
    activeSidecarLaunchRoot = null;
    if (activeSignalChild) {{
      const child = activeSignalChild;
      activeSignalChild = null;
      child.exitCode = null;
      child.signalCode = "SIGTERM";
      queueMicrotask(() => child.emit("exit", null, "SIGTERM"));
    }}
    return true;
  }}
  return origKill.call(process, pid, sig);
}};

let activeSignalChild = null;
childProcess.spawn = function inertSpawn(cmd, args, options = {{}}) {{
  const child = Object.assign(new EventEmitter(), {{
    pid: 424242,
    exitCode: null,
    signalCode: null,
    stdout: new EventEmitter(),
    stderr: new EventEmitter(),
    kill: () => true,
  }});
  const arg0 = Array.isArray(args) && typeof args[0] === "string" ? args[0] : "";
  const scenario = arg0.startsWith("--nebular-release-smoke=") ? arg0.slice("--nebular-release-smoke=".length) : "B";
  const smokeDir = options.env?.TFNF_RELEASE_SMOKE_DIR || null;
  const launchRoot = dirname(dirname(String(cmd)));
  queueMicrotask(() => {{
    if (faultMode === "NON_TARGET_RM") {{
      try {{
        fs.rmSync(join(sandboxTmp, "other-prefix-dir"), {{ recursive: false, force: false }});
      }} catch {{
        // Non-target rmSync failure inside harness run must not emit cleanup marker.
      }}
    }}
    if (smokeDir && scenario.startsWith("C")) {{
      const outFile = join(smokeDir, "fixtures/Derive Target/Case/fixture-mark-derived-dark.svg");
      fs.mkdirSync(dirname(outFile), {{ recursive: true }});
      fs.writeFileSync(outFile, "<svg/>\\n", "utf8");
    }}
    if (smokeDir) {{
      const bSteps = [
        "app-shell", "app-theme-status", "app-theme-compile", "theme-lab-compile",
        "brand-system-view", "host-start", "host-status", "project-open-upper",
        "brand-read-upper", "project-open-lower", "brand-read-lower", "host-status-final"
      ];
      const cSteps = [
        "app-shell", "host-start", "host-start-idempotent", "host-stop",
        "host-start-again", "host-status", "project-open-case",
        "derive-plan-cancel", "derive-plan-apply", "host-status-final"
      ];
      const reqIds = scenario === "B" ? bSteps : cSteps;
      const failStep = stepMode === "fail-host-status" && scenario === "C-signal";
      const steps = reqIds.map((id) => ({{
        id,
        ok: !(failStep && id === "host-status"),
        via: "inert-fixture",
        ms: 1,
        detail: "PRIVATE_STEP_DETAIL_/Users/secret_operator/" + id,
      }}));
      const rec = {{
        schema: "nebular.release-smoke-receipt-v1",
        scenario,
        status: failStep ? "fail" : "pass",
        failure: failStep ? "PRIVATE_FAILURE_/Users/secret_operator" : undefined,
        pid: 424242,
        target: scenario === "B" ? "aarch64-unknown-linux-gnu" : "x86_64-unknown-linux-gnu",
        executable: {{ sha256: "a".repeat(64) }},
        awaitingSignal: scenario === "C-signal",
        driver: {{ steps }},
      }};
      const receiptPath = join(smokeDir, "receipt.json");
      fs.mkdirSync(dirname(receiptPath), {{ recursive: true }});
      fs.writeFileSync(receiptPath, JSON.stringify(rec), {{ mode: 0o600 }});
    }}
    if (scenario === "C-signal") {{
      activeSidecarLaunchRoot = launchRoot;
      activeSignalChild = child;
    }} else {{
      child.exitCode = 0;
      child.emit("exit", 0, null);
    }}
  }});
  return child;
}};
syncBuiltinESMExports();

export function readRegularSnapshot(filePath) {{
  const p = String(filePath);
  if (p.endsWith("receipt.json")) {{
    if (!fs.existsSync(p)) return null;
    const raw = origReadFileSync(p);
    return {{ bytes: raw, sha256: {json.dumps("b" * 64)}, size: raw.length, executable: false, mode: 0o600 }};
  }}
  if (p.endsWith("/bin/tfnf")) {{
    const bytes = Buffer.from("#!/bin/sh\\n", "utf8");
    return {{ bytes, sha256: "d".repeat(64), size: bytes.length, executable: true, mode: 0o755 }};
  }}
  if (p.endsWith("/bin/theme-forge-nebular-fusion")) {{
    const bytes = Buffer.from("inert-candidate-binary", "utf8");
    return {{ bytes, sha256: "a".repeat(64), size: bytes.length, executable: true, mode: 0o755 }};
  }}
  const raw = origReadFileSync(p);
  return {{ bytes: raw, sha256: String(raw.length).padStart(64, "0"), size: raw.length, executable: false, mode: 0o644 }};
}}
export function snapshotTree() {{
  return new Map();
}}
export function diffSnapshots() {{
  return [];
}}
"""
    setup, exports = fs_snapshot.split("export function readRegularSnapshot", 1)
    preload = sandbox_root / "inert-preload.mjs"
    preload.parent.mkdir(parents=True, exist_ok=True)
    preload.write_text(
        setup.replace("const origReadFileSync =", "export const origReadFileSync =", 1),
        encoding="utf-8",
    )
    fs_snapshot = (
        'import fs from "node:fs";\n'
        + 'import { origReadFileSync } from ' + json.dumps(preload.as_uri()) + ';\n'
        + "export function readRegularSnapshot" + exports
    )
    return {
        "candidate-provenance.mjs": 'export const provenance = "inert";\n',
        "fs-snapshot.mjs": fs_snapshot,
        "native-launcher.mjs": (
            'import "./platform-targets.mjs";\n'
            'export function nativeLauncher() { return "#!/bin/sh\\n"; }\n'
            'export function resolveInstalledBinary(root) { return root + "/bin/theme-forge-nebular-fusion"; }\n'
        ),
        "native-rc-package.mjs": (
            'import "./fs-snapshot.mjs";\nimport "./native-launcher.mjs";\n'
            'import "./native-runtime.mjs";\nimport "./platform-targets.mjs";\n'
            'export function verifyPlatformPackage() { return { manifest: {} }; }\n'
        ),
        "native-runtime.mjs": (
            'import "./candidate-provenance.mjs";\n'
            'export async function selectPayloadNativeRuntime() { return { nativeRuntime: { id: "inert" } }; }\n'
        ),
        "platform-targets.mjs": (
            'export function expectedTargetForPlatform(p) {\n'
            '  return p === "linux-arm64" ? "aarch64-unknown-linux-gnu" : "x86_64-unknown-linux-gnu";\n'
            '}\n'
        ),
    }


class Current071CleanupObservationTests(unittest.TestCase):
    def setUp(self) -> None:
        gpg_patch = patch.object(signing_fixture, "find_gpg_binary", side_effect=AssertionError("GPG forbidden"))
        gpg_patch.start()
        self.addCleanup(gpg_patch.stop)
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name).resolve()

    def _build_authenticated_apt_fixture(
        self,
        subroot: Path,
        *,
        rm_fault_mode: str = "none",
        scenario_steps: str = "pass",
        family: str = "apt",
        nebular_version: str = "0.7.1",
    ) -> tuple[dict[str, object], dict[str, object], Path]:
        subroot.mkdir(parents=True, exist_ok=True)
        capture, captures, client, contract, sources, fixtures = current_import_fixture(subroot, nebular_version)
        sandbox = subroot / "sandbox"
        sandbox.mkdir(parents=True, exist_ok=True)
        sibling_map = _build_inert_sibling_modules(
            sandbox, rm_fault_mode=rm_fault_mode, scenario_steps=scenario_steps
        )
        profile = copy.deepcopy(pins.CURRENT071_REPLAY_PROGRESS_PROFILE)
        target_files = (
            "rs9.hosted_smoke.CURRENT071_VERIFIER_FILES"
            if nebular_version == "0.7.1"
            else "rs9.hosted_smoke.CURRENT070_VERIFIER_FILES"
        )
        contract_loader = (
            "rs9.nebular_callers._load_current071_contract"
            if nebular_version == "0.7.1"
            else "rs9.nebular_callers._load_current_contract"
        )
        for target, val in (
            (contract_loader, contract),
            (target_files, sources),
            ("rs9.hosted_smoke.CURRENT070_FIXTURE_FILES", fixtures),
            ("rs9.application_smoke_diagnostic.CURRENT071_REPLAY_PROGRESS_PROFILE", profile),
            ("rs9.current071_cleanup_observation.CURRENT071_REPLAY_PROGRESS_PROFILE", profile),
        ):
            p = patch(target, return_value=val) if target == contract_loader else patch(target, val)
            p.start()
            self.addCleanup(p.stop)

        host_prepared = smoke.prepare_smoke(capture, captures, client, subroot / "prepared")
        source_dir = Path(host_prepared["source"])
        for rel_name, content in sibling_map.items():
            full_rel = "tools/" + rel_name
            raw_bytes = content.encode("utf-8")
            (source_dir / full_rel).write_bytes(raw_bytes)
            sources[full_rel] = _pin_bytes(raw_bytes)
            contract["source_files"][full_rel] = _pin_bytes(raw_bytes)
        if nebular_version == "0.7.1":
            raw_smoke = FIXTURE_SMOKE_PATH.read_bytes()
            (source_dir / "tools/native-rc-smoke.mjs").write_bytes(raw_smoke)
            sources["tools/native-rc-smoke.mjs"] = _pin_bytes(raw_smoke)
            contract["source_files"]["tools/native-rc-smoke.mjs"] = _pin_bytes(raw_smoke)
        for mod_name in list(profile["modules"]):
            profile["modules"][mod_name] = copy.deepcopy(sources["tools/" + mod_name])
        profile["support"] = copy.deepcopy(sources["package.json"])
        for row in host_prepared["records"]:
            if row["path"] in sources:
                row.update(sources[row["path"]])
        (Path(host_prepared["scratch"]) / "source-bindings.json").write_bytes(canonical(host_prepared["records"]))

        readback = smoke.export_current_source_readback(host_prepared)
        serialized_readback = json.loads(canonical(readback))

        guest_source = subroot / "guest-source"
        shutil.copytree(host_prepared["source"], guest_source)
        proof = source_envelope.mint_guest_readback(serialized_readback, guest_source, guest_source / "tools")
        guest_checkout = subroot / "guest-checkout"
        shutil.copytree(guest_source, guest_checkout)
        source_envelope.verify_checkout(serialized_readback, guest_checkout)

        guest_scratch = subroot / "guest-scratch/smoke"
        guest_scratch.mkdir(parents=True, exist_ok=True)
        launch_root = subroot / "launch-root"
        (launch_root / "bin").mkdir(parents=True, exist_ok=True)
        (launch_root / "bin/theme-forge-nebular-fusion").write_bytes(b"inert-candidate-binary")
        (launch_root / "bin/tfnf").write_bytes(b"#!/bin/sh\n")

        guest_prepared: dict[str, object] = {
            "source": guest_source,
            "checkout": guest_checkout,
            "tools": guest_source / "tools",
            "scratch": guest_scratch,
            "container_client": True,
            "family": family,
            "label": family,
            "source_generation": source_envelope.GENERATION,
            "source_readback": serialized_readback,
            "records": serialized_readback["records"],
            "_source_readback_proof": proof,
        }
        return guest_prepared, profile, launch_root

    def _fixture_bin_env(self, subroot: Path) -> dict[str, str]:
        fbin = subroot / "fixture-bin"
        fbin.mkdir(parents=True, exist_ok=True)
        node_bin = shutil.which("node")
        self.assertIsNotNone(node_bin)
        if not (fbin / "node").exists():
            (fbin / "node").symlink_to(node_bin)
        for helper, flag in (("xvfb-run", "-a"), ("dbus-run-session", "--")):
            hp = fbin / helper
            hp.write_text('#!/bin/sh\n[ "$1" = "' + flag + '" ] || exit 97\nshift\nexec "$@"\n', encoding="utf-8")
            hp.chmod(0o755)
        return {
            **os.environ,
            "PATH": f"{fbin}:{os.environ.get('PATH', '')}",
            "NODE_OPTIONS": "--import=" + (subroot / "sandbox/inert-preload.mjs").as_uri(),
        }

    def test_disjoint_checkout_and_public_plan_identity_are_verified(self) -> None:
        prepared, profile, _launch = self._build_authenticated_apt_fixture(self.root / "disjoint")
        self.assertNotEqual(prepared["source"], prepared["checkout"])
        plan = cleanup_obs.prepare_current071_cleanup_observation(
            prepared, system="aarch64-linux", platform="linux-arm64", scenario="B"
        )
        expected = {
            "policy_id": cleanup_obs.CURRENT071_CLEANUP_POLICY_ID,
            "source_commit": pins.CURRENT071_COMMIT,
            "source_tree": pins.CURRENT071_TREE,
            "harness_sha256": cleanup_obs.CURRENT071_NATIVE_RC_SMOKE_PIN["sha256"],
            "observer_sha256": digest(cleanup_obs.render_current071_cleanup_observer_bytes(profile)),
        }
        self.assertEqual(plan["public_identity"], expected)
        self.assertNotIn(str(self.root), json.dumps(plan["public_identity"]))
        self.assertEqual(
            cleanup_obs.validate_cleanup_observation_plan(plan, prepared=prepared, platform="linux-arm64", scenario="B"),
            (plan["wrapper"], plan["harness"]),
        )
        for key in expected:
            bad = {**plan, "public_identity": {**expected, key: "invalid"}}
            with self.subTest(key=key), self.assertRaises(ContractError):
                cleanup_obs.validate_cleanup_observation_plan(bad, prepared=prepared, platform="linux-arm64", scenario="B")
        package = Path(prepared["checkout"]) / "package.json"
        original = package.read_bytes()
        try:
            package.write_bytes(original + b" ")
            with self.assertRaises(ContractError):
                cleanup_obs.prepare_current071_cleanup_observation(
                    prepared, system="aarch64-linux", platform="linux-arm64", scenario="B"
                )
        finally:
            package.write_bytes(original)

    def test_actual_rm_wrapper_preserves_return_error_receiver_and_emission_failure(self) -> None:
        rendered = cleanup_obs.render_current071_cleanup_observer_bytes().decode("utf-8")
        start = rendered.index("const expectedTmpParents =")
        end = rendered.index("\nsyncBuiltinESMExports();", start)
        block = rendered[start:end]
        script = '''import assert from "node:assert/strict";
import { resolve, dirname, basename } from "node:path";
const block = __BLOCK__;
const codes = new Set(__CODES__);
function build(original) {
  return new Function("fs", "originalRmSync", "originalLstatSync", "originalRealpathSync",
    "tmpdir", "resolve", "dirname", "basename", "ALLOWED_ERRNO_CODES", block + "; return fs.rmSync;")(
      {}, original, () => ({isSymbolicLink: () => false}), (value) => value,
      () => "/fixture-tmp", resolve, dirname, basename, codes);
}
const target = "/fixture-tmp/nebular-rc-smoke-fixture";
const options = { recursive: true, force: true };
const receiver = {};
const result = {};
const emitted = [];
const write = process.stderr.write;
process.stderr.write = (value) => { emitted.push(value); return true; };
let calls = 0;
try {
  const successful = build(function(...args) {
    calls++; assert.equal(this, receiver); assert.equal(args.length, 2);
    assert.equal(args[0], target); assert.equal(args[1], options); return result;
  });
  assert.equal(successful.call(receiver, target, options), result);
  assert.equal(calls, 1); assert.deepEqual(emitted, []);
  for (const code of ["EACCES", "EPERM", "ENOTEMPTY", "EBUSY", "PRIVATE_UNKNOWN"]) {
    const originalError = Object.assign(new Error("private fixture detail"), { code });
    calls = 0; emitted.length = 0;
    const failing = build(function(...args) {
      calls++; assert.equal(this, receiver); assert.equal(args[0], target);
      assert.equal(args[1], options); throw originalError;
    });
    assert.throws(() => failing.call(receiver, target, options), (error) => error === originalError);
    assert.equal(calls, 1);
    assert.deepEqual(emitted, ["RS9_CURRENT071_CLEANUP_ERRNO=" + (codes.has(code) ? code : "OTHER") + "\\n"]);
  }
  const originalError = Object.assign(new Error("original"), {code: "EPERM"});
  emitted.length = 0;
  assert.throws(() => build(() => {throw originalError;})("/fixture-tmp/unrelated", options),
    (error) => error === originalError);
  assert.deepEqual(emitted, []);
  process.stderr.write = () => {throw new Error("diagnostic emission failed");};
  assert.throws(() => build(() => {throw originalError;})(target, options),
    (error) => error === originalError);
} finally { process.stderr.write = write; }
process.stdout.write(JSON.stringify({cases: 8, realRemovalCalls: 0}) + "\\n");
'''
        script = script.replace("__BLOCK__", json.dumps(block)).replace(
            "__CODES__", json.dumps(sorted(cleanup_obs.CURRENT071_CLEANUP_ERRNO_CODES - {"OTHER"}))
        )
        completed = subprocess.run(["node", "--input-type=module", "-e", script], capture_output=True, timeout=15)
        self.assertEqual(completed.returncode, 0, completed.stderr.decode("utf-8", errors="replace"))
        self.assertEqual(json.loads(completed.stdout), {"cases": 8, "realRemovalCalls": 0})
        self.assertEqual(completed.stderr, b"")

    def test_real_node22_observer_preserves_cleanup_failure_identity_and_emits_closed_errno(self) -> None:
        for fault_mode, expected_errno in (
            ("ENOTEMPTY", "ENOTEMPTY"),
            ("EBUSY", "EBUSY"),
            ("EACCES", "EACCES"),
            ("EPERM", "EPERM"),
            ("UNKNOWN_CODE", "OTHER"),
            ("STRING_THROW", "OTHER"),
        ):
            with self.subTest(fault_mode=fault_mode):
                case_dir = self.root / f"case-{fault_mode}"
                prepared, _profile, launch_root = self._build_authenticated_apt_fixture(
                    case_dir, rm_fault_mode=fault_mode
                )
                env = self._fixture_bin_env(case_dir)
                with self.assertRaises(ContractError) as caught:
                    diagnostic.execute_application_smoke(
                        prepared=prepared,
                        system="aarch64-linux",
                        launch_root=launch_root,
                        env=env,
                        current071_cleanup_observation=True,
                    )
                err = caught.exception
                self.assertEqual(err.code, "APPLICATION_SMOKE")
                obs = err.smoke_observation
                self.assertEqual(obs["scenario"], "B")
                self.assertEqual(obs["cause"], "process-nonzero")
                self.assertEqual(obs["reason_token"], "process-nonzero")
                self.assertEqual(obs["raw_returncode"], 1)
                self.assertEqual(obs["exit_code"], 1)
                self.assertIsNone(obs["signal"])
                self.assertEqual(obs["stdout_bytes"], 111)
                self.assertEqual(obs["stdout_sha256"], EXPECTED_B_CLEANUP_STDOUT_SHA256)
                self.assertEqual(obs["receipt_error"], "receipt-failed")
                expected_stderr = f"RS9_CURRENT071_CLEANUP_ERRNO={expected_errno}\n".encode("utf-8")
                self.assertEqual(obs["stderr_bytes"], len(expected_stderr))
                self.assertEqual(obs["stderr_sha256"], digest(expected_stderr))
                self.assertEqual(
                    obs["cleanup_observation"],
                    {
                        "schema": cleanup_obs.CURRENT071_CLEANUP_OBSERVATION_SCHEMA,
                        "observer_id": cleanup_obs.CURRENT071_CLEANUP_OBSERVER_ID,
                        "family": "apt",
                        "system": "aarch64-linux",
                        "scenario": "B",
                        "stderr_bytes": len(expected_stderr),
                        "stderr_sha256": digest(expected_stderr),
                        "status": "cleanup-error-observed",
                        "errno_code": expected_errno,
                        "marker_count": 1,
                        "withheld_reason": None,
                    },
                )
                self.assertEqual(
                    obs["harness_problem_categories"]["problems"]["categories"],
                    [{"category": "harness-cleanup-failed", "count": 1}],
                )
                serialized = json.dumps(obs)
                for forbidden in ("secret-user", "nebular-rc-smoke-", "ghp_", "PRIVATE_STEP_DETAIL", "rmdir"):
                    self.assertNotIn(forbidden, serialized)
                # Wrapper must be in scratch only, never inside source or evidence
                self.assertTrue((Path(prepared["scratch"]) / cleanup_obs.CURRENT071_CLEANUP_OBSERVER_FILENAME).is_file())
                self.assertFalse((Path(prepared["source"]) / cleanup_obs.CURRENT071_CLEANUP_OBSERVER_FILENAME).exists())
                self.assertFalse((Path(prepared["tools"]) / cleanup_obs.CURRENT071_CLEANUP_OBSERVER_FILENAME).exists())
                # 3-pass idempotence under validate_smoke_observation
                p1 = pages_diag.validate_smoke_observation(obs, system="aarch64-linux")
                p2 = pages_diag.validate_smoke_observation(p1, system="aarch64-linux")
                p3 = pages_diag.validate_smoke_observation(p2, system="aarch64-linux")
                self.assertEqual(p1, obs)
                self.assertEqual(p2, p1)
                self.assertEqual(p3, p2)

    def test_real_node22_observer_passing_and_non_target_rm_emit_no_marker(self) -> None:
        for mode in ("none", "NON_TARGET_RM"):
            with self.subTest(mode=mode):
                case_dir = self.root / f"pass-{mode}"
                prepared, _profile, launch_root = self._build_authenticated_apt_fixture(
                    case_dir, rm_fault_mode=mode
                )
                env = self._fixture_bin_env(case_dir)
                runs = diagnostic.execute_application_smoke(
                    prepared=prepared,
                    system="x86_64-linux",
                    launch_root=launch_root,
                    env=env,
                    current071_cleanup_observation=True,
                )
                self.assertEqual([r["scenario"] for r in runs], ["C", "C-signal"])
                self.assertTrue(all(set(r) == {"scenario", "receipt_sha256", "executable_sha256"} for r in runs))

    def test_real_node22_c_signal_step_projection_from_already_read_run_record(self) -> None:
        case_dir = self.root / "c-signal-fail"
        prepared, _profile, launch_root = self._build_authenticated_apt_fixture(
            case_dir, rm_fault_mode="none", scenario_steps="fail-host-status"
        )
        env = self._fixture_bin_env(case_dir)
        with self.assertRaises(ContractError) as caught:
            diagnostic.execute_application_smoke(
                prepared=prepared,
                system="x86_64-linux",
                launch_root=launch_root,
                env=env,
                current071_cleanup_observation=True,
            )
        obs = caught.exception.smoke_observation
        self.assertEqual(obs["scenario"], "C-signal")
        self.assertEqual(obs["cleanup_observation"]["status"], "no-cleanup-error-observed")
        self.assertEqual(obs["cleanup_observation"]["marker_count"], 0)
        self.assertIsNone(obs["cleanup_observation"]["errno_code"])
        steps_proj = obs["harness_problem_categories"]["receipt_steps"]
        self.assertEqual(steps_proj["status"], "observed")
        state_by_id = {s["id"]: s["state"] for s in steps_proj["steps"]}
        self.assertEqual(state_by_id["host-status"], "fail")
        self.assertEqual(state_by_id["app-shell"], "pass")
        self.assertNotIn("PRIVATE_STEP_DETAIL", json.dumps(obs))
        self.assertNotIn("inert-fixture", json.dumps(obs))

    def test_caller_boolean_alone_cannot_bypass_source_or_family_authentication(self) -> None:
        case_dir = self.root / "auth-guards"
        prepared, _profile, launch_root = self._build_authenticated_apt_fixture(case_dir)
        # 1. Non-boolean flag rejected
        for bad_flag in (1, "true", None, ["apt"]):
            with self.subTest(bad_flag=repr(bad_flag)), self.assertRaises(ContractError):
                diagnostic.execute_application_smoke(
                    prepared=prepared,
                    system="x86_64-linux",
                    launch_root=launch_root,
                    current071_cleanup_observation=bad_flag,  # type: ignore[arg-type]
                )
            with self.subTest(verify_bad_flag=repr(bad_flag)), self.assertRaises(ContractError):
                smoke.verify_nebular_runtime(
                    launch_root,
                    prepared,
                    "x86_64-linux",
                    current071_cleanup_observation=bad_flag,  # type: ignore[arg-type]
                )
        # 2. Non-APT families, missing container_client, Nix route, Darwin, or conflicting family/label rejected
        bad_contexts = (
            {**prepared, "family": "pacman", "label": "pacman"},
            {**prepared, "family": "dnf", "label": "dnf"},
            {**prepared, "family": "nix", "label": "nix"},
            {**prepared, "family": "apt", "label": "pacman"},
            {**prepared, "family": None, "label": None},
            {**prepared, "container_client": False},
            {**prepared, "nix_client": True},
            {**prepared, "environment_transform": "current071-nix-inherited-xdg-fontconfig-v1"},
            {**prepared, "source_generation": "historical"},
            {k: v for k, v in prepared.items() if k != "_source_readback_proof"},
        )
        for idx, bad_prep in enumerate(bad_contexts):
            with self.subTest(bad_context=idx), self.assertRaises(ContractError):
                cleanup_obs.prepare_current071_cleanup_observation(
                    bad_prep, system="x86_64-linux", platform="linux-x64", scenario="C"
                )
        with self.assertRaises(ContractError):
            cleanup_obs.prepare_current071_cleanup_observation(
                prepared, system="aarch64-darwin", platform="darwin-arm64", scenario="A"
            )
        # 3. 0.7.0 source rejected even when family="apt" and container_client=True
        prep070, _prof070, _lr070 = self._build_authenticated_apt_fixture(
            self.root / "auth-070", nebular_version="0.7.0"
        )
        with self.assertRaises(ContractError):
            cleanup_obs.prepare_current071_cleanup_observation(
                prep070, system="x86_64-linux", platform="linux-x64", scenario="C"
            )

    def test_node22_wrapper_refuses_tampered_target_or_invalid_flags_before_import(self) -> None:
        case_dir = self.root / "wrapper-guards"
        prepared, _profile, launch_root = self._build_authenticated_apt_fixture(case_dir)
        plan = cleanup_obs.prepare_current071_cleanup_observation(
            prepared, system="aarch64-linux", platform="linux-arm64", scenario="B"
        )
        wrapper = Path(plan["wrapper"])
        harness = Path(plan["harness"])
        evidence = Path(prepared["scratch"]) / "evidence"
        evidence.mkdir(exist_ok=True)
        base_argv = [
            shutil.which("node") or "node",
            str(wrapper),
            str(harness),
            "--platform", "linux-arm64",
            "--scenario", "B",
            "--launch-root", str(launch_root),
            "--checkout", str(prepared["checkout"]),
            "--evidence", str(evidence),
            "--label", "linux-arm64-B",
        ]
        # Valid invocation except invalid platform/scenario pair (darwin-arm64 / A)
        bad_pair = list(base_argv)
        bad_pair[bad_pair.index("--platform") + 1] = "darwin-arm64"
        bad_pair[bad_pair.index("--scenario") + 1] = "A"
        bad_pair[bad_pair.index("--label") + 1] = "darwin-arm64-A"
        proc = subprocess.run(bad_pair, capture_output=True, timeout=15)
        self.assertEqual(proc.returncode, 2)
        self.assertIn(b"refused unauthenticated target", proc.stderr)

        # Mismatched --checkout path refused
        other_dir = case_dir / "other-checkout"
        other_dir.mkdir()
        bad_checkout = list(base_argv)
        bad_checkout[bad_checkout.index("--checkout") + 1] = str(other_dir)
        proc2 = subprocess.run(bad_checkout, capture_output=True, timeout=15)
        self.assertEqual(proc2.returncode, 2)

        # Tampered native-rc-smoke.mjs byte refused before import
        orig_bytes = harness.read_bytes()
        try:
            harness.write_bytes(orig_bytes + b"\n// tampered\n")
            proc3 = subprocess.run(base_argv, capture_output=True, timeout=15)
            self.assertEqual(proc3.returncode, 2)
            self.assertEqual(proc3.stdout, b"")
        finally:
            harness.write_bytes(orig_bytes)

    def test_observe_and_validate_cleanup_observation_closed_states_and_idempotence(self) -> None:
        raw_marker = b"RS9_CURRENT071_CLEANUP_ERRNO=ENOTEMPTY\n"
        obs = cleanup_obs.observe_current071_cleanup(
            raw_marker,
            system="aarch64-linux",
            scenario="B",
            stderr_bytes=len(raw_marker),
            stderr_sha256=digest(raw_marker),
            complete=True,
        )
        self.assertEqual(obs["status"], "cleanup-error-observed")
        self.assertEqual(obs["errno_code"], "ENOTEMPTY")
        self.assertEqual(obs["marker_count"], 1)
        self.assertIsNone(obs["withheld_reason"])

        # Multiple markers withheld as multiple-markers
        multi = b"RS9_CURRENT071_CLEANUP_ERRNO=EACCES\nRS9_CURRENT071_CLEANUP_ERRNO=EPERM\n"
        obs_multi = cleanup_obs.observe_current071_cleanup(
            multi,
            system="aarch64-linux",
            scenario="B",
            stderr_bytes=len(multi),
            stderr_sha256=digest(multi),
            complete=True,
        )
        self.assertEqual(obs_multi["status"], "withheld")
        self.assertEqual(obs_multi["withheld_reason"], "multiple-markers")
        self.assertIsNone(obs_multi["errno_code"])

        # Malformed or suffixed markers withheld as invalid-marker
        for bad_raw in (
            b"RS9_CURRENT071_CLEANUP_ERRNO=ENOTEMPTY /tmp/nebular-rc-smoke-123\n",
            b"RS9_CURRENT071_CLEANUP_ERRNO=enotempty\n",
            b"RS9_CURRENT071_CLEANUP_ERRNO=\n",
            b"prefix RS9_CURRENT071_CLEANUP_ERRNO=EACCES\n",
            b"RS9_CURRENT071_CLEANUP_ERRNO=EACCES",
            b"RS9_CURRENT071_CLEANUP_ERRNO=EACCES\x00\n",
            b"RS9_CURRENT071_CLEANUP_ERRNO=\xff\n",
        ):
            with self.subTest(bad_raw=bad_raw):
                res = cleanup_obs.observe_current071_cleanup(
                    bad_raw,
                    system="x86_64-linux",
                    scenario="C",
                    stderr_bytes=len(bad_raw),
                    stderr_sha256=digest(bad_raw),
                    complete=True,
                )
                self.assertEqual(res["status"], "withheld")
                self.assertEqual(res["withheld_reason"], "invalid-marker")
                self.assertIsNone(res["errno_code"])
                self.assertNotIn("nebular-rc-smoke", json.dumps(res))

        # Incomplete stream withheld as incomplete-stream
        inc = cleanup_obs.observe_current071_cleanup(
            raw_marker,
            system="x86_64-linux",
            scenario="C",
            stderr_bytes=len(raw_marker),
            stderr_sha256=digest(raw_marker),
            complete=False,
        )
        self.assertEqual(inc["status"], "withheld")
        self.assertEqual(inc["withheld_reason"], "incomplete-stream")

        # Cross-family or mismatched sha256/system/scenario rejected as binding-mismatch
        for kwargs in (
            {"family": "pacman"},
            {"family": "dnf"},
            {"system": "x86_64-linux"},
            {"scenario": "C"},
            {"stderr_bytes": len(raw_marker) + 1},
            {"stderr_sha256": "f" * 64},
        ):
            params = {
                "system": "aarch64-linux",
                "scenario": "B",
                "stderr_bytes": len(raw_marker),
                "stderr_sha256": digest(raw_marker),
                "complete": True,
                **kwargs,
            }
            validated = cleanup_obs.validate_current071_cleanup_observation(obs, **params)
            self.assertEqual(validated["status"], "withheld")
            self.assertEqual(validated["withheld_reason"], "binding-mismatch")
            # Fixed point on re-validation
            self.assertEqual(
                cleanup_obs.validate_current071_cleanup_observation(validated, **params),
                validated,
            )

    def test_pages_smoke_diagnostic_retains_and_validates_cleanup_observation(self):
        from rs9.pages_smoke_diagnostic import validate_smoke_observation

        raw_marker = b"RS9_CURRENT071_CLEANUP_ERRNO=EBUSY\n"
        obs = cleanup_obs.observe_current071_cleanup(
            raw_marker,
            system="aarch64-linux",
            scenario="B",
            stderr_bytes=len(raw_marker),
            stderr_sha256=digest(raw_marker),
            complete=True,
        )
        raw_smoke = {
            "scenario": "B",
            "cause": "process-nonzero",
            "raw_returncode": 1,
            "stdout_bytes": 111,
            "stderr_bytes": len(raw_marker),
            "stdout_sha256": "4c01e0ee066068fba7bb6f3bee1ec7c6afc82cba982193c284d0f0b87efd7a9a",
            "stderr_sha256": digest(raw_marker),
            "stream_capture_complete": True,
            "log_categories": ["unclassified"],
            "receipt_error": "receipt-failed",
            "problem_codes": ["withheld-token"],
            "elapsed_ms": 120,
            "reason_token": "process-nonzero",
            "cleanup_observation": obs,
        }
        v1 = validate_smoke_observation(raw_smoke, system="aarch64-linux", family="apt")
        v2 = validate_smoke_observation(v1, system="aarch64-linux", family="apt")
        v3 = validate_smoke_observation(v2, system="aarch64-linux", family="apt")
        self.assertEqual(v1["cleanup_observation"], obs)
        self.assertEqual(v1, v2)
        self.assertEqual(v2, v3)


if __name__ == "__main__":
    unittest.main()
