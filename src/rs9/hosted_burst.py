"""Prove the installed Burst release loader can load its target native prebuild."""
import json
from pathlib import Path
import re
import subprocess

from rs9.burst_native import BURST_CLOSED_PREBUILDS, inspect_binary_member, extract_macho_deployment_minimum
from rs9.errors import ContractError
from rs9.hosted_platforms import platform_contract
from rs9.release_core import digest
from rs9.scratch import physical_directory


def validate_load_receipt(receipt, expected, system, *, expected_addon_path=None):
    contract = platform_contract(system)
    if not isinstance(receipt, dict) or receipt.get("loaded") is not True:
        raise ContractError("BURST_NATIVE_LOAD", "Released Burst loader rejected its installed addon")
    if set(receipt) != {"loaded", "artifact", "loads", "sha256", "node_version", "node_abi", "platform", "architecture"}:
        raise ContractError("BURST_NATIVE_LOAD", "Closed native load receipt required")
    loads = receipt.get("loads")
    if not isinstance(loads, list) or len(loads) != 1:
        raise ContractError("BURST_NATIVE_LOAD_COUNT", "Exactly one installed native addon load required")
    target_path = expected_addon_path if expected_addon_path is not None else expected["path"]
    if loads[0] != target_path or receipt.get("artifact") != contract.native_prebuild_key:
        raise ContractError("BURST_NATIVE_LOAD_TARGET", "Released loader selected a foreign or external addon")
    if receipt.get("sha256") != expected["sha256"]:
        raise ContractError("BURST_NATIVE_LOAD_BYTES", "Loaded addon differs from the authenticated wheel")
    if (not isinstance(receipt.get("node_version"), str)
            or not re.fullmatch(r"v[0-9]+\.[0-9]+\.[0-9]+", receipt["node_version"])
            or int(receipt["node_version"].split(".")[0][1:]) < 22
            or not isinstance(receipt.get("node_abi"), str)
            or not re.fullmatch(r"[0-9]{1,6}", receipt["node_abi"])):
        raise ContractError("BURST_NATIVE_NODE", "Observed Node version and ABI required")
    expected_platform = "darwin" if system.endswith("darwin") else "linux"
    expected_arch = "x64" if system.startswith("x86_64") else "arm64"
    if (receipt.get("platform"), receipt.get("architecture")) != (expected_platform, expected_arch):
        raise ContractError("BURST_NATIVE_LOAD_TARGET", "Node host differs from the wheel platform contract")
    return {"status": "pass", "proof": "installed-released-loader-self-test", **receipt}


def verify_burst_payload(payload_root, record, system, scratch, *, layout_prefix="package", prefix=(), env=None, runner=None, evidence_sink=None):
    """Run the released lazy loader against an authentic payload root with selectable layout and runner seam."""
    expected = record.get("target_native_addon")
    contract = platform_contract(system)
    if (record.get("platform_specific") is not True or record.get("target_system") != system
            or not isinstance(expected, dict)
            or expected.get("path") != BURST_CLOSED_PREBUILDS[contract.native_prebuild_key]
            or not re.fullmatch(r"[0-9a-f]{64}", expected.get("sha256", ""))):
        raise ContractError("BURST_NATIVE_TARGET", "Authenticated platform-specific Burst record required")

    payload = physical_directory(payload_root)
    if layout_prefix == "package":
        addon_rel = expected["path"]
        loader_rel = "package/dist/directory-snapshot-native.js"
    elif not layout_prefix:
        addon_rel = expected["path"].removeprefix("package/")
        loader_rel = "dist/directory-snapshot-native.js"
    else:
        raise ContractError("BURST_NATIVE_TARGET", "Closed wheel or native-package layout required")

    addon = payload / addon_rel
    loader = payload / loader_rel
    for path in (addon, loader):
        if not path.is_file() or any(p.is_symlink() for p in (path, *path.parents)):
            raise ContractError("BURST_NATIVE_TARGET", "Physical installed target addon and released loader required")

    addon_bytes = addon.read_bytes()
    if digest(addon_bytes) != expected["sha256"]:
        raise ContractError("BURST_NATIVE_LOAD_BYTES", "Installed target prebuild bytes differ from the wheel")

    bin_info = inspect_binary_member(addon_rel, addon_bytes)
    if bin_info["arch"] != contract.expected_binary_arch:
        raise ContractError("BURST_NATIVE_TARGET", "Installed addon architecture differs from the target")
    if system == "aarch64-darwin":
        extract_macho_deployment_minimum(addon_bytes)

    loader_identity = record.get("native_loader")
    if (not isinstance(loader_identity, dict)
            or loader_identity.get("path") != "package/dist/directory-snapshot-native.js"
            or not re.fullmatch(r"[0-9a-f]{64}", loader_identity.get("sha256", ""))
            or digest(loader.read_bytes()) != loader_identity["sha256"]):
        raise ContractError("BURST_NATIVE_LOAD_BYTES", "Authenticated installed released loader required")

    scratch = Path(scratch)
    if scratch.exists():
        scratch = physical_directory(scratch)
        if any(scratch.iterdir()):
            raise ContractError("BURST_NATIVE_LOAD", "Empty physical probe directory required")
    else:
        physical_directory(scratch.parent)
        scratch.mkdir()
    preload = scratch / "observe-load.cjs"
    preload.write_text("""const fs=require('node:fs');
const path=require('node:path');
global.rs9Loads=[];
const original=process.dlopen;
process.dlopen=function(module,filename,...args) {
  const real=fs.realpathSync(filename);
  const base=fs.realpathSync(process.argv[2]);
  const relative=path.relative(base,real).split(path.sep).join('/');
  global.rs9Loads.push(relative.startsWith('../')||path.isAbsolute(relative)?'outside-installed-payload':relative);
  return original.call(this,module,filename,...args);
};
""")
    harness = scratch / "exercise-loader.mjs"
    harness_code = f"""import {{pathToFileURL}} from 'node:url';
import fs from 'node:fs';
import path from 'node:path';
import {{createHash}} from 'node:crypto';
let phase='import';
try {{
  const loader=await import(pathToFileURL(path.join(process.argv[2], {json.dumps(loader_rel)})));
  phase='load';
  const result=loader.loadDirectorySnapshotNative();
  const loads=global.rs9Loads;
  const sha=loads.length===1&&!loads[0].startsWith('outside-')?
    createHash('sha256').update(fs.readFileSync(path.join(process.argv[2],loads[0]))).digest('hex'):null;
  console.log(JSON.stringify({{loaded:result.ok===true,artifact:result.artifact,loads,sha256:sha,
    node_version:process.version,node_abi:process.versions.modules,platform:process.platform,architecture:process.arch}}));
  if(!result.ok)process.exitCode=2;
}} catch (error) {{
  const name=typeof error?.name==='string'&&/^[A-Za-z][A-Za-z0-9]{{0,63}}$/.test(error.name)?error.name:'Error';
  console.log(JSON.stringify({{loaded:false,phase,error_name:name}})); process.exitCode=2;
}}
"""
    harness.write_text(harness_code)

    cmd = [*prefix, "node", "--require", str(preload), str(harness), str(payload)]
    if runner is not None:
        raw_result = runner(cmd, env=env)
        if isinstance(raw_result, (tuple, list)):
            returncode = raw_result[0]
            stdout = raw_result[1] if isinstance(raw_result[1], bytes) else raw_result[1].encode()
            stderr = raw_result[2] if len(raw_result) > 2 else b""
            stderr = stderr if isinstance(stderr, bytes) else stderr.encode()
        else:
            returncode = raw_result.returncode
            stdout = raw_result.stdout if isinstance(raw_result.stdout, bytes) else raw_result.stdout.encode()
            stderr = raw_result.stderr if isinstance(raw_result.stderr, bytes) else raw_result.stderr.encode()
    else:
        try:
            sub_res = subprocess.run(cmd, env=env, capture_output=True, timeout=30)
            returncode = sub_res.returncode
            stdout = sub_res.stdout
            stderr = sub_res.stderr
        except (OSError, subprocess.TimeoutExpired):
            raise ContractError("BURST_NATIVE_LOAD", "Installed native loader probe could not execute") from None

    probe_evidence = {"preload_sha256": digest(preload.read_bytes()), "harness_sha256": digest(harness.read_bytes()),
                      "stdout_sha256": digest(stdout), "stderr_sha256": digest(stderr), "exit_code": returncode}
    if evidence_sink is not None:
        evidence_sink.update(probe_evidence)
    if returncode or len(stdout) > 4096:
        if len(stdout) <= 4096:
            try:
                failure = json.loads(stdout)
                if (isinstance(failure, dict) and failure.get("loaded") is False
                        and failure.get("phase") in ("import", "load")
                        and re.fullmatch(r"[A-Za-z][A-Za-z0-9]{0,63}", failure.get("error_name", ""))):
                    probe_evidence.update(phase=failure["phase"], reason_token=failure["error_name"])
            except (ValueError, UnicodeError):
                pass
        raise ContractError("BURST_NATIVE_LOAD", "Installed native loader probe failed",
                            details=probe_evidence)
    try:
        receipt = json.loads(stdout)
    except (ValueError, UnicodeError):
        raise ContractError("BURST_NATIVE_LOAD", "Bounded native load receipt required") from None
    return validate_load_receipt(receipt, expected, system, expected_addon_path=addon_rel)


def verify_installed_burst(console_script, record, system, scratch, prefix=(), env=None, runner=None, evidence_sink=None):
    """Run the released lazy loader unchanged inside the installed offline venv."""
    venv = physical_directory(Path(console_script).parent.parent)
    packages = list(venv.glob("lib/python*/site-packages/theme_forge_stellar_burst/payload"))
    if len(packages) != 1:
        raise ContractError("BURST_NATIVE_TARGET", "Exactly one installed Burst payload required")
    payload = physical_directory(packages[0])
    return verify_burst_payload(payload, record, system, scratch, layout_prefix="package", prefix=prefix, env=env, runner=runner, evidence_sink=evidence_sink)
