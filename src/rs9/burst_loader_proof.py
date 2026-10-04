"""Real released Stellar Burst 0.6.1 loader proof, offline closure, and payload verification."""
from __future__ import annotations

import json
import os
import posixpath
import re
import shutil
import subprocess
import sys
import types
from pathlib import Path
from typing import Any, Mapping

from rs9.burst_native import (
    BURST_BACKEND_NAME,
    BURST_CLOSED_PREBUILDS,
    BURST_PRODUCT_ID,
    extract_macho_deployment_minimum,
    inspect_binary_member,
)
from rs9.errors import ContractError
from rs9.github import PublicClient
from rs9.hosted_burst import validate_load_receipt, verify_burst_payload, verify_installed_burst
from rs9.hosted_platforms import platform_contract
from rs9.npm_deps import authenticate_dependencies, closure_for_capture
from rs9.release_core import ReleaseCapture, authenticate_release, capture_release, digest, authenticated_record_hash
from rs9.scratch import canonical, physical_directory
from rs9.verify_wheel import verify_wheel_record_bidirectional
from rs9.wheel_capture import build_capture_wheel

BURST_VERSION: str = "0.6.1"
BURST_TAG: str = "v0.6.1"
BURST_REPOSITORY: str = "Knowledge-Forge-AI/theme-forge-stellar-burst"
BURST_PAYLOAD_TGZ: str = "knowledge-forge-ai-theme-forge-stellar-burst-0.6.1.tgz"
BURST_PAYLOAD_SHA256: str = "53ef41a3de3335e042f2c4b1d299b1155b64bfc6556a84baf6a62cb28bcca209"
BURST_PAYLOAD_SIZE: int = 644313

BURST_LOADER_RELPATH: str = "package/dist/directory-snapshot-native.js"
BURST_LOADER_SHA256: str = "23a3bf942fa1f92fbf686b4cedc0ec2a9f6653ded6fd2df7ef9d3c58d6591e69"
BURST_LOADER_SIZE: int = 3639

_RAW_BURST_PREBUILD_IDENTITIES: dict[str, dict[str, Any]] = {
    "darwin-arm64": {
        "path": "package/native/directory-snapshot/prebuilds/darwin-arm64/native-addon-posix-openat-v1.node",
        "sha256": "2f842ce43f62c76b04884a92980037067c8e55dfd183c86e788f1c3ac8a533c8",
        "size": 53344,
        "format": "Mach-O 64-bit arm64",
        "arch": "arm64",
        "deployment_minimum": [13, 0],
    },
    "darwin-x64": {
        "path": "package/native/directory-snapshot/prebuilds/darwin-x64/native-addon-posix-openat-v1.node",
        "sha256": "41eb0b3091173132012565560d62b31f7320764c6fd6e780994fcef8803704c6",
        "size": 24200,
        "format": "Mach-O 64-bit x86_64",
        "arch": "x86_64",
        "deployment_minimum": [15, 0],
    },
    "linux-arm64-gnu": {
        "path": "package/native/directory-snapshot/prebuilds/linux-arm64-gnu/native-addon-posix-openat-v1.node",
        "sha256": "67fb6b85f339a7c2f43ababa20434b26a3ea9bb65b17e70257a03c07810beb79",
        "size": 73336,
        "format": "ELF 64-bit aarch64",
        "arch": "aarch64",
        "e_machine": 183,
    },
    "linux-x64-gnu": {
        "path": "package/native/directory-snapshot/prebuilds/linux-x64-gnu/native-addon-posix-openat-v1.node",
        "sha256": "a2999fc9ac1b1f0a31600595f7069e10aadb032f01059b4d7e64ed80cd8a38a8",
        "size": 27240,
        "format": "ELF 64-bit x86_64",
        "arch": "x86_64",
        "e_machine": 62,
    },
}

BURST_PREBUILD_IDENTITIES: Mapping[str, Mapping[str, Any]] = types.MappingProxyType({
    k: types.MappingProxyType(v) for k, v in _RAW_BURST_PREBUILD_IDENTITIES.items()
})

REAL_LOADER_CONTRACT: Mapping[str, Any] = types.MappingProxyType({
    "loader_module": BURST_LOADER_RELPATH,
    "loader_source": "src/directory-snapshot-native.ts",
    "loader_export": "loadDirectorySnapshotNative()",
    "loader_sha256": BURST_LOADER_SHA256,
    "loader_size": BURST_LOADER_SIZE,
    "backend_name": BURST_BACKEND_NAME,
    "backend_abi": 1,
    "exported_symbols": [
        "DIRECTORY_SNAPSHOT_BACKEND",
        "DIRECTORY_SNAPSHOT_BACKEND_ABI",
        "currentDirectorySnapshotArtifact",
        "loadDirectorySnapshotNative",
    ],
    "result_contract": {
        "success": {"ok": True, "artifact": "str", "addon": "object"},
        "failure": {"ok": False, "artifact": "str", "reason": "str"},
        "failure_reasons": [
            "unsupported-platform",
            "artifact-missing-or-corrupt",
            "backend-mismatch",
            "self-test-failed",
        ],
    },
    "dlopen_behavior": "Exactly once per process; loader caches result in module-scoped variable",
    "self_test_requirements": [
        "openFilesystemRoot() returns handle",
        "statHandle(root) directory validation with non-negative device/inode",
        "statFilesystem(root) filesystem class validation (apfs, ext4, unsupported)",
        "readDirectory(root) returns Array",
        "closeHandle(root) idempotent close and DIRECTORY_USE_AFTER_CLOSE verification",
    ],
})


def discover_burst_capture(
    capture_dir: str | Path | None = None,
    *,
    client: Any | None = None,
    scratch: Path | None = None,
) -> tuple[ReleaseCapture, dict[str, Any]]:
    """Discover authenticated release capture from directory, environment, or network via existing ingestion."""
    repo_root = Path(__file__).resolve().parents[2]
    sel_path = repo_root / "tests/fixtures/stellar-burst-0.6.1/selection.json"
    if not sel_path.is_file():
        raise ContractError("MISSING_FIXTURE", "Stellar Burst selection fixture required")
    selection = json.loads(sel_path.read_bytes())
    if "package-lock.json" not in selection.get("source_paths", []):
        selection["source_paths"] = sorted([*selection.get("source_paths", []), "package-lock.json"])

    target_dir: Path | None = None
    if capture_dir is not None:
        target_dir = physical_directory(capture_dir)
    elif os.environ.get("RS9_STELLAR_BURST_EVIDENCE_DIR"):
        target_dir = physical_directory(os.environ["RS9_STELLAR_BURST_EVIDENCE_DIR"])

    if target_dir is not None:
        capture = authenticate_release(selection, target_dir)
        return capture, {"source": "local-evidence-dir", "root": str(target_dir)}

    if scratch is None:
        raise ContractError("SCRATCH_REQUIRED", "Scratch directory required for network release ingestion")

    fetch_scratch = scratch / "captured_release"
    fetch_scratch.mkdir(parents=True, exist_ok=True)
    cl = client or PublicClient()
    try:
        capture_release(selection, fetch_scratch, client=cl)
    except Exception:
        raise ContractError("CAPTURE_FAILED", "Authenticated Burst release capture failed") from None

    capture = authenticate_release(selection, fetch_scratch)
    return capture, {"source": "authenticated-network-ingestion", "tag": BURST_TAG}


def resolve_burst_dependencies(
    capture: ReleaseCapture,
    *,
    client: Any | None = None,
    scratch: Path,
) -> dict[str, Path]:
    """Resolve and authenticate the 3 locked production dependencies without npm runtime."""
    closure = closure_for_capture(capture)
    archives_dir = scratch / "npm_downloads"
    archives_dir.mkdir(parents=True, exist_ok=True)
    cl = client or PublicClient()

    archives: dict[str, Path] = {}
    for idx, row in enumerate(closure):
        arc_filename = posixpath.basename(row["url"])
        dest = archives_dir / arc_filename
        if not dest.is_file():
            try:
                data = cl.get(row["url"], request_class="npm-tarball", limit=32 * 1024 * 1024)
                dest.write_bytes(data)
            except Exception:
                raise ContractError("NPM_DOWNLOAD_FAILED", "Locked dependency transport failed") from None
        archives[row["path"]] = dest

    authenticate_dependencies(capture, archives)
    return archives


def probe_local_node() -> dict[str, Any]:
    """Probe the local Node runtime for version and ABI eligibility without fabrication."""
    try:
        ver_proc = subprocess.run(["node", "--version"], capture_output=True, text=True, timeout=10)
        abi_proc = subprocess.run(["node", "-p", "process.versions.modules"], capture_output=True, text=True, timeout=10)
        plat_proc = subprocess.run(["node", "-p", "`${process.platform}:${process.arch}`"], capture_output=True, text=True, timeout=10)
    except (OSError, subprocess.SubprocessError):
        return {"available": False, "reason": "node-binary-unavailable"}

    if ver_proc.returncode != 0 or abi_proc.returncode != 0:
        return {"available": False, "reason": "node-execution-failed"}

    version = ver_proc.stdout.strip()
    abi = abi_proc.stdout.strip()
    plat_arch = plat_proc.stdout.strip().split(":")
    platform = plat_arch[0] if len(plat_arch) > 0 else ""
    arch = plat_arch[1] if len(plat_arch) > 1 else ""

    m = re.fullmatch(r"v(\d+)\.\d+\.\d+", version)
    if not m or int(m.group(1)) < 22:
        return {
            "available": False,
            "version": version,
            "abi": abi,
            "reason": f"node-version-insufficient: {version} (requires >= 22)",
        }

    return {
        "available": True,
        "version": version,
        "abi": abi,
        "platform": platform,
        "architecture": arch,
    }


def prove_burst_loader(
    *,
    system: str = "aarch64-darwin",
    capture_dir: str | Path | None = None,
    scratch_root: Path | None = None,
    output_evidence: Path | None = None,
    client: Any | None = None,
    runner: Any | None = None,
) -> dict[str, Any]:
    """Execute real authenticated Stellar Burst loader proof and produce bounded evidence."""
    if scratch_root is None:
        raise ContractError("SCRATCH_REQUIRED", "Explicit caller-owned scratch root required")
    scratch_base = physical_directory(scratch_root)
    contract = platform_contract(system)
    node_probe = probe_local_node()
    if not node_probe.get("available"):
        raise ContractError("NODE_UNAVAILABLE", node_probe.get("reason", "Node >= 22 runtime is unavailable"))

    expected_platform = "darwin" if system.endswith("darwin") else "linux"
    expected_arch = "x64" if system.startswith("x86_64") else "arm64"
    if (node_probe.get("platform"), node_probe.get("architecture")) != (expected_platform, expected_arch):
        raise ContractError(
            "HOST_ARCHITECTURE_MISMATCH",
            f"Local Node runtime ({node_probe.get('platform')}-{node_probe.get('architecture')}) differs from target system {system}",
        )

    # Establish persistent managed scratch below the explicit caller-owned root.
    run_id = f"burst-proof-{os.urandom(4).hex()}"
    run_dir = scratch_base / run_id
    run_dir.mkdir(parents=True, exist_ok=False)

    manifest_path = run_dir / "manifest.json"
    manifest_data = {
        "project": "release-starport-9",
        "phase": "live1-burst-loader-proof",
        "run_id": run_id,
        "purpose": "Stellar Burst 0.6.1 loader proof and offline closure qualification",
        "retention_state": "active",
    }
    manifest_path.write_bytes(canonical(manifest_data))

    succeeded = False
    try:
        capture, prov_info = discover_burst_capture(capture_dir, client=client, scratch=run_dir)
        payloads = capture.record.get("payloads", [])
        if (len(payloads) != 1 or payloads[0]["sha256"] != BURST_PAYLOAD_SHA256
                or payloads[0]["size"] != BURST_PAYLOAD_SIZE or payloads[0]["name"] != BURST_PAYLOAD_TGZ):
            raise ContractError("BURST_NATIVE_TARGET", "Exact authenticated Burst 0.6.1 release required")
        archives = resolve_burst_dependencies(capture, client=client, scratch=run_dir)

        # Build wheel deterministically with offline closure integrated
        wheel_out = run_dir / "wheel"
        wheel_out.mkdir(parents=True, exist_ok=True)
        build_res = build_capture_wheel(
            BURST_PRODUCT_ID,
            BURST_VERSION,
            capture,
            system=system,
            dependency_archives=archives,
            integrate_closure=True,
            output_dir=wheel_out,
            fixture_only=True,
        )
        if build_res.record.get("native_loader", {}).get("sha256") != BURST_LOADER_SHA256:
            raise ContractError("BURST_NATIVE_TARGET", "Discovered released loader contract identity changed")

        # Strict bidirectional RECORD verification
        inv = verify_wheel_record_bidirectional(build_res.wheel_path)
        if not inv["record_valid"]:
            raise ContractError("INVALID_RECORD", "Wheel RECORD validation failed")

        # Create isolated offline venv and install wheel
        venv_dir = run_dir / "venv"
        subprocess.check_call([sys.executable, "-m", "venv", str(venv_dir)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        pip_exe = venv_dir / "bin/pip"
        subprocess.check_call([str(pip_exe), "install", "--no-index", "--no-deps", "--disable-pip-version-check", str(build_res.wheel_path)],
                              stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

        console_script = venv_dir / "bin/tfsb"
        probe_scratch = run_dir / "burst-probe"
        probe_evidence = {}
        load_result = verify_installed_burst(console_script, build_res.record, system, probe_scratch, runner=runner,
                                             evidence_sink=probe_evidence)

        target_addon = build_res.record["target_native_addon"]
        evidence: dict[str, Any] = {
            "schema": "rs9.burst-loader-proof.v1alpha1",
            "status": "pass",
            "system": system,
            "product": BURST_PRODUCT_ID,
            "version": BURST_VERSION,
            "release_record_sha256": authenticated_record_hash(capture),
            "probe": probe_evidence,
            "release": {
                "repository": BURST_REPOSITORY,
                "tag": BURST_TAG,
                "release_id": capture.record["release"]["id"],
                "payload_asset": BURST_PAYLOAD_TGZ,
                "payload_sha256": BURST_PAYLOAD_SHA256,
                "payload_size_bytes": BURST_PAYLOAD_SIZE,
            },
            "loader_contract": {
                "module_path": BURST_LOADER_RELPATH,
                "sha256": BURST_LOADER_SHA256,
                "size_bytes": BURST_LOADER_SIZE,
                "export_function": REAL_LOADER_CONTRACT["loader_export"],
                "backend_name": BURST_BACKEND_NAME,
                "backend_abi": 1,
                "dlopen_behavior": "exactly-once-memoized",
                "result_shape": REAL_LOADER_CONTRACT["result_contract"],
            },
            "target_prebuild": {
                "key": contract.native_prebuild_key,
                "path": target_addon["path"],
                "sha256": target_addon["sha256"],
                "size_bytes": target_addon["size"],
                "format": target_addon["format"],
                "architecture": target_addon["arch"],
                **({"deployment_minimum": target_addon["macos_minimum"]} if "macos_minimum" in target_addon else {}),
            },
            "foreign_prebuilds": [
                {
                    "path": fp["path"],
                    "sha256": fp["sha256"],
                    "size_bytes": fp["size"],
                    "architecture": fp["architecture"],
                    "disposition": fp["disposition"],
                }
                for fp in build_res.record["foreign_prebuilds"]
            ],
            "offline_closure": [
                {
                    "package": dep["name"],
                    "version": dep["version"],
                    "sha256": dep["sha256"],
                    "integrity": dep["integrity"],
                    "size_bytes": dep["size"],
                }
                for dep in build_res.record["npm_dependencies"]["dependencies"]
            ],
            "wheel_artifact": {
                "filename": build_res.filename,
                "sha256": build_res.sha256,
                "tag": build_res.tag,
                "record_valid": inv["record_valid"],
            },
            "observed_load_receipt": {
                "proof": load_result["proof"],
                "loaded": load_result["loaded"],
                "artifact": load_result["artifact"],
                "loads_count": len(load_result["loads"]),
                "loads": load_result["loads"],
                "loaded_sha256": load_result["sha256"],
                "node_version": load_result["node_version"],
                "node_abi": load_result["node_abi"],
                "platform": load_result["platform"],
                "architecture": load_result["architecture"],
            },
        }

        if output_evidence is not None:
            out_p = Path(output_evidence)
            out_p.parent.mkdir(parents=True, exist_ok=True)
            out_p.write_bytes(canonical(evidence))

        succeeded = True
        return evidence

    finally:
        # Exact cleanup of ephemeral runtime resources
        for sub in ("venv", "burst-probe", "wheel", "npm_downloads", "captured_release"):
            target_sub = run_dir / sub
            if target_sub.is_dir():
                shutil.rmtree(target_sub)

        manifest_data["retention_state"] = "terminal"
        manifest_data["closeout_status"] = "pass" if succeeded else "fail"
        manifest_path.write_bytes(canonical(manifest_data))
