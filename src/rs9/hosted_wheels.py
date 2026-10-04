"""Deterministic hosted candidate wheel builder, verification, and qualification driver.

Builds, double-checks determinism, verifies strict bidirectional RECORD inventories,
and qualifies all 3 hosted wheel candidate platforms:
- aarch64-darwin (macOS arm64)
- x86_64-linux (Linux x86_64)
- aarch64-linux (Linux aarch64)

Fail-closed properties:
- Retains exact candidate-only Linux wheels; production Linux wheels remain strictly withheld.
- Probes bound to parent command contracts; unbound commands report not-run.
- Linux executes under unshare --net / setpriv network isolation; Darwin allowed offline not-run.
- Inspects immutable release capture source tools for released sidecar verifier representation without inventing.
- Shared execute(context) -> gates/artifacts/details interface.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import platform as sys_platform
import posixpath
import shutil
import stat
import subprocess
import sys
from typing import Any, Mapping

from rs9.candidate import capture_generation
from rs9.errors import ContractError
from rs9.hosted_commands import linux_runtime_prefix, runtime_environment
from rs9.hosted_contract import (
    REQUIRED_GATES,
    validate_execution_context,
    validate_execution_result,
)
from rs9.npm_deps import closure_for_capture
from rs9.release_core import ReleaseCapture, digest
from rs9.scratch import canonical, physical_directory
from rs9.verify_wheel import (
    verify_double_build,
    verify_nebular_sidecar_representation,
    verify_offline_venv_lifecycle,
)
from rs9.wheel import (
    THEME_FORGE_PRODUCTS,
    canonical_product_id,
    verify_wheel_record_bidirectional,
)
from rs9.wheel_capture import build_capture_wheel
from rs9.wheel_native import build_native_wheel

SUPPORTED_WHEEL_SYSTEMS: frozenset[str] = frozenset(
    {"aarch64-darwin", "x86_64-linux", "aarch64-linux"}
)

PRODUCT_VERSIONS: dict[str, str] = {
    "theme-forge-stellar-burst": "0.6.1",
    "theme-forge-stellar-loom": "0.4.0",
    "theme-forge-solar-sail": "0.2.1",
    "theme-forge-nebular-fusion": "0.6.1",
}


def _get_target_platform(system: str) -> str:
    if "darwin" in system:
        return "aarch64-apple-darwin"
    elif "x86_64" in system:
        return "x86_64-unknown-linux-gnu"
    elif "aarch64" in system:
        return "aarch64-unknown-linux-gnu"
    raise ContractError("INVALID_ARCHITECTURE", f"Unsupported wheel system: {system}")


def _resolve_offline_npm_archives(
    capture: ReleaseCapture,
    product_id: str,
    scratch: Path,
    inputs: Path | None,
    client: Any | None,
) -> dict[str, Path] | None:
    pkg_json = json.loads(capture.source.get("package.json", "{}"))
    if not (pkg_json.get("dependencies") or product_id == "theme-forge-stellar-burst"):
        return None

    closure = closure_for_capture(capture)
    archives: dict[str, Path] = {}
    for idx, row in enumerate(closure):
        arc_name = posixpath.basename(row["url"])
        staged = inputs / arc_name if inputs else None
        if staged and staged.is_file():
            archives[row["path"]] = staged
        elif client:
            dest = scratch / "npm_downloads" / f"dep-{product_id}-{idx}.tgz"
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_bytes(client.get(row["url"], request_class="npm-tarball", limit=32 * 1024 * 1024))
            archives[row["path"]] = dest
    return archives


def execute(context: dict[str, Any]) -> dict[str, Any]:
    """Execute real hosted candidate wheel builds, determinism, and lifecycle qualification."""
    validate_execution_context(context)
    repository = physical_directory(context["repository"])
    scratch = physical_directory(context["scratch"])
    system = context["system"]
    if system not in SUPPORTED_WHEEL_SYSTEMS:
        raise ContractError("INVALID_ARCHITECTURE", f"Unsupported wheel system: {system}")

    inputs: Path | None = (
        physical_directory(context["inputs"]) if context.get("inputs") else None
    )
    client: Any = context.get("client")
    binding: dict[str, Any] = context.get("binding", {})

    captures: list[tuple[ReleaseCapture, dict[str, Any], dict[str, Any]]] = context.get("captures", [])
    if not captures:
        capture_root = scratch / "capture"
        capture_root.mkdir(parents=True, exist_ok=True)
        checkout_binding = binding.get("checkout_binding", f"hosted:{binding.get('source_commit', 'main')}")
        captures = capture_generation(
            repository,
            capture_root,
            client=client,
            checkout_binding=checkout_binding,
        )

    gates: list[dict[str, Any]] = []
    artifacts: list[Path] = []
    product_records: dict[str, Any] = {}

    retained_dir = scratch / "retained"
    retained_dir.mkdir(parents=True, exist_ok=True)
    build_root = scratch / "build"
    build_root.mkdir(parents=True, exist_ok=True)

    is_darwin = "darwin" in system.lower()
    is_linux = "linux" in system.lower()
    target_platform = _get_target_platform(system)

    # 1. Deterministic double-build and strict RECORD check for all candidate products
    build_all_passed = True
    for capture, intent, profile in captures:
        product_id = intent["project"]["id"]
        version = PRODUCT_VERSIONS[product_id]
        is_native = product_id == "theme-forge-nebular-fusion"

        proj_build_a = build_root / product_id / "build_a"
        proj_build_b = build_root / product_id / "build_b"
        proj_build_a.mkdir(parents=True, exist_ok=True)
        proj_build_b.mkdir(parents=True, exist_ok=True)

        if is_native:
            first, second = verify_double_build(
                build_native_wheel,
                product_id,
                version,
                capture=capture,
                target_platform=target_platform,
                candidate_only=True,
                profile_result=profile,
                output_dir_a=proj_build_a,
                output_dir_b=proj_build_b,
            )
        else:
            dep_archives = _resolve_offline_npm_archives(
                capture, product_id, scratch, inputs, client
            )
            first, second = verify_double_build(
                build_capture_wheel,
                product_id,
                version,
                capture=capture,
                dependency_archives=dep_archives,
                profile_result=profile,
                output_dir_a=proj_build_a,
                output_dir_b=proj_build_b,
            )

        # Strict bidirectional RECORD verification across entire inventory
        record_inv = verify_wheel_record_bidirectional(first.wheel_path)
        if not record_inv["record_valid"]:
            build_all_passed = False
            gates.append({
                "name": f"record.{product_id}",
                "status": "fail",
                "reason": "strict-record-validation-failed",
            })
        else:
            gates.append({"name": f"record.{product_id}", "status": "pass"})

        # Retain candidate wheel artifact
        retained_wheel = retained_dir / first.filename
        retained_wheel.write_bytes(first.wheel_bytes)
        artifacts.append(retained_wheel)

        product_records[product_id] = {
            "filename": first.filename,
            "sha256": first.sha256,
            "size": first.size,
            "tag": first.tag,
            "can_publish": first.can_publish,
            "candidate_only": first.record.get("candidate_only", False),
            "promotability": first.record.get("promotability", "candidate"),
            "manylinux_proven": first.record.get("manylinux_proven", False),
            "inventory_members_count": record_inv["member_count"],
        }
        gates.append({"name": f"build.{product_id}", "status": "pass"})

    if build_all_passed:
        gates.append({"name": "wheel-deterministic-build", "status": "pass"})
    else:
        gates.append({"name": "wheel-deterministic-build", "status": "fail", "reason": "double-build-record-mismatch"})

    # Runtime denial is proved by an actual negative TCP probe, not tool discovery.
    net_prefix = []
    if is_darwin:
        gates.append({"name": "wheel-offline-isolation", "status": "not-run",
                      "reason": "darwin-offline-isolation-unsupported"})
    else:
        net_prefix = linux_runtime_prefix()
        negative = subprocess.run([*net_prefix, sys.executable, "-c",
            "import socket; s=socket.socket(); s.settimeout(2); "
            "assert s.connect_ex(('1.1.1.1',443)) != 0"], capture_output=True,
            env=runtime_environment(), timeout=10)
        if negative.returncode:
            raise ContractError("NETWORK_DENIAL", "Runtime egress denial probe failed")
        gates.append({"name": "wheel-offline-isolation", "status": "pass"})

    from rs9.hosted_commands import run_probes
    from rs9.hosted_smoke import prepare_smoke, verify_nebular_runtime
    neb = next(c for c, i, _ in captures if i["project"]["id"] == "theme-forge-nebular-fusion")
    prepared = prepare_smoke(neb, captures, client, scratch / "native-smoke")
    sidecar_details = None
    probe_gates, lifecycle_records = [], {}
    for capture, intent, _ in captures:
        product_id = intent["project"]["id"]
        wheel_path = retained_dir / product_records[product_id]["filename"]
        def verify_installed(path, prefix, env, command=None):
            nonlocal sidecar_details
            if is_linux:
                prefix = linux_runtime_prefix(env)
            rows = run_probes(command, path, repository=repository, prefix=prefix, env=env)
            if any(r["status"] != "pass" for r in rows):
                raise ContractError("COMMAND_CONTRACT", "Released command contract is incomplete")
            probe_gates.extend(rows)
            if command == "tfnf":
                roots = list(Path(env["THEME_FORGE_CACHE_DIR"]).glob("entries/*/payload/*"))
                if len(roots) != 1:
                    raise ContractError("SIDECAR_REPRESENTATION", "Installed wheel did not materialize one payload")
                sidecar_details = verify_nebular_runtime(roots[0], prepared, system, prefix, env)
            return {"status": "pass"}
        commands = {}
        for name in THEME_FORGE_PRODUCTS[product_id]["console_scripts"]:
            commands[name] = {"verifier": lambda p, pre, env, name=name: verify_installed(p, pre, env, name)}
        lifecycle_records[product_id] = verify_offline_venv_lifecycle(
            wheel_path, distribution_name=THEME_FORGE_PRODUCTS[product_id]["distribution_name"],
            commands_to_test=commands, venv_dir=scratch / "venvs" / product_id,
            cache_dir=scratch / "cache" / product_id, command_prefix=net_prefix)
    gates.extend(probe_gates)
    gates.append({"name": "wheel-lifecycle-install-test", "status": "pass"})
    if sidecar_details is None:
        raise ContractError("SIDECAR_REPRESENTATION", "Installed wheel native verifier was not executed")
    gates.append({"name": "wheel-native-verifier", "status": "pass"})
    if is_linux:
        from rs9.hosted_wheel_clients import qualify
        client_gates, client_files = qualify(context, {pid:retained_dir / rec["filename"] for pid,rec in product_records.items()}, prepared)
        gates.extend(client_gates)
        artifacts.extend(client_files)
    # 5. Manifest generation
    manifest = {
        "schema": "rs9.hosted-wheels-manifest.v1alpha1",
        "system": system,
        "production_enabled": False,
        "gates": gates,
        "products": product_records,
        "sidecar_verifier": sidecar_details,
    }
    manifest_path = scratch / "hosted-wheels-manifest.json"
    manifest_bytes = canonical(manifest)
    manifest_path.write_bytes(manifest_bytes)
    artifacts.append(manifest_path)

    result = {
        "gates": gates,
        "artifacts": artifacts,
        "details": {
            "system": system,
            "manifest": manifest,
            "manifest_path": manifest_path.relative_to(scratch).as_posix(),
            "manifest_sha256": digest(manifest_bytes),
            "products": product_records,
        },
    }
    return validate_execution_result(result)
