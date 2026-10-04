"""Resolve hosted preparation inputs once, then use immutable identities everywhere."""
from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path
import re
import subprocess
from typing import Any, Callable, Dict

from rs9.errors import ContractError
from rs9.scratch import canonical

ARCHES = {"x86_64": "amd64", "aarch64": "arm64", "amd64": "amd64", "arm64": "arm64"}
INSTALLER_SYSTEMS = ("aarch64-darwin", "x86_64-linux", "aarch64-linux")


def _run_cmd(argv: list[str], runner: Callable, *, substage: str) -> subprocess.CompletedProcess:
    """Run subprocess command safely, narrowing failures to ContractError with safe hashes."""
    tool_name = Path(argv[0]).name if argv else "tool"
    try:
        res = runner(argv, capture_output=True, check=False, timeout=120)
    except subprocess.TimeoutExpired as err:
        out = err.stdout if isinstance(err.stdout, (bytes, bytearray)) else (err.stdout or b"")
        err_b = err.stderr if isinstance(err.stderr, (bytes, bytearray)) else (err.stderr or b"")
        raise ContractError(
            "TOOL_TIMEOUT",
            f"Container tool timed out during {substage}",
            details={
                "tool": tool_name,
                "substage": substage,
                "stdout_sha256": hashlib.sha256(out if isinstance(out, bytes) else str(out).encode()).hexdigest(),
                "stderr_sha256": hashlib.sha256(err_b if isinstance(err_b, bytes) else str(err_b).encode()).hexdigest(),
            },
        ) from None
    except subprocess.CalledProcessError as err:
        out = err.stdout if isinstance(err.stdout, (bytes, bytearray)) else (err.stdout or b"")
        err_b = err.stderr if isinstance(err.stderr, (bytes, bytearray)) else (err.stderr or b"")
        raise ContractError(
            "IMAGE_INSPECT_FAILED",
            f"Container inspect command failed with exit {err.returncode}",
            details={
                "tool": tool_name,
                "substage": substage,
                "exit_code": err.returncode,
                "stdout_sha256": hashlib.sha256(out if isinstance(out, bytes) else str(out).encode()).hexdigest(),
                "stderr_sha256": hashlib.sha256(err_b if isinstance(err_b, bytes) else str(err_b).encode()).hexdigest(),
            },
        ) from None
    except OSError:
        raise ContractError(
            "TOOL_EXECUTION",
            f"Container tool could not be executed during {substage}",
            details={"tool": tool_name, "substage": substage},
        ) from None

    if res.returncode != 0:
        out = res.stdout if isinstance(res.stdout, (bytes, bytearray)) else (res.stdout or b"")
        err_b = res.stderr if isinstance(res.stderr, (bytes, bytearray)) else (res.stderr or b"")
        raise ContractError(
            "IMAGE_INSPECT_FAILED",
            f"Container inspect command failed with exit {res.returncode}",
            details={
                "tool": tool_name,
                "substage": substage,
                "exit_code": res.returncode,
                "stdout_sha256": hashlib.sha256(out if isinstance(out, bytes) else str(out).encode()).hexdigest(),
                "stderr_sha256": hashlib.sha256(err_b if isinstance(err_b, bytes) else str(err_b).encode()).hexdigest(),
            },
        )
    return res


def resolve_image(repository: str, tag_or_digest: str, architecture: str, runner: Callable = subprocess.run) -> str:
    """Resolve and verify container image identity with single-manifest config proof support."""
    target_arch = ARCHES.get(architecture, architecture)
    ref = tag_or_digest
    inspect_ref = f"{repository}@{ref}" if ref.startswith("sha256:") else f"{repository}:{ref}"

    res_raw = _run_cmd(
        ["docker", "buildx", "imagetools", "inspect", "--raw", inspect_ref],
        runner,
        substage="image-manifest-inspect",
    )
    raw = res_raw.stdout
    raw_bytes = raw if isinstance(raw, bytes) else raw.encode("utf-8")
    raw_hash = "sha256:" + hashlib.sha256(raw_bytes).hexdigest()

    # Validate exact raw manifest hash against source digest if ref is a digest
    if ref.startswith("sha256:") and raw_hash != ref:
        raise ContractError("IMAGE_DIGEST", "Raw manifest hash does not match source digest")

    try:
        doc = json.loads(raw_bytes)
    except (ValueError, TypeError):
        raise ContractError("IMAGE_MANIFEST", "Manifest output is not valid JSON")

    if not isinstance(doc, dict):
        raise ContractError("IMAGE_MANIFEST", "Manifest object required")

    if "manifests" in doc:
        if not isinstance(doc["manifests"], list) or any(not isinstance(r, dict) or not isinstance(r.get("platform", {}), dict) for r in doc["manifests"]):
            raise ContractError("IMAGE_MANIFEST", "Manifest platform rows invalid")
        matches = [
            r for r in doc["manifests"]
            if r.get("platform", {}).get("os") == "linux" and r.get("platform", {}).get("architecture") == target_arch
        ]
        if len(matches) != 1:
            raise ContractError("IMAGE_PLATFORM", "One exact platform image manifest required")
        platform_digest = matches[0].get("digest")
        if not isinstance(platform_digest, str) or not re.fullmatch(r"sha256:[0-9a-f]{64}", platform_digest):
            raise ContractError("IMAGE_DIGEST", "Platform manifest digest invalid")
        platform_ref = f"{repository}@{platform_digest}"

        res_plat = _run_cmd(
            ["docker", "buildx", "imagetools", "inspect", "--raw", platform_ref],
            runner,
            substage="platform-manifest-inspect",
        )
        plat_raw = res_plat.stdout
        plat_bytes = plat_raw if isinstance(plat_raw, bytes) else plat_raw.encode("utf-8")
        if "sha256:" + hashlib.sha256(plat_bytes).hexdigest() != platform_digest:
            raise ContractError("IMAGE_DIGEST", "Platform manifest raw hash mismatch")

        try:
            plat_doc = json.loads(plat_bytes)
        except (ValueError, TypeError):
            raise ContractError("IMAGE_MANIFEST", "Platform manifest output is not valid JSON")

        if not isinstance(plat_doc, dict) or not isinstance(plat_doc.get("config"), dict):
            raise ContractError("IMAGE_MANIFEST", "Platform manifest config invalid")
        cfg_digest = plat_doc["config"].get("digest")
        if not isinstance(cfg_digest, str) or not re.fullmatch(r"sha256:[0-9a-f]{64}", cfg_digest):
            raise ContractError("IMAGE_PLATFORM", "Platform manifest lacks valid config digest")

        # Prove config OS and architecture using docker buildx inspect --format '{{json .Image}}' by platform manifest reference
        cfg_res = _run_cmd(
            ["docker", "buildx", "imagetools", "inspect", "--format", "{{json .Image}}", platform_ref],
            runner,
            substage="image-config-inspect",
        )
        try:
            cfg_doc = json.loads(cfg_res.stdout)
        except (ValueError, TypeError):
            raise ContractError("IMAGE_CONFIG", "Image config output is not valid JSON")

        if not isinstance(cfg_doc, dict) or cfg_doc.get("os") != "linux" or cfg_doc.get("architecture") != target_arch:
            raise ContractError("IMAGE_PLATFORM", "Image config os/architecture does not match required platform")

        final_digest = platform_digest

    elif "config" in doc:
        if not isinstance(doc["config"], dict):
            raise ContractError("IMAGE_PLATFORM", "Single manifest config invalid")
        cfg_digest = doc["config"].get("digest")
        if not isinstance(cfg_digest, str) or not re.fullmatch(r"sha256:[0-9a-f]{64}", cfg_digest):
            raise ContractError("IMAGE_PLATFORM", "Single manifest lacks valid config digest")

        final_digest = ref if ref.startswith("sha256:") else raw_hash
        platform_ref = f"{repository}@{final_digest}"

        # Prove config OS and architecture using docker buildx inspect --format '{{json .Image}}' by platform manifest reference
        cfg_res = _run_cmd(
            ["docker", "buildx", "imagetools", "inspect", "--format", "{{json .Image}}", platform_ref],
            runner,
            substage="image-config-inspect",
        )
        try:
            cfg_doc = json.loads(cfg_res.stdout)
        except (ValueError, TypeError):
            raise ContractError("IMAGE_CONFIG", "Image config output is not valid JSON")

        if not isinstance(cfg_doc, dict) or cfg_doc.get("os") != "linux" or cfg_doc.get("architecture") != target_arch:
            raise ContractError("IMAGE_PLATFORM", "Single manifest config os/architecture does not match required platform")
    else:
        raise ContractError("IMAGE_PLATFORM", "A platform-indexed image or valid single manifest is required")

    if not re.fullmatch(r"sha256:[0-9a-f]{64}", final_digest):
        raise ContractError("IMAGE_DIGEST", "Container digest is invalid")
    return repository + "@" + final_digest


def resolve_targets(targets: Dict[str, Any], runner: Callable = subprocess.run,
                    verify_source_pins: bool = False) -> Dict[str, Any]:
    """Resolve and validate container and Nix targets, requiring complete per-system pins."""
    pins = copy.deepcopy(targets)
    provenance: Dict[str, str] = {}

    for family in ("pacman", "rpm", "deb"):
        cfg = pins[family]
        source_cfg = targets[family]
        for arch in cfg["architectures"]:
            key = "container_digest" if family == "pacman" else "container_digests"
            old = source_cfg.get(key) if family == "pacman" else source_cfg.get(key, {}).get(arch)
            if old:
                image = old if "@sha256:" in old else cfg["container_repository"] + "@" + old
                if verify_source_pins and runner is not None:
                    image = resolve_image(cfg["container_repository"], image.split("@")[-1], arch, runner)
                provenance[family + "." + arch] = "source-pinned"
            else:
                raise ContractError("IMAGE_PIN_MISSING", "Every hosted container requires a source-reviewed digest",
                                    details={"family": family, "system": arch})
            if not re.fullmatch(r"[a-z0-9./_-]+@sha256:[0-9a-f]{64}", image):
                raise ContractError("IMAGE_DIGEST", "Immutable container reference required")
            if family == "pacman":
                cfg[key] = image
            else:
                cfg.setdefault(key, {})[arch] = image

    nix = pins["nix"]
    if (not isinstance(nix.get("nixpkgs_revision"), str)
            or not re.fullmatch(r"[0-9a-f]{40}", nix["nixpkgs_revision"])
            or not isinstance(nix.get("nixpkgs_nar_hash"), str)
            or not re.fullmatch(r"sha256-[A-Za-z0-9+/]{43}=", nix["nixpkgs_nar_hash"])):
        raise ContractError("NIX_PIN", "Source nixpkgs revision and nar hash required")
    provenance["nix.nixpkgs"] = "source-pinned"

    installer_pins = nix.get("installer_sha256_by_system")
    if not isinstance(installer_pins, dict):
        raise ContractError("NIX_PIN", "Per-system Nix installer sha256 pins required: installer_sha256_by_system")

    if set(installer_pins.keys()) != set(INSTALLER_SYSTEMS):
        raise ContractError("NIX_PIN", f"installer_sha256_by_system must contain exactly {list(INSTALLER_SYSTEMS)}")

    for sys_name in INSTALLER_SYSTEMS:
        sys_sha = installer_pins.get(sys_name)
        if not isinstance(sys_sha, str) or not re.fullmatch(r"[0-9a-f]{64}", sys_sha):
            raise ContractError("NIX_PIN", f"Missing or invalid installer sha256 pin for {sys_name}")
        provenance["nix." + sys_name] = "source-pinned"

    if "installer_sha256" in nix:
        del nix["installer_sha256"]

    nix["installer_sha256_by_system"] = installer_pins
    pins["pin_provenance"] = provenance
    pins["all_source_pinned"] = all(p == "source-pinned" for p in provenance.values())
    return pins


def execute(context: Dict[str, Any]) -> Dict[str, Any]:
    targets = json.loads((context["repository"] / "operators/live1/targets.json").read_bytes())
    runner = context.get("runner", subprocess.run)
    pins = resolve_targets(targets, runner=runner, verify_source_pins=True)
    path = context["scratch"] / "pins.json"
    path.write_bytes(canonical({"schema": "rs9.hosted-pins.v1alpha1", "production_enabled": False, "pins": pins}))
    return {
        "gates": [
            {"name": "pinned-targets-readback", "status": "pass"},
            {"name": "container-digests-resolved", "status": "pass"},
            {"name": "nixpkgs-pin-resolved", "status": "pass"},
        ],
        "artifacts": [path],
        "details": {
            "pins": pins,
            "reproducibility": "source-pinned" if pins["all_source_pinned"] else "run-resolved-not-reproducible"
        }
    }
