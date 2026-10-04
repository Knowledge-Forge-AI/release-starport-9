"""Resolve hosted preparation inputs once, then use immutable identities everywhere."""
import copy
import hashlib
import json
from pathlib import Path
import re
import subprocess

from rs9.errors import ContractError
from rs9.scratch import canonical

ARCHES = {"x86_64": "amd64", "aarch64": "arm64", "amd64": "amd64", "arm64": "arm64"}


def resolve_image(repository, tag, architecture, runner=subprocess.run):
    result = runner(["docker", "buildx", "imagetools", "inspect", "--raw", repository + ":" + tag],
                    capture_output=True, check=True, timeout=120)
    raw = result.stdout
    doc = json.loads(raw)
    if "manifests" in doc:
        matches = [r for r in doc["manifests"] if r.get("platform", {}).get("os") == "linux"
                   and r["platform"].get("architecture") == ARCHES[architecture]]
        if len(matches) != 1:
            raise ContractError("IMAGE_PLATFORM", "One exact platform image manifest required")
        digest = matches[0]["digest"]
    else:
        raise ContractError("IMAGE_PLATFORM", "A platform-indexed image is required; unbound single manifests are refused")
    if not re.fullmatch(r"sha256:[0-9a-f]{64}", digest):
        raise ContractError("IMAGE_DIGEST", "Container digest is invalid")
    return repository + "@" + digest


def resolve_targets(targets, runner=subprocess.run):
    pins = copy.deepcopy(targets)
    provenance = {}
    for family in ("pacman", "rpm", "deb"):
        cfg = pins[family]
        source_cfg = targets[family]
        for arch in cfg["architectures"]:
            key = "container_digest" if family == "pacman" else "container_digests"
            old = source_cfg.get(key) if family == "pacman" else source_cfg.get(key, {}).get(arch)
            if old:
                image = old if "@sha256:" in old else cfg["container_repository"] + "@" + old
                provenance[family + "." + arch] = "source-pinned"
            else:
                image = resolve_image(cfg["container_repository"], cfg["container_tag"], arch, runner)
                provenance[family + "." + arch] = "run-resolved"
            if not re.fullmatch(r"[a-z0-9./_-]+@sha256:[0-9a-f]{64}", image):
                raise ContractError("IMAGE_DIGEST", "Immutable container reference required")
            if family == "pacman":
                cfg[key] = image
            else:
                cfg.setdefault(key, {})[arch] = image
    nix = pins["nix"]
    if not re.fullmatch(r"[0-9a-f]{40}", nix.get("nixpkgs_revision", "")) or not nix.get("nixpkgs_nar_hash"):
        raise ContractError("NIX_PIN", "Source nixpkgs revision and nar hash required")
    pins["pin_provenance"] = provenance
    pins["all_source_pinned"] = all(p == "source-pinned" for p in provenance.values())
    return pins


def execute(context):
    targets = json.loads((context["repository"] / "operators/live1/targets.json").read_bytes())
    pins = resolve_targets(targets)
    path = context["scratch"] / "pins.json"
    path.write_bytes(canonical({"schema": "rs9.hosted-pins.v1alpha1", "production_enabled": False, "pins": pins}))
    return {"gates": [{"name": "pinned-targets-readback", "status": "pass"},
                       {"name": "container-digests-resolved", "status": "pass"},
                       {"name": "nixpkgs-pin-resolved", "status": "pass"}],
            "artifacts": [path], "details": {"pins": pins,
            "reproducibility": "source-pinned" if pins["all_source_pinned"] else "run-resolved-not-reproducible"}}
