"""Deterministic intent manifest with evidence for the parsed input bytes."""
import json
import unicodedata
from rs9.constants import SCHEMA_NORMALIZED
from rs9.cross_validator import resolve_targets
from rs9.destinations import load_destinations
from rs9.project import load_project
from rs9.releases import safe_tag
from rs9.security import validate_safe_basename, validate_version_string


def nfc_data(value):
    if isinstance(value, str):
        return unicodedata.normalize("NFC", value)
    if isinstance(value, list):
        return [nfc_data(item) for item in value]
    if isinstance(value, dict):
        return {unicodedata.normalize("NFC", key): nfc_data(item) for key, item in value.items()}
    return value


def normalized_asset(asset, version):
    name = asset["name"].replace("{version}", version)
    validate_safe_basename(name, "resolved asset name")
    result = {"id": asset["id"], "name": name, "format": asset["format"],
              "platforms": sorted(asset["platforms"]), "commands": dict(asset["commands"])}
    if "launchers" in asset:
        result["launchers"] = dict(asset["launchers"])
    return result


def normalized_check(check, version):
    result = {"id": check["id"], "argv": list(check["argv"]),
              "requires-display": check["requires-display"],
              "expect-exit": check.get("expect-exit", 0)}
    if "expect-stdout-contains" in check:
        result["expect-stdout-contains"] = check["expect-stdout-contains"].replace("{version}", version)
    return result


def normalized_desktop(desktop):
    return {
        "categories": sorted(desktop["categories"]),
        "command": desktop["command"],
        "icon": {
            "path": desktop["icon"]["path"],
            "source": desktop["icon"]["source"],
        },
    }


def project_semantics(project, version):
    license = project["license"]
    result = {"project": dict(project["project"]),
              "license": {"expression": license["expression"], "source": license["source"],
                          "files": sorted(license["files"])},
              "commands": sorted(project.get("commands", []), key=lambda c: c["name"]),
              "checks": sorted([normalized_check(c, version) for c in project.get("checks", [])],
                               key=lambda c: c["id"])}
    if "status" in license:
        result["license"]["status"] = license["status"]
    if "desktop" in project:
        result["desktop"] = normalized_desktop(project["desktop"])
    if "runtime" in project:
        result["runtime"] = dict(project["runtime"])
    return result



def normalize(project_dir, destinations_path, version):
    validate_version_string(version)
    tenant_hashes, destination_hashes = {}, {}
    project = load_project(project_dir, input_hashes=tenant_hashes)
    destinations = load_destinations(destinations_path, input_hashes=destination_hashes)
    result = project_semantics(project["project.toml"], version)
    release = project["releases.toml"]
    tag = release["release"]["tag"].replace("{version}", version)
    safe_tag(tag)
    result.update(schema=SCHEMA_NORMALIZED, tag=tag, version=version)
    result["release"] = {"tag": tag, "version": version, "prerelease": release["release"]["prerelease"]}
    if "evidence" in release:
        policy = release["evidence"]
        rows = [{**row, "name": row["name"].replace("{version}", version)} for row in policy["assets"]]
        for row in rows:
            validate_safe_basename(row["name"])
        result["release"]["evidence"] = {"profile": policy["profile"], "checksums": policy["checksums"],
                                           "assets": sorted(rows, key=lambda row: row["role"])}
    result["assets"] = sorted([normalized_asset(a, version) for a in release["assets"]], key=lambda a: a["id"])
    result["targets"] = resolve_targets(project, destinations)
    result["evidence"] = {"inputs": [{"filename": filename, "sha256": digest}
                                    for filename, digest in sorted({**tenant_hashes, **destination_hashes}.items())]}
    return (json.dumps(nfc_data(result), indent=2, sort_keys=True, ensure_ascii=False) + "\n").encode("utf-8")
