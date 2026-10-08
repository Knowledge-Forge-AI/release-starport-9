"""Exact file custody for a single reviewed hosted source and release projection."""
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import shutil
import subprocess

from rs9.errors import ContractError
from rs9.scratch import canonical
from rs9.security import scan_for_credentials, validate_safe_relative_posix_path

SCHEMA = "rs9.hosted-artifact-set.v1alpha2"


def diagnostic_bytes(source):
    """Validate bounded diagnostic JSON without exposing its rejected contents."""
    if source.stat().st_size > 64 * 1024 or source.suffix != ".json":
        raise ContractError("DIAGNOSTIC_LIMIT", "Bounded JSON diagnostics required")
    data = source.read_bytes()
    if len(data) > 64 * 1024:
        raise ContractError("DIAGNOSTIC_LIMIT", "Bounded JSON diagnostics required")
    try:
        text = data.decode("utf-8")
        value = json.loads(text)
    except (ValueError, UnicodeError, RecursionError):
        raise ContractError("DIAGNOSTIC_SCHEMA", "Diagnostic JSON required") from None
    scan_for_credentials(text)
    private = re.compile(r"/(?:" + "Users" + r"|home|root|private|tmp)/|~[/\\]|[A-Za-z]:\\")
    def scan(item, depth=0):
        if depth > 32:
            raise ContractError("DIAGNOSTIC_LIMIT", "Diagnostic nesting exceeds bound")
        if isinstance(item, str):
            if private.search(item):
                raise ContractError("PRIVATE_PATH", "Private paths forbidden in diagnostic custody")
        elif isinstance(item, dict):
            for key, child in item.items():
                scan(key, depth + 1)
                scan(child, depth + 1)
        elif isinstance(item, list):
            for child in item:
                scan(child, depth + 1)
    scan(value)
    return data


def file_identity(path):
    if path.is_symlink() or not path.is_file():
        raise ContractError("CUSTODY_FILE", "Physical artifact required")
    hasher = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            hasher.update(chunk)
    return {"size": path.stat().st_size, "sha256": hasher.hexdigest()}


def builder_identity(repository):
    paths = sorted([*repository.glob("src/rs9/*.py"), *repository.glob("nix/**/*"),
                    repository / "flake.nix", repository / "operators/live1/targets.json",
                    repository / "operators/live1/command-contracts.json",
                    repository / "operators/live1/rpm-lint-policy.json"])
    rows = [{"path": p.relative_to(repository).as_posix(), **file_identity(p)} for p in paths if p.is_file()]
    return hashlib.sha256(canonical(rows)).hexdigest()


def provenance(repository, ingestion_hash):
    return {"source_commit": os.environ.get("GITHUB_SHA", "0" * 40),
            "workflow_sha256": hashlib.sha256((repository / ".github/workflows/rs9-candidate-tests.yml").read_bytes()).hexdigest(),
            "contract_sha256": hashlib.sha256((repository / "operators/live1/hosted-lanes.json").read_bytes()).hexdigest(),
            "release_ingestion_sha256": ingestion_hash, "builder_source_sha256": builder_identity(repository),
            "ref": os.environ.get("GITHUB_REF"), "event": os.environ.get("GITHUB_EVENT_NAME"),
            "attempt": int(os.environ.get("GITHUB_RUN_ATTEMPT", "1"))}


def runner_facts():
    tools = {"python": platform.python_version()}
    for tool in ("node", "nix", "docker", "gpg", "dpkg-deb", "rpm", "pacman"):
        if shutil.which(tool):
            result = subprocess.run([tool, "--version"], capture_output=True, timeout=10)
            lines = (result.stdout or result.stderr).decode(errors="replace").splitlines()
            tools[tool] = lines[0][:256] if lines else "version-output-unavailable"
    return {"os": platform.system(), "architecture": platform.machine(), "kernel": platform.release(),
            "image_os": os.environ.get("ImageOS"), "image_version": os.environ.get("ImageVersion"), "tools": tools}


def retain(scratch, output, files, record):
    output.mkdir(parents=True, exist_ok=True)
    rows = []
    seen = set()
    for source in files:
        source = Path(source)
        if any(p.is_symlink() for p in (source, *source.parents)):
            raise ContractError("CUSTODY_FILE", "Linked custody source refused")
        relative = Path(source).relative_to(scratch).as_posix()
        validate_safe_relative_posix_path(relative)
        if relative in seen:
            continue
        seen.add(relative)
        target = output / "objects" / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        if "diagnostics" in Path(relative).parts:
            try:
                data = diagnostic_bytes(source)
            except ContractError as error:
                identity = file_identity(source)
                failure = {"path": relative, "reason": error.code, **identity}
                record.setdefault("diagnostic_scan_failures", []).append(failure)
                # The primary client/verifier failure remains the lane's cause.
                if not record.get("execution_error"):
                    record["execution_error"] = "DIAGNOSTIC_CUSTODY"
                data = canonical({"schema": "rs9.withheld-diagnostic.v1alpha1",
                                  "status": "withheld", **failure})
                if target.suffix != ".json":
                    target = target.with_name(target.name + ".withheld.json")
            target.write_bytes(data)
        else:
            shutil.copyfile(source, target)
        kind = "custody" if target.name.endswith((".whl", ".rpm", ".deb", ".pkg.tar.zst", ".pkg.tar.xz")) else "evidence"
        fixture_copy = kind == "custody" and record["lane"] in {"rpm", "pacman", "pages"} and "unsigned" not in relative and "custody" not in relative
        rows.append({"path": target.relative_to(output).as_posix(), **file_identity(target), "kind": kind,
                     "promotion": "fixture-test-only" if fixture_copy else "candidate-policy-pending" if target.suffix == ".whl" and target.stem.rsplit("-", 1)[-1].startswith("linux_") else "candidate-only"})
    receipt_name = record["lane"] + "-" + record["system"] + ".json"
    raw = canonical(record)
    scan_for_credentials(raw.decode())
    (output / receipt_name).write_bytes(raw)
    manifest = {"schema": SCHEMA, **record["provenance"], "lane": record["lane"], "system": record["system"],
                "production_enabled": False, "publication_authority": False, "runner": record["runner"],
                "files": sorted(rows, key=lambda r: r["path"]),
                "qualification_receipt_hashes": {receipt_name: hashlib.sha256(raw).hexdigest()}}
    (output / "artifact-manifest.json").write_bytes(canonical(manifest))
    return manifest


def verify_set(directory, expected_provenance=None):
    path = directory / "artifact-manifest.json"
    manifest = json.loads(path.read_bytes())
    if manifest.get("schema") != SCHEMA or manifest.get("production_enabled") is not False or manifest.get("publication_authority") is not False:
        raise ContractError("CUSTODY_SCHEMA", "Non-production custody manifest required")
    if expected_provenance and any(manifest.get(k) != v for k, v in expected_provenance.items()):
        raise ContractError("CUSTODY_SOURCE", "Mixed source, workflow, contract or release custody")
    paths = [r["path"] for r in manifest["files"]]
    if len(set(paths)) != len(paths):
        raise ContractError("CUSTODY_INVENTORY", "Duplicate object paths")
    for row in manifest["files"]:
        validate_safe_relative_posix_path(row["path"])
        target = directory / row["path"]
        if any(p.is_symlink() for p in (target, *target.parents)) or file_identity(target) != {k: row[k] for k in ("size", "sha256")}:
            raise ContractError("CUSTODY_HASH", "Custody bytes or path changed")
    for relative, sha in manifest["qualification_receipt_hashes"].items():
        validate_safe_relative_posix_path(relative)
        if file_identity(directory / relative)["sha256"] != sha:
            raise ContractError("CUSTODY_RECEIPT", "Qualification receipt changed")
    expected = set(paths) | set(manifest["qualification_receipt_hashes"]) | {"artifact-manifest.json"}
    actual = {p.relative_to(directory).as_posix() for p in directory.rglob("*") if p.is_file() or p.is_symlink()}
    if expected != actual:
        raise ContractError("CUSTODY_INVENTORY", "Missing or surplus artifact object")
    return manifest
