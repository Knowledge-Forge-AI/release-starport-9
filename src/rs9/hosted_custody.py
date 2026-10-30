"""Exact file custody for a single reviewed hosted source and release projection."""
import hashlib
from dataclasses import dataclass, field
import json
import os
from pathlib import Path
import platform
import re
import shutil
import subprocess
from weakref import WeakKeyDictionary

from rs9.current_generation import (HISTORICAL_GENERATION, CURRENT_GENERATION, distribution_paths,
                                    configuration_paths, configuration_identity)
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


def builder_identity(repository, *, generation=HISTORICAL_GENERATION):
    distribution_paths(generation)
    paths = sorted([*repository.glob("src/rs9/*.py"), *repository.glob("nix/**/*"),
                    repository / "flake.nix", repository / "operators/live1/targets.json",
                    repository / "operators/live1/command-contracts.json",
                    repository / "operators/live1/rpm-lint-policy.json"])
    rows = [{"path": p.relative_to(repository).as_posix(), **file_identity(p)} for p in paths if p.is_file()]
    if generation == CURRENT_GENERATION:
        rows.append({"selected_configuration_sha256": configuration_identity(repository, generation=generation)})
    return hashlib.sha256(canonical(rows)).hexdigest()


def source_tree_identity(repository, commit):
    """Require clean tracked/untracked source; legitimate ignored caches remain allowed."""
    if not (Path(repository) / ".git").exists():
        raise ContractError("HOSTED_SOURCE_TREE", "Real adopted Git checkout required")
    try:
        head = subprocess.run(["git", "rev-parse", "HEAD"], cwd=repository, capture_output=True, check=True, timeout=10).stdout.decode().strip()
        tree = subprocess.run(["git", "rev-parse", commit + "^{tree}"], cwd=repository, capture_output=True, check=True, timeout=10).stdout.decode().strip()
        changed = subprocess.run(["git", "status", "--porcelain", "--untracked-files=all"], cwd=repository, capture_output=True, check=True, timeout=10).stdout
    except (OSError, ValueError, subprocess.SubprocessError):
        raise ContractError("HOSTED_SOURCE_TREE", "Real adopted Git checkout required") from None
    if head != commit or changed or not re.fullmatch(r"[0-9a-f]{40}", tree):
        raise ContractError("HOSTED_SOURCE_TREE", "Source checkout differs from adopted commit")
    return tree


def source_identity(repository, commit, *, generation=CURRENT_GENERATION):
    """Recompute source bytes and Git tree without consulting executor GITHUB_* values."""
    workflow, contract, scope = distribution_paths(generation)
    if generation != CURRENT_GENERATION or not isinstance(commit, str) or not re.fullmatch(r"[0-9a-f]{40}", commit):
        raise ContractError("HOSTED_PROVENANCE", "Exact current source identity required")
    try:
        return {"source_commit": commit, "source_tree": source_tree_identity(repository, commit),
                "repository": "Knowledge-Forge-AI/release-starport-9", "workflow_path": workflow,
                "workflow_sha256": file_identity(repository / workflow)["sha256"],
                "contract_sha256": file_identity(repository / contract)["sha256"],
                "builder_source_sha256": builder_identity(repository, generation=generation),
                "configuration_sha256": configuration_identity(repository, generation=generation),
                "generation": generation, "qualification_scope": scope}
    except (ContractError, OSError, ValueError, TypeError, subprocess.SubprocessError) as error:
        if isinstance(error, ContractError) and error.code in {"HOSTED_SOURCE_TREE", "HOSTED_PROVENANCE"}:
            raise
        raise ContractError("HOSTED_PROVENANCE", "Current source identity could not be recomputed") from None


_RUN_CONTEXT_PROOF = object()
_RUN_CONTEXT_BINDINGS = WeakKeyDictionary()


@dataclass(frozen=True, eq=False)
class OriginalRunContext:
    repository: str
    source_commit: str
    run_id: int
    workflow_path: str
    generation: str
    qualification_scope: str
    event: str
    ref: str
    attempt: int
    status: str
    _proof: object = field(default=None, repr=False, compare=False)


def _run_context_identity(context):
    return hashlib.sha256(canonical({name: getattr(context, name) for name in
        ("repository", "source_commit", "run_id", "workflow_path", "generation", "qualification_scope", "event", "ref", "attempt", "status")})).hexdigest()


def _mint_original_run_context(document, *, generation):
    """Internal collector handoff after fresh original API run admission."""
    _, _, scope = distribution_paths(generation)
    context = OriginalRunContext(document["repository"]["full_name"], document["head_sha"], document["id"],
        document["path"], generation, scope, document["event"], "refs/heads/" + document["head_branch"],
        document["run_attempt"], document.get("status"), _proof=_RUN_CONTEXT_PROOF)
    _RUN_CONTEXT_BINDINGS[context] = _run_context_identity(context)
    return context


def consumer_provenance(repository, ingestion_hash, original_run, *, source_commit, run_id=None, generation=CURRENT_GENERATION):
    """Use admitted ORIGINAL run identity, never executor env or saved summary flags."""
    workflow, _, scope = distribution_paths(generation)
    context = original_run
    if (generation != CURRENT_GENERATION or type(context) is not OriginalRunContext or context._proof is not _RUN_CONTEXT_PROOF
            or _RUN_CONTEXT_BINDINGS.get(context) != _run_context_identity(context)
            or context.generation != generation or context.qualification_scope != scope
            or context.repository != "Knowledge-Forge-AI/release-starport-9" or context.workflow_path != workflow
            or context.source_commit != source_commit or type(context.run_id) is not int or context.run_id <= 0
            or (run_id is not None and (type(run_id) is not int or context.run_id != run_id))
            or context.event != "push" or context.ref != "refs/heads/main" or type(context.attempt) is not int or context.attempt != 1
            or context.status != "completed"):
        raise ContractError("HOSTED_RUN_CONTEXT", "Fresh admitted original current run context required")
    return {**source_identity(repository, source_commit, generation=generation), "release_ingestion_sha256": ingestion_hash,
            "run_id": context.run_id, "event": context.event, "ref": context.ref, "attempt": context.attempt}


def _provenance(repository, ingestion_hash, *, generation=HISTORICAL_GENERATION, source_commit=None, run_id=None):
    workflow, contract, scope = distribution_paths(generation)
    if generation == CURRENT_GENERATION:
        # Producer provenance must describe this actual RS9 execution.
        commit = os.environ.get("GITHUB_SHA", "")
        identity = os.environ.get("GITHUB_RUN_ID", "")
        if (os.environ.get("GITHUB_REPOSITORY") != "Knowledge-Forge-AI/release-starport-9"
                or not re.fullmatch(r"[0-9a-f]{40}", commit) or not identity.isdigit() or int(identity) <= 0
                or (source_commit is not None and source_commit != commit)
                or (run_id is not None and str(run_id) != identity)):
            raise ContractError("HOSTED_PROVENANCE", "Actual RS9 producer execution identity required")
        return {**source_identity(repository, commit, generation=generation), "release_ingestion_sha256": ingestion_hash,
                "run_id": int(identity), "ref": os.environ.get("GITHUB_REF"), "event": os.environ.get("GITHUB_EVENT_NAME"),
                "attempt": int(os.environ.get("GITHUB_RUN_ATTEMPT", "1"))}
    return {"source_commit": os.environ.get("GITHUB_SHA", "0" * 40),
            "workflow_sha256": hashlib.sha256((repository / workflow).read_bytes()).hexdigest(),
            "contract_sha256": hashlib.sha256((repository / contract).read_bytes()).hexdigest(),
            "release_ingestion_sha256": ingestion_hash, "builder_source_sha256": builder_identity(repository, generation=generation),
            "ref": os.environ.get("GITHUB_REF"), "event": os.environ.get("GITHUB_EVENT_NAME"),
            "attempt": int(os.environ.get("GITHUB_RUN_ATTEMPT", "1"))}


def validate_current_provenance(record):
    """Unauthenticated diagnostic custody never becomes qualification evidence."""
    _, _, scope = distribution_paths(CURRENT_GENERATION)
    if (record.get("generation") != CURRENT_GENERATION or record.get("qualification_scope") != scope
            or record.get("source_identity_error") or record.get("repository") != "Knowledge-Forge-AI/release-starport-9"
            or not isinstance(record.get("source_commit"), str)
            or not re.fullmatch(r"[0-9a-f]{40}", record["source_commit"])
            or type(record.get("run_id")) is not int or record["run_id"] <= 0):
        raise ContractError("HOSTED_PROVENANCE", "Authenticated current source provenance required")
    if not isinstance(record.get("source_tree"), str) or not re.fullmatch(r"[0-9a-f]{40}", record["source_tree"]):
        raise ContractError("HOSTED_SOURCE_TREE", "Authenticated current source tree required")


def provenance(repository, ingestion_hash, *, generation=HISTORICAL_GENERATION, source_commit=None, run_id=None):
    distribution_paths(generation)
    if generation == HISTORICAL_GENERATION:
        return _provenance(repository, ingestion_hash, generation=generation, source_commit=source_commit, run_id=run_id)
    try:
        record = _provenance(repository, ingestion_hash, generation=generation, source_commit=source_commit, run_id=run_id)
        validate_current_provenance(record)
        return record
    except (ContractError, OSError, ValueError, TypeError, subprocess.SubprocessError) as error:
        if isinstance(error, ContractError) and error.code in {"HOSTED_SOURCE_TREE", "HOSTED_PROVENANCE"}:
            raise
        raise ContractError("HOSTED_PROVENANCE", "Current source provenance could not be authenticated") from None


def diagnostic_provenance(repository, ingestion_hash, reason, *, generation):
    """Retain claimed coordinates with an explicitly unauthenticated null tree."""
    if generation != CURRENT_GENERATION:
        raise ContractError("GENERATION_SELECTION", "Current diagnostic provenance required")
    workflow, contract, scope = distribution_paths(generation)
    def bounded_identity(callback):
        try:
            return callback()
        except (ContractError, OSError, ValueError, TypeError):
            return None
    def positive_integer(value):
        text = str(value)
        return int(text) if len(text) <= 20 and text.isdigit() and 0 < int(text) < 10 ** 20 else None
    commit = os.environ.get("GITHUB_SHA", "")
    repository_name = "Knowledge-Forge-AI/release-starport-9"
    return {"source_commit": commit if re.fullmatch(r"[0-9a-f]{40}", commit) else None,
            "source_tree": None,
            "source_identity_error": reason if reason in {"HOSTED_SOURCE_TREE", "HOSTED_PROVENANCE"} else "HOSTED_PROVENANCE",
            "generation": generation, "qualification_scope": scope, "workflow_path": workflow,
            "workflow_sha256": bounded_identity(lambda: file_identity(repository / workflow)["sha256"]),
            "contract_sha256": bounded_identity(lambda: file_identity(repository / contract)["sha256"]),
            "builder_source_sha256": bounded_identity(lambda: builder_identity(repository, generation=generation)),
            "configuration_sha256": bounded_identity(lambda: configuration_identity(repository, generation=generation)),
            "release_ingestion_sha256": ingestion_hash,
            "repository": repository_name if os.environ.get("GITHUB_REPOSITORY", repository_name) == repository_name else None,
            "run_id": positive_integer(os.environ.get("GITHUB_RUN_ID", "")),
            "attempt": positive_integer(os.environ.get("GITHUB_RUN_ATTEMPT", "1")),
            "event": os.environ.get("GITHUB_EVENT_NAME") if os.environ.get("GITHUB_EVENT_NAME") in {"push", "workflow_dispatch", "pull_request"} else None,
            "ref": os.environ.get("GITHUB_REF") if os.environ.get("GITHUB_REF") == "refs/heads/main" else None}


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
        role = None
        if kind == "custody":
            from rs9.package_roles import producer_role, UNCLASSIFIED_PACKAGE
            role = producer_role(record["lane"], relative)
            if role == UNCLASSIFIED_PACKAGE:
                # Preserve the object and all other evidence while refusing its
                # authority. Role verification rejects this explicit unknown role.
                record.setdefault("custody_role_failures", []).append({
                    "path": target.relative_to(output).as_posix(), "code": "CUSTODY_ROLE"})
                if not record.get("execution_error"):
                    record["execution_error"] = "CUSTODY_ROLE"
        fixture_copy = role == "fixture-signed-copy"
        row = {"path": target.relative_to(output).as_posix(), **file_identity(target), "kind": kind,
               "promotion": "fixture-test-only" if fixture_copy else "candidate-policy-pending" if target.suffix == ".whl" and target.stem.rsplit("-", 1)[-1].startswith("linux_") else "candidate-only"}
        if kind == "custody":
            row["role"] = role
        rows.append(row)
    receipt_name = record["lane"] + "-" + record["system"] + ".json"
    raw = canonical(record)
    scan_for_credentials(raw.decode())
    (output / receipt_name).write_bytes(raw)
    manifest = {"schema": SCHEMA, **record["provenance"], "lane": record["lane"], "system": record["system"],
                "production_enabled": False, "publication_authority": False, "runner": record["runner"],
                "files": sorted(rows, key=lambda r: r["path"]),
                "qualification_receipt_hashes": {receipt_name: hashlib.sha256(raw).hexdigest()}}
    if manifest.get("generation") == CURRENT_GENERATION and manifest.get("source_tree") is None:
        manifest["execution_error"] = record.get("execution_error") or "HOSTED_PROVENANCE"
    (output / "artifact-manifest.json").write_bytes(canonical(manifest))
    return manifest


def verify_set(directory, expected_provenance=None):
    path = directory / "artifact-manifest.json"
    manifest = json.loads(path.read_bytes())
    if manifest.get("schema") != SCHEMA or manifest.get("production_enabled") is not False or manifest.get("publication_authority") is not False:
        raise ContractError("CUSTODY_SCHEMA", "Non-production custody manifest required")
    if (manifest.get("generation") == CURRENT_GENERATION or
            (expected_provenance or {}).get("generation") == CURRENT_GENERATION):
        validate_current_provenance(manifest)
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
