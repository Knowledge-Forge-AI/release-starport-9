"""Current-only reuse of the canonical x86_64 Loom/Solar pacman ``any`` packages.

The native AArch64 pacman job never constructs ``any`` packages. It imports the
exact unsigned-custody bytes from the ORIGINAL ``pacman-x86_64-linux`` job of the
same RS9 repository, source commit/tree, workflow, push-to-main run and attempt 1.

Authority chain (each link is checked; no JSON flag confers authority):

1. The importer's own source identity is recomputed from its checkout and the
   executor run identity (``hosted_custody.provenance``), so workflow, contract,
   builder, configuration and release-ingestion hashes are local facts.
2. Provider data from the GitHub Actions API (read through the existing bounded
   ``collect_candidate`` allowlist): the run must be the same original push run,
   attempt 1, still in progress; the constructor job must be completed/success
   with its lane and upload steps executed; the importer job must be the one
   in-progress AArch64 job; exactly one constructor artifact must exist.
3. The original artifact ZIP is streamed against its provider digest and
   extracted with the existing no-follow, bounded ZIP guard.
4. ``verify_set`` binds every member to the custody manifest with the importer's
   own provenance; the receipt, producer roles, build manifests, unsigned
   custody bundle and Merkle commitment must all agree byte-for-byte.

Imported bytes are copied once into the worker's sole output directory and held
open. The returned token is a reuse witness, never a derivation. Construction
authority stays with the x86_64 job; the planner helpers below refuse a second
constructor instead of de-duplicating by filename.
"""
from __future__ import annotations

from datetime import datetime, timedelta
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import threading
from types import MappingProxyType
from typing import Any, Mapping
from weakref import WeakKeyDictionary
import zipfile

from rs9.current_generation import CURRENT_GENERATION, distribution_paths
from rs9.errors import ContractError
from rs9.scratch import canonical, physical_directory
from rs9.security import scan_for_credentials, validate_safe_basename, validate_safe_relative_posix_path

REPOSITORY = "Knowledge-Forge-AI/release-starport-9"
ANY_PRODUCTS = ("theme-forge-solar-sail", "theme-forge-stellar-loom")
CONSTRUCTOR_LANE, CONSTRUCTOR_SYSTEM = "pacman", "x86_64-linux"
CONSTRUCTOR_JOB = CONSTRUCTOR_LANE + "-" + CONSTRUCTOR_SYSTEM
IMPORTER_LANE, IMPORTER_SYSTEM = "pacman", "aarch64-linux"
IMPORTER_JOB = IMPORTER_LANE + "-" + IMPORTER_SYSTEM
IMPORTER_RUNNER = "ubuntu-24.04-arm"
IMPORTER_ARTIFACT = "candidate-" + IMPORTER_JOB
LANE_STEP = "Execute non-production native lane"
UPLOAD_STEP_PREFIX = "Run actions/upload-artifact@"
RECEIPT_SCHEMA = "rs9.hosted-candidate-diagnostic.v1alpha2"
BUILD_SCHEMA = "rs9.pacman-candidate.v1alpha1"
WITNESS_SCHEMA = "rs9.current-pacman-any-reuse-witness.v1alpha1"
SELECTION_SCHEMA = "rs9.current-pacman-any-selection.v1alpha1"
CONSTRUCTION_AUTHORITY = CONSTRUCTOR_LANE + "/" + CONSTRUCTOR_SYSTEM
CUSTODY_PREFIX = "objects/lane-work/unsigned-custody/"
UNSIGNED_PREFIX = "objects/lane-work/unsigned/"
BUILD_PREFIX = "objects/lane-work/build/"
REPLICA_DIRECTORY = "canonical-any/files"
ZSTD_MAGIC = b"\x28\xb5\x2f\xfd"
MAX_PACKAGE_BYTES = 512 * 1024 * 1024
MAX_JSON_BYTES = 4 * 1024 * 1024
MAX_ARTIFACT_BYTES = 2 * 1024 * 1024 * 1024
CLOCK_SKEW = timedelta(seconds=60)
SOURCE_KEYS = frozenset({
    "source_commit", "source_tree", "repository", "workflow_path", "workflow_sha256", "contract_sha256",
    "builder_source_sha256", "configuration_sha256", "generation", "qualification_scope",
    "release_ingestion_sha256", "run_id", "event", "ref", "attempt"})
WITNESS_KEYS = frozenset({
    "schema", "role", "derivation", "construction_authority", "production_enabled", "publication_authority",
    "source", "constructor", "importer", "files"})
CONSTRUCTOR_KEYS = frozenset({
    "lane", "system", "job_name", "job_id", "artifact_name", "artifact_id", "artifact_digest", "artifact_size",
    "artifact_manifest_sha256", "receipt_sha256", "custody_manifest_sha256", "merkle_root"})
IMPORTER_KEYS = frozenset({"lane", "system", "job_name", "job_id"})
FILE_KEYS = frozenset({"name", "sha256", "size", "architecture", "replica_path"})

_SEAL = object()
_REGISTRY: "WeakKeyDictionary[CanonicalAny, str]" = WeakKeyDictionary()
_ACQUIRED: set[int] = set()
_LOCK = threading.Lock()


def _fail(code, message, substage):
    return ContractError(code, message, details={"substage": substage})


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _hex64(value) -> bool:
    return isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value) is not None


def _positive(value) -> bool:
    return type(value) is int and value > 0


def _instant(value):
    if not isinstance(value, str) or not value.endswith("Z"):
        raise _fail("CANONICAL_ANY_JOB", "Provider timestamp required", "provider-time")
    try:
        return datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError:
        raise _fail("CANONICAL_ANY_JOB", "Provider timestamp required", "provider-time") from None


def _read_regular(path: Path, limit: int) -> bytes:
    """No-follow, regular-file, bounded read from an already-admitted tree."""
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_size > limit or info.st_mode & (stat.S_ISUID | stat.S_ISGID):
            raise _fail("CANONICAL_ANY_CUSTODY", "Bounded regular custody file required", "custody-read")
        chunks, total = [], 0
        while True:
            chunk = os.read(fd, 1024 * 1024)
            if not chunk:
                break
            total += len(chunk)
            if total > limit:
                raise _fail("CANONICAL_ANY_CUSTODY", "Bounded regular custody file required", "custody-read")
            chunks.append(chunk)
        return b"".join(chunks)
    finally:
        os.close(fd)


def _json_object(data: bytes, code: str, substage: str) -> dict:
    try:
        text = data.decode("utf-8")
        value = json.loads(text)
    except (ValueError, UnicodeError, RecursionError):
        raise _fail(code, "JSON object required", substage) from None
    scan_for_credentials(text)
    if not isinstance(value, dict):
        raise _fail(code, "JSON object required", substage)
    return value


def _fd_digest(fd: int) -> tuple[str, int]:
    hasher, offset = hashlib.sha256(), 0
    while True:
        chunk = os.pread(fd, 1024 * 1024, offset)
        if not chunk:
            return hasher.hexdigest(), offset
        hasher.update(chunk)
        offset += len(chunk)


# --------------------------------------------------------------------------- provider transport

class ActionsArtifactReader:
    """Closed read-only provider reader over the existing ``collect_candidate`` guards.

    Exactly four request shapes exist: one run document, the attempt-1 job list,
    the run artifact list and one artifact ZIP. ``gh`` argv still passes the
    shared GET-only allowlist. ``runner`` is the existing collector test seam.
    """
    __slots__ = ("_root", "_runner")

    def __init__(self, root, *, runner=None):
        self._root = physical_directory(root)
        self._runner = runner

    def run(self, run_id: int) -> dict:
        from rs9.collect_candidate import gh_read
        raw = gh_read(self._root, ["api", "--method", "GET", f"repos/{REPOSITORY}/actions/runs/{run_id}"], self._runner)
        return _json_object(raw.encode("utf-8") if isinstance(raw, str) else raw, "CANONICAL_ANY_RUN", "provider-run-json")

    def attempt_jobs(self, run_id: int) -> list:
        from rs9.collect_candidate import api_rows
        return api_rows(self._root, f"repos/{REPOSITORY}/actions/runs/{run_id}/attempts/1/jobs", "jobs", self._runner)

    def artifacts(self, run_id: int) -> list:
        from rs9.collect_candidate import api_rows
        return api_rows(self._root, f"repos/{REPOSITORY}/actions/runs/{run_id}/artifacts", "artifacts", self._runner)

    def download(self, artifact_id: int, zip_path: Path, digest: str) -> int:
        from rs9.collect_candidate import gh_stream_artifact
        return gh_stream_artifact(self._root, artifact_id, zip_path, digest, runner=self._runner,
                                  max_artifact_bytes=MAX_ARTIFACT_BYTES, max_total_bytes=MAX_ARTIFACT_BYTES)


# --------------------------------------------------------------------------- source contract

def _constructor_lane(repository: Path) -> dict:
    from rs9.hosted_summary import contract
    rows = [r for r in contract(repository, generation=CURRENT_GENERATION).get("lanes", [])
            if r.get("lane") == CONSTRUCTOR_LANE and r.get("system") == CONSTRUCTOR_SYSTEM]
    if len(rows) != 1:
        raise _fail("CANONICAL_ANY_SOURCE", "Exactly one source-owned canonical constructor lane required", "contract")
    row = rows[0]
    if (row.get("custody_required") is not True or not isinstance(row.get("artifact_name"), str)
            or not isinstance(row.get("runner"), str) or not isinstance(row.get("required_gates"), list)
            or not row["required_gates"] or not set(ANY_PRODUCTS) <= set(row.get("required_products", []))
            or len(set(row["required_products"])) != len(row["required_products"])):
        raise _fail("CANONICAL_ANY_SOURCE", "Canonical constructor lane lacks custody/product contract", "contract")
    from rs9.product_classes import get_product_class, supported_architectures
    for product in ANY_PRODUCTS:
        if (get_product_class(product) != "pure-js-cli"
                or supported_architectures(product, "pacman", generation=CURRENT_GENERATION) != {"any"}):
            raise _fail("CANONICAL_ANY_SOURCE", "Imported products must be current pacman any products", "contract")
    return row


def _intent_versions(captures) -> dict:
    versions = {}
    if not isinstance(captures, (list, tuple)):
        raise _fail("CANONICAL_ANY_CONTEXT", "Authenticated current captures required", "context")
    for item in captures:
        try:
            intent = item[1]
            product, version = intent["project"]["id"], intent["version"]
        except (TypeError, KeyError, IndexError):
            raise _fail("CANONICAL_ANY_CONTEXT", "Authenticated current captures required", "context") from None
        if product in ANY_PRODUCTS:
            if product in versions or not isinstance(version, str) or not re.fullmatch(r"[0-9A-Za-z.+_]{1,64}", version):
                raise _fail("CANONICAL_ANY_CONTEXT", "Exactly one authenticated intent per imported product", "context")
            versions[product] = version
    if set(versions) != set(ANY_PRODUCTS):
        raise _fail("CANONICAL_ANY_CONTEXT", "Authenticated intents for both imported products required", "context")
    return versions


def _importer_context(context) -> tuple[Path, dict, dict, dict]:
    """Recompute this ARM job's own source/run identity; never trust caller-supplied identity."""
    if not isinstance(context, Mapping):
        raise _fail("CANONICAL_ANY_CONTEXT", "Hosted lane context required", "context")
    binding = context.get("binding")
    if (context.get("generation") != CURRENT_GENERATION or context.get("family") != IMPORTER_LANE
            or context.get("system") != IMPORTER_SYSTEM or not isinstance(binding, Mapping)
            or not isinstance(binding.get("source_commit"), str)
            or not re.fullmatch(r"[0-9a-f]{40}", binding["source_commit"])
            or not _hex64(context.get("authentication_sha256"))):
        raise _fail("CANONICAL_ANY_CONTEXT", "Current native AArch64 pacman lane context required", "context")
    if not isinstance(context.get("repository"), (str, Path)):
        raise _fail("CANONICAL_ANY_CONTEXT", "Checked-out repository required", "context")
    repository = physical_directory(context["repository"])
    from rs9.hosted_custody import provenance
    local = provenance(repository, context["authentication_sha256"], generation=CURRENT_GENERATION,
                       source_commit=binding["source_commit"])
    _, _, scope = distribution_paths(CURRENT_GENERATION)
    if (set(local) != SOURCE_KEYS or local["attempt"] != 1 or local["event"] != "push"
            or local["ref"] != "refs/heads/main" or local["repository"] != REPOSITORY
            or local["generation"] != CURRENT_GENERATION or local["qualification_scope"] != scope
            or not _positive(local["run_id"])):
        raise _fail("CANONICAL_ANY_CONTEXT", "Original push-to-main attempt-1 importer execution required", "context")
    return repository, local, _constructor_lane(repository), _intent_versions(context.get("captures"))


# --------------------------------------------------------------------------- provider admission

def _check_run(doc, local, *, status):
    repo, head = doc.get("repository"), doc.get("head_repository")
    checks = (
        (doc.get("id") == local["run_id"] and type(doc.get("id")) is int, "provider-run-id"),
        (type(doc.get("run_attempt")) is int and doc["run_attempt"] == 1, "provider-run-attempt"),
        (doc.get("head_sha") == local["source_commit"], "provider-run-source"),
        (doc.get("event") == "push", "provider-run-event"),
        (doc.get("head_branch") == "main", "provider-run-branch"),
        (doc.get("path") == local["workflow_path"], "provider-run-workflow"),
        (isinstance(repo, dict) and repo.get("full_name") == REPOSITORY
         and _positive(repo.get("id")), "provider-run-repository"),
    )
    for accepted, label in checks:
        if not accepted:
            raise _fail("CANONICAL_ANY_RUN", "Provider run differs from the importer's original push run", label)
    if (not isinstance(head, dict) or head.get("full_name") != REPOSITORY
            or head.get("id") != repo["id"]):
        raise _fail("CANONICAL_ANY_RUN", "Provider run differs from the importer's original push run", "provider-run-head-repository")
    if doc.get("status") != status:
        label = ("provider-run-queued-null" if status == "in_progress"
                 and doc.get("status") == "queued" and "conclusion" in doc
                 and doc["conclusion"] is None else "provider-run-lifecycle")
        raise _fail("CANONICAL_ANY_RUN", "Provider run is not in the required lifecycle state", label)
    return repo["id"]


def _executed_steps(job):
    steps = job.get("steps")
    if not isinstance(steps, list) or any(not isinstance(s, dict) for s in steps):
        raise _fail("CANONICAL_ANY_JOB", "Provider job steps required", "provider-job")
    lane = [s for s in steps if s.get("name") == LANE_STEP]
    upload = [s for s in steps if isinstance(s.get("name"), str) and s["name"].startswith(UPLOAD_STEP_PREFIX)]
    if (len(lane) != 1 or len(upload) != 1
            or any(s.get("status") != "completed" or s.get("conclusion") != "success" for s in lane + upload)
            or type(lane[0].get("number")) is not int or type(upload[0].get("number")) is not int
            or lane[0]["number"] >= upload[0]["number"]):
        raise _fail("CANONICAL_ANY_JOB", "Constructor lane and upload steps must have executed successfully", "provider-job")


def _pacman_jobs(jobs, *, require_attempt=None):
    if not isinstance(jobs, list) or any(not isinstance(j, dict) or not isinstance(j.get("name"), str) for j in jobs):
        raise _fail("CANONICAL_ANY_JOB", "Typed provider job rows required", "provider-job")
    if require_attempt is not None:
        run_id, commit = require_attempt
        if any(j.get("run_id") != run_id or j.get("run_attempt") != 1 or j.get("head_sha") != commit for j in jobs):
            raise _fail("CANONICAL_ANY_JOB", "Provider job differs from the original run attempt", "provider-job")
    pacman = [j for j in jobs if j["name"].startswith("pacman-") or j["name"] == "pacman"]
    constructors = [j for j in pacman if j["name"] == CONSTRUCTOR_JOB]
    importers = [j for j in pacman if j["name"] == IMPORTER_JOB]
    if len(constructors) != 1 or len(importers) != 1 or len(pacman) != 2:
        # A second pacman producer is a second construction authority, not a duplicate to merge.
        raise _fail("CANONICAL_ANY_DUPLICATE", "Exactly one canonical constructor and one importer job required", "provider-job")
    constructor, importer = constructors[0], importers[0]
    if (not _positive(constructor.get("id")) or not _positive(importer.get("id")) or constructor["id"] == importer["id"]
            or constructor.get("status") != "completed" or constructor.get("conclusion") != "success"):
        raise _fail("CANONICAL_ANY_JOB", "Canonical x86_64 constructor job must have concluded success", "provider-job")
    _executed_steps(constructor)
    return constructor, importer


def _check_jobs(jobs, local, lane_row):
    constructor, importer = _pacman_jobs(jobs, require_attempt=(local["run_id"], local["source_commit"]))
    if constructor.get("labels") != [lane_row["runner"]]:
        raise _fail("CANONICAL_ANY_JOB", "Constructor job ran outside the source-required x86_64 runner", "provider-job")
    if (importer.get("status") != "in_progress" or importer.get("conclusion") is not None
            or importer.get("labels") != [IMPORTER_RUNNER]):
        raise _fail("CANONICAL_ANY_JOB", "Exactly one active native AArch64 importer job required", "provider-job")
    if _instant(importer.get("started_at")) < _instant(constructor.get("completed_at")) - CLOCK_SKEW:
        raise _fail("CANONICAL_ANY_JOB", "Importer must be sequenced after the canonical constructor", "provider-job")
    return constructor, importer


def _check_artifact_row(row, artifact_name):
    if (not isinstance(row, dict) or row.get("name") != artifact_name or not _positive(row.get("id"))
            or row.get("expired") is not False
            or not isinstance(row.get("digest"), str) or not re.fullmatch(r"sha256:[0-9a-f]{64}", row["digest"])
            or type(row.get("size_in_bytes")) is not int or not 0 < row["size_in_bytes"] <= MAX_ARTIFACT_BYTES):
        raise _fail("CANONICAL_ANY_ARTIFACT", "Unexpired original artifact identity, size and digest required", "provider-artifact")


def _check_artifacts(artifacts, local, lane_row, repository_id, constructor):
    if not isinstance(artifacts, list) or any(not isinstance(a, dict) for a in artifacts):
        raise _fail("CANONICAL_ANY_ARTIFACT", "Typed provider artifact rows required", "provider-artifact")
    name = lane_row["artifact_name"]
    rows = [a for a in artifacts if a.get("name") == name]
    if len(rows) != 1:
        raise _fail("CANONICAL_ANY_DUPLICATE", "Exactly one canonical constructor artifact required", "provider-artifact")
    if any(a.get("name") == IMPORTER_ARTIFACT for a in artifacts):
        raise _fail("CANONICAL_ANY_DUPLICATE", "Importer artifact cannot predate its own import", "provider-artifact")
    row = rows[0]
    _check_artifact_row(row, name)
    run = row.get("workflow_run")
    if (not isinstance(run, dict) or run.get("id") != local["run_id"] or run.get("head_sha") != local["source_commit"]
            or run.get("head_branch") != "main" or run.get("repository_id") != repository_id
            or run.get("head_repository_id") != repository_id
            or row.get("archive_download_url") != f"https://api.github.com/repos/{REPOSITORY}/actions/artifacts/{row['id']}/zip"):
        raise _fail("CANONICAL_ANY_ARTIFACT", "Artifact provider origin differs from the original run", "provider-artifact")
    created = _instant(row.get("created_at"))
    if not _instant(constructor.get("started_at")) - CLOCK_SKEW <= created <= _instant(constructor.get("completed_at")) + CLOCK_SKEW:
        raise _fail("CANONICAL_ANY_ARTIFACT", "Artifact was not uploaded during the constructor job", "provider-artifact")
    return row


# --------------------------------------------------------------------------- original custody admission

def _admit_constructor_tree(directory: Path, expected: dict, lane_row: dict, versions: dict | None) -> dict:
    """Admit an extracted ORIGINAL x86_64 artifact against exact expected provenance."""
    from rs9.hosted_custody import SCHEMA, verify_set
    from rs9.hosted_summary import gate_blockers
    from rs9.package_roles import BINARY_PACKAGE, validate_role_declarations
    from rs9.pages_candidate import CUSTODY_MANIFEST, load_custody_bundle
    directory = physical_directory(directory)
    manifest = verify_set(directory, expected_provenance=expected)
    raw_manifest = _read_regular(directory / "artifact-manifest.json", MAX_JSON_BYTES)
    if json.loads(raw_manifest) != manifest:
        raise _fail("CANONICAL_ANY_CUSTODY", "Custody manifest changed during admission", "custody-manifest")
    receipt_name = CONSTRUCTOR_LANE + "-" + CONSTRUCTOR_SYSTEM + ".json"
    if (manifest.get("schema") != SCHEMA or manifest.get("lane") != CONSTRUCTOR_LANE
            or manifest.get("system") != CONSTRUCTOR_SYSTEM or "execution_error" in manifest
            or set(manifest.get("qualification_receipt_hashes", {})) != {receipt_name}
            or any(manifest.get(key) != value for key, value in expected.items())):
        raise _fail("CANONICAL_ANY_CUSTODY", "Original x86_64 pacman custody manifest required", "custody-manifest")
    raw_receipt = _read_regular(directory / receipt_name, MAX_JSON_BYTES)
    receipt_sha = _sha(raw_receipt)
    if receipt_sha != manifest["qualification_receipt_hashes"][receipt_name]:
        raise _fail("CANONICAL_ANY_CUSTODY", "Receipt differs from its custody hash", "receipt")
    receipt = _json_object(raw_receipt, "CANONICAL_ANY_CUSTODY", "receipt")
    gates = receipt.get("gates")
    runner = receipt.get("runner")
    network = receipt.get("network")
    if (receipt.get("schema") != RECEIPT_SCHEMA or receipt.get("lane") != CONSTRUCTOR_LANE
            or receipt.get("system") != CONSTRUCTOR_SYSTEM or receipt.get("production_enabled") is not False
            or receipt.get("publication_authority") is not False or receipt.get("execution_error") is not None
            or receipt.get("policy_blockers") != [] or "custody_role_failures" in receipt
            or receipt.get("provenance") != {key: manifest[key] for key in expected}
            or not isinstance(runner, dict) or runner != manifest.get("runner")
            or runner.get("os") != "Linux" or runner.get("architecture") != "x86_64"
            or not isinstance(network, dict) or network.get("runtime_offline_status") != "pass"
            or not isinstance(gates, list) or any(not isinstance(g, dict) for g in gates)):
        raise _fail("CANONICAL_ANY_RECEIPT", "Original constructor receipt differs from executed lane policy", "receipt")
    statuses = {}
    for gate in gates:
        statuses.setdefault(gate.get("name"), []).append(gate.get("status"))
    if (gate_blockers(lane_row, receipt, generation=CURRENT_GENERATION)
            or any(statuses.get(name) != ["pass"] for name in lane_row["required_gates"])):
        raise _fail("CANONICAL_ANY_RECEIPT", "Every source-required constructor gate must have passed", "receipt")

    roles = validate_role_declarations(manifest)
    rows = {row["path"]: row for row in manifest["files"]}
    custody = load_custody_bundle(directory / CUSTODY_PREFIX.rstrip("/"), expected_family=CONSTRUCTOR_LANE,
                                  expected_authentication_sha256=expected["release_ingestion_sha256"])
    doc = custody["manifest"]
    custody_raw = _read_regular(directory / (CUSTODY_PREFIX + CUSTODY_MANIFEST), MAX_JSON_BYTES)
    custody_row = rows.get(CUSTODY_PREFIX + CUSTODY_MANIFEST)
    if (doc.get("system") != CONSTRUCTOR_SYSTEM or doc.get("source_commit") != expected["source_commit"]
            or not isinstance(custody_row, dict) or custody_row.get("kind") != "evidence"
            or custody_row.get("sha256") != _sha(custody_raw) or json.loads(custody_raw) != doc):
        raise _fail("CANONICAL_ANY_CUSTODY", "Unsigned custody bundle differs from original provenance", "custody-bundle")

    files = doc["files"]
    products = list(lane_row["required_products"])
    if len(files) < len(products):
        raise _fail("CANONICAL_ANY_CUSTODY", "Custody lacks a required constructor product", "custody-bundle")
    if len(files) > len(products):
        raise _fail("CANONICAL_ANY_DUPLICATE", "Custody must hold exactly one package per required product", "custody-bundle")
    for name, row in files.items():
        for path in (CUSTODY_PREFIX + "files/" + name, UNSIGNED_PREFIX + name):
            artifact_row = rows.get(path)
            if (not isinstance(artifact_row, dict) or artifact_row.get("kind") != "custody"
                    or roles.get(path) != BINARY_PACKAGE or artifact_row.get("promotion") != "candidate-only"
                    or artifact_row.get("sha256") != row["sha256"] or artifact_row.get("size") != row["size"]):
                raise _fail("CANONICAL_ANY_ROLE", "Custody object must be an unsigned binary-package from its producer",
                            "custody-role")

    admitted, claimed = {}, set()
    for product in products:
        matches = [name for name in files if name.startswith(product + "-")]
        if not matches:
            raise _fail("CANONICAL_ANY_CUSTODY", "Custody lacks a required constructor product", "custody-bundle")
        if len(matches) != 1:
            # Refuse instead of choosing one of several same-product packages.
            raise _fail("CANONICAL_ANY_DUPLICATE", "Exactly one custody package per product required", "custody-bundle")
        build_path = BUILD_PREFIX + product + "/pacman-manifest.json"
        build_row = rows.get(build_path)
        if not isinstance(build_row, dict) or build_row.get("kind") != "evidence":
            raise _fail("CANONICAL_ANY_CUSTODY", "Constructor build manifest required", "build-manifest")
        build_raw = _read_regular(directory / build_path, MAX_JSON_BYTES)
        if _sha(build_raw) != build_row.get("sha256"):
            raise _fail("CANONICAL_ANY_CUSTODY", "Constructor build manifest changed", "build-manifest")
        build = _json_object(build_raw, "CANONICAL_ANY_CUSTODY", "build-manifest")
        name = matches[0]
        package_file = build.get("package_file")
        any_product = product in ANY_PRODUCTS
        architecture = "any" if any_product else "x86_64"
        if (build.get("schema") != BUILD_SCHEMA or build.get("adapter") != "pacman" or build.get("project") != product
                or build.get("can_publish") is not False or build.get("architecture") != architecture
                or not isinstance(package_file, str) or Path(package_file).name != name
                or build.get("package_sha256") != files[name]["sha256"] or build.get("package_size") != files[name]["size"]
                or not isinstance(build.get("version"), str) or not isinstance(build.get("revision"), (str, int))
                or name != f"{product}-{build['version']}-{build['revision']}-{architecture}.pkg.tar.zst"
                or name in claimed):
            raise _fail("CANONICAL_ANY_CUSTODY", "Build manifest does not bind the custody package identity", "build-manifest")
        claimed.add(name)
        if not any_product:
            continue
        if build.get("package_class") != "pure-js-cli" or (versions is not None and build["version"] != versions[product]):
            raise _fail("CANONICAL_ANY_CUSTODY", "Imported package differs from authenticated pure-JS intent", "build-manifest")
        data = _read_regular(custody["packages"][name], MAX_PACKAGE_BYTES)
        if _sha(data) != files[name]["sha256"] or len(data) != files[name]["size"] or not data.startswith(ZSTD_MAGIC):
            raise _fail("CANONICAL_ANY_CUSTODY", "Imported package bytes differ from custody", "custody-bytes")
        admitted[product] = {"name": name, "sha256": files[name]["sha256"], "size": files[name]["size"],
                             "path": custody["packages"][name]}
    if claimed != set(files):
        raise _fail("CANONICAL_ANY_DUPLICATE", "Unbound custody package refused", "custody-bundle")
    # Every retained copy of an imported product (fixture repository copies included)
    # must be the same bytes; a different same-named package is a second construction.
    for row in manifest["files"]:
        base = Path(row["path"]).name
        for product, item in admitted.items():
            if base.startswith(product + "-") and row.get("kind") == "custody" and row.get("sha256") != item["sha256"]:
                raise _fail("CANONICAL_ANY_DUPLICATE", "Divergent same-product package refused", "custody-bundle")
    return {"artifact_manifest_sha256": _sha(raw_manifest), "receipt_sha256": receipt_sha,
            "custody_manifest_sha256": _sha(custody_raw), "merkle_root": doc["merkle"]["root"], "products": admitted}


# --------------------------------------------------------------------------- witness

def _public_strings(value, depth=0):
    if depth > 8:
        raise _fail("CANONICAL_ANY_WITNESS", "Witness nesting exceeds bound", "witness")
    if isinstance(value, str):
        if (not re.fullmatch(r"[A-Za-z0-9._][A-Za-z0-9._:/+-]{0,255}", value) or "//" in value
                or re.search(r"(?:^|/)(?:Users|home|root|private|tmp|var)(?:/|$)", value) or ".." in value.split("/")):
            raise _fail("CANONICAL_ANY_WITNESS", "Witness strings must be closed public identifiers", "witness")
    elif isinstance(value, dict):
        for key, child in value.items():
            _public_strings(key, depth + 1)
            _public_strings(child, depth + 1)
    elif isinstance(value, list):
        for child in value:
            _public_strings(child, depth + 1)
    elif not (value is None or type(value) in (int, bool)):
        raise _fail("CANONICAL_ANY_WITNESS", "Witness values must be closed JSON scalars", "witness")


def _witness_document(source, constructor_job, importer_job, artifact, admitted, lane_row) -> dict:
    files = {}
    for product in ANY_PRODUCTS:
        item = admitted["products"][product]
        validate_safe_basename(item["name"], "package name")
        replica = REPLICA_DIRECTORY + "/" + item["name"]
        validate_safe_relative_posix_path(replica)
        files[product] = {"name": item["name"], "sha256": item["sha256"], "size": item["size"],
                          "architecture": "any", "replica_path": replica}
    document = {
        "schema": WITNESS_SCHEMA, "role": "reuse-witness", "derivation": "none-original-bytes-reused",
        "construction_authority": CONSTRUCTION_AUTHORITY, "production_enabled": False, "publication_authority": False,
        "source": {key: source[key] for key in sorted(SOURCE_KEYS)},
        "constructor": {"lane": CONSTRUCTOR_LANE, "system": CONSTRUCTOR_SYSTEM, "job_name": CONSTRUCTOR_JOB,
                        "job_id": constructor_job["id"], "artifact_name": lane_row["artifact_name"],
                        "artifact_id": artifact["id"], "artifact_digest": artifact["digest"],
                        "artifact_size": artifact["size_in_bytes"],
                        "artifact_manifest_sha256": admitted["artifact_manifest_sha256"],
                        "receipt_sha256": admitted["receipt_sha256"],
                        "custody_manifest_sha256": admitted["custody_manifest_sha256"],
                        "merkle_root": admitted["merkle_root"]},
        "importer": {"lane": IMPORTER_LANE, "system": IMPORTER_SYSTEM, "job_name": IMPORTER_JOB, "job_id": importer_job["id"]},
        "files": files,
    }
    _public_strings(document)
    raw = canonical(document)
    scan_for_credentials(raw.decode("utf-8"))
    return document


def _parse_witness(witness) -> dict:
    if not isinstance(witness, (bytes, bytearray)) or len(witness) > 256 * 1024:
        raise _fail("CANONICAL_ANY_WITNESS", "Serialized bounded reuse witness required", "witness")
    doc = _json_object(bytes(witness), "CANONICAL_ANY_WITNESS", "witness")
    if canonical(doc) != bytes(witness):
        raise _fail("CANONICAL_ANY_WITNESS", "Canonical witness serialization required", "witness")
    _public_strings(doc)
    if (set(doc) != WITNESS_KEYS or doc["schema"] != WITNESS_SCHEMA or doc["role"] != "reuse-witness"
            or doc["derivation"] != "none-original-bytes-reused" or doc["construction_authority"] != CONSTRUCTION_AUTHORITY
            or doc["production_enabled"] is not False or doc["publication_authority"] is not False
            or not isinstance(doc["source"], dict) or set(doc["source"]) != SOURCE_KEYS
            or not isinstance(doc["constructor"], dict) or set(doc["constructor"]) != CONSTRUCTOR_KEYS
            or not isinstance(doc["importer"], dict) or set(doc["importer"]) != IMPORTER_KEYS
            or not isinstance(doc["files"], dict) or set(doc["files"]) != set(ANY_PRODUCTS)
            or any(not isinstance(v, dict) or set(v) != FILE_KEYS for v in doc["files"].values())):
        raise _fail("CANONICAL_ANY_WITNESS", "Closed reuse witness schema required", "witness")
    return doc


# --------------------------------------------------------------------------- held token

class CanonicalAny:
    """Held, sealed reuse token for the two imported canonical ``any`` packages.

    Not a construction record. Only ``acquire_canonical_any`` can mint it. Every
    ``files`` access re-verifies the held inode identity and the exact bytes.
    """
    __slots__ = ("_files", "_held", "_witness", "_closed", "__weakref__")

    def __init__(self, seal, files, held, witness):
        if seal is not _SEAL:
            raise _fail("CANONICAL_ANY_SEAL", "Canonical any tokens are minted only by authenticated import", "token")
        object.__setattr__(self, "_files", dict(files))
        object.__setattr__(self, "_held", dict(held))
        object.__setattr__(self, "_witness", bytes(witness))
        object.__setattr__(self, "_closed", False)
        _REGISTRY[self] = _sha(self._witness)

    def __setattr__(self, name, value):
        raise _fail("CANONICAL_ANY_SEAL", "Canonical any token is immutable", "token")

    def __reduce_ex__(self, protocol):
        raise _fail("CANONICAL_ANY_SEAL", "Canonical any token cannot be serialized or copied", "token")

    def __copy__(self):
        raise _fail("CANONICAL_ANY_SEAL", "Canonical any token cannot be serialized or copied", "token")

    def __deepcopy__(self, memo):
        raise _fail("CANONICAL_ANY_SEAL", "Canonical any token cannot be serialized or copied", "token")

    def _require(self):
        if self._closed or _REGISTRY.get(self) != _sha(self._witness):
            raise _fail("CANONICAL_ANY_SEAL", "Open sealed canonical any token required", "token")

    def verify(self):
        self._require()
        for product, path in self._files.items():
            fd, device, inode, size, digest = self._held[product]
            try:
                current = os.lstat(path)
                held = os.fstat(fd)
            except OSError:
                raise _fail("CANONICAL_ANY_REPLICA", "Imported replica disappeared", "replica") from None
            if (not stat.S_ISREG(current.st_mode) or (current.st_dev, current.st_ino) != (device, inode)
                    or (held.st_dev, held.st_ino) != (device, inode) or held.st_size != size
                    or _fd_digest(fd) != (digest, size)):
                raise _fail("CANONICAL_ANY_REPLICA", "Imported replica bytes or identity changed", "replica")

    @property
    def files(self) -> Mapping[str, Path]:
        self.verify()
        return MappingProxyType(dict(self._files))

    def witness_record(self) -> bytes:
        self._require()
        return self._witness

    def close(self):
        if self._closed:
            return
        object.__setattr__(self, "_closed", True)
        for fd, *_ in self._held.values():
            try:
                os.close(fd)
            except OSError:
                pass

    def __enter__(self):
        self._require()
        return self

    def __exit__(self, *exc):
        self.close()

    def __del__(self):
        try:
            self.close()
        except Exception:
            pass


def _copy_exclusive(source: Path, target: Path, expected: dict):
    data = _read_regular(source, MAX_PACKAGE_BYTES)
    if _sha(data) != expected["sha256"] or len(data) != expected["size"]:
        raise _fail("CANONICAL_ANY_CUSTODY", "Imported package bytes differ from custody", "replica-copy")
    fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o644)
    with os.fdopen(fd, "wb") as stream:
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())
    fd = os.open(target, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or _fd_digest(fd) != (expected["sha256"], expected["size"]):
            raise _fail("CANONICAL_ANY_REPLICA", "Imported replica differs after copy", "replica-copy")
    except BaseException:
        os.close(fd)
        raise
    return fd, info.st_dev, info.st_ino, info.st_size, expected["sha256"]


def acquire_canonical_any(context, client, workspace) -> CanonicalAny:
    """Authenticate and copy the ORIGINAL x86_64 Loom/Solar any packages for this ARM job.

    ``context`` is the current hosted lane context of the native AArch64 pacman job.
    ``client`` must be an ``ActionsArtifactReader``. ``workspace`` must be an empty
    physical directory owned by this worker; only ``canonical-any/files`` remains.
    """
    repository, local, lane_row, versions = _importer_context(context)
    if type(client) is not ActionsArtifactReader or client._root != repository:
        raise _fail("CANONICAL_ANY_CLIENT", "Closed provider reader for this checkout required", "client")
    workspace = physical_directory(workspace)
    if any(workspace.iterdir()):
        raise _fail("CANONICAL_ANY_WORKSPACE", "Empty worker output directory required", "workspace")
    run_id = local["run_id"]
    with _LOCK:
        if run_id in _ACQUIRED:
            raise _fail("CANONICAL_ANY_DUPLICATE", "Canonical any import already performed for this run", "token")
        _ACQUIRED.add(run_id)
    created = [workspace / ".transport", workspace / ".original", workspace / "canonical-any"]
    held = {}
    try:
        try:
            repository_id = _check_run(client.run(run_id), local, status="in_progress")
            constructor, importer = _check_jobs(client.attempt_jobs(run_id), local, lane_row)
            artifact = _check_artifacts(client.artifacts(run_id), local, lane_row, repository_id, constructor)
            created[0].mkdir(mode=0o700)
            zip_path = created[0] / "original.zip"
            if client.download(artifact["id"], zip_path, artifact["digest"]) != artifact["size_in_bytes"]:
                raise _fail("CANONICAL_ANY_ARTIFACT", "Artifact ZIP size differs from provider metadata", "provider-artifact")
            from rs9.collect_candidate import extract_safe_zip
            extract_safe_zip(zip_path, created[1], max_artifact_bytes=MAX_ARTIFACT_BYTES, max_total_bytes=MAX_ARTIFACT_BYTES)
            zip_path.unlink()
            admitted = _admit_constructor_tree(created[1], local, lane_row, versions)
            witness = canonical(_witness_document(local, constructor, importer, artifact, admitted, lane_row))
            output = workspace / REPLICA_DIRECTORY
            output.mkdir(parents=True, mode=0o755)
            physical_directory(output)
            files = {}
            for product in ANY_PRODUCTS:
                item = admitted["products"][product]
                target = output / item["name"]
                held[product] = _copy_exclusive(item["path"], target, item)
                files[product] = target
        except ContractError:
            raise
        except (OSError, ValueError, KeyError, TypeError, zipfile.BadZipFile) as error:
            raise _fail("CANONICAL_ANY_EVIDENCE", "Canonical any evidence could not be admitted", "admission") from error
        # Only the two copies remain: no original tree, ZIP, fixture repository,
        # detached signature, fixture DB/files or public key crosses into the worker output.
        for path in created[:2]:
            if path.exists():
                shutil.rmtree(path)
        if sorted(p.relative_to(workspace).as_posix() for p in workspace.rglob("*")) != sorted(
                ["canonical-any", REPLICA_DIRECTORY, *(REPLICA_DIRECTORY + "/" + p.name for p in files.values())]):
            raise _fail("CANONICAL_ANY_WORKSPACE", "Worker output contains surplus imported state", "workspace")
        return CanonicalAny(_SEAL, files, held, witness)
    except BaseException:
        for fd, *_ in held.values():
            os.close(fd)
        for path in created:
            if path.exists() and not path.is_symlink():
                shutil.rmtree(path, ignore_errors=True)
        with _LOCK:
            _ACQUIRED.discard(run_id)
        raise


# --------------------------------------------------------------------------- parent validation helpers

def _final_rows(packet, original_run, lane_row):
    if (not isinstance(packet, Mapping) or packet.get("run_id") != original_run.run_id
            or packet.get("source_commit") != original_run.source_commit
            or packet.get("generation") != CURRENT_GENERATION):
        raise _fail("CANONICAL_ANY_RUN", "Final collection packet differs from the admitted original run", "final-run")
    constructor, importer = _pacman_jobs(list(packet.get("jobs") or []))
    if importer.get("status") != "completed" or importer.get("conclusion") != "success":
        raise _fail("CANONICAL_ANY_JOB", "Final importer job must have concluded success", "final-job")
    artifacts = packet.get("artifacts")
    if not isinstance(artifacts, list):
        raise _fail("CANONICAL_ANY_ARTIFACT", "Final artifact rows required", "final-artifact")
    rows = [a for a in artifacts if isinstance(a, dict) and a.get("name") == lane_row["artifact_name"]]
    if len(rows) != 1:
        raise _fail("CANONICAL_ANY_DUPLICATE", "Exactly one canonical constructor artifact required", "final-artifact")
    row = rows[0]
    _check_artifact_row(row, lane_row["artifact_name"])
    if row.get("collection") != "verified" or not _hex64(row.get("manifest_sha256")):
        raise _fail("CANONICAL_ANY_ARTIFACT", "Final collector must have verified the constructor artifact", "final-artifact")
    return constructor, importer, row


def validate_reuse_witness(witness, *, repository, original_run, packet, canonical_directory, replica_files=None) -> dict:
    """Validate an ARM reuse witness AGAINST the final completed same-campaign x86_64 artifact.

    The witness never mints authority: the returned selection is derived only from
    the re-admitted original constructor artifact and the sealed completed run
    context, and the witness must equal the record recomputed from them.
    """
    doc = _parse_witness(witness)
    repository = physical_directory(repository)
    from rs9.hosted_custody import consumer_provenance
    expected = consumer_provenance(repository, doc["source"]["release_ingestion_sha256"], original_run,
                                   source_commit=doc["source"]["source_commit"], run_id=doc["source"]["run_id"],
                                   generation=CURRENT_GENERATION)
    lane_row = _constructor_lane(repository)
    try:
        constructor, importer, artifact = _final_rows(packet, original_run, lane_row)
        admitted = _admit_constructor_tree(canonical_directory, expected, lane_row, None)
    except ContractError:
        raise
    except (OSError, ValueError, KeyError, TypeError) as error:
        raise _fail("CANONICAL_ANY_EVIDENCE", "Final canonical evidence could not be admitted", "final-admission") from error
    if artifact["manifest_sha256"] != admitted["artifact_manifest_sha256"]:
        raise _fail("CANONICAL_ANY_ARTIFACT", "Final collector manifest differs from re-admitted custody", "final-artifact")
    recomputed = _witness_document(expected, constructor, importer, artifact, admitted, lane_row)
    if canonical(recomputed) != bytes(witness):
        raise _fail("CANONICAL_ANY_WITNESS", "Reuse witness differs from the original constructor evidence", "witness")
    if replica_files is not None:
        if not isinstance(replica_files, Mapping) or set(replica_files) != set(ANY_PRODUCTS):
            raise _fail("CANONICAL_ANY_REPLICA", "Exactly the two imported replicas required", "replica")
        for product, path in replica_files.items():
            item = admitted["products"][product]
            path = Path(path)
            physical_directory(path.parent)
            try:
                data = _read_regular(path, MAX_PACKAGE_BYTES)
            except OSError:
                raise _fail("CANONICAL_ANY_REPLICA", "Physical replica required", "replica") from None
            if path.name != item["name"] or _sha(data) != item["sha256"] or len(data) != item["size"]:
                raise _fail("CANONICAL_ANY_REPLICA", "Replica bytes differ from the canonical constructor", "replica")
    return {"schema": SELECTION_SCHEMA, "construction_authority": CONSTRUCTION_AUTHORITY,
            "provider": {"lane": CONSTRUCTOR_LANE, "system": CONSTRUCTOR_SYSTEM, "run_id": original_run.run_id,
                         "job_id": constructor["id"], "artifact_id": artifact["id"], "artifact_digest": artifact["digest"]},
            "files": {p: {k: v for k, v in admitted["products"][p].items() if k != "path"} for p in ANY_PRODUCTS},
            "custody_paths": MappingProxyType({p: admitted["products"][p]["path"] for p in ANY_PRODUCTS})}


def select_canonical_any_provider(providers):
    """Planner rule: the x86_64 constructor is the only ``any`` provider.

    ``providers`` rows are ``{"lane", "system", "role", "files": {product: sha256}}``.
    A second ``construction`` row is refused even if its names and bytes match;
    ``reuse-witness`` rows must match the constructor bytes and are never selected.
    """
    if not isinstance(providers, (list, tuple)) or any(not isinstance(p, Mapping) for p in providers):
        raise _fail("CANONICAL_ANY_PROVIDER", "Typed provider declarations required", "planner")
    constructors = [p for p in providers if p.get("role") == "construction"]
    witnesses = [p for p in providers if p.get("role") == "reuse-witness"]
    if len(constructors) + len(witnesses) != len(providers):
        raise _fail("CANONICAL_ANY_PROVIDER", "Unknown any provider role", "planner")
    if len(constructors) != 1:
        raise _fail("CANONICAL_ANY_DUPLICATE", "Exactly one any construction provider required", "planner")
    chosen = constructors[0]
    files = chosen.get("files")
    if ((chosen.get("lane"), chosen.get("system")) != (CONSTRUCTOR_LANE, CONSTRUCTOR_SYSTEM)
            or not isinstance(files, Mapping) or set(files) != set(ANY_PRODUCTS)
            or any(not _hex64(v) for v in files.values())):
        raise _fail("CANONICAL_ANY_PROVIDER", "Canonical x86_64 constructor required", "planner")
    for row in witnesses:
        if ((row.get("lane"), row.get("system")) != (IMPORTER_LANE, IMPORTER_SYSTEM)
                or dict(row.get("files") or {}) != dict(files)):
            raise _fail("CANONICAL_ANY_REPLICA", "Reuse witness differs from the canonical constructor", "planner")
    return {"lane": CONSTRUCTOR_LANE, "system": CONSTRUCTOR_SYSTEM, "files": dict(files)}
