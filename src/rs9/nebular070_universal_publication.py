"""Single-wheel publication verifier for the Nebular 0.7.0 universal launcher.

The qualification checkout (Q) owns every executable and publication byte. The
publisher checkout (P) may differ from Q only by the closed authority file.
Commands here re-admit retained hosted evidence, then stage or read back exactly
one wheel. There is deliberately no upload operation: only the registered,
pinned PyPA action in the ``pypi`` environment writes to the index.
"""
from __future__ import annotations

import argparse
from collections.abc import Callable, Mapping, Sequence
import hashlib
import io
import os
from pathlib import Path
import re
import stat
import sys
import time
import zipfile
import zlib

from rs9 import nebular070_universal_consumer as consumer
from rs9 import tf_pypi_nebular070_publish as legacy
from rs9 import tf_pypi_nebular070_universal as frontend
from rs9 import tf_pypi_remote as remote
from rs9 import wheel_nebular070_universal as builder
from rs9.errors import ContractError
from rs9.materialize import validate_ancestry_not_symlink
from rs9.scratch import canonical
from rs9.tf_pypi_archive import AdmissionError
from rs9.tf_pypi_model import strict_json


AUTHORITY = Path("operators/tf-pypi/nebular-fusion-0.7.0-universal-publication.json")
SCHEMA = "rs9.nebular070-universal-publication.v1"
MARKER_SCHEMA = "rs9.nebular070-universal-upload-attempt.v1"
READBACK_SCHEMA = "rs9.nebular070-universal-readback.v1"
PROJECT = legacy.PROJECT
WORKFLOW = legacy.WORKFLOW
ENVIRONMENT = "pypi"
REPOSITORY = frontend.REPOSITORY
LICENSE_EXPRESSION = "AGPL-3.0-or-later"
REQUIRES_PYTHON = ">=3.10"
PUBLIC_INPUTS = "tfnf-070-universal-public-inputs"
BUNDLE = "tfnf-070-universal-candidate-bundle"
QUALIFICATION = {target: "tfnf-070-universal-qualification-" + target for target in builder.LAYOUTS}
FLOOR = {target: "tfnf-070-universal-qualification-" + target + "-floor"
         for target in frontend.LINUX_TARGETS}
MATRIX = "tfnf-070-universal-matrix-receipt"
MATRIX_MEMBER = "matrix_receipt.json"
DESCRIPTOR_MEMBER = legacy.PUBLIC_INPUTS_DESCRIPTOR
ARTIFACTS = (PUBLIC_INPUTS, BUNDLE, *QUALIFICATION.values(), *FLOOR.values(), MATRIX)
API_FILES = ("run.json", "artifacts.json", "jobs.json")
MAX_AUTHORITY_BYTES = 1024 * 1024
MAX_API_BYTES = 4 * 1024 * 1024
MAX_MARKER_BYTES = 65536
MAX_METADATA_BYTES = 4 * 1024 * 1024
MAX_SMALL_ARCHIVE_BYTES = 16 * 1024 * 1024
MAX_SMALL_MEMBER_BYTES = 4 * 1024 * 1024
MAX_INPUTS_ARCHIVE_BYTES = legacy.PUBLIC_INPUTS_ARTIFACT_MAX_BYTES
MAX_INPUTS_MEMBER_BYTES = legacy.MAX_WHEEL_FILE_BYTES
MAX_INPUTS_FILES = 1024
MAX_JOBS = 100
READBACK_SCHEDULE = (0, 30, 60, 120, 180)
REMOTE_STATES = frozenset({"published-exact", "absent", "version-absent",
                           "incomplete", "conflict", "unknown"})
_HEX40 = re.compile(r"[0-9a-f]{40}")
_HEX64 = re.compile(r"[0-9a-f]{64}")
_RUN_ID = re.compile(r"[1-9][0-9]{0,19}")
_SEGMENT = re.compile(r"[A-Za-z0-9_+@-][A-Za-z0-9._+@-]{0,127}")


def _fail(code):
    raise ContractError("NEBULAR_UNIVERSAL_PUBLICATION_" + code,
                        "Universal publication contract failed")


def _sha(data):
    return hashlib.sha256(data).hexdigest()


def _hex(value, pattern):
    return isinstance(value, str) and bool(pattern.fullmatch(value))


def _int(value, low, high):
    return type(value) is int and low <= value <= high


def _read(path, limit, code):
    """Bounded nofollow regular-file bytes with a stable full stat identity."""
    try:
        return builder._read(Path(path), limit)[0]
    except ContractError:
        _fail(code)


def _real_dir(path, code) -> Path:
    if not isinstance(path, (str, os.PathLike)):
        _fail(code)
    try:
        candidate = validate_ancestry_not_symlink(path)
    except ContractError:
        _fail(code)
    if not candidate.is_dir():
        _fail(code)
    return candidate.resolve()


def _outside(path: Path, roots: Sequence[Path]) -> None:
    for root in roots:
        if path == root or root in path.parents:
            _fail("OUTPUT")


def _new_path(path, *roots: Path) -> Path:
    """A path that does not exist yet, under a real parent, outside both checkouts."""
    if not isinstance(path, (str, os.PathLike)):
        _fail("OUTPUT")
    try:
        candidate = Path(os.path.normpath(validate_ancestry_not_symlink(path)))
    except ContractError:
        _fail("OUTPUT")
    if candidate.exists() or candidate.is_symlink() or not candidate.parent.is_dir():
        _fail("OUTPUT")
    _outside(candidate, roots)
    return candidate


def _write_new(root: Path, relative: str, data: bytes) -> None:
    """Exclusively create one owned file below a fresh owned root."""
    try:
        path = root
        for part in relative.split("/")[:-1]:
            path = path / part
            try:
                os.mkdir(path, 0o700)
            except FileExistsError:
                pass
            if not stat.S_ISDIR(os.lstat(path).st_mode):
                _fail("OUTPUT")
        fd = os.open(path / relative.rsplit("/", 1)[-1],
                     os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
    except OSError:
        _fail("OUTPUT")


def _history():
    from rs9 import nebular070_universal_history
    return nebular070_universal_history


# Authority -----------------------------------------------------------------

def _file_record(value, limit):
    if (not isinstance(value, dict) or set(value) != {"size", "sha256"}
            or not _int(value["size"], 1, limit) or not _hex(value["sha256"], _HEX64)):
        _fail("AUTHORITY")


def _safe_member(value):
    if not isinstance(value, str) or len(value) > 512:
        _fail("AUTHORITY")
    parts = value.split("/")
    # The authenticated product smoke closure includes .tfsb fixture assets.
    # Other hidden components are not part of this release's input contract.
    if len(parts) > 16 or any(part != ".tfsb" and not _SEGMENT.fullmatch(part) for part in parts):
        _fail("AUTHORITY")


def _no_aliases(names):
    """Reject case-fold aliases and paths that are both a file and a directory."""
    folded, parents = set(), set()
    for name in names:
        key = name.casefold()
        if key in folded:
            _fail("AUTHORITY")
        folded.add(key)
        parts = key.split("/")
        parents.update("/".join(parts[:index]) for index in range(1, len(parts)))
    if folded & parents:
        _fail("AUTHORITY")


def _expected_members(name):
    """Exact member set per artifact; None means the bounded public-input tree."""
    if name == BUNDLE:
        return {"bundle.json", "universal-build-receipt.json", "dist/" + builder.FILENAME}
    if name == MATRIX:
        return {MATRIX_MEMBER}
    for target, artifact in QUALIFICATION.items():
        if name == artifact:
            return {target + "/result.json"}
    for target, artifact in FLOOR.items():
        if name == artifact:
            return {target + "/result.json", target + "/missing-runtime.json"}
    return None


def _artifact(name, value):
    if (not isinstance(value, dict)
            or set(value) != {"id", "size_in_bytes", "archive_sha256", "files"}):
        _fail("AUTHORITY")
    public = name == PUBLIC_INPUTS
    archive_limit = MAX_INPUTS_ARCHIVE_BYTES if public else MAX_SMALL_ARCHIVE_BYTES
    member_limit = MAX_INPUTS_MEMBER_BYTES if public else MAX_SMALL_MEMBER_BYTES
    files = value["files"]
    if (not _int(value["id"], 1, 2 ** 63 - 1)
            or not _int(value["size_in_bytes"], 1, archive_limit)
            or not _hex(value["archive_sha256"], _HEX64)
            or not isinstance(files, dict) or not 1 <= len(files) <= MAX_INPUTS_FILES):
        _fail("AUTHORITY")
    for path, record in files.items():
        _safe_member(path)
        _file_record(record, member_limit)
    _no_aliases(files)
    if sum(record["size"] for record in files.values()) > archive_limit:
        _fail("AUTHORITY")
    expected = _expected_members(name)
    if (DESCRIPTOR_MEMBER not in files) if expected is None else (set(files) != expected):
        _fail("AUTHORITY")


def validate_authority(value: Mapping) -> dict:
    """Validate the closed one-wheel publication authority and its identity."""
    keys = {"schema", "project", "version", "distribution", "workflow", "environment",
            "repository", "source", "run", "wheel", "runtime_inputs_sha256",
            "runtime_index_sha256", "description_sha256", "matrix_sha256",
            "api", "artifacts", "identity"}
    fixed = {"schema": SCHEMA, "project": PROJECT, "version": builder.VERSION,
             "distribution": consumer.DISTRIBUTION, "workflow": WORKFLOW,
             "environment": ENVIRONMENT, "repository": REPOSITORY}
    if (not isinstance(value, dict) or set(value) != keys
            or any(value[key] != expected for key, expected in fixed.items())):
        _fail("AUTHORITY")
    source, run, wheel = value["source"], value["run"], value["wheel"]
    if (not isinstance(source, dict) or set(source) != {"commit", "tree"}
            or not all(_hex(item, _HEX40) for item in source.values())
            or not isinstance(run, dict) or set(run) != {"id", "attempt"}
            or not _hex(run["id"], _RUN_ID) or run["attempt"] != "1"
            or not isinstance(wheel, dict)
            or set(wheel) != {"filename", "tag", "version", "size", "sha256"}
            or wheel["filename"] != builder.FILENAME or wheel["tag"] != consumer.TAG
            or wheel["version"] != builder.VERSION
            or not _int(wheel["size"], 1, consumer.MAX_WHEEL_BYTES)
            or not _hex(wheel["sha256"], _HEX64)
            or any(not _hex(value[key], _HEX64) for key in (
                "runtime_inputs_sha256", "runtime_index_sha256", "description_sha256",
                "matrix_sha256", "identity"))):
        _fail("AUTHORITY")
    api, artifacts = value["api"], value["artifacts"]
    if not isinstance(api, dict) or set(api) != set(API_FILES):
        _fail("AUTHORITY")
    for record in api.values():
        _file_record(record, MAX_API_BYTES)
    if not isinstance(artifacts, dict) or set(artifacts) != set(ARTIFACTS):
        _fail("AUTHORITY")
    for name, row in artifacts.items():
        _artifact(name, row)
    if (len({row["id"] for row in artifacts.values()}) != len(ARTIFACTS)
            or artifacts[BUNDLE]["files"]["dist/" + builder.FILENAME]
            != {"size": wheel["size"], "sha256": wheel["sha256"]}
            or artifacts[MATRIX]["files"][MATRIX_MEMBER]["sha256"] != value["matrix_sha256"]):
        _fail("AUTHORITY")
    unsigned = dict(value)
    if unsigned.pop("identity") != _sha(canonical(unsigned)):
        _fail("AUTHORITY_IDENTITY")
    return value


def load_authority(repository: Path) -> dict:
    """Read the publisher authority; a missing file fails closed."""
    path = _real_dir(repository, "AUTHORITY") / AUTHORITY
    return validate_authority(strict_json(_read(path, MAX_AUTHORITY_BYTES, "AUTHORITY")))


# Source lineage ------------------------------------------------------------

def _git(repository: Path, *args: str) -> str:
    """Fixed-argv read-only git query; never a shell, checkout or hook-driven status."""
    return legacy._git_output(
        repository, ["-c", "core.fsmonitor=false", "--no-optional-locks", *args], "SOURCE_LINEAGE")


def verify_source_lineage(publisher, qualification, *, publisher_revision: str | None = None,
                          authority: Mapping | None = None) -> dict:
    """Bind Q to the authority source and require P to add only the authority file."""
    pub = _real_dir(publisher, "SOURCE_LINEAGE")
    qual = _real_dir(qualification, "SOURCE_LINEAGE")
    if pub == qual or pub in qual.parents or qual in pub.parents:
        _fail("SOURCE_LINEAGE")
    authority = load_authority(pub) if authority is None else validate_authority(authority)
    source = authority["source"]
    if publisher_revision is not None and not _hex(publisher_revision, _HEX40):
        _fail("SOURCE_LINEAGE")
    head = _git(pub, "rev-parse", "--verify", "HEAD^{commit}")
    tree = _git(pub, "rev-parse", "--verify", "HEAD^{tree}")
    if (not _hex(head, _HEX40) or not _hex(tree, _HEX40) or head == source["commit"]
            or (publisher_revision is not None and head != publisher_revision)):
        _fail("SOURCE_LINEAGE")
    for repository in (pub, qual):
        if _git(repository, "status", "--porcelain=v1", "--untracked-files=all",
                "--ignore-submodules=none"):
            _fail("SOURCE_DIRTY")
    if (_git(qual, "rev-parse", "--verify", "HEAD^{commit}") != source["commit"]
            or _git(qual, "rev-parse", "--verify", "HEAD^{tree}") != source["tree"]):
        _fail("QUALIFICATION_SOURCE")
    if _git(pub, "rev-parse", "--verify", source["commit"] + "^{tree}") != source["tree"]:
        _fail("SOURCE_LINEAGE")
    # A nonzero exit (not an ancestor) raises inside the fixed git query.
    _git(pub, "merge-base", "--is-ancestor", source["commit"], head)
    changed = _git(pub, "diff", "--no-renames", "--no-ext-diff", "--name-only", "-z",
                   source["commit"], head, "--")
    if {item for item in changed.split("\0") if item} != {AUTHORITY.as_posix()}:
        _fail("FORBIDDEN_TREE_DIFF")
    return {"publisher_commit": head, "publisher_tree": tree,
            "qualification_commit": source["commit"], "qualification_tree": source["tree"],
            "qualification_run_id": authority["run"]["id"]}


# Retained hosted evidence --------------------------------------------------

def _check_run(run, authority):
    source = authority["source"]
    repo, head_repo, head = (run.get(key) if isinstance(run, dict) else None
                             for key in ("repository", "head_repository", "head_commit"))
    if (not isinstance(run, dict) or type(run.get("id")) is not int
            or run["id"] != int(authority["run"]["id"])
            or type(run.get("run_attempt")) is not int or run["run_attempt"] != 1
            or run.get("status") != "completed" or run.get("conclusion") != "success"
            or run.get("event") != "workflow_dispatch" or run.get("head_branch") != "main"
            or run.get("head_sha") != source["commit"]
            or run.get("path") != ".github/workflows/" + WORKFLOW
            or not isinstance(repo, dict) or repo.get("full_name") != REPOSITORY
            or not isinstance(head_repo, dict) or head_repo.get("full_name") != REPOSITORY
            or not isinstance(head, dict) or head.get("id") != source["commit"]
            or head.get("tree_id") != source["tree"]):
        _fail("QUALIFICATION_RUN")


def _check_artifacts(value, authority):
    if (not isinstance(value, dict) or set(value) != {"total_count", "artifacts"}
            or type(value["total_count"]) is not int or not isinstance(value["artifacts"], list)
            or value["total_count"] != len(value["artifacts"])
            or len(value["artifacts"]) != len(ARTIFACTS)):
        _fail("QUALIFICATION_ARTIFACTS")
    rows = {}
    for row in value["artifacts"]:
        name = row.get("name") if isinstance(row, dict) else None
        if not isinstance(name, str) or name in rows or name not in authority["artifacts"]:
            _fail("QUALIFICATION_ARTIFACTS")
        rows[name] = row
    run_id = int(authority["run"]["id"])
    for name, expected in authority["artifacts"].items():
        row = rows[name]
        workflow_run, digest = row.get("workflow_run"), row.get("digest")
        if (type(row.get("id")) is not int or row["id"] != expected["id"]
                or type(row.get("size_in_bytes")) is not int
                or row["size_in_bytes"] != expected["size_in_bytes"]
                or row.get("archive_download_url") != "https://api.github.com/repos/"
                + REPOSITORY + "/actions/artifacts/" + str(expected["id"]) + "/zip"
                or row.get("expired") is not False
                or (digest is not None and digest != "sha256:" + expected["archive_sha256"])
                or not isinstance(workflow_run, dict)
                or type(workflow_run.get("id")) is not int or workflow_run["id"] != run_id
                or workflow_run.get("head_sha") != authority["source"]["commit"]
                or workflow_run.get("head_branch") != "main"):
            _fail("QUALIFICATION_ARTIFACTS")


def _check_jobs(run, value):
    if (not isinstance(value, dict) or set(value) != {"total_count", "jobs"}
            or not _int(value["total_count"], 1, MAX_JOBS) or not isinstance(value["jobs"], list)
            or len(value["jobs"]) != value["total_count"]):
        _fail("QUALIFICATION_JOBS")
    _history().validate_qualification_jobs(run, value["jobs"])


def _exact_dir(path, names, code) -> Path:
    directory = _real_dir(path, code)
    if {item.name for item in directory.iterdir()} != set(names):
        _fail(code)
    return directory


def _extract(raw: bytes, files: Mapping, destination: Path, *, keep: bool) -> dict:
    """Extract authenticated in-memory ZIP bytes; the held file is never reopened."""
    try:
        archive = zipfile.ZipFile(io.BytesIO(raw))
    except (zipfile.BadZipFile, OSError, ValueError, EOFError):
        _fail("ARCHIVE_MEMBERS")
    kept = {}
    with archive:
        infos = archive.infolist()
        names = [info.orig_filename for info in infos]
        if len(names) != len(files) or len(set(names)) != len(names) or set(names) != set(files):
            _fail("ARCHIVE_MEMBERS")
        for info in infos:
            mode = info.external_attr >> 16
            if (info.filename != info.orig_filename or info.is_dir() or info.flag_bits & 0x1
                    or info.compress_type not in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED)
                    or info.file_size != files[info.filename]["size"]
                    or info.compress_size > len(raw)
                    or stat.S_IFMT(mode) not in (0, stat.S_IFREG) or mode & 0o7000):
                _fail("ARCHIVE_MEMBERS")
        try:
            destination.mkdir(mode=0o700, exist_ok=True)
        except OSError:
            _fail("OUTPUT")
        if not stat.S_ISDIR(os.lstat(destination).st_mode):
            _fail("OUTPUT")
        for info in infos:
            expected = files[info.filename]
            try:
                with archive.open(info) as stream:
                    data = stream.read(expected["size"] + 1)
            except (zipfile.BadZipFile, OSError, ValueError, EOFError, RuntimeError, zlib.error):
                _fail("ARCHIVE_MEMBERS")
            if len(data) != expected["size"] or _sha(data) != expected["sha256"]:
                _fail("ARCHIVE_MEMBERS")
            _write_new(destination, info.filename, data)
            if keep:
                kept[info.filename] = data
    return kept


def verify_capture(authority: Mapping, api_dir, archives_dir, output, *, repository) -> dict:
    """Re-admit the complete retained run and recompute its matrix from raw bytes.

    ``repository`` is the qualification checkout. No native product runs: the
    matrix reader re-authenticates native inputs and the five consumer and two
    missing-runtime receipts from the extracted artifacts.
    """
    authority = validate_authority(authority)
    repository = _real_dir(repository, "QUALIFICATION_SOURCE")
    source, run_id = dict(authority["source"]), authority["run"]["id"]
    api = _exact_dir(api_dir, API_FILES, "QUALIFICATION_API")
    documents = {}
    for name in API_FILES:
        record = authority["api"][name]
        data = _read(api / name, record["size"], "QUALIFICATION_API")
        if len(data) != record["size"] or _sha(data) != record["sha256"]:
            _fail("QUALIFICATION_API")
        documents[name] = strict_json(data)
    _check_run(documents["run.json"], authority)
    _check_artifacts(documents["artifacts.json"], authority)
    _check_jobs(documents["run.json"], documents["jobs.json"])

    archives = _exact_dir(archives_dir, [name + ".zip" for name in ARTIFACTS], "QUALIFICATION_ARCHIVE")
    output = _new_path(output, repository)
    try:
        output.mkdir(mode=0o700)
    except OSError:
        _fail("OUTPUT")
    roots = {PUBLIC_INPUTS: output / "public-inputs", BUNDLE: output / "bundle",
             MATRIX: output / "matrix",
             **{name: output / "receipts" for name in QUALIFICATION.values()},
             **{name: output / "floors" for name in FLOOR.values()}}
    held = {}
    for name in ARTIFACTS:
        row = authority["artifacts"][name]
        raw = _read(archives / (name + ".zip"), row["size_in_bytes"], "QUALIFICATION_ARCHIVE")
        if len(raw) != row["size_in_bytes"] or _sha(raw) != row["archive_sha256"]:
            _fail("QUALIFICATION_ARCHIVE")
        held[name] = _extract(raw, row["files"], roots[name], keep=name in (BUNDLE, MATRIX))
        del raw

    bundle, snapshot = frontend.load_bundle(roots[BUNDLE], repository=repository, expected_source=source)
    description = _read(repository / frontend.DESCRIPTION, 262144, "DESCRIPTION")
    wheel = held[BUNDLE]["dist/" + builder.FILENAME]
    if (snapshot["wheel"] != authority["wheel"] or bundle["wheel"] != authority["wheel"]
            or len(wheel) != authority["wheel"]["size"] or _sha(wheel) != authority["wheel"]["sha256"]
            or snapshot["runtime_inputs_sha256"] != authority["runtime_inputs_sha256"]
            or snapshot["runtime_index_sha256"] != authority["runtime_index_sha256"]
            or bundle["description_sha256"] != authority["description_sha256"]
            or _sha(description) != authority["description_sha256"]):
        _fail("BUNDLE")

    inputs = roots[PUBLIC_INPUTS]
    matrix = frontend.read_matrix_inputs(
        roots[BUNDLE], inputs / DESCRIPTOR_MEMBER, inputs, output / "receipts",
        output / "floors", output / "matrix-work", repository=repository,
        source=source, run_id=run_id, run_attempt="1")
    raw_matrix = held[MATRIX][MATRIX_MEMBER]
    if (not isinstance(matrix, dict) or canonical(matrix) != raw_matrix
            or _sha(raw_matrix) != authority["matrix_sha256"]
            or matrix.get("schema") != frontend.MATRIX_SCHEMA
            or matrix.get("distribution") != consumer.DISTRIBUTION
            or matrix.get("version") != builder.VERSION or matrix.get("status") != "passed"
            or matrix.get("source") != source or matrix.get("run") != {"id": run_id, "attempt": "1"}
            or matrix.get("wheel") != authority["wheel"]
            or not isinstance(matrix.get("lanes"), list) or len(matrix["lanes"]) != 5
            or matrix.get("native_qualified") is not True or matrix.get("fixture_only") is not False
            or matrix.get("publication_admitted") is not False):
        _fail("MATRIX")
    return {"authority": authority, "wheel": wheel, "description": description,
            "snapshot": snapshot, "matrix_identity": matrix.get("identity")}


# Index observation ---------------------------------------------------------

def _default_fetch(url: str, limit: int) -> bytes:
    body = remote.PublicReader().get(url)
    if len(body) > limit:
        _fail("REMOTE_LIMIT")
    return body


def _check_metadata(fetch, description: bytes) -> None:
    url = "https://pypi.org/pypi/" + PROJECT + "/" + builder.VERSION + "/json"
    try:
        value = strict_json(fetch(url, MAX_METADATA_BYTES))
        text = description.decode("utf-8")
    except (AdmissionError, UnicodeError):
        _fail("REMOTE_METADATA")
    info = value.get("info") if isinstance(value, dict) else None
    if (not isinstance(info, dict) or info.get("name") != PROJECT
            or info.get("version") != builder.VERSION
            or info.get("license_expression") != LICENSE_EXPRESSION
            or info.get("requires_python") != REQUIRES_PYTHON
            or info.get("description") != text
            or info.get("description_content_type") != "text/markdown"
            or info.get("yanked") is not False):
        _fail("REMOTE_METADATA")


def index_state(authority: Mapping, wheel: bytes, description: bytes,
                fetch: Callable[[str, int], bytes] | None = None) -> str:
    """Observe the single approved file; published-exact also proves bytes and metadata."""
    fetch = fetch or _default_fetch
    pair = (authority["wheel"]["size"], authority["wheel"]["sha256"])
    result = remote.approved_state(PROJECT, builder.VERSION, {builder.FILENAME: pair}, fetch)
    if not isinstance(result, Mapping):
        return "unknown"
    observed_state = result.get("state")
    state = observed_state if isinstance(observed_state, str) and observed_state in REMOTE_STATES else "unknown"
    if state == "published-exact":
        bodies = result.get("bodies")
        if not isinstance(bodies, Mapping) or bodies.get(builder.FILENAME) != wheel:
            _fail("REMOTE_CONFLICT")
        _check_metadata(fetch, description)
    return state


def _state_code(prefix, state):
    return prefix + state.upper().replace("-", "_")


# Operations ----------------------------------------------------------------

def _hosted(environ: Mapping, publisher_commit: str, authority: Mapping) -> str:
    run_id = environ.get("GITHUB_RUN_ID", "")
    if (environ.get("GITHUB_ACTIONS") != "true"
            or environ.get("GITHUB_REPOSITORY") != REPOSITORY
            or environ.get("GITHUB_REF") != "refs/heads/main"
            or environ.get("GITHUB_EVENT_NAME") != "workflow_dispatch"
            or environ.get("GITHUB_WORKFLOW_REF")
            != REPOSITORY + "/.github/workflows/" + WORKFLOW + "@refs/heads/main"
            or environ.get("GITHUB_RUN_ATTEMPT") != "1"
            or environ.get("GITHUB_SHA") != publisher_commit
            or not _hex(run_id, _RUN_ID) or run_id == authority["run"]["id"]):
        _fail("HOSTED_CONTEXT")
    return run_id


def _admit(operation, publisher_dir, qualification_dir, api_dir, archives_dir, work, *,
           publisher_revision, environ, hosted) -> dict:
    """Recheck lineage, hosted coordinates and complete custody in fresh W/<operation>."""
    if hosted and environ.get("RS9_TFNF_PRIOR_UPLOAD_UNCONFIRMED", "").strip():
        _fail("PRIOR_UPLOAD_UNCONFIRMED")
    if hosted and publisher_revision is None:
        _fail("HOSTED_CONTEXT")
    publisher = _real_dir(publisher_dir, "SOURCE_LINEAGE")
    qualification = _real_dir(qualification_dir, "SOURCE_LINEAGE")
    authority = load_authority(publisher)
    lineage = verify_source_lineage(publisher, qualification, publisher_revision=publisher_revision,
                                    authority=authority)
    run_id = _hosted(environ, lineage["publisher_commit"], authority) if hosted else None
    roots = (publisher, qualification)
    if not isinstance(work, (str, os.PathLike)):
        _fail("OUTPUT")
    try:
        work = Path(os.path.normpath(validate_ancestry_not_symlink(work)))
        _outside(work, roots)
        work.mkdir(mode=0o700, exist_ok=True)
    except (ContractError, OSError):
        _fail("OUTPUT")
    context = verify_capture(authority, api_dir, archives_dir, work / operation,
                             repository=qualification)
    return {**context, "lineage": lineage, "run_id": run_id, "roots": roots}


def _marker(context) -> bytes:
    authority, wheel = context["authority"], context["authority"]["wheel"]
    return canonical({
        "schema": MARKER_SCHEMA, "project": PROJECT, "version": builder.VERSION,
        "distribution": consumer.DISTRIBUTION, "authority_identity": authority["identity"],
        "qualification_run_id": authority["run"]["id"],
        "publisher_commit": context["lineage"]["publisher_commit"],
        "publisher_run_id": context["run_id"],
        "filename": wheel["filename"], "size": wheel["size"], "sha256": wheel["sha256"],
    })


def _check_upload(upload_dir, context) -> None:
    directory = _exact_dir(upload_dir, {builder.FILENAME}, "UPLOAD_DIR")
    _outside(directory, context["roots"])
    data = _read(directory / builder.FILENAME, consumer.MAX_WHEEL_BYTES, "UPLOAD_DIR")
    expected = context["authority"]["wheel"]
    if (data != context["wheel"] or len(data) != expected["size"]
            or _sha(data) != expected["sha256"]):
        _fail("UPLOAD_BYTES")


def _prior_runs(api_get, environ) -> None:
    """The established full-history guard, extended for prior universal runs."""
    legacy.check_prior_publish_runs(
        api_get=api_get, environ=environ,
        additional_run_validator=_history().check_prior_universal_run)


def select_missing(publisher_dir, qualification_dir, api_dir, archives_dir, work, upload_dir,
                   attempt_marker, *, publisher_revision, fetch=None, api_get=None,
                   environ: Mapping | None = None) -> dict:
    """Stage the one admitted wheel only when 0.7.0 is absent and history is clean."""
    environ = os.environ if environ is None else environ
    context = _admit("select-missing", publisher_dir, qualification_dir, api_dir, archives_dir,
                     work, publisher_revision=publisher_revision, environ=environ, hosted=True)
    upload = _new_path(upload_dir, *context["roots"])
    marker = _new_path(attempt_marker, *context["roots"])
    state = index_state(context["authority"], context["wheel"], context["description"], fetch)
    if state == "published-exact":
        return {"upload": False, "state": state}
    if state not in ("absent", "version-absent"):
        _fail(_state_code("REMOTE_", state))
    _prior_runs(api_get, environ)
    try:
        fd = os.open(marker, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, "wb") as stream:
            stream.write(_marker(context))
            stream.flush()
            os.fsync(stream.fileno())
        upload.mkdir(mode=0o700)
    except OSError:
        _fail("ATTEMPT_MARKER")
    _write_new(upload, builder.FILENAME, context["wheel"])
    _check_upload(upload, context)
    return {"upload": True, "state": state}


def verify_upload(publisher_dir, qualification_dir, api_dir, archives_dir, work, upload_dir,
                  attempt_marker, *, publisher_revision, fetch=None, api_get=None,
                  environ: Mapping | None = None) -> dict:
    """Immediately before the pinned action: same custody, bytes, marker, absence and history."""
    environ = os.environ if environ is None else environ
    context = _admit("verify-upload", publisher_dir, qualification_dir, api_dir, archives_dir,
                     work, publisher_revision=publisher_revision, environ=environ, hosted=True)
    _check_upload(upload_dir, context)
    if not isinstance(attempt_marker, (str, os.PathLike)):
        _fail("ATTEMPT_MARKER")
    marker = Path(os.path.normpath(validate_ancestry_not_symlink(attempt_marker)))
    _outside(marker, context["roots"])
    if _read(marker, MAX_MARKER_BYTES, "ATTEMPT_MARKER") != _marker(context):
        _fail("ATTEMPT_MARKER")
    state = index_state(context["authority"], context["wheel"], context["description"], fetch)
    if state not in ("absent", "version-absent"):
        _fail(_state_code("REMOTE_", state))
    _prior_runs(api_get, environ)
    return {"verified": True, "state": state}


def readback(publisher_dir, qualification_dir, api_dir, archives_dir, work, *,
             publisher_revision: str | None = None, upload_dir=None, fetch=None,
             schedule: Sequence[int | float] = READBACK_SCHEDULE,
             sleep: Callable[[float], None] = time.sleep) -> dict:
    """Bounded read-only confirmation of exactly the authorized file and metadata."""
    if (not isinstance(schedule, (tuple, list)) or not 1 <= len(schedule) <= 6
            or any(type(delay) not in (int, float) or delay < 0 for delay in schedule)
            or sum(schedule) > 600):
        _fail("READBACK_SCHEDULE")
    context = _admit("readback", publisher_dir, qualification_dir, api_dir, archives_dir, work,
                     publisher_revision=publisher_revision, environ=os.environ, hosted=False)
    if upload_dir is not None:
        _check_upload(upload_dir, context)
    state = "unknown"
    for attempt, delay in enumerate(schedule, start=1):
        if attempt > 1 and delay:
            sleep(float(delay))
        state = index_state(context["authority"], context["wheel"], context["description"], fetch)
        if state == "published-exact":
            authority = context["authority"]
            return {"schema": READBACK_SCHEMA, "project": PROJECT, "version": builder.VERSION,
                    "distribution": consumer.DISTRIBUTION, "state": state, "attempts": attempt,
                    "wheel": dict(authority["wheel"]), "authority_identity": authority["identity"],
                    "qualification_run_id": authority["run"]["id"], "public_writes": 0}
        if state == "conflict":
            break
    _fail(_state_code("READBACK_", state))


def resolve(publisher_dir) -> dict:
    """Checkout coordinates for Q; these grant no upload authority by themselves."""
    authority = load_authority(_real_dir(publisher_dir, "AUTHORITY"))
    return {"qualification_commit": authority["source"]["commit"],
            "qualification_run_id": authority["run"]["id"]}


# CLI -----------------------------------------------------------------------

def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    commands = result.add_subparsers(dest="operation", required=True)
    commands.add_parser("resolve").add_argument("--publisher-dir", type=Path, required=True)
    for name in ("select-missing", "verify-upload", "readback"):
        command = commands.add_parser(name)
        for field in ("publisher-dir", "qualification-dir", "api-dir", "archives-dir", "work"):
            command.add_argument("--" + field, type=Path, required=True)
        command.add_argument("--upload-dir", type=Path, required=name != "readback")
        command.add_argument("--publisher-revision", required=name != "readback")
        if name != "readback":
            command.add_argument("--attempt-marker", type=Path, required=True)
    return result


def _lines(value: Mapping) -> str:
    return "".join(key + "=" + (str(item).lower() if type(item) is bool else str(item)) + "\n"
                   for key, item in value.items())


def main(argv=None) -> int:
    args = parser().parse_args(argv)
    try:
        if args.operation == "resolve":
            output = _lines(resolve(args.publisher_dir))
        else:
            paths = (args.publisher_dir, args.qualification_dir, args.api_dir,
                     args.archives_dir, args.work)
            if args.operation == "readback":
                output = canonical(readback(*paths, publisher_revision=args.publisher_revision,
                                            upload_dir=args.upload_dir)).decode()
            else:
                operation = select_missing if args.operation == "select-missing" else verify_upload
                output = _lines(operation(*paths, args.upload_dir, args.attempt_marker,
                                          publisher_revision=args.publisher_revision))
        sys.stdout.write(output)
        return 0
    except (ContractError, AdmissionError) as error:
        sys.stderr.write(str(getattr(error, "code", "NEBULAR_UNIVERSAL_PUBLICATION_CONTRACT")) + "\n")
        return 1
    except Exception:
        sys.stderr.write("NEBULAR_UNIVERSAL_PUBLICATION_CONTRACT\n")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
