"""Observer-only PyPI application-to-distribution projection.

The reviewed record names exactly four admitted, published distributions; it is
never followed to a later version.  A PypiProjection is a module-private,
nonserializable capability bound to one fresh authenticated capture, its
evaluated profile, the committed approvals, intake pins and both bootstrap
manifests.  Holding one grants nothing outside rs9.readers.read_pypi_distribution:
no upload, ownership, publication or lineage authority.  Every trust failure is a
ContractError with a closed PYPI_PROJECTION_* code and is never a remote state.
"""

import io
import json
import re
import stat
import zipfile
import zlib
from collections import namedtuple
from email.parser import Parser
from pathlib import PurePosixPath

from rs9 import nebular_lineage
from rs9.errors import ContractError
from rs9.records import record_sha256
from rs9.release_core import (
    ReleaseCapture,
    authenticated_record_hash,
    authenticated_release_metadata,
    authenticated_tree,
    digest,
    read_evidence,
)
from rs9.scratch import canonical, physical_directory
from rs9.security import validate_safe_relative_posix_path
from rs9.tf_pypi_archive import AdmissionError, read_tar
from rs9.tf_pypi_archive import canonical as compact_canonical
from rs9.tf_pypi_model import (
    DISTRIBUTIONS,
    PRODUCTS,
    TARGETS,
    build_pin,
    strict_json,
    validate_pin,
)
from rs9.tf_pypi_platform import EXPECTED_TAGS

PROJECTION_RECORD_PATH = "config/forward/pypi-observe/v1alpha1/projection.json"
PROJECTION_RECORD_SHA256 = "ee166d0e73d079f3f2c127d24128a5f282bace6d57ab1e2d7149f9acf6bf1bab"
HISTORICAL_MANIFEST_PATH = "bootstrap/pre-rs9/theme-forge-live1/manifest.json"
CURRENT_MANIFEST_PATH = "bootstrap/pre-rs9/theme-forge-live1/manifest-author-aligned.json"
NEBULAR_PROJECT = "theme-forge-nebular-fusion"
# The published, immutable Nebular distribution; the unpublished successor is never selected.
NEBULAR_DISTRIBUTION_VERSION = "0.6.1"
STELLAR_FIXTURE_REPOSITORY = "Knowledge-Forge-AI/theme-forge-stellar-burst"

RECORD = "PYPI_PROJECTION_RECORD"
SCOPE = "PYPI_PROJECTION_SCOPE"
CAPTURE = "PYPI_PROJECTION_CAPTURE"
LINEAGE = "PYPI_PROJECTION_LINEAGE"
APPROVAL = "PYPI_PROJECTION_APPROVAL"
PROVENANCE = "PYPI_PROJECTION_PROVENANCE"

_SCHEMA = "rs9.pypi-observe-projection.v1alpha1"
_REASON = ("observer-only application-to-distribution projection; "
           "grants no upload, ownership or lineage authority outside this lane")
_IDENTITY_SCHEMA = "rs9.pypi-distribution-identity.v1alpha1"
_FACTS_SCHEMA = "rs9.pypi-projection-facts.v1alpha1"
_AGGREGATE_SCHEMA = "rs9.tf-pypi-candidate-aggregate.v1"
_PROFILE_SCHEMA = "rs9.evidence-profile-result.v1alpha1"
_NEBULAR_PROVENANCE_SCHEMA = "rs9.wheel-provenance.v1alpha1"
_KIND_BASIS = {"tf-npm-aggregate": "observer-equal-tree", "nebular-native-wheel": "nebular-forward-lineage"}
_PROJECTS = tuple(sorted({*PRODUCTS, NEBULAR_PROJECT}))
_RECORD_LIMIT = 64 * 1024
_APPROVAL_LIMIT = 1024 * 1024
_PIN_LIMIT = 64 * 1024
_MANIFEST_LIMIT = 1024 * 1024
# First-wave wheel bounds are the established tf_pypi_verify.read_wheel contract.
_WHEEL_MEMBERS = 20000
_WHEEL_MEMBER_BYTES = 8 * 1024 ** 2
_WHEEL_TOTAL_BYTES = 64 * 1024 ** 2

_SHA1 = re.compile(r"[0-9a-f]{40}\Z")
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_VERSION = re.compile(r"[0-9]+(?:\.[0-9]+)*(?:\.post[0-9]+)?\Z")
_ASSET_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._+-]{0,255}\Z")
_PROJECTION_TOKEN = object()

_ObserverInputs = namedtuple("_ObserverInputs", ("project", "version", "approved", "expected", "identity"))


def _fail(code, message):
    raise ContractError(code, message)


def _reraise(code, message, error):
    raise ContractError(code, message, details={"underlying_code": error.code}) from None


def _closed(value, fields, code=RECORD):
    if not isinstance(value, dict) or set(value) != set(fields):
        _fail(code, "PyPI projection input has an unexpected field set")
    return value


def _sha(value, length=64, code=RECORD):
    if not isinstance(value, str) or not (_SHA256 if length == 64 else _SHA1).fullmatch(value):
        _fail(code, "PyPI projection input contains an invalid digest")
    return value


def _positive_int(value, code=RECORD):
    if type(value) is not int or value <= 0:
        _fail(code, "PyPI projection input contains an invalid positive integer")
    return value


def _read(root, relative, limit, code):
    try:
        return read_evidence(root, relative, limit=limit)
    except ContractError as error:
        _reraise(code, "Required committed or captured evidence is unavailable", error)


def _json(raw, code):
    try:
        return strict_json(raw)
    except AdmissionError as error:
        _reraise(code, "Committed or embedded JSON is malformed", error)


# Record ---------------------------------------------------------------------------------------

def _safe_path(value, prefix=None):
    if not isinstance(value, str) or (prefix is not None and not value.startswith(prefix)):
        _fail(RECORD, "PyPI projection path is outside its authority")
    try:
        validate_safe_relative_posix_path(value)
    except ContractError as error:
        _reraise(RECORD, "PyPI projection path must be safe and relative", error)
    return value


def _validate_row(row):
    _closed(row, {"application", "binding_asset", "distribution", "intake", "lineage", "project"})
    project = row["project"]
    if project not in _PROJECTS:
        _fail(RECORD, "PyPI projection row names an unknown project")
    application = _closed(row["application"], {"release_id", "repository", "repository_id", "tag", "version"})
    if (application["repository"] != "Knowledge-Forge-AI/" + project
            or not isinstance(application["version"], str) or not _VERSION.fullmatch(application["version"])
            or application["tag"] != "v" + application["version"]):
        _fail(RECORD, "PyPI projection application identity is malformed")
    _positive_int(application["repository_id"])
    _positive_int(application["release_id"])
    distribution = _closed(row["distribution"], {"approval_path", "approval_sha256", "kind", "name",
                                                 "set_sha256", "version"})
    if (distribution["name"] != project or distribution["kind"] not in _KIND_BASIS
            or not isinstance(distribution["version"], str) or not _VERSION.fullmatch(distribution["version"])):
        _fail(RECORD, "PyPI projection distribution identity is malformed")
    _safe_path(distribution["approval_path"], "operators/tf-pypi/")
    if not distribution["approval_path"].endswith(".json"):
        _fail(RECORD, "PyPI projection approval path is outside its authority")
    _sha(distribution["approval_sha256"])
    _sha(distribution["set_sha256"])
    lineage = _closed(row["lineage"], {"basis", "current", "historical", "tree_relation_basis"})
    if (lineage["basis"] != _KIND_BASIS[distribution["kind"]]
            or lineage["tree_relation_basis"] != "reviewed-record"):
        _fail(RECORD, "PyPI projection lineage basis disagrees with its kind")
    for side in ("current", "historical"):
        _closed(lineage[side], {"commit", "tree"})
        _sha(lineage[side]["commit"], 40)
        _sha(lineage[side]["tree"], 40)
    binding = _closed(row["binding_asset"], {"github_asset_id", "name", "sha256", "size"})
    _positive_int(binding["github_asset_id"])
    _positive_int(binding["size"])
    _sha(binding["sha256"])
    if not isinstance(binding["name"], str) or not _ASSET_NAME.fullmatch(binding["name"]):
        _fail(RECORD, "PyPI projection binding asset name is malformed")
    intake = row["intake"]
    if distribution["kind"] == "nebular-native-wheel":
        if intake is not None:
            _fail(RECORD, "Nebular projection rows carry no intake pin")
    else:
        _closed(intake, {"pin_path", "pin_sha256"})
        if intake["pin_path"] != "operators/tf-pypi/" + project + ".json":
            _fail(RECORD, "PyPI projection intake pin path is outside its authority")
        _safe_path(intake["pin_path"])
        _sha(intake["pin_sha256"])


def _validate_record(record):
    _closed(record, {"current_manifest", "historical_manifest", "reason", "rows", "schema"})
    if record["schema"] != _SCHEMA or record["reason"] != _REASON:
        _fail(RECORD, "Unknown or unauthorized PyPI projection record")
    for key, path in (("historical_manifest", HISTORICAL_MANIFEST_PATH), ("current_manifest", CURRENT_MANIFEST_PATH)):
        _closed(record[key], {"path", "sha256"})
        if record[key]["path"] != path:
            _fail(RECORD, "PyPI projection manifest path is not the reviewed bootstrap manifest")
        _sha(record[key]["sha256"])
    rows = record["rows"]
    if not isinstance(rows, list) or len(rows) != len(_PROJECTS):
        _fail(RECORD, "Exactly four PyPI projection rows are required")
    for row in rows:
        _validate_row(row)
    if tuple(row["project"] for row in rows) != _PROJECTS:
        _fail(RECORD, "PyPI projection rows must be unique and sorted by project")
    return record


def load_projection_record(repository):
    """Load only the exact reviewed canonical record bytes; no trust beyond the record itself."""
    try:
        root = physical_directory(repository)
    except ContractError as error:
        _reraise(RECORD, "A physical repository root is required", error)
    raw = _read(root, PROJECTION_RECORD_PATH, _RECORD_LIMIT, RECORD)
    record = _json(raw, RECORD)
    if raw != canonical(record) or digest(raw) != PROJECTION_RECORD_SHA256:
        _fail(RECORD, "Only the exact reviewed canonical PyPI projection bytes are accepted")
    return root, raw, _validate_record(record)


# Scope ----------------------------------------------------------------------------------------

def _check_row_scope(row):
    project, application, distribution = row["project"], row["application"], row["distribution"]
    if project == NEBULAR_PROJECT:
        if ((distribution["name"], distribution["version"], distribution["kind"])
                != (NEBULAR_PROJECT, NEBULAR_DISTRIBUTION_VERSION, "nebular-native-wheel")
                or application["version"] != nebular_lineage.CURRENT_VERSION):
            _fail(SCOPE, "Nebular projects only the published 0.6.1 native wheel")
    elif (distribution["kind"] != "tf-npm-aggregate" or distribution["version"] != DISTRIBUTIONS[project]
          or application["version"] != PRODUCTS[project][0]):
        _fail(SCOPE, "First-wave projection kind or version disagrees with the admitted product")
    return row


def _select_row(record, intent):
    project = intent.get("project") if isinstance(intent, dict) else None
    if not isinstance(project, dict):
        _fail(SCOPE, "An intent project is required")
    matches = [row for row in record["rows"] if row["project"] == project.get("id")]
    if len(matches) != 1:
        _fail(SCOPE, "The intent project selects no reviewed projection row")
    row = matches[0]
    application = row["application"]
    if (intent.get("version") != application["version"] or intent.get("tag") != application["tag"]
            or project.get("repository") != application["repository"]):
        _fail(SCOPE, "The intent application version selects no reviewed projection row")
    return _check_row_scope(row)


# Approval and committed lineage ---------------------------------------------------------------

def _aggregate_approved(doc, pin, row):
    """Closed first-wave admitted aggregate; returns filename -> (size, sha256, target)."""
    project, dv = row["project"], row["distribution"]["version"]
    _closed(doc, {"files", "project", "publication_admitted", "schema", "set_sha256", "targets",
                  "upstream_version", "version"}, APPROVAL)
    if (doc["schema"] != _AGGREGATE_SCHEMA or doc["project"] != project
            or doc["version"] != pin["distribution_version"] or doc["version"] != dv
            or doc["upstream_version"] != pin["version"] or doc["targets"] != list(TARGETS)
            or doc["targets"] != pin["candidate_platforms"] or doc["publication_admitted"] is not True):
        _fail(APPROVAL, "First-wave approval is not the admitted aggregate for this distribution")
    stem = project.replace("-", "_") + "-" + dv
    expected = {stem + ".tar.gz": None}
    expected.update({stem + "-py3-none-" + EXPECTED_TAGS[project][target] + ".whl": target for target in TARGETS})
    files = doc["files"]
    if not isinstance(files, list) or len(files) != len(expected):
        _fail(APPROVAL, "First-wave approval must list one sdist and one wheel per target")
    approved = {}
    for item in files:
        _closed(item, {"filename", "logical_sha256", "sha256", "size", "target"}, APPROVAL)
        name = item["filename"]
        if name not in expected or name in approved or item["target"] != expected[name]:
            _fail(APPROVAL, "First-wave approval file set is not the closed aggregate shape")
        _sha(item["sha256"], code=APPROVAL)
        _sha(item["logical_sha256"], code=APPROVAL)
        _positive_int(item["size"], APPROVAL)
        approved[name] = (item["size"], item["sha256"], item["target"])
    if [item["filename"] for item in files] != sorted(expected):
        _fail(APPROVAL, "First-wave approval files must be sorted by filename")
    computed = digest(compact_canonical(files))
    if computed != doc["set_sha256"] or computed != row["distribution"]["set_sha256"]:
        _fail(APPROVAL, "First-wave approval set digest disagrees")
    return approved


def _nebular_approved(doc, row):
    # One schema authority: the publication contract's own pure validators, imported lazily.
    from rs9.tf_pypi_nebular import compute_set_sha256, validate_approval_schema
    try:
        validate_approval_schema(doc)
    except AdmissionError as error:
        _reraise(APPROVAL, "Nebular approval does not satisfy its schema", error)
    distribution = row["distribution"]
    if (doc["publication_admitted"] is not True or doc["builder_can_publish"] is not False
            or doc["project"] != row["project"] or doc["distribution"] != distribution["name"]
            or doc["version"] != distribution["version"]
            or compute_set_sha256(doc) != distribution["set_sha256"]
            or doc["set_sha256"] != distribution["set_sha256"]):
        _fail(APPROVAL, "Nebular approval is not the admitted, non-publishing reviewed set")
    members = doc["members"]
    for item in members:
        _closed(item, {"compressed_size", "mode", "path", "sha256", "size"}, APPROVAL)
        _sha(item["sha256"], code=APPROVAL)
        if (not isinstance(item["path"], str) or type(item["size"]) is not int or item["size"] < 0
                or type(item["compressed_size"]) is not int or item["compressed_size"] < 0
                or item["mode"] != 0o644):
            _fail(APPROVAL, "Nebular approval member table is malformed")
    paths = [item["path"] for item in members]
    if paths != sorted(set(paths)):
        _fail(APPROVAL, "Nebular approval member table must be unique and path-sorted")
    helpers = doc["embedded_helpers"]
    if not isinstance(helpers, dict) or not helpers or any(_SHA256.fullmatch(str(value)) is None
                                                           for value in helpers.values()):
        _fail(APPROVAL, "Nebular approval embedded helper map is malformed")
    item = doc["files"][0]
    return {item["filename"]: (item["size"], item["sha256"], None)}


def _manifest_row(root, record, key, repository):
    raw = _read(root, record[key]["path"], _MANIFEST_LIMIT, LINEAGE)
    if digest(raw) != record[key]["sha256"]:
        _fail(LINEAGE, "Bootstrap manifest bytes differ from the reviewed digest")
    doc = _json(raw, LINEAGE)
    projects = doc.get("projects") if isinstance(doc, dict) else None
    if not isinstance(projects, list):
        _fail(LINEAGE, "Bootstrap manifest project rows are required")
    matches = [item for item in projects if isinstance(item, dict) and item.get("repository") == repository]
    if len(matches) != 1:
        _fail(LINEAGE, "Bootstrap manifest must name the repository exactly once")
    return matches[0]


def _check_manifest_lineage(root, record, row):
    application, lineage = row["application"], row["lineage"]
    for key, side in (("historical_manifest", "historical"), ("current_manifest", "current")):
        item = _manifest_row(root, record, key, application["repository"])
        if (item.get("repository_id") != application["repository_id"] or item.get("tag") != application["tag"]
                or item.get("release_id") != application["release_id"]
                or item.get("version") != application["version"]
                or item.get("tag_commit") != lineage[side]["commit"] or item.get("tag_tree") != lineage[side]["tree"]):
            _fail(LINEAGE, "Bootstrap manifest identity disagrees with the projection lineage")
    # Equal trees alone are never enough: the binding asset and historical pins are also required.
    if (lineage["current"]["commit"] == lineage["historical"]["commit"]
            or lineage["current"]["tree"] != lineage["historical"]["tree"]):
        _fail(LINEAGE, "Projection lineage requires distinct commits with equal trees")


def _check_nebular_committed_lineage(root, record, row, doc):
    application, lineage, binding = row["application"], row["lineage"], row["binding_asset"]
    authentication = doc["authentication"]
    nebular = authentication.get("nebular") if isinstance(authentication, dict) else None
    stellar = authentication.get("stellar_fixture") if isinstance(authentication, dict) else None
    if (not isinstance(nebular, dict) or nebular.get("tag_commit") != lineage["historical"]["commit"]
            or nebular.get("tag_tree") != lineage["historical"]["tree"]
            or nebular.get("repository") != application["repository"] or nebular.get("tag") != application["tag"]
            or nebular.get("project") != row["project"] or _SHA256.fullmatch(str(nebular.get("release_record_sha256"))) is None):
        _fail(LINEAGE, "Nebular approval historical authentication disagrees with the projection")
    if authentication.get("bootstrap_sha256") != record["historical_manifest"]["sha256"]:
        _fail(LINEAGE, "Nebular approval bootstrap digest is not the historical manifest")
    burst = _manifest_row(root, record, "historical_manifest", STELLAR_FIXTURE_REPOSITORY)
    if (not isinstance(stellar, dict) or stellar.get("repository") != STELLAR_FIXTURE_REPOSITORY
            or any(stellar.get(key) != burst.get(key) for key in ("tag", "tag_commit", "tag_tree"))):
        _fail(LINEAGE, "Nebular approval Stellar fixture disagrees with the historical manifest")
    payload = doc["payload_asset"]
    if (not isinstance(payload, dict)
            or {key: payload.get(key) for key in ("github_asset_id", "name", "size", "sha256")} != binding
            or _SHA256.fullmatch(str(payload.get("payload_manifest_sha256"))) is None):
        _fail(LINEAGE, "Nebular approval payload asset is not the projection binding asset")
    raw = _read(root, nebular_lineage.FORWARD_RECORD_PATH, _RECORD_LIMIT, LINEAGE)
    if digest(raw) != nebular_lineage.FORWARD_RECORD_SHA256:
        _fail(LINEAGE, "Nebular forward lineage record differs from its reviewed digest")
    document = _json(raw, LINEAGE)
    inventory = document.get("asset_inventory") if isinstance(document, dict) else None
    expected = {"id": binding["github_asset_id"], "name": binding["name"],
                "sha256": binding["sha256"], "size": binding["size"]}
    if not isinstance(inventory, list) or inventory.count(expected) != 1:
        _fail(LINEAGE, "Nebular binding asset is not in the reviewed forward asset inventory")
    return digest(canonical(inventory))


def _offline_inputs(root, record, row):
    """All committed-source checks for one row; needs no capture and makes no network read."""
    _check_row_scope(row)
    distribution, intake = row["distribution"], row["intake"]
    raw = _read(root, distribution["approval_path"], _APPROVAL_LIMIT, APPROVAL)
    if digest(raw) != distribution["approval_sha256"]:
        _fail(APPROVAL, "Approval bytes differ from the reviewed digest")
    doc = _json(raw, APPROVAL)
    pin = inventory_sha = None
    if distribution["kind"] == "tf-npm-aggregate":
        pin_raw = _read(root, intake["pin_path"], _PIN_LIMIT, APPROVAL)
        if digest(pin_raw) != intake["pin_sha256"]:
            _fail(APPROVAL, "Intake pin bytes differ from the reviewed digest")
        pin = _json(pin_raw, APPROVAL)
        try:
            validate_pin(pin)
        except AdmissionError as error:
            _reraise(APPROVAL, "Intake pin does not satisfy the first-wave contract", error)
        if (pin["project"] != row["project"] or pin["source_status"] != "READY"
                or pin["version"] != row["application"]["version"]
                or pin["distribution_version"] != distribution["version"]):
            _fail(APPROVAL, "Intake pin is not the ready pin for this distribution")
        approved = _aggregate_approved(doc, pin, row)
    else:
        approved = _nebular_approved(doc, row)
    _check_manifest_lineage(root, record, row)
    if pin is not None:
        binding = row["binding_asset"]
        if (pin["source_commit"] != row["lineage"]["historical"]["commit"]
                or (pin["asset"], pin["size"], pin["sha256"]) != (binding["name"], binding["size"], binding["sha256"])):
            _fail(LINEAGE, "Intake pin does not bind the historical commit and release asset bytes")
    else:
        inventory_sha = _check_nebular_committed_lineage(root, record, row, doc)
    return {"approval": doc, "pin": pin, "approved": approved, "inventory_sha256": inventory_sha}


def _desired_identity(row, approved):
    return record_sha256({
        "schema": _IDENTITY_SCHEMA,
        "project": row["project"],
        "application_version": row["application"]["version"],
        "distribution": {"name": row["distribution"]["name"], "version": row["distribution"]["version"]},
        "approval_sha256": row["distribution"]["approval_sha256"],
        "set_sha256": row["distribution"]["set_sha256"],
        "files": {name: value[1] for name, value in sorted(approved.items())},
    })


# Capture, profile and live lineage ------------------------------------------------------------

def _check_capture(capture, row):
    if not isinstance(capture, ReleaseCapture):
        _fail(CAPTURE, "Fresh in-process authenticated capture required")
    try:
        release_hash = authenticated_record_hash(capture)
        tree = authenticated_tree(capture)
        metadata = authenticated_release_metadata(capture)
    except ContractError as error:
        _reraise(CAPTURE, "Fresh in-process authenticated capture required", error)
    application, current, binding = row["application"], row["lineage"]["current"], row["binding_asset"]
    record = capture.record
    repository, release, tag = record.get("repository"), record.get("release"), record.get("tag")
    if (not all(isinstance(item, dict) for item in (repository, release, tag, tree, metadata))
            or repository.get("full_name") != application["repository"]
            or repository.get("id") != application["repository_id"]
            or release.get("id") != application["release_id"] or release.get("tag") != application["tag"]
            or tag.get("commit") != current["commit"] or tag.get("tree") != current["tree"]):
        _fail(CAPTURE, "Authenticated capture is not the projected current release identity")
    if (metadata.get("id") != application["release_id"] or metadata.get("tag_name") != application["tag"]
            or metadata.get("draft") is not False or metadata.get("prerelease") is not False):
        _fail(CAPTURE, "Authenticated release metadata identity disagrees")
    if tree.get("sha") != current["tree"] or tree.get("truncated") is not False:
        _fail(CAPTURE, "Authenticated current tree is incomplete or differs")
    keys = ("github_asset_id", "name", "size", "sha256")
    selected = [item for item in record.get("assets", ()) if isinstance(item, dict) and item.get("name") == binding["name"]]
    if len(selected) != 1 or {key: selected[0].get(key) for key in keys} != binding:
        _fail(CAPTURE, "Authenticated selected asset differs from the projection binding asset")
    held = capture.asset_metadata.get(binding["name"])
    if not isinstance(held, dict) or held != binding:
        _fail(CAPTURE, "Byte-verified binding asset metadata is unavailable")
    api = [item for item in metadata.get("assets", ()) if isinstance(item, dict) and item.get("name") == binding["name"]]
    if (len(api) != 1 or api[0].get("id") != binding["github_asset_id"] or api[0].get("size") != binding["size"]
            or api[0].get("digest") != "sha256:" + binding["sha256"] or api[0].get("state") != "uploaded"):
        _fail(CAPTURE, "Authenticated release metadata differs from the projection binding asset")
    data = _read(capture.root, "assets/" + binding["name"], binding["size"], CAPTURE)
    if len(data) != binding["size"] or digest(data) != binding["sha256"]:
        _fail(CAPTURE, "Captured binding asset bytes changed after authentication")
    retained = capture.evidence_bytes.get(binding["name"])
    if retained is not None and retained != data:
        _fail(CAPTURE, "Retained binding asset bytes changed after authentication")
    return release_hash


def _check_profile(capture, intent, profile, release_hash, row):
    """The profile must be a fresh in-process evaluation of this exact capture and intent."""
    if (not isinstance(profile, dict)
            or set(profile) != {"intent_sha256", "profile", "release_record_sha256", "schema", "sections"}
            or profile["schema"] != _PROFILE_SCHEMA or profile["release_record_sha256"] != release_hash
            or record_sha256(profile) not in capture._profile_results
            or profile["intent_sha256"] != record_sha256(intent)
            or not isinstance(profile["sections"], dict)):
        _fail(CAPTURE, "Profile result requires fresh in-process evaluation of this capture and intent")
    release = intent.get("release")
    evidence = release.get("evidence") if isinstance(release, dict) else None
    if not isinstance(evidence, dict) or profile["profile"] != evidence.get("profile"):
        _fail(CAPTURE, "Profile result does not bind the selected intent profile")
    if row["distribution"]["kind"] == "tf-npm-aggregate" and "forward_lineage" in profile["sections"]:
        _fail(LINEAGE, "First-wave projections never consume forward lineage facts")


def _check_nebular_live_lineage(root, capture, intent, profile, row, inventory_sha, proof):
    try:
        if proof is None:
            proof = nebular_lineage.select_forward_lineage_proof(root, capture, intent)
            if proof is None:
                _fail(LINEAGE, "The reviewed Nebular forward lineage proof is required")
        facts = nebular_lineage.verify_forward_lineage_proof(capture, proof, intent=intent)
    except ContractError as error:
        if error.code.startswith("PYPI_PROJECTION_"):
            raise
        _reraise(LINEAGE, "The reviewed Nebular forward lineage proof is required", error)
    lineage, binding = row["lineage"], row["binding_asset"]
    if (facts.get("current") != lineage["current"] or facts.get("historical") != lineage["historical"]
            or facts.get("tree_relation") != "equal" or facts.get("tree_relation_basis") != "reviewed-record"
            or facts.get("asset_inventory_sha256") != inventory_sha
            or binding["name"] not in facts.get("byte_verified_assets", ())):
        _fail(LINEAGE, "Nebular forward lineage facts disagree with the projection")
    sections = profile["sections"]
    if "forward_lineage" not in sections or canonical(sections["forward_lineage"]) != canonical(facts):
        _fail(LINEAGE, "Profile forward lineage facts disagree with the proof")
    return proof, facts


def _evaluate(repository, capture, intent, profile, proof=None):
    root, raw, record = load_projection_record(repository)
    row = _select_row(record, intent)
    release_hash = _check_capture(capture, row)
    _check_profile(capture, intent, profile, release_hash, row)
    offline = _offline_inputs(root, record, row)
    facts = None
    if row["distribution"]["kind"] == "nebular-native-wheel":
        proof, facts = _check_nebular_live_lineage(root, capture, intent, profile, row,
                                                   offline["inventory_sha256"], proof)
    identity = _desired_identity(row, offline["approved"])
    public = {"schema": _FACTS_SCHEMA, "record_sha256": digest(raw), "row": row,
              "files": {name: value[1] for name, value in sorted(offline["approved"].items())},
              "desired_identity_sha256": identity}
    state = canonical({"release_record_sha256": release_hash, "lineage": facts, "public": public})
    return root, row, offline, proof, identity, canonical(public), state


class PypiProjection:
    """Opaque observer-only capability; public facts are exposed separately and never serialized."""

    __slots__ = ("_capture", "_facts", "_intent", "_profile", "_proof", "_root", "_state", "_token")

    def __init__(self, *, token, root, capture, intent, profile, proof, facts, state):
        if token is not _PROJECTION_TOKEN:
            _fail(RECORD, "PyPI projection construction is module-private")
        for name, value in (("_token", token), ("_root", root), ("_capture", capture), ("_intent", intent),
                            ("_profile", profile), ("_proof", proof), ("_facts", facts), ("_state", state)):
            object.__setattr__(self, name, value)

    def __setattr__(self, name, value):
        raise AttributeError("PyPI projections are immutable")

    def __delattr__(self, name):
        raise AttributeError("PyPI projections are immutable")

    def __reduce_ex__(self, protocol):
        raise TypeError("PyPI projections are in-process capabilities and cannot be serialized")

    def __reduce__(self):
        raise TypeError("PyPI projections are in-process capabilities and cannot be serialized")

    def __getstate__(self):
        raise TypeError("PyPI projections are in-process capabilities and cannot be serialized")

    def __copy__(self):
        raise TypeError("PyPI projections cannot be copied")

    def __deepcopy__(self, memo):
        raise TypeError("PyPI projections cannot be copied")

    def __repr__(self):
        return "PypiProjection(project=" + repr(self.public_facts()["row"]["project"]) + ")"

    @property
    def identity(self):
        return self.public_facts()["desired_identity_sha256"]

    def public_facts(self):
        """A fresh closed copy: record digest, row, approved file digests and desired identity."""
        return json.loads(self._facts)


def build_pypi_projection(repository, capture, intent, profile):
    """Validate every trust input offline, before any remote read, and issue a projection."""
    if not isinstance(intent, dict):
        _fail(SCOPE, "An intent is required")
    if not isinstance(profile, dict):
        _fail(CAPTURE, "An evaluated profile result is required")
    try:
        intent_bytes, profile_bytes = canonical(intent), canonical(profile)
    except (TypeError, ValueError):
        _fail(SCOPE, "Intent and profile must be JSON records")
    # Immutable snapshots: later caller mutation cannot change what the projection binds.
    intent, profile = json.loads(intent_bytes), json.loads(profile_bytes)
    root, _row, _offline, proof, _identity, facts, state = _evaluate(repository, capture, intent, profile)
    return PypiProjection(token=_PROJECTION_TOKEN, root=root, capture=capture, intent=intent_bytes,
                          profile=profile_bytes, proof=proof, facts=facts, state=state)


def _held(projection):
    if type(projection) is not PypiProjection or getattr(projection, "_token", None) is not _PROJECTION_TOKEN:
        _fail(RECORD, "Module-private PyPI projection required")
    return projection


def _revalidate(projection):
    projection = _held(projection)
    intent, profile = json.loads(projection._intent), json.loads(projection._profile)
    _root, row, offline, _proof, identity, facts, state = _evaluate(
        projection._root, projection._capture, intent, profile, projection._proof)
    if facts != projection._facts or state != projection._state:
        _fail(CAPTURE, "PyPI projection trust inputs changed after construction")
    return row, offline, identity


def verify_pypi_projection(projection):
    """Revalidate every trust input at use and return the observer inputs for approved_state."""
    row, offline, identity = _revalidate(projection)
    approved = {name: (value[0], value[1]) for name, value in sorted(offline["approved"].items())}
    return _ObserverInputs(row["distribution"]["name"], row["distribution"]["version"], approved,
                           {name: value[1] for name, value in approved.items()}, identity)


# Embedded provenance --------------------------------------------------------------------------

def _zip_path(info):
    path = info.filename
    if (info.orig_filename != path or not path or not path.isascii() or "\\" in path or "\x00" in path
            or ":" in path or path.startswith("/") or any(ord(c) < 32 or ord(c) == 127 for c in path)
            or any(part in ("", ".", "..") for part in path.split("/"))):
        _fail(PROVENANCE, "Distribution archive member path is unsafe")
    return path


def _read_zip(body, *, member_cap, total_cap, max_members, exact_count=None):
    """Bounded in-memory ZIP read: no extraction, links, duplicates, traversal or oversize members."""
    files, folded, total = {}, set(), 0
    try:
        with zipfile.ZipFile(io.BytesIO(body)) as archive:
            infos = archive.infolist()
            if archive.comment or len(infos) > max_members or (exact_count is not None and len(infos) != exact_count):
                _fail(PROVENANCE, "Distribution archive member count or comment is outside its contract")
            for info in infos:
                path = _zip_path(info)
                mode = info.external_attr >> 16
                cap = member_cap(path)
                if (stat.S_IFMT(mode) != stat.S_IFREG or stat.S_IMODE(mode) not in (0o644, 0o755) or info.is_dir()
                        or info.flag_bits & 1 or info.compress_type not in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED)
                        or info.file_size < 0 or info.file_size > cap or path.casefold() in folded):
                    _fail(PROVENANCE, "Distribution archive member is not a bounded unique regular file")
                folded.add(path.casefold())
                total += info.file_size
                if total > total_cap:
                    _fail(PROVENANCE, "Distribution archive exceeds its total bound")
                # Bound actual decompression; a forged declared size cannot inflate the read.
                with archive.open(info) as stream:
                    data = stream.read(info.file_size + 1)
                if len(data) != info.file_size:
                    _fail(PROVENANCE, "Distribution archive member size disagrees")
                files[path] = (data, stat.S_IMODE(mode), info.compress_size)
    except (zipfile.BadZipFile, zipfile.LargeZipFile, OSError, ValueError, RuntimeError, EOFError,
            NotImplementedError, zlib.error):
        _fail(PROVENANCE, "Distribution archive is not a readable bounded ZIP")
    for path in files:
        if any(parent.as_posix().casefold() in folded for parent in PurePosixPath(path).parents
               if parent.as_posix() != "."):
            _fail(PROVENANCE, "Distribution archive member collides with an ancestor")
    return files


def _metadata(data):
    try:
        return Parser().parsestr(data.decode("utf-8"), headersonly=True)
    except UnicodeError:
        _fail(PROVENANCE, "Distribution metadata is not UTF-8")


def _check_first_wave_wheel(body, name, target, row, pin):
    project, dv = row["project"], row["distribution"]["version"]
    files = _read_zip(body, member_cap=lambda _path: _WHEEL_MEMBER_BYTES, total_cap=_WHEEL_TOTAL_BYTES,
                      max_members=_WHEEL_MEMBERS)
    info = project.replace("-", "_") + "-" + dv + ".dist-info"
    entries = [files.get(info + suffix) for suffix in ("/METADATA", "/WHEEL", "/rs9-tf-transform.json")]
    if any(entry is None for entry in entries):
        _fail(PROVENANCE, "First-wave wheel provenance members are missing")
    metadata, wheel, transform = _metadata(entries[0][0]), _metadata(entries[1][0]), _json(entries[2][0], PROVENANCE)
    base = "https://github.com/" + row["application"]["repository"]
    urls = ["Release, " + base + "/releases/tag/" + row["application"]["tag"],
            "Source, " + base + "/tree/" + row["lineage"]["historical"]["commit"]]
    if (metadata.get_all("Name") != [project] or metadata.get_all("Version") != [dv]
            or sorted(metadata.get_all("Project-URL") or []) != urls):
        _fail(PROVENANCE, "First-wave wheel metadata does not bind the historical source and release")
    tag = EXPECTED_TAGS[project][target]
    if wheel.get_all("Tag") != ["py3-none-" + tag] or not name.endswith("-py3-none-" + tag + ".whl"):
        _fail(PROVENANCE, "First-wave wheel tag disagrees with its approved target")
    dependencies = {item["asset"]: item["sha256"] for item in pin.get("dependencies", [])}
    if (not isinstance(transform, dict) or transform.get("target_key") not in TARGETS
            or transform.get("target_key") != target
            or transform.get("source_sha256") != pin["sha256"]
            or transform.get("source_sha256") != row["binding_asset"]["sha256"]
            or transform.get("dependencies") != dependencies):
        _fail(PROVENANCE, "First-wave wheel transform does not bind the pinned release asset")


def _check_first_wave_sdist(body, row, pin):
    stem = row["project"].replace("-", "_") + "-" + row["distribution"]["version"]
    try:
        files = read_tar(body, stem)
    except AdmissionError as error:
        _reraise(PROVENANCE, "First-wave sdist is not a bounded safe archive", error)
    binding = row["binding_asset"]
    upstream = files.get(stem + "/upstream/" + pin["asset"])
    pins = files.get(stem + "/_rs9_build/rs9/pins.json")
    if (upstream is None or len(upstream[0]) != binding["size"] or digest(upstream[0]) != binding["sha256"]
            or pins is None or pins[0] != compact_canonical(build_pin(pin))):
        _fail(PROVENANCE, "First-wave sdist does not embed the pinned release asset and build pin")


def _check_nebular_wheel(body, row, approval):
    members = approval["members"]
    caps = {item["path"]: item["size"] for item in members}
    files = _read_zip(body, member_cap=lambda path: caps.get(path, -1), total_cap=sum(caps.values()),
                      max_members=len(members), exact_count=len(members))
    table = [{"compressed_size": compressed, "mode": mode, "path": path, "sha256": digest(data), "size": len(data)}
             for path, (data, mode, compressed) in sorted(files.items())]
    if table != members:
        _fail(PROVENANCE, "Nebular wheel member table differs from the approval")
    package = row["project"].replace("-", "_")
    binding, payload = row["binding_asset"], approval["payload_asset"]
    archive = files.get(package + "/payload/" + binding["name"])
    if archive is None or len(archive[0]) != binding["size"] or digest(archive[0]) != binding["sha256"]:
        _fail(PROVENANCE, "Nebular wheel payload is not the projection binding asset")
    for relative, sha in approval["embedded_helpers"].items():
        helper = files.get(package + "/_isolated/" + relative)
        if helper is None or digest(helper[0]) != sha:
            _fail(PROVENANCE, "Nebular wheel embedded helpers differ from the approval")
    manifest = files.get(package + "/payload/manifest.json")
    document = _json(manifest[0], PROVENANCE) if manifest is not None else None
    if not isinstance(document, dict) or document.get("manifest_sha256") != payload["payload_manifest_sha256"]:
        _fail(PROVENANCE, "Nebular wheel payload manifest differs from the approval")
    provenance = files.get(package + "/_rs9/provenance.json")
    document = _json(provenance[0], PROVENANCE) if provenance is not None else None
    expected = {
        "schema": _NEBULAR_PROVENANCE_SCHEMA,
        "product_id": approval["project"],
        "distribution_name": approval["distribution"],
        "version": approval["version"],
        "wheel_tag": approval["wheel_tag"],
        # Historical release record bound by the approval, never the current capture hash.
        "release_record_sha256": approval["authentication"]["nebular"]["release_record_sha256"],
        "payload_archive_sha256": binding["sha256"],
        "manifest_sha256": payload["payload_manifest_sha256"],
        "helper_source_sha256": approval["embedded_helpers"],
    }
    if (not isinstance(document, dict) or any(document.get(key) != value for key, value in expected.items())
            or any(document.get(flag) is not False for flag in ("fixture_only", "candidate_only", "can_publish"))):
        _fail(PROVENANCE, "Nebular wheel provenance disagrees with the approval")


def verify_distribution_provenance(projection, bodies):
    """Check embedded provenance of approved-digest bytes only; no rebuild and no current builder."""
    row, offline, _identity = _revalidate(projection)
    approved = offline["approved"]
    if not isinstance(bodies, dict) or set(bodies) != set(approved):
        _fail(PROVENANCE, "Provenance requires exactly the approved distribution files")
    for name, (size, sha, _target) in approved.items():
        body = bodies[name]
        if type(body) is not bytes or len(body) != size or digest(body) != sha:
            _fail(PROVENANCE, "Provenance is checked only on bytes matching the approved digest")
    if row["distribution"]["kind"] == "nebular-native-wheel":
        for name in approved:
            _check_nebular_wheel(bodies[name], row, offline["approval"])
        return
    pin = offline["pin"]
    for name, (_size, _sha, target) in sorted(approved.items()):
        if target is None:
            _check_first_wave_sdist(bodies[name], row, pin)
        else:
            _check_first_wave_wheel(bodies[name], name, target, row, pin)
