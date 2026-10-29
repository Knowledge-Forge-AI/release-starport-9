"""Exact forward provenance reconciliation for the Nebular v0.6.1 release.

The historical bootstrap and release records remain authoritative for their
original identity.  This module adds one module-private, capture-bound proof
for the reviewed current-tag/old-provenance pair.  It does not change GitHub
authentication, bootstrap authority, or publication capability.
"""

import copy
import json
import re

from rs9.errors import ContractError
from rs9.records import validate_rfc3339_utc
from rs9.release_core import (
    ReleaseCapture,
    authenticated_record_hash,
    authenticated_release_metadata,
    authenticated_tree,
    digest,
    read_evidence,
)
from rs9.scratch import canonical, physical_directory

FORWARD_RECORD_PATH = "config/forward/theme-forge-nebular-fusion/v0.6.1-lineage/reconciliation.json"
FORWARD_RECORD_SHA256 = "358da4d0d607aeb2ba8d2ab77131054a5c45165692e72d1f316d8d47b01ce5f9"

CURRENT_REPOSITORY = "Knowledge-Forge-AI/theme-forge-nebular-fusion"
CURRENT_REPOSITORY_ID = 1358643872
CURRENT_TAG = "v0.6.1"
CURRENT_VERSION = "0.6.1"
CURRENT_RELEASE_ID = 400494635
CURRENT_COMMIT = "75bc4125a1e6a109321071ce70b3b99ae826f050"
CURRENT_TREE = "203a80b33fc94c776c9c184f8cac4f1609cb0f2b"
HISTORICAL_COMMIT = "49e2c4919b6b4ec9bd4ed5d7e7ced90921e00f5e"
HISTORICAL_TREE = CURRENT_TREE
PROVENANCE_NAME = "PROVENANCE.json"
PROVENANCE_SHA256 = "3645984085dc434b1678eec16440d79a8c87dd704836eb8731085425dc976d1c"
PROVENANCE_SIZE = 14720
PROVENANCE_ASSET_ID = 601953752
CURRENT_NATIVE_PROVENANCE_SCHEMA = "nebular.public-native-ci-release-provenance.v1"

_PROOF_TOKEN = object()
_SHA1 = re.compile(r"[0-9a-f]{40}\Z")
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_ASSET_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._+-]{0,255}\Z")
_REASON = "operator-authorized Git author metadata correction; no payload or publication authority"


def _fail(code, message):
    raise ContractError(code, message)


def _closed(value, fields, *, code="LINEAGE_RECORD"):
    if not isinstance(value, dict) or set(value) != set(fields):
        _fail(code, "Forward lineage record has an unexpected field set")
    return value


def _sha(value, *, length=64):
    pattern = _SHA256 if length == 64 else _SHA1
    if not isinstance(value, str) or not pattern.fullmatch(value):
        _fail("LINEAGE_RECORD", "Forward lineage record contains an invalid object identity")
    return value


def _positive_int(value):
    if type(value) is not int or value <= 0:
        _fail("LINEAGE_RECORD", "Forward lineage record contains an invalid positive integer")
    return value


def _asset_row(value):
    _closed(value, {"id", "name", "sha256", "size"})
    _positive_int(value["id"])
    if not isinstance(value["name"], str) or not _ASSET_NAME.fullmatch(value["name"]):
        _fail("LINEAGE_RECORD", "Forward lineage record contains an invalid asset name")
    _sha(value["sha256"])
    _positive_int(value["size"])
    return value


def _validate_record(record, raw):
    """Validate the reviewed canonical JSON and all lineage invariants."""
    if raw != canonical(record) or digest(raw) != FORWARD_RECORD_SHA256:
        _fail("LINEAGE_RECORD", "Only the exact reviewed forward lineage bytes are accepted")
    _closed(record, {"asset_inventory", "current", "historical", "provenance_asset",
                     "publisher_assertions", "reason", "release", "repository", "schema"})
    if record["schema"] != "rs9.nebular-forward-lineage.v1alpha1" or record["reason"] != _REASON:
        _fail("LINEAGE_RECORD", "Unknown or unauthorized forward lineage record")

    repository = _closed(record["repository"], {"full_name", "id"})
    if repository != {"full_name": CURRENT_REPOSITORY, "id": CURRENT_REPOSITORY_ID}:
        _fail("LINEAGE_RECORD", "Forward lineage repository binding is not the reviewed Nebular repository")

    release = _closed(record["release"], {"id", "published_at", "tag", "version"})
    if (release["id"] != CURRENT_RELEASE_ID or release["tag"] != CURRENT_TAG
            or release["version"] != CURRENT_VERSION):
        _fail("LINEAGE_RECORD", "Forward lineage release binding is not the reviewed release")
    validate_rfc3339_utc(release["published_at"])

    current = _closed(record["current"], {"commit", "tree"})
    historical = _closed(record["historical"], {"commit", "tree"})
    _sha(current["commit"], length=40)
    _sha(current["tree"], length=40)
    _sha(historical["commit"], length=40)
    _sha(historical["tree"], length=40)
    if current != {"commit": CURRENT_COMMIT, "tree": CURRENT_TREE}:
        _fail("LINEAGE_RECORD", "Forward lineage current identity is not the reviewed tag")
    if historical != {"commit": HISTORICAL_COMMIT, "tree": HISTORICAL_TREE}:
        _fail("LINEAGE_RECORD", "Forward lineage historical identity is not the reviewed provenance")
    if current["commit"] == historical["commit"] or current["tree"] != historical["tree"]:
        _fail("LINEAGE_RECORD", "Forward lineage requires distinct commits with equal trees")

    assertions = _closed(record["publisher_assertions"],
                          {"mergedMainCommit", "mergedMainTree", "repository", "tag", "tagTarget"})
    expected_assertions = {
        "mergedMainCommit": historical["commit"],
        "mergedMainTree": historical["tree"],
        "repository": repository["full_name"],
        "tag": release["tag"],
        "tagTarget": historical["commit"],
    }
    if assertions != expected_assertions:
        _fail("LINEAGE_RECORD", "Forward lineage publisher assertions do not match the historical identity")

    inventory = record["asset_inventory"]
    if not isinstance(inventory, list) or len(inventory) != 13:
        _fail("LINEAGE_RECORD", "Exactly thirteen forward release assets are required")
    rows = [_asset_row(row) for row in inventory]
    names = [row["name"] for row in rows]
    ids = [row["id"] for row in rows]
    if names != sorted(names) or len(set(names)) != len(names) or len(set(ids)) != len(ids):
        _fail("LINEAGE_RECORD", "Forward asset inventory must be unique and name-sorted")

    provenance_asset = _asset_row(record["provenance_asset"])
    matching = [row for row in rows if row == provenance_asset]
    if len(matching) != 1 or provenance_asset != {
        "id": PROVENANCE_ASSET_ID,
        "name": PROVENANCE_NAME,
        "sha256": PROVENANCE_SHA256,
        "size": PROVENANCE_SIZE,
    }:
        _fail("LINEAGE_RECORD", "Forward provenance asset is not the reviewed immutable asset")
    return record


def _load_record(repository):
    root = physical_directory(repository)
    raw = read_evidence(root, FORWARD_RECORD_PATH, limit=64 * 1024)
    try:
        record = json.loads(raw)
    except (ValueError, UnicodeError):
        _fail("LINEAGE_RECORD", "Forward lineage configuration is not valid JSON")
    _validate_record(record, raw)
    return root, raw, record


def _intent_roles(intent):
    if not isinstance(intent, dict):
        _fail("LINEAGE_CAPTURE", "Forward lineage intent is required")
    if intent.get("project", {}).get("repository") != CURRENT_REPOSITORY:
        _fail("LINEAGE_CAPTURE", "Forward lineage intent repository disagrees")
    if intent.get("project", {}).get("id") != "theme-forge-nebular-fusion":
        _fail("LINEAGE_CAPTURE", "Forward lineage intent project disagrees")
    evidence = intent.get("release", {}).get("evidence")
    rows = evidence.get("assets") if isinstance(evidence, dict) else None
    if not isinstance(rows, list):
        _fail("LINEAGE_CAPTURE", "Forward lineage evidence roles are required")
    roles = {row.get("role"): row.get("name") for row in rows if isinstance(row, dict)}
    if len(roles) != len(rows) or roles.get("provenance") != PROVENANCE_NAME:
        _fail("LINEAGE_CAPTURE", "Forward lineage must bind the authenticated provenance role")
    return roles


def _metadata_inventory(capture, record):
    metadata = authenticated_release_metadata(capture)
    rows = metadata.get("assets") if isinstance(metadata, dict) else None
    if not isinstance(rows, list) or len(rows) != len(record["asset_inventory"]):
        _fail("LINEAGE_CAPTURE", "Authenticated release metadata must contain exactly thirteen assets")
    expected = {row["name"]: row for row in record["asset_inventory"]}
    observed = {}
    ids = set()
    for row in rows:
        if not isinstance(row, dict):
            _fail("LINEAGE_CAPTURE", "Authenticated release metadata contains a malformed asset")
        name, asset_id, size, state, raw_digest = (
            row.get("name"), row.get("id"), row.get("size"), row.get("state"), row.get("digest"))
        if (not isinstance(name, str) or not _ASSET_NAME.fullmatch(name)
                or name in observed or name not in expected
                or type(asset_id) is not int or asset_id <= 0 or asset_id in ids
                or type(size) is not int or size <= 0
                or state != "uploaded"
                or not isinstance(raw_digest, str) or not re.fullmatch(r"sha256:[0-9a-f]{64}", raw_digest)):
            _fail("LINEAGE_CAPTURE", "Authenticated release metadata contains an invalid asset row")
        ids.add(asset_id)
        observed[name] = {"id": asset_id, "name": name, "size": size, "sha256": raw_digest[7:]}
    if observed != expected:
        _fail("LINEAGE_CAPTURE", "Authenticated release metadata differs from the reviewed thirteen-row inventory")
    return observed


def _selected_inventory(capture, expected):
    selected = capture.record.get("assets")
    if not isinstance(selected, list) or not selected:
        _fail("LINEAGE_CAPTURE", "Authenticated selected asset records are required")
    verified = {}
    for row in selected:
        if not isinstance(row, dict):
            _fail("LINEAGE_CAPTURE", "Authenticated selected asset record is malformed")
        name = row.get("name")
        if name in verified or name not in expected:
            _fail("LINEAGE_CAPTURE", "Authenticated selected asset is outside the reviewed inventory")
        observed = {
            "id": row.get("github_asset_id"),
            "name": row.get("name"),
            "size": row.get("size"),
            "sha256": row.get("sha256"),
        }
        if observed != expected[name]:
            _fail("LINEAGE_CAPTURE", "Authenticated selected asset differs from the API inventory")
        authenticated = capture.asset_metadata.get(name)
        if (not isinstance(authenticated, dict)
                or {key: authenticated.get(key) for key in ("github_asset_id", "name", "size", "sha256")}
                != {"github_asset_id": expected[name]["id"], **{key: expected[name][key] for key in ("name", "size", "sha256")}}):
            _fail("LINEAGE_CAPTURE", "Byte-verified selected asset metadata is unavailable")
        verified[name] = True
    return sorted(verified)


def _provenance(capture, record):
    expected = record["provenance_asset"]
    raw = capture.evidence_bytes.get(PROVENANCE_NAME)
    if not isinstance(raw, bytes) or len(raw) != expected["size"] or digest(raw) != expected["sha256"]:
        _fail("LINEAGE_PROVENANCE", "Authenticated provenance bytes differ from the reviewed asset")
    disk = read_evidence(capture.root, "assets/" + PROVENANCE_NAME, limit=expected["size"])
    if disk != raw:
        _fail("LINEAGE_PROVENANCE", "Captured provenance bytes changed after authentication")
    try:
        parsed = json.loads(raw)
    except (ValueError, UnicodeError):
        _fail("LINEAGE_PROVENANCE", "Authenticated provenance bytes are not valid JSON")
    assertions = parsed.get("release") if isinstance(parsed, dict) else None
    required = record["publisher_assertions"]
    if not isinstance(assertions, dict) or any(assertions.get(key) != value for key, value in required.items()):
        _fail("LINEAGE_PROVENANCE", "Provenance assertions do not match the reviewed historical identity")
    return digest(raw)


def _validate_live(capture, record, intent=None, roles=None):
    if not isinstance(capture, ReleaseCapture):
        _fail("LINEAGE_CAPTURE", "Fresh in-process authenticated capture required")
    release_hash = authenticated_record_hash(capture)
    repository = capture.record.get("repository", {})
    release = capture.record.get("release", {})
    tag = capture.record.get("tag", {})
    current = record["current"]
    if (repository.get("full_name") != record["repository"]["full_name"]
            or repository.get("id") != record["repository"]["id"]
            or release.get("id") != record["release"]["id"]
            or release.get("tag") != record["release"]["tag"]
            or tag.get("commit") != current["commit"]
            or tag.get("tree") != current["tree"]):
        _fail("LINEAGE_CAPTURE", "Authenticated capture is not the reviewed current release identity")
    metadata = authenticated_release_metadata(capture)
    if (metadata.get("tag_name") != record["release"]["tag"]
            or metadata.get("id") != record["release"]["id"]
            or metadata.get("draft") is not False
            or metadata.get("prerelease") is not False):
        _fail("LINEAGE_CAPTURE", "Authenticated release metadata identity disagrees")
    published_at = capture.record.get("source_times", {}).get("published_at")
    if published_at != record["release"]["published_at"] or metadata.get("published_at") != published_at:
        _fail("LINEAGE_CAPTURE", "Authenticated publication timestamp disagrees")
    tree = authenticated_tree(capture)
    if tree.get("sha") != current["tree"] or tree.get("truncated") is not False:
        _fail("LINEAGE_CAPTURE", "Authenticated current tree is incomplete or differs")
    if intent is not None:
        intent_roles = _intent_roles(intent)
        if roles is not None and roles.get("provenance") != intent_roles["provenance"]:
            _fail("LINEAGE_CAPTURE", "Forward lineage profile roles disagree")
        if intent.get("version") != record["release"]["version"] or intent.get("tag") != record["release"]["tag"]:
            _fail("LINEAGE_CAPTURE", "Forward lineage intent version or tag disagrees")
    elif roles is not None and roles.get("provenance") != PROVENANCE_NAME:
        _fail("LINEAGE_CAPTURE", "Forward lineage profile role disagrees")
    expected = {row["name"]: row for row in record["asset_inventory"]}
    _metadata_inventory(capture, record)
    byte_verified = _selected_inventory(capture, expected)
    provenance_sha = _provenance(capture, record)
    inventory_sha = digest(canonical(record["asset_inventory"]))
    return {
        "schema": "rs9.nebular-forward-lineage-proof.v1alpha1",
        "forward_record_sha256": FORWARD_RECORD_SHA256,
        "authenticated_record_sha256": release_hash,
        "current": copy.deepcopy(record["current"]),
        "historical": copy.deepcopy(record["historical"]),
        "tree_relation": "equal",
        "tree_relation_basis": "reviewed-record",
        "provenance_asset": {
            "id": record["provenance_asset"]["id"],
            "name": record["provenance_asset"]["name"],
            "size": record["provenance_asset"]["size"],
            "sha256": provenance_sha,
        },
        "asset_inventory_sha256": inventory_sha,
        "byte_verified_assets": byte_verified,
        "api_digest_only_assets": sorted(set(expected) - set(byte_verified)),
    }


class ForwardLineageProof:
    """Opaque in-process capability; facts are exposed separately."""

    __slots__ = ("_capture", "_facts", "_record_bytes", "_record_root", "_token")

    def __init__(self, capture, record_root, record_bytes, facts, *, token):
        if token is not _PROOF_TOKEN:
            _fail("LINEAGE_PROOF", "Forward lineage proof construction is module-private")
        self._token = token
        self._capture = capture
        self._record_root = record_root
        self._record_bytes = record_bytes
        self._facts = copy.deepcopy(facts)


def build_forward_lineage_proof(capture, intent, repository):
    """Validate the reviewed record and current capture before issuing a proof."""
    record_root, record_bytes, record = _load_record(repository)
    roles = _intent_roles(intent)
    facts = _validate_live(capture, record, intent, roles)
    return ForwardLineageProof(capture, record_root, record_bytes, facts, token=_PROOF_TOKEN)


def verify_forward_lineage_proof(capture, proof, *, intent=None, roles=None):
    """Revalidate a proof and its exact capture/configuration inputs at use."""
    if not isinstance(proof, ForwardLineageProof) or proof._token is not _PROOF_TOKEN:
        _fail("LINEAGE_PROOF", "Module-private forward lineage proof required")
    if proof._capture is not capture:
        _fail("LINEAGE_PROOF", "Forward lineage proof is bound to another capture")
    _record_root, record_bytes, record = _load_record(proof._record_root)
    if record_bytes != proof._record_bytes:
        _fail("LINEAGE_PROOF", "Forward lineage configuration changed after proof construction")
    facts = _validate_live(capture, record, intent, roles)
    if canonical(facts) != canonical(proof._facts):
        _fail("LINEAGE_PROOF", "Forward lineage proof facts changed after construction")
    return copy.deepcopy(facts)


def verify_direct_release_lineage(capture, binding):
    """Verify the release-specific v0.7 tag/provenance equality contract.

    This is intentionally separate from the historical v0.6.1 author-metadata
    correction above.  A ready Gate1 binding supplies the exact release
    coordinates and the source path/field names for the v0.7 provenance
    document.  No value is inferred from the retained v0.6.1 record.
    """
    if not isinstance(capture, ReleaseCapture):
        _fail("LINEAGE_CAPTURE", "Fresh in-process authenticated capture required")
    if not isinstance(binding, dict) or binding.get("status") != "ready":
        _fail("LINEAGE_INPUTS_PENDING", "Ready v0.7 release binding is required")
    if binding.get("release") != "0.7.0" or binding.get("tag") != "v0.7.0":
        _fail("LINEAGE_BINDING", "Direct lineage is only defined for the v0.7.0 release")
    expected = binding.get("expected")
    if not isinstance(expected, dict) or set(expected) != {
        "repository_id", "release_id", "tag_commit", "tag_tree",
        "bootstrap_sha256", "expectations_sha256",
    }:
        _fail("LINEAGE_BINDING", "Direct lineage requires exact release coordinates")
    authenticated_record_hash(capture)
    repository = capture.record.get("repository", {})
    release = capture.record.get("release", {})
    tag = capture.record.get("tag", {})
    if (
        repository.get("full_name") != binding.get("repository")
        or repository.get("id") != expected["repository_id"]
        or release.get("id") != expected["release_id"]
        or release.get("tag") != binding.get("tag")
        or tag.get("commit") != expected["tag_commit"]
        or tag.get("tree") != expected["tag_tree"]
    ):
        _fail("LINEAGE_CAPTURE", "Authenticated v0.7 release identity differs from the ready binding")
    metadata = authenticated_release_metadata(capture)
    if (
        metadata.get("id") != expected["release_id"]
        or metadata.get("tag_name") != binding.get("tag")
        or metadata.get("draft") is not False
        or metadata.get("prerelease") is not False
    ):
        _fail("LINEAGE_CAPTURE", "Authenticated v0.7 release metadata disagrees")
    tree = authenticated_tree(capture)
    if tree.get("sha") != expected["tag_tree"] or tree.get("truncated") is not False:
        _fail("LINEAGE_CAPTURE", "Authenticated v0.7 tree is incomplete or differs")

    provenance = binding.get("provenance")
    legacy_provenance = {
        "path": PROVENANCE_NAME,
        "commit_field": "tagCommit",
        "tree_field": "tagTree",
    }
    current_provenance = {
        "path": PROVENANCE_NAME,
        "commit_field": "releaseCommit",
        "tree_field": "testedTree",
    }
    current_intake_provenance = {
        "path": "PYPI-INTAKE-PROVENANCE.json",
        "commit_field": "releaseCommit",
        "tree_field": "testedTree",
    }
    if provenance == legacy_provenance:
        provenance_kind = "legacy"
    elif provenance == current_provenance or provenance == current_intake_provenance or provenance == {
        "path": "nebular-v0.7.0-native-ci-provenance.json",
        "commit_field": "releaseCommit", "tree_field": "testedTree",
    }:
        provenance_kind = "current-native"
    else:
        _fail("LINEAGE_BINDING", "Direct provenance identity fields are fixed")
    path = provenance["path"]
    if not isinstance(path, str) or not path:
        _fail("LINEAGE_PROVENANCE", "Authenticated v0.7 provenance path is unavailable")
    # A release provenance document is normally an authenticated asset rather
    # than a tagged-source file.  Keep both routes explicit so the proof never
    # silently reads an arbitrary path from disk.
    if path in capture.source:
        raw = capture.source[path]
        provenance_source_kind = "source"
    elif path in capture.evidence_bytes:
        raw = capture.evidence_bytes[path]
        provenance_source_kind = "asset"
    else:
        _fail("LINEAGE_PROVENANCE", "Authenticated v0.7 provenance bytes are unavailable")
    try:
        document = json.loads(raw)
    except (ValueError, UnicodeError):
        _fail("LINEAGE_PROVENANCE", "Authenticated v0.7 provenance source is not valid JSON")
    if not isinstance(document, dict):
        _fail("LINEAGE_PROVENANCE", "Authenticated v0.7 provenance document must be an object")
    if provenance_kind == "legacy":
        release_document = document.get("release")
        if not isinstance(release_document, dict):
            _fail("LINEAGE_PROVENANCE", "Authenticated v0.7 provenance release object is required")
    else:
        # The current public-native schema stores releaseCommit/testedTree at
        # the document root; its numeric ``release`` field is checked below.
        release_document = document
    commit_field, tree_field = provenance["commit_field"], provenance["tree_field"]
    provenance_commit = release_document.get(commit_field)
    provenance_tree = release_document.get(tree_field)
    if provenance_commit != expected["tag_commit"] or provenance_tree != expected["tag_tree"]:
        _fail("LINEAGE_PROVENANCE", "v0.7 provenance commit/tree do not equal the authenticated tag")
    facts = {
        "schema": "rs9.nebular-direct-lineage.v1alpha1",
        "mode": "direct-tag-provenance-equality",
        "release": binding["release"],
        "tag": binding["tag"],
        "repository": binding["repository"],
        "tag_commit": expected["tag_commit"],
        "tag_tree": expected["tag_tree"],
        "provenance_path": path,
        "provenance_source_kind": provenance_source_kind,
        "provenance_sha256": digest(raw),
        "provenance_commit_field": commit_field,
        "provenance_tree_field": tree_field,
        "author_rewrite_required": False,
        "authenticated_record_sha256": authenticated_record_hash(capture),
    }
    if provenance_kind == "current-native":
        if document.get("schema") != CURRENT_NATIVE_PROVENANCE_SCHEMA:
            _fail("LINEAGE_PROVENANCE", "Current native provenance schema is not recognized")
        document_release = document.get("release")
        if (not isinstance(document.get("repository"), str)
                or not isinstance(document.get("version"), str)
                or type(document_release) is not int or document_release <= 0
                or document.get("repository") != binding["repository"]
                or document.get("version") != binding["release"]
                or document_release != release.get("id")):
            _fail("LINEAGE_PROVENANCE", "Current native provenance release identity disagrees")
        for field in ("releaseCommit", "testedCommit", "testedTree"):
            value = document.get(field)
            if not isinstance(value, str) or not _SHA1.fullmatch(value):
                _fail("LINEAGE_PROVENANCE", "Current native provenance contains an invalid commit identity")
        if (document["releaseCommit"] != expected["tag_commit"]
                or document["testedTree"] != expected["tag_tree"]
                or document["testedTree"] != tree["sha"]):
            _fail("LINEAGE_PROVENANCE", "Current native provenance commit/tree do not equal the authenticated tag")
        for field in ("nativeCiRun", "nativeCiAttempt", "sourceCiRun"):
            value = document.get(field)
            if type(value) is not int or value <= 0:
                _fail("LINEAGE_PROVENANCE", "Current native provenance contains an invalid CI identity")
        facts.update({
            "provenance_schema": document["schema"],
            "tested_commit": document["testedCommit"],
            "native_ci_run": document["nativeCiRun"],
            "native_ci_attempt": document["nativeCiAttempt"],
            "source_ci_run": document["sourceCiRun"],
        })
    return facts


def is_current_forward_identity(capture):
    """Select the correction only for the exact reviewed current identity."""
    if not isinstance(capture, ReleaseCapture):
        return False
    repository = capture.record.get("repository", {})
    release = capture.record.get("release", {})
    tag = capture.record.get("tag", {})
    return (repository.get("full_name") == CURRENT_REPOSITORY
            and repository.get("id") == CURRENT_REPOSITORY_ID
            and release.get("id") == CURRENT_RELEASE_ID
            and release.get("tag") == CURRENT_TAG
            and tag.get("commit") == CURRENT_COMMIT)


def select_forward_lineage_proof(repository, capture, intent):
    """Explicit caller opt-in: historical identities retain the strict path."""
    if not is_current_forward_identity(capture):
        return None
    return build_forward_lineage_proof(capture, intent, repository)
