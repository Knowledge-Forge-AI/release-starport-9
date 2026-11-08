"""Pure validation for the held 0.8 tracked-input contract.

This module deliberately stops before filesystem acquisition and route replay.
The prepared R source has real input bytes and digests, but its clean-checkout
commit and tree are not yet bound. A later clean checkout may consume this
contract after independently supplying that identity and rechecking every
tracked file.
"""

from __future__ import annotations

from collections.abc import Mapping
import hashlib
import json
import os
from pathlib import Path
import stat
from typing import Any

from rs9.materialize import validate_ancestry_not_symlink


SCHEMA = "rs9.tracked080-public-input-manifest.v1"
BINDING_SCHEMA = "rs9.tracked080-release-binding.v1"
RS9_REPOSITORY = "Knowledge-Forge-AI/release-starport-9"
PRODUCT_REPOSITORY = "Knowledge-Forge-AI/theme-forge-nebular-fusion"
PRODUCT_COMMIT = "516f5a7d8a449946a0246ea23d37991f586dfc2c"
PRODUCT_TREE = "907163a09d2995c9080074294db54c54af626563"
RELAY_TAG = "nebular-v0.8.0-native-evidence-run-42418673472-attempt-1"
RELAY_RELEASE_ID = 438017969
RELAY_ARCHIVE_ASSET_ID = 722806135
RELAY_INVENTORY_ASSET_ID = 722806134
TRACKED_CANDIDATE = "nebular080-r-os-complete-prep2"
TRACKED_INPUTS = {
    "bootstrap": {
        "path": "bootstrap/pre-rs9/theme-forge-current-202610/manifest.json",
        "bytes": 3168,
        "sha256": "9543dacd536623c891dd04a2163eca20be3ba5c75ef94686d47b45401e8ea8f6",
    },
    "expectations": {
        "path": "operators/theme-forge-current-202610/expectations.json",
        "bytes": 10351,
        "sha256": "b9bb151acea81b16000e6c169a74e40f7e724f0d5867d39f92679f57ef32d08a",
    },
    "command_contracts": {
        "path": "operators/theme-forge-current-202610/command-contracts.json",
        "bytes": 6379,
        "sha256": "a60527272a3c7915260bb3e7fdcd38f7c3c24eb0f3fba7739f9609f7cd5589b8",
    },
}
_HEX40 = frozenset("0123456789abcdef")
_HEX64 = _HEX40


def canonical(value: Any) -> bytes:
    """Return the stable compact JSON bytes used for contract identities."""
    return (json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")


def sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _fail(reason: str) -> None:
    raise ValueError("TRACKED080_" + reason)


def _hex(value: Any, width: int) -> bool:
    return isinstance(value, str) and len(value) == width and set(value) <= (_HEX40 if width == 40 else _HEX64)


def _path(value: Any) -> str:
    if (
        not isinstance(value, str)
        or not value
        or value.startswith("/")
        or "\\" in value
        or "\x00" in value
        or any(part in ("", ".", "..") for part in Path(value).parts)
    ):
        _fail("PATH")
    return value


def _file_row(value: Any, expected: Mapping[str, Any]) -> dict[str, Any]:
    if not isinstance(value, Mapping) or set(value) != {"path", "bytes", "sha256"}:
        _fail("FILE_ROW")
    if value.get("path") != expected["path"] or value.get("bytes") != expected["bytes"] or value.get("sha256") != expected["sha256"]:
        _fail("FILE_ROW")
    _path(value["path"])
    if type(value["bytes"]) is not int or value["bytes"] <= 0 or not _hex(value["sha256"], 64):
        _fail("FILE_ROW")
    return dict(value)


def _source(value: Any) -> dict[str, Any]:
    if not isinstance(value, Mapping) or set(value) != {
        "repository", "candidate", "candidate_status", "identity_status", "commit", "tree", "identity_reason",
    }:
        _fail("SOURCE")
    if (
        value["repository"] != RS9_REPOSITORY
        or value["candidate"] != TRACKED_CANDIDATE
        or value["candidate_status"] != "source-preparation-only"
        or value["identity_status"] != "late-bound-clean-checkout"
        or value["commit"] is not None
        or value["tree"] is not None
        or not isinstance(value["identity_reason"], str)
        or not value["identity_reason"]
    ):
        _fail("SOURCE")
    return dict(value)


def _product_evidence(value: Any) -> dict[str, Any]:
    required = {
        "repository", "tag", "release_id", "commit", "tree", "relay_release_id", "relay_tag",
        "relay_archive_asset_id", "relay_inventory_asset_id",
    }
    if not isinstance(value, Mapping) or set(value) != required:
        _fail("PRODUCT_EVIDENCE")
    if (
        value["repository"] != PRODUCT_REPOSITORY
        or value["tag"] != "v0.8.0"
        or value["release_id"] != 437909062
        or value["commit"] != PRODUCT_COMMIT
        or value["tree"] != PRODUCT_TREE
        or value["relay_release_id"] != RELAY_RELEASE_ID
        or value["relay_tag"] != RELAY_TAG
        or value["relay_archive_asset_id"] != RELAY_ARCHIVE_ASSET_ID
        or value["relay_inventory_asset_id"] != RELAY_INVENTORY_ASSET_ID
    ):
        _fail("PRODUCT_EVIDENCE")
    return dict(value)


def validate_tracked080_manifest(value: Mapping[str, Any]) -> dict[str, Any]:
    """Validate the closed held manifest without accepting a source identity."""
    required = {"schema", "status", "source", "tracked_inputs", "product_evidence", "limits"}
    if not isinstance(value, Mapping) or set(value) != required or value.get("schema") != SCHEMA:
        _fail("MANIFEST")
    if value.get("status") != "held; source-identity-late-bound":
        _fail("MANIFEST_STATUS")
    source = _source(value["source"])
    tracked = value["tracked_inputs"]
    if not isinstance(tracked, Mapping) or set(tracked) != {"bootstrap", "expectations", "command_contracts", "verifier_closure"}:
        _fail("TRACKED_INPUTS")
    for key, expected in TRACKED_INPUTS.items():
        _file_row(tracked[key], expected)
    closure = tracked["verifier_closure"]
    if not isinstance(closure, Mapping) or set(closure) != {"candidate_file_count", "harness_path", "harness_bytes", "harness_sha256"}:
        _fail("CLOSURE")
    if (
        closure["candidate_file_count"] != 15
        or closure["harness_path"] != "tests/fixtures/current080-native-rc-smoke.mjs.txt"
        or closure["harness_bytes"] != 65040
        or not _hex(closure["harness_sha256"], 64)
    ):
        _fail("CLOSURE")
    _path(closure["harness_path"])
    product = _product_evidence(value["product_evidence"])
    limits = value["limits"]
    if not isinstance(limits, Mapping) or set(limits) != {"full_route", "native_execution", "hosted_qualification", "publication"}:
        _fail("LIMITS")
    if (
        limits["full_route"] != "held-until-clean-r-checkout"
        or limits["native_execution"] is not False
        or limits["hosted_qualification"] is not False
        or limits["publication"] is not False
    ):
        _fail("LIMITS")
    result = {
        "schema": SCHEMA,
        "status": value["status"],
        "source": source,
        "tracked_inputs": {key: dict(tracked[key]) for key in ("bootstrap", "expectations", "command_contracts", "verifier_closure")},
        "product_evidence": product,
        "limits": dict(limits),
    }
    return json.loads(canonical(result))


def validate_release_binding(value: Mapping[str, Any], manifest: Mapping[str, Any]) -> dict[str, Any]:
    """Validate release-binding bytes against the held tracked manifest."""
    checked_manifest = validate_tracked080_manifest(manifest)
    required = {
        "schema", "status", "release", "repository", "candidate", "source_identity",
        "bootstrap", "expectations", "command_contracts", "product_evidence", "native_relay",
    }
    if not isinstance(value, Mapping) or set(value) != required or value.get("schema") != BINDING_SCHEMA:
        _fail("BINDING")
    if (
        value.get("status") != "held; source-identity-late-bound"
        or value.get("release") != "0.8.0"
        or value.get("repository") != RS9_REPOSITORY
        or value.get("candidate") != TRACKED_CANDIDATE
    ):
        _fail("BINDING")
    identity = value.get("source_identity")
    if not isinstance(identity, Mapping) or set(identity) != {"repository", "status", "commit", "tree"}:
        _fail("BINDING_SOURCE")
    if identity != {
        "repository": RS9_REPOSITORY,
        "status": "late-bound-clean-checkout",
        "commit": None,
        "tree": None,
    }:
        _fail("BINDING_SOURCE")
    tracked = checked_manifest["tracked_inputs"]
    for key in ("bootstrap", "expectations", "command_contracts"):
        if value.get(key) != tracked[key]:
            _fail("BINDING_INPUT")
    if value.get("product_evidence") != checked_manifest["product_evidence"]:
        _fail("BINDING_PRODUCT")
    relay = value.get("native_relay")
    expected_relay = {
        "release_id": RELAY_RELEASE_ID,
        "tag": RELAY_TAG,
        "archive_asset_id": RELAY_ARCHIVE_ASSET_ID,
        "inventory_asset_id": RELAY_INVENTORY_ASSET_ID,
    }
    if relay != expected_relay:
        _fail("BINDING_RELAY")
    return json.loads(canonical(value))


def validate_runtime_source_identity(value: Mapping[str, Any]) -> dict[str, str]:
    """Normalize one clean-checkout identity supplied by the source owner.

    The tracked contract intentionally leaves this identity out of checked-in
    JSON.  A runtime value must therefore be freshly obtained from the clean
    checkout owner and must remain distinct from the product release.
    """
    if not isinstance(value, Mapping) or not isinstance(value.get("repository"), str):
        _fail("RUNTIME_SOURCE")
    has_short = "commit" in value or "tree" in value
    has_owner = "source_commit" in value or "source_tree" in value
    if has_short and has_owner:
        _fail("RUNTIME_SOURCE")
    if has_owner:
        commit, tree = value.get("source_commit"), value.get("source_tree")
    else:
        commit, tree = value.get("commit"), value.get("tree")
    if (
        value.get("repository") != RS9_REPOSITORY
        or not _hex(commit, 40)
        or not _hex(tree, 40)
        or commit == PRODUCT_COMMIT
        or tree == PRODUCT_TREE
    ):
        _fail("RUNTIME_SOURCE")
    return {"repository": RS9_REPOSITORY, "commit": commit, "tree": tree}


def bind_runtime_source_identity(
    manifest: Mapping[str, Any],
    binding: Mapping[str, Any],
    identity: Mapping[str, Any],
) -> dict[str, Any]:
    """Return ephemeral runtime views without rewriting held source files."""
    checked_manifest = validate_tracked080_manifest(manifest)
    checked_binding = validate_release_binding(binding, checked_manifest)
    source = validate_runtime_source_identity(identity)
    runtime_manifest = json.loads(canonical(checked_manifest))
    runtime_manifest["status"] = "runtime-bound-clean-checkout"
    runtime_manifest["source"] = {
        **runtime_manifest["source"],
        "identity_status": "bound-clean-checkout",
        "commit": source["commit"],
        "tree": source["tree"],
        "identity_reason": "Bound by the clean checkout source owner for this run.",
    }
    runtime_binding = json.loads(canonical(checked_binding))
    runtime_binding["status"] = "runtime-bound-clean-checkout"
    runtime_binding["source_identity"] = {
        "repository": RS9_REPOSITORY,
        "status": "bound-clean-checkout",
        "commit": source["commit"],
        "tree": source["tree"],
    }
    return {"manifest": runtime_manifest, "binding": runtime_binding, "source": source}


def _read_tracked_file(repository: Path, row: Mapping[str, Any]) -> bytes:
    path = repository / row["path"]
    try:
        validate_ancestry_not_symlink(path)
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except (OSError, TypeError, ValueError):
        _fail("TRACKED_FILE")
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode) or before.st_size != row["bytes"]:
            _fail("TRACKED_FILE")
        data = os.read(fd, before.st_size + 1)
        after = os.fstat(fd)
        if len(data) != before.st_size or before.st_size != after.st_size:
            _fail("TRACKED_FILE")
        if sha256(data) != row["sha256"]:
            _fail("TRACKED_FILE")
        return data
    except OSError:
        _fail("TRACKED_FILE")
    finally:
        os.close(fd)


def validate_tracked_repository_rows(
    repository: str | Path,
    manifest: Mapping[str, Any],
) -> dict[str, dict[str, Any]]:
    """Re-read every fixed tracked row from the clean checkout before I/O."""
    checked = validate_tracked080_manifest(manifest)
    root = Path(repository)
    try:
        validate_ancestry_not_symlink(root)
    except (OSError, TypeError, ValueError):
        _fail("TRACKED_ROOT")
    tracked = checked["tracked_inputs"]
    rows: dict[str, dict[str, Any]] = {}
    for key in ("bootstrap", "expectations", "command_contracts"):
        body = _read_tracked_file(root, tracked[key])
        rows[key] = {"path": tracked[key]["path"], "bytes": len(body), "sha256": sha256(body)}
    closure = tracked["verifier_closure"]
    body = _read_tracked_file(root, {
        "path": closure["harness_path"],
        "bytes": closure["harness_bytes"],
        "sha256": closure["harness_sha256"],
    })
    rows["verifier_closure"] = {
        "path": closure["harness_path"], "bytes": len(body), "sha256": sha256(body),
    }
    return rows


def load_json(path: str | Path) -> dict[str, Any]:
    """Load one local contract without accepting a JSON envelope or extras."""
    def pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, item in items:
            if key in result:
                _fail("JSON_DUPLICATE")
            result[key] = item
        return result

    try:
        value = json.loads(Path(path).read_bytes(), object_pairs_hook=pairs)
    except (OSError, ValueError, UnicodeError, TypeError):
        _fail("JSON")
    if not isinstance(value, dict):
        _fail("JSON")
    return value


__all__ = [
    "bind_runtime_source_identity", "canonical", "load_json", "sha256",
    "validate_release_binding", "validate_runtime_source_identity",
    "validate_tracked080_manifest", "validate_tracked_repository_rows",
]
