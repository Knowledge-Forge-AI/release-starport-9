"""Candidate-only Nebular successor integration.

This adapter consumes an already captured release directory.  It authenticates
the current tagged release, requires the reviewed equal-tree forward proof, and
builds exactly three non-admitted wheel candidates through the successor
builder.  It has no publication or manylinux operation.
"""
from __future__ import annotations

import argparse
import csv
import io
import json
import os
import re
import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from rs9.bootstrap import (
    checked_bootstrap_configurations,
    load_bootstrap,
    require_configuration_authority,
)
from rs9.errors import ContractError
from rs9.hosted_platforms import (
    platform_contract,
    select_payload,
    system_from_target_triple,
)
from rs9.nebular_lineage import (
    select_forward_lineage_proof,
    verify_direct_release_lineage,
    verify_forward_lineage_proof,
)
from rs9.operator import (
    BOOTSTRAP,
    EXPECTATIONS,
    assert_release_expectations,
    validate_release_binding,
)
from rs9.profiles import evaluate_profile, selection_for_intent
from rs9.records import record_sha256
from rs9.release_core import (
    ReleaseCapture,
    authenticate_release,
    authenticated_record_hash,
    digest,
    read_evidence,
)
from rs9.scratch import canonical, physical_directory
from rs9.security import validate_safe_relative_posix_path
from rs9.wheel import WheelBuildResult, _record_digest
from rs9.wheel_native import (
    _extract_plist_from_payload_tar,
    get_embedded_rs9_helpers,
    resolve_native_darwin_tag,
    resolve_native_linux_candidate_tag,
    validate_darwin_payload_floor,
)
from rs9.wheel_nebular_successor import (
    DISTRIBUTION_NAME,
    DISTRIBUTION_VERSION,
    LEGAL_FILES,
    LICENSE_EXPRESSION,
    PACKAGE_NAME,
    PRODUCT_ID,
    SUCCESSOR_PROVENANCE_SCHEMA,
    SUCCESSOR_RELEASES,
    SuccessorRelease,
    _profile_license_facts,
    _release_description_path,
    _render_successor_launcher,
    _successor_entry_points_bytes,
    _successor_init_bytes,
    _successor_metadata_bytes,
    _successor_wheel_info_bytes,
    GATE1_PROFILE,
    SuccessorCandidateProfile,
    build_successor_wheel,
    build_gate1_successor_wheel,
    gate1_profile_record,
    successor_release,
)

_HEX40 = re.compile(r"[0-9a-f]{40}\Z")
_RECEIPT_SCHEMA = "rs9.nebular-successor-candidate.v1alpha1"
_SYSTEMS = ("aarch64-darwin", "aarch64-linux", "x86_64-linux")
_PROVENANCE_KEYS = {
    "schema", "product_id", "distribution_name", "application_version", "distribution_version",
    "source_identity", "forward_lineage", "rs9_source", "release_record_sha256", "wheel_tag",
    "target_system", "target_triple", "payload_archive_name", "payload_archive_sha256",
    "manifest_sha256", "selected_asset_id", "profile_result_sha256", "license_facts",
    "launcher_path", "gui_path", "license_expression", "legal_files", "readme_path",
    "readme_sha256", "readme_authority", "launcher_sha256", "metadata_sha256",
    "helper_source_sha256", "legacy_candidate", "fixture_only", "candidate_only",
    "candidate_status", "promotability", "manylinux_proven", "source_closure", "policy",
    "builder_can_publish", "can_publish", "publication_admitted",
}
_GATE1_PROVENANCE_KEYS = _PROVENANCE_KEYS | {
    "candidate_profile", "source_legal_profile", "linux_runtime_policy", "darwin_floor_evidence",
}


def _error(code: str, message: str) -> ContractError:
    return ContractError(code, message)


@dataclass(frozen=True)
class AuthenticatedSuccessorInputs:
    """Capture-bound inputs accepted by the candidate builder."""

    repository: Path
    evidence: Path
    capture: ReleaseCapture
    intent: dict[str, Any]
    profile: dict[str, Any]
    lineage_proof: Any
    lineage_facts: dict[str, Any]
    bootstrap_sha256: str
    release: SuccessorRelease = SUCCESSOR_RELEASES[DISTRIBUTION_VERSION]
    release_binding: dict[str, Any] | None = None


def _read_json(raw: bytes) -> dict[str, Any]:
    try:
        value = json.loads(raw)
    except (ValueError, UnicodeError) as exc:
        raise _error("INVALID_EVIDENCE", "Bounded candidate JSON is unavailable or malformed") from exc
    if not isinstance(value, dict):
        raise _error("INVALID_EVIDENCE", "Bounded candidate JSON object required")
    return value


def _expected_project(expectations: dict[str, Any], repository: str) -> dict[str, Any]:
    projects = expectations.get("projects")
    if not isinstance(projects, list):
        raise _error("LIVE1_RELEASE_MISMATCH", "Release expectations require a project list")
    matches = [row for row in projects if isinstance(row, dict) and row.get("repository") == repository]
    if len(matches) != 1:
        raise _error("LIVE1_RELEASE_MISMATCH", "Exactly one current Nebular release expectation is required")
    return matches[0]


def authenticate_successor_capture(
    repository: str | Path,
    evidence: str | Path,
    *,
    approved_bootstrap_sha256: str,
    release: str = DISTRIBUTION_VERSION,
) -> AuthenticatedSuccessorInputs:
    """Authenticate one captured current release and issue its forward proof.

    The evidence directory is read locally; this function never downloads from
    GitHub or npm.  A caller must supply the exact reviewed bootstrap digest so
    the candidate path cannot self-authorize a changed configuration.
    """
    selected_release = successor_release(release)
    root = physical_directory(repository)
    evidence_root = physical_directory(evidence)
    manifest_path = root / BOOTSTRAP
    try:
        manifest_raw = manifest_path.read_bytes()
    except OSError as exc:
        raise _error("BOOTSTRAP_MANIFEST", "Reviewed bootstrap manifest is unavailable") from exc
    bootstrap_sha256 = digest(manifest_raw)
    if not isinstance(approved_bootstrap_sha256, str) or not re.fullmatch(r"[0-9a-f]{64}", approved_bootstrap_sha256):
        raise _error("BOOTSTRAP_APPROVAL", "Exact reviewed bootstrap digest is required")
    if bootstrap_sha256 != approved_bootstrap_sha256:
        raise _error("BOOTSTRAP_APPROVAL", "Bootstrap bytes differ from the reviewed digest")
    configurations = checked_bootstrap_configurations(
        manifest_path, approved_manifests=[approved_bootstrap_sha256]
    )
    selected = [
        (row, intent)
        for row, intent in configurations
        if intent.get("project", {}).get("id") == PRODUCT_ID
    ]
    if len(selected) != 1:
        raise _error("BOOTSTRAP_BINDING", "Exactly one Nebular successor configuration is required")
    _row, intent = selected[0]
    selection = selection_for_intent(intent)
    capture = authenticate_release(selection, evidence_root)
    if capture.record.get("release", {}).get("tag") != "v" + selected_release.application_version:
        raise _error("TAG_MISMATCH", "Authenticated capture is for a different upstream version")
    expectations = _read_json(read_evidence(root, EXPECTATIONS, limit=512 * 1024))
    assert_release_expectations(capture, _expected_project(expectations, selection["repository"]))
    intent = load_bootstrap(
        manifest_path, capture, approved_manifests=[approved_bootstrap_sha256]
    )
    require_configuration_authority(capture, intent)
    proof = select_forward_lineage_proof(root, capture, intent)
    if proof is None:
        raise _error("LINEAGE_REQUIRED", "Current Nebular candidates require the reviewed forward lineage proof")
    lineage_facts = verify_forward_lineage_proof(capture, proof, intent=intent)
    profile_name = intent["release"]["evidence"]["profile"]
    profile = evaluate_profile(
        capture,
        profile_name,
        intent,
        lineage_correction=proof,
    )
    return AuthenticatedSuccessorInputs(
        repository=root,
        evidence=evidence_root,
        capture=capture,
        intent=intent,
        profile=profile,
        lineage_proof=proof,
        lineage_facts=lineage_facts,
        bootstrap_sha256=bootstrap_sha256,
        release=selected_release,
    )


def authenticate_gate1_capture(
    repository: str | Path,
    evidence: str | Path,
    *,
    release_binding: dict[str, Any],
    approved_bootstrap_sha256: str,
) -> AuthenticatedSuccessorInputs:
    """Authenticate a ready 0.7.0 capture using direct tag/provenance identity.

    The binding is caller-owned release evidence.  A pending profile or a
    historical v0.6.1 binding fails before any candidate output is created.
    """
    binding = validate_release_binding(release_binding)
    if binding["status"] != "ready":
        raise _error("RELEASE_INPUTS_PENDING", "Actual v0.7 release capture and reviewed expectations are not ready")
    expected = binding["expected"]
    if approved_bootstrap_sha256 != expected["bootstrap_sha256"]:
        raise _error("BOOTSTRAP_APPROVAL", "Approved bootstrap digest differs from the ready release binding")
    root = physical_directory(repository)
    evidence_root = physical_directory(evidence)
    manifest_path = root / binding["bootstrap_path"]
    configurations = checked_bootstrap_configurations(
        manifest_path,
        approved_manifests=[expected["bootstrap_sha256"]],
    )
    selected = [
        (row, intent)
        for row, intent in configurations
        if intent.get("project", {}).get("repository") == binding["repository"]
        and intent.get("tag") == binding["tag"]
        and intent.get("version") == binding["application_version"]
    ]
    if len(selected) != 1:
        raise _error("BOOTSTRAP_BINDING", "Exactly one ready v0.7 Nebular configuration is required")
    _row, intent = selected[0]
    selection = selection_for_intent(intent)
    capture = authenticate_release(selection, evidence_root)
    if capture.record.get("release", {}).get("tag") != binding["tag"]:
        raise _error("TAG_MISMATCH", "Authenticated capture is for a different upstream tag")
    expectations_raw = read_evidence(root, binding["expectations_path"], limit=512 * 1024)
    if digest(expectations_raw) != expected["expectations_sha256"]:
        raise _error("EXPECTATIONS_APPROVAL", "Expectations bytes differ from the ready release binding")
    expectations = _read_json(expectations_raw)
    assert_release_expectations(capture, _expected_project(expectations, binding["repository"]))
    intent = load_bootstrap(
        manifest_path,
        capture,
        approved_manifests=[expected["bootstrap_sha256"]],
    )
    require_configuration_authority(capture, intent)
    lineage_facts = verify_direct_release_lineage(capture, binding)
    profile_name = intent["release"]["evidence"]["profile"]
    profile = evaluate_profile(capture, profile_name, intent)
    return AuthenticatedSuccessorInputs(
        repository=root,
        evidence=evidence_root,
        capture=capture,
        intent=intent,
        profile=profile,
        lineage_proof=None,
        lineage_facts=lineage_facts,
        bootstrap_sha256=expected["bootstrap_sha256"],
        release=SUCCESSOR_RELEASES["0.7.0"],
        release_binding=binding,
    )


def _candidate_row(system: str, target_triple: str, result: WheelBuildResult) -> dict[str, Any]:
    record = result.record
    return {
        "system": system,
        "target_triple": target_triple,
        "wheel": {
            "filename": result.filename,
            "sha256": result.sha256,
            "size": result.size,
            "tag": result.tag,
            "version": result.version,
        },
        "selected_asset_id": record.get("selected_asset_id"),
        "payload_archive_name": record.get("payload_archive_name"),
        "payload_archive_sha256": record.get("payload_archive_sha256"),
        "manifest_sha256": record.get("manifest_sha256"),
        "source_identity": {
            **(record.get("source_identity") or {}),
            "release_record_sha256": record.get("release_record_sha256"),
        },
        "forward_lineage": record.get("forward_lineage"),
        "rs9_source": record.get("rs9_source"),
        "candidate_only": record.get("candidate_only"),
        "launcher_path": record.get("launcher_path"),
        "gui_path": record.get("gui_path"),
        "profile_result_sha256": record.get("profile_result_sha256"),
        "readme": {
            "path": record.get("readme_path"),
            "sha256": record.get("readme_sha256"),
        },
        "legal_files": record.get("legal_files"),
        "publication": {
            "builder_can_publish": record.get("builder_can_publish"),
            "can_publish": result.can_publish,
            "publication_admitted": record.get("publication_admitted"),
            "manylinux_proven": record.get("manylinux_proven"),
        },
    }


def _receipt(
    authenticated: AuthenticatedSuccessorInputs,
    rows: list[dict[str, Any]],
    *,
    rs9_source: dict[str, Any],
) -> dict[str, Any]:
    first = rows[0]
    capture_record = authenticated.capture.record
    release = authenticated.release
    return {
        "schema": _RECEIPT_SCHEMA,
        "application_version": release.application_version,
        "distribution_version": release.distribution_version,
        "repository": capture_record["repository"],
        "release": capture_record["release"],
        "source_identity": {
            "repository": capture_record["repository"]["full_name"],
            "tag": capture_record["release"]["tag"],
            "commit": capture_record["tag"]["commit"],
            "tree": capture_record["tag"]["tree"],
            "release_record_sha256": authenticated.profile["release_record_sha256"],
        },
        "bootstrap_sha256": authenticated.bootstrap_sha256,
        "forward_lineage": authenticated.lineage_facts,
        "rs9_source": rs9_source,
        "readme": first["readme"],
        "legal_files": first["legal_files"],
        "license": {"expression": LICENSE_EXPRESSION, "files": first["legal_files"]},
        "rows": rows,
        "flags": {
            "candidate_only": True,
            "builder_can_publish": False,
            "can_publish": False,
            "publication_admitted": False,
            "manylinux_proven": False,
        },
        "source_closure": {"status": "pending", "receipt_sha256": None, "admitted": False},
        "policy": {"status": "pending", "receipt_sha256": None, "manylinux_proven": False},
        "profile_result_sha256": record_sha256(authenticated.profile),
        "asset_facts": {
            "systems": [row["system"] for row in rows],
            "selected_asset_ids": [row["selected_asset_id"] for row in rows],
        },
    }


def _expected_source_identity(authenticated: AuthenticatedSuccessorInputs) -> dict[str, Any]:
    source = authenticated.capture.record
    return {
        "repository": source["repository"]["full_name"],
        "tag": source["release"]["tag"],
        "commit": source["tag"]["commit"],
        "tree": source["tag"]["tree"],
        "release_record_sha256": authenticated.profile["release_record_sha256"],
    }


def _expected_provenance_source(authenticated: AuthenticatedSuccessorInputs) -> dict[str, Any]:
    identity = _expected_source_identity(authenticated)
    return {key: identity[key] for key in ("repository", "tag", "commit", "tree")}


def _expected_legal_files(authenticated: AuthenticatedSuccessorInputs) -> dict[str, dict[str, Any]]:
    source = authenticated.capture.source
    expected: dict[str, dict[str, Any]] = {}
    for name in LEGAL_FILES:
        data = source.get(name)
        if not isinstance(data, bytes) or not data:
            raise _error("RECEIPT_BINDING", "Authenticated legal source bytes are unavailable")
        expected[name] = {"path": name, "size": len(data), "sha256": digest(data)}
    return expected


def _expected_gate1_legal_files(
    authenticated: AuthenticatedSuccessorInputs,
    profile: SuccessorCandidateProfile = GATE1_PROFILE,
) -> dict[str, dict[str, Any]]:
    """Bind required legal bytes and only an actually present optional companion."""
    expected: dict[str, dict[str, Any]] = {}
    for name in (*profile.required_legal_files, *profile.optional_legal_files):
        data = authenticated.capture.source.get(name)
        if data is None:
            if name in profile.required_legal_files:
                raise _error("RECEIPT_BINDING", "Authenticated required Gate1 legal source bytes are unavailable")
            continue
        if not isinstance(data, bytes) or not data:
            raise _error("RECEIPT_BINDING", "Authenticated Gate1 legal source bytes are malformed")
        expected[name] = {"path": name, "size": len(data), "sha256": digest(data)}
    observed = set(expected)
    required = set(profile.required_legal_files)
    if not required <= observed or not observed <= required | set(profile.optional_legal_files):
        raise _error("RECEIPT_BINDING", "Gate1 legal source set is outside its required/optional contract")
    return expected


def _command_path(value: Any) -> str | None:
    if isinstance(value, dict):
        value = value.get("path")
    return value if isinstance(value, str) else None


def _expected_asset(authenticated: AuthenticatedSuccessorInputs, system: str) -> dict[str, Any]:
    try:
        selected = select_payload(authenticated.capture, system, allow_any=False)
        manifest = authenticated.capture.manifests[selected["id"]]
    except (ContractError, KeyError, TypeError) as exc:
        raise _error("RECEIPT_BINDING", "Authenticated target asset is unavailable") from exc
    manifest_sha = manifest.get("manifest_sha256") if isinstance(manifest, dict) else None
    if (not isinstance(manifest_sha, str) or not re.fullmatch(r"[0-9a-f]{64}", manifest_sha)
            or manifest_sha != selected.get("payload_manifest_sha256")):
        raise _error("RECEIPT_BINDING", "Authenticated target manifest digest is unavailable")
    archive_path = authenticated.capture.archives.get(selected.get("id"))
    if archive_path is None:
        raise _error("RECEIPT_BINDING", "Authenticated target archive is unavailable")
    try:
        payload_bytes = archive_path.read_bytes()
    except OSError as exc:
        raise _error("RECEIPT_BINDING", "Authenticated target archive is unavailable") from exc
    if (len(payload_bytes) != selected.get("size") or digest(payload_bytes) != selected.get("sha256")
            or not isinstance(selected.get("name"), str)):
        raise _error("RECEIPT_BINDING", "Authenticated target archive changed")
    if not isinstance(manifest, dict):
        raise _error("RECEIPT_BINDING", "Authenticated target manifest is unavailable")
    launchers = selected.get("launchers", {})
    commands = selected.get("commands", {})
    return {
        "id": selected.get("id"),
        "name": selected.get("name"),
        "sha256": selected.get("sha256"),
        "manifest_sha256": manifest_sha,
        "payload_bytes": payload_bytes,
        "manifest": manifest,
        "manifest_bytes": canonical(manifest),
        "launcher_path": _command_path(launchers.get("tfnf") if isinstance(launchers, dict) else None),
        "gui_path": _command_path(commands.get("tfnf") if isinstance(commands, dict) else None),
    }


def _expected_candidate_rs9_source(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != {"status", "binding", "commit", "tree", "verified"}:
        raise _error("RECEIPT_BINDING", "Explicit candidate source coordinates are required")
    if value.get("status") != "candidate-input" or value.get("binding") != "explicit-reviewed-source-input":
        raise _error("RECEIPT_BINDING", "Candidate source coordinates are not in the pending state")
    if (not isinstance(value.get("commit"), str) or not _HEX40.fullmatch(value["commit"])
            or not isinstance(value.get("tree"), str) or not _HEX40.fullmatch(value["tree"])
            or value.get("verified") is not False):
        raise _error("RECEIPT_BINDING", "Candidate source coordinates are malformed")
    return value


def _expected_wheel_tag(system: str, target_triple: str, asset: dict[str, Any]) -> str:
    try:
        if system.endswith("-linux"):
            return resolve_native_linux_candidate_tag(target_triple, None)
        if system != "aarch64-darwin":
            raise _error("RECEIPT_TARGET", "Candidate target system is unsupported")
        return resolve_native_darwin_tag(_extract_plist_from_payload_tar(asset["payload_bytes"]), None)
    except (ContractError, KeyError, TypeError, ValueError) as exc:
        raise _error("RECEIPT_BINDING", "Authenticated target wheel tag is unavailable") from exc


def _read_wheel_snapshot(wheel_path: Path) -> tuple[bytes, dict[str, bytes], str]:
    """Read and validate one immutable in-memory wheel snapshot."""
    try:
        raw = wheel_path.read_bytes()
        with zipfile.ZipFile(io.BytesIO(raw), "r") as archive:
            names = archive.namelist()
            if len(names) != len(set(names)):
                raise _error("RECEIPT_ARTIFACT", "Candidate wheel contains duplicate members")
            entries = {name: archive.read(name) for name in names}
    except (OSError, zipfile.BadZipFile, KeyError) as exc:
        raise _error("RECEIPT_ARTIFACT", "Candidate wheel contents are unavailable") from exc
    dist_infos = sorted(name.split("/", 1)[0] for name in entries if name.endswith(".dist-info/METADATA"))
    if len(dist_infos) != 1:
        raise _error("RECEIPT_ARTIFACT", "Candidate wheel distribution metadata is ambiguous")
    dist_info = dist_infos[0]
    record_member = f"{dist_info}/RECORD"
    if record_member not in entries:
        raise _error("RECEIPT_ARTIFACT", "Candidate wheel RECORD is unavailable")
    try:
        rows = list(csv.reader(entries[record_member].decode("utf-8").splitlines()))
    except (UnicodeDecodeError, csv.Error) as exc:
        raise _error("RECEIPT_ARTIFACT", "Candidate wheel RECORD is malformed") from exc
    record_map: dict[str, tuple[str, int]] = {}
    for record_row in rows:
        if not record_row:
            continue
        if len(record_row) != 3 or record_row[0] in record_map:
            raise _error("RECEIPT_ARTIFACT", "Candidate wheel RECORD is malformed")
        name, encoded_digest, size_text = record_row
        if name == record_member:
            if encoded_digest or size_text:
                raise _error("RECEIPT_ARTIFACT", "Candidate wheel RECORD self-entry is malformed")
            record_map[name] = ("", 0)
            continue
        try:
            size = int(size_text)
        except ValueError as exc:
            raise _error("RECEIPT_ARTIFACT", "Candidate wheel RECORD size is malformed") from exc
        record_map[name] = (encoded_digest, size)
    if record_map.get(record_member) != ("", 0):
        raise _error("RECEIPT_ARTIFACT", "Candidate wheel RECORD self-entry is missing")
    for name, data in entries.items():
        if name == record_member:
            continue
        expected = record_map.get(name)
        if expected is None or expected[1] != len(data) or expected[0] != _record_digest(data):
            raise _error("RECEIPT_ARTIFACT", "Candidate wheel RECORD does not match its members")
    if set(record_map) != set(entries):
        raise _error("RECEIPT_ARTIFACT", "Candidate wheel RECORD has an unbound member")
    return raw, entries, dist_info


def _validate_wheel_artifact(
    row: dict[str, Any],
    authenticated: AuthenticatedSuccessorInputs,
    output_root: Path,
    expected_identity: dict[str, Any],
    expected_legal: dict[str, dict[str, Any]],
    expected_readme: dict[str, Any],
    expected_rs9_source: dict[str, Any],
    candidate_profile: SuccessorCandidateProfile | None = None,
) -> None:
    release = authenticated.release
    system = row["system"]
    wheel = row.get("wheel")
    if not isinstance(wheel, dict):
        raise _error("RECEIPT_ARTIFACT", "Candidate wheel identity is incomplete")
    filename = wheel.get("filename")
    if (not isinstance(filename, str) or not filename or Path(filename).name != filename
            or "/" in filename or "\\" in filename or not filename.endswith(".whl")):
        raise _error("RECEIPT_ARTIFACT", "Candidate wheel filename is unsafe")
    system_dir = output_root / system
    wheel_path = system_dir / filename
    if system_dir.is_symlink() or not system_dir.is_dir() or wheel_path.is_symlink() or not wheel_path.is_file():
        raise _error("RECEIPT_ARTIFACT", "Candidate wheel file is unavailable")
    try:
        wheel_path.relative_to(output_root)
        raw, entries, dist_info = _read_wheel_snapshot(wheel_path)
    except (OSError, ContractError, ValueError) as exc:
        raise _error("RECEIPT_ARTIFACT", "Candidate wheel RECORD validation failed") from exc
    if digest(raw) != wheel.get("sha256") or len(raw) != wheel.get("size"):
        raise _error("RECEIPT_ARTIFACT", "Candidate wheel bytes disagree with the receipt")
    if (not isinstance(wheel.get("sha256"), str) or not re.fullmatch(r"[0-9a-f]{64}", wheel["sha256"])
            or type(wheel.get("size")) is not int or wheel["size"] <= 0
            or wheel.get("version") != release.distribution_version or not isinstance(wheel.get("tag"), str)):
        raise _error("RECEIPT_ARTIFACT", "Candidate wheel identity is malformed")
    expected_dist_info = f"{DISTRIBUTION_NAME.replace('-', '_')}-{release.distribution_version}.dist-info"
    provenance_member = f"{PACKAGE_NAME}/_rs9/provenance.json"
    metadata_member = f"{expected_dist_info}/METADATA"
    expected_asset = _expected_asset(authenticated, system)
    expected_tag = _expected_wheel_tag(system, row["target_triple"], expected_asset)
    if wheel.get("tag") != expected_tag:
        raise _error("RECEIPT_TARGET", "Candidate wheel tag disagrees with its authenticated target")
    if not isinstance(expected_asset.get("launcher_path"), str) or not isinstance(expected_asset.get("gui_path"), str):
        raise _error("RECEIPT_BINDING", "Authenticated target command paths are unavailable")
    candidate_only = system.endswith("-linux")
    family = "darwin" if system.endswith("-darwin") else "linux"
    arch = "aarch64" if system.startswith(("aarch64", "arm64")) else "x86_64"
    expected_launcher = _render_successor_launcher(
        expected_asset["name"], expected_asset["sha256"], expected_asset["manifest_sha256"],
        expected_asset["launcher_path"], expected_asset["gui_path"], family, arch,
        application_version=release.application_version,
        distribution_version=release.distribution_version,
    )
    expected_helpers = get_embedded_rs9_helpers()
    names = set(entries)
    expected_members = {
        f"{PACKAGE_NAME}/__init__.py",
        f"{PACKAGE_NAME}/launcher.py",
        provenance_member,
        f"{PACKAGE_NAME}/payload/{expected_asset['name']}",
        f"{PACKAGE_NAME}/payload/manifest.json",
        *(f"{PACKAGE_NAME}/_isolated/{name}" for name in expected_helpers),
        metadata_member,
        f"{expected_dist_info}/WHEEL",
        f"{expected_dist_info}/entry_points.txt",
        f"{expected_dist_info}/RECORD",
        *(f"{expected_dist_info}/licenses/{name}" for name in expected_legal),
    }
    if names != expected_members:
        raise _error("RECEIPT_ARTIFACT", "Candidate wheel member set is not closed")
    if dist_info != expected_dist_info:
        raise _error("RECEIPT_ARTIFACT", "Candidate wheel distribution metadata is unexpected")
    try:
        provenance = _read_json(entries[provenance_member])
    except ContractError as exc:
        raise _error("RECEIPT_ARTIFACT", "Candidate wheel provenance is unavailable") from exc
    except KeyError as exc:
        raise _error("RECEIPT_ARTIFACT", "Candidate wheel provenance is unavailable") from exc
    provenance_keys = _GATE1_PROVENANCE_KEYS if candidate_profile is not None else _PROVENANCE_KEYS
    if set(provenance) != provenance_keys:
        raise _error("RECEIPT_ARTIFACT", "Candidate wheel provenance fields are not closed")
    metadata = entries.get(metadata_member)
    if metadata is None:
        raise _error("RECEIPT_ARTIFACT", "Candidate metadata is unavailable")
    expected_row_publication = {
        "builder_can_publish": False,
        "can_publish": False,
        "publication_admitted": False,
        "manylinux_proven": False,
    }
    expected_pending = {"status": "pending", "receipt_sha256": None, "admitted": False}
    expected_policy = {"status": "pending", "receipt_sha256": None, "manylinux_proven": False}
    expected_provenance = {
        "schema": candidate_profile.provenance_schema if candidate_profile else SUCCESSOR_PROVENANCE_SCHEMA,
        "product_id": PRODUCT_ID,
        "distribution_name": DISTRIBUTION_NAME,
        "application_version": release.application_version,
        "distribution_version": release.distribution_version,
        "wheel_tag": expected_tag,
        "source_identity": _expected_provenance_source(authenticated),
        "forward_lineage": authenticated.lineage_facts,
        "rs9_source": expected_rs9_source,
        "release_record_sha256": expected_identity["release_record_sha256"],
        "target_system": system,
        "target_triple": row["target_triple"],
        "payload_archive_name": expected_asset["name"],
        "payload_archive_sha256": expected_asset["sha256"],
        "manifest_sha256": expected_asset["manifest_sha256"],
        "selected_asset_id": expected_asset["id"],
        "profile_result_sha256": record_sha256(authenticated.profile),
        "license_facts": _profile_license_facts(authenticated.profile),
        "launcher_path": expected_asset["launcher_path"],
        "gui_path": expected_asset["gui_path"],
        "license_expression": candidate_profile.license_expression if candidate_profile else LICENSE_EXPRESSION,
        "legal_files": expected_legal,
        "readme_path": expected_readme["path"],
        "readme_sha256": expected_readme["sha256"],
        "launcher_sha256": digest(expected_launcher),
        "helper_source_sha256": {name: digest(data) for name, data in expected_helpers.items()},
        "metadata_sha256": digest(metadata),
        "fixture_only": False,
        "candidate_only": candidate_only,
        "candidate_status": "policy-pending" if candidate_only else "candidate",
        "promotability": "policy-pending" if candidate_only else "candidate",
        "manylinux_proven": False,
        "source_closure": expected_pending,
        "policy": expected_policy,
        **expected_row_publication,
    }
    if candidate_profile is not None:
        profile_record = gate1_profile_record(candidate_profile)
        if system == "aarch64-darwin":
            try:
                expected_floor_evidence = validate_darwin_payload_floor(
                    expected_asset["payload_bytes"],
                    required_floor=candidate_profile.darwin_floor,
                )
            except ContractError as exc:
                raise _error("RECEIPT_ARTIFACT", "Authenticated Darwin payload floor is invalid") from exc
            floor_evidence = provenance.get("darwin_floor_evidence")
            if floor_evidence != expected_floor_evidence:
                raise _error("RECEIPT_ARTIFACT", "Darwin Gate1 floor evidence is not authenticated to payload bytes")
        else:
            floor_evidence = None
        expected_provenance.update({
            "candidate_profile": profile_record,
            "source_legal_profile": {
                "expression": candidate_profile.license_expression,
                "required_files": list(candidate_profile.required_legal_files),
                "optional_files": list(candidate_profile.optional_legal_files),
                "observed_files": sorted(expected_legal),
            },
            "linux_runtime_policy": profile_record["linux_runtime_policy"],
            "darwin_floor_evidence": floor_evidence if system == "aarch64-darwin" else None,
        })
        if row.get("darwin_floor_evidence") != expected_provenance["darwin_floor_evidence"]:
            raise _error("RECEIPT_ARTIFACT", "Candidate row Darwin floor evidence is not wheel-bound")
    for key, expected in expected_provenance.items():
        if provenance.get(key) != expected:
            raise _error("RECEIPT_ARTIFACT", "Candidate wheel provenance is not capture-bound")
    expected_legacy = provenance.get("legacy_candidate")
    if (not isinstance(expected_legacy, dict)
            or set(expected_legacy) != {"version", "filename", "sha256"}
            or expected_legacy.get("version") != release.application_version
            or not isinstance(expected_legacy.get("filename"), str)
            or not isinstance(expected_legacy.get("sha256"), str)
            or not re.fullmatch(r"[0-9a-f]{64}", expected_legacy.get("sha256", ""))):
        raise _error("RECEIPT_ARTIFACT", "Legacy candidate provenance is malformed")
    authority = provenance.get("readme_authority")
    if (not isinstance(authority, dict)
            or set(authority) != {"source", "path", "sha256", "rs9_source", "verified"}
            or authority.get("source") != "rs9-candidate-input"
            or authority.get("path") != expected_readme["path"]
            or authority.get("sha256") != expected_readme["sha256"]
            or authority.get("rs9_source") != expected_rs9_source
            or authority.get("verified") is not False):
        raise _error("RECEIPT_ARTIFACT", "Candidate README authority is not capture-bound")

    expected_payload_members = {
        f"{PACKAGE_NAME}/payload/{expected_asset['name']}",
        f"{PACKAGE_NAME}/payload/manifest.json",
    }
    expected_helper_members = {f"{PACKAGE_NAME}/_isolated/{name}" for name in expected_helpers}
    actual_payload_members = {name for name in names if name.startswith(f"{PACKAGE_NAME}/payload/")}
    actual_helper_members = {name for name in names if name.startswith(f"{PACKAGE_NAME}/_isolated/")}
    if actual_payload_members != expected_payload_members or actual_helper_members != expected_helper_members:
        raise _error("RECEIPT_ARTIFACT", "Candidate wheel payload layout is not the authenticated layout")
    if entries[f"{PACKAGE_NAME}/payload/{expected_asset['name']}"] != expected_asset["payload_bytes"]:
        raise _error("RECEIPT_ARTIFACT", "Candidate payload bytes disagree with authenticated asset")
    if entries[f"{PACKAGE_NAME}/payload/manifest.json"] != expected_asset["manifest_bytes"]:
        raise _error("RECEIPT_ARTIFACT", "Candidate manifest bytes disagree with authenticated asset")
    for name, expected_bytes in expected_helpers.items():
        if entries[f"{PACKAGE_NAME}/_isolated/{name}"] != expected_bytes:
            raise _error("RECEIPT_ARTIFACT", "Candidate isolated helper bytes disagree with source")
    if entries[f"{PACKAGE_NAME}/launcher.py"] != expected_launcher:
        raise _error("RECEIPT_ARTIFACT", "Candidate launcher bytes disagree with bound target")

    if provenance.get("metadata_sha256") != digest(metadata):
        raise _error("RECEIPT_ARTIFACT", "Candidate metadata bytes disagree with provenance")
    marker = b"Description-Content-Type: text/markdown\n\n"
    if marker not in metadata or digest(metadata.split(marker, 1)[1]) != expected_readme["sha256"]:
        raise _error("RECEIPT_ARTIFACT", "Candidate README bytes disagree with the receipt")
    if metadata != _successor_metadata_bytes(
        metadata.split(marker, 1)[1],
        distribution_version=release.distribution_version,
        license_expression=candidate_profile.license_expression if candidate_profile else LICENSE_EXPRESSION,
        legal_files=tuple(expected_legal),
    ):
        raise _error("RECEIPT_ARTIFACT", "Candidate METADATA is not the deterministic successor metadata")
    wheel_info = entries.get(f"{expected_dist_info}/WHEEL")
    if wheel_info is None:
        raise _error("RECEIPT_ARTIFACT", "Candidate wheel metadata is unavailable")
    try:
        tag_line = next((line[5:] for line in wheel_info.decode("utf-8").splitlines() if line.startswith("Tag: ")), None)
    except UnicodeDecodeError as exc:
        raise _error("RECEIPT_ARTIFACT", "Candidate wheel metadata is malformed") from exc
    wheel_tag = wheel["tag"]
    if wheel_info != _successor_wheel_info_bytes(expected_tag):
        raise _error("RECEIPT_ARTIFACT", "Candidate WHEEL is not the deterministic successor metadata")
    expected_filename = f"{DISTRIBUTION_NAME.replace('-', '_')}-{release.distribution_version}-{expected_tag}.whl"
    if filename != expected_filename or tag_line != wheel_tag or not filename.endswith(f"-{wheel_tag}.whl"):
        raise _error("RECEIPT_ARTIFACT", "Candidate wheel tag disagrees with its metadata")
    if entries.get(f"{PACKAGE_NAME}/__init__.py") != _successor_init_bytes(
        application_version=release.application_version,
        distribution_version=release.distribution_version,
    ):
        raise _error("RECEIPT_ARTIFACT", "Candidate package identity is not deterministic")
    if entries.get(f"{expected_dist_info}/entry_points.txt") != _successor_entry_points_bytes():
        raise _error("RECEIPT_ARTIFACT", "Candidate entry points are not deterministic")
    for name in expected_legal:
        member = f"{expected_dist_info}/licenses/{name}"
        if entries.get(member) != authenticated.capture.source[name]:
            raise _error("RECEIPT_ARTIFACT", "Candidate legal bytes disagree with authenticated source")


def validate_candidate_receipt(
    receipt: dict[str, Any],
    authenticated: AuthenticatedSuccessorInputs,
    *,
    output_dir: str | Path,
) -> dict[str, Any]:
    """Validate a persisted receipt against authenticated capture and wheel bytes."""
    if not isinstance(authenticated, AuthenticatedSuccessorInputs):
        raise _error("RECEIPT_AUTHORITY", "Authenticated successor inputs are required")
    release = authenticated.release
    if not isinstance(release, SuccessorRelease) or SUCCESSOR_RELEASES.get(release.distribution_version) != release:
        raise _error("RECEIPT_VERSION", "Authenticated successor release selection is invalid")
    try:
        authenticated_record_hash(authenticated.capture)
    except ContractError as exc:
        raise _error("RECEIPT_AUTHORITY", "Authenticated successor capture changed") from exc
    if not isinstance(output_dir, (str, Path)):
        raise _error("RECEIPT_AUTHORITY", "Candidate output directory is required")
    try:
        output_root = physical_directory(output_dir)
    except (ContractError, OSError) as exc:
        raise _error("RECEIPT_AUTHORITY", "Candidate output directory is unavailable") from exc
    expected_top = {
        "schema", "application_version", "distribution_version", "repository", "release",
        "source_identity", "bootstrap_sha256", "forward_lineage", "rs9_source", "readme",
        "legal_files", "license", "rows", "flags", "source_closure", "policy",
        "profile_result_sha256", "asset_facts",
    }
    if not isinstance(receipt, dict) or receipt.get("schema") != _RECEIPT_SCHEMA:
        raise _error("RECEIPT_SCHEMA", "Versioned Nebular candidate receipt required")
    if set(receipt) != expected_top:
        raise _error("RECEIPT_SCHEMA", "Candidate receipt fields are not closed")
    source_record = authenticated.capture.record
    expected_identity = _expected_source_identity(authenticated)
    expected_legal = _expected_legal_files(authenticated)
    expected_readme = receipt.get("readme")
    expected_rs9_source = _expected_candidate_rs9_source(receipt.get("rs9_source"))
    if receipt.get("repository") != source_record.get("repository") or receipt.get("release") != source_record.get("release"):
        raise _error("RECEIPT_BINDING", "Candidate receipt release identity is cross-wired")
    if receipt.get("source_identity") != expected_identity:
        raise _error("RECEIPT_BINDING", "Successor receipt source identity is cross-wired")
    if receipt.get("bootstrap_sha256") != authenticated.bootstrap_sha256:
        raise _error("RECEIPT_BINDING", "Successor receipt bootstrap identity is cross-wired")
    if receipt.get("forward_lineage") != authenticated.lineage_facts:
        raise _error("RECEIPT_BINDING", "Successor receipt lineage facts are cross-wired")
    if receipt.get("profile_result_sha256") != record_sha256(authenticated.profile):
        raise _error("RECEIPT_BINDING", "Successor receipt profile identity is cross-wired")
    if not isinstance(expected_readme, dict) or set(expected_readme) != {"path", "sha256"}:
        raise _error("RECEIPT_BINDING", "Candidate README identity is incomplete")
    try:
        validate_safe_relative_posix_path(expected_readme["path"])
    except ContractError as exc:
        raise _error("RECEIPT_BINDING", "Candidate README path is not logical") from exc
    if not isinstance(expected_readme.get("sha256"), str) or not re.fullmatch(r"[0-9a-f]{64}", expected_readme["sha256"]):
        raise _error("RECEIPT_BINDING", "Candidate README digest is malformed")
    if receipt.get("legal_files") != expected_legal:
        raise _error("RECEIPT_BINDING", "Candidate legal files are not authenticated source facts")
    if receipt.get("license") != {"expression": LICENSE_EXPRESSION, "files": expected_legal}:
        raise _error("RECEIPT_BINDING", "Candidate license facts are not authenticated")
    if receipt.get("flags") != {
        "candidate_only": True,
        "builder_can_publish": False,
        "can_publish": False,
        "publication_admitted": False,
        "manylinux_proven": False,
    }:
        raise _error("PUBLICATION_HOLD", "Successor receipt admission flags must remain pending")
    if receipt.get("source_closure") != {"status": "pending", "receipt_sha256": None, "admitted": False}:
        raise _error("PUBLICATION_HOLD", "Successor source closure must remain pending")
    if receipt.get("policy") != {"status": "pending", "receipt_sha256": None, "manylinux_proven": False}:
        raise _error("PUBLICATION_HOLD", "Successor policy must remain pending")
    rows = receipt.get("rows")
    if not isinstance(rows, list) or len(rows) != len(_SYSTEMS):
        raise _error("RECEIPT_ROWS", "Exactly three successor candidate rows are required")
    observed = {row.get("system") for row in rows if isinstance(row, dict)}
    if observed != set(_SYSTEMS):
        raise _error("RECEIPT_TARGET", "Candidate receipt target systems are not the reviewed three-system set")
    for row in rows:
        if not isinstance(row, dict):
            raise _error("RECEIPT_ROWS", "Candidate receipt row is malformed")
        system, triple = row.get("system"), row.get("target_triple")
        try:
            expected = platform_contract(system).target_triple
        except ContractError as exc:
            raise _error("RECEIPT_TARGET", "Candidate receipt target system is unsupported") from exc
        if triple != expected or system_from_target_triple(triple) != system:
            raise _error("RECEIPT_TARGET", "Candidate receipt target triple disagrees with its system")
        wheel = row.get("wheel")
        if (not isinstance(wheel, dict) or set(wheel) != {"filename", "sha256", "size", "tag", "version"}
                or not isinstance(wheel.get("filename"), str)):
            raise _error("RECEIPT_ROWS", "Candidate wheel identity is incomplete")
        if set(row) != {
            "system", "target_triple", "wheel", "selected_asset_id", "payload_archive_name",
            "payload_archive_sha256", "manifest_sha256", "source_identity", "forward_lineage",
            "rs9_source", "candidate_only", "launcher_path", "gui_path", "profile_result_sha256",
            "readme", "legal_files", "publication",
        }:
            raise _error("RECEIPT_ROWS", "Candidate receipt row fields are not closed")
        publication = row.get("publication")
        if publication != {key: False for key in (
            "builder_can_publish", "can_publish", "publication_admitted", "manylinux_proven"
        )}:
            raise _error("PUBLICATION_HOLD", "Successor candidate publication flags must remain false")
    if (
        receipt.get("application_version") != release.application_version
        or receipt.get("distribution_version") != release.distribution_version
    ):
        raise _error("RECEIPT_VERSION", "Successor receipt version identity disagrees")
    if source_record.get("release", {}).get("tag") != "v" + release.application_version:
        raise _error("TAG_MISMATCH", "Authenticated capture is for a different upstream version")
    _release_description_path(release, expected_readme["path"])
    expected_assets = {system: _expected_asset(authenticated, system) for system in _SYSTEMS}
    if receipt.get("asset_facts") != {
        "systems": list(_SYSTEMS),
        "selected_asset_ids": [expected_assets[system]["id"] for system in _SYSTEMS],
    }:
        raise _error("RECEIPT_BINDING", "Candidate asset facts are not capture-bound")
    for row in rows:
        system = row["system"]
        asset = expected_assets[system]
        expected_candidate_only = system.endswith("-linux")
        if row.get("selected_asset_id") != asset["id"]:
            raise _error("RECEIPT_BINDING", "Successor receipt asset target is cross-wired")
        if row.get("source_identity") != expected_identity:
            raise _error("RECEIPT_BINDING", "Successor row source identity is cross-wired")
        if row.get("forward_lineage") != authenticated.lineage_facts:
            raise _error("RECEIPT_BINDING", "Successor row lineage facts are cross-wired")
        if row.get("rs9_source") != expected_rs9_source:
            raise _error("RECEIPT_BINDING", "Successor row RS9 source identity is cross-wired")
        if row.get("readme") != expected_readme or row.get("legal_files") != expected_legal:
            raise _error("RECEIPT_BINDING", "Successor row legal or README facts are cross-wired")
        if row.get("candidate_only") is not expected_candidate_only:
            raise _error("RECEIPT_BINDING", "Successor row candidate status is cross-wired")
        if row.get("payload_archive_name") != asset["name"] or row.get("payload_archive_sha256") != asset["sha256"]:
            raise _error("RECEIPT_BINDING", "Successor row payload identity is cross-wired")
        if row.get("manifest_sha256") != asset["manifest_sha256"]:
            raise _error("RECEIPT_BINDING", "Successor row manifest identity is cross-wired")
        if row.get("launcher_path") != asset["launcher_path"] or row.get("gui_path") != asset["gui_path"]:
            raise _error("RECEIPT_BINDING", "Successor row command identity is cross-wired")
        if row.get("profile_result_sha256") != record_sha256(authenticated.profile):
            raise _error("RECEIPT_BINDING", "Successor row profile identity is cross-wired")
        _validate_wheel_artifact(
            row, authenticated, output_root, expected_identity, expected_legal, expected_readme, expected_rs9_source
        )
    return receipt


def _gate1_candidate_row(system: str, target_triple: str, result: WheelBuildResult) -> dict[str, Any]:
    row = _candidate_row(system, target_triple, result)
    record = result.record
    row.pop("rs9_source", None)
    row.update({
        "candidate_rs9_source": record.get("rs9_source"),
        "candidate_profile": record.get("candidate_profile"),
        "source_legal_profile": record.get("source_legal_profile"),
        "linux_runtime_policy": record.get("linux_runtime_policy"),
        "darwin_floor_evidence": record.get("darwin_floor_evidence"),
    })
    return row


def _gate1_receipt(
    authenticated: AuthenticatedSuccessorInputs,
    rows: list[dict[str, Any]],
    *,
    candidate_rs9_source: dict[str, Any],
) -> dict[str, Any]:
    first = rows[0]
    binding = authenticated.release_binding
    if not isinstance(binding, dict) or binding.get("status") != "ready":
        raise _error("RELEASE_INPUTS_PENDING", "Ready v0.7 release binding is required for a candidate receipt")
    profile_record = gate1_profile_record(GATE1_PROFILE)
    return {
        "schema": "rs9.nebular-successor-candidate.v2alpha1",
        "application_version": "0.7.0",
        "distribution_version": "0.7.0",
        "repository": authenticated.capture.record["repository"],
        "release": authenticated.capture.record["release"],
        "release_binding": binding,
        "source_identity": _expected_source_identity(authenticated),
        "candidate_rs9_source": candidate_rs9_source,
        "qualification_rs9_source": {"status": "not-run", "reason": "gate1-only"},
        "bootstrap_sha256": authenticated.bootstrap_sha256,
        "direct_lineage": authenticated.lineage_facts,
        "profile": profile_record,
        "readme": first["readme"],
        "legal_files": first["legal_files"],
        "license": {"expression": GATE1_PROFILE.license_expression, "files": first["legal_files"]},
        "rows": rows,
        "flags": {
            "candidate_only": True,
            "builder_can_publish": False,
            "can_publish": False,
            "publication_admitted": False,
            "manylinux_proven": False,
        },
        "source_closure": {"status": "pending", "receipt_sha256": None, "admitted": False},
        "policy": {"status": "pending", "receipt_sha256": None, "manylinux_proven": False},
        "profile_result_sha256": record_sha256(authenticated.profile),
        "linux_runtime_policy": profile_record["linux_runtime_policy"],
        "darwin_floor_evidence": first.get("darwin_floor_evidence"),
        "asset_facts": {
            "systems": [row["system"] for row in rows],
            "selected_asset_ids": [row["selected_asset_id"] for row in rows],
        },
    }


def validate_gate1_receipt(
    receipt: dict[str, Any],
    authenticated: AuthenticatedSuccessorInputs,
    *,
    output_dir: str | Path,
) -> dict[str, Any]:
    """Validate the new closed 0.7 profile/metadata/floor candidate receipt."""
    if not isinstance(authenticated, AuthenticatedSuccessorInputs) or authenticated.release.distribution_version != "0.7.0":
        raise _error("RECEIPT_AUTHORITY", "Authenticated v0.7 successor inputs are required")
    if not isinstance(authenticated.release_binding, dict) or authenticated.release_binding.get("status") != "ready":
        raise _error("RELEASE_INPUTS_PENDING", "Ready v0.7 release binding is required")
    if authenticated.lineage_facts.get("schema") != "rs9.nebular-direct-lineage.v1alpha1":
        raise _error("RECEIPT_BINDING", "Direct v0.7 lineage facts are required")
    try:
        authenticated_record_hash(authenticated.capture)
        output_root = physical_directory(output_dir)
    except (ContractError, OSError) as exc:
        raise _error("RECEIPT_AUTHORITY", "Authenticated v0.7 capture/output is unavailable") from exc
    expected_top = {
        "schema", "application_version", "distribution_version", "repository", "release",
        "release_binding", "source_identity", "candidate_rs9_source", "qualification_rs9_source",
        "bootstrap_sha256", "direct_lineage", "profile", "readme", "legal_files", "license",
        "rows", "flags", "source_closure", "policy", "profile_result_sha256",
        "linux_runtime_policy", "darwin_floor_evidence", "asset_facts",
    }
    if not isinstance(receipt, dict) or set(receipt) != expected_top:
        raise _error("RECEIPT_SCHEMA", "Gate1 candidate receipt fields are not closed")
    if receipt.get("schema") != "rs9.nebular-successor-candidate.v2alpha1":
        raise _error("RECEIPT_SCHEMA", "Gate1 candidate receipt schema is required")
    if receipt.get("application_version") != "0.7.0" or receipt.get("distribution_version") != "0.7.0":
        raise _error("RECEIPT_VERSION", "Gate1 candidate receipt must select 0.7.0")
    if receipt.get("repository") != authenticated.capture.record.get("repository") \
            or receipt.get("release") != authenticated.capture.record.get("release"):
        raise _error("RECEIPT_BINDING", "Gate1 release identity is cross-wired")
    if receipt.get("release_binding") != authenticated.release_binding:
        raise _error("RECEIPT_BINDING", "Gate1 release binding is cross-wired")
    if receipt.get("source_identity") != _expected_source_identity(authenticated):
        raise _error("RECEIPT_BINDING", "Gate1 source identity is cross-wired")
    expected_rs9_source = _expected_candidate_rs9_source(receipt.get("candidate_rs9_source"))
    if receipt.get("bootstrap_sha256") != authenticated.bootstrap_sha256 \
            or receipt.get("direct_lineage") != authenticated.lineage_facts:
        raise _error("RECEIPT_BINDING", "Gate1 capture or lineage identity is cross-wired")
    if receipt.get("profile") != gate1_profile_record(GATE1_PROFILE):
        raise _error("RECEIPT_BINDING", "Gate1 profile revision is cross-wired")
    if receipt.get("qualification_rs9_source") != {"status": "not-run", "reason": "gate1-only"}:
        raise _error("RECEIPT_BINDING", "Gate1 must not claim a hosted qualification source")
    expected_legal = _expected_gate1_legal_files(authenticated)
    expected_readme = receipt.get("readme")
    if not isinstance(expected_readme, dict) or set(expected_readme) != {"path", "sha256"}:
        raise _error("RECEIPT_BINDING", "Gate1 README identity is incomplete")
    if expected_readme["path"] != GATE1_PROFILE.description_path \
            or not re.fullmatch(r"[0-9a-f]{64}", expected_readme.get("sha256", "")):
        raise _error("RECEIPT_BINDING", "Gate1 README identity is not the corrected profile input")
    if receipt.get("legal_files") != expected_legal:
        raise _error("RECEIPT_BINDING", "Gate1 legal files are not authenticated source facts")
    if receipt.get("license") != {"expression": GATE1_PROFILE.license_expression, "files": expected_legal}:
        raise _error("RECEIPT_BINDING", "Gate1 AGPL-only license facts are not authenticated")
    if receipt.get("flags") != {
        "candidate_only": True,
        "builder_can_publish": False,
        "can_publish": False,
        "publication_admitted": False,
        "manylinux_proven": False,
    }:
        raise _error("PUBLICATION_HOLD", "Gate1 publication flags must remain false")
    if receipt.get("source_closure") != {"status": "pending", "receipt_sha256": None, "admitted": False} \
            or receipt.get("policy") != {"status": "pending", "receipt_sha256": None, "manylinux_proven": False}:
        raise _error("PUBLICATION_HOLD", "Gate1 source/policy closure must remain pending")
    if receipt.get("profile_result_sha256") != record_sha256(authenticated.profile):
        raise _error("RECEIPT_BINDING", "Gate1 profile result identity is cross-wired")
    profile_record = gate1_profile_record(GATE1_PROFILE)
    if receipt.get("linux_runtime_policy") != profile_record["linux_runtime_policy"]:
        raise _error("RECEIPT_BINDING", "Gate1 Linux runtime policy is cross-wired")
    rows = receipt.get("rows")
    if not isinstance(rows, list) or len(rows) != len(_SYSTEMS):
        raise _error("RECEIPT_ROWS", "Exactly three Gate1 candidate rows are required")
    if {row.get("system") for row in rows if isinstance(row, dict)} != set(_SYSTEMS):
        raise _error("RECEIPT_TARGET", "Gate1 target systems are not the reviewed three-system set")
    if receipt.get("asset_facts") != {
        "systems": list(_SYSTEMS),
        "selected_asset_ids": [
            _expected_asset(authenticated, system)["id"] for system in _SYSTEMS
        ],
    }:
        raise _error("RECEIPT_BINDING", "Gate1 asset facts are not capture-bound")
    expected_assets = {system: _expected_asset(authenticated, system) for system in _SYSTEMS}
    expected_floor = next(
        (row.get("darwin_floor_evidence") for row in rows if row.get("system") == "aarch64-darwin"),
        None,
    )
    if receipt.get("darwin_floor_evidence") != expected_floor:
        raise _error("RECEIPT_BINDING", "Gate1 receipt Darwin floor evidence is not row-bound")
    for row in rows:
        if not isinstance(row, dict):
            raise _error("RECEIPT_ROWS", "Gate1 row is malformed")
        system, triple = row.get("system"), row.get("target_triple")
        try:
            expected_triple = platform_contract(system).target_triple
        except ContractError as exc:
            raise _error("RECEIPT_TARGET", "Gate1 row target is unsupported") from exc
        if triple != expected_triple or system_from_target_triple(triple) != system:
            raise _error("RECEIPT_TARGET", "Gate1 row target triple disagrees")
        expected_row_fields = {
            "system", "target_triple", "wheel", "selected_asset_id", "payload_archive_name",
            "payload_archive_sha256", "manifest_sha256", "source_identity", "forward_lineage",
            "candidate_rs9_source", "candidate_only", "launcher_path", "gui_path",
            "profile_result_sha256", "readme", "legal_files", "publication", "candidate_profile",
            "source_legal_profile", "linux_runtime_policy", "darwin_floor_evidence",
        }
        if set(row) != expected_row_fields:
            raise _error("RECEIPT_ROWS", "Gate1 row fields are not closed")
        if set(row["wheel"]) != {"filename", "sha256", "size", "tag", "version"}:
            raise _error("RECEIPT_ROWS", "Gate1 wheel identity fields are not closed")
        if row.get("candidate_rs9_source") != expected_rs9_source \
                or row.get("candidate_profile") != profile_record \
                or row.get("source_legal_profile") != {
                    "expression": GATE1_PROFILE.license_expression,
                    "required_files": list(GATE1_PROFILE.required_legal_files),
                    "optional_files": list(GATE1_PROFILE.optional_legal_files),
                    "observed_files": sorted(expected_legal),
                }:
            raise _error("RECEIPT_BINDING", "Gate1 row profile/source identity is cross-wired")
        if row.get("linux_runtime_policy") != profile_record["linux_runtime_policy"]:
            raise _error("RECEIPT_BINDING", "Gate1 row Linux policy is cross-wired")
        if row.get("source_identity") != _expected_source_identity(authenticated):
            raise _error("RECEIPT_BINDING", "Gate1 row source identity is cross-wired")
        if row.get("forward_lineage") != authenticated.lineage_facts:
            raise _error("RECEIPT_BINDING", "Gate1 row lineage facts are cross-wired")
        if row.get("candidate_only") is not system.endswith("-linux"):
            raise _error("RECEIPT_BINDING", "Gate1 row candidate status is cross-wired")
        asset = expected_assets[system]
        if row.get("selected_asset_id") != asset["id"] or row.get("payload_archive_name") != asset["name"] \
                or row.get("payload_archive_sha256") != asset["sha256"] \
                or row.get("manifest_sha256") != asset["manifest_sha256"]:
            raise _error("RECEIPT_BINDING", "Gate1 row payload identity is cross-wired")
        if (row.get("launcher_path") != asset["launcher_path"]
                or row.get("gui_path") != asset["gui_path"]
                or row.get("profile_result_sha256") != record_sha256(authenticated.profile)
                or row.get("readme") != expected_readme
                or row.get("legal_files") != expected_legal
                or row.get("publication") != {
                    "builder_can_publish": False,
                    "can_publish": False,
                    "publication_admitted": False,
                    "manylinux_proven": False,
                }):
            raise _error("RECEIPT_BINDING", "Gate1 row release or publication facts are cross-wired")
        _validate_wheel_artifact(
            row,
            authenticated,
            output_root,
            _expected_source_identity(authenticated),
            expected_legal,
            expected_readme,
            expected_rs9_source,
            candidate_profile=GATE1_PROFILE,
        )
    return receipt


def build_gate1_candidates(
    authenticated: AuthenticatedSuccessorInputs,
    output_dir: str | Path,
    *,
    rs9_source_commit: str,
    rs9_source_tree: str,
    description_path: str | Path | None = None,
    deterministic_timestamp: tuple[int, int, int, int, int, int] | None = None,
) -> dict[str, Any]:
    """Build fresh v0.7 Gate1 candidates only from a ready real capture."""
    if not isinstance(authenticated, AuthenticatedSuccessorInputs) \
            or authenticated.release.distribution_version != "0.7.0" \
            or not isinstance(authenticated.release_binding, dict) \
            or authenticated.release_binding.get("status") != "ready":
        raise _error("RELEASE_INPUTS_PENDING", "Actual v0.7 release inputs are required before candidate generation")
    if (not isinstance(rs9_source_commit, str) or not isinstance(rs9_source_tree, str)
            or not _HEX40.fullmatch(rs9_source_commit) or not _HEX40.fullmatch(rs9_source_tree)):
        raise _error("RS9_SOURCE_IDENTITY", "Explicit reviewed candidate source commit and tree are required")
    destination = Path(output_dir).absolute()
    if destination.is_symlink() or any(parent.is_symlink() for parent in (destination, *destination.parents)):
        raise _error("OUTPUT_CONFINEMENT", "Gate1 candidate output ancestry contains a symlink")
    destination.mkdir(parents=True, exist_ok=True)
    if any(destination.iterdir()):
        raise _error("OUTPUT_NOT_EMPTY", "Gate1 candidate output must start empty")
    target_specs = (
        ("aarch64-darwin", "aarch64-apple-darwin", False),
        ("aarch64-linux", "aarch64-unknown-linux-gnu", True),
        ("x86_64-linux", "x86_64-unknown-linux-gnu", True),
    )
    rows: list[dict[str, Any]] = []
    candidate_source = None
    for system, target_triple, candidate_only in target_specs:
        result = build_gate1_successor_wheel(
            PRODUCT_ID,
            authenticated.release.application_version,
            distribution_version=authenticated.release.distribution_version,
            capture=authenticated.capture,
            profile_result=authenticated.profile,
            output_dir=destination / system,
            system=system,
            target_platform=target_triple,
            description_path=description_path,
            rs9_source_commit=rs9_source_commit,
            rs9_source_tree=rs9_source_tree,
            lineage_proof=authenticated.lineage_facts,
            candidate_only=candidate_only,
            deterministic_timestamp=deterministic_timestamp,
        )
        row = _gate1_candidate_row(system, target_triple, result)
        if candidate_source is None:
            candidate_source = result.record["rs9_source"]
        elif result.record["rs9_source"] != candidate_source:
            raise _error("RECEIPT_BINDING", "Gate1 rows disagree on candidate source identity")
        rows.append(row)
    if len(rows) != 3 or candidate_source is None:
        raise _error("RECEIPT_ROWS", "Exactly three Gate1 candidates must be built")
    receipt = _gate1_receipt(authenticated, rows, candidate_rs9_source=candidate_source)
    return validate_gate1_receipt(receipt, authenticated, output_dir=destination)


def build_successor_candidates(
    authenticated: AuthenticatedSuccessorInputs,
    output_dir: str | Path,
    *,
    rs9_source_commit: str,
    rs9_source_tree: str,
    description_path: str | Path | None = None,
    deterministic_timestamp: tuple[int, int, int, int, int, int] | None = None,
) -> dict[str, Any]:
    """Build the exact Darwin, Linux arm64, and Linux amd64 candidates."""
    if not isinstance(authenticated, AuthenticatedSuccessorInputs):
        raise _error("CANDIDATE_INPUT", "Capture-bound successor inputs are required")
    if (not isinstance(rs9_source_commit, str) or not isinstance(rs9_source_tree, str)
            or not _HEX40.fullmatch(rs9_source_commit) or not _HEX40.fullmatch(rs9_source_tree)):
        raise _error("RS9_SOURCE_IDENTITY", "Explicit reviewed RS9 source commit and tree are required")
    destination = Path(output_dir).absolute()
    if destination.is_symlink() or any(parent.is_symlink() for parent in (destination, *destination.parents)):
        raise _error("OUTPUT_CONFINEMENT", "Candidate output ancestry contains a symlink")
    destination.mkdir(parents=True, exist_ok=True)
    if any(destination.iterdir()):
        raise _error("OUTPUT_NOT_EMPTY", "Successor candidate output must start empty")
    target_specs = (
        ("aarch64-darwin", "aarch64-apple-darwin", None, False),
        ("aarch64-linux", "aarch64-unknown-linux-gnu", None, True),
        ("x86_64-linux", "x86_64-unknown-linux-gnu", None, True),
    )
    rows: list[dict[str, Any]] = []
    rs9_source = None
    for system, target_triple, platform_tag, candidate_only in target_specs:
        result = build_successor_wheel(
            PRODUCT_ID,
            authenticated.release.application_version,
            distribution_version=authenticated.release.distribution_version,
            capture=authenticated.capture,
            profile_result=authenticated.profile,
            output_dir=destination / system,
            system=system,
            target_platform=target_triple,
            platform_tag=platform_tag,
            description_path=description_path,
            rs9_source_commit=rs9_source_commit,
            rs9_source_tree=rs9_source_tree,
            lineage_proof=authenticated.lineage_proof,
            lineage_intent=authenticated.intent,
            candidate_only=candidate_only,
            deterministic_timestamp=deterministic_timestamp,
        )
        row = _candidate_row(system, target_triple, result)
        if rs9_source is None:
            rs9_source = result.record["rs9_source"]
        elif result.record["rs9_source"] != rs9_source:
            raise _error("RECEIPT_BINDING", "Successor rows disagree on RS9 source identity")
        rows.append(row)
    if len(rows) != 3 or rs9_source is None:
        raise _error("RECEIPT_ROWS", "Exactly three successor candidates must be built")
    receipt = _receipt(
        authenticated,
        rows,
        rs9_source=rs9_source,
    )
    return validate_candidate_receipt(receipt, authenticated, output_dir=destination)


def write_gate1_receipt(
    path: str | Path,
    receipt: dict[str, Any],
    *,
    authenticated: AuthenticatedSuccessorInputs,
    output_dir: str | Path,
) -> None:
    """Write one exclusive Gate1 receipt after validating fresh wheel bytes."""
    validate_gate1_receipt(receipt, authenticated, output_dir=output_dir)
    target = Path(path).absolute()
    if target.is_symlink() or any(parent.is_symlink() for parent in (target, *target.parents)):
        raise _error("OUTPUT_CONFINEMENT", "Gate1 receipt ancestry contains a symlink")
    target.parent.mkdir(parents=True, exist_ok=True)
    try:
        descriptor = os.open(
            str(target), os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o644
        )
    except (FileExistsError, OSError) as exc:
        raise _error("RECEIPT_DESTINATION", "Gate1 receipt destination is unavailable") from exc
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(canonical(receipt, validate=True))
    except Exception:
        try:
            target.unlink()
        except OSError:
            pass
        raise


def write_candidate_receipt(
    path: str | Path,
    receipt: dict[str, Any],
    *,
    authenticated: AuthenticatedSuccessorInputs,
    output_dir: str | Path,
) -> None:
    """Write one exclusive canonical candidate receipt; never overwrite."""
    validate_candidate_receipt(receipt, authenticated, output_dir=output_dir)
    target = Path(path).absolute()
    if target.is_symlink() or any(parent.is_symlink() for parent in (target, *target.parents)):
        raise _error("OUTPUT_CONFINEMENT", "Receipt ancestry contains a symlink")
    target.parent.mkdir(parents=True, exist_ok=True)
    try:
        descriptor = os.open(str(target), os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o644)
    except (FileExistsError, OSError) as exc:
        raise _error("RECEIPT_DESTINATION", "Candidate receipt destination is unavailable") from exc
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(canonical(receipt, validate=True))
    except Exception:
        try:
            target.unlink()
        except OSError:
            pass
        raise


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Build non-admitted Nebular successor wheel candidates")
    parser.add_argument("command", choices=("build-candidate",))
    parser.add_argument("--repository", required=True)
    parser.add_argument("--evidence", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--receipt", required=True)
    parser.add_argument("--approved-bootstrap-sha256", required=True)
    parser.add_argument("--rs9-source-commit", required=True)
    parser.add_argument("--rs9-source-tree", required=True)
    parser.add_argument("--release", choices=tuple(SUCCESSOR_RELEASES), default=DISTRIBUTION_VERSION)
    parser.add_argument("--description", default=None)
    args = parser.parse_args(argv)
    authenticated = authenticate_successor_capture(
        args.repository,
        args.evidence,
        approved_bootstrap_sha256=args.approved_bootstrap_sha256,
        release=args.release,
    )
    receipt = build_successor_candidates(
        authenticated,
        args.output,
        rs9_source_commit=args.rs9_source_commit,
        rs9_source_tree=args.rs9_source_tree,
        description_path=args.description,
    )
    write_candidate_receipt(args.receipt, receipt, authenticated=authenticated, output_dir=args.output)
    print(canonical(receipt).decode(), end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
