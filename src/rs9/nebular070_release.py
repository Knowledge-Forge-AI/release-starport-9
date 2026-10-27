"""Stage-B external release admission and bounded wheel readback for Nebular 0.7.0."""
from __future__ import annotations

import base64
import csv
import hashlib
import io
import json
import re
import stat
import zipfile
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from rs9.errors import ContractError
from rs9.scratch import canonical
from rs9.nebular070_payload import (
    ADMISSION_SCHEMA,
    APPROVAL_SCHEMA,
    CLAIM,
    CONSUMER_RECEIPT_SCHEMA,
    HEX40,
    HEX64,
    LINUX_TARGETS,
    MAX_WHEEL_BYTES,
    MAX_WHEEL_MEMBERS,
    MAX_WHEEL_MEMBER_BYTES,
    MAX_WHEEL_TOTAL_BYTES,
    MATRIX_SCHEMA,
    VERSION,
    ValidatedPayloadPortability,
    _admission_digest,
    _body_digest,
    _closed,
    _digest,
    _fail,
    _hex,
    _source,
    _version_pair,
)


@dataclass(frozen=True)
class ValidatedReleaseAdmission:
    record: dict[str, Any]
    digest: str


def manylinux_tag_for_target(target: str) -> str:
    try:
        return LINUX_TARGETS[target][1]
    except KeyError as exc:
        raise _fail("NEBULAR_MANYLINUX_TARGET", "Target has no 0.7.0 manylinux tag") from exc


def _record_digest(data: bytes) -> str:
    return "sha256=" + base64.urlsafe_b64encode(hashlib.sha256(data).digest()).decode("ascii").rstrip("=")


def _read_wheel_entries(raw: bytes) -> dict[str, bytes]:
    if not isinstance(raw, bytes) or not raw or len(raw) > MAX_WHEEL_BYTES:
        raise _fail("NEBULAR_MANYLINUX_WHEEL", "Final wheel bytes are required")
    try:
        with zipfile.ZipFile(io.BytesIO(raw)) as archive:
            infos = archive.infolist()
            if not infos or len(infos) > MAX_WHEEL_MEMBERS:
                raise _fail("NEBULAR_MANYLINUX_WHEEL", "Final wheel member set is unsafe")
            entries: dict[str, bytes] = {}
            total = 0
            for info in infos:
                name = info.filename
                if (not name or name in entries or name.startswith("/") or "\\" in name
                        or name.endswith("/")
                        or any(part in ("", ".", "..") for part in name.split("/"))
                        or stat.S_IFMT(info.external_attr >> 16) == stat.S_IFLNK
                        or info.file_size < 0 or info.file_size > MAX_WHEEL_MEMBER_BYTES):
                    raise _fail("NEBULAR_MANYLINUX_WHEEL", "Final wheel member set is unsafe")
                total += info.file_size
                if total > MAX_WHEEL_TOTAL_BYTES:
                    raise _fail("NEBULAR_MANYLINUX_WHEEL", "Final wheel member total exceeds the bound")
                data = archive.read(name)
                if len(data) != info.file_size:
                    raise _fail("NEBULAR_MANYLINUX_WHEEL", "Final wheel member size is unstable")
                entries[name] = data
    except zipfile.BadZipFile as exc:
        raise _fail("NEBULAR_MANYLINUX_WHEEL", "Final wheel archive is malformed") from exc
    return entries


def _validate_wheel_members(entries: Mapping[str, bytes], *, target: str) -> tuple[str, str, str]:
    dist_infos = sorted(name.split("/", 1)[0] for name in entries if name.endswith(".dist-info/WHEEL"))
    if len(dist_infos) != 1:
        raise _fail("NEBULAR_MANYLINUX_WHEEL", "Final wheel metadata is ambiguous")
    dist_info = dist_infos[0]
    record_name = f"{dist_info}/RECORD"
    if record_name not in entries:
        raise _fail("NEBULAR_MANYLINUX_WHEEL", "Final wheel RECORD is missing")
    try:
        rows = list(csv.reader(entries[record_name].decode("utf-8").splitlines()))
    except (UnicodeDecodeError, csv.Error) as exc:
        raise _fail("NEBULAR_MANYLINUX_WHEEL", "Final wheel RECORD is malformed") from exc
    seen: set[str] = set()
    for row in rows:
        if len(row) != 3 or row[0] in seen:
            raise _fail("NEBULAR_MANYLINUX_WHEEL", "Final wheel RECORD rows are not closed")
        seen.add(row[0])
        if row[0] == record_name:
            if row[1:] != ["", ""]:
                raise _fail("NEBULAR_MANYLINUX_WHEEL", "Final wheel RECORD self-row is malformed")
        elif row[0] not in entries or row[1] != _record_digest(entries[row[0]]) or row[2] != str(len(entries[row[0]])):
            raise _fail("NEBULAR_MANYLINUX_WHEEL", "Final wheel RECORD does not match its bytes")
    if seen != set(entries):
        raise _fail("NEBULAR_MANYLINUX_WHEEL", "Final wheel RECORD member set is incomplete")
    wheel_member = f"{dist_info}/WHEEL"
    try:
        tag_lines = [
            line[5:] for line in entries[wheel_member].decode("utf-8").splitlines()
            if line.startswith("Tag: ")
        ]
    except UnicodeDecodeError as exc:
        raise _fail("NEBULAR_MANYLINUX_WHEEL", "Final wheel WHEEL metadata is malformed") from exc
    expected_tag = manylinux_tag_for_target(target)
    if tag_lines != [expected_tag]:
        raise _fail("NEBULAR_MANYLINUX_WHEEL", "Final wheel WHEEL tag does not match the target")
    return dist_info, record_name, wheel_member


def _validate_wheel_payload(
    entries: Mapping[str, bytes], *, stage_a_digest: str, expected_tag: str
) -> tuple[str, str, str]:
    provenance_name = "theme_forge_nebular_fusion/_rs9/provenance.json"
    if provenance_name not in entries:
        raise _fail("NEBULAR_MANYLINUX_WHEEL", "Final wheel provenance is missing")
    try:
        provenance = json.loads(entries[provenance_name].decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise _fail("NEBULAR_MANYLINUX_WHEEL", "Final wheel provenance is malformed") from exc
    if not isinstance(provenance, Mapping):
        raise _fail("NEBULAR_MANYLINUX_WHEEL", "Final wheel provenance is malformed")
    if provenance.get("wheel_tag") != expected_tag \
            or provenance.get("manylinux_construction_receipt_sha256") != stage_a_digest \
            or provenance.get("construction_stage") != "payload-portability" \
            or provenance.get("release_admission") != "external":
        raise _fail("NEBULAR_MANYLINUX_WHEEL", "Final wheel provenance is not Stage A-bound")
    payload_name = provenance.get("payload_archive_name")
    if (not isinstance(payload_name, str) or not payload_name or "/" in payload_name
            or "\\" in payload_name or payload_name in (".", "..")):
        raise _fail("NEBULAR_MANYLINUX_WHEEL", "Final wheel payload name is unsafe")
    archive_name = f"theme_forge_nebular_fusion/payload/{payload_name}"
    manifest_name = "theme_forge_nebular_fusion/payload/manifest.json"
    if archive_name not in entries or manifest_name not in entries:
        raise _fail("NEBULAR_MANYLINUX_WHEEL", "Final wheel payload members are missing")
    payload_sha = provenance.get("payload_archive_sha256")
    manifest_sha = provenance.get("manifest_sha256")
    try:
        manifest_value = json.loads(entries[manifest_name].decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise _fail("NEBULAR_MANYLINUX_WHEEL", "Final wheel payload manifest is malformed") from exc
    if not isinstance(manifest_value, Mapping) or not isinstance(manifest_value.get("members"), list):
        raise _fail("NEBULAR_MANYLINUX_WHEEL", "Final wheel payload manifest is malformed")
    try:
        manifest_members_sha = hashlib.sha256(canonical(manifest_value["members"])).hexdigest()
    except (ContractError, TypeError, ValueError) as exc:
        raise _fail("NEBULAR_MANYLINUX_WHEEL", "Final wheel payload manifest members are malformed") from exc
    if _hex(payload_sha, "final payload archive") != hashlib.sha256(entries[archive_name]).hexdigest() \
            or _hex(manifest_sha, "final payload manifest") != manifest_members_sha:
        raise _fail("NEBULAR_MANYLINUX_WHEEL", "Final wheel payload identity does not match provenance")
    return provenance_name, archive_name, manifest_sha


def _wheel_snapshot(raw: bytes, target: str, stage_a_digest: str) -> dict[str, Any]:
    entries = _read_wheel_entries(raw)
    _dist_info, record_name, wheel_member = _validate_wheel_members(entries, target=target)
    expected_tag = manylinux_tag_for_target(target)
    provenance_name, archive_name, manifest_sha = _validate_wheel_payload(
        entries, stage_a_digest=stage_a_digest, expected_tag=expected_tag
    )
    return {
        "archive_sha256": hashlib.sha256(raw).hexdigest(),
        "size": len(raw),
        "wheel_member_sha256": hashlib.sha256(entries[wheel_member]).hexdigest(),
        "record_member_sha256": hashlib.sha256(entries[record_name]).hexdigest(),
        "provenance_member_sha256": hashlib.sha256(entries[provenance_name]).hexdigest(),
        "payload_archive_sha256": hashlib.sha256(entries[archive_name]).hexdigest(),
        "manifest_sha256": manifest_sha,
        "tag": expected_tag,
    }


def _consumer_body(body: Any, *, target: str, wheel: dict[str, Any], kind: str) -> dict[str, Any]:
    body = _closed(body, {"schema", "kind", "status", "target", "wheel_sha256", "wheel_tag", "host", "identity"},
                   f"installed {target}/{kind} consumer")
    if body["schema"] != CONSUMER_RECEIPT_SCHEMA or body["kind"] != kind \
            or body["status"] != "pass" or body["target"] != target \
            or body["wheel_sha256"] != wheel["archive_sha256"] or body["wheel_tag"] != wheel["tag"]:
        raise _fail("NEBULAR_MANYLINUX_CONSUMER", f"Installed {target}/{kind} consumer does not join its wheel")
    host = _closed(body["host"], {"glibc", "loader"}, "consumer host")
    if not isinstance(host["glibc"], str) or not isinstance(host["loader"], str) or not host["loader"]:
        raise _fail("NEBULAR_MANYLINUX_CONSUMER", "Installed consumer host identity is malformed")
    parts = tuple(int(part) for part in re.fullmatch(r"(\d+)\.(\d+)", host["glibc"]).groups()) \
        if re.fullmatch(r"\d+\.\d+", host["glibc"]) else None
    if parts is None or (kind == "floor" and parts != (2, 36)) or (kind == "newer" and parts <= (2, 36)):
        raise _fail("NEBULAR_MANYLINUX_CONSUMER", f"Installed {target}/{kind} glibc host is outside the contract")
    unsigned = dict(body)
    unsigned.pop("identity")
    if _hex(body["identity"], "consumer identity") != _digest(unsigned):
        raise _fail("NEBULAR_MANYLINUX_CONSUMER", f"Installed {target}/{kind} identity does not match")
    return body


def _approval_set_digest(approval: Mapping[str, Any]) -> str:
    return _admission_digest({
        key: value
        for key, value in approval.items()
        if key not in {"set_sha256", "publication_admitted", "admission_sha256"}
    })


def _approval_admission_digest(approval: Mapping[str, Any]) -> str:
    return _admission_digest({
        "schema": "rs9.tf-pypi-nebular070-admission-binding.v1",
        "project": "theme-forge-nebular-fusion",
        "distribution": "theme-forge-nebular-fusion",
        "version": VERSION,
        "distribution_version": VERSION,
        "workflow": "rs9-tfnf-pypi-publish.yml",
        "environment": "pypi",
        "publication_admitted": True,
        "set_sha256": approval.get("set_sha256"),
        "candidate_receipt_sha256": approval.get("candidate_receipt_sha256"),
        "expected_artifact_record_sha256": approval.get("expected_artifact_record_sha256"),
        "profile_sha256": approval.get("profile_sha256"),
        "matrix_receipt_sha256": approval.get("matrix_receipt_sha256"),
        "manylinux_stage_a_sha256": approval.get("manylinux_stage_a_sha256"),
        "qualification": approval.get("qualification"),
    })


def _validate_approval_header(
    value: Any,
    *,
    stage_a: ValidatedPayloadPortability,
    expected_rs9_release_source: Mapping[str, str],
) -> dict[str, Any]:
    required = {
        "schema", "project", "distribution", "version", "distribution_version", "workflow",
        "environment", "requires_python", "command", "license_expression", "license_files", "readme",
        "candidate_receipt_sha256", "expected_artifact_record_sha256", "profile_sha256",
        "matrix_receipt_sha256", "qualification", "files", "builder_can_publish", "publication_admitted",
        "set_sha256", "admission_sha256", "manylinux_stage_a_sha256",
    }
    approval = _closed(value, required, "existing 0.7.0 approval")
    if (
        approval["schema"] != APPROVAL_SCHEMA
        or approval["project"] != "theme-forge-nebular-fusion"
        or approval["distribution"] != "theme-forge-nebular-fusion"
        or approval["version"] != VERSION
        or approval["distribution_version"] != VERSION
        or approval["workflow"] != "rs9-tfnf-pypi-publish.yml"
        or approval["environment"] != "pypi"
        or approval["builder_can_publish"] is not False
        or approval["publication_admitted"] is not True
        or approval["manylinux_stage_a_sha256"] != stage_a.digest
    ):
        raise _fail("NEBULAR_MANYLINUX_APPROVAL", "Existing approval is not the admitted 0.7.0 artifact approval")
    for field in (
        "candidate_receipt_sha256", "expected_artifact_record_sha256", "profile_sha256",
        "matrix_receipt_sha256", "set_sha256", "admission_sha256", "manylinux_stage_a_sha256",
    ):
        _hex(approval[field], f"approval {field}")
    qualification = approval["qualification"]
    expected_source = _source(expected_rs9_release_source, "expected RS9 release source")
    if not isinstance(qualification, Mapping) \
            or qualification.get("candidate_source_commit") != expected_source["commit"] \
            or qualification.get("candidate_source_tree") != expected_source["tree"] \
            or qualification.get("matrix_receipt_sha256") != approval["matrix_receipt_sha256"] \
            or not isinstance(qualification.get("target_qualification_sources"), Mapping) \
            or set(qualification["target_qualification_sources"]) != set(("darwin-arm64", *LINUX_TARGETS)):
        raise _fail("NEBULAR_MANYLINUX_SOURCE", "Approval qualification source does not join the release source")
    for field in (
        "candidate_source_commit", "candidate_source_tree", "qualification_source_commit", "qualification_source_tree",
    ):
        if not isinstance(qualification.get(field), str) or not HEX40.fullmatch(qualification[field]):
            raise _fail("NEBULAR_MANYLINUX_SOURCE", "Approval qualification source is malformed")
    return approval


def _validate_approval_files(files: Any) -> dict[str, Mapping[str, Any]]:
    if not isinstance(files, list) or len(files) != 3:
        raise _fail("NEBULAR_MANYLINUX_APPROVAL", "Existing approval file set is incomplete")
    files_by_target: dict[str, Mapping[str, Any]] = {}
    expected_file_keys = {
        "target", "system", "filename", "size", "sha256", "tag", "version",
        "payload_archive_name", "payload_archive_sha256", "manifest_sha256",
    }
    for row in files:
        row = _closed(row, expected_file_keys, "existing approval file")
        target = row["target"]
        if target in files_by_target or target not in {"darwin-arm64", *LINUX_TARGETS}:
            raise _fail("NEBULAR_MANYLINUX_APPROVAL", "Existing approval target set is not closed")
        _hex(row["sha256"], f"approval {target} wheel")
        _hex(row["payload_archive_sha256"], f"approval {target} payload")
        _hex(row["manifest_sha256"], f"approval {target} manifest")
        if row["version"] != VERSION:
            raise _fail("NEBULAR_MANYLINUX_APPROVAL", "Existing approval version does not join")
        if target in LINUX_TARGETS:
            expected_tag = manylinux_tag_for_target(target)
            expected_name = f"theme_forge_nebular_fusion-{VERSION}-{expected_tag}.whl"
            if row["tag"] != expected_tag or row["filename"] != expected_name:
                raise _fail("NEBULAR_MANYLINUX_APPROVAL", "Existing Linux approval is not manylinux_2_36-bound")
        elif row["tag"] != "py3-none-macosx_13_0_arm64":
            raise _fail("NEBULAR_MANYLINUX_APPROVAL", "Existing Darwin approval tag is not the reviewed target")
        files_by_target[target] = row
    if set(files_by_target) != {"darwin-arm64", *LINUX_TARGETS}:
        raise _fail("NEBULAR_MANYLINUX_APPROVAL", "Existing approval is missing a target")
    return files_by_target


def _validate_approval_legal(approval: Mapping[str, Any]) -> None:
    license_files = approval["license_files"]
    readme = approval["readme"]
    if (
        not isinstance(license_files, Mapping)
        or not isinstance(license_files.get("LICENSE"), Mapping)
        or not isinstance(license_files.get("NOTICE"), Mapping)
        or not isinstance(readme, Mapping)
        or not isinstance(readme.get("sha256"), str)
    ):
        raise _fail("NEBULAR_MANYLINUX_APPROVAL", "Existing legal/readme approval bindings are missing")
    for name in ("LICENSE", "NOTICE"):
        entry = license_files[name]
        if entry.get("path") != name:
            raise _fail("NEBULAR_MANYLINUX_APPROVAL", "Existing legal approval path is not canonical")
        _hex(entry.get("sha256"), f"approval {name}")
    _hex(readme["sha256"], "approval readme")


def _validate_existing_approval(
    value: Any,
    *,
    stage_a: ValidatedPayloadPortability,
    expected_rs9_release_source: Mapping[str, str],
) -> dict[str, Any]:
    approval = _validate_approval_header(
        value, stage_a=stage_a, expected_rs9_release_source=expected_rs9_release_source
    )
    files_by_target = _validate_approval_files(approval["files"])
    _validate_approval_legal(approval)
    if approval["set_sha256"] != _approval_set_digest(approval) \
            or approval["admission_sha256"] != _approval_admission_digest(approval):
        raise _fail("NEBULAR_MANYLINUX_APPROVAL", "Existing approval digest is not authenticated")
    return {"approval": approval, "files": files_by_target}


def _validate_matrix_header(
    value: Any, *, approval: Mapping[str, Any]
) -> tuple[dict[str, Any], list[str], Mapping[str, Any]]:
    keys = {
        "schema", "status", "fixture_only", "native_qualified", "candidate_receipt_sha256",
        "expected_artifact_record_sha256", "candidate_rs9_source", "qualification_rs9_source", "targets",
        "receipts", "run_id", "run_attempt", "publication_admitted", "public_writes",
    }
    matrix = _closed(value, keys, "existing hosted matrix")
    qualification = approval["qualification"]
    expected_targets = ["darwin-arm64", *LINUX_TARGETS]
    if (
        matrix["schema"] != MATRIX_SCHEMA
        or matrix["status"] != "native-matrix-passed"
        or matrix["fixture_only"] is not False
        or matrix["native_qualified"] is not True
        or matrix["publication_admitted"] is not False
        or matrix["public_writes"] != 0
        or matrix["targets"] != sorted(expected_targets)
        or matrix["candidate_receipt_sha256"] != approval["candidate_receipt_sha256"]
        or matrix["expected_artifact_record_sha256"] != approval["expected_artifact_record_sha256"]
        or matrix["candidate_rs9_source"] != {
            "commit": qualification["candidate_source_commit"],
            "tree": qualification["candidate_source_tree"],
        }
        or not isinstance(matrix["receipts"], Mapping)
        or set(matrix["receipts"]) != set(expected_targets)
        or _admission_digest(matrix) != approval["matrix_receipt_sha256"]
    ):
        raise _fail("NEBULAR_MANYLINUX_APPROVAL", "Existing hosted matrix is not the admitted three-target receipt")
    q_sources = matrix["qualification_rs9_source"]
    if not isinstance(q_sources, Mapping) or set(q_sources) != set(expected_targets):
        raise _fail("NEBULAR_MANYLINUX_APPROVAL", "Existing matrix qualification sources are incomplete")
    for target in expected_targets:
        source = q_sources[target]
        expected_q = qualification["target_qualification_sources"][target]
        if (
            not isinstance(source, Mapping)
            or source.get("commit") != expected_q.get("commit")
            or source.get("tree") != expected_q.get("tree")
        ):
            raise _fail("NEBULAR_MANYLINUX_APPROVAL", "Existing matrix source does not join approval")
    return matrix, expected_targets, qualification


def _validate_matrix_receipt(
    matrix: Mapping[str, Any],
    *,
    target: str,
    approval: Mapping[str, Any],
    approval_files: Mapping[str, Mapping[str, Any]],
) -> None:
    receipt = matrix["receipts"][target]
    if (
        not isinstance(receipt, Mapping)
        or receipt.get("schema") != "rs9.nebular070-hosted-consumer.v1"
        or receipt.get("status") != "native-consumer-passed"
        or receipt.get("fixture_only") is not False
        or receipt.get("native_qualified") is not True
        or receipt.get("target") != target
        or receipt.get("publication_admitted") is not False
        or receipt.get("candidate_receipt_sha256") != approval["candidate_receipt_sha256"]
        or receipt.get("expected_artifact_record_sha256") != approval["expected_artifact_record_sha256"]
        or receipt.get("candidate_rs9_source") != matrix["candidate_rs9_source"]
    ):
        raise _fail("NEBULAR_MANYLINUX_APPROVAL", "Existing hosted consumer receipt is not actual")
    consumer = receipt.get("consumer")
    if (
        not isinstance(consumer, Mapping)
        or consumer.get("fixture_only") is not False
        or consumer.get("native_qualified") is not True
        or consumer.get("process_observer", {}).get("orphan_count") != 0
        or consumer.get("user_state", {}).get("unchanged") is not True
        or consumer.get("sandbox", {}).get("network_disabled") is not True
        or consumer.get("provider_closure", {}).get("status") != "verified"
    ):
        raise _fail("NEBULAR_MANYLINUX_APPROVAL", "Existing hosted consumer closure is not verified")
    file_row = approval_files[target]
    if consumer.get("wheel") != {
        "target": target,
        "filename": file_row["filename"],
        "size": file_row["size"],
        "sha256": file_row["sha256"],
        "tag": file_row["tag"],
        "version": VERSION,
    }:
        raise _fail("NEBULAR_MANYLINUX_APPROVAL", "Existing hosted consumer wheel does not join approval")


def _validate_existing_matrix(
    value: Any,
    *,
    approval: Mapping[str, Any],
    approval_files: Mapping[str, Mapping[str, Any]],
) -> dict[str, Any]:
    matrix, expected_targets, _qualification = _validate_matrix_header(value, approval=approval)
    for target in expected_targets:
        _validate_matrix_receipt(
            matrix, target=target, approval=approval, approval_files=approval_files
        )
    return matrix


def _validate_release_header(
    record: Mapping[str, Any],
    *,
    stage_a: ValidatedPayloadPortability,
    expected_rs9_release_source: Mapping[str, str],
) -> dict[str, Any]:
    top = _closed(record, {
        "schema", "version", "claim", "stage_a_sha256", "rs9_release_source",
        "tf_producer_source", "targets", "darwin_release_row",
        "existing_three_target_approval_sha256", "legal_readme_description_digests",
        "final_wheel_set_sha256", "manylinux_claim", "publication_admitted", "identity",
    }, "release admission")
    if top["schema"] != ADMISSION_SCHEMA or top["version"] != VERSION or top["claim"] != CLAIM \
            or top["stage_a_sha256"] != stage_a.digest or top["manylinux_claim"] is not True \
            or top["publication_admitted"] is not True:
        raise _fail("NEBULAR_MANYLINUX_ADMISSION", "Release admission is not a validated 0.7.0 Stage B record")
    if _source(top["rs9_release_source"], "RS9 release source") != _source(
        expected_rs9_release_source, "expected RS9 release source"
    ) or _source(top["tf_producer_source"], "TF producer source") != stage_a.record["tf_producer_source"]:
        raise _fail("NEBULAR_MANYLINUX_SOURCE", "Release admission source identities do not join Stage A")
    return top


def _validate_release_target(
    row: Mapping[str, Any],
    *,
    stage_a: ValidatedPayloadPortability,
    wheel_bytes: bytes,
    wheel_filename: str,
    installed_bodies: Mapping[str, Mapping[str, Any]] | None,
) -> dict[str, Any]:
    row = _closed(row, {
        "target", "tag", "wheel_archive_sha256", "wheel_size", "wheel_member_sha256",
        "record_member_sha256", "provenance_member_sha256", "payload_archive_sha256",
        "manifest_sha256", "embedded_stage_a_digest",
        "installed_floor_consumer_receipt_sha256", "installed_newer_consumer_receipt_sha256",
    }, "release target")
    target = row["target"]
    if target not in LINUX_TARGETS or row["tag"] != manylinux_tag_for_target(target):
        raise _fail("NEBULAR_MANYLINUX_TARGET", "Release target tag is outside the reviewed 2.36 set")
    wheel = _wheel_snapshot(wheel_bytes, target, stage_a.digest)
    for row_key, wheel_key in (
        ("wheel_archive_sha256", "archive_sha256"),
        ("wheel_member_sha256", "wheel_member_sha256"),
        ("record_member_sha256", "record_member_sha256"),
        ("provenance_member_sha256", "provenance_member_sha256"),
        ("payload_archive_sha256", "payload_archive_sha256"),
        ("manifest_sha256", "manifest_sha256"),
    ):
        if row[row_key] != wheel[wheel_key]:
            raise _fail("NEBULAR_MANYLINUX_WHEEL", f"Release wheel {row_key} does not match its bytes")
    if row["wheel_size"] != wheel["size"] or row["embedded_stage_a_digest"] != stage_a.digest:
        raise _fail("NEBULAR_MANYLINUX_WHEEL", "Release wheel size or Stage A join is incorrect")
    expected_filename = f"theme_forge_nebular_fusion-0.7.0-{manylinux_tag_for_target(target)}.whl"
    if wheel_filename != expected_filename:
        raise _fail("NEBULAR_MANYLINUX_WHEEL", "Final Linux wheel filename is not tag-bound")
    if not isinstance(installed_bodies, Mapping) or set(installed_bodies) != {"floor", "newer"}:
        raise _fail("NEBULAR_MANYLINUX_CONSUMER", "Both installed-wheel consumer receipts are required")
    floor = _consumer_body(installed_bodies["floor"], target=target, wheel=wheel, kind="floor")
    newer = _consumer_body(installed_bodies["newer"], target=target, wheel=wheel, kind="newer")
    if row["installed_floor_consumer_receipt_sha256"] != floor["identity"] \
            or row["installed_newer_consumer_receipt_sha256"] != newer["identity"]:
        raise _fail("NEBULAR_MANYLINUX_CONSUMER", "Installed-wheel receipt digest does not match its body")
    return dict(row)


def _validate_release_darwin_legal(
    top: Mapping[str, Any],
    *,
    approval: Mapping[str, Any],
    approval_files: Mapping[str, Mapping[str, Any]],
    matrix: Mapping[str, Any],
) -> dict[str, Any]:
    darwin = _closed(
        top["darwin_release_row"],
        {"target", "tag", "wheel_archive_sha256", "receipt_sha256"},
        "Darwin release row",
    )
    if darwin["target"] != "darwin-arm64" or darwin["tag"] != "py3-none-macosx_13_0_arm64":
        raise _fail("NEBULAR_MANYLINUX_TARGET", "Darwin release row is not the existing three-target row")
    _hex(darwin["wheel_archive_sha256"], "Darwin wheel")
    _hex(darwin["receipt_sha256"], "Darwin receipt")
    if darwin["wheel_archive_sha256"] != approval_files["darwin-arm64"]["sha256"]:
        raise _fail("NEBULAR_MANYLINUX_WHEEL", "Darwin release row does not join the existing approval")
    if darwin["receipt_sha256"] != _admission_digest(matrix["receipts"]["darwin-arm64"]):
        raise _fail("NEBULAR_MANYLINUX_APPROVAL", "Darwin release receipt does not join the existing matrix")
    legal = _closed(
        top["legal_readme_description_digests"],
        {"license", "notice", "readme", "description"},
        "legal/readme digests",
    )
    for value in legal.values():
        _hex(value, "legal/readme digest")
    expected_legal = {
        "license": approval["license_files"]["LICENSE"]["sha256"],
        "notice": approval["license_files"]["NOTICE"]["sha256"],
        "readme": approval["readme"]["sha256"],
        "description": approval["readme"]["sha256"],
    }
    if legal != expected_legal:
        raise _fail("NEBULAR_MANYLINUX_APPROVAL", "Legal/readme digests do not join the existing approval")
    return dict(darwin)


def _validate_release_linux_rows(
    top: Mapping[str, Any],
    *,
    stage_a: ValidatedPayloadPortability,
    wheel_bytes_by_target: Mapping[str, bytes],
    wheel_filenames_by_target: Mapping[str, str] | None,
    installed_consumer_bodies: Mapping[str, Mapping[str, Mapping[str, Any]]],
) -> list[dict[str, Any]]:
    rows = top["targets"]
    if (not isinstance(rows, list) or len(rows) != len(LINUX_TARGETS)
            or {row.get("target") for row in rows if isinstance(row, Mapping)} != set(LINUX_TARGETS)):
        raise _fail("NEBULAR_MANYLINUX_TARGET", "Release admission must contain both Linux target rows")
    if not isinstance(wheel_bytes_by_target, Mapping) or set(wheel_bytes_by_target) != set(LINUX_TARGETS):
        raise _fail("NEBULAR_MANYLINUX_WHEEL", "Final Linux wheel bytes for both targets are required")
    if wheel_filenames_by_target is None or not isinstance(wheel_filenames_by_target, Mapping) \
            or set(wheel_filenames_by_target) != set(LINUX_TARGETS) \
            or any(not isinstance(name, str) for name in wheel_filenames_by_target.values()):
        raise _fail("NEBULAR_MANYLINUX_WHEEL", "Final Linux wheel filenames are not closed")
    return [
        _validate_release_target(
            row,
            stage_a=stage_a,
            wheel_bytes=wheel_bytes_by_target[row["target"]],
            wheel_filename=wheel_filenames_by_target[row["target"]],
            installed_bodies=installed_consumer_bodies.get(row["target"]),
        )
        for row in rows
    ]


def validate_nebular070_release_admission(
    record: Mapping[str, Any],
    *,
    stage_a: ValidatedPayloadPortability,
    wheel_bytes_by_target: Mapping[str, bytes],
    wheel_filenames_by_target: Mapping[str, str] | None = None,
    installed_consumer_bodies: Mapping[str, Mapping[str, Mapping[str, Any]]],
    existing_three_target_approval: Mapping[str, Any],
    existing_matrix_receipt: Mapping[str, Any],
    expected_rs9_release_source: Mapping[str, str],
) -> ValidatedReleaseAdmission:
    """Validate external post-build admission; never embed or infer Stage B."""
    top = _validate_release_header(
        record, stage_a=stage_a, expected_rs9_release_source=expected_rs9_release_source
    )
    approval_parts = _validate_existing_approval(
        existing_three_target_approval,
        stage_a=stage_a,
        expected_rs9_release_source=expected_rs9_release_source,
    )
    approval = approval_parts["approval"]
    approval_files = approval_parts["files"]
    _validate_existing_matrix(existing_matrix_receipt, approval=approval, approval_files=approval_files)
    if top["existing_three_target_approval_sha256"] != approval["admission_sha256"]:
        raise _fail("NEBULAR_MANYLINUX_APPROVAL", "Release admission approval digest does not join")
    checked_rows = _validate_release_linux_rows(
        top,
        stage_a=stage_a,
        wheel_bytes_by_target=wheel_bytes_by_target,
        wheel_filenames_by_target=wheel_filenames_by_target,
        installed_consumer_bodies=installed_consumer_bodies,
    )
    matrix = existing_matrix_receipt
    darwin = _validate_release_darwin_legal(
        top, approval=approval, approval_files=approval_files, matrix=matrix
    )
    expected_set = _admission_digest({"linux": sorted(checked_rows, key=lambda row: row["target"]), "darwin": darwin})
    if top["final_wheel_set_sha256"] != expected_set:
        raise _fail("NEBULAR_MANYLINUX_ADMISSION", "Final wheel-set digest does not match the three-target rows")
    unsigned = dict(top)
    unsigned.pop("identity")
    identity = _hex(top["identity"], "release admission identity")
    if identity != _admission_digest(unsigned):
        raise _fail("NEBULAR_MANYLINUX_ADMISSION", "Release admission identity does not match its contents")
    return ValidatedReleaseAdmission(dict(top), identity)

