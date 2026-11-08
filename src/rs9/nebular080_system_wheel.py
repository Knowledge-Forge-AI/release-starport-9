"""Narrow system-WebKit wheel readback for the Nebular 0.8 consumer route.

This is the deliberately small extraction of the legacy public-consumer
wheel reader.  It does not import the broad hosted/public-consumer owner and
does not construct a release or publication record.
"""
from __future__ import annotations

import hashlib
from collections.abc import Mapping
from typing import Any

from rs9.errors import ContractError
from rs9.nebular080_consumer_core import (
    NEBULAR080_SYSTEM_WEBKIT_PROFILE,
    NEBULAR080_SYSTEM_WEBKIT_PROFILE_ID,
    NEBULAR080_TARGET_SYSTEMS,
)
from rs9.nebular080_manylinux import MAX_WHEEL_BYTES
from rs9.wheel_nebular080_universal import LAYOUTS as NEBULAR080_LAYOUTS
from rs9.scratch import canonical
from rs9.tf_pypi_model import strict_json
from rs9.tf_pypi_verify import read_wheel, verify_record


_EXPECTED_WHEEL_TAGS = {
    key: f"py3-none-linux_{NEBULAR080_LAYOUTS[key][1]}"
    for key in ("linux-arm64-gnu", "linux-x64-gnu")
}


def _fail(code: str, message: str) -> None:
    raise ContractError(code, message)


def _validate_system_webkit_archive(
    archive_manifest: Mapping[str, Any],
    *,
    payload_name: str,
    system: str,
    profile_id: str | None,
) -> None:
    """Reject portable/private or manylinux material from a system-profile wheel."""
    if profile_id is not None and profile_id != NEBULAR080_SYSTEM_WEBKIT_PROFILE_ID:
        _fail("NEBULAR_SYSTEM_WEBKIT_PROFILE", "System-WebKit profile identity is not closed")
    if profile_id != NEBULAR080_SYSTEM_WEBKIT_PROFILE_ID or not system.endswith("-linux"):
        return
    if any(token in payload_name.lower() for token in ("manylinux", "musllinux")):
        _fail("NEBULAR_SYSTEM_WEBKIT_LAYOUT", "System-WebKit payload cannot carry a manylinux tag")
    members = archive_manifest.get("members")
    if not isinstance(members, list):
        _fail("NEBULAR_SYSTEM_WEBKIT_LAYOUT", "System-WebKit payload member manifest is unavailable")
    for row in members:
        if not isinstance(row, Mapping) or not isinstance(row.get("path"), str):
            _fail("NEBULAR_SYSTEM_WEBKIT_LAYOUT", "System-WebKit payload member is malformed")
        segments = set(row["path"].split("/"))
        if "nebular-private" in segments or ("opt" in segments and "nebular-private" in segments):
            _fail("NEBULAR_SYSTEM_WEBKIT_LAYOUT", "System-WebKit payload must not embed private runtime files")
    for key in archive_manifest:
        lowered_key = str(key).lower()
        if "manylinux" in lowered_key or "musllinux" in lowered_key:
            _fail("NEBULAR_SYSTEM_WEBKIT_LAYOUT", "System-WebKit payload cannot carry portable Linux metadata")


def _system_wheel(raw: bytes, target: str) -> dict[str, Any]:
    """Read back a generic-tag system-WebKit wheel without Stage-A data."""
    if not isinstance(raw, bytes):
        _fail("NEBULAR_STAGE_B_WHEEL", "Authenticated wheel bytes are required")
    files = read_wheel(raw, max_total_bytes=MAX_WHEEL_BYTES, max_member_bytes=MAX_WHEEL_BYTES)
    dist_infos = sorted({name.split("/", 1)[0] for name in files if name.endswith(".dist-info/WHEEL")})
    if len(dist_infos) != 1:
        _fail("NEBULAR_STAGE_B_WHEEL", "System wheel metadata is ambiguous")
    dist_info = dist_infos[0]
    verify_record(files, dist_info)
    wheel_name = f"{dist_info}/WHEEL"
    try:
        tags = [line[5:] for line in files[wheel_name][0].decode("utf-8").splitlines()
                if line.startswith("Tag: ")]
    except (KeyError, UnicodeDecodeError):
        _fail("NEBULAR_STAGE_B_WHEEL", "System wheel tag metadata is malformed")
    expected_tag = _EXPECTED_WHEEL_TAGS.get(target)
    if expected_tag is None or tags != [expected_tag]:
        _fail("NEBULAR_STAGE_B_WHEEL", "System wheel tag does not match its target")
    provenance_name = "theme_forge_nebular_fusion/_rs9/provenance.json"
    try:
        provenance = strict_json(files[provenance_name][0])
    except (KeyError, ValueError, UnicodeDecodeError):
        _fail("NEBULAR_STAGE_B_WHEEL", "System wheel provenance is malformed")
    profile = provenance.get("candidate_profile") if isinstance(provenance, Mapping) else None
    policy = provenance.get("linux_runtime_policy") if isinstance(provenance, Mapping) else None
    if (not isinstance(provenance, Mapping)
            or not isinstance(profile, Mapping)
            or profile.get("profile_id") != NEBULAR080_SYSTEM_WEBKIT_PROFILE_ID
            or provenance.get("wheel_tag") != expected_tag
            or not isinstance(policy, Mapping)
            or policy.get("provider_baseline") != "system-webkitgtk-4.1"
            or any(key in provenance for key in (
                "construction_stage", "release_admission", "manylinux_construction_receipt_sha256",
            ))):
        _fail("NEBULAR_STAGE_B_WHEEL", "System wheel provenance is not host-managed")
    payload_name = provenance.get("payload_archive_name")
    if (not isinstance(payload_name, str) or not payload_name or "/" in payload_name
            or "\\" in payload_name or payload_name in {".", ".."}):
        _fail("NEBULAR_STAGE_B_WHEEL", "System wheel payload name is unsafe")
    payload_member = f"theme_forge_nebular_fusion/payload/{payload_name}"
    manifest_member = "theme_forge_nebular_fusion/payload/manifest.json"
    if payload_member not in files or manifest_member not in files:
        _fail("NEBULAR_STAGE_B_WHEEL", "System wheel payload members are missing")
    try:
        manifest = strict_json(files[manifest_member][0])
    except (ValueError, UnicodeDecodeError):
        _fail("NEBULAR_STAGE_B_WHEEL", "System wheel manifest is malformed")
    members = manifest.get("members") if isinstance(manifest, Mapping) else None
    if (not isinstance(members, list)
            or provenance.get("payload_archive_sha256") != hashlib.sha256(files[payload_member][0]).hexdigest()
            or provenance.get("manifest_sha256") != hashlib.sha256(canonical(members)).hexdigest()):
        _fail("NEBULAR_STAGE_B_WHEEL", "System wheel payload identity is malformed")
    _validate_system_webkit_archive(
        manifest,
        payload_name=payload_name,
        system=NEBULAR080_TARGET_SYSTEMS[target],
        profile_id=profile.get("profile_id"),
    )
    return {
        "archive_sha256": hashlib.sha256(raw).hexdigest(),
        "size": len(raw),
        "wheel_member_sha256": hashlib.sha256(files[wheel_name][0]).hexdigest(),
        "record_member_sha256": hashlib.sha256(files[f"{dist_info}/RECORD"][0]).hexdigest(),
        "provenance_member_sha256": hashlib.sha256(files[provenance_name][0]).hexdigest(),
        "payload_archive_sha256": hashlib.sha256(files[payload_member][0]).hexdigest(),
        "manifest_sha256": provenance["manifest_sha256"],
        "tag": expected_tag,
        "linux_runtime_profile": NEBULAR080_SYSTEM_WEBKIT_PROFILE,
    }
