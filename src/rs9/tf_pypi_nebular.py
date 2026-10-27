"""Native Darwin ARM64 PyPI qualification and publication contract for Theme Forge Nebular Fusion 0.6.1.

Preserves unchanged embedded rs9 helpers, enforces native wheel-only scope,
binds authenticated release/profile/closure identities, enforces Darwin seatbelt
network denial with only the root-owned /bin/ps process-observation exception,
and provides finite post-upload readback without ever re-uploading.
"""
from __future__ import annotations

import argparse
import ast
import base64
import csv
from email.parser import BytesParser
import errno
import gzip
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import platform
import re
import shutil
import socket
import stat
import subprocess
import sys
import tarfile
import tempfile
import time
from typing import Any, Callable, Mapping, Sequence
from urllib.error import HTTPError, URLError
from urllib.request import ProxyHandler, Request, build_opener
import zipfile
import zlib

from rs9.bootstrap import (
    checked_bootstrap_configurations,
    load_bootstrap,
    require_configuration_authority,
)
from rs9.candidate import capture_generation
from rs9.errors import ContractError, safe_details
from rs9.github import PublicClient
from rs9.hosted_commands import bind_commands, run_probes, runtime_environment
from rs9.hosted_platforms import select_payload
from rs9.hosted_smoke import (
    VERIFIER_SUPPORT,
    prepare_smoke,
    runtime_evidence,
    snapshot_nebular_runtime,
    verifier_import_preflight,
    verify_nebular_runtime,
    verify_source_readback,
)
from rs9.nebular_host_state import (
    HostStateError,
    compare_snapshots,
    operator_home,
    public_summary as host_state_public_summary,
    snapshot as snapshot_host_state,
    verify_harness_targets,
)
from rs9.operator import BOOTSTRAP, EXPECTATIONS, assert_release_expectations
from rs9.profiles import (
    TAURI_AUTHORITY_PROFILE,
    TAURI_SOURCES,
    evaluate_profile,
    selection_for_intent,
)
from rs9.records import record_sha256
from rs9.release_core import (
    ReleaseCapture,
    authenticate_release,
    authenticated_record_hash,
    authenticated_tree,
    digest,
)
from rs9.scratch import canonical as scratch_canonical
from rs9.tf_pypi_archive import AdmissionError, canonical, fail, physical_bytes, sha256
from rs9.tf_pypi_intake import NoRedirect
from rs9.tf_pypi_model import logical_identity, strict_json
from rs9.tf_pypi_remote import _public_url
from rs9.verify_wheel import (
    _venv_inventory,
    verify_double_build,
    verify_offline_venv_lifecycle,
    verify_wheel_record_bidirectional,
)
from rs9.wheel_native import (
    DISTRIBUTION_NAME,
    PACKAGE_NAME,
    PRODUCT_ID,
    REVIEWED_HELPERS,
    VERSION,
    build_native_wheel,
    extract_darwin_minimum_version,
    get_embedded_rs9_helpers,
    render_native_launcher,
    resolve_native_darwin_tag,
)

PROJECT = PRODUCT_ID
STELLAR_PROJECT = "theme-forge-stellar-burst"
WORKFLOW = "rs9-tfnf-pypi-publish.yml"
ENVIRONMENT = "pypi"
QUALIFY_BRANCH = "rs9-tfnf-pypi-hostqual1"
SYSTEM = "aarch64-darwin"
TARGET_TRIPLE = "aarch64-apple-darwin"
PROFILE = TAURI_AUTHORITY_PROFILE
APPROVAL_SCHEMA = "rs9.tf-pypi-native-candidate.v1alpha1"
CONSUMER_REPORT_SCHEMA = "rs9.tf-pypi-nebular-native-consumer.v1alpha1"
EXPECTED_WHEEL_TAG = "py3-none-macosx_13_0_arm64"
EXPECTED_WHEEL_FILENAME = "theme_forge_nebular_fusion-0.6.1-py3-none-macosx_13_0_arm64.whl"
EXPECTED_REQUIRES_PYTHON = ">=3.10"
EXPECTED_LICENSE_EXPRESSION = "AGPL-3.0-or-later"
EXPECTED_LICENSE_FILES = ("LICENSE", "NOTICE")
EXPECTED_COMMAND = "tfnf"
EXPECTED_MEMBER_COUNT = 17
EXPECTED_RUNTIME_MEMBER_COUNT = 1656
SUPERSEDED_PRELIMINARY_SHA256 = (
    "7d2bcbee182e496fa6221e1b2dad75e7899373aba7801f17a16a838f843ae82c"
)
SUPERSEDED_PRELIMINARY_SIZE = 46792719
SANDBOX_PROFILE = (
    '(version 1)(allow default)(deny network*)'
    '(allow process-exec (with no-sandbox) (literal "/bin/ps"))'
)
SANDBOX_PROFILE_SHA256 = (
    "f23692d03ec61ae6b4b3eb407c8b94882c2e7ca92b2bf66c755f7bdeb23f4219"
)
PS_PATH = "/bin/ps"
PYPI_DEFAULT_FILE_LIMIT = 100_000_000
MAX_JSON_BYTES = 32 * 1024 * 1024
MAX_NON_PAYLOAD_MEMBER_BYTES = 1024 * 1024
MAX_TOTAL_UNCOMPRESSED_BYTES = 50 * 1024 * 1024
READBACK_SCHEDULE_SECONDS = (0, 15, 30, 60, 120, 180)
STELLAR_FIXTURE_PREFIX = "docs/examples/v0.4/brand-system/core-minimal/"


def repo_root(repository: str | Path | None = None) -> Path:
    """Return physical repository root."""
    return Path(repository).resolve() if repository else Path(__file__).resolve().parents[2]


def approval_path(repository: str | Path | None = None) -> Path:
    """Return path to the committed Nebular candidate artifact approval manifest."""
    return repo_root(repository) / "operators/tf-pypi" / f"{PROJECT}-artifacts.json"


def compute_set_sha256(doc: Mapping[str, Any]) -> str:
    """Compute identity-preserving SHA-256 excluding publication_admitted and set_sha256."""
    filtered = {
        k: v
        for k, v in doc.items()
        if k not in ("publication_admitted", "set_sha256")
    }
    return sha256(canonical(filtered))


def validate_approval_schema(doc: Any) -> dict[str, Any]:
    """Validate structure and self-digest of a Nebular native candidate approval document."""
    if not isinstance(doc, dict):
        fail("APPROVAL_SCHEMA")
    required_keys = {
        "schema",
        "project",
        "distribution",
        "version",
        "workflow",
        "environment",
        "system",
        "wheel_tag",
        "macos_minimum_version",
        "requires_python",
        "python_floor_basis",
        "builder_environment",
        "command",
        "license_expression",
        "license_files",
        "commercial_license_authority",
        "authentication",
        "payload_asset",
        "embedded_helpers",
        "verifier_closure",
        "pypi_size_limit",
        "files",
        "members",
        "superseded_candidates",
        "builder_can_publish",
        "publication_admitted",
        "set_sha256",
    }
    if set(doc.keys()) != required_keys:
        fail("APPROVAL_SCHEMA")
    if (
        doc["schema"] != APPROVAL_SCHEMA
        or doc["project"] != PROJECT
        or doc["distribution"] != DISTRIBUTION_NAME
        or doc["version"] != VERSION
        or doc["workflow"] != WORKFLOW
        or doc["environment"] != ENVIRONMENT
        or doc["system"] != SYSTEM
        or doc["wheel_tag"] != EXPECTED_WHEEL_TAG
        or doc["requires_python"] != EXPECTED_REQUIRES_PYTHON
        or doc["command"] != EXPECTED_COMMAND
        or doc["license_expression"] != EXPECTED_LICENSE_EXPRESSION
        or doc["builder_can_publish"] is not False
        or type(doc["publication_admitted"]) is not bool
    ):
        fail("APPROVAL_SCHEMA")

    files = doc["files"]
    if (
        not isinstance(files, list)
        or len(files) != 1
        or not isinstance(files[0], dict)
        or set(files[0].keys()) != {"filename", "size", "sha256", "logical_sha256"}
        or files[0]["filename"] != EXPECTED_WHEEL_FILENAME
        or type(files[0]["size"]) is not int
        or files[0]["size"] <= 0
        or files[0]["size"] > PYPI_DEFAULT_FILE_LIMIT
        or not re.fullmatch(r"[0-9a-f]{64}", str(files[0]["sha256"]))
        or not re.fullmatch(r"[0-9a-f]{64}", str(files[0]["logical_sha256"]))
        or files[0]["sha256"] == SUPERSEDED_PRELIMINARY_SHA256
    ):
        fail("APPROVAL_SCHEMA")

    members = doc["members"]
    if not isinstance(members, list) or len(members) != EXPECTED_MEMBER_COUNT:
        fail("APPROVAL_SCHEMA")

    comm = doc["commercial_license_authority"]
    if (
        not isinstance(comm, dict)
        or comm.get("path") != "COMMERCIAL-LICENSE.md"
        or comm.get("shipped_in_wheel") is not False
        or not re.fullmatch(r"[0-9a-f]{64}", str(comm.get("sha256", "")))
    ):
        fail("APPROVAL_SCHEMA")

    if doc["set_sha256"] != compute_set_sha256(doc):
        fail("APPROVAL_DIGEST")
    return doc


def load_approval(repository: str | Path | None = None) -> dict[str, Any]:
    """Load and validate the committed Nebular candidate artifact approval manifest."""
    path = approval_path(repository)
    if not path.is_file():
        fail("APPROVAL_ABSENT")
    data = physical_bytes(path, limit=1024 * 1024)
    return validate_approval_schema(strict_json(data))


def authenticate_captured(
    capture_dir: str | Path,
    *,
    project: str = PROJECT,
    repository: str | Path | None = None,
) -> tuple[ReleaseCapture, dict[str, Any], dict[str, Any]]:
    """Authenticate a retained or fresh release capture directory in-process against bootstrap and operator expectations."""
    root = repo_root(repository)
    c_dir = Path(capture_dir)
    if any(p.is_symlink() for p in (c_dir, *c_dir.parents)):
        fail("CAPTURE_SYMLINK")
    manifest_path = root / BOOTSTRAP
    manifest_bytes = physical_bytes(manifest_path, limit=1024 * 1024)
    manifest_sha = digest(manifest_bytes)
    try:
        configs = checked_bootstrap_configurations(
            manifest_path, approved_manifests=[manifest_sha]
        )
        matched = [
            (row, intent)
            for row, intent in configs
            if intent["project"]["id"] == project
        ]
        if len(matched) != 1:
            fail("BOOTSTRAP_PROJECT")
        row, intent = matched[0]
        selection = selection_for_intent(intent)
        capture = authenticate_release(selection, c_dir)
        expectations_raw = physical_bytes(root / EXPECTATIONS, limit=1024 * 1024)
        expectations = strict_json(expectations_raw)["projects"]
        exp_rows = [r for r in expectations if r["repository"] == row["repository"]]
        if len(exp_rows) != 1:
            fail("EXPECTATIONS_PROJECT")
        assert_release_expectations(capture, exp_rows[0])
        intent = load_bootstrap(
            manifest_path, capture, approved_manifests=[manifest_sha]
        )
        require_configuration_authority(capture, intent)
        expected_profile = intent["release"]["evidence"]["profile"]
        if project == PROJECT and expected_profile != PROFILE:
            fail("PROFILE_MISMATCH")
        profile = evaluate_profile(capture, expected_profile, intent)
    except ContractError as exc:
        fail(f"AUTH_{exc.code}")

    if project == PROJECT:
        # Enforce tagged source closure and legal separation
        for required_src in TAURI_SOURCES:
            if required_src not in capture.source:
                fail("MISSING_TAGGED_SOURCE")
        icon_path = intent.get("desktop", {}).get("icon", {}).get("path")
        if not icon_path or icon_path not in capture.source:
            fail("MISSING_TAGGED_ICON")
        if intent.get("license", {}).get("files") != list(EXPECTED_LICENSE_FILES):
            fail("LEGAL_FILE_POLICY")
        lic_section = (
            profile.get("sections", {})
            .get("legacy_ingestion", {})
            .get("license", {})
        )
        tagged_decls = [
            d
            for d in lic_section.get("declarations", [])
            if isinstance(d, dict) and str(d.get("source", "")).startswith("tagged:")
        ]
        if (
            lic_section.get("status") != "consistent"
            or lic_section.get("authority") != "tagged-repository"
            or not tagged_decls
            or any(d.get("expression") != EXPECTED_LICENSE_EXPRESSION for d in tagged_decls)
        ):
            fail("LICENSE_INCONSISTENT")

    return capture, intent, profile


def bind_prepared_closure(
    closure_dir: str | Path,
    nebular_capture: ReleaseCapture,
    stellar_capture: ReleaseCapture,
    *,
    scratch_dir: str | Path | None = None,
) -> dict[str, Any]:
    """Validate retained or freshly prepared verifier source closure against authenticated Git trees."""
    c_dir = Path(closure_dir)
    if any(p.is_symlink() for p in (c_dir, *c_dir.parents)):
        fail("CLOSURE_SYMLINK")
    bindings_path = c_dir / "source-bindings.json"
    source_dir = c_dir / "source"
    if not bindings_path.is_file() or not source_dir.is_dir():
        fail("CLOSURE_ABSENT")

    raw_bindings = physical_bytes(bindings_path, limit=4 * 1024 * 1024)
    records = strict_json(raw_bindings)
    if not isinstance(records, list) or not records or len(records) > 1000:
        fail("CLOSURE_SCHEMA")

    neb_commit = nebular_capture.record["tag"]["commit"]
    stl_commit = stellar_capture.record["tag"]["commit"]
    support_paths = set(VERIFIER_SUPPORT.get(neb_commit) or ())
    if not support_paths:
        fail("CLOSURE_UNREVIEWED_TAG")

    neb_tree = {
        entry["path"]: entry
        for entry in authenticated_tree(nebular_capture)["tree"]
        if entry.get("type") == "blob"
    }
    stl_tree = {
        entry["path"]: entry
        for entry in authenticated_tree(stellar_capture)["tree"]
        if entry.get("type") == "blob"
    }

    expected_neb_paths = {
        p
        for p in neb_tree
        if p in support_paths or p.startswith(("tools/", "apps/studio/tools/"))
    }
    expected_stl_paths = {
        p for p in stl_tree if p.startswith(STELLAR_FIXTURE_PREFIX)
    }
    if not expected_neb_paths or not expected_stl_paths:
        fail("CLOSURE_TREE_EMPTY")

    seen_neb: set[str] = set()
    seen_stl: set[str] = set()
    total_size = 0
    normalized_rows: list[dict[str, Any]] = []

    for row in records:
        if not isinstance(row, dict) or set(row.keys()) != {
            "path",
            "blob",
            "sha256",
            "size",
            "role",
            "tag_commit",
        }:
            fail("CLOSURE_ROW_SCHEMA")
        path = row["path"]
        role = row["role"]
        commit = row["tag_commit"]
        size = row["size"]
        blob = row["blob"]
        sha = row["sha256"]
        if (
            not isinstance(path, str)
            or not isinstance(role, str)
            or not isinstance(commit, str)
            or type(size) is not int
            or size < 0
            or size > 2 * 1024 * 1024
            or not re.fullmatch(r"[0-9a-f]{40}", str(blob))
            or not re.fullmatch(r"[0-9a-f]{64}", str(sha))
        ):
            fail("CLOSURE_ROW_SCHEMA")

        if role == "fixture":
            if commit != stl_commit or path not in expected_stl_paths or path in seen_stl:
                fail("CLOSURE_FIXTURE_BINDING")
            tree_entry = stl_tree[path]
            seen_stl.add(path)
        elif role in ("verifier-module", "verifier-support", "application-smoke"):
            if commit != neb_commit or path not in expected_neb_paths or path in seen_neb:
                fail("CLOSURE_VERIFIER_BINDING")
            expected_role = (
                "verifier-support"
                if path in support_paths
                else "application-smoke"
                if path.endswith("/native-rc-smoke.mjs")
                else "verifier-module"
            )
            if role != expected_role:
                fail("CLOSURE_ROLE_MISMATCH")
            tree_entry = neb_tree[path]
            seen_neb.add(path)
        else:
            fail("CLOSURE_UNKNOWN_ROLE")

        if (
            tree_entry.get("mode") not in ("100644", "100755")
            or tree_entry.get("sha") != blob
            or tree_entry.get("size") != size
        ):
            fail("CLOSURE_TREE_MISMATCH")

        total_size += size
        if total_size > 32 * 1024 * 1024:
            fail("CLOSURE_SIZE_LIMIT")
        normalized_rows.append(dict(row))

    if seen_neb != expected_neb_paths or seen_stl != expected_stl_paths:
        fail("CLOSURE_INCOMPLETE")

    tools_dir = source_dir / "tools"
    if not (tools_dir / "native-rc-smoke.mjs").is_file():
        tools_dir = source_dir / "apps/studio/tools"
    if not all(
        (tools_dir / p).is_file()
        for p in ("native-rc-smoke.mjs", "sidecar-common.mjs", "sidecar-verify.mjs")
    ):
        fail("CLOSURE_TOOLS_MISSING")

    prepared: dict[str, Any] = {
        "source": source_dir,
        "tools": tools_dir,
        "records": records,
        "scratch": Path(scratch_dir) if scratch_dir else c_dir / "scratch",
        "capture": nebular_capture,
        "label": "darwin-arm64",
        "family": "darwin-arm64",
        "records_sha256": sha256(
            canonical(sorted(normalized_rows, key=lambda r: (r["role"], r["path"])))
        ),
        "source_bindings_sha256": sha256(raw_bindings),
        "file_count": len(normalized_rows),
        "total_bytes": total_size,
    }
    try:
        verify_source_readback(prepared)
    except ContractError as exc:
        fail(f"CLOSURE_READBACK_{exc.code}")
    return prepared


def _validate_zip_member_path(member: zipfile.ZipInfo) -> str:
    path = member.filename
    if (
        member.orig_filename != path
        or not path
        or not path.isascii()
        or "\\" in path
        or "\x00" in path
        or ":" in path
        or str(PurePosixPath(path)) != path
        or PurePosixPath(path).is_absolute()
    ):
        fail("WHEEL_PATH")
    if any(ord(c) < 32 or ord(c) == 127 for c in path):
        fail("WHEEL_PATH")
    if any(part in ("", ".", "..") for part in path.split("/")):
        fail("WHEEL_PATH")
    return path


def _verify_record_dict(files: Mapping[str, tuple[bytes, int]], dist_info: str) -> None:
    record_path = f"{dist_info}/RECORD"
    if record_path not in files:
        fail("WHEEL_RECORD")
    try:
        text = files[record_path][0].decode("utf-8")
        rows = list(csv.reader(io.StringIO(text, newline=""), strict=True))
    except (UnicodeDecodeError, csv.Error):
        fail("WHEEL_RECORD")
    seen: set[str] = set()
    for row in rows:
        if len(row) != 3 or row[0] in seen or row[0] not in files:
            fail("WHEEL_RECORD")
        seen.add(row[0])
        if row[0] == record_path:
            if row[1:] != ["", ""]:
                fail("WHEEL_RECORD")
            continue
        body = files[row[0]][0]
        b64 = base64.urlsafe_b64encode(hashlib.sha256(body).digest()).decode("ascii").rstrip("=")
        if row[1:] != [f"sha256={b64}", str(len(body))]:
            fail("WHEEL_RECORD")
    if seen != set(files.keys()):
        fail("WHEEL_RECORD")


TOP_LEVEL_PLIST_RE = re.compile(r"(?:\./)?(?:[^/]+\.app/)?Contents/Info\.plist")


def _extract_plist_from_payload_tar(payload_bytes: bytes) -> bytes:
    plist_bytes: bytes | None = None
    try:
        with gzip.GzipFile(fileobj=io.BytesIO(payload_bytes)) as gz, tarfile.open(
            fileobj=gz, mode="r|"
        ) as tf:
            for member in tf:
                if TOP_LEVEL_PLIST_RE.fullmatch(member.name):
                    if not member.isfile():
                        fail("WHEEL_PLIST_INVALID")
                    if plist_bytes is not None:
                        fail("WHEEL_PLIST_DUPLICATE")
                    extracted = tf.extractfile(member)
                    if extracted is None:
                        fail("WHEEL_PLIST_INVALID")
                    data = extracted.read(256 * 1024 + 1)
                    if len(data) > 256 * 1024:
                        fail("WHEEL_PLIST_INVALID")
                    plist_bytes = data
    except AdmissionError:
        raise
    except Exception:
        fail("WHEEL_PAYLOAD_ARCHIVE")
    if plist_bytes is None:
        fail("WHEEL_PLIST_MISSING")
    return plist_bytes


def inspect_candidate(
    wheel_path: str | Path,
    *,
    capture: ReleaseCapture | None = None,
    profile_result: Mapping[str, Any] | None = None,
    approval: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Strictly inspect a native Nebular wheel against size, member, metadata, legal, helper, and provenance contracts."""
    if approval is not None:
        validate_approval_schema(approval)
        max_file_limit = min(PYPI_DEFAULT_FILE_LIMIT, approval["files"][0]["size"])
        expected_payload_size = approval["payload_asset"]["size"]
        expected_payload_name = approval["payload_asset"]["name"]
        expected_payload_sha256 = approval["payload_asset"]["sha256"]
        expected_manifest_sha256 = approval["payload_asset"]["payload_manifest_sha256"]
        expected_release_sha256 = approval["authentication"]["nebular"]["release_record_sha256"]
        expected_launcher_rel = approval["payload_asset"]["launcher_path"]
    elif capture is not None:
        if profile_result is None:
            fail("PROFILE_REQUIRED")
        matched_asset = select_payload(capture, SYSTEM, allow_any=False)
        max_file_limit = PYPI_DEFAULT_FILE_LIMIT
        expected_payload_size = matched_asset["size"]
        expected_payload_name = matched_asset["name"]
        expected_payload_sha256 = matched_asset["sha256"]
        expected_manifest_sha256 = matched_asset["payload_manifest_sha256"]
        expected_release_sha256 = authenticated_record_hash(capture)
        tfnf_launcher = matched_asset.get("launchers", {}).get("tfnf", {})
        expected_launcher_rel = (
            tfnf_launcher.get("path") if isinstance(tfnf_launcher, dict) else tfnf_launcher
        )
    else:
        fail("INSPECTION_AUTHORITY_REQUIRED")

    w_path = Path(wheel_path)
    if w_path.name != EXPECTED_WHEEL_FILENAME:
        fail("WHEEL_FILENAME")

    wheel_bytes = physical_bytes(w_path, limit=max_file_limit)
    if len(wheel_bytes) > PYPI_DEFAULT_FILE_LIMIT:
        fail("WHEEL_FILE_LIMIT")
    wheel_sha256 = sha256(wheel_bytes)
    if wheel_sha256 == SUPERSEDED_PRELIMINARY_SHA256:
        fail("SUPERSEDED_CANDIDATE")

    dist_info = f"{PACKAGE_NAME}-{VERSION}.dist-info"
    payload_member_path = f"{PACKAGE_NAME}/payload/{expected_payload_name}"
    embedded_helpers = get_embedded_rs9_helpers()
    expected_member_paths = {
        f"{dist_info}/METADATA",
        f"{dist_info}/RECORD",
        f"{dist_info}/WHEEL",
        f"{dist_info}/entry_points.txt",
        f"{dist_info}/licenses/LICENSE",
        f"{dist_info}/licenses/NOTICE",
        f"{PACKAGE_NAME}/__init__.py",
        f"{PACKAGE_NAME}/launcher.py",
        f"{PACKAGE_NAME}/_rs9/provenance.json",
        f"{PACKAGE_NAME}/payload/manifest.json",
        payload_member_path,
        *(f"{PACKAGE_NAME}/_isolated/{rel}" for rel in embedded_helpers),
    }

    files: dict[str, tuple[bytes, int]] = {}
    member_rows: list[dict[str, Any]] = []
    folded_seen: set[str] = set()
    total_uncompressed = 0

    try:
        with zipfile.ZipFile(io.BytesIO(wheel_bytes), "r") as zf:
            infolist = zf.infolist()
            if len(infolist) != EXPECTED_MEMBER_COUNT or zf.comment:
                fail("WHEEL_STRUCTURE")
            for info in infolist:
                path = _validate_zip_member_path(info)
                folded = path.casefold()
                if folded in folded_seen:
                    fail("WHEEL_DUPLICATE")
                folded_seen.add(folded)

                mode_full = info.external_attr >> 16
                if (
                    stat.S_IFMT(mode_full) != stat.S_IFREG
                    or stat.S_IMODE(mode_full) != 0o644
                    or info.is_dir()
                    or info.flag_bits & 1
                    or info.compress_type != zipfile.ZIP_DEFLATED
                    or info.create_system != 3
                    or info.date_time != (2026, 1, 1, 0, 0, 0)
                ):
                    fail("WHEEL_MEMBER_ATTR")

                member_cap = (
                    expected_payload_size
                    if path == payload_member_path
                    else MAX_NON_PAYLOAD_MEMBER_BYTES
                )
                if info.file_size < 0 or info.file_size > member_cap:
                    fail("WHEEL_MEMBER_LIMIT")

                with zf.open(info, "r") as stream:
                    body = stream.read(member_cap + 1)
                if len(body) != info.file_size or len(body) > member_cap:
                    fail("WHEEL_MEMBER_LIMIT")

                total_uncompressed += len(body)
                if total_uncompressed > MAX_TOTAL_UNCOMPRESSED_BYTES:
                    fail("WHEEL_TOTAL_LIMIT")

                files[path] = (body, 0o644)
                member_rows.append(
                    {
                        "path": path,
                        "size": len(body),
                        "compressed_size": info.compress_size,
                        "sha256": sha256(body),
                        "mode": 0o644,
                    }
                )
    except AdmissionError:
        raise
    except (zipfile.BadZipFile, OSError, ValueError, RuntimeError):
        fail("WHEEL_CORRUPT")

    for path in files:
        if any(
            parent.as_posix() in files
            for parent in PurePosixPath(path).parents
            if parent.as_posix() != "."
        ):
            fail("WHEEL_ANCESTOR_COLLISION")

    if set(files.keys()) != expected_member_paths:
        fail("WHEEL_MEMBER_SET")

    member_rows.sort(key=lambda r: r["path"])
    _verify_record_dict(files, dist_info)
    try:
        verify_wheel_record_bidirectional(w_path)
    except ContractError:
        fail("WHEEL_RECORD")

    # Verify METADATA
    meta_msg = BytesParser().parsebytes(files[f"{dist_info}/METADATA"][0])
    if (
        meta_msg.get("Metadata-Version") != "2.4"
        or meta_msg.get("Name") != DISTRIBUTION_NAME
        or meta_msg.get("Version") != VERSION
        or meta_msg.get("Requires-Python") != EXPECTED_REQUIRES_PYTHON
        or meta_msg.get("License-Expression") != EXPECTED_LICENSE_EXPRESSION
        or meta_msg.get_all("License-File") != list(EXPECTED_LICENSE_FILES)
    ):
        fail("WHEEL_METADATA")

    # Verify WHEEL tag and purelib flag
    wheel_msg = BytesParser().parsebytes(files[f"{dist_info}/WHEEL"][0])
    if (
        wheel_msg.get("Wheel-Version") != "1.0"
        or wheel_msg.get("Root-Is-Purelib") != "false"
        or wheel_msg.get_all("Tag") != [EXPECTED_WHEEL_TAG]
    ):
        fail("WHEEL_TAG_METADATA")

    # Verify entry_points.txt
    expected_ep = f"[console_scripts]\ntfnf = {PACKAGE_NAME}.launcher:main_tfnf\n".encode("utf-8")
    if files[f"{dist_info}/entry_points.txt"][0] != expected_ep:
        fail("WHEEL_ENTRY_POINTS")

    # Verify payload archive & Info.plist floor
    payload_bytes = files[payload_member_path][0]
    if len(payload_bytes) != expected_payload_size or sha256(payload_bytes) != expected_payload_sha256:
        fail("WHEEL_PAYLOAD_MISMATCH")
    plist_bytes = _extract_plist_from_payload_tar(payload_bytes)
    try:
        derived_tag = resolve_native_darwin_tag(plist_bytes)
        plist_major, plist_minor = extract_darwin_minimum_version(plist_bytes)
    except ContractError:
        fail("WHEEL_PLIST_INVALID")
    if derived_tag != EXPECTED_WHEEL_TAG or f"{plist_major}.{plist_minor}" != "13.0":
        fail("WHEEL_DARWIN_FLOOR")

    # Verify embedded manifest.json
    manifest_bytes = files[f"{PACKAGE_NAME}/payload/manifest.json"][0]
    manifest_doc = strict_json(manifest_bytes)
    if (
        not isinstance(manifest_doc, dict)
        or manifest_doc.get("manifest_sha256") != expected_manifest_sha256
    ):
        fail("WHEEL_MANIFEST_MISMATCH")
    if capture is not None:
        matched_asset = select_payload(capture, SYSTEM, allow_any=False)
        if manifest_bytes != scratch_canonical(capture.manifests[matched_asset["id"]]):
            fail("WHEEL_MANIFEST_MISMATCH")

    # Verify embedded helpers byte-for-byte
    for rel_path, expected_helper_bytes in embedded_helpers.items():
        if files[f"{PACKAGE_NAME}/_isolated/{rel_path}"][0] != expected_helper_bytes:
            fail("WHEEL_HELPER_DRIFT")

    # Verify rendered launcher byte-for-byte
    expected_launcher_bytes = render_native_launcher(
        expected_payload_name,
        expected_manifest_sha256,
        expected_payload_sha256,
        expected_launcher_rel,
        platform_family="darwin",
        target_arch="aarch64",
    ).encode("utf-8")
    if files[f"{PACKAGE_NAME}/launcher.py"][0] != expected_launcher_bytes:
        fail("WHEEL_LAUNCHER_DRIFT")

    # Verify legal files against capture or approval
    for lic_name in EXPECTED_LICENSE_FILES:
        lic_bytes = files[f"{dist_info}/licenses/{lic_name}"][0]
        if capture is not None and capture.source.get(lic_name) != lic_bytes:
            fail("WHEEL_LEGAL_MISMATCH")
        if approval is not None:
            lic_row = next(
                (r for r in approval["license_files"] if r["path"] == lic_name),
                None,
            )
            if (
                lic_row is None
                or lic_row["size"] != len(lic_bytes)
                or lic_row["sha256"] != sha256(lic_bytes)
            ):
                fail("WHEEL_LEGAL_MISMATCH")

    # Verify provenance.json
    prov_doc = strict_json(files[f"{PACKAGE_NAME}/_rs9/provenance.json"][0])
    if (
        not isinstance(prov_doc, dict)
        or prov_doc.get("schema") != "rs9.wheel-provenance.v1alpha1"
        or prov_doc.get("product_id") != PROJECT
        or prov_doc.get("distribution_name") != DISTRIBUTION_NAME
        or prov_doc.get("version") != VERSION
        or prov_doc.get("wheel_tag") != EXPECTED_WHEEL_TAG
        or prov_doc.get("release_record_sha256") != expected_release_sha256
        or prov_doc.get("fixture_only") is not False
        or prov_doc.get("candidate_only") is not False
        or prov_doc.get("can_publish") is not False
        or prov_doc.get("payload_archive_sha256") != expected_payload_sha256
        or prov_doc.get("manifest_sha256") != expected_manifest_sha256
        or prov_doc.get("helper_source_sha256")
        != {k: sha256(v) for k, v in embedded_helpers.items()}
    ):
        fail("WHEEL_PROVENANCE")

    file_record = {
        "filename": EXPECTED_WHEEL_FILENAME,
        "size": len(wheel_bytes),
        "sha256": wheel_sha256,
        "logical_sha256": logical_identity(files),
    }

    if approval is not None:
        if file_record != approval["files"][0] or member_rows != approval["members"]:
            fail("APPROVAL_MISMATCH")

    return {
        "file": file_record,
        "members": member_rows,
        "macos_minimum_version": f"{plist_major}.{plist_minor}",
    }


def _github_client(
    client: Any | None = None, *, environ: Mapping[str, str] | None = None
) -> Any:
    """Return supplied client or construct a PublicClient using RS9_GITHUB_READ_TOKEN in GitHub Actions."""
    if client is not None:
        return client
    env = environ if environ is not None else os.environ
    token = (
        env.get("RS9_GITHUB_READ_TOKEN")
        if env.get("GITHUB_ACTIONS") == "true"
        else None
    )
    return PublicClient(api_token=token)


PY311_PLUS_STDLIB_MODULES: frozenset[str] = frozenset({"tomllib", "wsgiref.types"})
PY311_PLUS_STDLIB_ATTRS: frozenset[str] = frozenset(
    {
        "UTC",
        "StrEnum",
        "ReprEnum",
        "Self",
        "Never",
        "LiteralString",
        "Required",
        "NotRequired",
        "TypeVarTuple",
        "Unpack",
        "assert_never",
        "assert_type",
        "reveal_type",
        "dataclass_transform",
        "override",
        "TaskGroup",
        "Runner",
        "timeout_at",
        "file_digest",
        "cbrt",
        "exp2",
        "sumprod",
    }
)
PY311_PLUS_BUILTINS: frozenset[str] = frozenset({"ExceptionGroup", "BaseExceptionGroup"})
PY311_PLUS_QUALIFIED_ATTRS: frozenset[tuple[str, str]] = frozenset(
    {
        ("datetime", "UTC"),
        ("contextlib", "chdir"),
        ("asyncio", "timeout"),
        ("asyncio", "timeout_at"),
        ("asyncio", "TaskGroup"),
        ("asyncio", "Runner"),
        ("enum", "StrEnum"),
        ("enum", "ReprEnum"),
        ("enum", "verify"),
        ("operator", "call"),
        ("hashlib", "file_digest"),
        ("typing", "LiteralString"),
        ("typing", "Required"),
        ("typing", "NotRequired"),
        ("typing", "Self"),
        ("typing", "Never"),
        ("typing", "TypeVarTuple"),
        ("typing", "Unpack"),
        ("typing", "assert_never"),
        ("typing", "assert_type"),
        ("typing", "reveal_type"),
        ("typing", "dataclass_transform"),
        ("typing", "override"),
    }
)


def analyze_embedded_python_floor(
    extra_python_sources: Mapping[str, bytes] | None = None,
) -> dict[str, str]:
    """Statically inspect embedded helpers and package Python files to confirm the 3.10 syntax floor and run heuristic >=3.11 stdlib/builtin denylist checks."""
    helpers = get_embedded_rs9_helpers()
    default_package_sources: dict[str, bytes] = {
        f"{PACKAGE_NAME}/__init__.py": f'"""Native wrapper distribution for {PROJECT}."""\n\n__version__ = "{VERSION}"\n'.encode(
            "utf-8"
        ),
        f"{PACKAGE_NAME}/launcher.py": render_native_launcher(
            "payload.tar.gz",
            "0" * 64,
            "0" * 64,
            "Theme Forge Nebular Fusion.app/Contents/Resources/bin/tfnf",
            platform_family="darwin",
            target_arch="aarch64",
        ).encode("utf-8"),
    }
    sources: dict[str, bytes] = {
        **helpers,
        **(
            dict(extra_python_sources)
            if extra_python_sources is not None
            else default_package_sources
        ),
    }
    bitor_sites: list[tuple[str, int]] = []

    for rel_path, raw in sorted(sources.items()):
        try:
            src = raw.decode("utf-8")
            tree = ast.parse(src, filename=rel_path, feature_version=(3, 10))
        except (UnicodeDecodeError, SyntaxError):
            fail("PYTHON_FLOOR_SYNTAX")
        has_future_annotations = any(
            isinstance(node, ast.ImportFrom)
            and node.module == "__future__"
            and any(alias.name == "annotations" for alias in node.names)
            for node in tree.body
        )
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    if alias.name in PY311_PLUS_STDLIB_MODULES:
                        fail("PYTHON_FLOOR_STDLIB")
            elif isinstance(node, ast.ImportFrom):
                mod = node.module or ""
                if mod in PY311_PLUS_STDLIB_MODULES:
                    fail("PYTHON_FLOOR_STDLIB")
                for alias in node.names:
                    if (
                        alias.name in PY311_PLUS_STDLIB_ATTRS
                        or alias.name in PY311_PLUS_BUILTINS
                        or (mod, alias.name) in PY311_PLUS_QUALIFIED_ATTRS
                    ):
                        fail("PYTHON_FLOOR_STDLIB")
            elif isinstance(node, ast.Attribute):
                if node.attr in PY311_PLUS_STDLIB_ATTRS or (
                    isinstance(node.value, ast.Name)
                    and (node.value.id, node.attr) in PY311_PLUS_QUALIFIED_ATTRS
                ):
                    fail("PYTHON_FLOOR_STDLIB")
            elif isinstance(node, ast.Name) and node.id in PY311_PLUS_BUILTINS:
                fail("PYTHON_FLOOR_STDLIB")
            elif isinstance(node, ast.FunctionDef) and not has_future_annotations:
                for arg in node.args.args + node.args.kwonlyargs:
                    if isinstance(arg.annotation, ast.BinOp) and isinstance(
                        arg.annotation.op, ast.BitOr
                    ):
                        prefix = "src/" if rel_path in helpers else ""
                        bitor_sites.append((f"{prefix}{rel_path}", arg.annotation.lineno))

    if not bitor_sites:
        fail("PYTHON_FLOOR_ANALYSIS")
    first_path, first_line = bitor_sites[0]
    return {
        "static_floor": "3.10",
        "decisive_construct": (
            f"{first_path}:{first_line} evaluated int | None union annotation without postponed annotations"
        ),
        "analysis_scope": "static-syntax-and-runtime-annotation-analysis-plus-lazy-import-reachability",
    }


def verify_cross_zlib_wheel(
    wheel_path: str | Path,
    alternate_python: str | Path = Path("/usr/bin/python3"),
) -> dict[str, Any]:
    """Re-deflate wheel members in a stdlib-only subprocess on alternate_python to prove cross-zlib ZIP equality."""
    w_path = Path(wheel_path).resolve()
    primary_bytes = physical_bytes(w_path, limit=PYPI_DEFAULT_FILE_LIMIT)
    primary_sha = sha256(primary_bytes)
    alt_py = Path(alternate_python)
    if not alt_py.is_file():
        return {
            "status": "alternate-interpreter-absent",
            "python_version": None,
            "zlib_version": None,
            "sha256": primary_sha,
            "size": len(primary_bytes),
            "matches_primary": None,
            "verified_zlib_versions": [zlib.ZLIB_VERSION],
        }

    probe_code = (
        "import hashlib, io, json, platform, stat, sys, zipfile, zlib\n"
        "src = sys.argv[1]\n"
        "with zipfile.ZipFile(src, 'r') as zf:\n"
        "    items = [(i.filename, zf.read(i.filename)) for i in zf.infolist()]\n"
        "buf = io.BytesIO()\n"
        "with zipfile.ZipFile(buf, 'w', compression=zipfile.ZIP_DEFLATED) as out:\n"
        "    for name, data in items:\n"
        "        zi = zipfile.ZipInfo(filename=name, date_time=(2026, 1, 1, 0, 0, 0))\n"
        "        zi.compress_type = zipfile.ZIP_DEFLATED\n"
        "        zi.create_system = 3\n"
        "        zi.external_attr = (0o644 | stat.S_IFREG) << 16\n"
        "        out.writestr(zi, data, compresslevel=9)\n"
        "raw = buf.getvalue()\n"
        "print(json.dumps({\n"
        "    'python_version': platform.python_version(),\n"
        "    'zlib_version': zlib.ZLIB_VERSION,\n"
        "    'sha256': hashlib.sha256(raw).hexdigest(),\n"
        "    'size': len(raw),\n"
        "}))\n"
    )
    try:
        res = subprocess.run(
            [str(alt_py), "-I", "-B", "-c", probe_code, str(w_path)],
            capture_output=True,
            timeout=60,
            check=True,
        )
        info = strict_json(res.stdout)
    except (subprocess.SubprocessError, OSError, AdmissionError):
        fail("CROSS_ZLIB_EXEC")

    if info.get("sha256") != primary_sha or info.get("size") != len(primary_bytes):
        fail("CROSS_ZLIB_DRIFT")

    verified_versions = sorted({zlib.ZLIB_VERSION, str(info["zlib_version"])})
    return {
        "status": "verified" if len(verified_versions) >= 2 else "single-zlib-only",
        "python_version": str(info["python_version"]),
        "zlib_version": str(info["zlib_version"]),
        "sha256": primary_sha,
        "size": len(primary_bytes),
        "matches_primary": True,
        "verified_zlib_versions": verified_versions,
    }


def approval_document(
    wheel_path: str | Path,
    *,
    nebular_capture: ReleaseCapture,
    nebular_profile: Mapping[str, Any],
    stellar_capture: ReleaseCapture,
    stellar_profile: Mapping[str, Any],
    prepared_closure: Mapping[str, Any],
    repository: str | Path | None = None,
    alternate_python: str | Path = Path("/usr/bin/python3"),
    executed_interpreters: Mapping[str, str] | None = None,
) -> dict[str, Any]:
    """Construct the deterministic candidate approval document from authenticated captures and built wheel."""
    inspected = inspect_candidate(
        wheel_path,
        capture=nebular_capture,
        profile_result=nebular_profile,
    )
    root = repo_root(repository)
    bootstrap_sha256 = sha256(physical_bytes(root / BOOTSTRAP, limit=1024 * 1024))
    matched_asset = select_payload(nebular_capture, SYSTEM, allow_any=False)
    embedded_helpers = get_embedded_rs9_helpers()
    comm_bytes = nebular_capture.source["COMMERCIAL-LICENSE.md"]
    file_rec = inspected["file"]
    with zipfile.ZipFile(wheel_path, "r") as zf:
        wheel_py_sources = {
            name: zf.read(name)
            for name in (
                f"{PACKAGE_NAME}/__init__.py",
                f"{PACKAGE_NAME}/launcher.py",
            )
        }
    floor_basis = analyze_embedded_python_floor(extra_python_sources=wheel_py_sources)
    cross_zlib = verify_cross_zlib_wheel(wheel_path, alternate_python=alternate_python)
    if (
        cross_zlib.get("matches_primary") is not True
        or len(cross_zlib.get("verified_zlib_versions") or ()) < 2
        or not isinstance(cross_zlib.get("python_version"), str)
        or not cross_zlib["python_version"]
    ):
        fail("CROSS_ZLIB_UNVERIFIED")
    py_ver = platform.python_version()
    py_minor = f"{sys.version_info.major}.{sys.version_info.minor}"
    alt_py_ver = cross_zlib["python_version"]
    interp_map = (
        dict(executed_interpreters)
        if executed_interpreters is not None
        else {
            alt_py_ver: "refused-by-pip-requires-python-before-install",
            "3.10_to_3.12": "not-executed-locally",
            py_ver: "full-installed-lifecycle-sidecar-and-darwin-scenario-a-passed",
        }
    )

    doc: dict[str, Any] = {
        "schema": APPROVAL_SCHEMA,
        "project": PROJECT,
        "distribution": DISTRIBUTION_NAME,
        "version": VERSION,
        "workflow": WORKFLOW,
        "environment": ENVIRONMENT,
        "system": SYSTEM,
        "wheel_tag": EXPECTED_WHEEL_TAG,
        "macos_minimum_version": inspected["macos_minimum_version"],
        "requires_python": EXPECTED_REQUIRES_PYTHON,
        "python_floor_basis": {
            **floor_basis,
            "executed_interpreters": interp_map,
        },
        "builder_environment": {
            "python_minor": py_minor,
            "python_version": py_ver,
            "zlib_version": zlib.ZLIB_VERSION,
            "cross_zlib_verified_versions": cross_zlib["verified_zlib_versions"],
        },
        "command": EXPECTED_COMMAND,
        "license_expression": EXPECTED_LICENSE_EXPRESSION,
        "license_files": [
            {
                "path": name,
                "size": len(nebular_capture.source[name]),
                "sha256": sha256(nebular_capture.source[name]),
            }
            for name in EXPECTED_LICENSE_FILES
        ],
        "commercial_license_authority": {
            "path": "COMMERCIAL-LICENSE.md",
            "size": len(comm_bytes),
            "sha256": sha256(comm_bytes),
            "shipped_in_wheel": False,
        },
        "authentication": {
            "bootstrap_sha256": bootstrap_sha256,
            "nebular": {
                "project": PROJECT,
                "repository": nebular_capture.record["repository"]["full_name"],
                "tag": nebular_capture.record["release"]["tag"],
                "tag_commit": nebular_capture.record["tag"]["commit"],
                "tag_tree": nebular_capture.record["tag"]["tree"],
                "profile": PROFILE,
                "release_record_sha256": authenticated_record_hash(nebular_capture),
                "profile_result_sha256": record_sha256(nebular_profile),
            },
            "stellar_fixture": {
                "project": STELLAR_PROJECT,
                "repository": stellar_capture.record["repository"]["full_name"],
                "tag": stellar_capture.record["release"]["tag"],
                "tag_commit": stellar_capture.record["tag"]["commit"],
                "tag_tree": stellar_capture.record["tag"]["tree"],
                "profile": stellar_profile["profile"],
                "release_record_sha256": authenticated_record_hash(stellar_capture),
                "profile_result_sha256": record_sha256(stellar_profile),
            },
        },
        "payload_asset": {
            "id": matched_asset["id"],
            "name": matched_asset["name"],
            "github_asset_id": matched_asset["github_asset_id"],
            "size": matched_asset["size"],
            "sha256": matched_asset["sha256"],
            "payload_manifest_sha256": matched_asset["payload_manifest_sha256"],
            "member_count": matched_asset["member_count"],
            "executable_path": matched_asset["commands"]["tfnf"]["path"],
            "executable_sha256": matched_asset["commands"]["tfnf"]["sha256"],
            "launcher_path": matched_asset["launchers"]["tfnf"]["path"],
            "launcher_sha256": matched_asset["launchers"]["tfnf"]["sha256"],
        },
        "embedded_helpers": {
            name: sha256(data) for name, data in sorted(embedded_helpers.items())
        },
        "verifier_closure": {
            "file_count": prepared_closure["file_count"],
            "total_bytes": prepared_closure["total_bytes"],
            "records_sha256": prepared_closure["records_sha256"],
            "source_bindings_sha256": prepared_closure["source_bindings_sha256"],
        },
        "pypi_size_limit": {
            "default_limit_bytes": PYPI_DEFAULT_FILE_LIMIT,
            "candidate_size_bytes": file_rec["size"],
            "headroom_bytes": PYPI_DEFAULT_FILE_LIMIT - file_rec["size"],
            "below_default_limit": file_rec["size"] <= PYPI_DEFAULT_FILE_LIMIT,
            "project_limit_status": "unread-while-pending",
        },
        "files": [file_rec],
        "members": inspected["members"],
        "superseded_candidates": [
            {
                "filename": EXPECTED_WHEEL_FILENAME,
                "size": SUPERSEDED_PRELIMINARY_SIZE,
                "sha256": SUPERSEDED_PRELIMINARY_SHA256,
                "reason": "requires-python-overstated-as-3.9",
            }
        ],
        "builder_can_publish": False,
        "publication_admitted": False,
    }
    doc["set_sha256"] = compute_set_sha256(doc)
    return validate_approval_schema(doc)


def verify_approved(
    dist: str | Path,
    *,
    approval: Mapping[str, Any] | None = None,
    repository: str | Path | None = None,
    require_admitted: bool = False,
) -> dict[str, Any]:
    """Verify local dist directory contains solely the exact approved Nebular wheel."""
    approved = (
        validate_approval_schema(dict(approval))
        if approval is not None
        else load_approval(repository)
    )
    if require_admitted and approved.get("publication_admitted") is not True:
        fail("PUBLICATION_NOT_ADMITTED")

    d_path = Path(dist)
    if d_path.is_symlink() or not d_path.is_dir():
        fail("FILE_SET")
    entries = sorted(p.name for p in d_path.iterdir())
    if entries != [EXPECTED_WHEEL_FILENAME]:
        fail("FILE_SET")

    inspect_candidate(d_path / EXPECTED_WHEEL_FILENAME, approval=approved)
    return approved


def build_candidate(
    output_dir: str | Path,
    *,
    nebular_capture_dir: str | Path | None = None,
    stellar_capture_dir: str | Path | None = None,
    closure_dir: str | Path | None = None,
    scratch_dir: str | Path | None = None,
    repository: str | Path | None = None,
    verify_against_committed: bool = True,
    client: Any | None = None,
) -> dict[str, Any]:
    """Authenticate inputs, run deterministic double-build, verify RECORD, and verify or produce approval."""
    root = repo_root(repository)
    out = Path(output_dir)
    if any(p.is_symlink() for p in (out, *out.parents)):
        fail("OUTPUT_SYMLINK")
    if out.exists() and any(out.iterdir()):
        fail("OUTPUT_NOT_EMPTY")

    temp_ctx: tempfile.TemporaryDirectory[str] | None = None
    if scratch_dir is None:
        temp_ctx = tempfile.TemporaryDirectory()
        scratch = Path(temp_ctx.name).resolve()
    else:
        scratch = Path(scratch_dir).resolve()
        scratch.mkdir(parents=True, exist_ok=True)

    try:
        if nebular_capture_dir is not None:
            neb_cap, neb_intent, neb_prof = authenticate_captured(
                nebular_capture_dir, project=PROJECT, repository=root
            )
        else:
            cap_out = scratch / "capture-nebular"
            cap_out.mkdir()
            eff_client = _github_client(client)
            rows = capture_generation(root, cap_out, project=PROJECT, client=eff_client)
            neb_cap, neb_intent, neb_prof = rows[0]

        if stellar_capture_dir is not None and closure_dir is not None:
            stl_cap, stl_intent, stl_prof = authenticate_captured(
                stellar_capture_dir, project=STELLAR_PROJECT, repository=root
            )
            prepared = bind_prepared_closure(
                closure_dir, neb_cap, stl_cap, scratch_dir=scratch / "closure-scratch"
            )
        elif verify_against_committed:
            approved_ref = load_approval(root)
            if (
                authenticated_record_hash(neb_cap)
                != approved_ref["authentication"]["nebular"]["release_record_sha256"]
                or record_sha256(neb_prof)
                != approved_ref["authentication"]["nebular"]["profile_result_sha256"]
            ):
                fail("APPROVAL_AUTH_MISMATCH")
            stl_cap = None
            stl_prof = None
            prepared = None
        else:
            fail("CLOSURE_INPUTS_REQUIRED")

        try:
            res_a, res_b = verify_double_build(
                build_native_wheel,
                PROJECT,
                VERSION,
                neb_cap,
                system=SYSTEM,
                profile_result=neb_prof,
                output_dir_a=scratch / "build-a",
                output_dir_b=scratch / "build-b",
            )
        except ContractError as exc:
            fail(f"BUILD_{exc.code}")

        if res_a.can_publish is not False or res_b.can_publish is not False:
            fail("BUILDER_CAN_PUBLISH")

        out.mkdir(parents=True, exist_ok=True)
        final_wheel = out / res_a.filename
        with final_wheel.open("xb") as stream:
            stream.write(res_a.wheel_bytes)

        if verify_against_committed:
            return verify_approved(out, repository=root)

        assert stl_cap is not None and stl_prof is not None and prepared is not None
        return approval_document(
            final_wheel,
            nebular_capture=neb_cap,
            nebular_profile=neb_prof,
            stellar_capture=stl_cap,
            stellar_profile=stl_prof,
            prepared_closure=prepared,
            repository=root,
        )
    finally:
        if temp_ctx is not None:
            temp_ctx.cleanup()


def prepare_hosted_inputs(
    output_dir: str | Path,
    *,
    repository: str | Path | None = None,
    client: Any | None = None,
) -> dict[str, Any]:
    """Acquire fresh authenticated Nebular + Stellar captures and verifier closure outside network denial."""
    root = repo_root(repository)
    out = Path(output_dir).resolve()
    if any(p.is_symlink() for p in (out, *out.parents)):
        fail("PREPARE_SYMLINK")
    if out.exists() and any(out.iterdir()):
        fail("PREPARE_NOT_EMPTY")
    out.mkdir(parents=True, exist_ok=True)

    eff_client = _github_client(client)
    captures_root = out / "captures"
    captures_root.mkdir()
    nebular_root = captures_root / "nebular"
    stellar_root = captures_root / "stellar"
    try:
        nebular_root.mkdir()
        neb_rows = capture_generation(
            root, nebular_root, project=PROJECT, client=eff_client
        )
        stellar_root.mkdir()
        stl_rows = capture_generation(
            root, stellar_root, project=STELLAR_PROJECT, client=eff_client
        )
        neb_cap, neb_intent, neb_prof = neb_rows[0]
        stl_cap, stl_intent, stl_prof = stl_rows[0]
        closure_root = out / "verifier-closure"
        prepare_smoke(
            neb_cap,
            [(neb_cap, neb_intent, neb_prof), (stl_cap, stl_intent, stl_prof)],
            eff_client,
            closure_root,
            label="darwin-arm64",
        )
    except ContractError as exc:
        fail(f"PREPARE_{exc.code}")

    approved = load_approval(root)
    if (
        authenticated_record_hash(neb_cap)
        != approved["authentication"]["nebular"]["release_record_sha256"]
        or record_sha256(neb_prof)
        != approved["authentication"]["nebular"]["profile_result_sha256"]
        or authenticated_record_hash(stl_cap)
        != approved["authentication"]["stellar_fixture"]["release_record_sha256"]
        or record_sha256(stl_prof)
        != approved["authentication"]["stellar_fixture"]["profile_result_sha256"]
    ):
        fail("PREPARE_AUTH_MISMATCH")

    prepared = bind_prepared_closure(closure_root, neb_cap, stl_cap)
    if prepared["records_sha256"] != approved["verifier_closure"]["records_sha256"]:
        fail("PREPARE_CLOSURE_MISMATCH")

    return {
        "nebular_capture_dir": str(nebular_root / PROJECT),
        "stellar_capture_dir": str(stellar_root / STELLAR_PROJECT),
        "closure_dir": str(closure_root),
        "records_sha256": prepared["records_sha256"],
    }


class NebularPublicReader:
    """Bounded read-only HTTP reader capped to 32 MiB for PyPI JSON and the approved size for the wheel."""

    def __init__(self, max_file_bytes: int):
        if type(max_file_bytes) is not int or not (1 <= max_file_bytes <= PYPI_DEFAULT_FILE_LIMIT):
            fail("READER_LIMIT")
        self.max_file_bytes = max_file_bytes
        self.opener = build_opener(ProxyHandler({}), NoRedirect())

    def get(self, url: str) -> bytes:
        try:
            _public_url(url, {"pypi.org", "files.pythonhosted.org"})
            limit = (
                self.max_file_bytes
                if url.startswith("https://files.pythonhosted.org/")
                else MAX_JSON_BYTES
            )
            req = Request(url, headers={"User-Agent": "RS9-TF-PyPI-Nebular/1"})
            with self.opener.open(req, timeout=30) as response:
                if response.status != 200 or response.geturl() != url:
                    fail("REMOTE_UNKNOWN")
                body = response.read(limit + 1)
                if len(body) > limit:
                    fail("REMOTE_UNKNOWN")
                return body
        except AdmissionError:
            raise
        except HTTPError as error:
            absent = error.code == 404 and error.geturl() == url
            error.close()
            fail("REMOTE_ABSENT" if absent else "REMOTE_UNKNOWN")
        except (URLError, OSError, ValueError):
            fail("REMOTE_UNKNOWN")


def project_state(
    approval: Mapping[str, Any], get: Callable[[str], bytes] | None = None
) -> str:
    """Classify remote PyPI project state without claiming project ownership."""
    validate_approval_schema(approval)
    reader = get or NebularPublicReader(approval["files"][0]["size"]).get
    url = f"https://pypi.org/pypi/{PROJECT}/json"
    try:
        obj = strict_json(reader(url))
        if not isinstance(obj, dict) or not isinstance(obj.get("releases"), dict):
            return "unknown"
        if not isinstance(obj.get("info"), dict) or obj["info"].get("name") != PROJECT:
            return "conflict"
        return "present-unverified" if VERSION in obj["releases"] else "conflict"
    except AdmissionError as error:
        return "absent" if error.code == "TF_PYPI_REMOTE_ABSENT" else "unknown"
    except ValueError:
        return "unknown"


def exact_state(
    approval: Mapping[str, Any],
    local: Mapping[str, bytes],
    *,
    get: Callable[[str], bytes] | None = None,
) -> dict[str, Any]:
    """Compare remote PyPI metadata and downloaded wheel bytes against the approved candidate."""
    validate_approval_schema(approval)
    reader = get or NebularPublicReader(approval["files"][0]["size"]).get
    state = project_state(approval, reader)
    if state != "present-unverified":
        return {"state": state, "missing": sorted(local) if state == "absent" else []}

    url = f"https://pypi.org/pypi/{PROJECT}/{VERSION}/json"
    try:
        obj = strict_json(reader(url))
        if not isinstance(obj, dict) or not isinstance(obj.get("info"), dict):
            fail("REMOTE_UNKNOWN")
        if obj["info"].get("name") != PROJECT or obj["info"].get("version") != VERSION:
            fail("REMOTE_CONFLICT")
        rows = obj.get("urls")
        if not isinstance(rows, list) or not rows:
            fail("REMOTE_UNKNOWN")
        seen: set[str] = set()
        for row in rows:
            if not isinstance(row, dict):
                fail("REMOTE_UNKNOWN")
            name = row.get("filename")
            if not isinstance(name, str) or name not in local or name in seen:
                fail("REMOTE_CONFLICT")
            body = local[name]
            if row.get("yanked") is not False or type(row.get("size")) is not int:
                fail("REMOTE_CONFLICT")
            digests = row.get("digests")
            if not isinstance(digests, dict) or (
                row["size"],
                digests.get("sha256"),
            ) != (len(body), sha256(body)):
                fail("REMOTE_CONFLICT")
            file_url = row.get("url")
            _public_url(file_url, {"files.pythonhosted.org"})
            if reader(file_url) != body:
                fail("REMOTE_CONFLICT")
            seen.add(name)
        missing = sorted(set(local) - seen)
        return {
            "state": "incomplete" if missing else "published-exact",
            "missing": missing,
        }
    except AdmissionError as error:
        mapped = "conflict" if error.code == "TF_PYPI_REMOTE_CONFLICT" else "unknown"
        return {"state": mapped, "missing": []}
    except ValueError:
        return {"state": "unknown", "missing": []}


MAX_PRIOR_RUN_PAGES = 10
PRIOR_RUN_PAGE_SIZE = 100
REVIEWED_SAFE_PRIOR_RUN_IDS: tuple[str, ...] = ()


def _fetch_paginated_github_list(
    base_url: str,
    list_key: str,
    client_json: Callable[[str], Any],
) -> list[dict[str, Any]]:
    """Fetch all pages of a GitHub Actions list endpoint up to MAX_PRIOR_RUN_PAGES, failing closed on truncation."""
    collected: list[dict[str, Any]] = []
    page = 1
    while True:
        if page > MAX_PRIOR_RUN_PAGES:
            fail("PRIOR_ATTEMPT_UNCONFIRMED")
        sep = "&" if "?" in base_url else "?"
        url = base_url if page == 1 else f"{base_url}{sep}page={page}"
        payload = client_json(url)
        if not isinstance(payload, dict):
            fail("PRIOR_ATTEMPT_UNCONFIRMED")
        total_count = payload.get("total_count")
        rows = payload.get(list_key)
        if (
            type(total_count) is not int
            or total_count < 0
            or not isinstance(rows, list)
        ):
            fail("PRIOR_ATTEMPT_UNCONFIRMED")
        for row in rows:
            if not isinstance(row, dict):
                fail("PRIOR_ATTEMPT_UNCONFIRMED")
            collected.append(row)
        if len(collected) >= total_count:
            break
        if not rows:
            fail("PRIOR_ATTEMPT_UNCONFIRMED")
        page += 1
    return collected


def check_prior_publish_runs(
    *,
    api_get: Callable[[str], Any] | None = None,
    environ: Mapping[str, str] | None = None,
) -> None:
    """Refuse repeat upload if RS9_TFNF_PRIOR_UPLOAD_UNCONFIRMED is set, run_attempt > 1, or any unreviewed prior run did not skip upload."""
    env = environ if environ is not None else os.environ
    if env.get("RS9_TFNF_PRIOR_UPLOAD_UNCONFIRMED", "").strip():
        fail("PRIOR_ATTEMPT_UNCONFIRMED")
    run_attempt = env.get("GITHUB_RUN_ATTEMPT", "1").strip()
    if run_attempt not in ("", "1"):
        fail("PRIOR_ATTEMPT_UNCONFIRMED")
    should_query = (
        api_get is not None
        or env.get("GITHUB_ACTIONS") == "true"
        or bool(env.get("RS9_TFNF_PRIOR_RUNS_CHECK", "").strip())
    )
    if not should_query:
        return
    repo = env.get("GITHUB_REPOSITORY", "").strip()
    current_run_id = env.get("GITHUB_RUN_ID", "").strip()
    if not repo or "/" not in repo:
        fail("PRIOR_ATTEMPT_UNCONFIRMED")
    client_json = api_get or (
        lambda url: _github_client(environ=env).json(
            url, request_class="github-api", no_redirect=True
        )
    )
    try:
        runs_base_url = (
            f"https://api.github.com/repos/{repo}/actions/workflows/{WORKFLOW}/runs"
            f"?branch=main&event=workflow_dispatch&per_page={PRIOR_RUN_PAGE_SIZE}"
        )
        runs = _fetch_paginated_github_list(
            runs_base_url, "workflow_runs", client_json
        )
        for run in runs:
            run_id = str(run.get("id", "")).strip()
            if not run_id:
                fail("PRIOR_ATTEMPT_UNCONFIRMED")
            if run_id == current_run_id or run_id in REVIEWED_SAFE_PRIOR_RUN_IDS:
                continue
            jobs_base_url = (
                f"https://api.github.com/repos/{repo}/actions/runs/{run_id}/jobs"
                f"?filter=all&per_page={PRIOR_RUN_PAGE_SIZE}"
            )
            jobs = _fetch_paginated_github_list(
                jobs_base_url, "jobs", client_json
            )
            from rs9.tf_pypi_nebular070_publish import (
                ALL_KNOWN_WORKFLOW_JOB_NAMES,
                QUALIFY_070_JOB_NAMES,
            )

            publish_jobs = [
                job
                for job in jobs
                if isinstance(job, dict)
                and job.get("name") == "Trusted Publishing to PyPI"
            ]
            qualify_070_jobs = [
                job
                for job in jobs
                if isinstance(job, dict)
                and job.get("name") in QUALIFY_070_JOB_NAMES
            ]
            active_qualify_070 = [
                job
                for job in qualify_070_jobs
                if job.get("conclusion") != "skipped"
            ]
            active_non_qualify_070 = [
                job
                for job in jobs
                if isinstance(job, dict)
                and job.get("name") not in QUALIFY_070_JOB_NAMES
                and job.get("conclusion") != "skipped"
            ]
            if active_qualify_070 or not publish_jobs:
                if (
                    run.get("status") in (None, "completed")
                    and jobs
                    and all(
                        isinstance(job, dict)
                        and job.get("name") in ALL_KNOWN_WORKFLOW_JOB_NAMES
                        and job.get("status") == "completed"
                        and isinstance(job.get("conclusion"), str)
                        and bool(job.get("conclusion"))
                        for job in jobs
                    )
                    and not active_non_qualify_070
                    and len(qualify_070_jobs) == len(QUALIFY_070_JOB_NAMES)
                    and {job.get("name") for job in qualify_070_jobs}
                    == QUALIFY_070_JOB_NAMES
                    and bool(active_qualify_070)
                ):
                    continue
                fail("PRIOR_ATTEMPT_UNCONFIRMED")
            if qualify_070_jobs and (
                len(qualify_070_jobs) != len(QUALIFY_070_JOB_NAMES)
                or {job.get("name") for job in qualify_070_jobs} != QUALIFY_070_JOB_NAMES
                or not all(job.get("status") == "completed" for job in qualify_070_jobs)
            ):
                fail("PRIOR_ATTEMPT_UNCONFIRMED")
            for job in publish_jobs:
                if job.get("status") not in (None, "completed"):
                    fail("PRIOR_ATTEMPT_UNCONFIRMED")
                if job.get("conclusion") == "skipped":
                    continue
                steps = job.get("steps")
                if not isinstance(steps, list) or not steps:
                    fail("PRIOR_ATTEMPT_UNCONFIRMED")
                publish_steps = [
                    step
                    for step in steps
                    if isinstance(step, dict)
                    and step.get("name") == "Publish package distribution to PyPI"
                ]
                if not publish_steps:
                    fail("PRIOR_ATTEMPT_UNCONFIRMED")
                for step in publish_steps:
                    if (
                        step.get("status") not in (None, "completed")
                        or step.get("conclusion") != "skipped"
                    ):
                        fail("PRIOR_ATTEMPT_UNCONFIRMED")
    except AdmissionError:
        raise
    except Exception:
        fail("PRIOR_ATTEMPT_UNCONFIRMED")


def select_missing(
    dist: str | Path = Path("dist"),
    upload_dir: str | Path = Path("upload"),
    *,
    approval: Mapping[str, Any] | None = None,
    repository: str | Path | None = None,
    get: Callable[[str], bytes] | None = None,
    attempt_marker: str | Path | None = None,
    api_get: Callable[[str], Any] | None = None,
    environ: Mapping[str, str] | None = None,
) -> dict[str, Any]:
    """Verify approved dist, refuse if publication_admitted is false or prior attempt unconfirmed, and stage missing wheel."""
    env = environ if environ is not None else os.environ
    if env.get("RS9_TFNF_PRIOR_UPLOAD_UNCONFIRMED", "").strip():
        fail("PRIOR_ATTEMPT_UNCONFIRMED")
    if attempt_marker is not None:
        m_path = Path(attempt_marker)
        if m_path.is_symlink() or m_path.exists():
            fail("PRIOR_ATTEMPT_UNCONFIRMED")

    approved = verify_approved(
        dist,
        approval=approval,
        repository=repository,
        require_admitted=True,
    )
    d_path = Path(dist)
    u_path = Path(upload_dir)
    if any(p.is_symlink() for p in (u_path, *u_path.parents)):
        fail("UPLOAD_DIR")
    if u_path.exists():
        if not u_path.is_dir() or any(u_path.iterdir()):
            fail("UPLOAD_DIR")

    local = {
        rec["filename"]: physical_bytes(
            d_path / rec["filename"], limit=rec["size"]
        )
        for rec in approved["files"]
    }
    state_info = exact_state(approved, local, get=get)
    state = state_info.get("state")
    missing = state_info.get("missing", [])

    if state in ("unknown", "conflict"):
        fail(f"REMOTE_{state.upper()}")
    if state not in ("published-exact", "incomplete", "absent"):
        fail("REMOTE_UNKNOWN")

    if missing:
        check_prior_publish_runs(api_get=api_get, environ=env)

    approved_names = {rec["filename"] for rec in approved["files"]}
    if missing:
        u_path.mkdir(parents=True, exist_ok=True)
    for filename in missing:
        if filename not in approved_names:
            fail("UNAPPROVED_FILE")
        dest = u_path / filename
        if dest.exists() or dest.is_symlink():
            fail("UPLOAD_DIR")
        with dest.open("xb") as stream:
            stream.write(local[filename])
        verify_upload_dir(d_path, u_path, approval=approved)

    if missing and attempt_marker is not None:
        m_path = Path(attempt_marker)
        m_path.parent.mkdir(parents=True, exist_ok=True)
        with m_path.open("xb") as stream:
            stream.write(
                canonical(
                    {
                        "project": PROJECT,
                        "version": VERSION,
                        "set_sha256": approved["set_sha256"],
                        "staged_files": missing,
                    }
                )
            )

    return {"upload": bool(missing), "state": state, "missing": missing}


def verify_upload_dir(
    dist: str | Path = Path("dist"),
    upload_dir: str | Path = Path("upload"),
    *,
    approval: Mapping[str, Any] | None = None,
    repository: str | Path | None = None,
) -> dict[str, Any]:
    """Re-verify both dist/ and staged upload/ bytes against the committed approval immediately before upload."""
    approved = verify_approved(
        dist,
        approval=approval,
        repository=repository,
        require_admitted=True,
    )
    u_path = Path(upload_dir)
    if any(p.is_symlink() for p in (u_path, *u_path.parents)) or not u_path.is_dir():
        fail("UPLOAD_DIR")
    entries = sorted(p.name for p in u_path.iterdir())
    if entries != [EXPECTED_WHEEL_FILENAME]:
        fail("UPLOAD_FILE_SET")
    inspect_candidate(u_path / EXPECTED_WHEEL_FILENAME, approval=approved)
    return approved


def readback(
    dist: str | Path = Path("dist"),
    *,
    approval: Mapping[str, Any] | None = None,
    repository: str | Path | None = None,
    get: Callable[[str], bytes] | None = None,
    schedule: Sequence[int | float] = READBACK_SCHEDULE_SECONDS,
    sleep_fn: Callable[[ float], None] = time.sleep,
) -> dict[str, Any]:
    """Perform bounded finite readback after upload without any upload capability."""
    if not schedule or len(schedule) > 6 or sum(schedule) > 600:
        fail("READBACK_SCHEDULE")
    approved = verify_approved(dist, approval=approval, repository=repository)
    d_path = Path(dist)
    local = {
        rec["filename"]: physical_bytes(
            d_path / rec["filename"], limit=rec["size"]
        )
        for rec in approved["files"]
    }
    attempts: list[dict[str, Any]] = []
    last_state = "unknown"

    for idx, delay in enumerate(schedule):
        if delay < 0:
            fail("READBACK_SCHEDULE")
        if idx > 0 and delay > 0:
            sleep_fn(float(delay))
        info = exact_state(approved, local, get=get)
        state = str(info.get("state") or "unknown")
        last_state = state
        attempts.append(
            {
                "attempt": idx + 1,
                "delay_seconds": delay,
                "state": state,
            }
        )
        if state == "published-exact":
            return {
                "project": PROJECT,
                "version": VERSION,
                "state": "published-exact",
                "attempts": attempts,
            }
        if state == "conflict":
            err = AdmissionError("TF_PYPI_READBACK_CONFLICT")
            err.attempts = attempts  # type: ignore[attr-defined]
            err.disposition = "conflict-abort-immediately"  # type: ignore[attr-defined]
            raise err

    code = f"TF_PYPI_READBACK_{last_state.upper().replace('-', '_')}"
    err = AdmissionError(code)
    err.attempts = attempts  # type: ignore[attr-defined]
    err.disposition = "unconfirmed-no-redispatch-before-independent-readback"  # type: ignore[attr-defined]
    raise err


NEBULAR_PRODUCT_PATHS = (
    ".github/workflows/rs9-tfnf-pypi-publish.yml",
    "operators/tf-pypi/theme-forge-nebular-fusion-artifacts.json",
    "src/rs9/nebular_host_state.py",
    "src/rs9/tf_pypi_nebular.py",
    "src/rs9/wheel_native.py",
)


def _nebular_import_closure_paths(root: Path) -> tuple[str, ...]:
    """Resolve the deterministic transitive src/rs9/*.py import closure and authority inputs for Nebular."""
    seen: set[str] = {
        *NEBULAR_PRODUCT_PATHS,
        str(BOOTSTRAP),
        str(EXPECTATIONS),
        "src/rs9/__init__.py",
    }
    queue: list[str] = [
        "src/rs9/tf_pypi_nebular.py",
        "src/rs9/nebular_host_state.py",
        "src/rs9/wheel_native.py",
    ]
    while queue:
        rel = queue.pop()
        path = root / rel
        if not path.is_file():
            continue
        try:
            tree = ast.parse(
                physical_bytes(path, limit=4 * 1024 * 1024).decode("utf-8"),
                filename=rel,
            )
        except (OSError, UnicodeDecodeError, SyntaxError, AdmissionError):
            continue
        candidates: list[str] = []
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom):
                mod = node.module or ""
                if mod.startswith("rs9."):
                    candidates.append(f"src/{mod.replace('.', '/')}.py")
                elif mod == "rs9" or node.level == 1:
                    base = f"src/rs9/{mod}" if (node.level == 1 and mod) else "src/rs9"
                    if node.level == 1 and mod:
                        candidates.append(f"src/rs9/{mod.replace('.', '/')}.py")
                    for alias in node.names:
                        candidates.append(f"{base}/{alias.name}.py")
            elif isinstance(node, ast.Import):
                for alias in node.names:
                    if alias.name.startswith("rs9."):
                        candidates.append(f"src/{alias.name.replace('.', '/')}.py")
        for cand in candidates:
            if cand not in seen and (root / cand).is_file():
                seen.add(cand)
                queue.append(cand)
    return tuple(sorted(seen))


def source_tree_state(
    expected: str,
    repository: str | Path | None = None,
    *,
    require_clean: bool = False,
) -> dict[str, Any]:
    """Verify HEAD equals expected 40-hex commit, optionally enforce clean worktree, and hash Nebular product and import-closure bytes."""
    if not re.fullmatch(r"[0-9a-f]{40}", expected or ""):
        fail("HOSTED_COMMIT")
    root = repo_root(repository)
    res = subprocess.run(
        ["git", "-C", str(root), "rev-parse", "HEAD"],
        capture_output=True,
        timeout=15,
        check=False,
    )
    if res.returncode != 0 or res.stdout.decode("ascii", "replace").strip() != expected:
        fail("HOSTED_COMMIT")

    st_res = subprocess.run(
        ["git", "-C", str(root), "status", "--porcelain", "--untracked-files=all"],
        capture_output=True,
        timeout=15,
        check=False,
    )
    if st_res.returncode != 0:
        fail("HOSTED_COMMIT")
    dirty_lines = [
        line
        for line in st_res.stdout.decode("utf-8", "replace").splitlines()
        if line and not line[3:].startswith(".serena/")
    ]
    worktree_clean = len(dirty_lines) == 0
    if require_clean and not worktree_clean:
        fail("HOSTED_WORKTREE_DIRTY")

    product_digests: dict[str, str] = {}
    for rel in NEBULAR_PRODUCT_PATHS:
        p = root / rel
        if p.is_file():
            product_digests[rel] = sha256(physical_bytes(p, limit=4 * 1024 * 1024))

    closure_digests: dict[str, str] = {}
    for rel in _nebular_import_closure_paths(root):
        p = root / rel
        if p.is_file():
            closure_digests[rel] = sha256(physical_bytes(p, limit=4 * 1024 * 1024))

    return {
        "head_commit": expected,
        "worktree_clean": worktree_clean,
        "dirty_paths_count": len(dirty_lines),
        "status_porcelain_sha256": sha256("\n".join(dirty_lines).encode("utf-8")),
        "product_files_sha256": sha256(canonical(product_digests)),
        "closure_files_count": len(closure_digests),
        "closure_files_sha256": sha256(canonical(closure_digests)),
        "serena_excluded_from_dirty_check": True,
    }


def source_commit(
    expected: str,
    repository: str | Path | None = None,
    *,
    require_clean: bool = False,
) -> str:
    """Verify HEAD equals the expected 40-hex commit and optionally require a clean worktree."""
    return source_tree_state(expected, repository=repository, require_clean=require_clean)[
        "head_commit"
    ]


def probe_network_denial(
    python_bin: str | Path,
    node_bin: str | Path,
    env: Mapping[str, str],
    *,
    sandbox_profile: str | None = None,
) -> dict[str, Any]:
    """Verify Python and Node literal-IP TCP and DNS requests are denied by the active sandbox."""
    active_profile = (
        sandbox_profile
        or env.get("RS9_TFNF_SANDBOX_PROFILE")
        or SANDBOX_PROFILE
    )
    python_probe = (
        "import socket, json\n"
        "r = {}\n"
        "s = socket.socket()\n"
        "s.settimeout(2)\n"
        "try:\n"
        "    s.connect(('1.1.1.1', 443))\n"
        "    r['1.1.1.1'] = 0\n"
        "except OSError as e:\n"
        "    r['1.1.1.1'] = e.errno or -1\n"
        "finally:\n"
        "    s.close()\n"
        "try:\n"
        "    socket.getaddrinfo('registry.npmjs.org', 443)\n"
        "    r['registry.npmjs.org'] = 0\n"
        "except socket.gaierror as e:\n"
        "    r['registry.npmjs.org'] = e.errno or -1\n"
        "except OSError:\n"
        "    r['registry.npmjs.org'] = -1\n"
        "print(json.dumps(r))\n"
    )
    node_probe = (
        "const net = require('node:net'), dns = require('node:dns');\n"
        "const s = net.connect(443, '1.1.1.1');\n"
        "s.on('connect', () => { console.log('TCP:CONNECTED'); s.destroy(); });\n"
        "s.on('error', (e) => { console.log('TCP:' + (e.code || 'ERROR')); });\n"
        "s.setTimeout(2000, () => { console.log('TCP:TIMEOUT'); s.destroy(); });\n"
        "dns.lookup('registry.npmjs.org', (e) => { console.log('DNS:' + (e ? (e.code || 'ERROR') : 'CONNECTED')); });\n"
    )
    try:
        py_res = subprocess.run(
            [str(python_bin), "-I", "-B", "-c", python_probe],
            capture_output=True,
            env=dict(env),
            timeout=15,
            check=True,
        )
        node_res = subprocess.run(
            [str(node_bin), "-e", node_probe],
            capture_output=True,
            env=dict(env),
            timeout=15,
            check=True,
        )
        facts = strict_json(py_res.stdout)
        lines = [
            line.strip()
            for line in node_res.stdout.decode("utf-8", "replace").splitlines()
            if line.strip()
        ]
    except (subprocess.SubprocessError, OSError, ValueError, AdmissionError):
        fail("OFFLINE_ISOLATION")

    tcp_errno = facts.get("1.1.1.1")
    dns_errno = facts.get("registry.npmjs.org")
    allowed_dns_errnos = {
        getattr(socket, "EAI_NONAME", 8),
        getattr(socket, "EAI_AGAIN", 2),
        getattr(socket, "EAI_FAIL", 4),
        getattr(socket, "EAI_NODATA", 7),
    }
    if (
        tcp_errno not in (errno.EPERM, errno.EACCES)
        or dns_errno not in allowed_dns_errnos
    ):
        fail("OFFLINE_ISOLATION")

    node_tcp_tokens = {
        line.split(":", 1)[1] for line in lines if line.startswith("TCP:")
    }
    node_dns_tokens = {
        line.split(":", 1)[1] for line in lines if line.startswith("DNS:")
    }
    if (
        not node_tcp_tokens
        or not (node_tcp_tokens <= {"EPERM", "EACCES"})
        or not node_dns_tokens
        or not (node_dns_tokens <= {"ENOTFOUND", "EAI_AGAIN", "EPERM", "EACCES"})
    ):
        fail("OFFLINE_ISOLATION")

    return {
        "method": "sandbox-exec-deny-network-except-exact-system-ps-observer",
        "sandbox_profile": active_profile,
        "sandbox_profile_sha256": sha256(active_profile.encode("utf-8")),
        "python_tcp_errno": tcp_errno,
        "python_dns_errno": dns_errno,
        "node_tcp_denials": sorted(node_tcp_tokens),
        "node_dns_denials": sorted(node_dns_tokens),
        "node_denials": sorted(node_tcp_tokens | node_dns_tokens),
        "network_disabled": True,
    }


def verify_ps_observer(
    harness_path: str,
    env: Mapping[str, str],
    *,
    ps_path: str | Path = PS_PATH,
    which_fn: Callable[..., str | None] = shutil.which,
    lstat_fn: Callable[[str | Path], os.stat_result] = os.lstat,
    run_fn: Callable[..., subprocess.CompletedProcess[Any]] = subprocess.run,
) -> dict[str, Any]:
    """Bind PATH resolution of ps to root-owned regular /bin/ps and verify single-PID observation."""
    target = Path(ps_path)
    if str(target) != PS_PATH:
        fail("PS_OBSERVER_PATH")
    resolved = which_fn("ps", path=harness_path)
    if resolved is None or os.path.abspath(resolved) != PS_PATH:
        fail("PS_OBSERVER_RESOLUTION")
    try:
        st = lstat_fn(target)
    except OSError:
        fail("PS_OBSERVER_STAT")
    imode = stat.S_IMODE(st.st_mode)
    if (
        stat.S_ISLNK(st.st_mode)
        or not stat.S_ISREG(st.st_mode)
        or st.st_uid != 0
        or (imode & 0o022) != 0
        or imode not in (0o4755, 0o0755)
    ):
        fail("PS_OBSERVER_OWNERSHIP")

    ps_bytes = physical_bytes(target, limit=4 * 1024 * 1024)
    ps_digest = sha256(ps_bytes)

    try:
        probe = run_fn(
            [PS_PATH, "-p", str(os.getpid()), "-o", "pid=,comm="],
            capture_output=True,
            env=dict(env),
            timeout=10,
            check=False,
        )
    except (subprocess.SubprocessError, OSError):
        fail("PS_OBSERVER_EXEC")

    out_lines = [
        line.strip()
        for line in (probe.stdout or b"").decode("utf-8", "replace").splitlines()
        if line.strip()
    ]
    if (
        probe.returncode != 0
        or probe.stderr
        or len(out_lines) != 1
        or out_lines[0].split(None, 1)[0] != str(os.getpid())
    ):
        fail("PS_OBSERVER_EXEC")

    return {
        "path": PS_PATH,
        "resolved_from_harness_path": resolved,
        "uid": st.st_uid,
        "mode": imode,
        "sha256": ps_digest,
        "self_pid_probe_passed": True,
        "raw_process_output_retained": False,
    }


def verify_python39_refusal(
    wheel_path: str | Path,
    python39_bin: str | Path,
    work_dir: str | Path,
    isolated_env: Mapping[str, str],
) -> dict[str, Any]:
    """Verify a real Python 3.9 interpreter refuses the >=3.10 wheel before installation with venv unchanged."""
    py39 = Path(python39_bin)
    if not py39.is_file():
        return {
            "status": "blocked",
            "reason": "python39-interpreter-absent",
        }
    try:
        ver_res = subprocess.run(
            [
                str(py39),
                "-I",
                "-B",
                "-c",
                "import json, platform, sys; print(json.dumps({'version': platform.python_version(), 'major_minor': list(sys.version_info[:2])}))",
            ],
            capture_output=True,
            env=dict(isolated_env),
            timeout=15,
            check=False,
        )
        ver_info = strict_json(ver_res.stdout) if ver_res.returncode == 0 else {}
    except (subprocess.SubprocessError, OSError, AdmissionError):
        ver_info = {}

    if ver_info.get("major_minor") != [3, 9]:
        return {
            "status": "blocked",
            "reason": "python39-version-mismatch",
            "observed_version": ver_info.get("version"),
        }

    venv39 = Path(work_dir) / "venv-py39"
    if venv39.exists():
        fail("PY39_VENV_EXISTS")
    try:
        subprocess.run(
            [str(py39), "-m", "venv", str(venv39)],
            capture_output=True,
            env=dict(isolated_env),
            timeout=90,
            check=True,
        )
    except (subprocess.SubprocessError, OSError):
        fail("PY39_VENV_CREATE")

    baseline_inv = _venv_inventory(venv39)
    pip_env = {
        **runtime_environment(isolated_env),
        "PIP_CONFIG_FILE": os.devnull,
        "PIP_NO_INDEX": "1",
        "PIP_DISABLE_PIP_VERSION_CHECK": "1",
        "PIP_NO_CACHE_DIR": "1",
        "PYTHONDONTWRITEBYTECODE": "1",
    }
    venv_py = venv39 / "bin" / "python"
    try:
        install_res = subprocess.run(
            [
                str(venv_py),
                "-m",
                "pip",
                "install",
                "--no-index",
                "--no-deps",
                str(Path(wheel_path).resolve()),
            ],
            capture_output=True,
            env=pip_env,
            timeout=60,
            check=False,
        )
    except (subprocess.SubprocessError, OSError):
        fail("PY39_PIP_EXEC")

    after_inv = _venv_inventory(venv39)
    combined = (install_res.stdout or b"") + b"\n" + (install_res.stderr or b"")
    text = combined.decode("utf-8", "replace")
    requires_python_attributed = (
        ("Requires-Python" in text or "requires a different Python" in text)
        and ">=3.10" in text
        and "is not a supported wheel on this platform" not in text
    )
    venv_unchanged = (
        after_inv == baseline_inv and not (venv39 / "bin" / "tfnf").exists()
    )
    if install_res.returncode == 0 or not requires_python_attributed or not venv_unchanged:
        fail("PY39_REFUSAL_INVALID")

    return {
        "status": "pass",
        "client_python": ver_info["version"],
        "pip_exit_code": install_res.returncode,
        "attributed_to": "Requires-Python >=3.10",
        "venv_unchanged": True,
        "tfnf_installed": False,
        "stderr_sha256": sha256(install_res.stderr or b""),
    }


def _check_orphan_processes(work_root: Path, env: Mapping[str, str]) -> dict[str, Any]:
    real_root = str(work_root.resolve())
    try:
        res = subprocess.run(
            [PS_PATH, "-axww", "-o", "pid=,command="],
            capture_output=True,
            env=dict(env),
            timeout=15,
            check=True,
        )
    except (subprocess.SubprocessError, OSError):
        fail("PS_ORPHAN_CHECK")
    my_pid = os.getpid()
    matched_lines: list[str] = []
    for line in (res.stdout or b"").decode("utf-8", "replace").splitlines():
        m = re.match(r"^\s*(\d+)\s+(.*)$", line)
        if not m:
            continue
        pid = int(m.group(1))
        cmd = m.group(2)
        if pid != my_pid and (cmd.startswith(real_root + "/") or f" {real_root}/" in cmd):
            matched_lines.append(f"{pid}:{sha256(cmd.encode('utf-8'))}")
    if matched_lines:
        fail("ORPHAN_PROCESSES_REMAIN")
    return {
        "orphan_processes": 0,
        "observation_digest": sha256("\n".join(matched_lines).encode("utf-8")),
        "raw_process_output_retained": False,
    }


def qualify(
    dist: str | Path,
    work: str | Path,
    *,
    nebular_capture_dir: str | Path,
    stellar_capture_dir: str | Path,
    closure_dir: str | Path,
    expected_commit: str,
    python39_bin: str | Path = Path("/usr/bin/python3"),
    repository: str | Path | None = None,
    require_clean: bool = False,
) -> dict[str, Any]:
    """Execute full Darwin ARM64 native consumer qualification inside the network-denial sandbox."""
    if platform.system() != "Darwin" or platform.machine().lower() not in ("arm64", "aarch64"):
        fail("HOSTED_NATIVE_ARM64")
    if sys.version_info < (3, 10):
        fail("SUPERVISOR_PYTHON_FLOOR")

    root = repo_root(repository)
    src_state = source_tree_state(
        expected_commit, repository=root, require_clean=require_clean
    )
    commit = src_state["head_commit"]
    approved = verify_approved(dist, repository=root)
    wheel_path = Path(dist).resolve() / EXPECTED_WHEEL_FILENAME

    w_dir = Path(work)
    if any(p.is_symlink() for p in (w_dir, *w_dir.parents)):
        fail("WORK_SYMLINK")
    if w_dir.exists() and any(w_dir.iterdir()):
        fail("WORK_NOT_EMPTY")
    w_dir.mkdir(parents=True, mode=0o700, exist_ok=True)
    w_dir = w_dir.resolve()
    for sub in ("home", "tmp", "cache", "smoke"):
        (w_dir / sub).mkdir(mode=0o700)

    node_bin = shutil.which("node")
    if not node_bin:
        fail("NODE_MISSING")
    node_dir = str(Path(os.path.abspath(node_bin)).parent)
    harness_path = f"{node_dir}:/usr/bin:/bin"

    isolated_env = {
        "PATH": harness_path,
        "HOME": str(w_dir / "home"),
        "TMPDIR": str(w_dir / "tmp"),
        "XDG_CACHE_HOME": str(w_dir / "home/cache"),
        "XDG_CONFIG_HOME": str(w_dir / "home/config"),
        "XDG_DATA_HOME": str(w_dir / "home/data"),
        "XDG_STATE_HOME": str(w_dir / "home/state"),
        "PYTHONDONTWRITEBYTECODE": "1",
    }
    for k in ("LANG", "LC_ALL", "TZ"):
        if k in os.environ:
            isolated_env[k] = os.environ[k]

    real_home = operator_home()
    host_before = snapshot_host_state(real_home)
    (w_dir / "host-state-before.json").write_bytes(
        canonical(host_state_public_summary(host_before))
    )

    isolation = probe_network_denial(sys.executable, node_bin, isolated_env)
    ps_info = verify_ps_observer(harness_path, isolated_env)

    neb_cap, neb_intent, neb_prof = authenticate_captured(
        nebular_capture_dir, project=PROJECT, repository=root
    )
    stl_cap, stl_intent, stl_prof = authenticate_captured(
        stellar_capture_dir, project=STELLAR_PROJECT, repository=root
    )
    if (
        authenticated_record_hash(neb_cap)
        != approved["authentication"]["nebular"]["release_record_sha256"]
        or record_sha256(neb_prof)
        != approved["authentication"]["nebular"]["profile_result_sha256"]
        or authenticated_record_hash(stl_cap)
        != approved["authentication"]["stellar_fixture"]["release_record_sha256"]
        or record_sha256(stl_prof)
        != approved["authentication"]["stellar_fixture"]["profile_result_sha256"]
    ):
        fail("QUALIFY_AUTH_MISMATCH")

    prepared = bind_prepared_closure(
        closure_dir, neb_cap, stl_cap, scratch_dir=w_dir / "smoke"
    )
    if prepared["records_sha256"] != approved["verifier_closure"]["records_sha256"]:
        fail("QUALIFY_CLOSURE_MISMATCH")

    harness_targets = verify_harness_targets(
        prepared["tools"] / "native-rc-smoke.mjs"
    )
    bind_commands([(neb_cap, neb_intent, neb_prof)], root, w_dir)

    py39_gate = verify_python39_refusal(
        wheel_path, python39_bin, w_dir, isolated_env
    )
    if py39_gate.get("status") != "pass":
        err = AdmissionError("TF_PYPI_PY39_GATE_BLOCKED")
        err.gate = py39_gate  # type: ignore[attr-defined]
        raise err

    node_ver = (
        subprocess.check_output([node_bin, "--version"], env=isolated_env, timeout=10)
        .decode("utf-8", "replace")
        .strip()
    )

    runtime_holder: dict[str, Any] = {}

    def verify_installed(bin_path: Path, prefix: Sequence[str], env: Mapping[str, str]) -> dict[str, Any]:
        try:
            preflight = verifier_import_preflight(prepared, SYSTEM, prefix, env)
            baseline: dict[str, Any] | None = None

            def after_probe() -> None:
                nonlocal baseline
                if baseline is None:
                    roots = list(Path(env["THEME_FORGE_CACHE_DIR"]).glob("entries/*/payload/*"))
                    if len(roots) != 1:
                        fail("CACHE_MATERIALIZATION")
                    baseline = snapshot_nebular_runtime(roots[0], prepared, SYSTEM)

            probe_rows = run_probes(
                "tfnf",
                bin_path,
                repository=root,
                prefix=prefix,
                env=env,
                system=SYSTEM,
                substage="wheel-lifecycle-command-probe",
                after_probe=after_probe,
            )
            if not probe_rows or any(r.get("status") != "pass" for r in probe_rows):
                fail("COMMAND_PROBE")
            roots = list(Path(env["THEME_FORGE_CACHE_DIR"]).glob("entries/*/payload/*"))
            if len(roots) != 1 or baseline is None:
                fail("CACHE_MATERIALIZATION")
            runtime_ver = verify_nebular_runtime(
                roots[0],
                prepared,
                SYSTEM,
                prefix,
                env,
                baseline=baseline,
                diagnostic_extras=False,
            )
        except ContractError as exc:
            try:
                fail(f"RUNTIME_{exc.code}")
            except AdmissionError as err:
                if exc.code == "APPLICATION_SMOKE":
                    err.smoke_observation = smoke_failure_observation(
                        getattr(exc, "smoke_observation", None)
                    )  # type: ignore[attr-defined]
                raise

        scenarios = runtime_ver.get("scenarios", [])
        if (
            len(scenarios) != 1
            or scenarios[0].get("scenario") != "A"
            or not re.fullmatch(r"[0-9a-f]{64}", str(scenarios[0].get("receipt_sha256", "")))
            or scenarios[0].get("executable_sha256")
            != approved["payload_asset"]["executable_sha256"]
            or runtime_ver.get("sidecar", {}).get("verified") is not True
            or runtime_ver.get("drift", {}).get("has_drift") is not False
            or baseline.get("actual_member_count") != EXPECTED_RUNTIME_MEMBER_COUNT
        ):
            fail("SCENARIO_A_VERIFICATION")

        runtime_holder["import_preflight"] = preflight
        runtime_holder["command_probes"] = probe_rows
        runtime_holder["baseline"] = {k: v for k, v in baseline.items() if k != "members"}
        runtime_holder["verification"] = {
            "sidecar": runtime_ver["sidecar"],
            "scenarios": scenarios,
            "drift": runtime_ver.get("drift"),
            "source_bindings_count": len(runtime_ver.get("source_bindings", [])),
        }
        return {"status": "pass", "scenarios": scenarios}

    try:
        lifecycle = verify_offline_venv_lifecycle(
            wheel_path,
            distribution_name=DISTRIBUTION_NAME,
            commands_to_test={
                "tfnf": {
                    "verifier": verify_installed,
                    "clean_environment": True,
                    "env": isolated_env,
                }
            },
            venv_dir=w_dir / "venv",
            cache_dir=w_dir / "cache",
        )
    except ContractError as exc:
        fail(f"LIFECYCLE_{exc.code}")

    # Verify retained cache post-uninstall matches baseline
    cache_roots = list((w_dir / "cache").glob("entries/*/payload/*"))
    if len(cache_roots) != 1:
        fail("RETAINED_CACHE_MISSING")
    sidecars = [
        p
        for p in cache_roots[0].rglob("tfsb-studio-service*")
        if p.is_file() and p.parent.name in ("bin", "MacOS")
    ]
    manifests = list(cache_roots[0].rglob("sidecar-payload/manifest.json"))
    if len(sidecars) != 1 or len(manifests) != 1:
        fail("RETAINED_CACHE_CORRUPT")
    post_cache_ev = runtime_evidence(cache_roots[0], sidecars[0], manifests[0])
    if (
        post_cache_ev["runtime_root_sha256"]
        != runtime_holder["baseline"]["runtime_root_sha256"]
        or post_cache_ev["actual_member_count"] != EXPECTED_RUNTIME_MEMBER_COUNT
    ):
        fail("RETAINED_CACHE_DRIFT")

    orphans = _check_orphan_processes(w_dir, isolated_env)

    host_after = snapshot_host_state(real_home)
    (w_dir / "host-state-after.json").write_bytes(
        canonical(host_state_public_summary(host_after))
    )
    host_comparison = compare_snapshots(host_before, host_after)

    after_approved = verify_approved(dist, repository=root)
    if after_approved != approved:
        fail("HOSTED_ARTIFACT_CHANGED")

    gates = [
        {"name": "network-denial-probe", "status": "pass"},
        {"name": "system-ps-observer-binding", "status": "pass"},
        {"name": "authenticated-release-and-profile-binding", "status": "pass"},
        {"name": "verifier-closure-and-harness-scope-binding", "status": "pass"},
        {"name": "python39-requires-python-refusal", "status": "pass"},
        {"name": "offline-venv-install-and-command-probes", "status": "pass"},
        {"name": "released-sidecar-verifier", "status": "pass"},
        {"name": "darwin-scenario-a-application-smoke", "status": "pass"},
        {"name": "clean-uninstall-and-retained-cache-accounting", "status": "pass"},
        {"name": "zero-orphan-processes", "status": "pass"},
        {"name": "actual-operator-home-state-unchanged", "status": "pass"},
    ]

    floor_basis = approved["python_floor_basis"]
    py_ver = platform.python_version()
    py39_ver = py39_gate["client_python"]
    limit_info = approved["pypi_size_limit"]

    return {
        "schema": CONSUMER_REPORT_SCHEMA,
        "status": "native-consumer-passed",
        "project": PROJECT,
        "version": VERSION,
        "commit": commit,
        "source_state": src_state,
        "system": SYSTEM,
        "python": py_ver,
        "node": node_ver,
        "set_sha256": approved["set_sha256"],
        "artifacts": approved["files"],
        "isolation": isolation,
        "ps_observer": ps_info,
        "harness_targets": harness_targets,
        "python39_negative": py39_gate,
        "lifecycle": lifecycle,
        "runtime_baseline": runtime_holder["baseline"],
        "runtime_verification": runtime_holder["verification"],
        "retained_cache_post_uninstall": {
            "runtime_root_sha256": post_cache_ev["runtime_root_sha256"],
            "actual_member_count": post_cache_ev["actual_member_count"],
            "matches_baseline": True,
            "retained_outside_pip_uninstall": True,
        },
        "orphans": orphans,
        "actual_operator_home_state": host_comparison,
        "gates": gates,
        "limitations": [
            "Embedded errors.py contains lazy imports of non-embedded modules (bounded_process, product_classes, github) inside safe_details branches unreachable from the native launcher.",
            f"Requires-Python {approved['requires_python']} is backed by static AST/annotation analysis ({floor_basis['decisive_construct']}), a real Python {py39_ver} pip refusal, and a full Python {py_ver} installed lifecycle; Python 3.10-3.12 were not executed locally.",
            f"Released harness persistentStateLocations runs against its isolated outer HOME while nebular_host_state separately snapshots only the exact {harness_targets['target_count']} Nebular state names beneath actual operator HOME without parent directory enumeration.",
            f"Project-specific PyPI file-size limit status is {limit_info['project_limit_status']}; candidate size ({approved['files'][0]['size']:,} bytes) is verified below the {limit_info['default_limit_bytes']:,}-byte PyPI default limit.",
        ],
        "can_publish": bool(approved.get("builder_can_publish", False)),
        "publication_admitted": bool(approved.get("publication_admitted", False)),
        "public_writes": 0,
    }


SMOKE_OBSERVATION_MAX_BYTES = 8 * 1024
_SMOKE_UNAVAILABLE_REASONS = frozenset({"absent", "invalid", "oversized"})


def smoke_failure_observation(raw: Any) -> dict[str, Any]:
    """Closed, bounded record of the original failed smoke attempt; never raises or replaces the failure.

    Enforces local pre-validation structural and UTF-8 size checks (requiring non-empty string
    scenario/cause and enforcing SMOKE_OBSERVATION_MAX_BYTES on both raw input before validation
    and the validated projection).
    """
    record: dict[str, Any] = {
        "status": "unavailable",
        "reason": "absent",
        "origin": "original-producer-attempt",
        "single_attempt": True,
        "diagnostic_replay": False,
        "cause_is_observation_not_root_cause": True,
    }
    base_keys = set(record.keys())
    if isinstance(raw, dict) and raw.get("origin") == "original-producer-attempt":
        if (
            raw.get("status") == "unavailable"
            and raw.get("reason") in _SMOKE_UNAVAILABLE_REASONS
            and set(raw.keys()) == base_keys
            and raw.get("single_attempt") is True
            and raw.get("diagnostic_replay") is False
            and raw.get("cause_is_observation_not_root_cause") is True
        ):
            return dict(record, reason=raw["reason"])
        if (
            raw.get("status") == "observed"
            and raw.get("reason") is None
            and set(raw.keys()) == (base_keys | {"observation"})
            and raw.get("single_attempt") is True
            and raw.get("diagnostic_replay") is False
            and raw.get("cause_is_observation_not_root_cause") is True
        ):
            raw = raw.get("observation")
        else:
            return dict(record, reason="invalid")
    elif raw is None:
        return record
    if (
        not isinstance(raw, dict)
        or not isinstance(raw.get("scenario"), str)
        or not raw["scenario"].strip()
        or not isinstance(raw.get("cause"), str)
        or not raw["cause"].strip()
    ):
        return dict(record, reason="invalid")
    try:
        raw_encoded = json.dumps(
            raw,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
            default=str,
        ).encode("utf-8")
    except Exception:
        return dict(record, reason="invalid")
    if len(raw_encoded) > SMOKE_OBSERVATION_MAX_BYTES:
        return dict(record, reason="oversized")
    try:
        from rs9.pages_smoke_diagnostic import validate_smoke_observation

        observation = validate_smoke_observation(raw, system=SYSTEM)
        if not isinstance(observation, dict) or not observation:
            return dict(record, reason="invalid")
        encoded = json.dumps(
            observation,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("utf-8")
    except Exception:
        return dict(record, reason="invalid")
    if len(encoded) > SMOKE_OBSERVATION_MAX_BYTES:
        return dict(record, reason="oversized")
    return dict(record, status="observed", reason=None, observation=observation)


def write_report(path: str | Path, record: Mapping[str, Any]) -> None:
    """Write a sanitized JSON report to a physical destination without overwriting."""
    target = Path(path).absolute()
    if any(p.is_symlink() for p in (target, *target.parents)):
        fail("REPORT_PATH_SYMLINK")
    target.parent.mkdir(parents=True, exist_ok=True)
    with target.open("x", encoding="utf-8") as stream:
        json.dump(record, stream, indent=2, sort_keys=True, allow_nan=False)
        stream.write("\n")


def _legacy_workflow_text() -> str:
    """Generate the historical 0.6.1-only GitHub Actions workflow."""
    return f"""name: RS9 {PROJECT} PyPI Publish
run-name: 'RS9 {PROJECT} ${{{{ inputs.mode }}}} / ${{{{ inputs.dispatch_id }}}}'

on:
  push:
    branches: [{QUALIFY_BRANCH}]
  workflow_dispatch:
    inputs:
      mode:
        description: 'Execution mode'
        required: true
        type: choice
        options:
          - qualify
          - publish
        default: qualify
      dispatch_id:
        description: 'Unique attended intent correlation; not publication authority'
        required: false
        type: string

permissions:
  contents: read

concurrency:
  group: rs9-tfnf-pypi-publish-${{{{ github.ref }}}}
  cancel-in-progress: false

jobs:
  build_verify:
    if: github.ref == 'refs/heads/main' || github.ref == 'refs/heads/{QUALIFY_BRANCH}'
    name: Build and Verify Native Darwin Wheel
    runs-on: macos-15
    timeout-minutes: 30
    steps:
      - name: Checkout repository
        uses: actions/checkout@fbc6f3992d24b796d5a048ff273f7fcc4a7b6c09
        with:
          ref: '${{{{ github.sha }}}}'
          persist-credentials: false

      - name: Set up Python 3.13
        id: setup_python
        uses: actions/setup-python@ece7cb06caefa5fff74198d8649806c4678c61a1
        with:
          python-version: '3.13'

      - name: Build and verify candidate wheel
        env:
          PYTHONPATH: src
          PYTHONDONTWRITEBYTECODE: '1'
          RS9_GITHUB_READ_TOKEN: ${{{{ github.token }}}}
        run: |
          "${{{{ steps.setup_python.outputs.python-path }}}}" -B -m rs9.tf_pypi_nebular build \\
            --output dist --scratch "${{{{ runner.temp }}}}/tfnf-build"

      - name: Stage verified wheel artifact
        uses: actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02
        with:
          name: pypi-artifacts
          path: dist/
          retention-days: 1
          if-no-files-found: error

  native_consumer:
    name: Native macOS ARM64 installed consumer and Scenario A
    needs: [build_verify]
    runs-on: macos-15
    timeout-minutes: 45
    permissions:
      contents: read
    steps:
      - name: Checkout exact source
        uses: actions/checkout@fbc6f3992d24b796d5a048ff273f7fcc4a7b6c09
        with:
          ref: '${{{{ github.sha }}}}'
          persist-credentials: false

      - name: Set up Python 3.13
        id: setup_python
        uses: actions/setup-python@ece7cb06caefa5fff74198d8649806c4678c61a1
        with:
          python-version: '3.13'

      - name: Set up Node 22
        uses: actions/setup-node@249970729cb0ef3589644e2896645e5dc5ba9c38
        with:
          node-version: '22'
          package-manager-cache: false

      - name: Download the same run's verified wheel
        uses: actions/download-artifact@d3f86a106a0bac45b974a628896c90dbdf5c8093
        with:
          name: pypi-artifacts
          path: '${{{{ runner.temp }}}}/tfnf-dist'

      - name: Prepare authenticated captures and verifier closure outside network denial
        env:
          PYTHONPATH: src
          PYTHONDONTWRITEBYTECODE: '1'
          RS9_GITHUB_READ_TOKEN: ${{{{ github.token }}}}
        run: |
          "${{{{ steps.setup_python.outputs.python-path }}}}" -B -m rs9.tf_pypi_nebular prepare \\
            --output "${{{{ runner.temp }}}}/tfnf-inputs"

      - name: Qualify installed wheel and Darwin Scenario A under network denial
        env:
          PYTHONPATH: src
          PYTHONDONTWRITEBYTECODE: '1'
          QUALIFY_COMMIT: '${{{{ github.sha }}}}'
          SUPERVISOR_PYTHON: '${{{{ steps.setup_python.outputs.python-path }}}}'
        shell: bash
        run: |
          set -euo pipefail
          PHYSICAL_TMP="$("$SUPERVISOR_PYTHON" -c 'import os,tempfile; print(os.path.realpath(tempfile.gettempdir()))')"
          export TMPDIR="$PHYSICAL_TMP" TMP="$PHYSICAL_TMP" TEMP="$PHYSICAL_TMP"
          PHYSICAL_RUNNER_TEMP="$("$SUPERVISOR_PYTHON" -c 'import os; print(os.path.realpath(os.environ["RUNNER_TEMP"]))')"
          mkdir -p "$PHYSICAL_RUNNER_TEMP/tfnf-consumer-report"
          /usr/bin/sandbox-exec -p '{SANDBOX_PROFILE}' \\
            "$SUPERVISOR_PYTHON" -B -m rs9.tf_pypi_nebular qualify \\
            --dist "$PHYSICAL_RUNNER_TEMP/tfnf-dist" \\
            --work "$PHYSICAL_RUNNER_TEMP/tfnf-consumer" \\
            --nebular-capture "$PHYSICAL_RUNNER_TEMP/tfnf-inputs/captures/nebular/{PROJECT}" \\
            --stellar-capture "$PHYSICAL_RUNNER_TEMP/tfnf-inputs/captures/stellar/{STELLAR_PROJECT}" \\
            --closure "$PHYSICAL_RUNNER_TEMP/tfnf-inputs/verifier-closure" \\
            --python39 /usr/bin/python3 \\
            --report "$PHYSICAL_RUNNER_TEMP/tfnf-consumer-report/result.json" \\
            --expected-commit "$QUALIFY_COMMIT" \\
            --require-clean

      - name: Preserve native consumer result
        if: always()
        uses: actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02
        with:
          name: native-consumer-{PROJECT}
          path: '${{{{ runner.temp }}}}/tfnf-consumer-report/'
          retention-days: 14
          if-no-files-found: error

  publish:
    if: github.ref == 'refs/heads/main' && github.event_name == 'workflow_dispatch' && inputs.mode == 'publish'
    name: Trusted Publishing to PyPI
    needs: [build_verify, native_consumer]
    runs-on: ubuntu-24.04
    timeout-minutes: 20
    concurrency:
      group: rs9-tfnf-pypi-publish-main
      cancel-in-progress: false
    environment:
      name: {ENVIRONMENT}
      url: https://pypi.org/p/{PROJECT}
    permissions:
      id-token: write
      contents: read
      actions: read
    steps:
      - name: Checkout repository
        uses: actions/checkout@fbc6f3992d24b796d5a048ff273f7fcc4a7b6c09
        with:
          ref: '${{{{ github.sha }}}}'
          persist-credentials: false

      - name: Set up Python 3.13
        id: setup_python
        uses: actions/setup-python@ece7cb06caefa5fff74198d8649806c4678c61a1
        with:
          python-version: '3.13'

      - name: Download staged artifacts
        uses: actions/download-artifact@d3f86a106a0bac45b974a628896c90dbdf5c8093
        with:
          name: pypi-artifacts
          path: dist/

      - name: Verify artifact integrity and select only missing files
        id: missing
        env:
          PYTHONPATH: src
          PYTHONDONTWRITEBYTECODE: '1'
          RS9_GITHUB_READ_TOKEN: ${{{{ github.token }}}}
          RS9_TFNF_PRIOR_UPLOAD_UNCONFIRMED: ${{{{ vars.RS9_TFNF_PRIOR_UPLOAD_UNCONFIRMED }}}}
          GITHUB_RUN_ATTEMPT: ${{{{ github.run_attempt }}}}
        run: |
          "${{{{ steps.setup_python.outputs.python-path }}}}" -B -m rs9.tf_pypi_nebular select-missing \\
            --dist dist --upload-dir upload \\
            --attempt-marker "${{{{ runner.temp }}}}/tfnf-upload-attempt.json" >> "$GITHUB_OUTPUT"

      - name: Re-verify staged upload artifact against approval before upload
        if: steps.missing.outputs.upload == 'true'
        env:
          PYTHONPATH: src
          PYTHONDONTWRITEBYTECODE: '1'
        run: |
          "${{{{ steps.setup_python.outputs.python-path }}}}" -B -m rs9.tf_pypi_nebular verify-upload \\
            --dist dist --upload-dir upload

      - name: Publish package distribution to PyPI
        if: steps.missing.outputs.upload == 'true'
        uses: pypa/gh-action-pypi-publish@ed0c53931b1dc9bd32cbe73a98c7f6766f8a527e
        with:
          packages-dir: upload/
          verify-metadata: true
          print-hash: true
          skip-existing: false
          attestations: false

      - name: Read back published PyPI state
        if: always() && (steps.missing.outputs.upload == 'true' || steps.missing.outputs.state == 'published-exact')
        env:
          PYTHONPATH: src
          PYTHONDONTWRITEBYTECODE: '1'
        run: |
          "${{{{ steps.setup_python.outputs.python-path }}}}" -B -m rs9.tf_pypi_nebular readback --dist dist
"""


def workflow_text(release: str = "0.6.1", *, mode: str | None = None) -> str:
    """Generate the exact registered GitHub Actions workflow rs9-tfnf-pypi-publish.yml."""
    if release not in ("0.6.1", "0.7.0"):
        fail("WORKFLOW_RELEASE")
    from rs9.tf_pypi_nebular070_publish import (
        publication_resume_job_text,
        validate_workflow_dispatch,
        workflow_070_qualify_jobs_text,
    )

    if mode is not None:
        validate_workflow_dispatch(release, mode)

    return f"""name: RS9 {PROJECT} PyPI Publish
run-name: "RS9 {PROJECT} ${{{{ inputs.release || '0.6.1' }}}} ${{{{ inputs.mode || 'qualify' }}}} / ${{{{ inputs.dispatch_id }}}}"

on:
  push:
    branches: [{QUALIFY_BRANCH}]
  workflow_dispatch:
    inputs:
      release:
        description: 'Target Nebular release'
        required: false
        type: choice
        options:
          - 0.6.1
          - 0.7.0
        default: 0.6.1
      mode:
        description: 'Execution mode'
        required: true
        type: choice
        options:
          - qualify
          - publish
          - resume
        default: qualify
      dispatch_id:
        description: 'Unique attended intent correlation; not publication authority'
        required: false
        type: string

permissions:
  contents: read

concurrency:
  group: rs9-tfnf-pypi-publish-${{{{ github.ref }}}}
  cancel-in-progress: false

jobs:
  build_verify:
    if: (github.ref == 'refs/heads/main' || github.ref == 'refs/heads/{QUALIFY_BRANCH}') && inputs.release != '0.7.0' && inputs.mode != 'resume'
    name: Build and Verify Native Darwin Wheel
    runs-on: macos-15
    timeout-minutes: 30
    steps:
      - name: Checkout repository
        uses: actions/checkout@fbc6f3992d24b796d5a048ff273f7fcc4a7b6c09
        with:
          ref: '${{{{ github.sha }}}}'
          persist-credentials: false

      - name: Set up Python 3.13
        id: setup_python
        uses: actions/setup-python@ece7cb06caefa5fff74198d8649806c4678c61a1
        with:
          python-version: '3.13'

      - name: Build and verify candidate wheel
        env:
          PYTHONPATH: src
          PYTHONDONTWRITEBYTECODE: '1'
          RS9_GITHUB_READ_TOKEN: ${{{{ github.token }}}}
        run: |
          "${{{{ steps.setup_python.outputs.python-path }}}}" -B -m rs9.tf_pypi_nebular build \\
            --output dist --scratch "${{{{ runner.temp }}}}/tfnf-build"

      - name: Stage verified wheel artifact
        uses: actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02
        with:
          name: pypi-artifacts
          path: dist/
          retention-days: 1
          if-no-files-found: error

  native_consumer:
    if: inputs.release != '0.7.0' && inputs.mode != 'resume'
    name: Native macOS ARM64 installed consumer and Scenario A
    needs: [build_verify]
    runs-on: macos-15
    timeout-minutes: 45
    permissions:
      contents: read
    steps:
      - name: Checkout exact source
        uses: actions/checkout@fbc6f3992d24b796d5a048ff273f7fcc4a7b6c09
        with:
          ref: '${{{{ github.sha }}}}'
          persist-credentials: false

      - name: Set up Python 3.13
        id: setup_python
        uses: actions/setup-python@ece7cb06caefa5fff74198d8649806c4678c61a1
        with:
          python-version: '3.13'

      - name: Set up Node 22
        uses: actions/setup-node@249970729cb0ef3589644e2896645e5dc5ba9c38
        with:
          node-version: '22'
          package-manager-cache: false

      - name: Download the same run's verified wheel
        uses: actions/download-artifact@d3f86a106a0bac45b974a628896c90dbdf5c8093
        with:
          name: pypi-artifacts
          path: '${{{{ runner.temp }}}}/tfnf-dist'

      - name: Prepare authenticated captures and verifier closure outside network denial
        env:
          PYTHONPATH: src
          PYTHONDONTWRITEBYTECODE: '1'
          RS9_GITHUB_READ_TOKEN: ${{{{ github.token }}}}
        run: |
          "${{{{ steps.setup_python.outputs.python-path }}}}" -B -m rs9.tf_pypi_nebular prepare \\
            --output "${{{{ runner.temp }}}}/tfnf-inputs"

      - name: Qualify installed wheel and Darwin Scenario A under network denial
        env:
          PYTHONPATH: src
          PYTHONDONTWRITEBYTECODE: '1'
          QUALIFY_COMMIT: '${{{{ github.sha }}}}'
          SUPERVISOR_PYTHON: '${{{{ steps.setup_python.outputs.python-path }}}}'
        shell: bash
        run: |
          set -euo pipefail
          PHYSICAL_TMP="$("$SUPERVISOR_PYTHON" -c 'import os,tempfile; print(os.path.realpath(tempfile.gettempdir()))')"
          export TMPDIR="$PHYSICAL_TMP" TMP="$PHYSICAL_TMP" TEMP="$PHYSICAL_TMP"
          PHYSICAL_RUNNER_TEMP="$("$SUPERVISOR_PYTHON" -c 'import os; print(os.path.realpath(os.environ["RUNNER_TEMP"]))')"
          mkdir -p "$PHYSICAL_RUNNER_TEMP/tfnf-consumer-report"
          /usr/bin/sandbox-exec -p '{SANDBOX_PROFILE}' \\
            "$SUPERVISOR_PYTHON" -B -m rs9.tf_pypi_nebular qualify \\
            --dist "$PHYSICAL_RUNNER_TEMP/tfnf-dist" \\
            --work "$PHYSICAL_RUNNER_TEMP/tfnf-consumer" \\
            --nebular-capture "$PHYSICAL_RUNNER_TEMP/tfnf-inputs/captures/nebular/{PROJECT}" \\
            --stellar-capture "$PHYSICAL_RUNNER_TEMP/tfnf-inputs/captures/stellar/{STELLAR_PROJECT}" \\
            --closure "$PHYSICAL_RUNNER_TEMP/tfnf-inputs/verifier-closure" \\
            --python39 /usr/bin/python3 \\
            --report "$PHYSICAL_RUNNER_TEMP/tfnf-consumer-report/result.json" \\
            --expected-commit "$QUALIFY_COMMIT" \\
            --require-clean

      - name: Preserve native consumer result
        if: always()
        uses: actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02
        with:
          name: native-consumer-{PROJECT}
          path: '${{{{ runner.temp }}}}/tfnf-consumer-report/'
          retention-days: 14
          if-no-files-found: error
""" + workflow_070_qualify_jobs_text() + f"""
  publish:
    if: github.ref == 'refs/heads/main' && github.event_name == 'workflow_dispatch' && inputs.release != '0.7.0' && inputs.mode == 'publish'
    name: Trusted Publishing to PyPI
    needs: [build_verify, native_consumer]
    runs-on: ubuntu-24.04
    timeout-minutes: 20
    concurrency:
      group: rs9-tfnf-pypi-publish-main
      cancel-in-progress: false
    environment:
      name: {ENVIRONMENT}
      url: https://pypi.org/p/{PROJECT}
    permissions:
      id-token: write
      contents: read
      actions: read
    steps:
      - name: Checkout repository
        uses: actions/checkout@fbc6f3992d24b796d5a048ff273f7fcc4a7b6c09
        with:
          ref: '${{{{ github.sha }}}}'
          persist-credentials: false

      - name: Set up Python 3.13
        id: setup_python
        uses: actions/setup-python@ece7cb06caefa5fff74198d8649806c4678c61a1
        with:
          python-version: '3.13'

      - name: Download staged artifacts
        uses: actions/download-artifact@d3f86a106a0bac45b974a628896c90dbdf5c8093
        with:
          name: pypi-artifacts
          path: dist/

      - name: Verify artifact integrity and select only missing files
        id: missing
        env:
          PYTHONPATH: src
          PYTHONDONTWRITEBYTECODE: '1'
          RS9_GITHUB_READ_TOKEN: ${{{{ github.token }}}}
          RS9_TFNF_PRIOR_UPLOAD_UNCONFIRMED: ${{{{ vars.RS9_TFNF_PRIOR_UPLOAD_UNCONFIRMED }}}}
          GITHUB_RUN_ATTEMPT: ${{{{ github.run_attempt }}}}
        run: |
          "${{{{ steps.setup_python.outputs.python-path }}}}" -B -m rs9.tf_pypi_nebular select-missing \\
            --dist dist --upload-dir upload \\
            --attempt-marker "${{{{ runner.temp }}}}/tfnf-upload-attempt.json" >> "$GITHUB_OUTPUT"

      - name: Re-verify staged upload artifact against approval before upload
        if: steps.missing.outputs.upload == 'true'
        env:
          PYTHONPATH: src
          PYTHONDONTWRITEBYTECODE: '1'
        run: |
          "${{{{ steps.setup_python.outputs.python-path }}}}" -B -m rs9.tf_pypi_nebular verify-upload \\
            --dist dist --upload-dir upload

      - name: Publish package distribution to PyPI
        if: steps.missing.outputs.upload == 'true'
        uses: pypa/gh-action-pypi-publish@ed0c53931b1dc9bd32cbe73a98c7f6766f8a527e
        with:
          packages-dir: upload/
          verify-metadata: true
          print-hash: true
          skip-existing: false
          attestations: false

      - name: Read back published PyPI state
        if: always() && (steps.missing.outputs.upload == 'true' || steps.missing.outputs.state == 'published-exact')
        env:
          PYTHONPATH: src
          PYTHONDONTWRITEBYTECODE: '1'
        run: |
          "${{{{ steps.setup_python.outputs.python-path }}}}" -B -m rs9.tf_pypi_nebular readback --dist dist
""" + publication_resume_job_text()


def parser() -> argparse.ArgumentParser:
    """Build CLI parser for tf_pypi_nebular operations."""
    p = argparse.ArgumentParser(description=__doc__)
    sub = p.add_subparsers(dest="operation", required=True)

    b_cmd = sub.add_parser("build")
    b_cmd.add_argument("--output", type=Path, default=Path("dist"))
    b_cmd.add_argument("--scratch", type=Path, default=None)
    b_cmd.add_argument("--nebular-capture", type=Path, default=None)
    b_cmd.add_argument("--stellar-capture", type=Path, default=None)
    b_cmd.add_argument("--closure", type=Path, default=None)

    a_cmd = sub.add_parser("approval")
    a_cmd.add_argument("--output", type=Path, required=True)
    a_cmd.add_argument("--scratch", type=Path, default=None)
    a_cmd.add_argument("--nebular-capture", type=Path, required=True)
    a_cmd.add_argument("--stellar-capture", type=Path, required=True)
    a_cmd.add_argument("--closure", type=Path, required=True)

    p_cmd = sub.add_parser("prepare")
    p_cmd.add_argument("--output", type=Path, required=True)

    q_cmd = sub.add_parser("qualify")
    q_cmd.add_argument("--dist", type=Path, required=True)
    q_cmd.add_argument("--work", type=Path, required=True)
    q_cmd.add_argument("--nebular-capture", type=Path, required=True)
    q_cmd.add_argument("--stellar-capture", type=Path, required=True)
    q_cmd.add_argument("--closure", type=Path, required=True)
    q_cmd.add_argument("--python39", type=Path, default=Path("/usr/bin/python3"))
    q_cmd.add_argument("--report", type=Path, required=True)
    q_cmd.add_argument("--expected-commit", required=True)
    q_cmd.add_argument("--require-clean", action="store_true")

    s_cmd = sub.add_parser("select-missing")
    s_cmd.add_argument("--dist", type=Path, default=Path("dist"))
    s_cmd.add_argument("--upload-dir", type=Path, default=Path("upload"))
    s_cmd.add_argument("--attempt-marker", type=Path, default=None)

    vu_cmd = sub.add_parser("verify-upload")
    vu_cmd.add_argument("--dist", type=Path, default=Path("dist"))
    vu_cmd.add_argument("--upload-dir", type=Path, default=Path("upload"))

    r_cmd = sub.add_parser("readback")
    r_cmd.add_argument("--dist", type=Path, default=Path("dist"))

    wf_cmd = sub.add_parser("workflow")
    wf_cmd.add_argument("--release", choices=("0.6.1", "0.7.0"), default="0.6.1")
    return p


def main(
    argv: Sequence[str] | None = None,
    *,
    get: Callable[[str], bytes] | None = None,
    sleep_fn: Callable[[float], None] = time.sleep,
) -> int:
    """Run CLI dispatch with privacy-safe admission error handling."""
    args = parser().parse_args(argv)
    op = args.operation
    if op == "qualify":
        report: dict[str, Any] = {
            "schema": CONSUMER_REPORT_SCHEMA,
            "project": PROJECT,
            "status": "failed",
            "can_publish": False,
            "publication_admitted": False,
            "public_writes": 0,
        }
        code = 1
        try:
            report = qualify(
                args.dist,
                args.work,
                nebular_capture_dir=args.nebular_capture,
                stellar_capture_dir=args.stellar_capture,
                closure_dir=args.closure,
                expected_commit=args.expected_commit,
                python39_bin=args.python39,
                require_clean=bool(args.require_clean),
            )
            code = 0
        except HostStateError as error:
            report["error_code"] = error.code
            report["host_state_error"] = error.public_details()
        except AdmissionError as error:
            report["error_code"] = error.code
            if hasattr(error, "gate"):
                report["status"] = "blocked"
                report["blocked_gate"] = getattr(error, "gate")
            elif error.code == "TF_PYPI_RUNTIME_APPLICATION_SMOKE":
                report["smoke_observation"] = smoke_failure_observation(
                    getattr(error, "smoke_observation", None)
                )
        except Exception as error:
            report["error_type"] = type(error).__name__
        try:
            write_report(args.report, report)
        except AdmissionError as error:
            sys.stderr.write(error.code + "\n")
            return 1
        sys.stdout.write(
            json.dumps(
                {
                    "status": report["status"],
                    "project": PROJECT,
                    "can_publish": bool(report.get("can_publish", False)),
                    "publication_admitted": bool(
                        report.get("publication_admitted", False)
                    ),
                },
                sort_keys=True,
            )
            + "\n"
        )
        return code

    try:
        if op == "build":
            result = build_candidate(
                args.output,
                nebular_capture_dir=args.nebular_capture,
                stellar_capture_dir=args.stellar_capture,
                closure_dir=args.closure,
                scratch_dir=args.scratch,
                verify_against_committed=True,
            )
            sys.stdout.buffer.write(canonical(result))
            return 0
        if op == "approval":
            result = build_candidate(
                args.output,
                nebular_capture_dir=args.nebular_capture,
                stellar_capture_dir=args.stellar_capture,
                closure_dir=args.closure,
                scratch_dir=args.scratch,
                verify_against_committed=False,
            )
            sys.stdout.buffer.write(scratch_canonical(result))
            return 0
        if op == "prepare":
            result = prepare_hosted_inputs(args.output)
            sys.stdout.buffer.write(canonical(result))
            return 0
        if op == "select-missing":
            res = select_missing(
                args.dist,
                args.upload_dir,
                get=get,
                attempt_marker=args.attempt_marker,
            )
            sys.stdout.write(
                f"upload={'true' if res['upload'] else 'false'}\nstate={res['state']}\n"
            )
            return 0
        if op == "verify-upload":
            verify_upload_dir(args.dist, args.upload_dir)
            sys.stdout.write("verified=true\n")
            return 0
        if op == "readback":
            res = readback(args.dist, get=get, sleep_fn=sleep_fn)
            for att in res["attempts"]:
                sys.stdout.write(json.dumps(att, sort_keys=True) + "\n")
            sys.stdout.write(f"state={res['state']}\n")
            return 0
        if op == "workflow":
            sys.stdout.write(workflow_text(release=args.release))
            return 0
        return 1
    except AdmissionError as error:
        if hasattr(error, "attempts"):
            for att in getattr(error, "attempts"):
                sys.stdout.write(json.dumps(att, sort_keys=True) + "\n")
        if hasattr(error, "disposition"):
            sys.stderr.write(f"disposition={getattr(error, 'disposition')}\n")
        sys.stderr.write(error.code + "\n")
        return 1
    except (OSError, ValueError, KeyError, RuntimeError):
        sys.stderr.write("TF_PYPI_OPERATION_FAILED\n")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
