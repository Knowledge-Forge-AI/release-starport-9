"""Additive Theme Forge Nebular Fusion 0.7.0 three-wheel PyPI publisher seam.

Implements the minimal version-scoped 0.7.0 publication pin, 3-wheel artifact
approval manifest, strict Gate 2 matrix admission bridge, multi-wheel PyPI
remote state/readback verifier, two-checkout publication-resume helpers, and
registered workflow 0.7.0 job fragments while leaving the 0.6.1 single-wheel
Darwin path in rs9.tf_pypi_nebular untouched.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib
import io
import json
import os
import re
import shutil
import socket
import ssl
import stat
import subprocess
import sys
import time
import urllib.error
import urllib.request
import zipfile
from collections.abc import Callable, Mapping, Sequence
from pathlib import Path
from types import ModuleType
from typing import Any

from rs9.errors import ContractError
from rs9.github import PublicClient
from rs9.materialize import parse_manifest_members
from rs9.nebular070_manylinux import (
    ARCHIVE_PORTABILITY_INPUT_SCHEMA,
    ARCHIVE_PORTABILITY_SCHEMA,
    MAX_INPUT_BYTES,
    PORTABILITY_INPUT_SCHEMA,
    PORTABILITY_SCHEMA,
    validate_nebular070_payload_portability,
    ValidatedPayloadPortability,
    ValidatedReleaseAdmission,
    load_payload_portability_bundle,
    manylinux_tag_for_target,
    validate_nebular070_release_admission as _validate_nebular070_release_admission,
)
from rs9.release_core import digest
from rs9.scratch import canonical as gate1_canonical
from rs9.tf_pypi_archive import AdmissionError, canonical, physical_bytes, sha256
from rs9.tf_pypi_hosted import (
    NEBULAR070_EXPECTED_ARTIFACT_SCHEMA,
    NEBULAR070_MATRIX_SCHEMA,
    admit_nebular070_matrix,
    qualify_nebular070,
)
from rs9.tf_pypi_model import strict_json
from rs9.tf_pypi_remote import NoRedirect, _public_url
from rs9.verify_wheel import verify_wheel_record_bidirectional
from rs9.wheel_native import (
    get_embedded_rs9_helpers,
    validate_darwin_payload_floor,
)
from rs9.wheel_nebular_successor import (
    DESCRIPTION_070_PATH,
    GATE1_PROFILE,
    SYSTEM_WEBKIT_PROFILE,
    _validate_system_webkit_archive,
    _render_successor_launcher,
    _successor_entry_points_bytes,
    _successor_init_bytes,
    _successor_metadata_bytes,
    _successor_wheel_info_bytes,
    gate1_profile_record,
)

PROJECT = "theme-forge-nebular-fusion"
PACKAGE_NAME = "theme_forge_nebular_fusion"
DISTRIBUTION_NAME = "theme-forge-nebular-fusion"
DISTRIBUTION_WHEEL_PREFIX = "theme_forge_nebular_fusion"
VERSION = "0.7.0"
DISTRIBUTION_VERSION = "0.7.0"
TAG = "v0.7.0"
WORKFLOW = "rs9-tfnf-pypi-publish.yml"
QUALIFY_BRANCH = "rs9/nebular-pypi-qualify"
ENVIRONMENT = "pypi"
DEFAULT_GITHUB_REPOSITORY = "Knowledge-Forge-AI/release-starport-9"

EXPECTED_COMMAND = "tfnf"
EXPECTED_REQUIRES_PYTHON = ">=3.10"
EXPECTED_LICENSE_EXPRESSION = "AGPL-3.0-or-later"
FORBIDDEN_COMMERCIAL_EXPRESSION = "AGPL-3.0-or-later OR LicenseRef-Commercial"
EXPECTED_REQUIRED_LICENSE_FILES = ("LICENSE", "NOTICE")
EXPECTED_OPTIONAL_LICENSE_FILES = ("COMMERCIAL-LICENSE.md",)

DESCRIPTION_BASENAME = "nebular-fusion-0.7.0.md"
DESCRIPTION_PATH = Path(DESCRIPTION_070_PATH)
SYSTEM_WEBKIT_DESCRIPTION_PATH = Path(
    "operators/tf-pypi/descriptions/nebular-fusion-0.7.0-system-webkitgtk.md"
)
GATE1_PROFILE_PATH = Path("operators/tf-pypi/theme-forge-nebular-fusion-0.7.0-gate1.json")

PIN_BASENAME = "theme-forge-nebular-fusion-0.7.0.json"
PIN_PATH = Path("operators/tf-pypi") / PIN_BASENAME
APPROVAL_BASENAME = "theme-forge-nebular-fusion-0.7.0-artifacts.json"
APPROVAL_PATH = Path("operators/tf-pypi") / APPROVAL_BASENAME
CAPTURE_BASENAME = "theme-forge-nebular-fusion-0.7.0-qualification.json"
CAPTURE_PATH = Path("operators/tf-pypi") / CAPTURE_BASENAME
QUALIFICATION_INPUTS_BASENAME = "theme-forge-nebular-fusion-0.7.0-qualification-inputs.json"
QUALIFICATION_INPUTS_PATH = Path("operators/tf-pypi") / QUALIFICATION_INPUTS_BASENAME
PUBLIC_INPUTS_MANIFEST_PATH = Path(
    "operators/tf-pypi/theme-forge-nebular-fusion-0.7.0-public-inputs.json"
)
PUBLIC_INPUTS_ARTIFACT = "tfnf-070-public-inputs"
PUBLIC_INPUTS_TEMPLATE_DESCRIPTOR = "qualification-inputs.json"
PUBLIC_INPUTS_DESCRIPTOR = "qualification-inputs-prep.json"
PUBLIC_STAGE_A_SPEC = "stage-a-files.json"
PUBLIC_STAGE_A_OUTPUT = "evidence/public-release/generated-stage-a"
PUBLIC_INPUTS_PREPARATION_RECEIPT = "public-inputs-preparation.json"
PUBLIC_INPUTS_PREPARATION_SCHEMA = "rs9.tf-pypi-nebular070-public-inputs-preparation.v1"
SYSTEM_PUBLIC_INPUTS_PREPARATION_SCHEMA = "rs9.tf-pypi-nebular070-public-inputs-preparation.v2"
PUBLIC_TF_PRODUCER_SOURCE = {
    "commit": "79c67bb70d800701b4b0cdbb9caa9be2bbc7c2ff",
    "tree": "e663c9cf15144578a17d3cd501cf031ac83a7e0e",
}

PIN_SCHEMA = "rs9.tf-pypi-nebular-publication.v1"
APPROVAL_SCHEMA = "rs9.tf-pypi-nebular070-artifacts.v1"
CAPTURE_SCHEMA = "rs9.tf-pypi-nebular070-qualification-capture.v1"
QUALIFICATION_INPUTS_SCHEMA = "rs9.tf-pypi-nebular070-qualification-inputs.v1"
RAW_RELEASE_HANDOFF_SCHEMA = "rs9.tf-pypi-nebular070-raw-release-handoff.v1"
CANDIDATE_RECEIPT_SCHEMA = "rs9.nebular-successor-candidate.v2alpha1"
EXPECTED_ARTIFACT_SCHEMA = NEBULAR070_EXPECTED_ARTIFACT_SCHEMA
MATRIX_RECEIPT_SCHEMA = NEBULAR070_MATRIX_SCHEMA
PROVENANCE_SCHEMA = "rs9.wheel-provenance.v3alpha1"

TARGETS = ("darwin-arm64", "linux-arm64-gnu", "linux-x64-gnu")
SYSTEM_BY_TARGET = {
    "darwin-arm64": "aarch64-darwin",
    "linux-arm64-gnu": "aarch64-linux",
    "linux-x64-gnu": "x86_64-linux",
}
TARGET_BY_SYSTEM = {v: k for k, v in SYSTEM_BY_TARGET.items()}
TARGET_TRIPLE_BY_TARGET = {
    "darwin-arm64": "aarch64-apple-darwin",
    "linux-arm64-gnu": "aarch64-unknown-linux-gnu",
    "linux-x64-gnu": "x86_64-unknown-linux-gnu",
}
TAG_BY_TARGET = {
    "darwin-arm64": "py3-none-macosx_13_0_arm64",
    "linux-arm64-gnu": "py3-none-linux_aarch64",
    "linux-x64-gnu": "py3-none-linux_x86_64",
}
EXPECTED_WHEEL_FILENAMES = {
    target: f"{DISTRIBUTION_WHEEL_PREFIX}-{DISTRIBUTION_VERSION}-{TAG_BY_TARGET[target]}.whl"
    for target in TARGETS
}
TARGET_BY_FILENAME = {v: k for k, v in EXPECTED_WHEEL_FILENAMES.items()}

CANDIDATE_BUNDLE_ARTIFACT = "tfnf-070-candidate-bundle"
TARGET_QUALIFICATION_ARTIFACTS = {
    target: f"tfnf-070-qualification-{target}" for target in TARGETS
}
FLOOR_TARGET_QUALIFICATION_ARTIFACTS = {
    target: f"tfnf-070-qualification-{target}-floor"
    for target in ("linux-arm64-gnu", "linux-x64-gnu")
}
MATRIX_RECEIPT_ARTIFACT = "tfnf-070-matrix-receipt"
MATRIX_RECEIPT_MEMBER = "matrix_receipt.json"
MANYLINUX_ADMISSION_ARTIFACT = "tfnf-070-manylinux-admission"
MANYLINUX_ADMISSION_MEMBER = "manylinux_admission.json"
MANYLINUX_STAGE_A_MEMBER = "payload_portability.json"
MANYLINUX_CONSUMER_KINDS = ("floor", "newer")


def _manylinux_consumer_member(target: str, kind: str) -> str:
    """Return the closed Stage-B capture member name for one installed-wheel receipt."""
    if target not in ("linux-arm64-gnu", "linux-x64-gnu") or kind not in MANYLINUX_CONSUMER_KINDS:
        fail("MANYLINUX_CAPTURE_MEMBER")
    return f"consumers/{target}/{kind}.json"


def _manylinux_consumer_members() -> tuple[str, ...]:
    return tuple(
        _manylinux_consumer_member(target, kind)
        for target in ("linux-arm64-gnu", "linux-x64-gnu")
        for kind in MANYLINUX_CONSUMER_KINDS
    )


MANYLINUX_ADMISSION_MEMBERS = {
    MANYLINUX_ADMISSION_MEMBER,
    *_manylinux_consumer_members(),
}


def _resume_stage_b_member_path(resume: Path, name: str) -> Path:
    """Map one closed Stage-B archive member to its prepared resume path."""
    if name == MANYLINUX_ADMISSION_MEMBER:
        return resume / name
    if name in MANYLINUX_ADMISSION_MEMBERS and name != MANYLINUX_ADMISSION_MEMBER:
        return resume / "manylinux-consumers" / name
    fail("MANYLINUX_CAPTURE_MEMBER")


REQUIRED_CAPTURE_ARTIFACTS = (
    CANDIDATE_BUNDLE_ARTIFACT,
    TARGET_QUALIFICATION_ARTIFACTS["darwin-arm64"],
    TARGET_QUALIFICATION_ARTIFACTS["linux-arm64-gnu"],
    TARGET_QUALIFICATION_ARTIFACTS["linux-x64-gnu"],
    MATRIX_RECEIPT_ARTIFACT,
)


def _capture_artifact_names(
    approval: Mapping[str, Any] | None = None,
    artifacts: Mapping[str, Any] | None = None,
) -> tuple[str, ...]:
    """Return the capture artifact set, adding Stage B only for a qualified claim."""
    names = list(REQUIRED_CAPTURE_ARTIFACTS)
    stage_a_claimed = isinstance(approval, Mapping) and approval.get("manylinux_stage_a_sha256") is not None
    if stage_a_claimed or (
        approval is None
        and isinstance(artifacts, Mapping)
        and MANYLINUX_ADMISSION_ARTIFACT in artifacts
    ):
        names.append(MANYLINUX_ADMISSION_ARTIFACT)
    return tuple(names)
REQUIRED_RESUME_FILES = (
    PIN_BASENAME,
    APPROVAL_BASENAME,
    CAPTURE_BASENAME,
)
QUALIFICATION_SOURCE_HELPERS = (
    "src/rs9/tf_pypi_hosted.py",
    "src/rs9/tf_pypi_nebular_successor.py",
    "src/rs9/tf_pypi_nebular070_publish.py",
    "src/rs9/tf_pypi_consumer.py",
    "src/rs9/wheel_nebular_successor.py",
)

# Project-specific PyPI upload limit is UNKNOWN while logged out; actual 0.7.0
# Linux archives are ~164 MiB (ARM64) and ~224 MiB (AMD64). Allow up to 512 MiB
# for local/remote inspection while still enforcing exact approved byte size.
MAX_WHEEL_FILE_BYTES = 512 * 1024 * 1024
MAX_PAYLOAD_UNCOMPRESSED_BYTES = 2 * 1024 * 1024 * 1024
MAX_TOTAL_UNCOMPRESSED_BYTES = 3 * 1024 * 1024 * 1024
MAX_ZIP_MEMBERS = 64

READBACK_SCHEDULE_SECONDS: tuple[int, ...] = (0, 15, 30, 60, 120, 180)
PRIOR_RUN_PAGE_SIZE = 100
PRIOR_RUN_MAX_PAGES = 20

CHECKOUT_ACTION = "actions/checkout@fbc6f3992d24b796d5a048ff273f7fcc4a7b6c09"
SETUP_PYTHON_ACTION = "actions/setup-python@ece7cb06caefa5fff74198d8649806c4678c61a1"
SETUP_NODE_ACTION = "actions/setup-node@249970729cb0ef3589644e2896645e5dc5ba9c38"
UPLOAD_ARTIFACT_ACTION = "actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02"
DOWNLOAD_ARTIFACT_ACTION = "actions/download-artifact@d3f86a106a0bac45b974a628896c90dbdf5c8093"
PYPA_PUBLISH_ACTION = "pypa/gh-action-pypi-publish@ed0c53931b1dc9bd32cbe73a98c7f6766f8a527e"

# Release-scoped Linux native-consumer display policy.  The Bookworm floor
# jobs use exact package versions; the hosted Ubuntu jobs use the same minimal
# package class while recording the runner-resolved versions.
BOOKWORM_DISPLAY_TOOL_PACKAGES = (
    "xvfb=2:21.1.7-3+deb12u13",
    "xauth=1:1.1.2-1",
    "dbus-x11=1.14.10-1~deb12u1",
)
UBUNTU_DISPLAY_TOOL_PACKAGES = ("xvfb", "xauth", "dbus-x11")
DISPLAY_TOOL_COMMANDS = ("xvfb-run", "xauth", "dbus-run-session")

RESUME_070_JOB_NAME = "Attended Nebular 0.7.0 PyPI publication resume"
# The system-WebKit profile owns the host GTK/WebKit closure.  Keep the
# distro package lists explicit and separate from the display-tool class so a
# portable/manylinux run never installs or records the system profile.
UBUNTU_SYSTEM_WEBKIT_PACKAGES = (
    "libgtk-3-0t64",
    "libcairo2",
    "libpango-1.0-0",
    "libgdk-pixbuf-2.0-0",
    "libsoup-3.0-0",
    "libwebkit2gtk-4.1-0",
    "libjavascriptcoregtk-4.1-0",
)
BOOKWORM_SYSTEM_WEBKIT_PACKAGES = (
    "libgtk-3-0",
    "libcairo2",
    "libpango-1.0-0",
    "libgdk-pixbuf-2.0-0",
    "libsoup-3.0-0",
    "libwebkit2gtk-4.1-0",
    "libjavascriptcoregtk-4.1-0",
)

RESUME_070_JOB_NAME = "Attended Nebular 0.7.0 PyPI publication resume"
PREPARE_PUBLIC_INPUTS_070_JOB_NAME = "Prepare held Nebular 0.7.0 public inputs"
PUBLISH_JOB_NAMES = frozenset({
    RESUME_070_JOB_NAME,
})
DISPATCH_GUARD_070_JOB_NAME = "Reject unsupported release and mode combination"
BUILD_VERIFY_070_JOB_NAME = "Build and Verify Nebular 0.7.0 Candidate Bundle"
NATIVE_CONSUMER_070_JOB_NAMES = frozenset({
    "Native consumer 0.7.0 (darwin-arm64)",
    "Native consumer 0.7.0 (linux-arm64-gnu)",
    "Native consumer 0.7.0 (linux-x64-gnu)",
    "Native consumer 0.7.0 (linux-arm64-gnu floor)",
    "Native consumer 0.7.0 (linux-x64-gnu floor)",
})
NATIVE_CONSUMER_070_FLOOR_JOB_NAMES = frozenset({
    "Native consumer 0.7.0 (linux-arm64-gnu floor)",
    "Native consumer 0.7.0 (linux-x64-gnu floor)",
})
QUALIFICATION_GATE_070_JOB_NAME = "Qualification matrix gate 0.7.0"
QUALIFY_070_JOB_NAMES = (
    frozenset({
        PREPARE_PUBLIC_INPUTS_070_JOB_NAME,
        BUILD_VERIFY_070_JOB_NAME,
        QUALIFICATION_GATE_070_JOB_NAME,
    })
    | NATIVE_CONSUMER_070_JOB_NAMES
)
LEGACY_061_BUILD_JOB_NAME = "Build and Verify Native Darwin Wheel"
LEGACY_061_CONSUMER_JOB_NAME = "Native macOS ARM64 installed consumer and Scenario A"
LEGACY_061_PUBLISH_JOB_NAME = "Trusted Publishing to PyPI"
LEGACY_061_JOB_NAMES = frozenset({
    LEGACY_061_BUILD_JOB_NAME,
    LEGACY_061_CONSUMER_JOB_NAME,
    LEGACY_061_PUBLISH_JOB_NAME,
})

# The Actions jobs API includes runner-owned ``Set up job``/``Complete job``
# records and may include a post record for an action step.  Keep the
# maintained, display-name keyed profiles explicit: the second tuple member
# records that the generated step is a ``uses`` step, which is the only kind
# allowed to receive a corresponding ``Post <step name>`` record.
WORKFLOW_STEP_PROFILES = {
    PREPARE_PUBLIC_INPUTS_070_JOB_NAME: (
        ("Checkout repository", True),
        ("Set up Python 3.13", True),
        ("Resolve current source tree", False),
        ("Prepare held 0.7.0 public inputs", False),
        ("Upload 0.7.0 public inputs", True),
    ),
    DISPATCH_GUARD_070_JOB_NAME: (
        ("Checkout repository", True),
        ("Set up Python 3.13", True),
        ("Fail closed on unsupported release and mode combination", False),
    ),
    BUILD_VERIFY_070_JOB_NAME: (
        ('Checkout repository', True),
        ('Set up Python 3.13', True),
        ('Download 0.7.0 public inputs', True),
        ('Validate explicit 0.7.0 runtime profile', False),
        ('Build and verify 0.7.0 candidate bundle', False),
        ('Upload 0.7.0 candidate bundle', True),
    ),
    "Native consumer 0.7.0 (darwin-arm64)": (
        ("Checkout exact source", True),
        ("Set up Python 3.13", True),
        ("Set up Node 22", True),
        ("Download 0.7.0 candidate bundle", True),
        ("Download 0.7.0 public inputs", True),
        ("Qualify native consumer on darwin-arm64", False),
        ("Upload darwin-arm64 qualification receipt", True),
        ("Upload failed native harness report", True),
    ),
    "Native consumer 0.7.0 (linux-arm64-gnu)": (
        ("Checkout exact source", True),
        ("Set up Python 3.13", True),
        ("Set up Node 22", True),
        ("Install minimal Ubuntu display tools", False),
        ("Verify Ubuntu display tool class", False),
        ("Download 0.7.0 candidate bundle", True),
        ("Download 0.7.0 public inputs", True),
        ("Resolve explicit Linux runtime profile", False),
        ("Install Ubuntu system WebKit runtime packages", False),
        ("Verify Ubuntu system WebKit runtime packages", False),
        ("Qualify native consumer on linux-arm64-gnu", False),
        ("Upload linux-arm64-gnu qualification receipt", True),
        ("Upload failed native harness report", True),
    ),
    "Native consumer 0.7.0 (linux-x64-gnu)": (
        ("Checkout exact source", True),
        ("Set up Python 3.13", True),
        ("Set up Node 22", True),
        ("Install minimal Ubuntu display tools", False),
        ("Verify Ubuntu display tool class", False),
        ("Download 0.7.0 candidate bundle", True),
        ("Download 0.7.0 public inputs", True),
        ("Resolve explicit Linux runtime profile", False),
        ("Install Ubuntu system WebKit runtime packages", False),
        ("Verify Ubuntu system WebKit runtime packages", False),
        ("Qualify native consumer on linux-x64-gnu", False),
        ("Upload linux-x64-gnu qualification receipt", True),
        ("Upload failed native harness report", True),
    ),
    "Native consumer 0.7.0 (linux-arm64-gnu floor)": (
        ("Install pinned Bookworm floor tools", False),
        ("Verify Bookworm display tool class", False),
        ("Checkout exact source", True),
        ("Select pinned Bookworm Python 3.11", False),
        ("Set up Node 22", True),
        ("Download 0.7.0 candidate bundle", True),
        ("Download 0.7.0 public inputs", True),
        ("Resolve explicit Linux runtime profile", False),
        ("Check Bookworm installed tfnf missing system WebKit before runtime install", False),
        ("Install Bookworm system WebKit runtime packages", False),
        ("Verify Bookworm system WebKit runtime packages", False),
        ("Qualify native consumer on linux-arm64-gnu floor", False),
        ("Upload linux-arm64-gnu floor qualification receipt", True),
        ("Upload failed native harness report", True),
    ),
    "Native consumer 0.7.0 (linux-x64-gnu floor)": (
        ("Install pinned Bookworm floor tools", False),
        ("Verify Bookworm display tool class", False),
        ("Checkout exact source", True),
        ("Select pinned Bookworm Python 3.11", False),
        ("Set up Node 22", True),
        ("Download 0.7.0 candidate bundle", True),
        ("Download 0.7.0 public inputs", True),
        ("Resolve explicit Linux runtime profile", False),
        ("Check Bookworm installed tfnf missing system WebKit before runtime install", False),
        ("Install Bookworm system WebKit runtime packages", False),
        ("Verify Bookworm system WebKit runtime packages", False),
        ("Qualify native consumer on linux-x64-gnu floor", False),
        ("Upload linux-x64-gnu floor qualification receipt", True),
        ("Upload failed native harness report", True),
    ),
    QUALIFICATION_GATE_070_JOB_NAME: (
        ('Checkout exact source', True),
        ('Set up Python 3.13', True),
        ('Download 0.7.0 candidate bundle', True),
        ('Download 0.7.0 public inputs', True),
        ('Validate explicit 0.7.0 runtime profile for matrix', False),
        ('Download darwin-arm64 qualification receipt', True),
        ('Download linux-arm64-gnu qualification receipt', True),
        ('Download linux-x64-gnu qualification receipt', True),
        ('Download linux-arm64-gnu floor qualification receipt', True),
        ('Download linux-x64-gnu floor qualification receipt', True),
        ('Verify floor consumer receipts', False),
        ('Admit complete 3-platform 0.7.0 qualification matrix', False),
        ('Upload 0.7.0 matrix qualification receipt', True),
        ('Assemble authenticated 0.7.0 Stage-B admission input', False),
        ('Verify system-WebKit matrix has no manylinux admission', False),
        ('Upload 0.7.0 manylinux admission input', True),
    ),
    RESUME_070_JOB_NAME: (
        ("Checkout publisher authority commit", True),
        ("Set up Python 3.13", True),
        ("Resolve pinned qualification commit from publisher authority", False),
        ("Checkout exact qualified source commit", True),
        ("Verify publisher and qualification source lineage", False),
        ("Fetch retained qualification run and artifact archives", False),
        ("Extract and bind held public input roots", False),
        ("Authenticate retained archives and stage verified distribution", False),
        ("Verify external Stage-B and Stage-A bindings", False),
        ("Resolve captured 0.7.0 manylinux source coordinates", False),
        ("Stage admitted 0.7.0 operator metadata into qualification checkout", False),
        ("Verify artifact integrity and select only missing files", False),
        ("Re-verify staged upload artifacts against approval before upload", False),
        ("Publish package distribution to PyPI", True),
        ("Read back published PyPI state", False),
    ),
    LEGACY_061_BUILD_JOB_NAME: (
        ("Checkout repository", True),
        ("Set up Python 3.13", True),
        ("Build and verify candidate wheel", False),
        ("Stage verified wheel artifact", True),
    ),
    LEGACY_061_CONSUMER_JOB_NAME: (
        ("Checkout exact source", True),
        ("Set up Python 3.13", True),
        ("Set up Node 22", True),
        ("Download the same run's verified wheel", True),
        ("Prepare authenticated captures and verifier closure outside network denial", False),
        ("Qualify installed wheel and Darwin Scenario A under network denial", False),
        ("Preserve native consumer result", True),
    ),
    LEGACY_061_PUBLISH_JOB_NAME: (
        ("Checkout repository", True),
        ("Set up Python 3.13", True),
        ("Download staged artifacts", True),
        ("Verify artifact integrity and select only missing files", False),
        ("Re-verify staged upload artifact against approval before upload", False),
        ("Publish package distribution to PyPI", True),
        ("Read back published PyPI state", False),
    ),
}
WORKFLOW_STEP_PROFILE_ALLOWED_NAMES = {
    job_name: frozenset(
        {step_name for step_name, _is_action in profile}
        | {"Set up job", "Complete job"}
        | {
            f"Post {step_name}"
            for step_name, is_action in profile
            if is_action
        }
    )
    for job_name, profile in WORKFLOW_STEP_PROFILES.items()
}
CURRENT_070_PROFILE_JOB_NAMES = (
    QUALIFY_070_JOB_NAMES | PUBLISH_JOB_NAMES | frozenset({DISPATCH_GUARD_070_JOB_NAME})
)
ALL_KNOWN_WORKFLOW_JOB_NAMES = (
    PUBLISH_JOB_NAMES
    | QUALIFY_070_JOB_NAMES
    | LEGACY_061_JOB_NAMES
    | frozenset({DISPATCH_GUARD_070_JOB_NAME})
)
PUBLISH_PYPI_STEP_NAME = "Publish package distribution to PyPI"
VALID_WORKFLOW_RUN_CONCLUSIONS = frozenset({
    "success",
    "failure",
    "cancelled",
    "timed_out",
})
VALID_WORKFLOW_JOB_CONCLUSIONS = frozenset({
    "success",
    "failure",
    "cancelled",
    "skipped",
    "timed_out",
})
ACTIVE_FAILURE_CONCLUSIONS = frozenset({
    "failure",
    "cancelled",
    "timed_out",
})
DARWIN_QUALIFY_SANDBOX_PROFILE = "(version 1)(allow default)(deny network*)"
LINUX_SANDBOX_PRESERVE_ENV = (
    "PATH,HOME,TMPDIR,TEMP,TMP,LANG,LC_ALL,"
    "PIP_CONFIG_FILE,PIP_NO_INDEX,PIP_NO_CACHE_DIR,PIP_DISABLE_PIP_VERSION_CHECK,"
    "PYTHONDONTWRITEBYTECODE,XDG_CACHE_HOME,XDG_CONFIG_HOME,XDG_DATA_HOME,XDG_STATE_HOME"
)
REQUIRED_RAW_RELEASE_HANDOFF_KEYS = frozenset({
    "root",
    "record",
    "readme",
    "legal_files",
    "payload",
    "manifest",
    "provenance",
    "native_consumer",
})
REQUIRED_DESCRIPTOR_TARGET_RAW_RELEASE_KEYS = REQUIRED_RAW_RELEASE_HANDOFF_KEYS - frozenset({"root"})
OPTIONAL_DESCRIPTOR_TARGET_RAW_RELEASE_KEYS = frozenset({"schema", "target"})
OPTIONAL_RAW_RELEASE_HANDOFF_KEYS = frozenset({
    "schema",
    "target",
    "candidate_receipt_sha256",
    "expected_artifact_record_sha256",
    "profile_result_sha256",
    "wheel_sha256",
})
REQUIRED_QUALIFICATION_INPUTS_KEYS = frozenset({
    "schema",
    "project",
    "version",
    "distribution_version",
    "workflow",
    "status",
    "upstream_origin",
    "release_binding",
    "release_binding_sha256",
    "evidence",
    "raw_release",
})
OPTIONAL_QUALIFICATION_INPUTS_KEYS = frozenset({"manylinux", "system_webkit"})
SYSTEM_WEBKIT_INPUT_SCHEMA = "rs9.tf-pypi-nebular070-public-inrun-system-webkit.v1"
SYSTEM_WEBKIT_PROFILE_ID = "nebular-fusion-0.7.0-system-webkitgtk-4.1-v1"
SYSTEM_WEBKIT_RUNTIME_PROFILE = "system-webkitgtk-4.1"
SYSTEM_WEBKIT_INPUT_KEYS = frozenset({"schema", "origin_kind", "profile_id"})
MANYLINUX_INPUT_SPEC_KEYS = frozenset({"stage_a", "stage_b", "tf_producer_source"})
PUBLIC_INRUN_MANYLINUX_SCHEMA = "rs9.tf-pypi-nebular070-public-inrun-manylinux.v1"
PUBLIC_INRUN_MANYLINUX_ORIGIN_KIND = "public-in-run"
PUBLIC_INRUN_MANYLINUX_INPUT_SPEC_KEYS = frozenset({
    "schema",
    "origin_kind",
    "stage_a",
    "stage_b",
    "tf_producer_source",
})
QUALIFICATION_INPUT_PHASE_PREP = "qualification-prep"
QUALIFICATION_INPUT_PHASE_PUBLICATION = "publication"
QUALIFICATION_INPUT_PHASES = frozenset({
    QUALIFICATION_INPUT_PHASE_PREP,
    QUALIFICATION_INPUT_PHASE_PUBLICATION,
})

_HEX40_RE = re.compile(r"^[0-9a-f]{40}$")
_HEX64_RE = re.compile(r"^[0-9a-f]{64}$")
_NUMERIC_ID_RE = re.compile(r"^[1-9][0-9]*$")

REQUIRED_PIN_KEYS = frozenset({
    "schema",
    "project",
    "version",
    "distribution_version",
    "workflow",
    "environment",
    "license",
    "description",
    "candidate_platforms",
    "qualified_platforms",
    "source_status",
    "withheld",
    "artifacts_manifest",
    "qualification_manifest",
    "qualification",
    "publication_admitted",
})

REQUIRED_READY_QUALIFICATION_KEYS = frozenset({
    "candidate_source_commit",
    "candidate_source_tree",
    "qualification_source_commit",
    "qualification_source_tree",
    "qualification_run_id",
    "qualification_run_attempt",
    "candidate_receipt_sha256",
    "expected_artifact_record_sha256",
    "profile_sha256",
    "matrix_receipt_sha256",
    "target_qualification_sources",
})

REQUIRED_APPROVAL_KEYS = frozenset({
    "schema",
    "project",
    "distribution",
    "version",
    "distribution_version",
    "workflow",
    "environment",
    "requires_python",
    "command",
    "license_expression",
    "license_files",
    "readme",
    "candidate_receipt_sha256",
    "expected_artifact_record_sha256",
    "profile_sha256",
    "matrix_receipt_sha256",
    "qualification",
    "files",
    "builder_can_publish",
    "publication_admitted",
    "set_sha256",
})

REQUIRED_FILE_RECORD_KEYS = frozenset({
    "target",
    "system",
    "filename",
    "size",
    "sha256",
    "tag",
    "version",
    "payload_archive_name",
    "payload_archive_sha256",
    "manifest_sha256",
})

REQUIRED_CAPTURE_KEYS = frozenset({
    "schema",
    "project",
    "version",
    "distribution_version",
    "workflow",
    "repository",
    "run_id",
    "run_attempt",
    "head_branch",
    "event",
    "status",
    "conclusion",
    "candidate_source_commit",
    "candidate_source_tree",
    "qualification_source_commit",
    "qualification_source_tree",
    "candidate_receipt_sha256",
    "expected_artifact_record_sha256",
    "profile_sha256",
    "matrix_receipt_sha256",
    "artifacts",
})


def fail(code: str) -> None:
    """Raise a closed AdmissionError with TF_PYPI_ prefix."""
    raise AdmissionError(f"TF_PYPI_{code}")


def _system_runtime_profile(value: Mapping[str, Any]) -> bool:
    """Require an explicit system profile; missing portability is not selection."""
    if "linux_runtime_profile" not in value:
        return False
    if (value["linux_runtime_profile"] != SYSTEM_WEBKIT_RUNTIME_PROFILE
            or "manylinux_stage_a_sha256" in value):
        fail("RUNTIME_PROFILE")
    return True


def repo_root(repository: str | Path | None = None) -> Path:
    """Return physical repository root and reject symlinked paths."""
    root = (
        Path(repository)
        if repository is not None
        else Path(__file__).resolve().parents[2]
    )
    if any(p.is_symlink() for p in (root, *root.parents)):
        fail("REPO_SYMLINK")
    return root.resolve()


def _check_no_symlinks(path: Path, code: str = "SYMLINK") -> None:
    if any(p.is_symlink() for p in (path, *path.parents)):
        fail(code)


def _validate_consumer_capture_options(
    target: str,
    consumer_host_role: str | None,
    consumer_capture_output: str | Path | None,
) -> Path | None:
    """Validate the opt-in Linux Stage-B capture destination before native work."""
    if (consumer_host_role is None) != (consumer_capture_output is None):
        fail("CONSUMER_CAPTURE_OPTIONS")
    if consumer_host_role is None:
        return None
    if target not in ("linux-arm64-gnu", "linux-x64-gnu"):
        fail("CONSUMER_CAPTURE_TARGET")
    if consumer_host_role not in MANYLINUX_CONSUMER_KINDS:
        fail("CONSUMER_CAPTURE_ROLE")
    if not isinstance(consumer_capture_output, (str, os.PathLike)):
        fail("CONSUMER_CAPTURE_OUTPUT")
    path = Path(consumer_capture_output)
    _check_no_symlinks(path, "CONSUMER_CAPTURE_SYMLINK")
    if path.exists():
        fail("CONSUMER_CAPTURE_OUTPUT")
    if path.parent.exists() and not path.parent.is_dir():
        fail("CONSUMER_CAPTURE_OUTPUT")
    return path


def _is_hex40(val: Any) -> bool:
    return isinstance(val, str) and bool(_HEX40_RE.fullmatch(val))


def _is_hex64(val: Any) -> bool:
    return isinstance(val, str) and bool(_HEX64_RE.fullmatch(val))


def _normalize_description_field(value: Any, *, system_webkit: bool = False) -> str:
    if not isinstance(value, str) or not value:
        fail("PIN_DESCRIPTION")
    expected = SYSTEM_WEBKIT_DESCRIPTION_PATH if system_webkit else DESCRIPTION_PATH
    if value in (expected.name, str(expected)):
        return str(expected)
    fail("PIN_DESCRIPTION")
    raise AssertionError("unreachable")


def _validate_ready_qualification_block(
    qual: Any,
    *,
    code_prefix: str = "PIN",
) -> dict[str, Any]:
    if not isinstance(qual, dict):
        fail(f"{code_prefix}_QUALIFICATION")
    allowed = set(REQUIRED_READY_QUALIFICATION_KEYS) | {"release_tag_commit"}
    if not REQUIRED_READY_QUALIFICATION_KEYS.issubset(qual.keys()) or (set(qual.keys()) - allowed):
        fail(f"{code_prefix}_QUALIFICATION")

    cand_commit = qual.get("candidate_source_commit")
    cand_tree = qual.get("candidate_source_tree")
    qual_commit = qual.get("qualification_source_commit")
    qual_tree = qual.get("qualification_source_tree")
    run_id = qual.get("qualification_run_id")
    run_attempt = qual.get("qualification_run_attempt")
    cand_sha = qual.get("candidate_receipt_sha256")
    exp_sha = qual.get("expected_artifact_record_sha256")
    prof_sha = qual.get("profile_sha256")
    mat_sha = qual.get("matrix_receipt_sha256")
    target_sources = qual.get("target_qualification_sources")

    if (
        not _is_hex40(cand_commit)
        or not _is_hex40(cand_tree)
        or not _is_hex40(qual_commit)
        or not _is_hex40(qual_tree)
        or not isinstance(run_id, str)
        or not _NUMERIC_ID_RE.fullmatch(run_id)
        or run_attempt != "1"
        or not _is_hex64(cand_sha)
        or not _is_hex64(exp_sha)
        or not _is_hex64(prof_sha)
        or not _is_hex64(mat_sha)
        or not isinstance(target_sources, dict)
        or set(target_sources.keys()) != set(TARGETS)
    ):
        fail(f"{code_prefix}_QUALIFICATION")

    if "release_tag_commit" in qual:
        tag_commit = qual["release_tag_commit"]
        if not _is_hex40(tag_commit):
            fail(f"{code_prefix}_QUALIFICATION")
        if tag_commit in (cand_commit, qual_commit):
            fail("SOURCE_IDENTITY_CONFLATED")

    for target in TARGETS:
        tsrc = target_sources.get(target)
        if (
            not isinstance(tsrc, dict)
            or set(tsrc.keys()) != {"commit", "tree", "status", "verified"}
            or tsrc.get("commit") != qual_commit
            or tsrc.get("tree") != qual_tree
            or tsrc.get("status") != "verified-hosted-checkout"
            or tsrc.get("verified") is not True
        ):
            fail(f"{code_prefix}_QUALIFICATION")
    return qual


def pin_path(repository: str | Path | None = None) -> Path:
    """Return path to the 0.7.0 Nebular publication pin."""
    path = repo_root(repository) / PIN_PATH
    _check_no_symlinks(path, "PIN_SYMLINK")
    return path


def validate_pin(pin: Mapping[str, Any]) -> dict[str, Any]:
    """Validate the closed 0.7.0 Nebular publication pin schema."""
    if not isinstance(pin, dict):
        fail("PIN_SCHEMA")
    allowed_pin_keys = set(REQUIRED_PIN_KEYS) | {"admission_sha256", "linux_runtime_profile"}
    if not REQUIRED_PIN_KEYS.issubset(pin.keys()) or (set(pin.keys()) - allowed_pin_keys):
        fail("PIN_SCHEMA")

    if (
        pin.get("schema") != PIN_SCHEMA
        or pin.get("project") != PROJECT
        or pin.get("version") != VERSION
        or pin.get("distribution_version") != DISTRIBUTION_VERSION
        or pin.get("workflow") != WORKFLOW
        or pin.get("environment") != ENVIRONMENT
    ):
        fail("PIN_SCHEMA")

    lic = pin.get("license")
    if lic != EXPECTED_LICENSE_EXPRESSION:
        fail("PIN_LICENSE")

    _normalize_description_field(pin.get("description"), system_webkit=_system_runtime_profile(pin))

    if (
        pin.get("candidate_platforms") != list(TARGETS)
        or pin.get("artifacts_manifest") != APPROVAL_BASENAME
        or pin.get("qualification_manifest") != CAPTURE_BASENAME
        or type(pin.get("publication_admitted")) is not bool
    ):
        fail("PIN_SCHEMA")

    q_plats = pin.get("qualified_platforms")
    if (
        not isinstance(q_plats, list)
        or any(not isinstance(p, str) for p in q_plats)
        or len(q_plats) != len(set(q_plats))
        or any(p not in TARGETS for p in q_plats)
    ):
        fail("PIN_PLATFORMS")

    withheld = pin.get("withheld")
    if (
        not isinstance(withheld, list)
        or any(not isinstance(item, str) or not item.strip() for item in withheld)
    ):
        fail("PIN_SCHEMA")

    status = pin.get("source_status")
    admitted = pin["publication_admitted"]
    qual = pin.get("qualification")
    if not isinstance(qual, dict):
        fail("PIN_QUALIFICATION")

    if status == "BLOCKED":
        if admitted is not False or q_plats != [] or not withheld:
            fail("PIN_BLOCKED_INCONSISTENT")
        if pin.get("admission_sha256") is not None:
            fail("PIN_ADMISSION_DIGEST")
    elif status == "READY":
        if q_plats != list(TARGETS) or withheld != []:
            fail("PIN_READY_INCOMPLETE")
        _validate_ready_qualification_block(qual, code_prefix="PIN")
        if admitted is False:
            if pin.get("admission_sha256") is not None:
                fail("PIN_ADMISSION_DIGEST")
        else:
            if not _is_hex64(pin.get("admission_sha256")):
                fail("PIN_ADMISSION_DIGEST")
    else:
        fail("PIN_SCHEMA")

    return dict(pin)


def load_pin(
    repository: str | Path | None = None,
    *,
    path: str | Path | None = None,
) -> dict[str, Any]:
    """Load and validate the 0.7.0 Nebular publication pin; fail closed when absent."""
    if path is None:
        target = pin_path(repository)
    else:
        target = Path(path)
        _check_no_symlinks(target, "PIN_SYMLINK")
        if target.name != PIN_BASENAME:
            fail("PIN_PATH")
    if not target.is_file():
        fail("PIN_ABSENT")
    data = physical_bytes(target, limit=1024 * 1024)
    return validate_pin(strict_json(data))


def approval_path(repository: str | Path | None = None) -> Path:
    """Return path to the 0.7.0 Nebular 3-wheel approval manifest."""
    path = repo_root(repository) / APPROVAL_PATH
    _check_no_symlinks(path, "APPROVAL_SYMLINK")
    return path


def compute_set_sha256(approval: Mapping[str, Any]) -> str:
    """Compute canonical digest of the 0.7.0 approval manifest excluding set_sha256, publication_admitted, and admission_sha256."""
    body = {
        k: v
        for k, v in approval.items()
        if k not in ("set_sha256", "publication_admitted", "admission_sha256")
    }
    return sha256(canonical(body))


def compute_admission_sha256(approval: Mapping[str, Any]) -> str:
    """Compute reviewed cryptographic admission digest binding set_sha256, matrix receipt, and publication_admitted=True."""
    return sha256(
        canonical(
            {
                "schema": "rs9.tf-pypi-nebular070-admission-binding.v1",
                "project": PROJECT,
                "distribution": DISTRIBUTION_NAME,
                "version": VERSION,
                "distribution_version": DISTRIBUTION_VERSION,
                "workflow": WORKFLOW,
                "environment": ENVIRONMENT,
                "publication_admitted": True,
                "set_sha256": approval.get("set_sha256"),
                "candidate_receipt_sha256": approval.get("candidate_receipt_sha256"),
                "expected_artifact_record_sha256": approval.get("expected_artifact_record_sha256"),
                "profile_sha256": approval.get("profile_sha256"),
                "matrix_receipt_sha256": approval.get("matrix_receipt_sha256"),
                "manylinux_stage_a_sha256": approval.get("manylinux_stage_a_sha256"),
                "qualification": approval.get("qualification"),
            }
        )
    )


def validate_approval(doc: Mapping[str, Any]) -> dict[str, Any]:
    """Validate the closed 3-wheel 0.7.0 artifact approval manifest schema, set_sha256, and admission_sha256."""
    if not isinstance(doc, dict):
        fail("APPROVAL_SCHEMA")
    allowed_approval_keys = set(REQUIRED_APPROVAL_KEYS) | {
        "admission_sha256", "manylinux_stage_a_sha256", "linux_runtime_profile",
    }
    if not REQUIRED_APPROVAL_KEYS.issubset(doc.keys()) or (set(doc.keys()) - allowed_approval_keys):
        fail("APPROVAL_SCHEMA")

    if (
        doc.get("schema") != APPROVAL_SCHEMA
        or doc.get("project") != PROJECT
        or doc.get("distribution") != DISTRIBUTION_NAME
        or doc.get("version") != VERSION
        or doc.get("distribution_version") != DISTRIBUTION_VERSION
        or doc.get("workflow") != WORKFLOW
        or doc.get("environment") != ENVIRONMENT
        or doc.get("requires_python") != EXPECTED_REQUIRES_PYTHON
        or doc.get("command") != EXPECTED_COMMAND
        or doc.get("builder_can_publish") is not False
        or type(doc.get("publication_admitted")) is not bool
    ):
        fail("APPROVAL_SCHEMA")

    if doc.get("license_expression") != EXPECTED_LICENSE_EXPRESSION:
        fail("APPROVAL_LICENSE")
    system_webkit = _system_runtime_profile(doc)

    lic_files = doc.get("license_files")
    if not isinstance(lic_files, dict):
        fail("APPROVAL_LICENSE")
    allowed_legal = set(EXPECTED_REQUIRED_LICENSE_FILES) | set(EXPECTED_OPTIONAL_LICENSE_FILES)
    if (
        not set(EXPECTED_REQUIRED_LICENSE_FILES).issubset(lic_files.keys())
        or (set(lic_files.keys()) - allowed_legal)
    ):
        fail("APPROVAL_LICENSE")
    for name, entry in lic_files.items():
        if (
            not isinstance(entry, dict)
            or set(entry.keys()) != {"path", "size", "sha256"}
            or entry.get("path") != name
            or type(entry.get("size")) is not int
            or entry["size"] <= 0
            or not _is_hex64(entry.get("sha256"))
        ):
            fail("APPROVAL_LICENSE")

    readme = doc.get("readme")
    if (
        not isinstance(readme, dict)
        or set(readme.keys()) not in ({"path", "sha256"}, {"path", "size", "sha256"})
        or readme.get("path") != str(
            SYSTEM_WEBKIT_DESCRIPTION_PATH if system_webkit else DESCRIPTION_PATH
        )
        or not _is_hex64(readme.get("sha256"))
    ):
        fail("APPROVAL_README")
    if "size" in readme and (type(readme["size"]) is not int or readme["size"] <= 0):
        fail("APPROVAL_README")

    cand_sha = doc.get("candidate_receipt_sha256")
    exp_sha = doc.get("expected_artifact_record_sha256")
    prof_sha = doc.get("profile_sha256")
    mat_sha = doc.get("matrix_receipt_sha256")
    if (
        not _is_hex64(cand_sha)
        or not _is_hex64(exp_sha)
        or not _is_hex64(prof_sha)
        or not _is_hex64(mat_sha)
    ):
        fail("APPROVAL_SCHEMA")

    qual = _validate_ready_qualification_block(
        doc.get("qualification"), code_prefix="APPROVAL"
    )
    if (
        qual["candidate_receipt_sha256"] != cand_sha
        or qual["expected_artifact_record_sha256"] != exp_sha
        or qual["profile_sha256"] != prof_sha
        or qual["matrix_receipt_sha256"] != mat_sha
    ):
        fail("APPROVAL_QUALIFICATION")

    files = doc.get("files")
    if not isinstance(files, list) or len(files) != len(TARGETS):
        fail("APPROVAL_FILES")

    seen_targets: list[str] = []
    stage_a_digest = doc.get("manylinux_stage_a_sha256")
    qualified_linux = stage_a_digest is not None
    if qualified_linux and not _is_hex64(stage_a_digest):
        fail("APPROVAL_MANYLINUX")
    if not qualified_linux and any(
        isinstance(row, Mapping) and isinstance(row.get("tag"), str) and "manylinux_2_36" in row["tag"]
        for row in files if isinstance(files, list)
    ):
        fail("APPROVAL_MANYLINUX")
    for expected_target, row in zip(TARGETS, files):
        if not isinstance(row, dict) or set(row.keys()) != REQUIRED_FILE_RECORD_KEYS:
            fail("APPROVAL_FILES")
        filename = row.get("filename")
        if isinstance(filename, str) and filename.endswith((".tar.gz", ".tgz")):
            fail("SDIST_FORBIDDEN")
        expected_tag = TAG_BY_TARGET[expected_target]
        expected_filename = EXPECTED_WHEEL_FILENAMES[expected_target]
        if qualified_linux and expected_target.startswith("linux"):
            expected_tag = manylinux_tag_for_target(expected_target)
            expected_filename = f"{DISTRIBUTION_WHEEL_PREFIX}-{DISTRIBUTION_VERSION}-{expected_tag}.whl"
        if (
            row.get("target") != expected_target
            or row.get("system") != SYSTEM_BY_TARGET[expected_target]
            or filename != expected_filename
            or row.get("tag") != expected_tag
            or row.get("version") != VERSION
            or type(row.get("size")) is not int
            or not (0 < row["size"] <= MAX_WHEEL_FILE_BYTES)
            or not _is_hex64(row.get("sha256"))
            or not isinstance(row.get("payload_archive_name"), str)
            or not row["payload_archive_name"].endswith((".tar.gz", ".tgz"))
            or not _is_hex64(row.get("payload_archive_sha256"))
            or not _is_hex64(row.get("manifest_sha256"))
        ):
            fail("APPROVAL_FILES")
        seen_targets.append(expected_target)

    if seen_targets != list(TARGETS):
        fail("APPROVAL_FILES")

    if not _is_hex64(doc.get("set_sha256")) or doc["set_sha256"] != compute_set_sha256(doc):
        fail("APPROVAL_DIGEST")

    if doc["publication_admitted"] is False:
        if doc.get("admission_sha256") is not None:
            fail("APPROVAL_ADMISSION_DIGEST")
    else:
        if doc.get("admission_sha256") != compute_admission_sha256(doc):
            fail("APPROVAL_ADMISSION_DIGEST")

    return dict(doc)


validate_approval_schema = validate_approval


def load_approval(
    repository: str | Path | None = None,
    *,
    path: str | Path | None = None,
) -> dict[str, Any]:
    """Load and validate the 0.7.0 3-wheel approval manifest; fail closed when absent."""
    if path is None:
        target = approval_path(repository)
    else:
        target = Path(path)
        _check_no_symlinks(target, "APPROVAL_SYMLINK")
        if target.name != APPROVAL_BASENAME:
            fail("APPROVAL_PATH")
    if not target.is_file():
        fail("APPROVAL_ABSENT")
    data = physical_bytes(target, limit=1024 * 1024)
    return validate_approval(strict_json(data))


def _cross_check_pin_and_approval(
    pin: Mapping[str, Any],
    approval: Mapping[str, Any],
    *,
    require_admitted: bool = False,
) -> tuple[dict[str, Any], dict[str, Any]]:
    v_pin = validate_pin(pin)
    v_app = validate_approval(approval)
    if _system_runtime_profile(v_pin) != _system_runtime_profile(v_app):
        fail("PIN_APPROVAL_MISMATCH")
    if v_pin["source_status"] != "READY" or v_pin["qualified_platforms"] != list(TARGETS):
        fail("PIN_NOT_READY")
    if v_pin["qualification"] != v_app["qualification"]:
        fail("PIN_APPROVAL_MISMATCH")
    if v_pin["publication_admitted"] != v_app["publication_admitted"]:
        fail("PIN_APPROVAL_MISMATCH")
    if v_pin.get("admission_sha256") != v_app.get("admission_sha256"):
        fail("PIN_APPROVAL_MISMATCH")
    if v_pin["publication_admitted"] is True:
        expected_admission_sha = compute_admission_sha256(v_app)
        if v_pin.get("admission_sha256") != expected_admission_sha:
            fail("PIN_ADMISSION_DIGEST")
    if require_admitted and (
        v_pin["publication_admitted"] is not True
        or v_app["publication_admitted"] is not True
    ):
        fail("PUBLICATION_NOT_ADMITTED")
    return v_pin, v_app


def inspect_candidate_wheel(
    wheel_path: str | Path,
    *,
    file_record: Mapping[str, Any],
    approval: Mapping[str, Any],
    manylinux_stage_a_digest: str | None = None,
) -> dict[str, Any]:
    """Verify a single 0.7.0 wheel's bytes, zip safety, RECORD, METADATA, legal files, helpers, and v3alpha1 provenance."""
    w_path = Path(wheel_path)
    _check_no_symlinks(w_path, "WHEEL_SYMLINK")
    if not w_path.is_file():
        fail("WHEEL_MISSING")

    system_webkit = _system_runtime_profile(approval)
    profile = SYSTEM_WEBKIT_PROFILE if system_webkit else GATE1_PROFILE
    if system_webkit and manylinux_stage_a_digest is not None:
        fail("WHEEL_LINUX_POLICY")
    target = str(file_record.get("target") or "")
    if target not in TARGETS:
        fail("WHEEL_TARGET")
    expected_tag = TAG_BY_TARGET[target]
    if manylinux_stage_a_digest is not None:
        if target == "linux-arm64-gnu":
            expected_tag = manylinux_tag_for_target("linux-arm64-gnu")
        elif target == "linux-x64-gnu":
            expected_tag = manylinux_tag_for_target("linux-x64-gnu")
        else:
            fail("WHEEL_TARGET")
        if not _is_hex64(manylinux_stage_a_digest):
            fail("WHEEL_PROVENANCE")
    expected_filename = f"{DISTRIBUTION_WHEEL_PREFIX}-{DISTRIBUTION_VERSION}-{expected_tag}.whl"
    if w_path.name != expected_filename or file_record.get("filename") != expected_filename:
        fail("WHEEL_FILENAME")

    expected_size = int(file_record["size"])
    if expected_size <= 0 or expected_size > MAX_WHEEL_FILE_BYTES:
        fail("WHEEL_SIZE")
    raw = physical_bytes(w_path, limit=expected_size)
    if len(raw) != expected_size:
        fail("WHEEL_SIZE")
    actual_sha = sha256(raw)
    if actual_sha != file_record["sha256"]:
        fail("WHEEL_SHA256")

    try:
        verify_wheel_record_bidirectional(w_path)
    except ContractError as exc:
        fail(f"WHEEL_{exc.code}")

    try:
        zf = zipfile.ZipFile(io.BytesIO(raw), "r")
    except zipfile.BadZipFile:
        fail("WHEEL_BAD_ZIP")

    with zf:
        infos = zf.infolist()
        if not infos or len(infos) > MAX_ZIP_MEMBERS:
            fail("WHEEL_MEMBER_COUNT")
        seen_names: set[str] = set()
        total_uncompressed = 0
        entries: dict[str, bytes] = {}
        for zi in infos:
            name = zi.filename
            if (
                not name
                or name in seen_names
                or name.startswith("/")
                or "\\" in name
                or ".." in name.split("/")
                or zi.is_dir()
            ):
                fail("WHEEL_UNSAFE_MEMBER")
            unix_ftype = stat.S_IFMT(zi.external_attr >> 16)
            if unix_ftype == stat.S_IFLNK:
                fail("WHEEL_SYMLINK_MEMBER")
            if zi.file_size < 0 or zi.file_size > MAX_PAYLOAD_UNCOMPRESSED_BYTES:
                fail("WHEEL_MEMBER_LIMIT")
            total_uncompressed += zi.file_size
            if total_uncompressed > MAX_TOTAL_UNCOMPRESSED_BYTES:
                fail("WHEEL_TOTAL_LIMIT")
            body = zf.read(name)
            if len(body) != zi.file_size:
                fail("WHEEL_MEMBER_SIZE")
            seen_names.add(name)
            entries[name] = body

    dist_info = f"{DISTRIBUTION_WHEEL_PREFIX}-{DISTRIBUTION_VERSION}.dist-info"
    payload_name = str(file_record["payload_archive_name"])
    archive_member = f"{PACKAGE_NAME}/payload/{payload_name}"
    manifest_member = f"{PACKAGE_NAME}/payload/manifest.json"
    init_member = f"{PACKAGE_NAME}/__init__.py"
    launcher_member = f"{PACKAGE_NAME}/launcher.py"
    provenance_member = f"{PACKAGE_NAME}/_rs9/provenance.json"
    metadata_member = f"{dist_info}/METADATA"
    wheel_member = f"{dist_info}/WHEEL"
    entry_points_member = f"{dist_info}/entry_points.txt"
    record_member = f"{dist_info}/RECORD"

    helpers = get_embedded_rs9_helpers()
    helper_members = {f"{PACKAGE_NAME}/_isolated/{rel}": rel for rel in helpers}
    license_files_map: Mapping[str, Any] = approval["license_files"]
    license_members = {f"{dist_info}/licenses/{name}": name for name in license_files_map}

    expected_member_names = {
        init_member,
        launcher_member,
        provenance_member,
        archive_member,
        manifest_member,
        metadata_member,
        wheel_member,
        entry_points_member,
        record_member,
        *helper_members.keys(),
        *license_members.keys(),
    }
    if set(entries.keys()) != expected_member_names:
        fail("WHEEL_MEMBER_SET")

    if entries[init_member] != _successor_init_bytes(
        application_version=VERSION,
        distribution_version=DISTRIBUTION_VERSION,
    ):
        fail("WHEEL_INIT_DRIFT")

    for member_path, rel_name in helper_members.items():
        if entries[member_path] != helpers[rel_name]:
            fail("WHEEL_HELPER_DRIFT")

    for member_path, lic_name in license_members.items():
        lic_bytes = entries[member_path]
        expected_lic = license_files_map[lic_name]
        if len(lic_bytes) != expected_lic["size"] or sha256(lic_bytes) != expected_lic["sha256"]:
            fail("WHEEL_LICENSE_DRIFT")

    metadata_bytes = entries[metadata_member]
    if b"\n\n" not in metadata_bytes:
        fail("WHEEL_METADATA")
    _, readme_body = metadata_bytes.split(b"\n\n", 1)
    if sha256(readme_body) != approval["readme"]["sha256"]:
        fail("WHEEL_README_DRIFT")
    if "size" in approval["readme"] and len(readme_body) != approval["readme"]["size"]:
        fail("WHEEL_README_DRIFT")
    expected_metadata = _successor_metadata_bytes(
        readme_body,
        distribution_version=DISTRIBUTION_VERSION,
        license_expression=EXPECTED_LICENSE_EXPRESSION,
        legal_files=tuple(license_files_map.keys()),
    )
    if metadata_bytes != expected_metadata:
        fail("WHEEL_METADATA")

    if entries[wheel_member] != _successor_wheel_info_bytes(expected_tag):
        fail("WHEEL_TAG_MISMATCH")
    if entries[entry_points_member] != _successor_entry_points_bytes():
        fail("WHEEL_ENTRYPOINT")

    payload_bytes = entries[archive_member]
    payload_sha = sha256(payload_bytes)
    if payload_sha != file_record["payload_archive_sha256"]:
        fail("WHEEL_PAYLOAD_SHA256")

    manifest_doc = strict_json(entries[manifest_member])
    if not isinstance(manifest_doc, dict):
        fail("WHEEL_MANIFEST")
    try:
        parse_manifest_members(manifest_doc)
    except ContractError:
        fail("WHEEL_MANIFEST")
    manifest_sha = manifest_doc.get("manifest_sha256")
    if (
        not _is_hex64(manifest_sha)
        or manifest_sha != file_record["manifest_sha256"]
        or digest(gate1_canonical(manifest_doc.get("members", []))) != manifest_sha
    ):
        fail("WHEEL_MANIFEST")

    prov = strict_json(entries[provenance_member])
    if not isinstance(prov, dict):
        fail("WHEEL_PROVENANCE")

    if manylinux_stage_a_digest is None:
        if any(key in prov for key in (
            "construction_stage", "release_admission", "manylinux_construction_receipt_sha256",
        )):
            fail("WHEEL_PROVENANCE")
    elif (
        prov.get("construction_stage") != "payload-portability"
        or prov.get("release_admission") != "external"
        or prov.get("manylinux_construction_receipt_sha256") != manylinux_stage_a_digest
        or prov.get("candidate_status") != "payload-qualified"
        or prov.get("promotability") != "payload-qualified"
        or prov.get("policy") != {
            "status": "payload-qualified",
            "receipt_sha256": manylinux_stage_a_digest,
            "manylinux_proven": False,
        }
    ):
        fail("WHEEL_PROVENANCE")

    expected_system = SYSTEM_BY_TARGET[target]
    expected_triple = TARGET_TRIPLE_BY_TARGET[target]
    qual = approval["qualification"]
    if (
        prov.get("schema") != PROVENANCE_SCHEMA
        or prov.get("product_id") != PROJECT
        or prov.get("distribution_name") != DISTRIBUTION_NAME
        or prov.get("application_version") != VERSION
        or prov.get("distribution_version") != DISTRIBUTION_VERSION
        or prov.get("wheel_tag") != expected_tag
        or prov.get("target_system") != expected_system
        or prov.get("target_triple") != expected_triple
        or prov.get("payload_archive_name") != payload_name
        or prov.get("payload_archive_sha256") != payload_sha
        or prov.get("manifest_sha256") != manifest_sha
        or prov.get("license_expression") != EXPECTED_LICENSE_EXPRESSION
        or prov.get("legal_files") != license_files_map
        or prov.get("readme_path") != profile.description_path
        or prov.get("readme_sha256") != approval["readme"]["sha256"]
        or prov.get("metadata_sha256") != sha256(metadata_bytes)
        or prov.get("helper_source_sha256") != {name: sha256(data) for name, data in helpers.items()}
        or prov.get("manylinux_proven") is not False
        or prov.get("builder_can_publish") is not False
        or prov.get("can_publish") is not False
        or prov.get("publication_admitted") is not False
    ):
        fail("WHEEL_PROVENANCE")

    rs9_src = prov.get("rs9_source")
    if (
        not isinstance(rs9_src, dict)
        or rs9_src.get("commit") != qual["candidate_source_commit"]
        or rs9_src.get("tree") != qual["candidate_source_tree"]
    ):
        fail("WHEEL_SOURCE_MISMATCH")

    src_id = prov.get("source_identity")
    if not isinstance(src_id, dict) or not _is_hex40(src_id.get("commit")):
        fail("WHEEL_PROVENANCE")
    if src_id["commit"] in (qual["candidate_source_commit"], qual["qualification_source_commit"]):
        fail("SOURCE_IDENTITY_CONFLATED")

    linux_policy = prov.get("linux_runtime_policy")
    expected_profile_rec = gate1_profile_record(profile)
    if (linux_policy != expected_profile_rec["linux_runtime_policy"]
            or prov.get("candidate_profile") != expected_profile_rec):
        fail("WHEEL_LINUX_POLICY")

    family = "darwin" if target == "darwin-arm64" else "linux"
    arch = "aarch64" if expected_system.startswith("aarch64") else "x86_64"
    launcher_path = prov.get("launcher_path")
    gui_path = prov.get("gui_path")
    if not isinstance(launcher_path, str) or not isinstance(gui_path, str):
        fail("WHEEL_LAUNCHER")
    expected_launcher = _render_successor_launcher(
        payload_name,
        payload_sha,
        manifest_sha,
        launcher_path,
        gui_path,
        family,
        arch,
        application_version=VERSION,
        distribution_version=DISTRIBUTION_VERSION,
        system_webkit=system_webkit and target.startswith("linux"),
    )
    if (
        entries[launcher_member] != expected_launcher
        or prov.get("launcher_sha256") != sha256(expected_launcher)
    ):
        fail("WHEEL_LAUNCHER")

    if target == "darwin-arm64":
        try:
            floor_ev = validate_darwin_payload_floor(
                payload_bytes,
                required_floor=profile.darwin_floor,
            )
        except ContractError:
            fail("WHEEL_DARWIN_FLOOR")
        if prov.get("darwin_floor_evidence") != floor_ev:
            fail("WHEEL_DARWIN_FLOOR")
    else:
        if prov.get("darwin_floor_evidence") is not None:
            fail("WHEEL_DARWIN_FLOOR")

    if system_webkit:
        try:
            _validate_system_webkit_archive(
                manifest_doc, payload_name=payload_name, system=expected_system,
                profile=profile,
            )
        except ContractError:
            fail("WHEEL_LINUX_POLICY")

    return {
        "target": target,
        "filename": expected_filename,
        "size": len(raw),
        "sha256": actual_sha,
        "provenance": prov,
    }


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
    """Public publisher seam for the external, post-wheel 0.7.0 admission."""
    return _validate_nebular070_release_admission(
        record,
        stage_a=stage_a,
        wheel_bytes_by_target=wheel_bytes_by_target,
        wheel_filenames_by_target=wheel_filenames_by_target,
        installed_consumer_bodies=installed_consumer_bodies,
        existing_three_target_approval=existing_three_target_approval,
        existing_matrix_receipt=existing_matrix_receipt,
        expected_rs9_release_source=expected_rs9_release_source,
    )


def verify_approved(
    dist: str | Path = Path("dist"),
    *,
    approval: Mapping[str, Any] | None = None,
    pin: Mapping[str, Any] | None = None,
    repository: str | Path | None = None,
    require_admitted: bool = False,
) -> dict[str, Any]:
    """Verify dist/ contains solely the 3 approved 0.7.0 wheels and inspect each wheel."""
    if approval is None and pin is None:
        v_pin = load_pin(repository)
        v_app = load_approval(repository)
        _, approved = _cross_check_pin_and_approval(
            v_pin, v_app, require_admitted=require_admitted
        )
    elif pin is not None:
        eff_app = load_approval(repository) if approval is None else approval
        _, approved = _cross_check_pin_and_approval(
            pin, eff_app, require_admitted=require_admitted
        )
    else:
        approved = validate_approval(approval)  # type: ignore[arg-type]
        if require_admitted and approved["publication_admitted"] is not True:
            fail("PUBLICATION_NOT_ADMITTED")

    d_path = Path(dist)
    _check_no_symlinks(d_path, "DIST_DIR")
    if not d_path.is_dir():
        fail("DIST_DIR")

    observed_files: list[str] = []
    for entry in sorted(d_path.iterdir(), key=lambda p: p.name):
        if entry.is_symlink() or not entry.is_file():
            fail("DIST_FILE_SET")
        if entry.name.endswith((".tar.gz", ".tgz")):
            fail("SDIST_FORBIDDEN")
        observed_files.append(entry.name)

    expected_names = sorted(rec["filename"] for rec in approved["files"])
    if observed_files != expected_names:
        fail("DIST_FILE_SET")

    for file_rec in approved["files"]:
        inspect_candidate_wheel(
            d_path / file_rec["filename"],
            file_record=file_rec,
            approval=approved,
            manylinux_stage_a_digest=(
                approved.get("manylinux_stage_a_sha256")
                if file_rec["target"].startswith("linux") and approved.get("manylinux_stage_a_sha256")
                else None
            ),
        )

    return approved


def verify_matrix_receipts(
    candidate_receipt_path: str | Path,
    expected_artifacts_path: str | Path,
    receipts_dir: str | Path,
    *,
    dist: str | Path | None = None,
    approval: Mapping[str, Any] | None = None,
    pin: Mapping[str, Any] | None = None,
    repository: str | Path | None = None,
) -> dict[str, Any]:
    """Bind the 0.7.0 approval manifest to Gate 1 candidate receipt, expected artifacts, and Gate 2 matrix admission."""
    if approval is None and pin is None:
        v_pin = load_pin(repository)
        v_app = load_approval(repository)
        _, approved = _cross_check_pin_and_approval(v_pin, v_app)
    elif pin is not None:
        eff_app = load_approval(repository) if approval is None else approval
        _, approved = _cross_check_pin_and_approval(pin, eff_app)
    else:
        approved = validate_approval(approval)  # type: ignore[arg-type]

    if dist is not None:
        verify_approved(dist, approval=approved, pin=pin, repository=repository)

    c_path = Path(candidate_receipt_path)
    e_path = Path(expected_artifacts_path)
    r_dir = Path(receipts_dir)
    _check_no_symlinks(c_path, "CANDIDATE_RECEIPT_SYMLINK")
    _check_no_symlinks(e_path, "EXPECTED_ARTIFACTS_SYMLINK")
    _check_no_symlinks(r_dir, "RECEIPTS_DIR_SYMLINK")
    if not c_path.is_file() or not e_path.is_file() or not r_dir.is_dir():
        fail("MATRIX_RECEIPTS_MISSING")

    candidate = strict_json(physical_bytes(c_path, limit=4 * 1024 * 1024))
    expected_artifacts = strict_json(physical_bytes(e_path, limit=1024 * 1024))
    if not isinstance(candidate, dict) or not isinstance(expected_artifacts, dict):
        fail("MATRIX_RECEIPTS_SCHEMA")

    cand_sha = sha256(canonical(candidate))
    if cand_sha != approved["candidate_receipt_sha256"]:
        fail("CANDIDATE_RECEIPT_DIGEST")

    if expected_artifacts.get("record_sha256") != approved["expected_artifact_record_sha256"]:
        fail("EXPECTED_ARTIFACTS_DIGEST")

    qual = approved["qualification"]
    cand_rs9 = candidate.get("candidate_rs9_source")
    if (
        not isinstance(cand_rs9, dict)
        or cand_rs9.get("commit") != qual["candidate_source_commit"]
        or cand_rs9.get("tree") != qual["candidate_source_tree"]
    ):
        fail("CANDIDATE_SOURCE_MISMATCH")

    src_identity = candidate.get("source_identity")
    if not isinstance(src_identity, dict) or not _is_hex40(src_identity.get("commit")):
        fail("CANDIDATE_SOURCE_MISMATCH")
    upstream_commit = src_identity["commit"]
    if upstream_commit in (
        qual["candidate_source_commit"],
        qual["qualification_source_commit"],
    ):
        fail("SOURCE_IDENTITY_CONFLATED")
    if "release_tag_commit" in qual and upstream_commit != qual["release_tag_commit"]:
        fail("CANDIDATE_SOURCE_MISMATCH")

    if (
        candidate.get("readme") != {
            "path": approved["readme"]["path"], "sha256": approved["readme"]["sha256"],
        }
        or candidate.get("profile") != gate1_profile_record(
            SYSTEM_WEBKIT_PROFILE if _system_runtime_profile(approved) else GATE1_PROFILE
        )
        or candidate.get("license", {}).get("expression") != EXPECTED_LICENSE_EXPRESSION
    ):
        fail("CANDIDATE_METADATA_MISMATCH")

    hosted_root = Path(admit_nebular070_matrix.__code__.co_filename).resolve().parents[2]
    check_root = repo_root(repository) if repository is not None else hosted_root
    actual_commit = _git_output(check_root, ["rev-parse", "--verify", "HEAD^{commit}"], "HOSTED_COMMIT")
    actual_tree = _git_output(check_root, ["rev-parse", "--verify", "HEAD^{tree}"], "HOSTED_COMMIT")
    if (
        actual_commit != qual["qualification_source_commit"]
        or actual_tree != qual["qualification_source_tree"]
    ):
        fail("QUALIFICATION_SOURCE_MISMATCH")

    if check_root == hosted_root:
        admit_expected_commit = qual["qualification_source_commit"]
        admit_expected_tree = qual["qualification_source_tree"]
    else:
        admit_expected_commit = _git_output(
            hosted_root, ["rev-parse", "--verify", "HEAD^{commit}"], "HOSTED_COMMIT"
        )
        admit_expected_tree = _git_output(
            hosted_root, ["rev-parse", "--verify", "HEAD^{tree}"], "HOSTED_COMMIT"
        )

    system_floors = None
    if _system_runtime_profile(approved):
        captured = load_captured_matrix_receipt(r_dir.parent / MATRIX_RECEIPT_MEMBER)
        if (sha256(canonical(captured)) != approved["matrix_receipt_sha256"]
                or captured.get("linux_runtime_profile") != SYSTEM_WEBKIT_RUNTIME_PROFILE):
            fail("MATRIX_RECEIPT_DIGEST")
        system_floors = captured.get("system_floor_receipts")
        if not isinstance(system_floors, Mapping):
            fail("MATRIX_TARGETS_MISMATCH")
    matrix = admit_nebular070_matrix(
        candidate,
        expected_artifacts,
        r_dir,
        expected_commit=admit_expected_commit,
        expected_tree=admit_expected_tree,
        profile_sha256=approved["profile_sha256"],
        candidate_receipt_sha256=approved["candidate_receipt_sha256"],
        run_id=qual["qualification_run_id"],
        run_attempt=qual["qualification_run_attempt"],
        **({"system_floor_receipts": system_floors} if system_floors is not None else {}),
    )

    matrix_sha = sha256(canonical(matrix))
    if matrix_sha != approved["matrix_receipt_sha256"]:
        fail("MATRIX_RECEIPT_DIGEST")

    if matrix.get("targets") != list(TARGETS):
        fail("MATRIX_TARGETS_MISMATCH")

    qual_sources = matrix.get("qualification_rs9_source")
    receipts_map = matrix.get("receipts")
    if (
        not isinstance(qual_sources, dict)
        or set(qual_sources.keys()) != set(TARGETS)
        or not isinstance(receipts_map, dict)
        or set(receipts_map.keys()) != set(TARGETS)
    ):
        fail("MATRIX_TARGETS_MISMATCH")

    files_by_target = {rec["target"]: rec for rec in approved["files"]}
    for target in TARGETS:
        q_src = qual_sources[target]
        if (
            not isinstance(q_src, dict)
            or q_src.get("commit") != qual["qualification_source_commit"]
            or q_src.get("tree") != qual["qualification_source_tree"]
        ):
            fail("QUALIFICATION_SOURCE_MISMATCH")
        t_entry = receipts_map[target]
        f_rec = files_by_target[target]
        expected_wheel_summary = {
            "target": target,
            "filename": f_rec["filename"],
            "size": f_rec["size"],
            "sha256": f_rec["sha256"],
            "tag": f_rec["tag"],
            "version": VERSION,
        }
        if not isinstance(t_entry, dict) or t_entry.get("consumer", {}).get("wheel") != expected_wheel_summary:
            fail("MATRIX_WHEEL_MISMATCH")
        t_qsrc = t_entry.get("qualification_rs9_source")
        expected_qsrc = qual["target_qualification_sources"][target]
        if (
            not isinstance(t_qsrc, dict)
            or t_qsrc.get("commit") != expected_qsrc["commit"]
            or t_qsrc.get("tree") != expected_qsrc["tree"]
        ):
            fail("MATRIX_SOURCE_MISMATCH")

    return matrix


class Nebular070PublicReader:
    """Bounded HTTPS reader for PyPI JSON and 3-wheel files without redirects or ambient proxies."""

    def __init__(
        self,
        *,
        timeout: int = 30,
        max_json_bytes: int = 2 * 1024 * 1024,
        max_file_bytes: int = MAX_WHEEL_FILE_BYTES,
    ) -> None:
        if timeout <= 0 or timeout > 60:
            fail("READER_TIMEOUT")
        if max_json_bytes <= 0 or max_json_bytes > 4 * 1024 * 1024:
            fail("READER_LIMIT")
        if max_file_bytes <= 0 or max_file_bytes > MAX_WHEEL_FILE_BYTES:
            fail("READER_LIMIT")
        self.timeout = timeout
        self.max_json_bytes = max_json_bytes
        self.max_file_bytes = max_file_bytes
        self._opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({}),
            NoRedirect(),
        )

    def __call__(self, url: str) -> bytes:
        _public_url(url, ("pypi.org", "files.pythonhosted.org"))
        limit = self.max_json_bytes if url.endswith("/json") else self.max_file_bytes
        req = urllib.request.Request(
            url,
            headers={
                "Accept": "application/json" if url.endswith("/json") else "application/octet-stream",
                "User-Agent": "rs9-tf-pypi-nebular070/1",
            },
        )
        try:
            with self._opener.open(req, timeout=self.timeout) as resp:
                data = resp.read(limit + 1)
        except urllib.error.HTTPError as exc:
            if exc.code == 404:
                fail("REMOTE_ABSENT")
            if 300 <= exc.code < 400:
                fail("REMOTE_REDIRECT")
            fail("REMOTE_HTTP")
        except (urllib.error.URLError, TimeoutError, socket.timeout, ssl.SSLError, OSError):
            fail("REMOTE_NETWORK")
        if len(data) > limit:
            fail("REMOTE_OVERSIZE")
        return data


def _canon_pep440_simple(version: str) -> str:
    v = version.strip().lower()
    if v.startswith("v"):
        v = v[1:]
    v = re.sub(r"[-_.]?(post|rev|r)[-_.]?(\d+)", r".post\2", v)
    v = re.sub(r"\.post0\b", ".post0", v)
    parts = v.split(".")
    head: list[str] = []
    tail: list[str] = []
    in_num = True
    for p in parts:
        if in_num and p.isdigit():
            head.append(str(int(p)))
        else:
            in_num = False
            tail.append(p)
    while len(head) > 1 and head[-1] == "0":
        head.pop()
    return ".".join(head + tail)


def project_state(get: Callable[[str], bytes] | None = None) -> str:
    """Query PyPI project JSON and return 'absent', 'version-absent', 'version-present', 'conflict', or 'unknown'."""
    reader = get or Nebular070PublicReader()
    url = f"https://pypi.org/pypi/{PROJECT}/json"
    try:
        raw = reader(url)
    except AdmissionError as exc:
        if exc.code == "TF_PYPI_REMOTE_ABSENT":
            return "absent"
        return "unknown"
    except Exception:
        return "unknown"
    try:
        doc = strict_json(raw)
    except AdmissionError:
        return "unknown"
    if not isinstance(doc, dict):
        return "unknown"
    info = doc.get("info")
    releases = doc.get("releases")
    if not isinstance(info, dict) or info.get("name") != PROJECT or not isinstance(releases, dict):
        return "unknown"

    target_canon = _canon_pep440_simple(VERSION)
    for rel_ver in releases:
        if not isinstance(rel_ver, str):
            return "unknown"
        if _canon_pep440_simple(rel_ver) == target_canon and rel_ver != VERSION:
            return "conflict"
    return "version-present" if VERSION in releases else "version-absent"


def remote_state(
    approval: Mapping[str, Any],
    get: Callable[[str], bytes] | None = None,
) -> dict[str, Any]:
    """Query PyPI metadata for the 3-wheel 0.7.0 release set without downloading wheel bodies."""
    approved = validate_approval(approval)
    reader = get or Nebular070PublicReader()
    expected_by_name = {rec["filename"]: rec for rec in approved["files"]}
    all_names = [rec["filename"] for rec in approved["files"]]

    p_state = project_state(get=reader)
    if p_state in ("unknown", "conflict"):
        return {"state": p_state, "matched": [], "missing": [], "urls": {}}
    if p_state in ("absent", "version-absent"):
        return {"state": p_state, "matched": [], "missing": list(all_names), "urls": {}}

    ver_url = f"https://pypi.org/pypi/{PROJECT}/{VERSION}/json"
    try:
        raw = reader(ver_url)
    except AdmissionError as exc:
        if exc.code == "TF_PYPI_REMOTE_ABSENT":
            return {"state": "version-absent", "matched": [], "missing": list(all_names), "urls": {}}
        return {"state": "unknown", "matched": [], "missing": [], "urls": {}}
    except Exception:
        return {"state": "unknown", "matched": [], "missing": [], "urls": {}}

    try:
        doc = strict_json(raw)
    except AdmissionError:
        return {"state": "unknown", "matched": [], "missing": [], "urls": {}}
    if not isinstance(doc, dict):
        return {"state": "unknown", "matched": [], "missing": [], "urls": {}}

    info = doc.get("info")
    urls = doc.get("urls")
    if not isinstance(info, dict) or not isinstance(urls, list):
        return {"state": "unknown", "matched": [], "missing": [], "urls": {}}
    if info.get("name") != PROJECT or info.get("version") != VERSION or info.get("yanked") is True:
        return {"state": "conflict", "matched": [], "missing": [], "urls": {}}

    if not urls:
        return {"state": "incomplete", "matched": [], "missing": list(all_names), "urls": {}}

    if len(urls) > len(expected_by_name):
        return {"state": "conflict", "matched": [], "missing": [], "urls": {}}

    matched_urls: dict[str, str] = {}
    for row in urls:
        if not isinstance(row, dict):
            return {"state": "unknown", "matched": [], "missing": [], "urls": {}}
        filename = row.get("filename")
        if not isinstance(filename, str) or filename not in expected_by_name or filename in matched_urls:
            return {"state": "conflict", "matched": [], "missing": [], "urls": {}}
        expected_rec = expected_by_name[filename]
        digests = row.get("digests")
        file_url = row.get("url")
        if (
            row.get("yanked") is not False
            or row.get("packagetype") not in (None, "bdist_wheel")
            or row.get("size") != expected_rec["size"]
            or not isinstance(digests, dict)
            or digests.get("sha256") != expected_rec["sha256"]
            or not isinstance(file_url, str)
        ):
            return {"state": "conflict", "matched": [], "missing": [], "urls": {}}
        try:
            _public_url(file_url, ("files.pythonhosted.org",))
        except AdmissionError:
            return {"state": "conflict", "matched": [], "missing": [], "urls": {}}
        if not file_url.endswith("/" + filename):
            return {"state": "conflict", "matched": [], "missing": [], "urls": {}}
        matched_urls[filename] = file_url

    matched = [name for name in all_names if name in matched_urls]
    missing = [name for name in all_names if name not in matched_urls]
    state = "published-exact" if len(matched) == len(all_names) else "incomplete"
    return {"state": state, "matched": matched, "missing": missing, "urls": matched_urls}


def exact_state(
    approval: Mapping[str, Any],
    local: Mapping[str, bytes],
    get: Callable[[str], bytes] | None = None,
) -> dict[str, Any]:
    """Compare remote PyPI metadata and downloaded bytes against the complete 3-wheel 0.7.0 set."""
    approved = validate_approval(approval)
    reader = get or Nebular070PublicReader()
    expected_by_name = {rec["filename"]: rec for rec in approved["files"]}
    all_names = [rec["filename"] for rec in approved["files"]]

    if set(local.keys()) != set(all_names):
        fail("LOCAL_SET")
    for name, rec in expected_by_name.items():
        blob = local[name]
        if len(blob) != rec["size"] or sha256(blob) != rec["sha256"]:
            fail("LOCAL_BYTES")

    meta = remote_state(approved, get=reader)
    m_state = meta["state"]
    if m_state in ("unknown", "conflict", "absent", "version-absent"):
        return {
            "state": m_state,
            "matched": meta["matched"],
            "missing": meta["missing"],
        }

    matched_urls: Mapping[str, str] = meta["urls"]
    for filename in meta["matched"]:
        file_url = matched_urls[filename]
        expected_rec = expected_by_name[filename]
        try:
            body = reader(file_url)
        except AdmissionError as exc:
            if exc.code in ("TF_PYPI_REMOTE_ABSENT", "TF_PYPI_REMOTE_REDIRECT", "TF_PYPI_REMOTE_OVERSIZE"):
                return {"state": "conflict", "matched": [], "missing": []}
            return {"state": "unknown", "matched": [], "missing": []}
        except Exception:
            return {"state": "unknown", "matched": [], "missing": []}

        if (
            len(body) != expected_rec["size"]
            or sha256(body) != expected_rec["sha256"]
            or body != local[filename]
        ):
            return {"state": "conflict", "matched": [], "missing": []}

    return {
        "state": meta["state"],
        "matched": meta["matched"],
        "missing": meta["missing"],
    }


def _fetch_paginated_github_list(
    base_url: str,
    list_key: str,
    client_json: Callable[[str], Any],
) -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = []
    total_count: int | None = None
    for page in range(1, PRIOR_RUN_MAX_PAGES + 1):
        sep = "&" if "?" in base_url else "?"
        page_url = base_url if page == 1 else f"{base_url}{sep}page={page}"
        doc = client_json(page_url)
        if not isinstance(doc, dict):
            fail("PRIOR_ATTEMPT_UNCONFIRMED")
        raw_total = doc.get("total_count")
        if type(raw_total) is not int or raw_total < 0:
            fail("PRIOR_ATTEMPT_UNCONFIRMED")
        if total_count is None:
            total_count = raw_total
        elif raw_total != total_count:
            fail("PRIOR_ATTEMPT_UNCONFIRMED")
        page_items = doc.get(list_key)
        if not isinstance(page_items, list):
            fail("PRIOR_ATTEMPT_UNCONFIRMED")
        items.extend(page_items)
        if len(items) > total_count:
            fail("PRIOR_ATTEMPT_UNCONFIRMED")
        if len(items) == total_count:
            return items
        if not page_items:
            fail("PRIOR_ATTEMPT_UNCONFIRMED")
    fail("PRIOR_ATTEMPT_UNCONFIRMED")
    raise AssertionError("unreachable")


def _normalize_workflow_run_path(raw_path: Any, *, head_sha: str) -> str:
    if not isinstance(raw_path, str) or not raw_path.strip():
        fail("PRIOR_ATTEMPT_UNCONFIRMED")
    expected_rel = f".github/workflows/{WORKFLOW}"
    if raw_path == expected_rel:
        return expected_rel
    path_part, sep, ref_part = raw_path.partition("@")
    if (
        sep == "@"
        and path_part == expected_rel
        and ref_part in ("main", "refs/heads/main", head_sha)
    ):
        return expected_rel
    fail("PRIOR_ATTEMPT_UNCONFIRMED")
    raise AssertionError("unreachable")


def _parse_prior_run_title_and_inputs(
    run: Mapping[str, Any],
) -> tuple[str, str | None, bool]:
    raw_title = run.get("display_title")
    if raw_title is None:
        raw_title = run.get("name")
    if not isinstance(raw_title, str) or not raw_title.strip():
        fail("PRIOR_ATTEMPT_UNCONFIRMED")
    if raw_title != raw_title.lstrip():
        fail("PRIOR_ATTEMPT_UNCONFIRMED")

    title_release: str
    title_mode: str | None
    is_historical_061 = False

    if raw_title == f"RS9 {PROJECT} PyPI Publish":
        title_release = "0.6.1"
        title_mode = None
        is_historical_061 = True
    else:
        head, sep, dispatch_tail = raw_title.partition(" /")
        if sep != " /":
            fail("PRIOR_ATTEMPT_UNCONFIRMED")
        if dispatch_tail not in ("", " "):
            if not dispatch_tail.startswith(" "):
                fail("PRIOR_ATTEMPT_UNCONFIRMED")
            dispatch_id_val = dispatch_tail[1:]
            if not dispatch_id_val or dispatch_id_val != dispatch_id_val.strip():
                fail("PRIOR_ATTEMPT_UNCONFIRMED")
        tokens = head.split(" ")
        if len(tokens) == 4 and tokens[0] == "RS9" and tokens[1] == PROJECT:
            release_tok, mode_tok = tokens[2], tokens[3]
            try:
                validate_workflow_dispatch(release_tok, mode_tok)
            except AdmissionError:
                fail("PRIOR_ATTEMPT_UNCONFIRMED")
            title_release = release_tok
            title_mode = mode_tok
        elif (
            len(tokens) == 3
            and tokens[0] == "RS9"
            and tokens[1] == PROJECT
            and tokens[2] in ("qualify", "publish")
        ):
            title_release = "0.6.1"
            title_mode = tokens[2]
            is_historical_061 = True
        else:
            fail("PRIOR_ATTEMPT_UNCONFIRMED")

    if "inputs" in run and run.get("inputs") is not None:
        raw_inputs = run.get("inputs")
        if not isinstance(raw_inputs, Mapping) or not raw_inputs:
            fail("PRIOR_ATTEMPT_UNCONFIRMED")
        inp_mode = raw_inputs.get("mode")
        inp_release = raw_inputs.get("release")
        if not isinstance(inp_mode, str) or not inp_mode.strip():
            fail("PRIOR_ATTEMPT_UNCONFIRMED")
        if is_historical_061 and inp_release is None:
            eff_inp_release = "0.6.1"
        elif isinstance(inp_release, str) and inp_release.strip():
            eff_inp_release = inp_release
        else:
            fail("PRIOR_ATTEMPT_UNCONFIRMED")
        try:
            validate_workflow_dispatch(eff_inp_release, inp_mode)
        except AdmissionError:
            fail("PRIOR_ATTEMPT_UNCONFIRMED")
        if eff_inp_release != title_release:
            fail("PRIOR_ATTEMPT_UNCONFIRMED")
        if title_mode is not None and inp_mode != title_mode:
            fail("PRIOR_ATTEMPT_UNCONFIRMED")
        title_mode = inp_mode

    return title_release, title_mode, is_historical_061


def _validate_prior_run_job_steps(
    job_name: str,
    job_conclusion: str,
    job: Mapping[str, Any],
) -> None:
    """Validate retained job step names against the generated workflow profile."""
    steps_present = "steps" in job
    if not steps_present:
        if (
            job_name in CURRENT_070_PROFILE_JOB_NAMES
            and job_conclusion != "skipped"
        ):
            fail("PRIOR_ATTEMPT_UNCONFIRMED")
        return

    steps = job.get("steps")
    if not isinstance(steps, list):
        fail("PRIOR_ATTEMPT_UNCONFIRMED")
    if (
        job_name in CURRENT_070_PROFILE_JOB_NAMES
        and job_conclusion != "skipped"
        and not steps
    ):
        fail("PRIOR_ATTEMPT_UNCONFIRMED")

    allowed_names = WORKFLOW_STEP_PROFILE_ALLOWED_NAMES[job_name]
    for step in steps:
        if not isinstance(step, dict):
            fail("PRIOR_ATTEMPT_UNCONFIRMED")
        sname = step.get("name")
        sstatus = step.get("status")
        sconc = step.get("conclusion")
        if (
            not isinstance(sname, str)
            or not sname.strip()
            or sstatus != "completed"
            or not isinstance(sconc, str)
            or sconc not in VALID_WORKFLOW_JOB_CONCLUSIONS
        ):
            fail("PRIOR_ATTEMPT_UNCONFIRMED")
        if job_conclusion == "skipped" and sconc != "skipped":
            fail("PRIOR_ATTEMPT_UNCONFIRMED")
        # A skipped record is explicit non-execution and is safe to retain even
        # when GitHub reports a newly injected or historical name.  Any active
        # record must be a maintained step or a post-step of a declared action;
        # this is the guard against an injected active upload/execute step.
        if sconc != "skipped" and sname not in allowed_names:
            fail("PRIOR_ATTEMPT_UNCONFIRMED")


def _validate_prior_run_jobs_map(
    jobs: list[dict[str, Any]],
    *,
    run_id: int,
    run_attempt: int,
    head_sha: str,
    seen_job_ids: set[int] | None = None,
) -> dict[str, dict[str, Any]]:
    if not jobs:
        fail("PRIOR_ATTEMPT_UNCONFIRMED")
    jobs_by_name: dict[str, dict[str, Any]] = {}
    job_ids = seen_job_ids if seen_job_ids is not None else set()
    for job in jobs:
        if not isinstance(job, dict):
            fail("PRIOR_ATTEMPT_UNCONFIRMED")
        jname = job.get("name")
        if (
            not isinstance(jname, str)
            or jname not in ALL_KNOWN_WORKFLOW_JOB_NAMES
            or jname in jobs_by_name
        ):
            fail("PRIOR_ATTEMPT_UNCONFIRMED")
        jid = job.get("id")
        if type(jid) is not int or jid <= 0 or jid in job_ids:
            fail("PRIOR_ATTEMPT_UNCONFIRMED")
        job_ids.add(jid)
        if job.get("run_id") != run_id:
            fail("PRIOR_ATTEMPT_UNCONFIRMED")
        if job.get("run_attempt") != run_attempt:
            fail("PRIOR_ATTEMPT_UNCONFIRMED")
        if job.get("head_sha") != head_sha:
            fail("PRIOR_ATTEMPT_UNCONFIRMED")
        if job.get("status") != "completed":
            fail("PRIOR_ATTEMPT_UNCONFIRMED")
        j_conc = job.get("conclusion")
        if not isinstance(j_conc, str) or j_conc not in VALID_WORKFLOW_JOB_CONCLUSIONS:
            fail("PRIOR_ATTEMPT_UNCONFIRMED")
        _validate_prior_run_job_steps(jname, j_conc, job)
        jobs_by_name[jname] = job
    return jobs_by_name


def _validate_prior_run_jobs_by_attempt(
    jobs: list[dict[str, Any]],
    *,
    run_id: int,
    run_attempt: int,
    head_sha: str,
) -> dict[int, dict[str, dict[str, Any]]]:
    if not jobs:
        fail("PRIOR_ATTEMPT_UNCONFIRMED")
    grouped: dict[int, list[dict[str, Any]]] = {}
    for job in jobs:
        if not isinstance(job, dict):
            fail("PRIOR_ATTEMPT_UNCONFIRMED")
        j_attempt = job.get("run_attempt")
        if type(j_attempt) is not int or j_attempt < 1 or j_attempt > run_attempt:
            fail("PRIOR_ATTEMPT_UNCONFIRMED")
        grouped.setdefault(j_attempt, []).append(job)
    expected_attempts = set(range(1, run_attempt + 1))
    if set(grouped.keys()) != expected_attempts:
        fail("PRIOR_ATTEMPT_UNCONFIRMED")
    seen_job_ids: set[int] = set()
    by_attempt: dict[int, dict[str, dict[str, Any]]] = {}
    for attempt_idx in range(1, run_attempt + 1):
        by_attempt[attempt_idx] = _validate_prior_run_jobs_map(
            grouped[attempt_idx],
            run_id=run_id,
            run_attempt=attempt_idx,
            head_sha=head_sha,
            seen_job_ids=seen_job_ids,
        )
    return by_attempt


def _validate_070_qualify_prior_run(
    run: Mapping[str, Any],
    jobs_by_name: Mapping[str, Mapping[str, Any]],
    *,
    check_run_conclusion: bool = True,
) -> None:
    if set(jobs_by_name.keys()) != ALL_KNOWN_WORKFLOW_JOB_NAMES:
        fail("PRIOR_ATTEMPT_UNCONFIRMED")
    non_qualify_names = ALL_KNOWN_WORKFLOW_JOB_NAMES - QUALIFY_070_JOB_NAMES
    for nq_name in non_qualify_names:
        if jobs_by_name[nq_name]["conclusion"] != "skipped":
            fail("PRIOR_ATTEMPT_UNCONFIRMED")

    build_conc = jobs_by_name[BUILD_VERIFY_070_JOB_NAME]["conclusion"]
    native_concs = [
        jobs_by_name[n_name]["conclusion"]
        for n_name in sorted(NATIVE_CONSUMER_070_JOB_NAMES)
    ]
    matrix_conc = jobs_by_name[QUALIFICATION_GATE_070_JOB_NAME]["conclusion"]
    run_conc = run["conclusion"]

    if build_conc in ACTIVE_FAILURE_CONCLUSIONS:
        if any(c != "skipped" for c in native_concs) or matrix_conc != "skipped":
            fail("PRIOR_ATTEMPT_UNCONFIRMED")
        if check_run_conclusion and run_conc not in ACTIVE_FAILURE_CONCLUSIONS:
            fail("PRIOR_ATTEMPT_UNCONFIRMED")
        return

    if build_conc != "success":
        fail("PRIOR_ATTEMPT_UNCONFIRMED")

    if any(
        c not in (frozenset({"success"}) | ACTIVE_FAILURE_CONCLUSIONS)
        for c in native_concs
    ):
        fail("PRIOR_ATTEMPT_UNCONFIRMED")

    if any(c in ACTIVE_FAILURE_CONCLUSIONS for c in native_concs):
        if matrix_conc != "skipped" or (
            check_run_conclusion and run_conc not in ACTIVE_FAILURE_CONCLUSIONS
        ):
            fail("PRIOR_ATTEMPT_UNCONFIRMED")
        return

    if matrix_conc == "success":
        if check_run_conclusion and run_conc != "success":
            fail("PRIOR_ATTEMPT_UNCONFIRMED")
        return

    if matrix_conc in ACTIVE_FAILURE_CONCLUSIONS:
        if check_run_conclusion and run_conc not in ACTIVE_FAILURE_CONCLUSIONS:
            fail("PRIOR_ATTEMPT_UNCONFIRMED")
        return

    fail("PRIOR_ATTEMPT_UNCONFIRMED")


def _validate_070_resume_prior_run(
    run: Mapping[str, Any],
    jobs_by_name: Mapping[str, Mapping[str, Any]],
) -> None:
    if run["run_attempt"] != 1:
        fail("PRIOR_ATTEMPT_UNCONFIRMED")
    if set(jobs_by_name.keys()) != ALL_KNOWN_WORKFLOW_JOB_NAMES:
        fail("PRIOR_ATTEMPT_UNCONFIRMED")
    for other_name in ALL_KNOWN_WORKFLOW_JOB_NAMES - PUBLISH_JOB_NAMES:
        if jobs_by_name[other_name]["conclusion"] != "skipped":
            fail("PRIOR_ATTEMPT_UNCONFIRMED")

    resume_job = jobs_by_name[RESUME_070_JOB_NAME]
    if resume_job["conclusion"] not in ACTIVE_FAILURE_CONCLUSIONS:
        fail("PRIOR_ATTEMPT_UNCONFIRMED")
    if run["conclusion"] not in ACTIVE_FAILURE_CONCLUSIONS:
        fail("PRIOR_ATTEMPT_UNCONFIRMED")

    steps = resume_job.get("steps")
    if not isinstance(steps, list) or not steps:
        fail("PRIOR_ATTEMPT_UNCONFIRMED")
    publish_steps = [
        step for step in steps if step.get("name") == PUBLISH_PYPI_STEP_NAME
    ]
    if not publish_steps:
        fail("PRIOR_ATTEMPT_UNCONFIRMED")
    for p_step in publish_steps:
        if (
            p_step.get("status") != "completed"
            or p_step.get("conclusion") != "skipped"
        ):
            fail("PRIOR_ATTEMPT_UNCONFIRMED")


def _validate_061_legacy_prior_run(
    run: Mapping[str, Any],
    jobs_by_name: Mapping[str, Mapping[str, Any]],
    *,
    title_mode: str | None,
    is_historical_061: bool,
    check_run_conclusion: bool = True,
) -> None:
    job_keys = set(jobs_by_name.keys())
    if job_keys == ALL_KNOWN_WORKFLOW_JOB_NAMES:
        for non_061_name in ALL_KNOWN_WORKFLOW_JOB_NAMES - LEGACY_061_JOB_NAMES:
            if jobs_by_name[non_061_name]["conclusion"] != "skipped":
                fail("PRIOR_ATTEMPT_UNCONFIRMED")
    elif is_historical_061 and job_keys == LEGACY_061_JOB_NAMES:
        pass
    else:
        fail("PRIOR_ATTEMPT_UNCONFIRMED")

    b_conc = jobs_by_name[LEGACY_061_BUILD_JOB_NAME]["conclusion"]
    c_conc = jobs_by_name[LEGACY_061_CONSUMER_JOB_NAME]["conclusion"]
    p_conc = jobs_by_name[LEGACY_061_PUBLISH_JOB_NAME]["conclusion"]
    run_conc = run["conclusion"]

    if b_conc in ACTIVE_FAILURE_CONCLUSIONS:
        if (
            c_conc != "skipped"
            or p_conc != "skipped"
            or (check_run_conclusion and run_conc not in ACTIVE_FAILURE_CONCLUSIONS)
        ):
            fail("PRIOR_ATTEMPT_UNCONFIRMED")
        return

    if b_conc != "success":
        fail("PRIOR_ATTEMPT_UNCONFIRMED")

    if c_conc in ACTIVE_FAILURE_CONCLUSIONS:
        if p_conc != "skipped" or (
            check_run_conclusion and run_conc not in ACTIVE_FAILURE_CONCLUSIONS
        ):
            fail("PRIOR_ATTEMPT_UNCONFIRMED")
        return

    if c_conc != "success":
        fail("PRIOR_ATTEMPT_UNCONFIRMED")

    if title_mode == "qualify":
        if p_conc != "skipped" or (check_run_conclusion and run_conc != "success"):
            fail("PRIOR_ATTEMPT_UNCONFIRMED")
        return

    if title_mode == "publish":
        if p_conc == "success":
            if check_run_conclusion and run_conc != "success":
                fail("PRIOR_ATTEMPT_UNCONFIRMED")
            return
        if p_conc in ACTIVE_FAILURE_CONCLUSIONS:
            if check_run_conclusion and run_conc not in ACTIVE_FAILURE_CONCLUSIONS:
                fail("PRIOR_ATTEMPT_UNCONFIRMED")
            return
        fail("PRIOR_ATTEMPT_UNCONFIRMED")

    # Static historical 0.6.1 title (title_mode is None): either qualify (p skipped) or publish (p active)
    if p_conc in ("skipped", "success"):
        if check_run_conclusion and run_conc != "success":
            fail("PRIOR_ATTEMPT_UNCONFIRMED")
        return
    if p_conc in ACTIVE_FAILURE_CONCLUSIONS:
        if check_run_conclusion and run_conc not in ACTIVE_FAILURE_CONCLUSIONS:
            fail("PRIOR_ATTEMPT_UNCONFIRMED")
        return
    fail("PRIOR_ATTEMPT_UNCONFIRMED")


def check_prior_publish_runs(
    *,
    api_get: Callable[[str], Any] | None = None,
    environ: Mapping[str, str] | None = None,
) -> None:
    """Enforce durable cross-run repeat-upload guard via GitHub Actions workflow-run history."""
    env = environ if environ is not None else os.environ
    if env.get("RS9_TFNF_PRIOR_UPLOAD_UNCONFIRMED", "").strip():
        fail("PRIOR_ATTEMPT_UNCONFIRMED")
    attempt_raw = env.get("GITHUB_RUN_ATTEMPT", "1").strip()
    if attempt_raw != "1":
        fail("PRIOR_ATTEMPT_UNCONFIRMED")

    in_actions = env.get("GITHUB_ACTIONS", "").strip().lower() == "true"
    check_requested = bool(env.get("RS9_TFNF_PRIOR_RUNS_CHECK", "").strip())
    if api_get is None and not in_actions and not check_requested:
        return

    repo_slug = env.get("GITHUB_REPOSITORY", DEFAULT_GITHUB_REPOSITORY).strip()
    if repo_slug != DEFAULT_GITHUB_REPOSITORY:
        fail("PRIOR_ATTEMPT_UNCONFIRMED")
    current_run_id_raw = env.get("GITHUB_RUN_ID", "").strip()
    if current_run_id_raw:
        if not _NUMERIC_ID_RE.fullmatch(current_run_id_raw):
            fail("PRIOR_ATTEMPT_UNCONFIRMED")
        current_run_id: int | None = int(current_run_id_raw)
    elif in_actions:
        fail("PRIOR_ATTEMPT_UNCONFIRMED")
    else:
        current_run_id = None

    def _default_api_get(url: str) -> Any:
        tok = env.get("RS9_GITHUB_READ_TOKEN", "").strip() or None
        client = PublicClient(api_token=tok)
        return client.json(url, request_class="github-api", no_redirect=True)

    client_json = api_get if api_get is not None else _default_api_get
    runs_base_url = (
        f"https://api.github.com/repos/{repo_slug}/actions/workflows/{WORKFLOW}/runs"
        f"?branch=main&event=workflow_dispatch&per_page={PRIOR_RUN_PAGE_SIZE}"
    )
    try:
        runs = _fetch_paginated_github_list(
            runs_base_url, "workflow_runs", client_json
        )
        seen_run_ids: set[int] = set()
        expected_workflow_id: int | None = None
        for run in runs:
            if not isinstance(run, dict):
                fail("PRIOR_ATTEMPT_UNCONFIRMED")
            rid = run.get("id")
            if type(rid) is not int or rid <= 0 or rid in seen_run_ids:
                fail("PRIOR_ATTEMPT_UNCONFIRMED")
            seen_run_ids.add(rid)
            if current_run_id is not None and rid == current_run_id:
                continue

            wf_id = run.get("workflow_id")
            if type(wf_id) is not int or wf_id <= 0:
                fail("PRIOR_ATTEMPT_UNCONFIRMED")
            if expected_workflow_id is None:
                expected_workflow_id = wf_id
            elif wf_id != expected_workflow_id:
                fail("PRIOR_ATTEMPT_UNCONFIRMED")

            head_sha = run.get("head_sha")
            if (
                run.get("event") != "workflow_dispatch"
                or run.get("head_branch") != "main"
                or not _is_hex40(head_sha)
            ):
                fail("PRIOR_ATTEMPT_UNCONFIRMED")
            _normalize_workflow_run_path(run.get("path"), head_sha=head_sha)

            run_attempt = run.get("run_attempt")
            if type(run_attempt) is not int or run_attempt < 1:
                fail("PRIOR_ATTEMPT_UNCONFIRMED")
            if run.get("status") != "completed":
                fail("PRIOR_ATTEMPT_UNCONFIRMED")
            run_conc = run.get("conclusion")
            if (
                not isinstance(run_conc, str)
                or run_conc not in VALID_WORKFLOW_RUN_CONCLUSIONS
            ):
                fail("PRIOR_ATTEMPT_UNCONFIRMED")

            for repo_key in ("repository", "head_repository"):
                if repo_key in run and run.get(repo_key) is not None:
                    repo_obj = run.get(repo_key)
                    if (
                        not isinstance(repo_obj, Mapping)
                        or repo_obj.get("full_name") != repo_slug
                    ):
                        fail("PRIOR_ATTEMPT_UNCONFIRMED")

            title_release, title_mode, is_historical_061 = (
                _parse_prior_run_title_and_inputs(run)
            )

            jobs_base_url = (
                f"https://api.github.com/repos/{repo_slug}/actions/runs/{rid}/jobs"
                f"?filter=all&per_page={PRIOR_RUN_PAGE_SIZE}"
            )
            jobs = _fetch_paginated_github_list(
                jobs_base_url, "jobs", client_json
            )
            attempts_map = _validate_prior_run_jobs_by_attempt(
                jobs,
                run_id=rid,
                run_attempt=run_attempt,
                head_sha=head_sha,
            )

            if title_release == "0.7.0" and title_mode == "qualify":
                for attempt_idx in range(1, run_attempt + 1):
                    _validate_070_qualify_prior_run(
                        run,
                        attempts_map[attempt_idx],
                        check_run_conclusion=(attempt_idx == run_attempt),
                    )
            elif title_release == "0.7.0" and title_mode == "resume":
                if run_attempt != 1:
                    fail("PRIOR_ATTEMPT_UNCONFIRMED")
                _validate_070_resume_prior_run(run, attempts_map[1])
            elif title_release == "0.6.1":
                for attempt_idx in range(1, run_attempt + 1):
                    _validate_061_legacy_prior_run(
                        run,
                        attempts_map[attempt_idx],
                        title_mode=title_mode,
                        is_historical_061=is_historical_061,
                        check_run_conclusion=(attempt_idx == run_attempt),
                    )
            else:
                fail("PRIOR_ATTEMPT_UNCONFIRMED")
    except AdmissionError:
        raise
    except Exception:
        fail("PRIOR_ATTEMPT_UNCONFIRMED")


def verify_upload_dir(
    dist: str | Path = Path("dist"),
    upload_dir: str | Path = Path("upload"),
    *,
    approval: Mapping[str, Any] | None = None,
    pin: Mapping[str, Any] | None = None,
    repository: str | Path | None = None,
    expected_files: Sequence[str] | None = None,
    manylinux_admission: str | Path | None = None,
    payload_portability: str | Path | None = None,
    manylinux_consumer_receipts: str | Path | None = None,
    tf_producer_source: Mapping[str, str] | None = None,
    captured_matrix: Mapping[str, Any] | None = None,
    qualification_inputs: str | Path | Mapping[str, Any] | None = None,
    inrun_root: str | Path | None = None,
) -> dict[str, Any]:
    """Re-verify both dist/ (all 3 wheels) and staged upload/ bytes against the approval immediately before upload."""
    approved = verify_approved(
        dist,
        approval=approval,
        pin=pin,
        repository=repository,
        require_admitted=True,
    )
    _validate_optional_inrun_transport(
        qualification_inputs,
        repository=repository,
        inrun_root=inrun_root,
        phase=QUALIFICATION_INPUT_PHASE_PUBLICATION,
    )
    if approved.get("manylinux_stage_a_sha256") is not None:
        if (
            manylinux_admission is None
            or payload_portability is None
            or manylinux_consumer_receipts is None
            or tf_producer_source is None
        ):
            fail("MANYLINUX_ADMISSION_REQUIRED")
        if captured_matrix is None:
            fail("MATRIX_RECEIPTS_REQUIRED")
        _validate_manylinux_admission_files(
            manylinux_admission,
            payload_portability=payload_portability,
            consumer_receipts=manylinux_consumer_receipts,
            tf_producer_source=tf_producer_source,
            approved=approved,
            dist=dist,
            captured_matrix=captured_matrix,
        )
    if _system_runtime_profile(approved):
        if any(value is not None for value in (
            manylinux_admission, payload_portability, manylinux_consumer_receipts, tf_producer_source,
        )):
            fail("SYSTEM_WEBKIT_INPUT")
        if (not isinstance(captured_matrix, Mapping)
                or captured_matrix.get("linux_runtime_profile") != SYSTEM_WEBKIT_RUNTIME_PROFILE
                or sha256(canonical(captured_matrix)) != approved["matrix_receipt_sha256"]):
            fail("MATRIX_RECEIPT_DIGEST")
    u_path = Path(upload_dir)
    _check_no_symlinks(u_path, "UPLOAD_DIR")
    if not u_path.is_dir():
        fail("UPLOAD_DIR")

    rec_by_name = {rec["filename"]: rec for rec in approved["files"]}
    entries: list[str] = []
    for entry in sorted(u_path.iterdir(), key=lambda p: p.name):
        if entry.is_symlink() or not entry.is_file():
            fail("UPLOAD_DIR")
        if entry.name.endswith((".tar.gz", ".tgz")):
            fail("SDIST_FORBIDDEN")
        if entry.name not in rec_by_name:
            fail("UPLOAD_FILE_SET")
        entries.append(entry.name)

    if not entries:
        fail("UPLOAD_FILE_SET")
    if expected_files is not None and entries != sorted(expected_files):
        fail("UPLOAD_FILE_SET")

    for filename in entries:
        inspect_candidate_wheel(
            u_path / filename,
            file_record=rec_by_name[filename],
            approval=approved,
            manylinux_stage_a_digest=(
                approved.get("manylinux_stage_a_sha256")
                if filename.endswith(("manylinux_2_36_aarch64.whl", "manylinux_2_36_x86_64.whl"))
                else None
            ),
        )
    return approved


def _read_json_object(path: str | Path, code: str, *, limit: int = 8 * 1024 * 1024) -> dict[str, Any]:
    candidate = Path(path)
    _check_no_symlinks(candidate, code)
    if not candidate.is_file():
        fail(code)
    value = strict_json(physical_bytes(candidate, limit=limit))
    if not isinstance(value, dict):
        fail(code)
    return value


def load_captured_matrix_receipt(path: str | Path) -> dict[str, Any]:
    """Load the exact resume matrix member without weakening its later equality checks."""
    candidate = Path(path)
    _check_no_symlinks(candidate, "MATRIX_RECEIPT_SYMLINK")
    if candidate.name != MATRIX_RECEIPT_MEMBER:
        fail("MATRIX_RECEIPT_PATH")
    return _read_json_object(candidate, "MATRIX_RECEIPT", limit=4 * 1024 * 1024)


def _validate_captured_consumer_member(
    target: str,
    kind: str,
    claim: Any,
    raw: Any,
    expected_body: Any,
    source: Mapping[str, Any],
) -> dict[str, Any]:
    """Validate one captured Stage-B member, including source and exact body bytes."""
    member = _manylinux_consumer_member(target, kind)
    if (
        not isinstance(claim, Mapping)
        or set(claim) != {"member", "sha256", "source"}
        or claim["member"] != member
        or not _is_hex64(claim["sha256"])
        or claim["source"] != dict(source)
        or not isinstance(raw, bytes)
        or sha256(raw) != claim["sha256"]
    ):
        fail("MANYLINUX_CAPTURE_MEMBER")
    try:
        body = strict_json(raw)
    except (AdmissionError, OSError, ValueError):
        fail("MANYLINUX_CAPTURE_MEMBER")
    if not isinstance(body, Mapping) or canonical(body) != canonical(expected_body):
        fail("MANYLINUX_CAPTURE_MEMBER")
    return dict(body)


def _validate_captured_consumer_members(
    envelope: Mapping[str, Any],
    members: Mapping[str, bytes],
) -> dict[str, dict[str, dict[str, Any]]]:
    """Bind Stage-B consumer rows to separately captured member bytes and source."""
    expected_members = set(MANYLINUX_ADMISSION_MEMBERS) - {MANYLINUX_ADMISSION_MEMBER}
    if set(members) != expected_members:
        fail("MANYLINUX_CAPTURE_MEMBER")
    captured = envelope.get("captured_consumer_receipts")
    record = envelope.get("record")
    consumers = envelope.get("consumers")
    source = record.get("rs9_release_source") if isinstance(record, Mapping) else None
    if (
        not isinstance(captured, Mapping)
        or set(captured) != {"linux-arm64-gnu", "linux-x64-gnu"}
        or not isinstance(consumers, Mapping)
        or set(consumers) != set(captured)
        or not isinstance(source, Mapping)
        or set(source) != {"commit", "tree"}
    ):
        fail("MANYLINUX_CAPTURE_MEMBER")
    result: dict[str, dict[str, dict[str, Any]]] = {}
    for target in ("linux-arm64-gnu", "linux-x64-gnu"):
        target_captured = captured.get(target)
        target_consumers = consumers.get(target)
        if (
            not isinstance(target_captured, Mapping)
            or set(target_captured) != set(MANYLINUX_CONSUMER_KINDS)
            or not isinstance(target_consumers, Mapping)
            or set(target_consumers) != set(MANYLINUX_CONSUMER_KINDS)
        ):
            fail("MANYLINUX_CAPTURE_MEMBER")
        result[target] = {}
        for kind in MANYLINUX_CONSUMER_KINDS:
            member = _manylinux_consumer_member(target, kind)
            result[target][kind] = _validate_captured_consumer_member(
                target,
                kind,
                target_captured[kind],
                members.get(member),
                target_consumers[kind],
                source,
            )
    return result


def _encoded_manylinux_consumer_member(
    target: str,
    kind: str,
    claim: Any,
    body: Any,
    source: Mapping[str, Any],
) -> tuple[str, bytes]:
    member = _manylinux_consumer_member(target, kind)
    raw = canonical(body) if isinstance(body, Mapping) else b""
    if (
        not isinstance(claim, Mapping)
        or set(claim) != {"member", "sha256", "source"}
        or claim["member"] != member
        or claim["source"] != dict(source)
        or not _is_hex64(claim["sha256"])
        or not raw
        or sha256(raw) != claim["sha256"]
    ):
        fail("MANYLINUX_CAPTURE_MEMBER")
    return member, raw


def _collect_manylinux_consumer_member_bytes(envelope: Mapping[str, Any]) -> dict[str, bytes]:
    consumers = envelope.get("consumers")
    captured = envelope.get("captured_consumer_receipts")
    record = envelope.get("record")
    source = record.get("rs9_release_source") if isinstance(record, Mapping) else None
    if not isinstance(consumers, Mapping) or not isinstance(captured, Mapping) or not isinstance(source, Mapping):
        fail("MANYLINUX_CAPTURE_MEMBER")
    member_bytes: dict[str, bytes] = {}
    for target in ("linux-arm64-gnu", "linux-x64-gnu"):
        target_consumers = consumers.get(target)
        target_captured = captured.get(target)
        if not isinstance(target_consumers, Mapping) or not isinstance(target_captured, Mapping):
            fail("MANYLINUX_CAPTURE_MEMBER")
        for kind in MANYLINUX_CONSUMER_KINDS:
            member, raw = _encoded_manylinux_consumer_member(
                target,
                kind,
                target_captured.get(kind),
                target_consumers.get(kind),
                source,
            )
            member_bytes[member] = raw
    return member_bytes


def _prepare_manylinux_consumer_output_dir(output_dir: str | Path) -> Path:
    out = Path(output_dir)
    _check_no_symlinks(out, "MANYLINUX_CAPTURE_MEMBER")
    if out.exists():
        if not out.is_dir():
            fail("MANYLINUX_CAPTURE_MEMBER")
        for entry in out.iterdir():
            if entry.name != MANYLINUX_ADMISSION_MEMBER or entry.is_symlink() or not entry.is_file():
                fail("MANYLINUX_CAPTURE_MEMBER")
    out.mkdir(parents=True, exist_ok=True)
    return out


def materialize_manylinux_consumer_receipts(
    admission_path: str | Path,
    output_dir: str | Path,
) -> Path:
    """Materialize the closed Stage-B consumer members before capture/upload."""
    envelope = _read_json_object(admission_path, "MANYLINUX_ADMISSION", limit=16 * 1024 * 1024)
    if envelope.get("schema") != "rs9.nebular070-manylinux-admission-input.v1":
        fail("MANYLINUX_ADMISSION")
    member_bytes = _collect_manylinux_consumer_member_bytes(envelope)
    out = _prepare_manylinux_consumer_output_dir(output_dir)
    for member, raw in member_bytes.items():
        dest = out / member
        dest.parent.mkdir(parents=True, exist_ok=True)
        with dest.open("xb") as stream:
            stream.write(raw)
    return out


def _load_manylinux_admission_envelope(path: str | Path) -> dict[str, Any]:
    """Load the closed Stage-B envelope before any dependent member is read."""
    envelope = _read_json_object(path, "MANYLINUX_ADMISSION", limit=16 * 1024 * 1024)
    required = {
        "schema", "record", "consumers", "approval", "matrix", "captured_consumer_receipts"
    }
    if set(envelope) != required or envelope.get("schema") != "rs9.nebular070-manylinux-admission-input.v1":
        fail("MANYLINUX_ADMISSION")
    return envelope


def _load_manylinux_stage_a(
    path: str | Path,
    *,
    tf_producer_source: Mapping[str, str],
    approved: Mapping[str, Any],
) -> ValidatedPayloadPortability:
    """Load Stage A with the already-approved producer/tool source joins."""
    stage_a = load_payload_portability_bundle(
        path,
        expected_tf_producer_source=tf_producer_source,
        expected_rs9_tool_source={
            "commit": approved["qualification"]["candidate_source_commit"],
            "tree": approved["qualification"]["candidate_source_tree"],
        },
    )
    if stage_a.digest != approved.get("manylinux_stage_a_sha256"):
        fail("MANYLINUX_ADMISSION")
    return stage_a


def _load_candidate_stage_a(
    bundle: Path,
    descriptor: Mapping[str, Any] | None,
    *,
    expected_commit: str,
    expected_tree: str,
) -> ValidatedPayloadPortability | None:
    """Load the bundle Stage-A member only with the same anchored descriptor joins."""
    stage_a_path = bundle / MANYLINUX_STAGE_A_MEMBER
    manylinux_spec = descriptor.get("manylinux") if isinstance(descriptor, Mapping) else None
    if manylinux_spec is None:
        if stage_a_path.exists() or stage_a_path.is_symlink():
            fail("BUNDLE_MANYLINUX_INPUT")
        return None
    if not isinstance(manylinux_spec, Mapping):
        fail("BUNDLE_MANYLINUX_INPUT")
    _check_no_symlinks(stage_a_path, "BUNDLE_MANYLINUX_INPUT")
    if not stage_a_path.is_file():
        fail("BUNDLE_MANYLINUX_INPUT")
    captured = manylinux_spec.get("stage_a")
    if not isinstance(captured, Mapping):
        fail("BUNDLE_MANYLINUX_INPUT")
    stage_a_bytes = physical_bytes(stage_a_path, limit=MAX_INPUT_BYTES)
    if (len(stage_a_bytes) != captured.get("size")
            or sha256(stage_a_bytes) != captured.get("sha256")):
        fail("BUNDLE_MANYLINUX_INPUT")
    # Validate the exact authenticated read, without reopening the mutable path.
    envelope = strict_json(stage_a_bytes)
    expected_input_schemas = {PORTABILITY_INPUT_SCHEMA, ARCHIVE_PORTABILITY_INPUT_SCHEMA}
    expected_record_schemas = {PORTABILITY_SCHEMA, ARCHIVE_PORTABILITY_SCHEMA}
    envelope_schema = envelope.get("schema") if isinstance(envelope, Mapping) else None
    record = envelope.get("record") if isinstance(envelope, Mapping) else None
    record_schema = record.get("schema") if isinstance(record, Mapping) else None
    if (not isinstance(envelope, Mapping)
            or set(envelope) != {"schema", "record", "bodies"}
            or not isinstance(envelope_schema, str)
            or envelope_schema not in expected_input_schemas
            or not isinstance(record, Mapping)
            or not isinstance(record_schema, str)
            or record_schema not in expected_record_schemas
            or envelope_schema != (
                ARCHIVE_PORTABILITY_INPUT_SCHEMA
                if record_schema == ARCHIVE_PORTABILITY_SCHEMA
                else PORTABILITY_INPUT_SCHEMA
            )
            or not isinstance(envelope["bodies"], Mapping)):
        fail("BUNDLE_MANYLINUX_INPUT")
    return validate_nebular070_payload_portability(
        envelope["record"],
        envelope["bodies"],
        expected_tf_producer_source=manylinux_spec["tf_producer_source"],
        expected_rs9_tool_source={"commit": expected_commit, "tree": expected_tree},
    )


def _validate_manylinux_matrix_binding(
    envelope: Mapping[str, Any],
    *,
    approved: Mapping[str, Any],
    captured_matrix: Mapping[str, Any] | None,
) -> Mapping[str, Any]:
    """Bind the envelope matrix to the captured resume member when supplied."""
    if envelope.get("approval") != approved:
        fail("MANYLINUX_ADMISSION")
    matrix = envelope.get("matrix")
    receipts = matrix.get("receipts") if isinstance(matrix, Mapping) else None
    expected_targets = {"darwin-arm64", "linux-arm64-gnu", "linux-x64-gnu"}
    if not isinstance(receipts, Mapping) or set(receipts) != expected_targets:
        fail("MANYLINUX_CAPTURE_MATRIX_SHAPE")
    if captured_matrix is not None:
        if canonical(matrix) != canonical(captured_matrix):
            fail("MANYLINUX_CAPTURE_MATRIX")
        captured_receipts = captured_matrix.get("receipts")
        if not isinstance(captured_receipts, Mapping) or set(captured_receipts) != expected_targets:
            fail("MANYLINUX_CAPTURE_MATRIX_SHAPE")
        if canonical(captured_receipts) != canonical(receipts):
            fail("MANYLINUX_CAPTURE_MATRIX")
    return matrix


def _read_manylinux_consumer_members(
    root: str | Path,
    *,
    envelope: Mapping[str, Any],
) -> dict[str, dict[str, Any]]:
    """Read exactly the four captured Linux consumer members and validate their bytes."""
    receipt_root = Path(root)
    _check_no_symlinks(receipt_root, "MANYLINUX_CAPTURE_MEMBER")
    if not receipt_root.is_dir():
        fail("MANYLINUX_CAPTURE_MEMBER")
    member_bytes: dict[str, bytes] = {}
    expected_members = set(MANYLINUX_ADMISSION_MEMBERS) - {MANYLINUX_ADMISSION_MEMBER}
    actual_members: set[str] = set()
    for dirpath, dirnames, filenames in os.walk(receipt_root, followlinks=False):
        dp = Path(dirpath)
        if any((dp / dname).is_symlink() for dname in dirnames):
            fail("MANYLINUX_CAPTURE_MEMBER")
        for fname in filenames:
            path = dp / fname
            if path.is_symlink() or not path.is_file():
                fail("MANYLINUX_CAPTURE_MEMBER")
            rel = path.relative_to(receipt_root).as_posix()
            if rel not in expected_members:
                fail("MANYLINUX_CAPTURE_MEMBER")
            actual_members.add(rel)
            member_bytes[rel] = physical_bytes(path, limit=2 * 1024 * 1024)
    if actual_members != expected_members:
        fail("MANYLINUX_CAPTURE_MEMBER")
    return _validate_captured_consumer_members(envelope, member_bytes)


def _read_manylinux_wheels(
    dist: str | Path,
    *,
    approved: Mapping[str, Any],
) -> tuple[dict[str, bytes], dict[str, str]]:
    """Read the two Linux wheel bytes named by the approved three-target set."""
    dist_path = Path(dist)
    wheels: dict[str, bytes] = {}
    names: dict[str, str] = {}
    for target in ("linux-arm64-gnu", "linux-x64-gnu"):
        row = next((item for item in approved["files"] if item["target"] == target), None)
        if not isinstance(row, Mapping):
            fail("MANYLINUX_ADMISSION")
        wheel_path = dist_path / row["filename"]
        wheels[target] = physical_bytes(wheel_path, limit=MAX_WHEEL_FILE_BYTES)
        names[target] = wheel_path.name
    return wheels, names


def _validate_manylinux_admission_files(
    admission_path: str | Path,
    *,
    payload_portability: str | Path,
    consumer_receipts: str | Path,
    tf_producer_source: Mapping[str, str],
    approved: Mapping[str, Any],
    dist: str | Path,
    captured_matrix: Mapping[str, Any] | None = None,
) -> ValidatedReleaseAdmission:
    """Validate the external Stage-B record against the actual wheel directory."""
    envelope = _load_manylinux_admission_envelope(admission_path)
    stage_a = _load_manylinux_stage_a(
        payload_portability, tf_producer_source=tf_producer_source, approved=approved
    )
    matrix = _validate_manylinux_matrix_binding(
        envelope, approved=approved, captured_matrix=captured_matrix
    )
    captured_consumers = _read_manylinux_consumer_members(
        consumer_receipts, envelope=envelope
    )
    wheels, names = _read_manylinux_wheels(dist, approved=approved)
    result = _validate_nebular070_release_admission(
        envelope["record"],
        stage_a=stage_a,
        wheel_bytes_by_target=wheels,
        wheel_filenames_by_target=names,
        installed_consumer_bodies=captured_consumers,
        existing_three_target_approval=approved,
        existing_matrix_receipt=matrix,
        expected_rs9_release_source={
            "commit": approved["qualification"]["candidate_source_commit"],
            "tree": approved["qualification"]["candidate_source_tree"],
        },
    )
    if result.digest != envelope["record"].get("identity"):
        fail("MANYLINUX_ADMISSION")
    return result


def select_missing(
    dist: str | Path = Path("dist"),
    upload_dir: str | Path = Path("upload"),
    *,
    approval: Mapping[str, Any] | None = None,
    pin: Mapping[str, Any] | None = None,
    candidate_receipt: str | Path | None = None,
    expected_artifacts: str | Path | None = None,
    receipts_dir: str | Path | None = None,
    repository: str | Path | None = None,
    get: Callable[[str], bytes] | None = None,
    attempt_marker: str | Path | None = None,
    api_get: Callable[[str], Any] | None = None,
    environ: Mapping[str, str] | None = None,
    manylinux_admission: str | Path | None = None,
    payload_portability: str | Path | None = None,
    manylinux_consumer_receipts: str | Path | None = None,
    tf_producer_source: Mapping[str, str] | None = None,
    qualification_inputs: str | Path | Mapping[str, Any] | None = None,
    inrun_root: str | Path | None = None,
) -> dict[str, Any]:
    """Verify admitted pin, 3-wheel approval, and Gate 2 matrix receipts, then stage only missing 0.7.0 wheels."""
    env = environ if environ is not None else os.environ
    if env.get("RS9_TFNF_PRIOR_UPLOAD_UNCONFIRMED", "").strip():
        fail("PRIOR_ATTEMPT_UNCONFIRMED")
    if attempt_marker is not None:
        m_path = Path(attempt_marker)
        if m_path.is_symlink() or m_path.exists():
            fail("PRIOR_ATTEMPT_UNCONFIRMED")

    if approval is None and pin is None:
        v_pin = load_pin(repository)
        v_app = load_approval(repository)
        validated_pin, approved = _cross_check_pin_and_approval(
            v_pin, v_app, require_admitted=True
        )
    elif pin is not None:
        eff_app = load_approval(repository) if approval is None else approval
        validated_pin, approved = _cross_check_pin_and_approval(
            pin, eff_app, require_admitted=True
        )
    else:
        validated_pin = None
        approved = validate_approval(approval)  # type: ignore[arg-type]
        if approved["publication_admitted"] is not True:
            fail("PUBLICATION_NOT_ADMITTED")

    verify_approved(
        dist,
        approval=approved,
        pin=validated_pin,
        repository=repository,
        require_admitted=True,
    )
    _validate_optional_inrun_transport(
        qualification_inputs,
        repository=repository,
        inrun_root=inrun_root,
        phase=QUALIFICATION_INPUT_PHASE_PUBLICATION,
    )

    if (
        candidate_receipt is None
        or expected_artifacts is None
        or receipts_dir is None
    ):
        fail("MATRIX_RECEIPTS_REQUIRED")
    captured_matrix = verify_matrix_receipts(
        candidate_receipt,
        expected_artifacts,
        receipts_dir,
        dist=dist,
        approval=approved,
        pin=validated_pin,
        repository=repository,
    )

    if approved.get("manylinux_stage_a_sha256") is not None:
        if (
            manylinux_admission is None
            or payload_portability is None
            or manylinux_consumer_receipts is None
            or tf_producer_source is None
        ):
            fail("MANYLINUX_ADMISSION_REQUIRED")
        _validate_manylinux_admission_files(
            manylinux_admission,
            payload_portability=payload_portability,
            consumer_receipts=manylinux_consumer_receipts,
            tf_producer_source=tf_producer_source,
            approved=approved,
            dist=dist,
            captured_matrix=captured_matrix,
        )

    d_path = Path(dist)
    u_path = Path(upload_dir)
    _check_no_symlinks(u_path, "UPLOAD_DIR")
    if u_path.exists():
        if not u_path.is_dir() or any(u_path.iterdir()):
            fail("UPLOAD_DIR")

    local = {
        rec["filename"]: physical_bytes(d_path / rec["filename"], limit=rec["size"])
        for rec in approved["files"]
    }
    state_info = exact_state(approved, local, get=get)
    state = state_info.get("state")
    missing = list(state_info.get("missing", []))

    if state in ("unknown", "conflict"):
        fail(f"REMOTE_{state.upper()}")
    if state not in ("published-exact", "incomplete", "absent", "version-absent"):
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
        verify_upload_dir(
            d_path,
            u_path,
            approval=approved,
            pin=validated_pin,
            repository=repository,
            expected_files=missing,
            manylinux_admission=manylinux_admission,
            payload_portability=payload_portability,
            manylinux_consumer_receipts=manylinux_consumer_receipts,
            tf_producer_source=tf_producer_source,
            captured_matrix=captured_matrix,
            qualification_inputs=qualification_inputs,
            inrun_root=inrun_root,
        )

    if missing and attempt_marker is not None:
        m_path = Path(attempt_marker)
        _check_no_symlinks(m_path.parent, "UPLOAD_DIR")
        m_path.parent.mkdir(parents=True, exist_ok=True)
        with m_path.open("xb") as stream:
            stream.write(
                canonical(
                    {
                        "project": PROJECT,
                        "version": VERSION,
                        "set_sha256": approved["set_sha256"],
                        "matrix_receipt_sha256": approved["matrix_receipt_sha256"],
                        "staged_files": missing,
                    }
                )
            )

    return {"upload": bool(missing), "state": state, "missing": missing}


def readback(
    dist: str | Path = Path("dist"),
    *,
    approval: Mapping[str, Any] | None = None,
    pin: Mapping[str, Any] | None = None,
    repository: str | Path | None = None,
    get: Callable[[str], bytes] | None = None,
    schedule: Sequence[int | float] = READBACK_SCHEDULE_SECONDS,
    sleep_fn: Callable[[float], None] = time.sleep,
) -> dict[str, Any]:
    """Perform bounded finite readback of all 3 wheels after upload without any upload capability."""
    if not schedule or len(schedule) > 6 or sum(schedule) > 600:
        fail("READBACK_SCHEDULE")
    approved = verify_approved(
        dist,
        approval=approval,
        pin=pin,
        repository=repository,
    )
    d_path = Path(dist)
    local = {
        rec["filename"]: physical_bytes(d_path / rec["filename"], limit=rec["size"])
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


def capture_path(repository: str | Path | None = None) -> Path:
    """Return path to the 0.7.0 qualification capture manifest."""
    path = repo_root(repository) / CAPTURE_PATH
    _check_no_symlinks(path, "CAPTURE_SYMLINK")
    return path


def validate_qualification_capture(
    doc: Mapping[str, Any],
    *,
    pin: Mapping[str, Any] | None = None,
    approval: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Validate the 0.7.0 qualification capture manifest and cross-bind against pin/approval."""
    if not isinstance(doc, dict) or set(doc.keys()) != REQUIRED_CAPTURE_KEYS:
        fail("QUALIFICATION_CAPTURE_SCHEMA")

    run_id = doc.get("run_id")
    run_id_str = str(run_id) if type(run_id) is int and run_id > 0 else (run_id if isinstance(run_id, str) else "")
    run_attempt = doc.get("run_attempt")
    run_attempt_str = "1" if run_attempt in (1, "1") else ""

    if (
        doc.get("schema") != CAPTURE_SCHEMA
        or doc.get("project") != PROJECT
        or doc.get("version") != VERSION
        or doc.get("distribution_version") != DISTRIBUTION_VERSION
        or doc.get("workflow") != WORKFLOW
        or doc.get("repository") != DEFAULT_GITHUB_REPOSITORY
        or not _NUMERIC_ID_RE.fullmatch(run_id_str)
        or run_attempt_str != "1"
        or doc.get("head_branch") != "main"
        or doc.get("event") != "workflow_dispatch"
        or doc.get("status") != "completed"
        or doc.get("conclusion") != "success"
        or not _is_hex40(doc.get("candidate_source_commit"))
        or not _is_hex40(doc.get("candidate_source_tree"))
        or not _is_hex40(doc.get("qualification_source_commit"))
        or not _is_hex40(doc.get("qualification_source_tree"))
        or not _is_hex64(doc.get("candidate_receipt_sha256"))
        or not _is_hex64(doc.get("expected_artifact_record_sha256"))
        or not _is_hex64(doc.get("profile_sha256"))
        or not _is_hex64(doc.get("matrix_receipt_sha256"))
    ):
        fail("QUALIFICATION_CAPTURE_SCHEMA")

    artifacts = doc.get("artifacts")
    capture_artifacts = _capture_artifact_names(approval, artifacts)
    if not isinstance(artifacts, dict) or set(artifacts.keys()) != set(capture_artifacts):
        fail("QUALIFICATION_CAPTURE_ARTIFACTS")

    seen_ids: set[int] = set()
    for art_name in capture_artifacts:
        art = artifacts.get(art_name)
        if (
            not isinstance(art, dict)
            or set(art.keys()) != {"id", "size_in_bytes", "archive_download_url", "archive_sha256", "files"}
            or type(art.get("id")) is not int
            or art["id"] <= 0
            or art["id"] in seen_ids
            or type(art.get("size_in_bytes")) is not int
            or not (0 < art["size_in_bytes"] <= 3 * MAX_WHEEL_FILE_BYTES)
            or not _is_hex64(art.get("archive_sha256"))
            or not isinstance(art.get("archive_download_url"), str)
            or art["archive_download_url"]
            != f"https://api.github.com/repos/{DEFAULT_GITHUB_REPOSITORY}/actions/artifacts/{art['id']}/zip"
            or not isinstance(art.get("files"), dict)
            or not art["files"]
        ):
            fail("QUALIFICATION_CAPTURE_ARTIFACTS")
        seen_ids.add(art["id"])
        for member_name, member_meta in art["files"].items():
            if (
                not isinstance(member_name, str)
                or not member_name
                or member_name.startswith("/")
                or "\\" in member_name
                or ".." in member_name.split("/")
                or not isinstance(member_meta, dict)
                or set(member_meta.keys()) != {"size", "sha256"}
                or type(member_meta.get("size")) is not int
                or member_meta["size"] <= 0
                or not _is_hex64(member_meta.get("sha256"))
            ):
                fail("QUALIFICATION_CAPTURE_ARTIFACTS")

    bundle_files = artifacts[CANDIDATE_BUNDLE_ARTIFACT]["files"]
    expected_bundle_members = {
        *(f"dist/{EXPECTED_WHEEL_FILENAMES[t]}" for t in TARGETS),
        "candidate_receipt.json",
        "expected_artifacts.json",
    }
    stage_a_claimed = (
        isinstance(approval, Mapping)
        and approval.get("manylinux_stage_a_sha256") is not None
    )
    if stage_a_claimed or (
        approval is None and MANYLINUX_STAGE_A_MEMBER in bundle_files
    ):
        expected_bundle_members.add(MANYLINUX_STAGE_A_MEMBER)
    if set(bundle_files.keys()) != expected_bundle_members:
        fail("QUALIFICATION_CAPTURE_ARTIFACTS")

    if MANYLINUX_ADMISSION_ARTIFACT in artifacts:
        admission_files = artifacts[MANYLINUX_ADMISSION_ARTIFACT]["files"]
        if set(admission_files.keys()) != MANYLINUX_ADMISSION_MEMBERS:
            fail("QUALIFICATION_CAPTURE_ARTIFACTS")

    for target, art_name in TARGET_QUALIFICATION_ARTIFACTS.items():
        if set(artifacts[art_name]["files"].keys()) != {f"{target}/result.json"}:
            fail("QUALIFICATION_CAPTURE_ARTIFACTS")

    if set(artifacts[MATRIX_RECEIPT_ARTIFACT]["files"].keys()) != {MATRIX_RECEIPT_MEMBER}:
        fail("QUALIFICATION_CAPTURE_ARTIFACTS")

    for ref in (pin, approval):
        if ref is None:
            continue
        qual = ref.get("qualification")
        if (
            not isinstance(qual, dict)
            or qual.get("candidate_source_commit") != doc["candidate_source_commit"]
            or qual.get("candidate_source_tree") != doc["candidate_source_tree"]
            or qual.get("qualification_source_commit") != doc["qualification_source_commit"]
            or qual.get("qualification_source_tree") != doc["qualification_source_tree"]
            or qual.get("qualification_run_id") != run_id_str
            or qual.get("qualification_run_attempt") != "1"
            or qual.get("candidate_receipt_sha256") != doc["candidate_receipt_sha256"]
            or qual.get("expected_artifact_record_sha256") != doc["expected_artifact_record_sha256"]
            or qual.get("profile_sha256") != doc["profile_sha256"]
            or qual.get("matrix_receipt_sha256") != doc["matrix_receipt_sha256"]
        ):
            fail("QUALIFICATION_CAPTURE_MISMATCH")

    if approval is not None:
        v_app = validate_approval(approval)
        for f_rec in v_app["files"]:
            b_entry = bundle_files.get(f"dist/{f_rec['filename']}")
            if (
                not isinstance(b_entry, dict)
                or b_entry["size"] != f_rec["size"]
                or b_entry["sha256"] != f_rec["sha256"]
            ):
                fail("QUALIFICATION_CAPTURE_MISMATCH")

    return dict(doc)


def load_qualification_capture(
    repository: str | Path | None = None,
    *,
    path: str | Path | None = None,
    pin: Mapping[str, Any] | None = None,
    approval: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Load and validate the 0.7.0 qualification capture manifest; fail closed when absent."""
    if path is None:
        target = capture_path(repository)
    else:
        target = Path(path)
        _check_no_symlinks(target, "CAPTURE_SYMLINK")
        if target.name != CAPTURE_BASENAME:
            fail("CAPTURE_PATH")
    if not target.is_file():
        fail("QUALIFICATION_CAPTURE_ABSENT")
    data = physical_bytes(target, limit=1024 * 1024)
    return validate_qualification_capture(
        strict_json(data), pin=pin, approval=approval
    )


def _git_output(repo: Path, args: Sequence[str], code: str = "SOURCE_LINEAGE") -> str:
    try:
        completed = subprocess.run(
            ["git", "-C", str(repo), *args],
            check=False,
             stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=30,
        )
    except (OSError, subprocess.SubprocessError):
        fail(code)
    if completed.returncode != 0:
        if code == "HOSTED_COMMIT":
            stderr = completed.stderr if isinstance(completed.stderr, str) else ""
            if "detected dubious ownership" in stderr:
                fail("HOSTED_COMMIT_OWNERSHIP")
            if "not a git repository" in stderr:
                fail("HOSTED_COMMIT_REPOSITORY")
        fail(code)
    return completed.stdout.strip()


def _require_real_directory(path: str | Path, code: str) -> Path:
    if not isinstance(path, (str, os.PathLike)):
        fail(code)
    candidate = Path(path)
    _check_no_symlinks(candidate, code)
    if not candidate.is_dir():
        fail(code)
    return candidate.resolve()


def verify_source_lineage(
    publisher_dir: str | Path,
    qualification_dir: str | Path,
    *,
    publisher_revision: str | None = None,
    pin: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Verify two-checkout lineage between publisher authority checkout and pinned qualification checkout."""
    pub = _require_real_directory(publisher_dir, "SOURCE_LINEAGE")
    qual = _require_real_directory(qualification_dir, "SOURCE_LINEAGE")
    if pub == qual:
        fail("SOURCE_LINEAGE")

    eff_pin = load_pin(pub) if pin is None else validate_pin(pin)
    eff_app = load_approval(pub)
    eff_cap = load_qualification_capture(pub, pin=eff_pin, approval=eff_app)
    _cross_check_pin_and_approval(eff_pin, eff_app, require_admitted=True)

    qual_commit = eff_pin["qualification"]["qualification_source_commit"]
    qual_tree = eff_pin["qualification"]["qualification_source_tree"]

    pub_head = _git_output(pub, ["rev-parse", "--verify", "HEAD^{commit}"], "SOURCE_LINEAGE")
    pub_tree = _git_output(pub, ["rev-parse", "--verify", "HEAD^{tree}"], "SOURCE_LINEAGE")
    if not _is_hex40(pub_head) or not _is_hex40(pub_tree):
        fail("SOURCE_LINEAGE")
    if publisher_revision is not None:
        if not _is_hex40(publisher_revision) or pub_head != publisher_revision:
            fail("SOURCE_LINEAGE")
    if _git_output(pub, ["status", "--porcelain", "--untracked-files=all"], "SOURCE_LINEAGE") != "":
        fail("SOURCE_LINEAGE")

    _git_output(
        pub,
        ["merge-base", "--is-ancestor", qual_commit, pub_head],
        "SOURCE_LINEAGE",
    )
    if _git_output(pub, ["rev-parse", "--verify", f"{qual_commit}^{{tree}}"], "SOURCE_LINEAGE") != qual_tree:
        fail("SOURCE_LINEAGE")

    diff_out = _git_output(
        pub,
        ["diff", "--name-only", qual_commit, pub_head, "--"],
        "SOURCE_LINEAGE",
    )
    allowed_diff_paths = {f"operators/tf-pypi/{name}" for name in REQUIRED_RESUME_FILES}
    changed_paths = {line.strip() for line in diff_out.splitlines() if line.strip()}
    if not changed_paths.issubset(allowed_diff_paths):
        fail("FORBIDDEN_TREE_DIFF")

    qual_head = _git_output(qual, ["rev-parse", "--verify", "HEAD^{commit}"], "SOURCE_LINEAGE")
    qual_actual_tree = _git_output(qual, ["rev-parse", "--verify", "HEAD^{tree}"], "SOURCE_LINEAGE")
    if qual_head != qual_commit or qual_actual_tree != qual_tree:
        fail("SOURCE_LINEAGE")
    if _git_output(qual, ["status", "--porcelain", "--untracked-files=all"], "SOURCE_LINEAGE") != "":
        fail("SOURCE_LINEAGE")

    for helper in QUALIFICATION_SOURCE_HELPERS:
        helper_path = qual / helper
        _check_no_symlinks(helper_path, "SOURCE_LINEAGE")
        if not helper_path.is_file():
            fail("SOURCE_LINEAGE")
        blob = _git_output(qual, ["rev-parse", "--verify", f"HEAD:{helper}"], "SOURCE_LINEAGE")
        pub_blob = _git_output(
            pub, ["rev-parse", "--verify", f"{qual_commit}:{helper}"], "SOURCE_LINEAGE"
        )
        worktree_blob = _git_output(qual, ["hash-object", "--", helper], "SOURCE_LINEAGE")
        if not _is_hex40(blob) or blob != pub_blob or worktree_blob != blob:
            fail("SOURCE_LINEAGE")

    return {
        "publisher_commit": pub_head,
        "publisher_tree": pub_tree,
        "qualification_commit": qual_head,
        "qualification_tree": qual_actual_tree,
        "qualification_run_id": eff_cap["run_id"],
    }


def validate_api_metadata(
    api_dir: str | Path,
    *,
    capture: Mapping[str, Any] | None = None,
    repository: str | Path | None = None,
) -> dict[str, Any]:
    """Validate retained GitHub Actions run.json and artifacts.json against qualification capture."""
    a_dir = _require_real_directory(api_dir, "QUALIFICATION_API")
    eff_cap = (
        load_qualification_capture(repository)
        if capture is None
        else validate_qualification_capture(capture)
    )
    run_path = a_dir / "run.json"
    artifacts_path = a_dir / "artifacts.json"
    _check_no_symlinks(run_path, "QUALIFICATION_API")
    _check_no_symlinks(artifacts_path, "QUALIFICATION_API")
    if not run_path.is_file() or not artifacts_path.is_file():
        fail("QUALIFICATION_API")

    run_doc = strict_json(physical_bytes(run_path, limit=1024 * 1024))
    artifacts_doc = strict_json(physical_bytes(artifacts_path, limit=1024 * 1024))
    if not isinstance(run_doc, dict) or not isinstance(artifacts_doc, dict):
        fail("QUALIFICATION_API")

    expected_run_id = int(eff_cap["run_id"])
    repo_info = run_doc.get("repository")
    if (
        run_doc.get("id") != expected_run_id
        or run_doc.get("run_attempt") != 1
        or run_doc.get("head_sha") != eff_cap["qualification_source_commit"]
        or run_doc.get("head_branch") != "main"
        or run_doc.get("event") != "workflow_dispatch"
        or run_doc.get("status") != "completed"
        or run_doc.get("conclusion") != "success"
        or run_doc.get("path") != f".github/workflows/{WORKFLOW}"
        or not isinstance(repo_info, dict)
        or repo_info.get("full_name") != eff_cap["repository"]
    ):
        fail("QUALIFICATION_RUN")

    rows = artifacts_doc.get("artifacts")
    if not isinstance(rows, list):
        fail("QUALIFICATION_ARTIFACTS")
    by_name: dict[str, dict[str, Any]] = {}
    for row in rows:
        if not isinstance(row, dict):
            fail("QUALIFICATION_ARTIFACTS")
        name = row.get("name")
        if isinstance(name, str) and name in eff_cap["artifacts"]:
            if name in by_name:
                fail("QUALIFICATION_ARTIFACTS")
            by_name[name] = row

    if set(by_name.keys()) != set(eff_cap["artifacts"]):
        fail("QUALIFICATION_ARTIFACTS")

    for name, expected in eff_cap["artifacts"].items():
        row = by_name[name]
        wf_run = row.get("workflow_run")
        digest_str = row.get("digest")
        if (
            row.get("id") != expected["id"]
            or row.get("size_in_bytes") != expected["size_in_bytes"]
            or row.get("archive_download_url") != expected["archive_download_url"]
            or row.get("expired") is not False
            or (digest_str is not None and digest_str != "sha256:" + expected["archive_sha256"])
            or not isinstance(wf_run, dict)
            or wf_run.get("id") != expected_run_id
            or wf_run.get("head_sha") != eff_cap["qualification_source_commit"]
            or wf_run.get("head_branch") != "main"
        ):
            fail("QUALIFICATION_ARTIFACTS")

    return {"run_id": expected_run_id, "artifacts": sorted(by_name.keys())}


def _read_exact_zip_members(
    archive_path: Path,
    expected_files: Mapping[str, Mapping[str, Any]],
) -> dict[str, bytes]:
    try:
        zf = zipfile.ZipFile(archive_path, "r")
    except (OSError, zipfile.BadZipFile):
        fail("QUALIFICATION_ARCHIVE")

    members: dict[str, bytes] = {}
    with zf:
        for info in zf.infolist():
            name = info.filename
            if (
                not name
                or name.startswith("/")
                or "\\" in name
                or ".." in name.split("/")
                or info.is_dir()
            ):
                fail("QUALIFICATION_ARCHIVE")
            mode = (info.external_attr >> 16) & 0o170000
            if mode == stat.S_IFLNK or name in members:
                fail("QUALIFICATION_ARCHIVE")
            expected = expected_files.get(name)
            if expected is None or info.file_size != expected["size"]:
                fail("QUALIFICATION_ARCHIVE")
            data = zf.read(info)
            if len(data) != expected["size"] or sha256(data) != expected["sha256"]:
                fail("QUALIFICATION_ARCHIVE")
            members[name] = data

    if set(members.keys()) != set(expected_files.keys()):
        fail("QUALIFICATION_ARCHIVE")
    return members


def validate_archives(
    archives_dir: str | Path,
    *,
    capture: Mapping[str, Any] | None = None,
    approval: Mapping[str, Any] | None = None,
    repository: str | Path | None = None,
) -> dict[str, dict[str, bytes]]:
    """Validate the retained GitHub Actions qualification archives and their extracted members."""
    root = _require_real_directory(archives_dir, "QUALIFICATION_ARCHIVE")
    eff_cap = (
        load_qualification_capture(repository, approval=approval)
        if capture is None
        else validate_qualification_capture(capture, approval=approval)
    )
    expected_zip_names = {f"{name}.zip" for name in eff_cap["artifacts"]}
    actual_zip_names = {p.name for p in root.iterdir()}
    if actual_zip_names != expected_zip_names:
        fail("QUALIFICATION_ARCHIVE")

    extracted: dict[str, dict[str, bytes]] = {}
    for name in eff_cap["artifacts"]:
        spec = eff_cap["artifacts"][name]
        zip_path = root / f"{name}.zip"
        _check_no_symlinks(zip_path, "QUALIFICATION_ARCHIVE")
        if not zip_path.is_file():
            fail("QUALIFICATION_ARCHIVE")
        archive_bytes = physical_bytes(zip_path, limit=spec["size_in_bytes"])
        if len(archive_bytes) != spec["size_in_bytes"] or sha256(archive_bytes) != spec["archive_sha256"]:
            fail("QUALIFICATION_ARCHIVE")
        extracted[name] = _read_exact_zip_members(zip_path, spec["files"])
    return extracted


def _write_resume_member(output_dir: Path, name: str, data: bytes) -> Path:
    """Write one capture-authenticated manylinux member into the resume root."""
    if not name or "/" in name or "\\" in name or name in (".", ".."):
        fail("MANYLINUX_CAPTURE_MEMBER")
    path = output_dir / name
    _check_no_symlinks(path, "MANYLINUX_CAPTURE_MEMBER")
    if path.exists():
        fail("MANYLINUX_CAPTURE_MEMBER")
    with path.open("xb") as stream:
        stream.write(data)
    return path


def prepare_resume(
    api_dir: str | Path,
    archives_dir: str | Path,
    output_dir: str | Path,
    *,
    publisher_dir: str | Path | None = None,
    qualification_dir: str | Path | None = None,
    qualification_inputs: str | Path | None = None,
    inrun_root: str | Path | None = None,
) -> dict[str, Any]:
    """Authenticate retained 0.7.0 qualification archives and stage verified dist + receipts for resume."""
    pub = _require_real_directory(publisher_dir or repo_root(), "RESUME_PREPARE")
    qual_repo = (
        _require_real_directory(qualification_dir, "RESUME_PREPARE")
        if qualification_dir is not None
        else None
    )
    pin = load_pin(pub)
    approval = load_approval(pub)
    capture = load_qualification_capture(pub, pin=pin, approval=approval)
    _cross_check_pin_and_approval(pin, approval, require_admitted=True)

    validate_api_metadata(api_dir, capture=capture)
    extracted = validate_archives(archives_dir, capture=capture, approval=approval)

    out = Path(output_dir)
    _check_no_symlinks(out, "RESUME_OUTPUT")
    if out.exists():
        if not out.is_dir() or any(out.iterdir()):
            fail("RESUME_OUTPUT")
    dist_dir = out / "dist"
    receipts_dir = out / "receipts"
    dist_dir.mkdir(parents=True, exist_ok=True)
    receipts_dir.mkdir(parents=True, exist_ok=True)

    bundle = extracted[CANDIDATE_BUNDLE_ARTIFACT]
    for f_rec in approval["files"]:
        rel_key = f"dist/{f_rec['filename']}"
        w_dest = dist_dir / f_rec["filename"]
        with w_dest.open("xb") as stream:
            stream.write(bundle[rel_key])

    cand_path = out / "candidate_receipt.json"
    exp_path = out / "expected_artifacts.json"
    with cand_path.open("xb") as stream:
        stream.write(bundle["candidate_receipt.json"])
    with exp_path.open("xb") as stream:
        stream.write(bundle["expected_artifacts.json"])

    stage_a_claimed = approval.get("manylinux_stage_a_sha256") is not None
    if stage_a_claimed:
        stage_a_bytes = bundle.get(MANYLINUX_STAGE_A_MEMBER)
        admission_artifact = extracted.get(MANYLINUX_ADMISSION_ARTIFACT)
        if stage_a_bytes is None or admission_artifact is None:
            fail("MANYLINUX_CAPTURE_MEMBER")
        try:
            stage_a_doc = strict_json(stage_a_bytes)
        except (AdmissionError, OSError, ValueError):
            fail("MANYLINUX_CAPTURE_MEMBER")
        stage_a_record = stage_a_doc.get("record") if isinstance(stage_a_doc, Mapping) else None
        tf_source = stage_a_record.get("tf_producer_source") if isinstance(stage_a_record, Mapping) else None
        if not isinstance(tf_source, Mapping):
            fail("MANYLINUX_CAPTURE_MEMBER")
        if (
            qual_repo is not None
            or qualification_inputs is not None
            or inrun_root is not None
        ):
            descriptor_repository = qual_repo or pub
            qual_inputs = load_qualification_inputs_descriptor(
                qualification_inputs,
                repository=descriptor_repository,
                phase=QUALIFICATION_INPUT_PHASE_PREP,
                inrun_root=inrun_root,
            )
            if (
                qualification_inputs is not None
                and inrun_root is None
                and isinstance(qual_inputs.get("manylinux"), Mapping)
                and qual_inputs["manylinux"].get("schema") == PUBLIC_INRUN_MANYLINUX_SCHEMA
                and qual_inputs["manylinux"].get("origin_kind") == PUBLIC_INRUN_MANYLINUX_ORIGIN_KIND
            ):
                fail("QUALIFICATION_INPUTS_ROOT")
            qual_manylinux = qual_inputs.get("manylinux")
            if (
                not isinstance(qual_manylinux, Mapping)
                or dict(tf_source) != dict(qual_manylinux["tf_producer_source"])
            ):
                fail("MANYLINUX_CAPTURE_MEMBER")
        stage_a = load_payload_portability_bundle(
            _write_resume_member(out, MANYLINUX_STAGE_A_MEMBER, stage_a_bytes),
            expected_tf_producer_source=tf_source,
            expected_rs9_tool_source={
                "commit": approval["qualification"]["candidate_source_commit"],
                "tree": approval["qualification"]["candidate_source_tree"],
            },
        )
        if stage_a.digest != approval["manylinux_stage_a_sha256"]:
            fail("MANYLINUX_CAPTURE_MEMBER")
        try:
            admission_doc = strict_json(admission_artifact[MANYLINUX_ADMISSION_MEMBER])
        except (AdmissionError, OSError, ValueError):
            fail("MANYLINUX_CAPTURE_MEMBER")
        consumer_member_bytes = {
            name: data
            for name, data in admission_artifact.items()
            if name != MANYLINUX_ADMISSION_MEMBER
        }
        _validate_captured_consumer_members(admission_doc, consumer_member_bytes)
        consumer_root = out / "manylinux-consumers"
        _check_no_symlinks(consumer_root, "MANYLINUX_CAPTURE_MEMBER")
        consumer_root.mkdir(parents=True, exist_ok=True)
        for member, data in consumer_member_bytes.items():
            dest = consumer_root / member
            _check_no_symlinks(dest.parent, "MANYLINUX_CAPTURE_MEMBER")
            dest.parent.mkdir(parents=True, exist_ok=True)
            with dest.open("xb") as stream:
                stream.write(data)
        _write_resume_member(
            out,
            MANYLINUX_ADMISSION_MEMBER,
            admission_artifact[MANYLINUX_ADMISSION_MEMBER],
        )

    for target, art_name in TARGET_QUALIFICATION_ARTIFACTS.items():
        t_dir = receipts_dir / target
        t_dir.mkdir(parents=True, exist_ok=True)
        q_dest = t_dir / "result.json"
        with q_dest.open("xb") as stream:
            stream.write(extracted[art_name][f"{target}/result.json"])

    mat_bytes = extracted[MATRIX_RECEIPT_ARTIFACT][MATRIX_RECEIPT_MEMBER]
    mat_path = out / MATRIX_RECEIPT_MEMBER
    with mat_path.open("xb") as stream:
        stream.write(mat_bytes)

    verify_approved(dist_dir, approval=approval, pin=pin, require_admitted=True)
    admitted_matrix = verify_matrix_receipts(
        cand_path,
        exp_path,
        receipts_dir,
        dist=dist_dir,
        approval=approval,
        pin=pin,
        repository=qual_repo,
    )
    if canonical(strict_json(mat_bytes)) != canonical(admitted_matrix):
        fail("MATRIX_RECEIPT_DIGEST")

    return {
        "project": PROJECT,
        "version": VERSION,
        "run_id": int(capture["run_id"]),
        "qualification_commit": capture["qualification_source_commit"],
        "set_sha256": approval["set_sha256"],
        "matrix_receipt_sha256": approval["matrix_receipt_sha256"],
        "files": [rec["filename"] for rec in approval["files"]],
        "manylinux": stage_a_claimed,
    }


def stage_metadata(
    publisher_dir: str | Path,
    qualification_dir: str | Path,
) -> dict[str, Any]:
    """Copy only the 3 admitted 0.7.0 operator files from publisher checkout into qualification checkout."""
    pub = _require_real_directory(publisher_dir, "STAGE_METADATA")
    qual = _require_real_directory(qualification_dir, "STAGE_METADATA")
    if pub == qual:
        fail("STAGE_METADATA")

    pin = load_pin(pub)
    approval = load_approval(pub)
    capture = load_qualification_capture(pub, pin=pin, approval=approval)
    _cross_check_pin_and_approval(pin, approval, require_admitted=True)

    qual_commit = pin["qualification"]["qualification_source_commit"]
    qual_tree = pin["qualification"]["qualification_source_tree"]

    if (
        _git_output(qual, ["rev-parse", "--verify", "HEAD^{commit}"], "STAGE_METADATA") != qual_commit
        or _git_output(qual, ["rev-parse", "--verify", "HEAD^{tree}"], "STAGE_METADATA") != qual_tree
        or _git_output(qual, ["status", "--porcelain", "--untracked-files=all"], "STAGE_METADATA") != ""
    ):
        fail("STAGE_METADATA")

    src_ops = _require_real_directory(pub / "operators/tf-pypi", "STAGE_METADATA")
    dst_ops = _require_real_directory(qual / "operators/tf-pypi", "STAGE_METADATA")

    staged: list[str] = []
    for filename in REQUIRED_RESUME_FILES:
        src = src_ops / filename
        dst = dst_ops / filename
        _check_no_symlinks(src, "STAGE_METADATA")
        _check_no_symlinks(dst, "STAGE_METADATA")
        if not src.is_file():
            fail("STAGE_METADATA")
        if dst.exists():
            fail("STAGE_TARGET_EXISTS")
        data = physical_bytes(src, limit=1024 * 1024)
        with dst.open("xb") as stream:
            stream.write(data)
        staged.append(f"operators/tf-pypi/{filename}")

    if (
        _git_output(qual, ["rev-parse", "--verify", "HEAD^{commit}"], "STAGE_METADATA") != qual_commit
        or _git_output(qual, ["rev-parse", "--verify", "HEAD^{tree}"], "STAGE_METADATA") != qual_tree
    ):
        fail("STAGE_METADATA")

    status_lines = [
        line
        for line in _git_output(
            qual, ["status", "--porcelain", "--untracked-files=all"], "STAGE_METADATA"
        ).splitlines()
        if line
    ]
    allowed_paths = set(staged)
    for line in status_lines:
        path_part = line[3:].strip()
        if path_part not in allowed_paths:
            fail("STAGE_METADATA")

    return {
        "qualification_commit": qual_commit,
        "qualification_tree": qual_tree,
        "staged": staged,
        "run_id": int(capture["run_id"]),
    }


def validate_workflow_dispatch(release: str, mode: str) -> dict[str, str]:
    """Validate that (release, mode) is an explicitly supported workflow_dispatch route."""
    if release not in ("0.6.1", "0.7.0"):
        fail("WORKFLOW_RELEASE")
    if (release == "0.6.1" and mode in ("qualify", "publish")) or (
        release == "0.7.0" and mode in ("qualify", "resume")
    ):
        return {"release": release, "mode": mode}
    fail("WORKFLOW_MODE_UNSUPPORTED")
    raise AssertionError("unreachable")


def workflow_070_qualify_jobs_text() -> str:
    """Render the 0.7.0 qualification jobs and dispatch guard for rs9-tfnf-pypi-publish.yml (zero OIDC permissions)."""
    return f"""
  reject_unsupported_dispatch:
    if: github.event_name == 'workflow_dispatch' && ((inputs.release == '0.7.0' && inputs.mode == 'publish') || (inputs.release != '0.7.0' && inputs.mode == 'resume'))
    name: Reject unsupported release and mode combination
    runs-on: ubuntu-24.04
    timeout-minutes: 5
    permissions:
      contents: read
    steps:
      - name: Checkout repository
        uses: {CHECKOUT_ACTION}
        with:
          ref: '${{{{ github.sha }}}}'
          persist-credentials: false

      - name: Set up Python 3.13
        id: setup_python
        uses: {SETUP_PYTHON_ACTION}
        with:
          python-version: '3.13'

      - name: Fail closed on unsupported release and mode combination
        env:
          PYTHONPATH: src
          PYTHONDONTWRITEBYTECODE: '1'
        run: |
          "${{{{ steps.setup_python.outputs.python-path }}}}" -B -m rs9.tf_pypi_nebular070_publish validate-dispatch \\
            --release "${{{{ inputs.release || '0.6.1' }}}}" \\
            --mode "${{{{ inputs.mode }}}}"

  prepare_public_inputs_070:
    if: (github.ref == 'refs/heads/main' || github.ref == 'refs/heads/{QUALIFY_BRANCH}') && github.event_name == 'workflow_dispatch' && inputs.release == '0.7.0' && inputs.mode == 'qualify'
    name: {PREPARE_PUBLIC_INPUTS_070_JOB_NAME}
    runs-on: ubuntu-24.04
    timeout-minutes: 45
    permissions:
      contents: read
    steps:
      - name: Checkout repository
        uses: {CHECKOUT_ACTION}
        with:
          ref: '${{{{ github.sha }}}}'
          persist-credentials: false

      - name: Set up Python 3.13
        id: setup_python
        uses: {SETUP_PYTHON_ACTION}
        with:
          python-version: '3.13'

      - name: Resolve current source tree
        id: source_tree
        run: |
          set -euo pipefail
          printf 'tree=%s\\n' "$(git rev-parse --verify 'HEAD^{{tree}}')" >> "$GITHUB_OUTPUT"

      - name: Prepare held 0.7.0 public inputs
        env:
          PYTHONPATH: src
          PYTHONDONTWRITEBYTECODE: '1'
        run: |
          set -euo pipefail
          "${{{{ steps.setup_python.outputs.python-path }}}}" -B -m rs9.tf_pypi_nebular070_publish prepare-public-inputs-070 \\
            --manifest {PUBLIC_INPUTS_MANIFEST_PATH.as_posix()} \\
            --output "${{{{ runner.temp }}}}/{PUBLIC_INPUTS_ARTIFACT}" \\
            --repository "$GITHUB_WORKSPACE" \\
            --stage-a-spec {PUBLIC_STAGE_A_SPEC} \\
            --rs9-commit "${{{{ github.sha }}}}" \\
            --rs9-tree "${{{{ steps.source_tree.outputs.tree }}}}" \\
            --tf-producer-commit {PUBLIC_TF_PRODUCER_SOURCE['commit']} \\
            --tf-producer-tree {PUBLIC_TF_PRODUCER_SOURCE['tree']}

      - name: Upload 0.7.0 public inputs
        uses: {UPLOAD_ARTIFACT_ACTION}
        with:
          name: {PUBLIC_INPUTS_ARTIFACT}
          path: '${{{{ runner.temp }}}}/{PUBLIC_INPUTS_ARTIFACT}/'
          include-hidden-files: true
          compression-level: 0
          retention-days: 14
          if-no-files-found: error

  build_verify_070:
    if: (github.ref == 'refs/heads/main' || github.ref == 'refs/heads/{QUALIFY_BRANCH}') && github.event_name == 'workflow_dispatch' && inputs.release == '0.7.0' && inputs.mode == 'qualify'
    name: Build and Verify Nebular 0.7.0 Candidate Bundle
    needs: [prepare_public_inputs_070]
    runs-on: ubuntu-24.04
    timeout-minutes: 30
    permissions:
      contents: read
    steps:
      - name: Checkout repository
        uses: {CHECKOUT_ACTION}
        with:
          ref: '${{{{ github.sha }}}}'
          persist-credentials: false

      - name: Set up Python 3.13
        id: setup_python
        uses: {SETUP_PYTHON_ACTION}
        with:
          python-version: '3.13'

      - name: Download 0.7.0 public inputs
        uses: {DOWNLOAD_ARTIFACT_ACTION}
        with:
          name: {PUBLIC_INPUTS_ARTIFACT}
          path: '${{{{ runner.temp }}}}/{PUBLIC_INPUTS_ARTIFACT}'

      - name: Validate explicit 0.7.0 runtime profile
        id: runtime_profile
        env:
          PYTHONPATH: src
          PYTHONDONTWRITEBYTECODE: '1'
          QUALIFICATION_INPUTS: '${{{{ runner.temp }}}}/{PUBLIC_INPUTS_ARTIFACT}/{PUBLIC_INPUTS_DESCRIPTOR}'
          INRUN_ROOT: '${{{{ runner.temp }}}}/{PUBLIC_INPUTS_ARTIFACT}'
        run: |
          set -euo pipefail
          PROFILE="$("${{{{ steps.setup_python.outputs.python-path }}}}" -B - <<'PY'
          import os
          from pathlib import Path
          from rs9.tf_pypi_nebular070_publish import (
              SYSTEM_WEBKIT_RUNTIME_PROFILE,
              load_qualification_inputs_descriptor,
          )

          descriptor = load_qualification_inputs_descriptor(
              Path(os.environ["QUALIFICATION_INPUTS"]),
              repository=Path(os.environ["GITHUB_WORKSPACE"]),
              phase="qualification-prep",
              inrun_root=Path(os.environ["INRUN_ROOT"]),
          )
          if "system_webkit" in descriptor:
              print(SYSTEM_WEBKIT_RUNTIME_PROFILE)
          elif "manylinux" in descriptor:
              print("manylinux")
          else:
              raise SystemExit("explicit runtime profile missing")
          PY
          )"
          case "$PROFILE" in
            manylinux|system-webkitgtk-4.1) ;;
            *) echo "unsupported runtime profile" >&2; exit 1 ;;
          esac
          printf 'profile=%s\\n' "$PROFILE" >> "$GITHUB_OUTPUT"

      - name: Build and verify 0.7.0 candidate bundle
        env:
          PYTHONPATH: src
          PYTHONDONTWRITEBYTECODE: '1'
          RS9_GITHUB_READ_TOKEN: ${{{{ github.token }}}}
        run: |
          build_args=(
            build-candidates
            --qualification-inputs "${{{{ runner.temp }}}}/{PUBLIC_INPUTS_ARTIFACT}/{PUBLIC_INPUTS_DESCRIPTOR}"
            --inrun-root "${{{{ runner.temp }}}}/{PUBLIC_INPUTS_ARTIFACT}"
            --evidence "${{{{ runner.temp }}}}/tfnf-070-evidence"
            --output "${{{{ runner.temp }}}}/tfnf-070-bundle"
            --expected-commit "${{{{ github.sha }}}}"
            --require-clean
          )
          if [[ "${{{{ steps.runtime_profile.outputs.profile }}}}" == "manylinux" ]]; then
            build_args+=(
              --tf-producer-commit {PUBLIC_TF_PRODUCER_SOURCE['commit']}
              --tf-producer-tree {PUBLIC_TF_PRODUCER_SOURCE['tree']}
              --require-manylinux
            )
          fi
          "${{{{ steps.setup_python.outputs.python-path }}}}" -B -m rs9.tf_pypi_nebular070_publish "${{build_args[@]}}"

      - name: Upload 0.7.0 candidate bundle
        uses: {UPLOAD_ARTIFACT_ACTION}
        with:
          name: {CANDIDATE_BUNDLE_ARTIFACT}
          path: '${{{{ runner.temp }}}}/tfnf-070-bundle/'
          retention-days: 14
          if-no-files-found: error

  native_consumer_070_darwin_arm64:
    if: (github.ref == 'refs/heads/main' || github.ref == 'refs/heads/{QUALIFY_BRANCH}') && github.event_name == 'workflow_dispatch' && inputs.release == '0.7.0' && inputs.mode == 'qualify'
    name: Native consumer 0.7.0 (darwin-arm64)
    needs: [build_verify_070]
    runs-on: macos-15
    timeout-minutes: 45
    permissions:
      contents: read
    steps:
      - name: Checkout exact source
        uses: {CHECKOUT_ACTION}
        with:
          ref: '${{{{ github.sha }}}}'
          persist-credentials: false

      - name: Set up Python 3.13
        id: setup_python
        uses: {SETUP_PYTHON_ACTION}
        with:
          python-version: '3.13'

      - name: Set up Node 22
        uses: {SETUP_NODE_ACTION}
        with:
          node-version: '22'
          package-manager-cache: false

      - name: Download 0.7.0 candidate bundle
        uses: {DOWNLOAD_ARTIFACT_ACTION}
        with:
          name: {CANDIDATE_BUNDLE_ARTIFACT}
          path: '${{{{ runner.temp }}}}/tfnf-070-bundle'

      - name: Download 0.7.0 public inputs
        uses: {DOWNLOAD_ARTIFACT_ACTION}
        with:
          name: {PUBLIC_INPUTS_ARTIFACT}
          path: '${{{{ runner.temp }}}}/{PUBLIC_INPUTS_ARTIFACT}'

      - name: Qualify native consumer on darwin-arm64
        env:
          PYTHONPATH: src
          PYTHONDONTWRITEBYTECODE: '1'
        run: |
          "${{{{ steps.setup_python.outputs.python-path }}}}" -B -m rs9.tf_pypi_nebular070_publish qualify-native \\
            --target darwin-arm64 \\
            --qualification-inputs "${{{{ runner.temp }}}}/{PUBLIC_INPUTS_ARTIFACT}/{PUBLIC_INPUTS_DESCRIPTOR}" \\
            --inrun-root "${{{{ runner.temp }}}}/{PUBLIC_INPUTS_ARTIFACT}" \\
            --raw-release "${{{{ runner.temp }}}}/tfnf-070-raw-release-darwin-arm64/raw_release.json" \\
            --bundle "${{{{ runner.temp }}}}/tfnf-070-bundle" \\
            --work "${{{{ runner.temp }}}}/tfnf-070-work-darwin-arm64" \\
            --output "${{{{ runner.temp }}}}/tfnf-070-qual/darwin-arm64/result.json" \\
            --expected-commit "${{{{ github.sha }}}}" \\
            --run-id "${{{{ github.run_id }}}}" \\
            --run-attempt "${{{{ github.run_attempt }}}}"

      - name: Upload darwin-arm64 qualification receipt
        uses: {UPLOAD_ARTIFACT_ACTION}
        with:
          name: {TARGET_QUALIFICATION_ARTIFACTS['darwin-arm64']}
          path: '${{{{ runner.temp }}}}/tfnf-070-qual/'
          retention-days: 14
          if-no-files-found: error

      - name: Upload failed native harness report
        if: failure()
        uses: {UPLOAD_ARTIFACT_ACTION}
        with:
          name: {TARGET_QUALIFICATION_ARTIFACTS['darwin-arm64']}-failure-diagnostic
          path: '${{{{ runner.temp }}}}/tfnf-070-work-darwin-arm64/installed-native-smoke/**/*.run.json'
          retention-days: 14
          if-no-files-found: ignore

  native_consumer_070_linux_arm64_gnu:
    if: (github.ref == 'refs/heads/main' || github.ref == 'refs/heads/{QUALIFY_BRANCH}') && github.event_name == 'workflow_dispatch' && inputs.release == '0.7.0' && inputs.mode == 'qualify'
    name: Native consumer 0.7.0 (linux-arm64-gnu)
    needs: [build_verify_070]
    runs-on: ubuntu-24.04-arm
    timeout-minutes: 45
    permissions:
      contents: read
    steps:
      - name: Checkout exact source
        uses: {CHECKOUT_ACTION}
        with:
          ref: '${{{{ github.sha }}}}'
          persist-credentials: false

      - name: Set up Python 3.13
        id: setup_python
        uses: {SETUP_PYTHON_ACTION}
        with:
          python-version: '3.13'

      - name: Set up Node 22
        uses: {SETUP_NODE_ACTION}
        with:
          node-version: '22'
          package-manager-cache: false

      - name: Install minimal Ubuntu display tools
        shell: bash
        run: |
          set -euo pipefail
          sudo apt-get update
          sudo apt-get install -y --no-install-recommends \\
            {" ".join(UBUNTU_DISPLAY_TOOL_PACKAGES)}

      - name: Verify Ubuntu display tool class
        shell: bash
        run: |
          set -euo pipefail
          for tool in {" ".join(DISPLAY_TOOL_COMMANDS)}; do
            command -v "$tool" >/dev/null
          done
          for package in {" ".join(UBUNTU_DISPLAY_TOOL_PACKAGES)}; do
            dpkg-query -W -f='${{Version}}' "$package" >/dev/null
          done
          {{
            printf 'platform=ubuntu-runner\\n'
            dpkg-query -W -f='${{Package}}\\t${{Version}}\\n' {" ".join(UBUNTU_DISPLAY_TOOL_PACKAGES)}
            for tool in {" ".join(DISPLAY_TOOL_COMMANDS)}; do
              printf 'tool=%s path=%s\\n' "$tool" "$(command -v "$tool")"
            done
          }} | tee "${{{{ runner.temp }}}}/tfnf-070-display-tools.tsv"

      - name: Download 0.7.0 candidate bundle
        uses: {DOWNLOAD_ARTIFACT_ACTION}
        with:
          name: {CANDIDATE_BUNDLE_ARTIFACT}
          path: '${{{{ runner.temp }}}}/tfnf-070-bundle'

      - name: Download 0.7.0 public inputs
        uses: {DOWNLOAD_ARTIFACT_ACTION}
        with:
          name: {PUBLIC_INPUTS_ARTIFACT}
          path: '${{{{ runner.temp }}}}/{PUBLIC_INPUTS_ARTIFACT}'

      - name: Resolve explicit Linux runtime profile
        id: linux_runtime_profile
        env:
          PYTHONPATH: src
          PYTHONDONTWRITEBYTECODE: '1'
          QUALIFICATION_INPUTS: '${{{{ runner.temp }}}}/{PUBLIC_INPUTS_ARTIFACT}/{PUBLIC_INPUTS_DESCRIPTOR}'
          INRUN_ROOT: '${{{{ runner.temp }}}}/{PUBLIC_INPUTS_ARTIFACT}'
        run: |
          set -euo pipefail
          PROFILE="$("${{{{ steps.setup_python.outputs.python-path }}}}" -B - <<'PY'
          import os
          from pathlib import Path
          from rs9.tf_pypi_nebular070_publish import (
              SYSTEM_WEBKIT_RUNTIME_PROFILE,
              load_qualification_inputs_descriptor,
          )

          descriptor = load_qualification_inputs_descriptor(
              Path(os.environ["QUALIFICATION_INPUTS"]),
              repository=Path(os.environ["GITHUB_WORKSPACE"]),
              phase="qualification-prep",
              inrun_root=Path(os.environ["INRUN_ROOT"]),
          )
          if "system_webkit" in descriptor:
              print(SYSTEM_WEBKIT_RUNTIME_PROFILE)
          elif "manylinux" in descriptor:
              print("manylinux")
          else:
              raise SystemExit("explicit runtime profile missing")
          PY
          )"
          case "$PROFILE" in
            manylinux|system-webkitgtk-4.1) ;;
            *) echo "unsupported runtime profile" >&2; exit 1 ;;
          esac
          printf 'profile=%s\\n' "$PROFILE" >> "$GITHUB_OUTPUT"

      - name: Install Ubuntu system WebKit runtime packages
        if: steps.linux_runtime_profile.outputs.profile == 'system-webkitgtk-4.1'
        shell: bash
        run: |
          set -euo pipefail
          sudo apt-get update
          sudo apt-get install -y --no-install-recommends \\
            {" ".join(UBUNTU_SYSTEM_WEBKIT_PACKAGES)}

      - name: Verify Ubuntu system WebKit runtime packages
        if: steps.linux_runtime_profile.outputs.profile == 'system-webkitgtk-4.1'
        shell: bash
        run: |
          set -euo pipefail
          dpkg-query -W -f='${{Package}}\\t${{Version}}\\n' {" ".join(UBUNTU_SYSTEM_WEBKIT_PACKAGES)} \\
            | tee "${{{{ runner.temp }}}}/tfnf-070-system-webkit-packages.tsv"
          ldconfig -p | grep -F 'libwebkit2gtk-4.1.so.0' >/dev/null
          ldconfig -p | grep -F 'libjavascriptcoregtk-4.1.so.0' >/dev/null

      - name: Qualify native consumer on linux-arm64-gnu
        env:
          PYTHONPATH: src
          PYTHONDONTWRITEBYTECODE: '1'
        run: |
          "${{{{ steps.setup_python.outputs.python-path }}}}" -B -m rs9.tf_pypi_nebular070_publish qualify-native \\
            --target linux-arm64-gnu \\
            --qualification-inputs "${{{{ runner.temp }}}}/{PUBLIC_INPUTS_ARTIFACT}/{PUBLIC_INPUTS_DESCRIPTOR}" \\
            --inrun-root "${{{{ runner.temp }}}}/{PUBLIC_INPUTS_ARTIFACT}" \\
            --raw-release "${{{{ runner.temp }}}}/tfnf-070-raw-release-linux-arm64-gnu/raw_release.json" \\
            --bundle "${{{{ runner.temp }}}}/tfnf-070-bundle" \\
            --work "${{{{ runner.temp }}}}/tfnf-070-work-linux-arm64-gnu" \\
            --output "${{{{ runner.temp }}}}/tfnf-070-qual/linux-arm64-gnu/result.json" \\
            --expected-commit "${{{{ github.sha }}}}" \\
            --run-id "${{{{ github.run_id }}}}" \\
            --run-attempt "${{{{ github.run_attempt }}}}" \\
            --consumer-host-role newer \\
            --consumer-capture-output "${{{{ runner.temp }}}}/tfnf-070-qual/linux-arm64-gnu/newer.json"

      - name: Upload linux-arm64-gnu qualification receipt
        uses: {UPLOAD_ARTIFACT_ACTION}
        with:
          name: {TARGET_QUALIFICATION_ARTIFACTS['linux-arm64-gnu']}
          path: '${{{{ runner.temp }}}}/tfnf-070-qual/'
          retention-days: 14
          if-no-files-found: error

      - name: Upload failed native harness report
        if: failure()
        uses: {UPLOAD_ARTIFACT_ACTION}
        with:
          name: {TARGET_QUALIFICATION_ARTIFACTS['linux-arm64-gnu']}-failure-diagnostic
          path: '${{{{ runner.temp }}}}/tfnf-070-work-linux-arm64-gnu/installed-native-smoke/**/*.run.json'
          retention-days: 14
          if-no-files-found: ignore

  native_consumer_070_linux_x64_gnu:
    if: (github.ref == 'refs/heads/main' || github.ref == 'refs/heads/{QUALIFY_BRANCH}') && github.event_name == 'workflow_dispatch' && inputs.release == '0.7.0' && inputs.mode == 'qualify'
    name: Native consumer 0.7.0 (linux-x64-gnu)
    needs: [build_verify_070]
    runs-on: ubuntu-24.04
    timeout-minutes: 45
    permissions:
      contents: read
    steps:
      - name: Checkout exact source
        uses: {CHECKOUT_ACTION}
        with:
          ref: '${{{{ github.sha }}}}'
          persist-credentials: false

      - name: Set up Python 3.13
        id: setup_python
        uses: {SETUP_PYTHON_ACTION}
        with:
          python-version: '3.13'

      - name: Set up Node 22
        uses: {SETUP_NODE_ACTION}
        with:
          node-version: '22'
          package-manager-cache: false

      - name: Install minimal Ubuntu display tools
        shell: bash
        run: |
          set -euo pipefail
          sudo apt-get update
          sudo apt-get install -y --no-install-recommends \\
            {" ".join(UBUNTU_DISPLAY_TOOL_PACKAGES)}

      - name: Verify Ubuntu display tool class
        shell: bash
        run: |
          set -euo pipefail
          for tool in {" ".join(DISPLAY_TOOL_COMMANDS)}; do
            command -v "$tool" >/dev/null
          done
          for package in {" ".join(UBUNTU_DISPLAY_TOOL_PACKAGES)}; do
            dpkg-query -W -f='${{Version}}' "$package" >/dev/null
          done
          {{
            printf 'platform=ubuntu-runner\\n'
            dpkg-query -W -f='${{Package}}\\t${{Version}}\\n' {" ".join(UBUNTU_DISPLAY_TOOL_PACKAGES)}
            for tool in {" ".join(DISPLAY_TOOL_COMMANDS)}; do
              printf 'tool=%s path=%s\\n' "$tool" "$(command -v "$tool")"
            done
          }} | tee "${{{{ runner.temp }}}}/tfnf-070-display-tools.tsv"

      - name: Download 0.7.0 candidate bundle
        uses: {DOWNLOAD_ARTIFACT_ACTION}
        with:
          name: {CANDIDATE_BUNDLE_ARTIFACT}
          path: '${{{{ runner.temp }}}}/tfnf-070-bundle'

      - name: Download 0.7.0 public inputs
        uses: {DOWNLOAD_ARTIFACT_ACTION}
        with:
          name: {PUBLIC_INPUTS_ARTIFACT}
          path: '${{{{ runner.temp }}}}/{PUBLIC_INPUTS_ARTIFACT}'

      - name: Resolve explicit Linux runtime profile
        id: linux_runtime_profile
        env:
          PYTHONPATH: src
          PYTHONDONTWRITEBYTECODE: '1'
          QUALIFICATION_INPUTS: '${{{{ runner.temp }}}}/{PUBLIC_INPUTS_ARTIFACT}/{PUBLIC_INPUTS_DESCRIPTOR}'
          INRUN_ROOT: '${{{{ runner.temp }}}}/{PUBLIC_INPUTS_ARTIFACT}'
        run: |
          set -euo pipefail
          PROFILE="$("${{{{ steps.setup_python.outputs.python-path }}}}" -B - <<'PY'
          import os
          from pathlib import Path
          from rs9.tf_pypi_nebular070_publish import (
              SYSTEM_WEBKIT_RUNTIME_PROFILE,
              load_qualification_inputs_descriptor,
          )

          descriptor = load_qualification_inputs_descriptor(
              Path(os.environ["QUALIFICATION_INPUTS"]),
              repository=Path(os.environ["GITHUB_WORKSPACE"]),
              phase="qualification-prep",
              inrun_root=Path(os.environ["INRUN_ROOT"]),
          )
          if "system_webkit" in descriptor:
              print(SYSTEM_WEBKIT_RUNTIME_PROFILE)
          elif "manylinux" in descriptor:
              print("manylinux")
          else:
              raise SystemExit("explicit runtime profile missing")
          PY
          )"
          case "$PROFILE" in
            manylinux|system-webkitgtk-4.1) ;;
            *) echo "unsupported runtime profile" >&2; exit 1 ;;
          esac
          printf 'profile=%s\\n' "$PROFILE" >> "$GITHUB_OUTPUT"

      - name: Install Ubuntu system WebKit runtime packages
        if: steps.linux_runtime_profile.outputs.profile == 'system-webkitgtk-4.1'
        shell: bash
        run: |
          set -euo pipefail
          sudo apt-get update
          sudo apt-get install -y --no-install-recommends \\
            {" ".join(UBUNTU_SYSTEM_WEBKIT_PACKAGES)}

      - name: Verify Ubuntu system WebKit runtime packages
        if: steps.linux_runtime_profile.outputs.profile == 'system-webkitgtk-4.1'
        shell: bash
        run: |
          set -euo pipefail
          dpkg-query -W -f='${{Package}}\\t${{Version}}\\n' {" ".join(UBUNTU_SYSTEM_WEBKIT_PACKAGES)} \\
            | tee "${{{{ runner.temp }}}}/tfnf-070-system-webkit-packages.tsv"
          ldconfig -p | grep -F 'libwebkit2gtk-4.1.so.0' >/dev/null
          ldconfig -p | grep -F 'libjavascriptcoregtk-4.1.so.0' >/dev/null

      - name: Qualify native consumer on linux-x64-gnu
        env:
          PYTHONPATH: src
          PYTHONDONTWRITEBYTECODE: '1'
        run: |
          "${{{{ steps.setup_python.outputs.python-path }}}}" -B -m rs9.tf_pypi_nebular070_publish qualify-native \\
            --target linux-x64-gnu \\
            --qualification-inputs "${{{{ runner.temp }}}}/{PUBLIC_INPUTS_ARTIFACT}/{PUBLIC_INPUTS_DESCRIPTOR}" \\
            --inrun-root "${{{{ runner.temp }}}}/{PUBLIC_INPUTS_ARTIFACT}" \\
            --raw-release "${{{{ runner.temp }}}}/tfnf-070-raw-release-linux-x64-gnu/raw_release.json" \\
            --bundle "${{{{ runner.temp }}}}/tfnf-070-bundle" \\
            --work "${{{{ runner.temp }}}}/tfnf-070-work-linux-x64-gnu" \\
            --output "${{{{ runner.temp }}}}/tfnf-070-qual/linux-x64-gnu/result.json" \\
            --expected-commit "${{{{ github.sha }}}}" \\
            --run-id "${{{{ github.run_id }}}}" \\
            --run-attempt "${{{{ github.run_attempt }}}}" \\
            --consumer-host-role newer \\
            --consumer-capture-output "${{{{ runner.temp }}}}/tfnf-070-qual/linux-x64-gnu/newer.json"

      - name: Upload linux-x64-gnu qualification receipt
        uses: {UPLOAD_ARTIFACT_ACTION}
        with:
          name: {TARGET_QUALIFICATION_ARTIFACTS['linux-x64-gnu']}
          path: '${{{{ runner.temp }}}}/tfnf-070-qual/'
          retention-days: 14
          if-no-files-found: error

      - name: Upload failed native harness report
        if: failure()
        uses: {UPLOAD_ARTIFACT_ACTION}
        with:
          name: {TARGET_QUALIFICATION_ARTIFACTS['linux-x64-gnu']}-failure-diagnostic
          path: '${{{{ runner.temp }}}}/tfnf-070-work-linux-x64-gnu/installed-native-smoke/**/*.run.json'
          retention-days: 14
          if-no-files-found: ignore

  native_consumer_070_linux_arm64_gnu_floor:
    if: (github.ref == 'refs/heads/main' || github.ref == 'refs/heads/{QUALIFY_BRANCH}') && github.event_name == 'workflow_dispatch' && inputs.release == '0.7.0' && inputs.mode == 'qualify'
    name: Native consumer 0.7.0 (linux-arm64-gnu floor)
    needs: [build_verify_070]
    runs-on: ubuntu-24.04-arm
    timeout-minutes: 60
    defaults:
      run:
        shell: bash
    env:
      TFNF_CI_TEMP: /__w/_temp
    permissions:
      contents: read
    # Release-scoped Bookworm/SYS_ADMIN floor policy; held pending its
    # corresponding release-policy decision.
    container:
      image: debian:bookworm-slim@sha256:3783cc01769c7b2b1b83a5c5ad96c815348e28ed7da68e2e3687004faa906251
      options: --init --cap-add=SYS_ADMIN
    steps:
      - name: Install pinned Bookworm floor tools
        shell: bash
        run: |
          set -euo pipefail
          mkdir -p "${{{{ env.TFNF_CI_TEMP }}}}"
          apt-get update
          apt-get install -y --no-install-recommends \\
            ca-certificates git python3 python3-venv=3.11.2-1+b1 \\
            sudo=1.9.13p3-1+deb12u4 util-linux=2.38.1-5+deb12u3 \\
            binutils procps \\
            {BOOKWORM_DISPLAY_TOOL_PACKAGES[0]} \\
            {BOOKWORM_DISPLAY_TOOL_PACKAGES[1]} \\
            {BOOKWORM_DISPLAY_TOOL_PACKAGES[2]}

      - name: Verify Bookworm display tool class
        shell: bash
        run: |
          set -euo pipefail
          for tool in {" ".join(DISPLAY_TOOL_COMMANDS)}; do
            command -v "$tool" >/dev/null
          done
          test "$(dpkg-query -W -f='${{Version}}' xvfb)" = "2:21.1.7-3+deb12u13"
          test "$(dpkg-query -W -f='${{Version}}' xauth)" = "1:1.1.2-1"
          test "$(dpkg-query -W -f='${{Version}}' dbus-x11)" = "1.14.10-1~deb12u1"
          {{
            printf 'platform=debian-bookworm-floor\\n'
            dpkg-query -W -f='${{Package}}\\t${{Version}}\\n' xvfb xauth dbus-x11
            for tool in {" ".join(DISPLAY_TOOL_COMMANDS)}; do
              printf 'tool=%s path=%s\\n' "$tool" "$(command -v "$tool")"
            done
          }} | tee "${{{{ env.TFNF_CI_TEMP }}}}/tfnf-070-floor-display-tools.tsv"

      - name: Checkout exact source
        uses: {CHECKOUT_ACTION}
        with:
          ref: '${{{{ github.sha }}}}'
          fetch-depth: 1
          persist-credentials: false

      - name: Select pinned Bookworm Python 3.11
        id: setup_python
        run: |
          set -euo pipefail
          /usr/bin/python3 -I -B -c 'import sys; assert sys.version_info[:2] == (3, 11)'
          dpkg-query -W python3 python3.11 python3.11-venv
          echo 'python-path=/usr/bin/python3' >> "$GITHUB_OUTPUT"

      - name: Set up Node 22
        uses: {SETUP_NODE_ACTION}
        with:
          node-version: '22.23.3'
          package-manager-cache: false

      - name: Download 0.7.0 candidate bundle
        uses: {DOWNLOAD_ARTIFACT_ACTION}
        with:
          name: {CANDIDATE_BUNDLE_ARTIFACT}
          path: '${{{{ env.TFNF_CI_TEMP }}}}/tfnf-070-bundle'

      - name: Download 0.7.0 public inputs
        uses: {DOWNLOAD_ARTIFACT_ACTION}
        with:
          name: {PUBLIC_INPUTS_ARTIFACT}
          path: '${{{{ env.TFNF_CI_TEMP }}}}/{PUBLIC_INPUTS_ARTIFACT}'

      - name: Resolve explicit Linux runtime profile
        id: linux_runtime_profile
        env:
          PYTHONPATH: src
          PYTHONDONTWRITEBYTECODE: '1'
          QUALIFICATION_INPUTS: '${{{{ env.TFNF_CI_TEMP }}}}/{PUBLIC_INPUTS_ARTIFACT}/{PUBLIC_INPUTS_DESCRIPTOR}'
          INRUN_ROOT: '${{{{ env.TFNF_CI_TEMP }}}}/{PUBLIC_INPUTS_ARTIFACT}'
        run: |
          set -euo pipefail
          PROFILE="$("${{{{ steps.setup_python.outputs.python-path }}}}" -B - <<'PY'
          import os
          from pathlib import Path
          from rs9.tf_pypi_nebular070_publish import (
              SYSTEM_WEBKIT_RUNTIME_PROFILE,
              load_qualification_inputs_descriptor,
          )

          descriptor = load_qualification_inputs_descriptor(
              Path(os.environ["QUALIFICATION_INPUTS"]),
              repository=Path(os.environ["GITHUB_WORKSPACE"]),
              phase="qualification-prep",
              inrun_root=Path(os.environ["INRUN_ROOT"]),
          )
          if "system_webkit" in descriptor:
              print(SYSTEM_WEBKIT_RUNTIME_PROFILE)
          elif "manylinux" in descriptor:
              print("manylinux")
          else:
              raise SystemExit("explicit runtime profile missing")
          PY
          )"
          case "$PROFILE" in
            manylinux|system-webkitgtk-4.1) ;;
            *) echo "unsupported runtime profile" >&2; exit 1 ;;
          esac
          printf 'profile=%s\\n' "$PROFILE" >> "$GITHUB_OUTPUT"

      - name: Check Bookworm installed tfnf missing system WebKit before runtime install
        if: steps.linux_runtime_profile.outputs.profile == 'system-webkitgtk-4.1'
        shell: bash
        env:
          PYTHONPATH: src
          PYTHONDONTWRITEBYTECODE: '1'
        run: |
          set -euo pipefail
          "${{{{ steps.setup_python.outputs.python-path }}}}" -B -m rs9.tf_pypi_nebular070_publish check-system-webkit-missing \\
            --target linux-arm64-gnu \\
            --bundle "${{{{ env.TFNF_CI_TEMP }}}}/tfnf-070-bundle" \\
            --work "${{{{ env.TFNF_CI_TEMP }}}}/tfnf-070-preflight-linux-arm64-gnu-floor" \\
            --output "${{{{ env.TFNF_CI_TEMP }}}}/tfnf-070-floor/linux-arm64-gnu/missing-runtime.json" \\
            --expected-commit "${{{{ github.sha }}}}" \\
            --run-id "${{{{ github.run_id }}}}" \\
            --run-attempt "${{{{ github.run_attempt }}}}"

      - name: Install Bookworm system WebKit runtime packages
        if: steps.linux_runtime_profile.outputs.profile == 'system-webkitgtk-4.1'
        shell: bash
        run: |
          set -euo pipefail
          apt-get update
          apt-get install -y --no-install-recommends \\
            {" ".join(BOOKWORM_SYSTEM_WEBKIT_PACKAGES)}

      - name: Verify Bookworm system WebKit runtime packages
        if: steps.linux_runtime_profile.outputs.profile == 'system-webkitgtk-4.1'
        shell: bash
        run: |
          set -euo pipefail
          dpkg-query -W -f='${{Package}}\\t${{Version}}\\n' {" ".join(BOOKWORM_SYSTEM_WEBKIT_PACKAGES)} \\
            | tee "${{{{ env.TFNF_CI_TEMP }}}}/tfnf-070-floor-system-webkit-packages.tsv"
          ldconfig -p | grep -F 'libwebkit2gtk-4.1.so.0' >/dev/null
          ldconfig -p | grep -F 'libjavascriptcoregtk-4.1.so.0' >/dev/null

      - name: Qualify native consumer on linux-arm64-gnu floor
        env:
          PYTHONPATH: src
          PYTHONDONTWRITEBYTECODE: '1'
        run: |
          "${{{{ steps.setup_python.outputs.python-path }}}}" -B -m rs9.tf_pypi_nebular070_publish qualify-native \\
            --target linux-arm64-gnu \\
            --consumer-host-role floor \\
            --consumer-capture-output "${{{{ env.TFNF_CI_TEMP }}}}/tfnf-070-floor/linux-arm64-gnu/floor.json" \\
            --qualification-inputs "${{{{ env.TFNF_CI_TEMP }}}}/{PUBLIC_INPUTS_ARTIFACT}/{PUBLIC_INPUTS_DESCRIPTOR}" \\
            --inrun-root "${{{{ env.TFNF_CI_TEMP }}}}/{PUBLIC_INPUTS_ARTIFACT}" \\
            --raw-release "${{{{ env.TFNF_CI_TEMP }}}}/tfnf-070-raw-release-linux-arm64-gnu-floor/raw_release.json" \\
            --bundle "${{{{ env.TFNF_CI_TEMP }}}}/tfnf-070-bundle" \\
            --work "${{{{ env.TFNF_CI_TEMP }}}}/tfnf-070-work-linux-arm64-gnu-floor" \\
            --output "${{{{ env.TFNF_CI_TEMP }}}}/tfnf-070-floor/linux-arm64-gnu/result.json" \\
            --expected-commit "${{{{ github.sha }}}}" \\
            --run-id "${{{{ github.run_id }}}}" \\
            --run-attempt "${{{{ github.run_attempt }}}}"

      - name: Upload linux-arm64-gnu floor qualification receipt
        uses: {UPLOAD_ARTIFACT_ACTION}
        with:
          name: {FLOOR_TARGET_QUALIFICATION_ARTIFACTS['linux-arm64-gnu']}
          path: '${{{{ env.TFNF_CI_TEMP }}}}/tfnf-070-floor/'
          compression-level: 0
          retention-days: 14
          if-no-files-found: error

      - name: Upload failed native harness report
        if: failure()
        uses: {UPLOAD_ARTIFACT_ACTION}
        with:
          name: {FLOOR_TARGET_QUALIFICATION_ARTIFACTS['linux-arm64-gnu']}-failure-diagnostic
          path: '${{{{ env.TFNF_CI_TEMP }}}}/tfnf-070-work-linux-arm64-gnu-floor/installed-native-smoke/**/*.run.json'
          retention-days: 14
          if-no-files-found: ignore

  native_consumer_070_linux_x64_gnu_floor:
    if: (github.ref == 'refs/heads/main' || github.ref == 'refs/heads/{QUALIFY_BRANCH}') && github.event_name == 'workflow_dispatch' && inputs.release == '0.7.0' && inputs.mode == 'qualify'
    name: Native consumer 0.7.0 (linux-x64-gnu floor)
    needs: [build_verify_070]
    runs-on: ubuntu-24.04
    timeout-minutes: 60
    defaults:
      run:
        shell: bash
    env:
      TFNF_CI_TEMP: /__w/_temp
    permissions:
      contents: read
    # Release-scoped Bookworm/SYS_ADMIN floor policy; held pending its
    # corresponding release-policy decision.
    container:
      image: debian:bookworm-slim@sha256:3783cc01769c7b2b1b83a5c5ad96c815348e28ed7da68e2e3687004faa906251
      options: --init --cap-add=SYS_ADMIN
    steps:
      - name: Install pinned Bookworm floor tools
        shell: bash
        run: |
          set -euo pipefail
          mkdir -p "${{{{ env.TFNF_CI_TEMP }}}}"
          apt-get update
          apt-get install -y --no-install-recommends \\
            ca-certificates git python3 python3-venv=3.11.2-1+b1 \\
            sudo=1.9.13p3-1+deb12u4 util-linux=2.38.1-5+deb12u3 \\
            binutils procps \\
            {BOOKWORM_DISPLAY_TOOL_PACKAGES[0]} \\
            {BOOKWORM_DISPLAY_TOOL_PACKAGES[1]} \\
            {BOOKWORM_DISPLAY_TOOL_PACKAGES[2]}

      - name: Verify Bookworm display tool class
        shell: bash
        run: |
          set -euo pipefail
          for tool in {" ".join(DISPLAY_TOOL_COMMANDS)}; do
            command -v "$tool" >/dev/null
          done
          test "$(dpkg-query -W -f='${{Version}}' xvfb)" = "2:21.1.7-3+deb12u13"
          test "$(dpkg-query -W -f='${{Version}}' xauth)" = "1:1.1.2-1"
          test "$(dpkg-query -W -f='${{Version}}' dbus-x11)" = "1.14.10-1~deb12u1"
          {{
            printf 'platform=debian-bookworm-floor\\n'
            dpkg-query -W -f='${{Package}}\\t${{Version}}\\n' xvfb xauth dbus-x11
            for tool in {" ".join(DISPLAY_TOOL_COMMANDS)}; do
              printf 'tool=%s path=%s\\n' "$tool" "$(command -v "$tool")"
            done
          }} | tee "${{{{ env.TFNF_CI_TEMP }}}}/tfnf-070-floor-display-tools.tsv"

      - name: Checkout exact source
        uses: {CHECKOUT_ACTION}
        with:
          ref: '${{{{ github.sha }}}}'
          fetch-depth: 1
          persist-credentials: false

      - name: Select pinned Bookworm Python 3.11
        id: setup_python
        run: |
          set -euo pipefail
          /usr/bin/python3 -I -B -c 'import sys; assert sys.version_info[:2] == (3, 11)'
          dpkg-query -W python3 python3.11 python3.11-venv
          echo 'python-path=/usr/bin/python3' >> "$GITHUB_OUTPUT"

      - name: Set up Node 22
        uses: {SETUP_NODE_ACTION}
        with:
          node-version: '22.23.3'
          package-manager-cache: false

      - name: Download 0.7.0 candidate bundle
        uses: {DOWNLOAD_ARTIFACT_ACTION}
        with:
          name: {CANDIDATE_BUNDLE_ARTIFACT}
          path: '${{{{ env.TFNF_CI_TEMP }}}}/tfnf-070-bundle'

      - name: Download 0.7.0 public inputs
        uses: {DOWNLOAD_ARTIFACT_ACTION}
        with:
          name: {PUBLIC_INPUTS_ARTIFACT}
          path: '${{{{ env.TFNF_CI_TEMP }}}}/{PUBLIC_INPUTS_ARTIFACT}'

      - name: Resolve explicit Linux runtime profile
        id: linux_runtime_profile
        env:
          PYTHONPATH: src
          PYTHONDONTWRITEBYTECODE: '1'
          QUALIFICATION_INPUTS: '${{{{ env.TFNF_CI_TEMP }}}}/{PUBLIC_INPUTS_ARTIFACT}/{PUBLIC_INPUTS_DESCRIPTOR}'
          INRUN_ROOT: '${{{{ env.TFNF_CI_TEMP }}}}/{PUBLIC_INPUTS_ARTIFACT}'
        run: |
          set -euo pipefail
          PROFILE="$("${{{{ steps.setup_python.outputs.python-path }}}}" -B - <<'PY'
          import os
          from pathlib import Path
          from rs9.tf_pypi_nebular070_publish import (
              SYSTEM_WEBKIT_RUNTIME_PROFILE,
              load_qualification_inputs_descriptor,
          )

          descriptor = load_qualification_inputs_descriptor(
              Path(os.environ["QUALIFICATION_INPUTS"]),
              repository=Path(os.environ["GITHUB_WORKSPACE"]),
              phase="qualification-prep",
              inrun_root=Path(os.environ["INRUN_ROOT"]),
          )
          if "system_webkit" in descriptor:
              print(SYSTEM_WEBKIT_RUNTIME_PROFILE)
          elif "manylinux" in descriptor:
              print("manylinux")
          else:
              raise SystemExit("explicit runtime profile missing")
          PY
          )"
          case "$PROFILE" in
            manylinux|system-webkitgtk-4.1) ;;
            *) echo "unsupported runtime profile" >&2; exit 1 ;;
          esac
          printf 'profile=%s\\n' "$PROFILE" >> "$GITHUB_OUTPUT"

      - name: Check Bookworm installed tfnf missing system WebKit before runtime install
        if: steps.linux_runtime_profile.outputs.profile == 'system-webkitgtk-4.1'
        shell: bash
        env:
          PYTHONPATH: src
          PYTHONDONTWRITEBYTECODE: '1'
        run: |
          set -euo pipefail
          "${{{{ steps.setup_python.outputs.python-path }}}}" -B -m rs9.tf_pypi_nebular070_publish check-system-webkit-missing \\
            --target linux-x64-gnu \\
            --bundle "${{{{ env.TFNF_CI_TEMP }}}}/tfnf-070-bundle" \\
            --work "${{{{ env.TFNF_CI_TEMP }}}}/tfnf-070-preflight-linux-x64-gnu-floor" \\
            --output "${{{{ env.TFNF_CI_TEMP }}}}/tfnf-070-floor/linux-x64-gnu/missing-runtime.json" \\
            --expected-commit "${{{{ github.sha }}}}" \\
            --run-id "${{{{ github.run_id }}}}" \\
            --run-attempt "${{{{ github.run_attempt }}}}"

      - name: Install Bookworm system WebKit runtime packages
        if: steps.linux_runtime_profile.outputs.profile == 'system-webkitgtk-4.1'
        shell: bash
        run: |
          set -euo pipefail
          apt-get update
          apt-get install -y --no-install-recommends \\
            {" ".join(BOOKWORM_SYSTEM_WEBKIT_PACKAGES)}

      - name: Verify Bookworm system WebKit runtime packages
        if: steps.linux_runtime_profile.outputs.profile == 'system-webkitgtk-4.1'
        shell: bash
        run: |
          set -euo pipefail
          dpkg-query -W -f='${{Package}}\\t${{Version}}\\n' {" ".join(BOOKWORM_SYSTEM_WEBKIT_PACKAGES)} \\
            | tee "${{{{ env.TFNF_CI_TEMP }}}}/tfnf-070-floor-system-webkit-packages.tsv"
          ldconfig -p | grep -F 'libwebkit2gtk-4.1.so.0' >/dev/null
          ldconfig -p | grep -F 'libjavascriptcoregtk-4.1.so.0' >/dev/null

      - name: Qualify native consumer on linux-x64-gnu floor
        env:
          PYTHONPATH: src
          PYTHONDONTWRITEBYTECODE: '1'
        run: |
          "${{{{ steps.setup_python.outputs.python-path }}}}" -B -m rs9.tf_pypi_nebular070_publish qualify-native \\
            --target linux-x64-gnu \\
            --consumer-host-role floor \\
            --consumer-capture-output "${{{{ env.TFNF_CI_TEMP }}}}/tfnf-070-floor/linux-x64-gnu/floor.json" \\
            --qualification-inputs "${{{{ env.TFNF_CI_TEMP }}}}/{PUBLIC_INPUTS_ARTIFACT}/{PUBLIC_INPUTS_DESCRIPTOR}" \\
            --inrun-root "${{{{ env.TFNF_CI_TEMP }}}}/{PUBLIC_INPUTS_ARTIFACT}" \\
            --raw-release "${{{{ env.TFNF_CI_TEMP }}}}/tfnf-070-raw-release-linux-x64-gnu-floor/raw_release.json" \\
            --bundle "${{{{ env.TFNF_CI_TEMP }}}}/tfnf-070-bundle" \\
            --work "${{{{ env.TFNF_CI_TEMP }}}}/tfnf-070-work-linux-x64-gnu-floor" \\
            --output "${{{{ env.TFNF_CI_TEMP }}}}/tfnf-070-floor/linux-x64-gnu/result.json" \\
            --expected-commit "${{{{ github.sha }}}}" \\
            --run-id "${{{{ github.run_id }}}}" \\
            --run-attempt "${{{{ github.run_attempt }}}}"

      - name: Upload linux-x64-gnu floor qualification receipt
        uses: {UPLOAD_ARTIFACT_ACTION}
        with:
          name: {FLOOR_TARGET_QUALIFICATION_ARTIFACTS['linux-x64-gnu']}
          path: '${{{{ env.TFNF_CI_TEMP }}}}/tfnf-070-floor/'
          compression-level: 0
          retention-days: 14
          if-no-files-found: error

      - name: Upload failed native harness report
        if: failure()
        uses: {UPLOAD_ARTIFACT_ACTION}
        with:
          name: {FLOOR_TARGET_QUALIFICATION_ARTIFACTS['linux-x64-gnu']}-failure-diagnostic
          path: '${{{{ env.TFNF_CI_TEMP }}}}/tfnf-070-work-linux-x64-gnu-floor/installed-native-smoke/**/*.run.json'
          retention-days: 14
          if-no-files-found: ignore

  qualification_gate_070:
    if: (github.ref == 'refs/heads/main' || github.ref == 'refs/heads/{QUALIFY_BRANCH}') && github.event_name == 'workflow_dispatch' && inputs.release == '0.7.0' && inputs.mode == 'qualify'
    name: Qualification matrix gate 0.7.0
    needs:
      - build_verify_070
      - native_consumer_070_darwin_arm64
      - native_consumer_070_linux_arm64_gnu
      - native_consumer_070_linux_x64_gnu
      - native_consumer_070_linux_arm64_gnu_floor
      - native_consumer_070_linux_x64_gnu_floor
    runs-on: ubuntu-24.04
    timeout-minutes: 20
    permissions:
      contents: read
    steps:
      - name: Checkout exact source
        uses: {CHECKOUT_ACTION}
        with:
          ref: '${{{{ github.sha }}}}'
          persist-credentials: false

      - name: Set up Python 3.13
        id: setup_python
        uses: {SETUP_PYTHON_ACTION}
        with:
          python-version: '3.13'

      - name: Download 0.7.0 candidate bundle
        uses: {DOWNLOAD_ARTIFACT_ACTION}
        with:
          name: {CANDIDATE_BUNDLE_ARTIFACT}
          path: '${{{{ runner.temp }}}}/tfnf-070-bundle'

      - name: Download 0.7.0 public inputs
        uses: {DOWNLOAD_ARTIFACT_ACTION}
        with:
          name: {PUBLIC_INPUTS_ARTIFACT}
          path: '${{{{ runner.temp }}}}/{PUBLIC_INPUTS_ARTIFACT}'

      - name: Validate explicit 0.7.0 runtime profile for matrix
        id: runtime_profile
        env:
          PYTHONPATH: src
          PYTHONDONTWRITEBYTECODE: '1'
          QUALIFICATION_INPUTS: '${{{{ runner.temp }}}}/{PUBLIC_INPUTS_ARTIFACT}/{PUBLIC_INPUTS_DESCRIPTOR}'
          INRUN_ROOT: '${{{{ runner.temp }}}}/{PUBLIC_INPUTS_ARTIFACT}'
        run: |
          set -euo pipefail
          PROFILE="$("${{{{ steps.setup_python.outputs.python-path }}}}" -B - <<'PY'
          import os
          from pathlib import Path
          from rs9.tf_pypi_nebular070_publish import (
              SYSTEM_WEBKIT_RUNTIME_PROFILE,
              load_qualification_inputs_descriptor,
          )

          descriptor = load_qualification_inputs_descriptor(
              Path(os.environ["QUALIFICATION_INPUTS"]),
              repository=Path(os.environ["GITHUB_WORKSPACE"]),
              phase="qualification-prep",
              inrun_root=Path(os.environ["INRUN_ROOT"]),
          )
          if "system_webkit" in descriptor:
              print(SYSTEM_WEBKIT_RUNTIME_PROFILE)
          elif "manylinux" in descriptor:
              print("manylinux")
          else:
              raise SystemExit("explicit runtime profile missing")
          PY
          )"
          case "$PROFILE" in
            manylinux|system-webkitgtk-4.1) ;;
            *) echo "unsupported runtime profile" >&2; exit 1 ;;
          esac
          printf 'profile=%s\\n' "$PROFILE" >> "$GITHUB_OUTPUT"

      - name: Download darwin-arm64 qualification receipt
        uses: {DOWNLOAD_ARTIFACT_ACTION}
        with:
          name: {TARGET_QUALIFICATION_ARTIFACTS['darwin-arm64']}
          path: '${{{{ runner.temp }}}}/tfnf-070-receipts'

      - name: Download linux-arm64-gnu qualification receipt
        uses: {DOWNLOAD_ARTIFACT_ACTION}
        with:
          name: {TARGET_QUALIFICATION_ARTIFACTS['linux-arm64-gnu']}
          path: '${{{{ runner.temp }}}}/tfnf-070-receipts'

      - name: Download linux-x64-gnu qualification receipt
        uses: {DOWNLOAD_ARTIFACT_ACTION}
        with:
          name: {TARGET_QUALIFICATION_ARTIFACTS['linux-x64-gnu']}
          path: '${{{{ runner.temp }}}}/tfnf-070-receipts'

      - name: Download linux-arm64-gnu floor qualification receipt
        uses: {DOWNLOAD_ARTIFACT_ACTION}
        with:
          name: {FLOOR_TARGET_QUALIFICATION_ARTIFACTS['linux-arm64-gnu']}
          path: '${{{{ runner.temp }}}}/tfnf-070-floor-receipts'

      - name: Download linux-x64-gnu floor qualification receipt
        uses: {DOWNLOAD_ARTIFACT_ACTION}
        with:
          name: {FLOOR_TARGET_QUALIFICATION_ARTIFACTS['linux-x64-gnu']}
          path: '${{{{ runner.temp }}}}/tfnf-070-floor-receipts'

      - name: Verify floor consumer receipts
        shell: bash
        run: |
          set -euo pipefail
          test -s "${{{{ runner.temp }}}}/tfnf-070-floor-receipts/linux-arm64-gnu/floor.json"
          test -s "${{{{ runner.temp }}}}/tfnf-070-floor-receipts/linux-x64-gnu/floor.json"

      - name: Admit complete 3-platform 0.7.0 qualification matrix
        env:
          PYTHONPATH: src
          PYTHONDONTWRITEBYTECODE: '1'
        run: |
          set -euo pipefail
          FLOOR_ARGS=()
          if [ "${{{{ steps.runtime_profile.outputs.profile }}}}" = system-webkitgtk-4.1 ]; then
            FLOOR_ARGS=(--system-floor-receipts "${{{{ runner.temp }}}}/tfnf-070-floor-receipts")
          fi
          "${{{{ steps.setup_python.outputs.python-path }}}}" -B -m rs9.tf_pypi_nebular070_publish admit-matrix \\
            --bundle "${{{{ runner.temp }}}}/tfnf-070-bundle" \\
            --receipts-dir "${{{{ runner.temp }}}}/tfnf-070-receipts" \\
            --output "${{{{ runner.temp }}}}/tfnf-070-matrix/matrix_receipt.json" \\
            --expected-commit "${{{{ github.sha }}}}" \\
            --qualification-inputs "${{{{ runner.temp }}}}/{PUBLIC_INPUTS_ARTIFACT}/{PUBLIC_INPUTS_DESCRIPTOR}" \\
            --inrun-root "${{{{ runner.temp }}}}/{PUBLIC_INPUTS_ARTIFACT}" \\
            --run-id "${{{{ github.run_id }}}}" \\
            --run-attempt "${{{{ github.run_attempt }}}}" \\
            "${{FLOOR_ARGS[@]}}"

      - name: Upload 0.7.0 matrix qualification receipt
        uses: {UPLOAD_ARTIFACT_ACTION}
        with:
          name: {MATRIX_RECEIPT_ARTIFACT}
          path: '${{{{ runner.temp }}}}/tfnf-070-matrix/'
          retention-days: 14
          if-no-files-found: error

      - name: Assemble authenticated 0.7.0 Stage-B admission input
        if: steps.runtime_profile.outputs.profile == 'manylinux'
        env:
          PYTHONPATH: src
          PYTHONDONTWRITEBYTECODE: '1'
        run: |
          set -euo pipefail
          CAPTURES="${{{{ runner.temp }}}}/tfnf-070-stage-b-captures"
          mkdir -p "$CAPTURES/linux-arm64-gnu" "$CAPTURES/linux-x64-gnu"
          cp "${{{{ runner.temp }}}}/tfnf-070-receipts/linux-arm64-gnu/newer.json" \\
            "$CAPTURES/linux-arm64-gnu/newer.json"
          cp "${{{{ runner.temp }}}}/tfnf-070-receipts/linux-x64-gnu/newer.json" \\
            "$CAPTURES/linux-x64-gnu/newer.json"
          cp "${{{{ runner.temp }}}}/tfnf-070-floor-receipts/linux-arm64-gnu/floor.json" \\
            "$CAPTURES/linux-arm64-gnu/floor.json"
          cp "${{{{ runner.temp }}}}/tfnf-070-floor-receipts/linux-x64-gnu/floor.json" \\
            "$CAPTURES/linux-x64-gnu/floor.json"
          RS9_TREE="$(git rev-parse --verify 'HEAD^{{tree}}')"
          "${{{{ steps.setup_python.outputs.python-path }}}}" -B -m rs9.nebular070_public_consumers assemble-stage-b \\
            --stage-a "${{{{ runner.temp }}}}/{PUBLIC_INPUTS_ARTIFACT}/{PUBLIC_STAGE_A_OUTPUT}/payload-portability.json" \\
            --approval "{APPROVAL_PATH.as_posix()}" \\
            --matrix "${{{{ runner.temp }}}}/tfnf-070-matrix/{MATRIX_RECEIPT_MEMBER}" \\
            --wheels-dir "${{{{ runner.temp }}}}/tfnf-070-bundle/dist" \\
            --captures-dir "$CAPTURES" \\
            --output "${{{{ runner.temp }}}}/tfnf-070-manylinux-admission" \\
            --tf-producer-commit {PUBLIC_TF_PRODUCER_SOURCE['commit']} \\
            --tf-producer-tree {PUBLIC_TF_PRODUCER_SOURCE['tree']} \\
            --rs9-tool-commit "${{{{ github.sha }}}}" \\
            --rs9-tool-tree "$RS9_TREE" \\
            --rs9-release-commit "${{{{ github.sha }}}}" \\
            --rs9-release-tree "$RS9_TREE"

      - name: Verify system-WebKit matrix has no manylinux admission
        if: steps.runtime_profile.outputs.profile == 'system-webkitgtk-4.1'
        env:
          PYTHONPATH: src
          PYTHONDONTWRITEBYTECODE: '1'
          QUALIFICATION_INPUTS: '${{{{ runner.temp }}}}/{PUBLIC_INPUTS_ARTIFACT}/{PUBLIC_INPUTS_DESCRIPTOR}'
          INRUN_ROOT: '${{{{ runner.temp }}}}/{PUBLIC_INPUTS_ARTIFACT}'
        run: |
          set -euo pipefail
          "${{{{ steps.setup_python.outputs.python-path }}}}" -B - <<'PY'
          import json
          import os
          from pathlib import Path
          from rs9.tf_pypi_nebular070_publish import load_qualification_inputs_descriptor

          descriptor = load_qualification_inputs_descriptor(
              Path(os.environ["QUALIFICATION_INPUTS"]),
              repository=Path(os.environ["GITHUB_WORKSPACE"]),
              phase="qualification-prep",
              inrun_root=Path(os.environ["INRUN_ROOT"]),
          )
          if "system_webkit" not in descriptor or "manylinux" in descriptor:
              raise SystemExit("system profile binding mismatch")
          bundle = Path(os.environ["RUNNER_TEMP"]) / "tfnf-070-bundle"
          if (bundle / "payload_portability.json").exists():
              raise SystemExit("system profile unexpectedly has Stage-A payload")
          candidate = json.loads((bundle / "candidate_receipt.json").read_bytes())
          if "manylinux_stage_a_sha256" in candidate:
              raise SystemExit("system profile unexpectedly has Stage-A receipt")
          PY

      - name: Upload 0.7.0 manylinux admission input
        if: steps.runtime_profile.outputs.profile == 'manylinux'
        uses: {UPLOAD_ARTIFACT_ACTION}
        with:
          name: {MANYLINUX_ADMISSION_ARTIFACT}
          path: '${{{{ runner.temp }}}}/tfnf-070-manylinux-admission/'
          retention-days: 14
          if-no-files-found: error
"""


def publication_resume_job_text() -> str:
    """Render the attended two-checkout 0.7.0 publication-resume job for rs9-tfnf-pypi-publish.yml."""
    return f"""
  publication_resume_070:
    if: github.ref == 'refs/heads/main' && github.event_name == 'workflow_dispatch' && inputs.release == '0.7.0' && inputs.mode == 'resume'
    name: Attended Nebular 0.7.0 PyPI publication resume
    runs-on: ubuntu-24.04
    timeout-minutes: 30
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
      - name: Checkout publisher authority commit
        uses: {CHECKOUT_ACTION}
        with:
          ref: '${{{{ github.sha }}}}'
          path: publisher-authority
          fetch-depth: 0
          persist-credentials: false

      - name: Set up Python 3.13
        id: setup_python
        uses: {SETUP_PYTHON_ACTION}
        with:
          python-version: '3.13'

      - name: Resolve pinned qualification commit from publisher authority
        id: resolve_qual
        env:
          PYTHONPATH: publisher-authority/src
          PYTHONDONTWRITEBYTECODE: '1'
        run: |
          "${{{{ steps.setup_python.outputs.python-path }}}}" -B -c '
          from pathlib import Path
          from rs9.tf_pypi_nebular070_publish import (
              _system_runtime_profile, load_approval, load_pin, load_qualification_capture,
          )
          pub = Path("publisher-authority")
          pin = load_pin(pub)
          app = load_approval(pub)
          cap = load_qualification_capture(pub, pin=pin, approval=app)
          print(f"qualification_commit={{cap[\"qualification_source_commit\"]}}")
          print(f"qualification_run_id={{cap[\"run_id\"]}}")
          profile = "system-webkitgtk-4.1" if _system_runtime_profile(app) else "manylinux"
          print(f"runtime_profile={{profile}}")
          ' >> "$GITHUB_OUTPUT"

      - name: Checkout exact qualified source commit
        uses: {CHECKOUT_ACTION}
        with:
          ref: '${{{{ steps.resolve_qual.outputs.qualification_commit }}}}'
          path: qualification-source
          persist-credentials: false

      - name: Verify publisher and qualification source lineage
        env:
          PYTHONPATH: qualification-source/src
          PYTHONDONTWRITEBYTECODE: '1'
        run: |
          "${{{{ steps.setup_python.outputs.python-path }}}}" -B -m rs9.tf_pypi_nebular070_publish verify-source \\
            --publisher-dir publisher-authority \\
            --qualification-dir qualification-source \\
            --publisher-revision "${{{{ github.sha }}}}"

      - name: Fetch retained qualification run and artifact archives
        env:
          GH_TOKEN: ${{{{ github.token }}}}
          PYTHONPATH: qualification-source/src
          PYTHONDONTWRITEBYTECODE: '1'
        run: |
          set -euo pipefail
          API_DIR="${{{{ runner.temp }}}}/tfnf-070-api"
          ARCHIVES_DIR="${{{{ runner.temp }}}}/tfnf-070-archives"
          EXTERNAL_DIR="${{{{ runner.temp }}}}/tfnf-070-external-archives"
          mkdir -p "$API_DIR" "$ARCHIVES_DIR" "$EXTERNAL_DIR"
          RUN_ID="${{{{ steps.resolve_qual.outputs.qualification_run_id }}}}"
          gh api --header 'X-GitHub-Api-Version: 2022-11-28' \\
            "/repos/${{{{ github.repository }}}}/actions/runs/$RUN_ID" \\
            > "$API_DIR/run.json"
          gh api --header 'X-GitHub-Api-Version: 2022-11-28' \\
            "/repos/${{{{ github.repository }}}}/actions/runs/$RUN_ID/artifacts?per_page=100" \\
            > "$API_DIR/artifacts.json"
          "${{{{ steps.setup_python.outputs.python-path }}}}" -B -c '
          import os, subprocess
          from pathlib import Path
          from rs9.tf_pypi_nebular070_publish import load_qualification_capture
          cap = load_qualification_capture(Path("publisher-authority"))
          repo = cap["repository"]
          archives_dir = Path(os.environ["RUNNER_TEMP"]) / "tfnf-070-archives"
          for name, spec in cap["artifacts"].items():
              art_id = spec["id"]
              with (archives_dir / f"{{name}}.zip").open("xb") as out:
                  subprocess.run(
                      [
                          "gh",
                          "api",
                          "--header",
                          "X-GitHub-Api-Version: 2022-11-28",
                          f"/repos/{{repo}}/actions/artifacts/{{art_id}}/zip",
                      ],
                      check=True,
                      stdout=out,
                  )
          '
          "${{{{ steps.setup_python.outputs.python-path }}}}" -B -c '
          import json, os, subprocess
          from pathlib import Path
          from rs9.tf_pypi_nebular070_publish import (
              PUBLIC_INPUTS_ARTIFACT,
              MANYLINUX_ADMISSION_ARTIFACT,
              load_approval,
              load_qualification_capture,
              validate_public_external_artifact_metadata,
          )
          pub = Path("publisher-authority")
          cap = load_qualification_capture(pub)
          repo = cap["repository"]
          rows = validate_public_external_artifact_metadata(
              Path(os.environ["RUNNER_TEMP"]) / "tfnf-070-api",
              capture=cap,
              approval=load_approval(pub),
          )
          out_dir = Path(os.environ["RUNNER_TEMP"]) / "tfnf-070-external-archives"
          for name, row in rows.items():
              artifact_id = row["id"]
              destination = out_dir / f"{{name}}.zip"
              temporary = out_dir / f".{{name}}.zip.part"
              if destination.exists() or temporary.exists():
                  raise SystemExit("external artifact output already exists")
              with temporary.open("xb") as out:
                  subprocess.run(
                      [
                          "gh",
                          "api",
                          "--header",
                          "X-GitHub-Api-Version: 2022-11-28",
                          f"/repos/{{repo}}/actions/artifacts/{{artifact_id}}/zip",
                      ],
                      check=True,
                      stdout=out,
                  )
              data = temporary.read_bytes()
              if len(data) != row["size_in_bytes"]:
                  temporary.unlink()
                  raise SystemExit("external artifact size mismatch")
              if row["archive_sha256"] is not None:
                  import hashlib
                  if hashlib.sha256(data).hexdigest() != row["archive_sha256"]:
                      temporary.unlink()
                      raise SystemExit("external artifact digest mismatch")
              temporary.replace(destination)
          '

      - name: Extract and bind held public input roots
        env:
          PYTHONPATH: qualification-source/src
          PYTHONDONTWRITEBYTECODE: '1'
        run: |
          set -euo pipefail
          "${{{{ steps.setup_python.outputs.python-path }}}}" -B -c '
          import os
          from pathlib import Path
          from rs9.tf_pypi_nebular070_publish import (
              PUBLIC_INPUTS_ARTIFACT,
              MANYLINUX_ADMISSION_ARTIFACT,
              _system_runtime_profile,
              extract_public_external_artifact,
              load_approval,
          )
          temp = Path(os.environ["RUNNER_TEMP"])
          extract_public_external_artifact(
              temp / "tfnf-070-external-archives" / f"{{PUBLIC_INPUTS_ARTIFACT}}.zip",
              temp / "tfnf-070-public-inputs",
              artifact_name=PUBLIC_INPUTS_ARTIFACT,
          )
          if not _system_runtime_profile(load_approval(Path("publisher-authority"))):
              extract_public_external_artifact(
                  temp / "tfnf-070-external-archives" / f"{{MANYLINUX_ADMISSION_ARTIFACT}}.zip",
                  temp / "tfnf-070-external-manylinux",
                  artifact_name=MANYLINUX_ADMISSION_ARTIFACT,
              )
          '

      - name: Authenticate retained archives and stage verified distribution
        env:
          PYTHONPATH: qualification-source/src
          PYTHONDONTWRITEBYTECODE: '1'
        run: |
          "${{{{ steps.setup_python.outputs.python-path }}}}" -B -m rs9.tf_pypi_nebular070_publish prepare-resume \\
            --publisher-dir publisher-authority \\
            --qualification-dir qualification-source \\
            --qualification-inputs "${{{{ runner.temp }}}}/tfnf-070-public-inputs/{PUBLIC_INPUTS_DESCRIPTOR}" \\
            --inrun-root "${{{{ runner.temp }}}}/tfnf-070-public-inputs" \\
            --api-dir "${{{{ runner.temp }}}}/tfnf-070-api" \\
            --archives-dir "${{{{ runner.temp }}}}/tfnf-070-archives" \\
            --output "${{{{ runner.temp }}}}/tfnf-070-resume"

      - name: Verify external Stage-B and Stage-A bindings
        if: steps.resolve_qual.outputs.runtime_profile == 'manylinux'
        env:
          PYTHONPATH: qualification-source/src
          PYTHONDONTWRITEBYTECODE: '1'
        run: |
          set -euo pipefail
          "${{{{ steps.setup_python.outputs.python-path }}}}" -B -c '
          import hashlib, os
          from pathlib import Path
          temp = Path(os.environ["RUNNER_TEMP"])
          resume = temp / "tfnf-070-resume"
          external = temp / "tfnf-070-external-manylinux"
          names = (
              "manylinux_admission.json",
              "consumers/linux-arm64-gnu/floor.json",
              "consumers/linux-arm64-gnu/newer.json",
              "consumers/linux-x64-gnu/floor.json",
              "consumers/linux-x64-gnu/newer.json",
          )
          from rs9.tf_pypi_nebular070_publish import _resume_stage_b_member_path
          for name in names:
              left = external / name
              right = _resume_stage_b_member_path(resume, name)
              if left.read_bytes() != right.read_bytes():
                  raise SystemExit("external Stage-B binding mismatch")
          stage_a = temp / "tfnf-070-public-inputs" / "{PUBLIC_STAGE_A_OUTPUT}" / "payload-portability.json"
          resumed_stage_a = resume / "payload_portability.json"
          if hashlib.sha256(stage_a.read_bytes()).digest() != hashlib.sha256(resumed_stage_a.read_bytes()).digest():
              raise SystemExit("external Stage-A binding mismatch")
          '

      - name: Resolve captured 0.7.0 manylinux source coordinates
        id: manylinux_source
        if: steps.resolve_qual.outputs.runtime_profile == 'manylinux'
        env:
          PYTHONPATH: qualification-source/src
          PYTHONDONTWRITEBYTECODE: '1'
        run: |
          "${{{{ steps.setup_python.outputs.python-path }}}}" -B -m rs9.tf_pypi_nebular070_publish resolve-manylinux-source \\
            --payload-portability "${{{{ runner.temp }}}}/tfnf-070-resume/{MANYLINUX_STAGE_A_MEMBER}" >> "$GITHUB_OUTPUT"

      - name: Stage admitted 0.7.0 operator metadata into qualification checkout
        env:
          PYTHONPATH: qualification-source/src
          PYTHONDONTWRITEBYTECODE: '1'
        run: |
          "${{{{ steps.setup_python.outputs.python-path }}}}" -B -m rs9.tf_pypi_nebular070_publish stage-metadata \\
            --publisher-dir publisher-authority \\
            --qualification-dir qualification-source

      - name: Verify artifact integrity and select only missing files
        id: missing
        working-directory: qualification-source
        env:
          PYTHONPATH: src
          PYTHONDONTWRITEBYTECODE: '1'
          RS9_GITHUB_READ_TOKEN: ${{{{ github.token }}}}
          RS9_TFNF_PRIOR_UPLOAD_UNCONFIRMED: ${{{{ vars.RS9_TFNF_PRIOR_UPLOAD_UNCONFIRMED }}}}
          GITHUB_RUN_ATTEMPT: ${{{{ github.run_attempt }}}}
        run: |
          set -euo pipefail
          PORTABILITY_ARGS=()
          if [ "${{{{ steps.resolve_qual.outputs.runtime_profile }}}}" = manylinux ]; then
            PORTABILITY_ARGS=(
              --manylinux-admission "${{{{ runner.temp }}}}/tfnf-070-resume/{MANYLINUX_ADMISSION_MEMBER}"
              --manylinux-consumer-receipts "${{{{ runner.temp }}}}/tfnf-070-resume/manylinux-consumers"
              --payload-portability "${{{{ runner.temp }}}}/tfnf-070-resume/{MANYLINUX_STAGE_A_MEMBER}"
              --tf-producer-commit "${{{{ steps.manylinux_source.outputs.tf_producer_commit }}}}"
              --tf-producer-tree "${{{{ steps.manylinux_source.outputs.tf_producer_tree }}}}"
            )
          fi
          "${{{{ steps.setup_python.outputs.python-path }}}}" -B -m rs9.tf_pypi_nebular070_publish select-missing \\
            --dist "${{{{ runner.temp }}}}/tfnf-070-resume/dist" \\
            --upload-dir "${{{{ runner.temp }}}}/tfnf-070-resume/upload" \\
            --candidate-receipt "${{{{ runner.temp }}}}/tfnf-070-resume/candidate_receipt.json" \\
            --expected-artifacts "${{{{ runner.temp }}}}/tfnf-070-resume/expected_artifacts.json" \\
            --receipts-dir "${{{{ runner.temp }}}}/tfnf-070-resume/receipts" \\
            --qualification-inputs "${{{{ runner.temp }}}}/tfnf-070-public-inputs/{PUBLIC_INPUTS_DESCRIPTOR}" \\
            --inrun-root "${{{{ runner.temp }}}}/tfnf-070-public-inputs" \\
            "${{PORTABILITY_ARGS[@]}}" \\
            --attempt-marker "${{{{ runner.temp }}}}/tfnf-070-upload-attempt.json" >> "$GITHUB_OUTPUT"

      - name: Re-verify staged upload artifacts against approval before upload
        if: steps.missing.outputs.upload == 'true'
        working-directory: qualification-source
        env:
          PYTHONPATH: src
          PYTHONDONTWRITEBYTECODE: '1'
        run: |
          set -euo pipefail
          PORTABILITY_ARGS=()
          if [ "${{{{ steps.resolve_qual.outputs.runtime_profile }}}}" = manylinux ]; then
            PORTABILITY_ARGS=(
              --manylinux-admission "${{{{ runner.temp }}}}/tfnf-070-resume/{MANYLINUX_ADMISSION_MEMBER}"
              --manylinux-consumer-receipts "${{{{ runner.temp }}}}/tfnf-070-resume/manylinux-consumers"
              --payload-portability "${{{{ runner.temp }}}}/tfnf-070-resume/{MANYLINUX_STAGE_A_MEMBER}"
              --tf-producer-commit "${{{{ steps.manylinux_source.outputs.tf_producer_commit }}}}"
              --tf-producer-tree "${{{{ steps.manylinux_source.outputs.tf_producer_tree }}}}"
            )
          fi
          "${{{{ steps.setup_python.outputs.python-path }}}}" -B -m rs9.tf_pypi_nebular070_publish verify-upload \\
            --dist "${{{{ runner.temp }}}}/tfnf-070-resume/dist" \\
            --upload-dir "${{{{ runner.temp }}}}/tfnf-070-resume/upload" \\
            --matrix-receipt "${{{{ runner.temp }}}}/tfnf-070-resume/{MATRIX_RECEIPT_MEMBER}" \\
            --qualification-inputs "${{{{ runner.temp }}}}/tfnf-070-public-inputs/{PUBLIC_INPUTS_DESCRIPTOR}" \\
            --inrun-root "${{{{ runner.temp }}}}/tfnf-070-public-inputs" \\
            "${{PORTABILITY_ARGS[@]}}"

      - name: Publish package distribution to PyPI
        if: steps.missing.outputs.upload == 'true'
        uses: {PYPA_PUBLISH_ACTION}
        with:
          packages-dir: '${{{{ runner.temp }}}}/tfnf-070-resume/upload/'
          verify-metadata: true
          print-hash: true
          skip-existing: false
          attestations: false

      - name: Read back published PyPI state
        if: always() && (steps.missing.outputs.upload == 'true' || steps.missing.outputs.state == 'published-exact')
        working-directory: qualification-source
        env:
          PYTHONPATH: src
          PYTHONDONTWRITEBYTECODE: '1'
        run: |
          "${{{{ steps.setup_python.outputs.python-path }}}}" -B -m rs9.tf_pypi_nebular070_publish readback \\
            --dist "${{{{ runner.temp }}}}/tfnf-070-resume/dist"
"""


def workflow_070_jobs_text() -> str:
    """Render both 0.7.0 qualification jobs and 0.7.0 publication-resume job."""
    return workflow_070_qualify_jobs_text() + publication_resume_job_text()


def workflow_text(release: str = "0.7.0", *, mode: str | None = None) -> str:
    """Render the registered combined workflow rs9-tfnf-pypi-publish.yml."""
    if release not in ("0.6.1", "0.7.0"):
        fail("WORKFLOW_RELEASE")
    if mode is not None:
        validate_workflow_dispatch(release, mode)
    from rs9.tf_pypi_nebular import workflow_text as combined_workflow_text

    return combined_workflow_text(release=release)


def _require_candidate_profile_sha(candidate: Any) -> str:
    if not isinstance(candidate, Mapping):
        fail("CANDIDATE_RECEIPT_SCHEMA")
    prof_sha = candidate.get("profile_result_sha256")
    if not _is_hex64(prof_sha):
        fail("CANDIDATE_RECEIPT_SCHEMA")
    return str(prof_sha)


def qualification_inputs_path(repository: str | Path | None = None) -> Path:
    """Return path to the 0.7.0 qualification-inputs descriptor."""
    path = repo_root(repository) / QUALIFICATION_INPUTS_PATH
    _check_no_symlinks(path, "QUALIFICATION_INPUTS_SYMLINK")
    return path


def _public_relative_path(value: Any, code: str) -> str:
    """Validate a private transport-relative path without resolving links."""
    if (
        not isinstance(value, str)
        or not value
        or value.startswith("/")
        or "\\" in value
        or value in (".", "..")
        or ".." in Path(value).parts
        or any(part in ("", ".") for part in value.split("/"))
    ):
        fail(code)
    return value


def _public_stage_a_output_from_descriptor(doc: Mapping[str, Any]) -> str:
    """Return the descriptor-bound Stage-A directory, never a caller-selected path."""
    manylinux = doc.get("manylinux")
    if (
        not isinstance(manylinux, Mapping)
        or manylinux.get("schema") != PUBLIC_INRUN_MANYLINUX_SCHEMA
        or manylinux.get("origin_kind") != PUBLIC_INRUN_MANYLINUX_ORIGIN_KIND
    ):
        fail("PUBLIC_INPUTS_STAGE_A_DESCRIPTOR")
    stage_a = manylinux.get("stage_a")
    if not isinstance(stage_a, Mapping):
        fail("PUBLIC_INPUTS_STAGE_A_DESCRIPTOR")
    stage_a_path = _public_relative_path(stage_a.get("path"), "PUBLIC_INPUTS_STAGE_A_DESCRIPTOR")
    if not stage_a_path.endswith("/payload-portability.json"):
        fail("PUBLIC_INPUTS_STAGE_A_DESCRIPTOR")
    output = stage_a_path.rsplit("/", 1)[0]
    if not output or output == ".":
        fail("PUBLIC_INPUTS_STAGE_A_DESCRIPTOR")
    return _public_relative_path(output, "PUBLIC_INPUTS_STAGE_A_DESCRIPTOR")


def _load_public_stage_a_adapter() -> ModuleType:
    """Load the separately maintained detached-file Stage-A adapter.

    The adapter is deliberately not copied into this publisher candidate.  A
    workflow run must use the independently maintained implementation, and a
    missing adapter is a held, fail-closed input error rather than permission
    to synthesize a payload or receipt here.
    """
    try:
        module = importlib.import_module("rs9.nebular070_public_stagea_files")
        assembler = getattr(module, "assemble_stage_a_files")
        binder = getattr(module, "bind_descriptor_phase")
    except (ImportError, AttributeError):
        fail("PUBLIC_STAGE_A_ADAPTER")
    if not callable(assembler) or not callable(binder):
        fail("PUBLIC_STAGE_A_ADAPTER")
    return module


def _read_public_descriptor_bind_output(
    root: Path,
    descriptor_path: Path,
    stage_path: str,
    result: Mapping[str, Any],
) -> dict[str, Any]:
    """Authenticate the maintained Stage-A descriptor binder result."""
    old_bytes = physical_bytes(root / PUBLIC_INPUTS_TEMPLATE_DESCRIPTOR, limit=4 * 1024 * 1024)
    try:
        old_descriptor = strict_json(old_bytes)
    except (AdmissionError, OSError, ValueError):
        fail("PUBLIC_INPUTS_DESCRIPTOR_BIND")
    evidence = old_descriptor.get("evidence") if isinstance(old_descriptor, Mapping) else None
    if not isinstance(evidence, Mapping):
        fail("PUBLIC_INPUTS_DESCRIPTOR_BIND")
    evidence_root = _public_relative_path(
        evidence.get("source_root"), "PUBLIC_INPUTS_DESCRIPTOR_BIND"
    )
    artifact_stage_path = _public_relative_path(stage_path, "PUBLIC_INPUTS_DESCRIPTOR_BIND")
    if artifact_stage_path == evidence_root:
        fail("PUBLIC_INPUTS_DESCRIPTOR_BIND")
    if artifact_stage_path.startswith(evidence_root + "/"):
        evidence_stage_path = artifact_stage_path[len(evidence_root) + 1:]
    else:
        evidence_stage_path = artifact_stage_path
        artifact_stage_path = f"{evidence_root}/{evidence_stage_path}"
    stage_entry = result.get("stage_file")
    if (
        set(result)
        != {
            "schema",
            "status",
            "phase",
            "role",
            "old_descriptor_sha256",
            "new_descriptor_sha256",
            "stage_file",
        }
        or result.get("schema") != "rs9.nebular070-public-descriptor-bind.v1"
        or result.get("status") != "pass"
        or result.get("phase") != QUALIFICATION_INPUT_PHASE_PREP
        or result.get("role") != "stage_a"
        or not isinstance(stage_entry, Mapping)
        or set(stage_entry) != {"path", "size", "sha256"}
        or stage_entry.get("path") != evidence_stage_path
        or type(stage_entry.get("size")) is not int
        or stage_entry.get("size") < 0
        or not _is_hex64(stage_entry.get("sha256"))
        or not _is_hex64(result.get("old_descriptor_sha256"))
        or not _is_hex64(result.get("new_descriptor_sha256"))
    ):
        fail("PUBLIC_INPUTS_DESCRIPTOR_BIND")
    new_bytes = physical_bytes(descriptor_path, limit=4 * 1024 * 1024)
    stage_bytes = physical_bytes(root / artifact_stage_path, limit=MAX_INPUT_BYTES)
    if (
        sha256(old_bytes) != result["old_descriptor_sha256"]
        or sha256(new_bytes) != result["new_descriptor_sha256"]
        or stage_entry["size"] != len(stage_bytes)
        or stage_entry["sha256"] != sha256(stage_bytes)
    ):
        fail("PUBLIC_INPUTS_DESCRIPTOR_BIND")
    return {
        "schema": result["schema"],
        "phase": result["phase"],
        "role": result["role"],
        "descriptor": {
            "path": PUBLIC_INPUTS_DESCRIPTOR,
            "bytes": len(new_bytes),
            "sha256": sha256(new_bytes),
        },
        "stage_file": dict(stage_entry),
        "stage_artifact_path": artifact_stage_path,
    }


def _read_public_stage_a_output(
    root: Path,
    output_rel: str,
    result: Mapping[str, Any],
) -> dict[str, Any]:
    """Authenticate the adapter's bounded output using the returned bytes."""
    if (
        set(result) != {"schema", "status", "output", "payload_sha256", "receipt_sha256"}
        or result.get("status") != "pass"
        or not isinstance(result.get("schema"), str)
        or result.get("output") != output_rel
        or not _is_hex64(result.get("payload_sha256"))
        or not _is_hex64(result.get("receipt_sha256"))
    ):
        fail("PUBLIC_INPUTS_STAGE_A_RESULT")
    output_dir = root / output_rel
    payload_path = output_dir / "payload-portability.json"
    receipt_path = output_dir / "stage-a-receipt.json"
    _check_no_symlinks(output_dir, "PUBLIC_INPUTS_STAGE_A_OUTPUT")
    _check_no_symlinks(payload_path, "PUBLIC_INPUTS_STAGE_A_OUTPUT")
    _check_no_symlinks(receipt_path, "PUBLIC_INPUTS_STAGE_A_OUTPUT")
    payload = physical_bytes(payload_path, limit=MAX_INPUT_BYTES)
    receipt = physical_bytes(receipt_path, limit=4 * 1024 * 1024)
    if sha256(payload) != result["payload_sha256"] or sha256(receipt) != result["receipt_sha256"]:
        fail("PUBLIC_INPUTS_STAGE_A_RESULT")
    return {
        "schema": result["schema"],
        "output": output_rel,
        "payload": {
            "path": f"{output_rel}/payload-portability.json",
            "bytes": len(payload),
            "sha256": sha256(payload),
        },
        "receipt": {
            "path": f"{output_rel}/stage-a-receipt.json",
            "bytes": len(receipt),
            "sha256": sha256(receipt),
        },
    }


PUBLIC_INPUTS_ARTIFACT_MAX_BYTES = 1024 * 1024 * 1024 + 64 * 1024 * 1024
PUBLIC_EXTERNAL_ARTIFACT_NAMES = frozenset({
    PUBLIC_INPUTS_ARTIFACT,
    MANYLINUX_ADMISSION_ARTIFACT,
})


def validate_public_external_artifact_metadata(
    api_dir: str | Path,
    *,
    capture: Mapping[str, Any],
    names: Sequence[str] | None = None,
    approval: Mapping[str, Any] | None = None,
) -> dict[str, dict[str, Any]]:
    """Validate same-run GitHub artifact metadata for the external input roots.

    The public-input artifact is intentionally not part of the historical
    qualification capture schema.  It is therefore bound to the captured run
    using the run/head/repository fields and the server's immutable artifact
    identity, while the already-captured Stage-B artifact is additionally
    compared with its historical artifact row.
    """
    if not isinstance(capture, Mapping):
        fail("PUBLIC_EXTERNAL_ARTIFACTS")
    expected_names = (
        frozenset({PUBLIC_INPUTS_ARTIFACT})
        if approval is not None and _system_runtime_profile(approval)
        else PUBLIC_EXTERNAL_ARTIFACT_NAMES
    )
    requested = tuple(sorted(expected_names)) if names is None else tuple(names)
    if (not requested or len(requested) != len(expected_names)
            or set(requested) != expected_names):
        fail("PUBLIC_EXTERNAL_ARTIFACTS")
    a_dir = _require_real_directory(api_dir, "PUBLIC_EXTERNAL_ARTIFACTS")
    artifacts_path = a_dir / "artifacts.json"
    _check_no_symlinks(artifacts_path, "PUBLIC_EXTERNAL_ARTIFACTS")
    if not artifacts_path.is_file():
        fail("PUBLIC_EXTERNAL_ARTIFACTS")
    doc = strict_json(physical_bytes(artifacts_path, limit=4 * 1024 * 1024))
    rows = doc.get("artifacts") if isinstance(doc, Mapping) else None
    if not isinstance(rows, list):
        fail("PUBLIC_EXTERNAL_ARTIFACTS")
    by_name: dict[str, Mapping[str, Any]] = {}
    for row in rows:
        if not isinstance(row, Mapping):
            fail("PUBLIC_EXTERNAL_ARTIFACTS")
        name = row.get("name")
        if name in requested:
            if name in by_name:
                fail("PUBLIC_EXTERNAL_ARTIFACTS")
            by_name[str(name)] = row
    if set(by_name) != set(requested):
        fail("PUBLIC_EXTERNAL_ARTIFACTS")

    repository = capture.get("repository")
    run_id = capture.get("run_id")
    head_sha = capture.get("qualification_source_commit")
    head_branch = capture.get("head_branch")
    if (
        not isinstance(repository, str)
        or type(run_id) is not int
        or run_id <= 0
        or not _is_hex40(head_sha)
        or head_branch not in {"main", QUALIFY_BRANCH}
    ):
        fail("PUBLIC_EXTERNAL_ARTIFACTS")
    result: dict[str, dict[str, Any]] = {}
    historical = capture.get("artifacts")
    for name in requested:
        row = by_name[name]
        art_id = row.get("id")
        size = row.get("size_in_bytes")
        url = row.get("archive_download_url")
        workflow_run = row.get("workflow_run")
        digest_value = row.get("digest")
        digest_hex = (
            digest_value[7:]
            if isinstance(digest_value, str) and digest_value.startswith("sha256:")
            else None
        )
        if (
            type(art_id) is not int
            or art_id <= 0
            or type(size) is not int
            or not 0 < size <= PUBLIC_INPUTS_ARTIFACT_MAX_BYTES
            or row.get("expired") is not False
            or url != f"https://api.github.com/repos/{repository}/actions/artifacts/{art_id}/zip"
            or not isinstance(workflow_run, Mapping)
            or workflow_run.get("id") != run_id
            or workflow_run.get("head_sha") != head_sha
            or workflow_run.get("head_branch") != head_branch
            or (
                digest_value is not None
                and (
                    not isinstance(digest_value, str)
                    or not digest_value.startswith("sha256:")
                    or not _is_hex64(digest_hex)
                )
            )
        ):
            fail("PUBLIC_EXTERNAL_ARTIFACTS")
        expected = historical.get(name) if isinstance(historical, Mapping) else None
        archive_sha256 = digest_hex
        if name == MANYLINUX_ADMISSION_ARTIFACT:
            if (
                not isinstance(expected, Mapping)
                or expected.get("id") != art_id
                or expected.get("size_in_bytes") != size
                or expected.get("archive_download_url") != url
                or (
                    digest_hex is not None
                    and expected.get("archive_sha256") != digest_hex
                )
            ):
                fail("PUBLIC_EXTERNAL_ARTIFACTS")
            archive_sha256 = expected.get("archive_sha256")
            if not _is_hex64(archive_sha256):
                fail("PUBLIC_EXTERNAL_ARTIFACTS")
        result[name] = {
            "id": art_id,
            "size_in_bytes": size,
            "archive_download_url": url,
            "archive_sha256": archive_sha256,
        }
    return result


def extract_public_external_artifact(
    archive: str | Path,
    output: str | Path,
    *,
    artifact_name: str,
) -> dict[str, Any]:
    """Extract one held workflow artifact with a closed, no-follow ZIP boundary."""
    if artifact_name not in PUBLIC_EXTERNAL_ARTIFACT_NAMES:
        fail("PUBLIC_EXTERNAL_ARTIFACT")
    archive_path = Path(archive)
    _check_no_symlinks(archive_path, "PUBLIC_EXTERNAL_ARTIFACT")
    if not archive_path.is_file():
        fail("PUBLIC_EXTERNAL_ARTIFACT")
    output_path = Path(output)
    if not output_path.is_absolute():
        fail("PUBLIC_EXTERNAL_ARTIFACT")
    _check_no_symlinks(output_path, "PUBLIC_EXTERNAL_ARTIFACT")
    if output_path.exists() and (not output_path.is_dir() or any(output_path.iterdir())):
        fail("PUBLIC_EXTERNAL_ARTIFACT")
    output_path.mkdir(parents=True, exist_ok=True)

    try:
        with zipfile.ZipFile(archive_path, "r") as zf:
            infos = zf.infolist()
            if not infos or len(infos) > 1024:
                fail("PUBLIC_EXTERNAL_ARTIFACT")
            seen: set[str] = set()
            files: list[zipfile.ZipInfo] = []
            total = 0
            for info in infos:
                name = info.filename
                if (
                    not name
                    or name.startswith("/")
                    or "\\" in name
                    or any(part in ("", ".", "..") for part in name.rstrip("/").split("/"))
                    or name in seen
                ):
                    fail("PUBLIC_EXTERNAL_ARTIFACT")
                seen.add(name)
                file_type = (info.external_attr >> 16) & 0o170000
                if file_type == stat.S_IFLNK:
                    fail("PUBLIC_EXTERNAL_ARTIFACT")
                if info.is_dir():
                    if info.file_size != 0:
                        fail("PUBLIC_EXTERNAL_ARTIFACT")
                    continue
                if file_type not in (0, stat.S_IFREG):
                    fail("PUBLIC_EXTERNAL_ARTIFACT")
                if info.file_size <= 0 or info.file_size > MAX_WHEEL_FILE_BYTES:
                    fail("PUBLIC_EXTERNAL_ARTIFACT")
                total += info.file_size
                if total > PUBLIC_INPUTS_ARTIFACT_MAX_BYTES:
                    fail("PUBLIC_EXTERNAL_ARTIFACT")
                files.append(info)
            file_names = {info.filename for info in files}
            if artifact_name == MANYLINUX_ADMISSION_ARTIFACT:
                if file_names != MANYLINUX_ADMISSION_MEMBERS:
                    fail("PUBLIC_EXTERNAL_ARTIFACT")
            else:
                required = {
                    PUBLIC_INPUTS_TEMPLATE_DESCRIPTOR,
                    PUBLIC_INPUTS_DESCRIPTOR,
                    "fetch-receipt.json",
                    PUBLIC_INPUTS_PREPARATION_RECEIPT,
                    f"{PUBLIC_STAGE_A_OUTPUT}/payload-portability.json",
                    f"{PUBLIC_STAGE_A_OUTPUT}/stage-a-receipt.json",
                }
                if not required.issubset(file_names):
                    fail("PUBLIC_EXTERNAL_ARTIFACT")
            for info in files:
                dest = output_path / info.filename
                _check_no_symlinks(dest.parent, "PUBLIC_EXTERNAL_ARTIFACT")
                dest.parent.mkdir(parents=True, exist_ok=True)
                _check_no_symlinks(dest, "PUBLIC_EXTERNAL_ARTIFACT")
                with zf.open(info, "r") as source, dest.open("xb") as target:
                    remaining = info.file_size
                    while remaining:
                        chunk = source.read(min(1024 * 1024, remaining))
                        if not chunk:
                            fail("PUBLIC_EXTERNAL_ARTIFACT")
                        target.write(chunk)
                        remaining -= len(chunk)
                    if source.read(1):
                        fail("PUBLIC_EXTERNAL_ARTIFACT")
    except ContractError:
        raise
    except (OSError, zipfile.BadZipFile, RuntimeError, ValueError):
        fail("PUBLIC_EXTERNAL_ARTIFACT")
    return {
        "artifact": artifact_name,
        "archive_sha256": sha256(physical_bytes(archive_path, limit=PUBLIC_INPUTS_ARTIFACT_MAX_BYTES)),
        "members": sorted(file_names),
    }


def _prepare_system_webkit_public_descriptor(
    *,
    root: Path,
    output_path: Path,
    manifest_path: Path,
    transport: Mapping[str, Any],
    descriptor: Mapping[str, Any],
    template_bytes: bytes,
    rs9_source: Mapping[str, str],
) -> dict[str, Any]:
    """Hold system-runtime inputs without inventing a manylinux Stage A."""
    _validate_system_webkit_input_spec(descriptor.get("system_webkit"))
    if "manylinux" in descriptor:
        fail("QUALIFICATION_INPUTS_RUNTIME_PROFILE")
    if (_git_output(root, ["rev-parse", "HEAD^{commit}"], "PUBLIC_INPUTS_SOURCE") != rs9_source["commit"]
            or _git_output(root, ["rev-parse", "HEAD^{tree}"], "PUBLIC_INPUTS_SOURCE") != rs9_source["tree"]
            or _git_output(root, ["status", "--porcelain", "--untracked-files=all"], "PUBLIC_INPUTS_SOURCE")):
        fail("PUBLIC_INPUTS_SOURCE")
    validated = validate_qualification_inputs_descriptor(
        descriptor, repository=root, phase=QUALIFICATION_INPUT_PHASE_PREP,
        inrun_root=output_path,
    )
    if canonical(validated) != canonical(descriptor):
        fail("PUBLIC_INPUTS_DESCRIPTOR_BIND")
    transport_descriptor = transport.get("descriptor")
    transport_metadata = transport.get("metadata")
    if (not isinstance(transport_descriptor, Mapping)
            or transport_descriptor.get("path") != PUBLIC_INPUTS_TEMPLATE_DESCRIPTOR
            or not isinstance(transport_metadata, Mapping)
            or sha256(template_bytes) != transport_metadata.get("descriptor_sha256")):
        fail("PUBLIC_INPUTS_DESCRIPTOR_BIND")
    prepared_path = output_path / PUBLIC_INPUTS_DESCRIPTOR
    _check_no_symlinks(prepared_path, "PUBLIC_INPUTS_OUTPUT")
    fd = os.open(prepared_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(template_bytes)
        stream.flush()
        os.fsync(stream.fileno())
    prep = {
        "schema": SYSTEM_PUBLIC_INPUTS_PREPARATION_SCHEMA,
        "status": "held",
        "runtime_profile": SYSTEM_WEBKIT_RUNTIME_PROFILE,
        "manifest": {"path": manifest_path.as_posix(),
                     "sha256": transport["manifest_sha256"], "release_id": transport["release_id"]},
        "transport": {"schema": transport["schema"], "receipt_sha256": sha256(canonical(transport)),
                      "descriptor": transport["descriptor"], "metadata": transport["metadata"],
                      "payloads": transport["payloads"]},
        "descriptor": {"path": PUBLIC_INPUTS_DESCRIPTOR, "bytes": len(template_bytes),
                       "sha256": sha256(template_bytes)},
        "template_descriptor": {"path": PUBLIC_INPUTS_TEMPLATE_DESCRIPTOR,
                                "bytes": len(template_bytes), "sha256": sha256(template_bytes)},
        "source": {"rs9": dict(rs9_source)},
    }
    prep_path = output_path / PUBLIC_INPUTS_PREPARATION_RECEIPT
    _check_no_symlinks(prep_path, "PUBLIC_INPUTS_OUTPUT")
    fd = os.open(prep_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(canonical(prep))
        stream.flush()
        os.fsync(stream.fileno())
    return prep


def prepare_public_inputs_070(
    manifest: str | Path,
    output: str | Path,
    *,
    repository: str | Path | None = None,
    stage_a_spec: str = PUBLIC_STAGE_A_SPEC,
    rs9_source: Mapping[str, str],
    tf_producer_source: Mapping[str, str] = PUBLIC_TF_PRODUCER_SOURCE,
) -> dict[str, Any]:
    """Prepare the held public input root and detached Stage-A payload.

    The generic transport owns release-asset download/authentication.  The
    maintained Stage-A adapter owns source/runtime/body joins.  This caller
    only binds those two already-authenticated stages to the current checkout
    and validates the descriptor after Stage-A exists; it never manufactures
    qualification facts.
    """
    root = repo_root(repository)
    manifest_path = Path(manifest)
    # The tracked manifest is repository-relative.  Keeping this boundary
    # relative prevents a private runner path from entering the held receipt
    # or accidentally selecting an untracked host file.
    if manifest_path.is_absolute():
        fail("PUBLIC_INPUTS_MANIFEST")
    if not isinstance(rs9_source, Mapping) or set(rs9_source) != {"commit", "tree"}:
        fail("PUBLIC_INPUTS_SOURCE")
    if not _is_hex40(rs9_source.get("commit")) or not _is_hex40(rs9_source.get("tree")):
        fail("PUBLIC_INPUTS_SOURCE")
    if not isinstance(tf_producer_source, Mapping) or set(tf_producer_source) != {"commit", "tree"}:
        fail("PUBLIC_INPUTS_SOURCE")
    if not _is_hex40(tf_producer_source.get("commit")) or not _is_hex40(tf_producer_source.get("tree")):
        fail("PUBLIC_INPUTS_SOURCE")
    spec_rel = _public_relative_path(stage_a_spec, "PUBLIC_INPUTS_STAGE_A_SPEC")
    output_path = Path(output)
    if not output_path.is_absolute():
        fail("PUBLIC_INPUTS_OUTPUT")
    _check_no_symlinks(output_path, "PUBLIC_INPUTS_OUTPUT")
    if output_path.exists():
        fail("PUBLIC_INPUTS_OUTPUT")

    try:
        from rs9.nebular070_public_inputs import materialize_public_inputs

        transport = materialize_public_inputs(
            manifest_path, output_path, repository_root=root
        )
        template_descriptor_path = output_path / PUBLIC_INPUTS_TEMPLATE_DESCRIPTOR
        template_descriptor_bytes = physical_bytes(
            template_descriptor_path, limit=4 * 1024 * 1024
        )
        descriptor = strict_json(template_descriptor_bytes)
        if not isinstance(descriptor, Mapping):
            fail("PUBLIC_INPUTS_DESCRIPTOR")
        if "system_webkit" in descriptor:
            return _prepare_system_webkit_public_descriptor(
                root=root, output_path=output_path, manifest_path=manifest_path,
                transport=transport, descriptor=descriptor,
                template_bytes=template_descriptor_bytes, rs9_source=rs9_source,
            )
        evidence = descriptor.get("evidence")
        if not isinstance(evidence, Mapping) or not isinstance(evidence.get("source_root"), str):
            fail("PUBLIC_INPUTS_STAGE_A_DESCRIPTOR")
        evidence_root = _public_relative_path(
            evidence["source_root"], "PUBLIC_INPUTS_STAGE_A_DESCRIPTOR"
        )
        output_rel = f"{evidence_root}/generated-stage-a"
        if output_rel != PUBLIC_STAGE_A_OUTPUT:
            fail("PUBLIC_INPUTS_STAGE_A_DESCRIPTOR")
        spec_path = output_path / spec_rel
        _check_no_symlinks(spec_path, "PUBLIC_INPUTS_STAGE_A_SPEC")
        if not spec_path.is_file():
            fail("PUBLIC_INPUTS_STAGE_A_SPEC")

        adapter = _load_public_stage_a_adapter()
        assembler = adapter.assemble_stage_a_files
        binder = adapter.bind_descriptor_phase
        stage_result = assembler(
            repository=root,
            input_root=output_path,
            spec=spec_rel,
            output=output_rel,
            expected_rs9_commit=str(rs9_source["commit"]),
            expected_rs9_tree=str(rs9_source["tree"]),
            expected_tf_producer_commit=str(tf_producer_source["commit"]),
            expected_tf_producer_tree=str(tf_producer_source["tree"]),
        )
        if not isinstance(stage_result, Mapping):
            fail("PUBLIC_INPUTS_STAGE_A_RESULT")
        stage = _read_public_stage_a_output(output_path, output_rel, stage_result)

        # The transport descriptor is an immutable template.  The maintained
        # binder creates a fresh, phase-specific descriptor after the detached
        # Stage-A bytes exist; callers must never relabel the template itself.
        prepared_descriptor_path = output_path / PUBLIC_INPUTS_DESCRIPTOR
        bind_result = binder(
            descriptor_path=template_descriptor_path,
            stage_file=stage["payload"]["path"],
            output_path=prepared_descriptor_path,
            repository=root,
            inrun_root=output_path,
            phase=QUALIFICATION_INPUT_PHASE_PREP,
        )
        if not isinstance(bind_result, Mapping):
            fail("PUBLIC_INPUTS_DESCRIPTOR_BIND")
        binding = _read_public_descriptor_bind_output(
            output_path,
            prepared_descriptor_path,
            stage["payload"]["path"],
            bind_result,
        )
        prepared_descriptor_bytes = physical_bytes(
            prepared_descriptor_path, limit=4 * 1024 * 1024
        )

        # The descriptor is validated only after the adapter has created the
        # descriptor-declared Stage-A member.  External roots are accepted by
        # the maintained public-in-run route; bootstrap/expectations remain
        # checkout-owned and unchanged.
        validated = load_qualification_inputs_descriptor(
            prepared_descriptor_path,
            repository=root,
            pending_code="PUBLIC_INPUTS_DESCRIPTOR_PENDING",
            phase=QUALIFICATION_INPUT_PHASE_PREP,
            inrun_root=output_path,
        )
        manylinux = validated.get("manylinux")
        if not isinstance(manylinux, Mapping):
            fail("PUBLIC_INPUTS_STAGE_A_DESCRIPTOR")
        stage_a_binding = manylinux.get("stage_a")
        if (
            not isinstance(stage_a_binding, Mapping)
            or stage_a_binding.get("path") != binding["stage_file"]["path"]
            or binding.get("stage_artifact_path") != stage["payload"]["path"]
        ):
            fail("PUBLIC_INPUTS_STAGE_A_DESCRIPTOR")
        receipt_bytes = canonical(transport)
        prep = {
            "schema": PUBLIC_INPUTS_PREPARATION_SCHEMA,
            "status": "held",
            "manifest": {
                "path": manifest_path.as_posix(),
                "sha256": transport["manifest_sha256"],
                "release_id": transport["release_id"],
            },
            "transport": {
                "schema": transport["schema"],
                "receipt_sha256": sha256(receipt_bytes),
                "descriptor": transport["descriptor"],
                "metadata": transport["metadata"],
                "payloads": transport["payloads"],
            },
            "descriptor": {
                "path": PUBLIC_INPUTS_DESCRIPTOR,
                "bytes": len(prepared_descriptor_bytes),
                "sha256": sha256(prepared_descriptor_bytes),
            },
            "template_descriptor": {
                "path": PUBLIC_INPUTS_TEMPLATE_DESCRIPTOR,
                "bytes": len(template_descriptor_bytes),
                "sha256": sha256(template_descriptor_bytes),
            },
            "stage_a": stage,
            "binding": binding,
            "source": {
                "rs9": dict(rs9_source),
                "tf_producer": dict(tf_producer_source),
            },
        }
        prep_path = output_path / PUBLIC_INPUTS_PREPARATION_RECEIPT
        _check_no_symlinks(prep_path, "PUBLIC_INPUTS_OUTPUT")
        with prep_path.open("xb") as stream:
            stream.write(canonical(prep))
        return prep
    except Exception:
        # The transport owns its own partial-output cleanup.  Once Stage-A has
        # started, this caller must not recursively delete a root it did not
        # create; the run remains diagnosable and the workflow is held.
        raise


def _validate_file_digest_entry(
    entry: Any,
    *,
    code: str,
) -> dict[str, Any]:
    if not isinstance(entry, Mapping):
        fail(code)
    rel_path = entry.get("path")
    name = entry.get("name")
    size = entry.get("size")
    digest_hex = entry.get("sha256")
    if (
        not isinstance(rel_path, str)
        or not rel_path
        or rel_path.startswith("/")
        or "\\" in rel_path
        or ".." in Path(rel_path).parts
    ):
        fail(code)
    if (
        name is not None
        and (
            not isinstance(name, str)
            or not name
            or "/" in name
            or "\\" in name
            or name in (".", "..")
            or name != Path(rel_path).name
        )
    ):
        fail(code)
    if type(size) is not int or size <= 0 or not _is_hex64(digest_hex):
        fail(code)
    return dict(entry)


def _validate_repo_relative_dir_spec(raw_rel: Any, *, code: str) -> str:
    if (
        not isinstance(raw_rel, str)
        or not raw_rel.strip()
        or raw_rel.startswith("/")
        or "\\" in raw_rel
    ):
        fail(code)
    parts = Path(raw_rel).parts
    if not parts or any(part in ("", ".", "..") for part in parts):
        fail(code)
    return raw_rel


def _validate_system_webkit_input_spec(value: Any) -> dict[str, str]:
    """Select the explicit host-WebKit profile without implying qualification."""
    if (not isinstance(value, Mapping) or set(value) != SYSTEM_WEBKIT_INPUT_KEYS
            or value.get("schema") != SYSTEM_WEBKIT_INPUT_SCHEMA
            or value.get("origin_kind") != PUBLIC_INRUN_MANYLINUX_ORIGIN_KIND
            or value.get("profile_id") != SYSTEM_WEBKIT_PROFILE_ID):
        fail("SYSTEM_WEBKIT_INPUT")
    return dict(value)


def _validate_qualification_input_phase(phase: str) -> str:
    """Validate the explicit phase of the v1 public-in-run descriptor route."""
    if not isinstance(phase, str) or phase not in QUALIFICATION_INPUT_PHASES:
        fail("QUALIFICATION_INPUTS_PHASE")
    return phase


def _resolve_repo_contained_dir(
    root: Path,
    rel_dir: str,
    *,
    symlink_code: str,
    missing_code: str,
    containment_code: str,
) -> Path:
    _validate_repo_relative_dir_spec(rel_dir, code=containment_code)
    cand = root / rel_dir
    _check_no_symlinks(cand, symlink_code)
    try:
        resolved = cand.resolve()
        resolved.relative_to(root)
    except (OSError, ValueError):
        fail(containment_code)
    if not cand.is_dir():
        fail(missing_code)
    return resolved


def _resolve_inrun_artifact_root(
    repository_root: Path,
    manylinux_spec: Mapping[str, Any] | None,
    inrun_root: str | Path | None,
    *,
    system_webkit_spec: Mapping[str, Any] | None = None,
) -> Path:
    """Resolve the optional external public-in-run evidence root.

    Bootstrap and expectation files stay repository-owned.  Only the
    versioned public-in-run runtime descriptor may select an external
    evidence root; legacy descriptors must not gain a root override.  The
    root is deliberately not serialized into the descriptor, so private
    runner paths cannot become release metadata.
    """
    if inrun_root is None:
        return repository_root
    manylinux_inrun = (
        isinstance(manylinux_spec, Mapping)
        and manylinux_spec.get("schema") == PUBLIC_INRUN_MANYLINUX_SCHEMA
        and manylinux_spec.get("origin_kind") == PUBLIC_INRUN_MANYLINUX_ORIGIN_KIND
    )
    if system_webkit_spec is not None:
        _validate_system_webkit_input_spec(system_webkit_spec)
    if (manylinux_spec is not None and system_webkit_spec is not None
            or not (manylinux_inrun or system_webkit_spec is not None)):
        fail("QUALIFICATION_INPUTS_ROOT")
    if not isinstance(inrun_root, (str, os.PathLike)):
        fail("QUALIFICATION_INPUTS_ROOT")
    candidate = Path(inrun_root)
    if not candidate.is_absolute():
        fail("QUALIFICATION_INPUTS_ROOT")
    _check_no_symlinks(candidate, "QUALIFICATION_INPUTS_ROOT")
    if not candidate.exists() or not candidate.is_dir():
        fail("QUALIFICATION_INPUTS_ROOT")
    try:
        candidate_stat = candidate.stat()
        candidate_real = candidate.resolve(strict=True)
        repository_real = repository_root.resolve(strict=True)
    except (OSError, RuntimeError):
        fail("QUALIFICATION_INPUTS_ROOT")
    if not stat.S_ISDIR(candidate_stat.st_mode):
        fail("QUALIFICATION_INPUTS_ROOT")
    if candidate_stat.st_uid != os.getuid() or candidate_stat.st_mode & 0o022:
        fail("QUALIFICATION_INPUTS_ROOT")
    try:
        candidate_real.relative_to(repository_real)
    except ValueError:
        try:
            repository_real.relative_to(candidate_real)
        except ValueError:
            return candidate_real
        fail("QUALIFICATION_INPUTS_ROOT")
    fail("QUALIFICATION_INPUTS_ROOT")
    raise AssertionError("unreachable")


def _validate_system_native_raw_input(
    value: Any,
    raw_target: Mapping[str, Any],
    *,
    target: str,
    descriptor: bool = False,
    evidence_files: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Authenticate static inputs without consuming a previous native result."""
    from rs9.nebular070_installed_smoke import validate_system_webkit_native_input

    checked = validate_system_webkit_native_input(
        value, target=target, descriptor=descriptor, evidence_files=evidence_files,
    )
    payload = raw_target["payload"]
    manifest = raw_target["manifest"]
    if (
        checked["archive"]["payload"] != {
            "name": Path(payload["path"]).name,
            "size": payload["size"], "sha256": payload["sha256"],
        }
        or checked["archive"]["manifest"] != {
            key: manifest[key] for key in ("path", "size", "sha256")
        }
    ):
        fail("RAW_RELEASE_HANDOFF_BINDING")
    return checked


def _validate_descriptor_target_raw_release(
    target: str,
    t_entry: Any,
    *,
    evidence_files: Mapping[str, Any] | None = None,
    system_webkit: bool = False,
) -> None:
    if (
        not isinstance(t_entry, Mapping)
        or not REQUIRED_DESCRIPTOR_TARGET_RAW_RELEASE_KEYS.issubset(t_entry.keys())
        or not set(t_entry.keys()).issubset(
            REQUIRED_DESCRIPTOR_TARGET_RAW_RELEASE_KEYS
            | OPTIONAL_DESCRIPTOR_TARGET_RAW_RELEASE_KEYS
        )
    ):
        fail("QUALIFICATION_INPUTS_RAW_RELEASE")
    if "schema" in t_entry and t_entry["schema"] != RAW_RELEASE_HANDOFF_SCHEMA:
        fail("QUALIFICATION_INPUTS_RAW_RELEASE")
    if "target" in t_entry and t_entry["target"] != target:
        fail("RAW_RELEASE_HANDOFF_BINDING")
    for req_k in ("record", "readme", "provenance", "payload", "manifest"):
        _validate_file_digest_entry(
            t_entry.get(req_k), code="QUALIFICATION_INPUTS_RAW_RELEASE"
        )
    legal_map = t_entry.get("legal_files")
    if not isinstance(legal_map, Mapping) or set(legal_map.keys()) != {
        "LICENSE",
        "NOTICE",
        "COMMERCIAL-LICENSE.md",
    }:
        fail("QUALIFICATION_INPUTS_RAW_RELEASE")
    for leg_entry in legal_map.values():
        _validate_file_digest_entry(leg_entry, code="QUALIFICATION_INPUTS_RAW_RELEASE")
    nc_map = t_entry.get("native_consumer")
    if not isinstance(nc_map, Mapping) or target not in nc_map:
        fail("QUALIFICATION_INPUTS_RAW_RELEASE")
    nc_target = nc_map.get(target)
    if not isinstance(nc_target, Mapping):
        fail("QUALIFICATION_INPUTS_RAW_RELEASE")
    if system_webkit and target.startswith("linux"):
        if set(nc_map) != {target}:
            fail("QUALIFICATION_INPUTS_RAW_RELEASE")
        _validate_system_native_raw_input(
            nc_target, t_entry, target=target, descriptor=True,
            evidence_files=evidence_files,
        )
        return
    if "smoke_support" in nc_target:
        from rs9.nebular070_smoke_support import validate_smoke_support
        try:
            validate_smoke_support(
                nc_target["smoke_support"], target,
                evidence_files=evidence_files, descriptor=evidence_files is not None,
            )
        except AdmissionError:
            fail("QUALIFICATION_INPUTS_RAW_RELEASE")
    _validate_file_digest_entry(
        nc_target.get("qualification"), code="QUALIFICATION_INPUTS_RAW_RELEASE"
    )
    smoke_map = nc_target.get("smoke")
    if not isinstance(smoke_map, Mapping) or set(smoke_map.keys()) != {
        "raw-archive",
        "npm-package",
    }:
        fail("QUALIFICATION_INPUTS_RAW_RELEASE")
    for channel in ("raw-archive", "npm-package"):
        ch_spec = smoke_map.get(channel)
        if not isinstance(ch_spec, Mapping):
            fail("QUALIFICATION_INPUTS_RAW_RELEASE")
        _validate_file_digest_entry(
            ch_spec.get("run"), code="QUALIFICATION_INPUTS_RAW_RELEASE"
        )
        _validate_file_digest_entry(
            ch_spec.get("receipt"), code="QUALIFICATION_INPUTS_RAW_RELEASE"
        )


def _validate_manylinux_input_spec(
    value: Any,
    *,
    evidence_files: Mapping[str, Any],
    phase: str = QUALIFICATION_INPUT_PHASE_PUBLICATION,
) -> dict[str, Any]:
    """Validate the legacy v1 or explicit public-in-run manylinux route.

    Legacy qualification-inputs v1 remains a closed precomputed Stage-A plus
    Stage-B descriptor and is intentionally phase-insensitive.  The
    phase-aware preparation/publication split is opt-in only through the
    versioned nested ``manylinux.schema`` and ``origin_kind`` fields.
    """
    phase = _validate_qualification_input_phase(phase)
    if not isinstance(value, Mapping):
        fail("QUALIFICATION_INPUTS_MANYLINUX")
    keys = set(value.keys())
    public_inrun = (
        value.get("schema") == PUBLIC_INRUN_MANYLINUX_SCHEMA
        and value.get("origin_kind") == PUBLIC_INRUN_MANYLINUX_ORIGIN_KIND
    )
    if public_inrun:
        required_keys = {"schema", "origin_kind", "stage_a", "tf_producer_source"}
        if not required_keys.issubset(keys) or not keys.issubset(
            PUBLIC_INRUN_MANYLINUX_INPUT_SPEC_KEYS
        ):
            fail("QUALIFICATION_INPUTS_MANYLINUX")
        if phase == QUALIFICATION_INPUT_PHASE_PREP and "stage_b" in keys:
            fail("QUALIFICATION_INPUTS_STAGE_B_EARLY")
        if (
            phase == QUALIFICATION_INPUT_PHASE_PUBLICATION
            and keys != set(PUBLIC_INRUN_MANYLINUX_INPUT_SPEC_KEYS)
        ):
            fail("QUALIFICATION_INPUTS_MANYLINUX")
    elif keys != set(MANYLINUX_INPUT_SPEC_KEYS):
        # A caller-supplied phase must never reinterpret an unversioned v1
        # descriptor as a new preparation/publication route.
        fail("QUALIFICATION_INPUTS_MANYLINUX")
    source = value.get("tf_producer_source")
    if (
        not isinstance(source, Mapping)
        or set(source.keys()) != {"commit", "tree"}
        or not _is_hex40(source.get("commit"))
        or not _is_hex40(source.get("tree"))
    ):
        fail("QUALIFICATION_INPUTS_MANYLINUX")
    checked: dict[str, Any] = {"tf_producer_source": dict(source)}
    if public_inrun:
        checked = {
            "schema": value["schema"],
            "origin_kind": value["origin_kind"],
            **checked,
        }
        roles = ("stage_a",)
        if "stage_b" in keys:
            roles = (*roles, "stage_b")
    else:
        roles = ("stage_a", "stage_b")
    for role in roles:
        entry = _validate_file_digest_entry(
            value.get(role), code="QUALIFICATION_INPUTS_MANYLINUX"
        )
        rel_path = entry["path"]
        if rel_path not in evidence_files:
            fail("QUALIFICATION_INPUTS_MANYLINUX")
        ev_entry = _validate_file_digest_entry(
            evidence_files[rel_path], code="QUALIFICATION_INPUTS_EVIDENCE"
        )
        if entry != ev_entry:
            fail("QUALIFICATION_INPUTS_MANYLINUX")
        checked[role] = entry
    return checked


def validate_qualification_inputs_descriptor(
    doc: Mapping[str, Any],
    *,
    repository: str | Path | None = None,
    pending_code: str = "RELEASE_INPUTS_PENDING",
    phase: str = QUALIFICATION_INPUT_PHASE_PUBLICATION,
    inrun_root: str | Path | None = None,
) -> dict[str, Any]:
    """Validate the v1 operator descriptor for its explicit public-in-run phase."""
    from rs9.operator import validate_release_binding

    phase = _validate_qualification_input_phase(phase)
    if not isinstance(doc, Mapping):
        fail("QUALIFICATION_INPUTS_SCHEMA")
    status = doc.get("status")
    if status == "pending":
        fail(pending_code)
    if (
        not REQUIRED_QUALIFICATION_INPUTS_KEYS.issubset(doc.keys())
        or not set(doc.keys()).issubset(
            REQUIRED_QUALIFICATION_INPUTS_KEYS | OPTIONAL_QUALIFICATION_INPUTS_KEYS
        )
        or doc.get("schema") != QUALIFICATION_INPUTS_SCHEMA
        or doc.get("project") != PROJECT
        or doc.get("version") != VERSION
        or doc.get("distribution_version") != DISTRIBUTION_VERSION
        or doc.get("workflow") != WORKFLOW
        or status != "ready"
    ):
        fail("QUALIFICATION_INPUTS_SCHEMA")

    upstream_origin = doc.get("upstream_origin")
    if not isinstance(upstream_origin, Mapping) or set(upstream_origin.keys()) != {
        "repository",
        "tag",
        "release_url",
        "api_release_url",
    }:
        fail("QUALIFICATION_INPUTS_ORIGIN")
    origin_repo = upstream_origin.get("repository")
    origin_tag = upstream_origin.get("tag")
    release_url = upstream_origin.get("release_url")
    api_release_url = upstream_origin.get("api_release_url")
    if (
        not isinstance(origin_repo, str)
        or not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", origin_repo)
        or origin_tag != TAG
        or not isinstance(release_url, str)
        or not isinstance(api_release_url, str)
    ):
        fail("QUALIFICATION_INPUTS_ORIGIN")
    try:
        _public_url(release_url, frozenset({"github.com"}))
        _public_url(api_release_url, frozenset({"api.github.com"}))
    except AdmissionError:
        fail("QUALIFICATION_INPUTS_ORIGIN")

    raw_binding = doc.get("release_binding")
    binding_sha = doc.get("release_binding_sha256")
    if not isinstance(raw_binding, Mapping) or not _is_hex64(binding_sha):
        fail("QUALIFICATION_INPUTS_BINDING")
    if raw_binding.get("status") != "ready":
        fail(pending_code)
    try:
        validated_binding = validate_release_binding(dict(raw_binding))
    except ContractError as exc:
        fail(f"GATE1_{exc.code}")
    if (
        validated_binding.get("release") != VERSION
        or validated_binding.get("tag") != TAG
        or validated_binding.get("repository") != origin_repo
        or sha256(canonical(validated_binding)) != binding_sha
    ):
        fail("QUALIFICATION_INPUTS_BINDING")

    root = repo_root(repository)
    bootstrap_path = root / validated_binding["bootstrap_path"]
    expectations_path = root / validated_binding["expectations_path"]
    _check_no_symlinks(bootstrap_path, "BOOTSTRAP_SYMLINK")
    _check_no_symlinks(expectations_path, "EXPECTATIONS_SYMLINK")
    if not bootstrap_path.is_file() or not expectations_path.is_file():
        fail(pending_code)
    bootstrap_sha = sha256(physical_bytes(bootstrap_path, limit=1024 * 1024))
    if bootstrap_sha != validated_binding["expected"]["bootstrap_sha256"]:
        fail("GATE1_BOOTSTRAP_DIGEST_MISMATCH")
    expectations_sha = sha256(physical_bytes(expectations_path, limit=1024 * 1024))
    if expectations_sha != validated_binding["expected"]["expectations_sha256"]:
        fail("GATE1_EXPECTATIONS_DIGEST_MISMATCH")

    ev_spec = doc.get("evidence")
    if not isinstance(ev_spec, Mapping) or set(ev_spec.keys()) != {
        "source_root",
        "files",
    }:
        fail("QUALIFICATION_INPUTS_EVIDENCE")
    ev_root_raw = _validate_repo_relative_dir_spec(
        ev_spec.get("source_root"), code="QUALIFICATION_INPUTS_EVIDENCE"
    )
    ev_files = ev_spec.get("files")
    if not isinstance(ev_files, Mapping) or not ev_files:
        fail("QUALIFICATION_INPUTS_EVIDENCE")
    required_ev_keys = {
        "api/release.json",
        "api/repository.json",
        "api/ref.json",
        "api/commit.json",
        "api/tree.json",
        "assets/SHA256SUMS",
        "assets/PROVENANCE.json",
        "npm/metadata.json",
        "npm/package.tgz",
        "source/LICENSE",
        "source/NOTICE",
    }
    if not required_ev_keys.issubset(ev_files.keys()):
        fail("QUALIFICATION_INPUTS_EVIDENCE")
    for rel_key, f_entry in ev_files.items():
        if (
            not isinstance(rel_key, str)
            or not rel_key
            or rel_key.startswith("/")
            or "\\" in rel_key
            or ".." in Path(rel_key).parts
        ):
            fail("QUALIFICATION_INPUTS_EVIDENCE")
        checked = _validate_file_digest_entry(
            f_entry, code="QUALIFICATION_INPUTS_EVIDENCE"
        )
        if checked.get("path", rel_key) != rel_key:
            fail("QUALIFICATION_INPUTS_EVIDENCE")

    if "manylinux" in doc and "system_webkit" in doc:
        fail("QUALIFICATION_INPUTS_RUNTIME_PROFILE")
    system_webkit_spec = None
    if "system_webkit" in doc:
        system_webkit_spec = _validate_system_webkit_input_spec(doc["system_webkit"])
    manylinux_spec = None
    if "manylinux" in doc:
        manylinux_spec = _validate_manylinux_input_spec(
            doc["manylinux"], evidence_files=ev_files, phase=phase
        )
    artifact_root = _resolve_inrun_artifact_root(
        root, manylinux_spec, inrun_root, system_webkit_spec=system_webkit_spec,
    )
    _check_no_symlinks(artifact_root / ev_root_raw, "EVIDENCE_SYMLINK")

    rr_spec = doc.get("raw_release")
    if not isinstance(rr_spec, Mapping) or set(rr_spec.keys()) != {
        "source_root",
        "targets",
    }:
        fail("QUALIFICATION_INPUTS_RAW_RELEASE")
    rr_root_raw = _validate_repo_relative_dir_spec(
        rr_spec.get("source_root"), code="QUALIFICATION_INPUTS_RAW_RELEASE"
    )
    _check_no_symlinks(artifact_root / rr_root_raw, "RAW_RELEASE_SYMLINK")
    rr_targets = rr_spec.get("targets")
    if not isinstance(rr_targets, Mapping) or set(rr_targets.keys()) != set(TARGETS):
        fail("QUALIFICATION_INPUTS_RAW_RELEASE")
    for target in TARGETS:
        _validate_descriptor_target_raw_release(
            target, rr_targets.get(target), evidence_files=ev_files,
            system_webkit=system_webkit_spec is not None,
        )
    validated = json.loads(canonical(doc))
    if manylinux_spec is not None:
        validated["manylinux"] = manylinux_spec
    if system_webkit_spec is not None:
        validated["system_webkit"] = system_webkit_spec
    return validated


def load_qualification_inputs_descriptor(
    path: str | Path | None = None,
    *,
    repository: str | Path | None = None,
    pending_code: str = "RELEASE_INPUTS_PENDING",
    phase: str = QUALIFICATION_INPUT_PHASE_PUBLICATION,
    inrun_root: str | Path | None = None,
) -> dict[str, Any]:
    """Load and validate the 0.7.0 operator qualification-inputs descriptor; fail closed when pending or absent."""
    root = repo_root(repository)
    if path is not None:
        cand = Path(path)
        desc_path = (
            root / cand
            if not cand.is_absolute() and not cand.exists() and (root / cand).exists()
            else cand
        )
    else:
        env_path = os.environ.get("RS9_TFNF070_QUALIFICATION_INPUTS", "").strip()
        if env_path:
            cand = Path(env_path)
            desc_path = (
                root / cand
                if not cand.is_absolute() and not cand.exists() and (root / cand).exists()
                else cand
            )
        else:
            desc_path = qualification_inputs_path(root)
    _check_no_symlinks(desc_path, "QUALIFICATION_INPUTS_SYMLINK")
    if not desc_path.is_file():
        fail(pending_code)
    doc = strict_json(physical_bytes(desc_path, limit=4 * 1024 * 1024))
    if not isinstance(doc, Mapping):
        fail("QUALIFICATION_INPUTS_SCHEMA")
    return validate_qualification_inputs_descriptor(
        doc,
        repository=root,
        pending_code=pending_code,
        phase=phase,
        inrun_root=inrun_root,
    )


def _validate_optional_inrun_transport(
    qualification_inputs: str | Path | Mapping[str, Any] | None,
    *,
    repository: str | Path | None,
    inrun_root: str | Path | None,
    phase: str,
) -> None:
    """Validate a downstream consumer's explicit descriptor/root transport pair."""
    if qualification_inputs is None and inrun_root is None:
        return
    if qualification_inputs is None:
        fail("QUALIFICATION_INPUTS_ROOT")
    if isinstance(qualification_inputs, Mapping):
        validate_qualification_inputs_descriptor(
            qualification_inputs,
            repository=repository,
            pending_code="RELEASE_INPUTS_PENDING",
            phase=phase,
            inrun_root=inrun_root,
        )
    else:
        load_qualification_inputs_descriptor(
            qualification_inputs,
            repository=repository,
            pending_code="RELEASE_INPUTS_PENDING",
            phase=phase,
            inrun_root=inrun_root,
        )


def materialize_qualification_evidence(
    qualification_inputs: str | Path | Mapping[str, Any] | None,
    evidence_dir: str | Path,
    *,
    repository: str | Path | None = None,
    phase: str = QUALIFICATION_INPUT_PHASE_PUBLICATION,
    inrun_root: str | Path | None = None,
) -> dict[str, Any]:
    """Materialize or verify the digest-bound Gate 1 evidence directory from the qualification-inputs descriptor."""
    root = repo_root(repository)
    descriptor = (
        validate_qualification_inputs_descriptor(
            qualification_inputs,
            repository=root,
            pending_code="RELEASE_INPUTS_PENDING",
            phase=phase,
            inrun_root=inrun_root,
        )
        if isinstance(qualification_inputs, Mapping)
        else load_qualification_inputs_descriptor(
            qualification_inputs,
            repository=root,
            pending_code="RELEASE_INPUTS_PENDING",
            phase=phase,
            inrun_root=inrun_root,
        )
    )
    ev_spec = descriptor["evidence"]
    artifact_root = _resolve_inrun_artifact_root(
        root, descriptor.get("manylinux"), inrun_root,
        system_webkit_spec=descriptor.get("system_webkit"),
    )
    src_dir = _resolve_repo_contained_dir(
        artifact_root,
        ev_spec["source_root"],
        symlink_code="EVIDENCE_SYMLINK",
        missing_code="RELEASE_INPUTS_PENDING",
        containment_code="QUALIFICATION_INPUTS_EVIDENCE",
    )
    files_spec: Mapping[str, Mapping[str, Any]] = ev_spec["files"]

    dst_root = Path(evidence_dir)
    _check_no_symlinks(dst_root, "EVIDENCE_SYMLINK")
    if dst_root.exists():
        if not dst_root.is_dir():
            fail("QUALIFICATION_INPUTS_EVIDENCE")
        actual_rels: set[str] = set()
        for dirpath, dirnames, filenames in os.walk(dst_root, followlinks=False):
            dp = Path(dirpath)
            for dname in dirnames:
                if (dp / dname).is_symlink():
                    fail("EVIDENCE_SYMLINK")
            for fname in filenames:
                fpath = dp / fname
                if fpath.is_symlink() or not fpath.is_file():
                    fail("EVIDENCE_SYMLINK")
                actual_rels.add(fpath.relative_to(dst_root).as_posix())
        if actual_rels != set(files_spec.keys()):
            fail("QUALIFICATION_INPUTS_EVIDENCE")
        for rel_key, spec in sorted(files_spec.items()):
            f_path = dst_root / rel_key
            _check_no_symlinks(f_path, "EVIDENCE_SYMLINK")
            data = physical_bytes(f_path, limit=MAX_PAYLOAD_UNCOMPRESSED_BYTES)
            if len(data) != spec["size"] or sha256(data) != spec["sha256"]:
                fail("QUALIFICATION_INPUTS_DIGEST")
        return descriptor

    dst_root.mkdir(parents=True, exist_ok=True)
    try:
        for rel_key, spec in sorted(files_spec.items()):
            rel_src = spec.get("path", rel_key)
            src_file = src_dir / rel_src
            _check_no_symlinks(src_file, "EVIDENCE_SYMLINK")
            if not src_file.is_file():
                fail("RELEASE_INPUTS_PENDING")
            data = physical_bytes(src_file, limit=MAX_PAYLOAD_UNCOMPRESSED_BYTES)
            if len(data) != spec["size"] or sha256(data) != spec["sha256"]:
                fail("QUALIFICATION_INPUTS_DIGEST")
            dst_file = dst_root / rel_key
            _check_no_symlinks(dst_file.parent, "EVIDENCE_SYMLINK")
            dst_file.parent.mkdir(parents=True, exist_ok=True)
            with dst_file.open("xb") as stream:
                stream.write(data)
    except BaseException:
        if dst_root.exists():
            shutil.rmtree(dst_root, ignore_errors=True)
        raise
    return descriptor


def materialize_manylinux_inputs(
    qualification_inputs: str | Path | Mapping[str, Any] | None,
    evidence_dir: str | Path,
    *,
    repository: str | Path | None = None,
    phase: str = QUALIFICATION_INPUT_PHASE_PUBLICATION,
    inrun_root: str | Path | None = None,
) -> dict[str, Any]:
    """Materialize digest-bound public-in-run inputs for the requested phase."""
    descriptor = materialize_qualification_evidence(
        qualification_inputs,
        evidence_dir,
        repository=repository,
        phase=phase,
        inrun_root=inrun_root,
    )
    spec = descriptor.get("manylinux")
    if not isinstance(spec, Mapping):
        fail("MANYLINUX_INPUT")
    root = Path(evidence_dir)
    result: dict[str, Any] = {
        "stage_a": str((root / spec["stage_a"]["path"]).resolve()),
        "tf_producer_commit": spec["tf_producer_source"]["commit"],
        "tf_producer_tree": spec["tf_producer_source"]["tree"],
    }
    roles = ("stage_a",)
    if "stage_b" in spec:
        result["stage_b"] = str((root / spec["stage_b"]["path"]).resolve())
        roles = (*roles, "stage_b")
    for role in roles:
        path = Path(result[role])
        _check_no_symlinks(path, "MANYLINUX_INPUT")
        if not path.is_file():
            fail("MANYLINUX_INPUT")
        expected = spec[role]
        data = physical_bytes(path, limit=16 * 1024 * 1024)
        if len(data) != expected["size"] or sha256(data) != expected["sha256"]:
            fail("MANYLINUX_INPUT")
    return result


def _validate_bundle_file_set(bundle: Path) -> None:
    cand_file = bundle / "candidate_receipt.json"
    exp_file = bundle / "expected_artifacts.json"
    _check_no_symlinks(cand_file, "CANDIDATE_RECEIPT_SYMLINK")
    _check_no_symlinks(exp_file, "EXPECTED_ARTIFACTS_SYMLINK")
    if not cand_file.is_file() or not exp_file.is_file():
        fail("BUNDLE_FILES_MISSING")
    try:
        candidate_doc = strict_json(physical_bytes(cand_file, limit=4 * 1024 * 1024))
        candidate_rows = candidate_doc.get("rows") if isinstance(candidate_doc, Mapping) else None
        wheel_names = {
            row["wheel"]["filename"]
            for row in candidate_rows
            if isinstance(row, Mapping) and isinstance(row.get("wheel"), Mapping)
            and isinstance(row["wheel"].get("filename"), str)
        }
    except (AdmissionError, OSError, ValueError, KeyError, TypeError):
        fail("BUNDLE_FILES_MISSING")
    if len(wheel_names) != len(TARGETS):
        fail("BUNDLE_FILES_MISSING")
    expected_bundle_files = {
        "candidate_receipt.json",
        "expected_artifacts.json",
        *{f"dist/{name}" for name in wheel_names},
    }
    actual_files: set[str] = set()
    for dirpath, dirnames, filenames in os.walk(bundle, followlinks=False):
        dp = Path(dirpath)
        for dname in dirnames:
            if (dp / dname).is_symlink():
                fail("BUNDLE_DIR")
        for fname in filenames:
            fpath = dp / fname
            if fpath.is_symlink() or not fpath.is_file():
                fail("BUNDLE_DIR")
            actual_files.add(fpath.relative_to(bundle).as_posix())
    optional_manylinux = {"payload_portability.json"}
    if actual_files != expected_bundle_files and actual_files != expected_bundle_files | optional_manylinux:
        fail("BUNDLE_FILE_SET")
    if "payload_portability.json" in actual_files:
        try:
            envelope = strict_json(physical_bytes(bundle / "payload_portability.json", limit=8 * 1024 * 1024))
        except (AdmissionError, OSError, ValueError):
            fail("BUNDLE_MANYLINUX_INPUT")
        if (not isinstance(envelope, Mapping)
                or not isinstance(envelope.get("schema"), str)
                or envelope["schema"] not in {
                    PORTABILITY_INPUT_SCHEMA, ARCHIVE_PORTABILITY_INPUT_SCHEMA,
                }):
            fail("BUNDLE_MANYLINUX_INPUT")


def _verify_handoff_file_entry_matches_descriptor(
    h_entry: Mapping[str, Any],
    d_entry: Mapping[str, Any],
) -> None:
    if (
        h_entry["size"] != d_entry["size"]
        or h_entry["sha256"] != d_entry["sha256"]
    ):
        fail("RAW_RELEASE_HANDOFF_DIGEST")
    if (
        h_entry.get("path") != d_entry.get("path")
        or h_entry.get("name") != d_entry.get("name")
    ):
        fail("RAW_RELEASE_HANDOFF_BINDING")


def _verify_handoff_matches_descriptor(
    raw_release: Mapping[str, Any],
    descriptor: Mapping[str, Any],
    *,
    target: str,
) -> None:
    t_spec = descriptor["raw_release"]["targets"][target]
    for k in ("record", "readme", "provenance", "payload", "manifest"):
        _verify_handoff_file_entry_matches_descriptor(raw_release[k], t_spec[k])

    for leg_name in ("LICENSE", "NOTICE", "COMMERCIAL-LICENSE.md"):
        _verify_handoff_file_entry_matches_descriptor(
            raw_release["legal_files"][leg_name],
            t_spec["legal_files"][leg_name],
        )

    if set(raw_release["native_consumer"].keys()) != {target}:
        fail("RAW_RELEASE_HANDOFF_BINDING")
    nc_hand = raw_release["native_consumer"][target]
    nc_desc = t_spec["native_consumer"][target]
    if set(nc_hand.keys()) != set(nc_desc.keys()):
        fail("RAW_RELEASE_HANDOFF_BINDING")
    system_webkit = "system_webkit" in descriptor and target.startswith("linux")
    if system_webkit:
        _validate_system_native_raw_input(
            nc_desc, t_spec, target=target, descriptor=True,
            evidence_files=descriptor["evidence"]["files"],
        )
        _validate_system_native_raw_input(nc_hand, raw_release, target=target)
    else:
        _verify_handoff_file_entry_matches_descriptor(
            nc_hand["qualification"], nc_desc["qualification"],
        )
        for channel in ("raw-archive", "npm-package"):
            for kind in ("run", "receipt"):
                _verify_handoff_file_entry_matches_descriptor(
                    nc_hand["smoke"][channel][kind],
                    nc_desc["smoke"][channel][kind],
                )
    for meta_k in set(nc_desc.keys()) - {"qualification", "smoke"}:
        if meta_k == "smoke_support":
            from rs9.nebular070_smoke_support import validate_smoke_support
            descriptor_support = validate_smoke_support(
                nc_desc[meta_k], target, descriptor=True,
            )
            handoff_support = validate_smoke_support(
                nc_hand.get(meta_k), target,
            )
            descriptor_support["files"] = [
                {key: item[key] for key in ("path", "size", "sha256", "blob", "role")}
                for item in descriptor_support["files"]
            ]
            descriptor_support["source_binding"] = {
                kind: {
                    key: ref[key] for key in ("path", "size", "sha256")
                }
                for kind, ref in descriptor_support["source_binding"].items()
            }
            if handoff_support != descriptor_support:
                fail("RAW_RELEASE_HANDOFF_BINDING")
        elif nc_hand.get(meta_k) != nc_desc.get(meta_k):
            fail("RAW_RELEASE_HANDOFF_BINDING")


def validate_raw_release_handoff_binding(
    raw_release: Mapping[str, Any],
    *,
    target: str,
    candidate: Mapping[str, Any] | None = None,
    expected_artifacts: Mapping[str, Any] | None = None,
    qualification_inputs: str | Path | Mapping[str, Any] | None = None,
    repository: str | Path | None = None,
    inrun_root: str | Path | None = None,
) -> dict[str, Any]:
    """Validate raw-release handoff schema, physical file digests, and cryptographic binding to the candidate bundle."""
    if target not in TARGETS:
        fail("WHEEL_TARGET")
    if (
        not isinstance(raw_release, Mapping)
        or not REQUIRED_RAW_RELEASE_HANDOFF_KEYS.issubset(raw_release.keys())
        or not set(raw_release.keys()).issubset(
            REQUIRED_RAW_RELEASE_HANDOFF_KEYS | OPTIONAL_RAW_RELEASE_HANDOFF_KEYS
        )
    ):
        fail("RAW_RELEASE_HANDOFF_SCHEMA")
    if "schema" in raw_release and raw_release["schema"] != RAW_RELEASE_HANDOFF_SCHEMA:
        fail("RAW_RELEASE_HANDOFF_SCHEMA")
    if "target" in raw_release and raw_release["target"] != target:
        fail("RAW_RELEASE_HANDOFF_BINDING")

    root_raw = raw_release.get("root")
    if not isinstance(root_raw, str) or not root_raw.strip():
        fail("RAW_RELEASE_HANDOFF_SCHEMA")
    root_dir = _require_real_directory(root_raw, "RAW_RELEASE_HANDOFF_ROOT")

    def _verify_bound_file(entry: Any) -> tuple[dict[str, Any], str]:
        checked = _validate_file_digest_entry(entry, code="RAW_RELEASE_HANDOFF_SCHEMA")
        rel = checked.get("path") or checked.get("name")
        assert isinstance(rel, str)
        fpath = root_dir / rel
        _check_no_symlinks(fpath, "RAW_RELEASE_SYMLINK")
        try:
            resolved = fpath.resolve()
            resolved.relative_to(root_dir)
        except (OSError, ValueError):
            fail("RAW_RELEASE_HANDOFF_SCHEMA")
        if not fpath.is_file():
            fail("RAW_RELEASE_HANDOFF_FILE")
        data = physical_bytes(fpath, limit=MAX_PAYLOAD_UNCOMPRESSED_BYTES)
        if len(data) != checked["size"] or sha256(data) != checked["sha256"]:
            fail("RAW_RELEASE_HANDOFF_DIGEST")
        return checked, rel

    rec_entry, _ = _verify_bound_file(raw_release.get("record"))
    readme_entry, readme_rel = _verify_bound_file(raw_release.get("readme"))
    prov_entry, _ = _verify_bound_file(raw_release.get("provenance"))
    payload_entry, payload_rel = _verify_bound_file(raw_release.get("payload"))
    manifest_entry, _ = _verify_bound_file(raw_release.get("manifest"))

    legal_files = raw_release.get("legal_files")
    if not isinstance(legal_files, Mapping) or set(legal_files.keys()) != {
        "LICENSE",
        "NOTICE",
        "COMMERCIAL-LICENSE.md",
    }:
        fail("RAW_RELEASE_HANDOFF_SCHEMA")
    checked_legal: dict[str, dict[str, Any]] = {}
    for leg_name, leg_spec in legal_files.items():
        checked_leg, _ = _verify_bound_file(leg_spec)
        checked_legal[leg_name] = checked_leg

    nc_all = raw_release.get("native_consumer")
    if not isinstance(nc_all, Mapping) or target not in nc_all:
        fail("RAW_RELEASE_HANDOFF_BINDING")
    for nc_key in nc_all:
        if nc_key not in TARGETS:
            fail("RAW_RELEASE_HANDOFF_SCHEMA")
    nc_target = nc_all.get(target)
    if not isinstance(nc_target, Mapping):
        fail("RAW_RELEASE_HANDOFF_SCHEMA")
    if "target" in nc_target and nc_target["target"] != target:
        fail("RAW_RELEASE_HANDOFF_BINDING")
    from rs9.nebular070_installed_smoke import SYSTEM_WEBKIT_NATIVE_INPUT_SCHEMA
    system_webkit = nc_target.get("schema") == SYSTEM_WEBKIT_NATIVE_INPUT_SCHEMA
    if candidate is not None and target.startswith("linux"):
        candidate_system = candidate.get("profile") == gate1_profile_record(SYSTEM_WEBKIT_PROFILE)
        if candidate_system != system_webkit:
            fail("RAW_RELEASE_HANDOFF_BINDING")
    if system_webkit:
        _validate_system_native_raw_input(nc_target, raw_release, target=target)
    else:
        _verify_bound_file(nc_target.get("qualification"))
        smoke_map = nc_target.get("smoke")
        if not isinstance(smoke_map, Mapping) or set(smoke_map.keys()) != {
            "raw-archive", "npm-package",
        }:
            fail("RAW_RELEASE_HANDOFF_SCHEMA")
        for channel in ("raw-archive", "npm-package"):
            ch_spec = smoke_map.get(channel)
            if not isinstance(ch_spec, Mapping):
                fail("RAW_RELEASE_HANDOFF_SCHEMA")
            _verify_bound_file(ch_spec.get("run"))
            _verify_bound_file(ch_spec.get("receipt"))

    if "smoke_support" in nc_target:
        from rs9.nebular070_smoke_support import (
            SOURCE_ARCHIVE_SIZE,
            SOURCE_AUTHORITY_SIZE,
            validate_smoke_support,
            verify_source_binding,
        )
        support = validate_smoke_support(nc_target["smoke_support"], target)
        for item in support["files"]:
            _verify_bound_file({
                "path": f"{support['root']}/{item['path']}",
                "size": item["size"],
                "sha256": item["sha256"],
            })
        for ref in support["source_binding"].values():
            _verify_bound_file({
                "path": f"{support['root']}/{ref['path']}",
                "size": ref["size"],
                "sha256": ref["sha256"],
            })
        verify_source_binding(root_dir, support)

    if system_webkit:
        loader_spec = nc_target["members"]["launcher"]
    else:
        loader_spec = nc_target.get("loader")
        closure_spec = nc_target.get("provider_closure")
        if not isinstance(loader_spec, Mapping) or not isinstance(closure_spec, Mapping):
            fail("RAW_RELEASE_HANDOFF_SCHEMA")
        if closure_spec.get("target") not in (None, target):
            fail("RAW_RELEASE_HANDOFF_BINDING")

    if candidate is not None:
        if not isinstance(candidate, Mapping):
            fail("CANDIDATE_RECEIPT_SCHEMA")
        cand_sha = sha256(canonical(candidate))
        prof_sha = _require_candidate_profile_sha(candidate)
        if (
            "candidate_receipt_sha256" in raw_release
            and raw_release["candidate_receipt_sha256"] != cand_sha
        ):
            fail("RAW_RELEASE_HANDOFF_BINDING")
        if (
            "profile_result_sha256" in raw_release
            and raw_release["profile_result_sha256"] != prof_sha
        ):
            fail("RAW_RELEASE_HANDOFF_BINDING")

        expected_system = SYSTEM_BY_TARGET[target]
        rows = candidate.get("rows")
        if not isinstance(rows, list):
            fail("CANDIDATE_RECEIPT_SCHEMA")
        target_rows = [
            r for r in rows if isinstance(r, Mapping) and r.get("system") == expected_system
        ]
        if len(target_rows) != 1:
            fail("CANDIDATE_RECEIPT_SCHEMA")
        t_row = target_rows[0]

        src_id = candidate.get("source_identity")
        cand_readme = candidate.get("readme")
        cand_legal = candidate.get("legal_files")
        cand_lineage = candidate.get("direct_lineage")
        fwd_lineage = t_row.get("forward_lineage")
        wheel_info = t_row.get("wheel")
        if (
            not isinstance(src_id, Mapping)
            or not isinstance(cand_readme, Mapping)
            or not isinstance(cand_legal, Mapping)
            or not isinstance(cand_lineage, Mapping)
            or not isinstance(fwd_lineage, Mapping)
            or not isinstance(wheel_info, Mapping)
        ):
            fail("CANDIDATE_RECEIPT_SCHEMA")

        if (
            rec_entry["sha256"] != src_id.get("release_record_sha256")
            or readme_rel != cand_readme.get("path")
            or readme_entry["sha256"] != cand_readme.get("sha256")
            or prov_entry["sha256"] != cand_lineage.get("provenance_sha256")
            or prov_entry["sha256"] != fwd_lineage.get("provenance_sha256")
            or Path(payload_rel).name != t_row.get("payload_archive_name")
            or payload_entry["sha256"] != t_row.get("payload_archive_sha256")
            or manifest_entry["sha256"] != t_row.get("manifest_sha256")
            or loader_spec.get("path") != t_row.get("launcher_path")
        ):
            fail("RAW_RELEASE_HANDOFF_BINDING")

        for leg_name, checked_leg in checked_legal.items():
            cand_leg_entry = cand_legal.get(leg_name)
            if (
                not isinstance(cand_leg_entry, Mapping)
                or checked_leg["size"] != cand_leg_entry.get("size")
                or checked_leg["sha256"] != cand_leg_entry.get("sha256")
            ):
                fail("RAW_RELEASE_HANDOFF_BINDING")

        if (
            "wheel_sha256" in raw_release
            and raw_release["wheel_sha256"] != wheel_info.get("sha256")
        ):
            fail("RAW_RELEASE_HANDOFF_BINDING")

    if expected_artifacts is not None:
        if not isinstance(expected_artifacts, Mapping):
            fail("EXPECTED_ARTIFACTS_SCHEMA")
        if (
            "expected_artifact_record_sha256" in raw_release
            and raw_release["expected_artifact_record_sha256"]
            != expected_artifacts.get("record_sha256")
        ):
            fail("RAW_RELEASE_HANDOFF_BINDING")
        wheels = expected_artifacts.get("wheels")
        if not isinstance(wheels, list):
            fail("EXPECTED_ARTIFACTS_SCHEMA")
        w_rows = [
            w for w in wheels if isinstance(w, Mapping) and w.get("target") == target
        ]
        if len(w_rows) != 1:
            fail("EXPECTED_ARTIFACTS_SCHEMA")
        if (
            "wheel_sha256" in raw_release
            and raw_release["wheel_sha256"] != w_rows[0].get("sha256")
        ):
            fail("RAW_RELEASE_HANDOFF_BINDING")

    if qualification_inputs is not None:
        descriptor = (
            validate_qualification_inputs_descriptor(
                qualification_inputs,
                repository=repository,
                pending_code="RAW_RELEASE_HANDOFF_PENDING",
                phase=QUALIFICATION_INPUT_PHASE_PREP,
                inrun_root=inrun_root,
            )
            if isinstance(qualification_inputs, Mapping)
            else load_qualification_inputs_descriptor(
                qualification_inputs,
                repository=repository,
                pending_code="RAW_RELEASE_HANDOFF_PENDING",
                phase=QUALIFICATION_INPUT_PHASE_PREP,
                inrun_root=inrun_root,
            )
        )
        _verify_handoff_matches_descriptor(raw_release, descriptor, target=target)

    return json.loads(canonical(raw_release))


def materialize_raw_release_handoff(
    qualification_inputs: str | Path | Mapping[str, Any] | None,
    output_path: str | Path,
    *,
    target: str,
    candidate: Mapping[str, Any],
    expected_artifacts: Mapping[str, Any],
    repository: str | Path | None = None,
    inrun_root: str | Path | None = None,
) -> dict[str, Any]:
    """Materialize a target-bound, digest-verified raw-release handoff directory and JSON descriptor."""
    if target not in TARGETS:
        fail("WHEEL_TARGET")
    if not isinstance(candidate, Mapping):
        fail("CANDIDATE_RECEIPT_SCHEMA")
    cand_rows = candidate.get("rows")
    if not isinstance(cand_rows, list):
        fail("CANDIDATE_RECEIPT_SCHEMA")
    expected_system = SYSTEM_BY_TARGET[target]
    matching_rows = [
        r for r in cand_rows if isinstance(r, Mapping) and r.get("system") == expected_system
    ]
    if len(matching_rows) != 1:
        fail("CANDIDATE_RECEIPT_SCHEMA")
    t_row = matching_rows[0]
    wheel_info = t_row.get("wheel")
    if not isinstance(wheel_info, Mapping) or not _is_hex64(wheel_info.get("sha256")):
        fail("CANDIDATE_RECEIPT_SCHEMA")
    if not isinstance(expected_artifacts, Mapping) or not _is_hex64(
        expected_artifacts.get("record_sha256")
    ):
        fail("EXPECTED_ARTIFACTS_SCHEMA")

    root = repo_root(repository)
    descriptor = (
        validate_qualification_inputs_descriptor(
            qualification_inputs,
            repository=root,
            pending_code="RAW_RELEASE_HANDOFF_PENDING",
            phase=QUALIFICATION_INPUT_PHASE_PREP,
            inrun_root=inrun_root,
        )
        if isinstance(qualification_inputs, Mapping)
        else load_qualification_inputs_descriptor(
            qualification_inputs,
            repository=root,
            pending_code="RAW_RELEASE_HANDOFF_PENDING",
            phase=QUALIFICATION_INPUT_PHASE_PREP,
            inrun_root=inrun_root,
        )
    )
    rr_spec = descriptor["raw_release"]
    artifact_root = _resolve_inrun_artifact_root(
        root, descriptor.get("manylinux"), inrun_root,
        system_webkit_spec=descriptor.get("system_webkit"),
    )
    ev_root_raw = _validate_repo_relative_dir_spec(
        descriptor["evidence"]["source_root"], code="QUALIFICATION_INPUTS_EVIDENCE"
    )
    src_dir = _resolve_repo_contained_dir(
        artifact_root,
        rr_spec["source_root"],
        symlink_code="RAW_RELEASE_SYMLINK",
        missing_code="RAW_RELEASE_HANDOFF_PENDING",
        containment_code="QUALIFICATION_INPUTS_RAW_RELEASE",
    )
    t_spec = json.loads(canonical(rr_spec["targets"][target]))

    out_file = Path(output_path)
    _check_no_symlinks(out_file.parent, "RAW_RELEASE_SYMLINK")
    stage_dir = out_file.parent / "files"
    if out_file.exists() or stage_dir.exists():
        fail("RAW_RELEASE_HANDOFF_OUTPUT")
    stage_dir.mkdir(parents=True, exist_ok=True)

    def _stage_entry(entry: dict[str, Any], *, use_name: bool = False) -> dict[str, Any]:
        checked = _validate_file_digest_entry(entry, code="RAW_RELEASE_HANDOFF_SCHEMA")
        src_rel = checked.get("path") or checked.get("name")
        assert isinstance(src_rel, str)
        dst_rel = Path(src_rel).name if use_name else src_rel
        src_file = src_dir / src_rel
        _check_no_symlinks(src_file, "RAW_RELEASE_SYMLINK")
        if not src_file.is_file():
            fail("RAW_RELEASE_HANDOFF_PENDING")
        data = physical_bytes(src_file, limit=MAX_PAYLOAD_UNCOMPRESSED_BYTES)
        if len(data) != checked["size"] or sha256(data) != checked["sha256"]:
            fail("RAW_RELEASE_HANDOFF_DIGEST")
        dst_file = stage_dir / dst_rel
        _check_no_symlinks(dst_file.parent, "RAW_RELEASE_SYMLINK")
        dst_file.parent.mkdir(parents=True, exist_ok=True)
        if dst_file.exists():
            existing = physical_bytes(dst_file, limit=MAX_PAYLOAD_UNCOMPRESSED_BYTES)
            if existing != data:
                fail("RAW_RELEASE_HANDOFF_DIGEST")
        else:
            with dst_file.open("xb") as stream:
                stream.write(data)
        out_entry = dict(checked)
        if use_name and "name" in out_entry and "path" not in out_entry:
            out_entry["name"] = dst_rel
        else:
            out_entry["path"] = dst_rel
        return out_entry

    try:
        nc_entry = json.loads(canonical(t_spec["native_consumer"][target]))
        system_webkit = "system_webkit" in descriptor and target.startswith("linux")
        if not system_webkit:
            nc_entry["qualification"] = _stage_entry(nc_entry["qualification"])
            for channel in ("raw-archive", "npm-package"):
                nc_entry["smoke"][channel]["run"] = _stage_entry(
                    nc_entry["smoke"][channel]["run"]
                )
                nc_entry["smoke"][channel]["receipt"] = _stage_entry(
                    nc_entry["smoke"][channel]["receipt"]
                )
        if "smoke_support" in nc_entry:
            from rs9.nebular070_smoke_support import (
                SOURCE_ARCHIVE_SIZE,
                SOURCE_AUTHORITY_SIZE,
                validate_smoke_support,
            )
            support = validate_smoke_support(
                nc_entry["smoke_support"], target,
                evidence_files=descriptor["evidence"]["files"], descriptor=True,
            )
            # Descriptor-only evidence_path fields must not leak into the
            # staged handoff.  The consumer receives the normalized closure
            # and the raw handoff validator intentionally accepts only the
            # executable path/size/digest/blob/role records.
            handoff_support = dict(support)
            handoff_support["files"] = [
                {key: item[key] for key in ("path", "size", "sha256", "blob", "role")}
                for item in support["files"]
            ]
            handoff_support["source_binding"] = {
                kind: {
                    key: ref[key] for key in ("path", "size", "sha256")
                }
                for kind, ref in support["source_binding"].items()
            }
            nc_entry["smoke_support"] = handoff_support
            evidence_dir = artifact_root / ev_root_raw
            for item in support["files"]:
                evidence_file = evidence_dir / item["evidence_path"]
                _check_no_symlinks(evidence_file, "RAW_RELEASE_SYMLINK")
                data = physical_bytes(evidence_file, limit=8 * 1024 * 1024)
                if len(data) != item["size"] or sha256(data) != item["sha256"]:
                    fail("RAW_RELEASE_HANDOFF_DIGEST")
                destination = stage_dir / support["root"] / item["path"]
                _check_no_symlinks(destination.parent, "RAW_RELEASE_SYMLINK")
                destination.parent.mkdir(parents=True, exist_ok=True)
                if destination.exists() or destination.is_symlink():
                    fail("RAW_RELEASE_HANDOFF_OUTPUT")
                with destination.open("xb") as stream:
                    stream.write(data)
            for ref in support["source_binding"].values():
                evidence_file = evidence_dir / ref["evidence_path"]
                _check_no_symlinks(evidence_file, "RAW_RELEASE_SYMLINK")
                data = physical_bytes(evidence_file, limit=SOURCE_ARCHIVE_SIZE if ref["path"].endswith(".tar.gz") else SOURCE_AUTHORITY_SIZE)
                if len(data) != ref["size"] or sha256(data) != ref["sha256"]:
                    fail("RAW_RELEASE_HANDOFF_DIGEST")
                destination = stage_dir / support["root"] / ref["path"]
                _check_no_symlinks(destination.parent, "RAW_RELEASE_SYMLINK")
                destination.parent.mkdir(parents=True, exist_ok=True)
                if destination.exists() or destination.is_symlink():
                    fail("RAW_RELEASE_HANDOFF_OUTPUT")
                with destination.open("xb") as stream:
                    stream.write(data)

        handoff_doc: dict[str, Any] = {
            "schema": RAW_RELEASE_HANDOFF_SCHEMA,
            "target": target,
            "candidate_receipt_sha256": sha256(canonical(candidate)),
            "expected_artifact_record_sha256": expected_artifacts["record_sha256"],
            "profile_result_sha256": _require_candidate_profile_sha(candidate),
            "wheel_sha256": wheel_info["sha256"],
            "root": str(stage_dir.resolve()),
            "record": _stage_entry(t_spec["record"]),
            "readme": _stage_entry(t_spec["readme"]),
            "legal_files": {
                k: _stage_entry(v) for k, v in sorted(t_spec["legal_files"].items())
            },
            "payload": _stage_entry(
                t_spec["payload"],
                use_name=("name" in t_spec["payload"] and "path" not in t_spec["payload"]),
            ),
            "manifest": _stage_entry(t_spec["manifest"]),
            "provenance": _stage_entry(t_spec["provenance"]),
            "native_consumer": {target: nc_entry},
        }
        validated = validate_raw_release_handoff_binding(
            handoff_doc,
            target=target,
            candidate=candidate,
            expected_artifacts=expected_artifacts,
            qualification_inputs=descriptor,
            repository=root,
            inrun_root=inrun_root,
        )
        with out_file.open("xb") as stream:
            stream.write(canonical(validated))
    except BaseException:
        if out_file.exists():
            out_file.unlink(missing_ok=True)
        if stage_dir.exists():
            shutil.rmtree(stage_dir, ignore_errors=True)
        raise
    return validated


def load_raw_release_handoff(
    path: str | Path | None = None,
    *,
    target: str,
    bundle_dir: str | Path | None = None,
    candidate: Mapping[str, Any] | None = None,
    expected_artifacts: Mapping[str, Any] | None = None,
    qualification_inputs: str | Path | Mapping[str, Any] | None = None,
    repository: str | Path | None = None,
    inrun_root: str | Path | None = None,
) -> dict[str, Any]:
    """Load and validate the late-bound raw-release handoff for 0.7.0 native consumer qualification."""
    if target not in TARGETS:
        fail("WHEEL_TARGET")
    if path is not None:
        handoff_path = Path(path)
    else:
        env_raw = os.environ.get("RS9_TFNF070_RAW_RELEASE_HANDOFF", "").strip()
        if env_raw:
            handoff_path = Path(env_raw)
        else:
            fail("RAW_RELEASE_HANDOFF_PENDING")
    _check_no_symlinks(handoff_path, "RAW_RELEASE_SYMLINK")
    if not handoff_path.is_file():
        fail("RAW_RELEASE_HANDOFF_PENDING")
    doc = strict_json(physical_bytes(handoff_path, limit=4 * 1024 * 1024))
    if not isinstance(doc, Mapping):
        fail("RAW_RELEASE_HANDOFF_SCHEMA")
    if "target" in doc and doc["target"] != target:
        fail("RAW_RELEASE_HANDOFF_BINDING")
    per_target = doc.get("per_target")
    if isinstance(per_target, Mapping):
        if target not in per_target:
            fail("RAW_RELEASE_HANDOFF_BINDING")
        entry = per_target.get(target)
    else:
        entry = doc
    if not isinstance(entry, Mapping):
        fail("RAW_RELEASE_HANDOFF_SCHEMA")

    cand_doc = candidate
    exp_doc = expected_artifacts
    if bundle_dir is not None and (cand_doc is None or exp_doc is None):
        bundle = _require_real_directory(bundle_dir, "BUNDLE_DIR")
        _validate_bundle_file_set(bundle)
        if cand_doc is None:
            cand_doc = strict_json(
                physical_bytes(bundle / "candidate_receipt.json", limit=4 * 1024 * 1024)
            )
        if exp_doc is None:
            exp_doc = strict_json(
                physical_bytes(bundle / "expected_artifacts.json", limit=1024 * 1024)
            )
    return validate_raw_release_handoff_binding(
        entry,
        target=target,
        candidate=cand_doc,
        expected_artifacts=exp_doc,
        qualification_inputs=qualification_inputs,
        repository=repository,
        inrun_root=inrun_root,
    )


def default_sandbox_prefix(target: str) -> tuple[str, ...]:
    """Return the platform network-denial prefix for 0.7.0 native consumer qualification."""
    if target == "darwin-arm64":
        return ("/usr/bin/sandbox-exec", "-p", DARWIN_QUALIFY_SANDBOX_PROFILE)
    if target in ("linux-arm64-gnu", "linux-x64-gnu"):
        uid, gid = os.getuid(), os.getgid()
        return (
            "sudo",
            "-n",
            f"--preserve-env={LINUX_SANDBOX_PRESERVE_ENV}",
            "unshare",
            "--net",
            "--",
            "setpriv",
            f"--reuid={uid}",
            f"--regid={gid}",
            "--clear-groups",
            "--",
        )
    fail("WHEEL_TARGET")
    raise AssertionError("unreachable")


def make_real_user_state_snapshotter(
    target: str,
    *,
    home_dir: str | Path | None = None,
) -> Callable[[str, str], dict[str, Any]]:
    """Build a real-user persistent-state snapshot callback without parent directory enumeration."""
    from rs9.nebular_host_state import (
        BASES,
        HostStateError,
        NAMES,
        SUFFIXES,
        operator_home,
        snapshot,
    )

    host_state = sys.modules["rs9.nebular_host_state"]
    if target not in TARGETS:
        fail("WHEEL_TARGET")
    try:
        real_home = (
            Path(home_dir).resolve()
            if home_dir is not None
            else operator_home()
        )
    except HostStateError:
        fail("USER_STATE_HOME")
    _check_no_symlinks(real_home, "USER_STATE_HOME")
    if not real_home.is_dir():
        fail("USER_STATE_HOME")

    bases = (
        BASES
        if target == "darwin-arm64"
        else (".cache", ".config", ".local/share", ".local/state")
    )
    relatives = tuple(
        f"{base}/{name}{suffix}"
        for base in bases
        for name in NAMES
        for suffix in SUFFIXES
    )
    before_rows: dict[str, dict[str, Any]] | None = None

    def _capture_rows() -> tuple[dict[str, dict[str, Any]], str]:
        orig_bases = host_state.BASES
        try:
            host_state.BASES = bases
            snap = snapshot(real_home)
            entries = snap["entries"]
            rows_map = {
                rel: {
                    k: v
                    for k, v in entries.items()
                    if k == rel or k.startswith(rel + "/")
                }
                for rel in relatives
            }
            return rows_map, str(snap["sha256"])
        except HostStateError:
            fail("NEBULAR_USER_STATE_GUARD")
            raise AssertionError("unreachable")
        finally:
            host_state.BASES = orig_bases

    def _snapshot(phase: str, observed_target: str) -> dict[str, Any]:
        nonlocal before_rows
        if observed_target != target or phase not in ("before", "after"):
            fail("NEBULAR_USER_STATE_GUARD")
        rows_map, digest_hex = _capture_rows()
        if phase == "before":
            before_rows = rows_map
            changed: list[str] = []
        else:
            if before_rows is None:
                fail("NEBULAR_USER_STATE_GUARD")
            changed = sorted(
                rel for rel, row in rows_map.items() if before_rows.get(rel) != row
            )
        return {
            "schema": "nebular.native-rc-persistent-user-state-v1",
            "method": "native-rc-smoke.persistentStateLocations+snapshotLocations",
            "scope": "real-user-state",
            "target": observed_target,
            "phase": phase,
            "locations": len(rows_map),
            "snapshot_sha256": digest_hex,
            "changed": changed,
        }

    return _snapshot


def qualify_native_target(
    bundle_dir: str | Path,
    work_dir: str | Path,
    output_path: str | Path,
    *,
    target: str,
    expected_commit: str,
    run_id: str,
    run_attempt: str,
    raw_release_path: str | Path | None = None,
    qualification_inputs: str | Path | Mapping[str, Any] | None = None,
    repository: str | Path | None = None,
    inrun_root: str | Path | None = None,
    sandbox_prefix: Sequence[str] | None = None,
    real_user_state_snapshot: Callable[[str, str], Mapping[str, Any]] | None = None,
    home_dir: str | Path | None = None,
    consumer_host_role: str | None = None,
    consumer_capture_output: str | Path | None = None,
    smoke_support: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Execute 0.7.0 native consumer qualification for one target with sandbox and user-state guards."""
    capture_path = _validate_consumer_capture_options(
        target, consumer_host_role, consumer_capture_output,
    )
    if capture_path is not None:
        qualify_output = Path(output_path)
        _check_no_symlinks(qualify_output, "QUALIFY_OUTPUT")
        if qualify_output.exists() or (
            qualify_output.parent.exists() and not qualify_output.parent.is_dir()
        ):
            fail("QUALIFY_OUTPUT")
        if capture_path.resolve() == qualify_output.resolve():
            fail("CONSUMER_CAPTURE_OUTPUT")
    bundle = _require_real_directory(bundle_dir, "BUNDLE_DIR")
    _validate_bundle_file_set(bundle)
    cand_file = bundle / "candidate_receipt.json"
    exp_file = bundle / "expected_artifacts.json"
    candidate = strict_json(physical_bytes(cand_file, limit=4 * 1024 * 1024))
    expected = strict_json(physical_bytes(exp_file, limit=1024 * 1024))
    prof_sha = _require_candidate_profile_sha(candidate)
    root = repo_root(repository)

    eff_qual_inputs: str | Path | Mapping[str, Any] | None = qualification_inputs
    if eff_qual_inputs is None:
        env_qual_inputs = os.environ.get("RS9_TFNF070_QUALIFICATION_INPUTS", "").strip()
        if env_qual_inputs:
            eff_qual_inputs = Path(env_qual_inputs)

    if raw_release_path is not None:
        rr_out_path = Path(raw_release_path)
    else:
        env_raw_out = os.environ.get("RS9_TFNF070_RAW_RELEASE_HANDOFF", "").strip()
        rr_out_path = (
            Path(env_raw_out)
            if env_raw_out
            else Path(work_dir).parent
            / f"tfnf-070-raw-release-{target}"
            / "raw_release.json"
        )
    if capture_path is not None and rr_out_path.resolve() in {
        capture_path.resolve(), Path(output_path).resolve(),
    }:
        fail("CONSUMER_CAPTURE_OUTPUT")
    _check_no_symlinks(rr_out_path, "RAW_RELEASE_SYMLINK")
    descriptor: Mapping[str, Any]
    if rr_out_path.is_file():
        raw_release = load_raw_release_handoff(
            rr_out_path,
            target=target,
            candidate=candidate,
            expected_artifacts=expected,
            qualification_inputs=eff_qual_inputs,
            repository=root,
            inrun_root=inrun_root,
        )
        descriptor = (
            validate_qualification_inputs_descriptor(
                eff_qual_inputs,
                repository=root,
                pending_code="RAW_RELEASE_HANDOFF_PENDING",
                phase=QUALIFICATION_INPUT_PHASE_PREP,
                inrun_root=inrun_root,
            )
            if isinstance(eff_qual_inputs, Mapping)
            else load_qualification_inputs_descriptor(
                eff_qual_inputs,
                repository=root,
                pending_code="RAW_RELEASE_HANDOFF_PENDING",
                phase=QUALIFICATION_INPUT_PHASE_PREP,
                inrun_root=inrun_root,
            )
        )
        _verify_handoff_matches_descriptor(raw_release, descriptor, target=target)
    else:
        raw_release = materialize_raw_release_handoff(
            eff_qual_inputs,
            rr_out_path,
            target=target,
            candidate=candidate,
            expected_artifacts=expected,
            repository=root,
            inrun_root=inrun_root,
        )
        descriptor = (
            validate_qualification_inputs_descriptor(
                eff_qual_inputs,
                repository=root,
                pending_code="RAW_RELEASE_HANDOFF_PENDING",
                phase=QUALIFICATION_INPUT_PHASE_PREP,
                inrun_root=inrun_root,
            )
            if isinstance(eff_qual_inputs, Mapping)
            else load_qualification_inputs_descriptor(
                eff_qual_inputs,
                repository=root,
                pending_code="RAW_RELEASE_HANDOFF_PENDING",
                phase=QUALIFICATION_INPUT_PHASE_PREP,
                inrun_root=inrun_root,
            )
        )

    tree = _git_output(root, ["rev-parse", "--verify", "HEAD^{tree}"], "HOSTED_COMMIT")
    manylinux_stage_a = _load_candidate_stage_a(
        bundle,
        descriptor,
        expected_commit=expected_commit,
        expected_tree=tree,
    )
    system_profile = candidate.get("profile") == gate1_profile_record(SYSTEM_WEBKIT_PROFILE)
    if system_profile != ("system_webkit" in descriptor):
        fail("QUALIFICATION_INPUTS_RUNTIME_PROFILE")
    if capture_path is not None and manylinux_stage_a is None and not system_profile:
        fail("CONSUMER_CAPTURE_STAGE_A")
    target_system = SYSTEM_BY_TARGET[target]
    target_row = next(
        (row for row in candidate.get("rows", [])
         if isinstance(row, Mapping) and row.get("system") == target_system),
        None,
    )
    if not isinstance(target_row, Mapping) or not isinstance(target_row.get("wheel"), Mapping):
        fail("CANDIDATE_RECEIPT_SCHEMA")
    wheel_name = target_row["wheel"].get("filename")
    if not isinstance(wheel_name, str):
        fail("CANDIDATE_RECEIPT_SCHEMA")
    wheel_path = bundle / "dist" / wheel_name
    capture_host_body: Mapping[str, Any] | None = None
    capture_host_extras: Mapping[str, Any] | None = None
    capture_wheel: Mapping[str, Any] | None = None
    if capture_path is not None:
        # Keep these imports local: public_consumers imports this module for
        # the existing sandbox/user-state owners, so a top-level import would
        # create a circular import during normal CLI startup.
        from rs9.nebular070_host_observation import observe_host
        from rs9.nebular070_manylinux import _wheel_snapshot
        from rs9.nebular070_public_consumers import _system_wheel

        capture_host_body, capture_host_extras = observe_host(consumer_host_role)
        wheel_bytes = physical_bytes(wheel_path, limit=MAX_WHEEL_FILE_BYTES)
        capture_wheel = (
            _system_wheel(wheel_bytes, target) if system_profile
            else _wheel_snapshot(wheel_bytes, target, manylinux_stage_a.digest)
        )
    eff_prefix = (
        tuple(sandbox_prefix)
        if sandbox_prefix is not None
        else default_sandbox_prefix(target)
    )
    eff_user_state = real_user_state_snapshot or make_real_user_state_snapshotter(
        target, home_dir=home_dir
    )
    system_options: dict[str, Any] = {}
    if system_profile and target.startswith("linux"):
        if capture_host_body is None:
            fail("CONSUMER_CAPTURE_INPUTS")
        from rs9.nebular070_system_webkit import observe_provider
        system_options = {
            "system_webkit_native_input": raw_release["native_consumer"][target],
            "system_webkit_host_observation_identity": capture_host_body["identity"],
            "system_webkit_host_observation": {
                "identity": capture_host_body["identity"], "role": consumer_host_role,
                "class": "bookworm-floor" if consumer_host_role == "floor" else "ubuntu-newer",
            },
            "system_webkit_provider_observation": observe_provider(target),
        }
    qual_res = qualify_nebular070(
        candidate,
        wheel_path,
        raw_release,
        work_dir,
        expected_artifacts=expected,
        expected_commit=expected_commit,
        expected_tree=tree,
        profile_sha256=prof_sha,
        candidate_receipt_sha256=sha256(canonical(candidate)),
        target=target,
        run_id=run_id,
        run_attempt=run_attempt,
        sandbox_prefix=eff_prefix,
        real_user_state_snapshot=eff_user_state,
        manylinux_stage_a=manylinux_stage_a,
        smoke_support=smoke_support,
        **system_options,
    )
    out_path = Path(output_path)
    if capture_path is None:
        _check_no_symlinks(out_path.parent, "QUALIFY_OUTPUT")
        out_path.parent.mkdir(parents=True, exist_ok=True)
        with out_path.open("xb") as stream:
            stream.write(canonical(qual_res))
        return qual_res

    from rs9.nebular070_public_consumers import (
        PUBLIC_CONSUMER_CAPTURE_SCHEMA,
        consumer_body_from_actual,
    )

    if capture_host_body is None or capture_host_extras is None or capture_wheel is None:
        fail("CONSUMER_CAPTURE_INPUTS")
    capture_body = consumer_body_from_actual(
        qual_res,
        capture_host_body,
        capture_host_extras,
        target=target,
        kind=consumer_host_role,
        wheel=capture_wheel,
    )
    capture_doc = {
        "schema": PUBLIC_CONSUMER_CAPTURE_SCHEMA,
        "evidence_mode": "actual",
        "target": target,
        "kind": consumer_host_role,
        "body": capture_body,
        "qualification": qual_res,
        "host_observation": capture_host_body,
        "host_extras": capture_host_extras,
    }
    # Build and validate both complete documents before either exclusive write,
    # so a projection mismatch cannot leave a status-pass receipt behind.
    qual_bytes = canonical(qual_res)
    capture_bytes = canonical(capture_doc)
    _check_no_symlinks(out_path.parent, "QUALIFY_OUTPUT")
    _check_no_symlinks(capture_path.parent, "CONSUMER_CAPTURE_OUTPUT")
    if out_path.exists():
        fail("QUALIFY_OUTPUT")
    if capture_path.exists():
        fail("CONSUMER_CAPTURE_OUTPUT")
    out_path.parent.mkdir(parents=True, exist_ok=True)
    capture_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open("xb") as stream:
        stream.write(qual_bytes)
    try:
        with capture_path.open("xb") as stream:
            stream.write(capture_bytes)
    except Exception:
        try:
            out_path.unlink()
        except OSError:
            pass
        raise
    return qual_res


def build_candidates_bundle(
    output_dir: str | Path,
    *,
    expected_commit: str,
    repository: str | Path | None = None,
    inrun_root: str | Path | None = None,
    evidence_dir: str | Path | None = None,
    release_binding: Mapping[str, Any] | str | Path | None = None,
    qualification_inputs: Mapping[str, Any] | str | Path | None = None,
    payload_portability: str | Path | None = None,
    tf_producer_source: Mapping[str, str] | None = None,
    require_manylinux: bool = False,
    require_clean: bool = False,
) -> dict[str, Any]:
    """Build 0.7.0 Gate 1 candidate bundle; fail closed when release inputs remain pending."""
    from rs9.operator import release_bindings, validate_release_binding
    from rs9.tf_pypi_nebular_successor import (
        authenticate_gate1_capture,
        build_gate1_candidates,
        write_gate1_receipt,
    )

    root = repo_root(repository)
    commit = _git_output(root, ["rev-parse", "--verify", "HEAD^{commit}"], "HOSTED_COMMIT")
    tree = _git_output(root, ["rev-parse", "--verify", "HEAD^{tree}"], "HOSTED_COMMIT")
    if not _is_hex40(expected_commit) or commit != expected_commit:
        fail("HOSTED_COMMIT")
    if require_clean and _git_output(root, ["status", "--porcelain", "--untracked-files=all"], "HOSTED_COMMIT") != "":
        fail("HOSTED_WORKTREE_DIRTY")

    eff_evidence = evidence_dir
    if eff_evidence is None:
        env_evidence = os.environ.get("RS9_TFNF070_EVIDENCE_DIR", "").strip()
        if env_evidence:
            eff_evidence = Path(env_evidence)
    if eff_evidence is None:
        fail("RELEASE_INPUTS_PENDING")

    descriptor = materialize_qualification_evidence(
        qualification_inputs,
        eff_evidence,
        repository=root,
        phase=QUALIFICATION_INPUT_PHASE_PREP,
        inrun_root=inrun_root,
    )

    system_webkit = "system_webkit" in descriptor
    candidate_profile = SYSTEM_WEBKIT_PROFILE if system_webkit else GATE1_PROFILE
    if system_webkit:
        _validate_system_webkit_input_spec(descriptor["system_webkit"])
        if ("manylinux" in descriptor or require_manylinux
                or payload_portability is not None or tf_producer_source is not None):
            fail("SYSTEM_WEBKIT_INPUT")
    manylinux_spec = descriptor.get("manylinux")
    if require_manylinux:
        if not isinstance(manylinux_spec, Mapping):
            fail("MANYLINUX_INPUT")
        expected_stage_a = (
            Path(eff_evidence).resolve() / manylinux_spec["stage_a"]["path"]
        )
        if payload_portability is None:
            payload_portability = expected_stage_a
        else:
            _check_no_symlinks(Path(payload_portability), "MANYLINUX_INPUT")
            try:
                if Path(payload_portability).resolve() != expected_stage_a:
                    fail("MANYLINUX_INPUT")
            except OSError:
                fail("MANYLINUX_INPUT")
        expected_tf_source = dict(manylinux_spec["tf_producer_source"])
        if tf_producer_source is None:
            tf_producer_source = expected_tf_source
        elif dict(tf_producer_source) != expected_tf_source:
            fail("MANYLINUX_INPUT")

    if release_binding is None:
        env_binding = os.environ.get("RS9_TFNF070_RELEASE_BINDING", "").strip()
        if env_binding:
            rb_path = Path(env_binding)
            _check_no_symlinks(rb_path, "RELEASE_BINDING_SYMLINK")
            if not rb_path.is_file():
                fail("RELEASE_INPUTS_PENDING")
            raw_binding = strict_json(physical_bytes(rb_path, limit=1024 * 1024))
        else:
            raw_binding = descriptor["release_binding"]
    elif isinstance(release_binding, (str, os.PathLike, Path)):
        rb_path = Path(release_binding)
        _check_no_symlinks(rb_path, "RELEASE_BINDING_SYMLINK")
        if not rb_path.is_file():
            fail("RELEASE_INPUTS_PENDING")
        raw_binding = strict_json(physical_bytes(rb_path, limit=1024 * 1024))
    else:
        raw_binding = dict(release_binding)

    if (
        not isinstance(raw_binding, Mapping)
        or raw_binding.get("status") != "ready"
    ):
        fail("RELEASE_INPUTS_PENDING")

    try:
        validated_binding = validate_release_binding(dict(raw_binding))
    except ContractError as exc:
        fail(f"GATE1_{exc.code}")

    if sha256(canonical(validated_binding)) != descriptor["release_binding_sha256"]:
        fail("QUALIFICATION_INPUTS_BINDING")

    bootstrap_rel = validated_binding["bootstrap_path"]
    bootstrap_path = root / bootstrap_rel
    _check_no_symlinks(bootstrap_path, "BOOTSTRAP_SYMLINK")
    if not bootstrap_path.is_file():
        fail("RELEASE_INPUTS_PENDING")
    bootstrap_sha = sha256(physical_bytes(bootstrap_path, limit=1024 * 1024))
    if bootstrap_sha != validated_binding["expected"]["bootstrap_sha256"]:
        fail("GATE1_BOOTSTRAP_DIGEST_MISMATCH")

    stage_a: ValidatedPayloadPortability | None = None
    if payload_portability is not None:
        if tf_producer_source is None:
            fail("MANYLINUX_INPUT")
        stage_a = load_payload_portability_bundle(
            payload_portability,
            expected_tf_producer_source=tf_producer_source,
            expected_rs9_tool_source={"commit": commit, "tree": tree},
        )
    elif require_manylinux:
        fail("MANYLINUX_INPUT")

    out = Path(output_dir)
    _check_no_symlinks(out, "BUNDLE_OUTPUT")
    if out.exists() and (not out.is_dir() or any(out.iterdir())):
        fail("BUNDLE_OUTPUT")
    out.mkdir(parents=True, exist_ok=True)
    cand_dir = out / ".candidates-staging"
    try:
        try:
            authenticated = authenticate_gate1_capture(
                root,
                eff_evidence,
                release_binding=validated_binding,
                approved_bootstrap_sha256=bootstrap_sha,
            )
            receipt = build_gate1_candidates(
                authenticated,
                cand_dir,
                rs9_source_commit=commit,
                rs9_source_tree=tree,
                payload_portability=stage_a,
                candidate_profile=candidate_profile,
            )
            receipt_path = out / "candidate_receipt.json"
            write_gate1_receipt(
                receipt_path,
                receipt,
                authenticated=authenticated,
                output_dir=cand_dir,
                candidate_profile=candidate_profile,
            )
        except ContractError as exc:
            fail(f"GATE1_{exc.code}")

        dist_dir = out / "dist"
        dist_dir.mkdir(parents=True, exist_ok=True)
        wheels_list: list[dict[str, Any]] = []
        for row in receipt["rows"]:
            target = TARGET_BY_SYSTEM[row["system"]]
            src_w = cand_dir / row["system"] / row["wheel"]["filename"]
            dst_w = dist_dir / row["wheel"]["filename"]
            shutil.copyfile(src_w, dst_w)
            expected_wheel = {"target": target, **row["wheel"]}
            if stage_a is not None and target.startswith("linux"):
                construction = {
                    key: row.get(key)
                    for key in (
                        "construction_stage", "release_admission",
                        "manylinux_construction_receipt_sha256",
                    )
                }
                if construction != {
                    "construction_stage": "payload-portability",
                    "release_admission": "external",
                    "manylinux_construction_receipt_sha256": stage_a.digest,
                }:
                    fail("MANYLINUX_INPUT")
                expected_wheel.update(construction)
            wheels_list.append(expected_wheel)
    finally:
        if cand_dir.exists():
            shutil.rmtree(cand_dir)

    wheels_sorted = sorted(wheels_list, key=lambda r: r["target"])
    expected_artifacts = {
        "schema": EXPECTED_ARTIFACT_SCHEMA,
        "candidate_rs9_source": receipt["candidate_rs9_source"],
        "wheels": wheels_sorted,
        "record_sha256": sha256(canonical(wheels_sorted)),
    }
    (out / "expected_artifacts.json").write_bytes(canonical(expected_artifacts))
    if stage_a is not None:
        (out / "payload_portability.json").write_bytes(canonical({
            "schema": (
                ARCHIVE_PORTABILITY_INPUT_SCHEMA
                if stage_a.record.get("schema") == ARCHIVE_PORTABILITY_SCHEMA
                else PORTABILITY_INPUT_SCHEMA
            ),
            "record": stage_a.record,
            "bodies": stage_a.receipt_bodies,
        }))
    _validate_bundle_file_set(out)
    return {
        "candidate_receipt_sha256": sha256(canonical(receipt)),
        "expected_artifact_record_sha256": expected_artifacts["record_sha256"],
        "manylinux_stage_a_sha256": stage_a.digest if stage_a is not None else None,
    }


def _load_system_floor_receipts(path: str | Path | None) -> dict[str, Any] | None:
    if path is None:
        return None
    root = _require_real_directory(path, "MATRIX_RECEIPTS_MISSING")
    targets = tuple(target for target in TARGETS if target.startswith("linux"))
    if sorted(item.name for item in root.iterdir()) != sorted(targets):
        fail("MATRIX_TARGETS_MISMATCH")
    result = {}
    for target in targets:
        target_root = root / target
        _check_no_symlinks(target_root, "MATRIX_RECEIPTS_MISSING")
        result[target] = {
            "qualification": _read_json_object(target_root / "result.json", "MATRIX_RECEIPTS_MISSING"),
            "missing_runtime": _read_json_object(target_root / "missing-runtime.json", "MATRIX_RECEIPTS_MISSING"),
        }
    return result


def parser() -> argparse.ArgumentParser:
    """Build CLI parser for tf_pypi_nebular070_publish operations."""
    p = argparse.ArgumentParser(description=__doc__)
    sub = p.add_subparsers(dest="operation", required=True)

    b_cmd = sub.add_parser("build-candidates")
    b_cmd.add_argument("--output", type=Path, required=True)
    b_cmd.add_argument("--expected-commit", required=True)
    b_cmd.add_argument("--qualification-inputs", type=Path, default=None)
    b_cmd.add_argument("--inrun-root", type=Path, default=None)
    b_cmd.add_argument("--evidence", type=Path, default=None)
    b_cmd.add_argument("--release-binding", type=Path, default=None)
    b_cmd.add_argument("--payload-portability", type=Path, default=None)
    b_cmd.add_argument("--tf-producer-commit", default=None)
    b_cmd.add_argument("--tf-producer-tree", default=None)
    b_cmd.add_argument("--require-manylinux", action="store_true")
    b_cmd.add_argument("--require-clean", action="store_true")

    negative = sub.add_parser("check-system-webkit-missing")
    negative.add_argument("--bundle", type=Path, required=True)
    negative.add_argument("--target", choices=("linux-arm64-gnu", "linux-x64-gnu"), required=True)
    negative.add_argument("--work", type=Path, required=True)
    negative.add_argument("--output", type=Path, required=True)
    negative.add_argument("--expected-commit", required=True)
    negative.add_argument("--run-id", required=True)
    negative.add_argument("--run-attempt", required=True)

    pi_cmd = sub.add_parser("prepare-public-inputs-070")
    pi_cmd.add_argument("--manifest", type=Path, default=PUBLIC_INPUTS_MANIFEST_PATH)
    pi_cmd.add_argument("--output", type=Path, required=True)
    pi_cmd.add_argument("--repository", type=Path, default=None)
    pi_cmd.add_argument("--stage-a-spec", default=PUBLIC_STAGE_A_SPEC)
    pi_cmd.add_argument("--rs9-commit", required=True)
    pi_cmd.add_argument("--rs9-tree", required=True)
    pi_cmd.add_argument("--tf-producer-commit", default=PUBLIC_TF_PRODUCER_SOURCE["commit"])
    pi_cmd.add_argument("--tf-producer-tree", default=PUBLIC_TF_PRODUCER_SOURCE["tree"])

    mi_cmd = sub.add_parser("materialize-manylinux-inputs")
    mi_cmd.add_argument("--qualification-inputs", type=Path, required=True)
    mi_cmd.add_argument("--evidence", type=Path, required=True)
    mi_cmd.add_argument("--inrun-root", type=Path, default=None)
    mi_cmd.add_argument(
        "--phase",
        choices=sorted(QUALIFICATION_INPUT_PHASES),
        default=QUALIFICATION_INPUT_PHASE_PUBLICATION,
    )

    mc_cmd = sub.add_parser("materialize-manylinux-consumers")
    mc_cmd.add_argument("--admission", type=Path, required=True)
    mc_cmd.add_argument("--output", type=Path, required=True)

    q_cmd = sub.add_parser("qualify-native")
    q_cmd.add_argument("--target", choices=TARGETS, required=True)
    q_cmd.add_argument("--qualification-inputs", type=Path, default=None)
    q_cmd.add_argument("--inrun-root", type=Path, default=None)
    q_cmd.add_argument("--bundle", type=Path, required=True)
    q_cmd.add_argument("--work", type=Path, required=True)
    q_cmd.add_argument("--output", type=Path, required=True)
    q_cmd.add_argument("--expected-commit", required=True)
    q_cmd.add_argument("--run-id", required=True)
    q_cmd.add_argument("--run-attempt", required=True)
    q_cmd.add_argument("--raw-release", type=Path, default=None)
    q_cmd.add_argument(
        "--consumer-host-role",
        choices=MANYLINUX_CONSUMER_KINDS,
        default=None,
        help="Opt in to one actual Linux Stage-B host capture (floor or newer).",
    )
    q_cmd.add_argument(
        "--consumer-capture-output",
        type=Path,
        default=None,
        help="Exclusive output path for the opt-in actual Stage-B capture envelope.",
    )

    m_cmd = sub.add_parser("admit-matrix")
    m_cmd.add_argument("--bundle", type=Path, required=True)
    m_cmd.add_argument("--receipts-dir", type=Path, required=True)
    m_cmd.add_argument("--system-floor-receipts", type=Path, default=None)
    m_cmd.add_argument("--output", type=Path, required=True)
    m_cmd.add_argument("--expected-commit", required=True)
    m_cmd.add_argument("--qualification-inputs", type=Path, default=None)
    m_cmd.add_argument("--inrun-root", type=Path, default=None)
    m_cmd.add_argument("--run-id", required=True)
    m_cmd.add_argument("--run-attempt", required=True)

    ma_cmd = sub.add_parser("admit-manylinux")
    ma_cmd.add_argument("--approval", type=Path, required=True)
    ma_cmd.add_argument("--dist", type=Path, required=True)
    ma_cmd.add_argument("--payload-portability", type=Path, required=True)
    ma_cmd.add_argument("--manylinux-admission", type=Path, required=True)
    ma_cmd.add_argument("--manylinux-consumer-receipts", type=Path, required=True)
    ma_cmd.add_argument("--tf-producer-commit", required=True)
    ma_cmd.add_argument("--tf-producer-tree", required=True)
    ma_cmd.add_argument("--output", type=Path, required=True)

    vp_cmd = sub.add_parser("validate-portability")
    vp_cmd.add_argument("--input", type=Path, required=True)
    vp_cmd.add_argument("--tf-producer-commit", required=True)
    vp_cmd.add_argument("--tf-producer-tree", required=True)
    vp_cmd.add_argument("--rs9-commit", required=True)
    vp_cmd.add_argument("--rs9-tree", required=True)

    vs_cmd = sub.add_parser("verify-source")
    vs_cmd.add_argument("--publisher-dir", type=Path, required=True)
    vs_cmd.add_argument("--qualification-dir", type=Path, required=True)
    vs_cmd.add_argument("--publisher-revision", required=True)

    pr_cmd = sub.add_parser("prepare-resume")
    pr_cmd.add_argument("--publisher-dir", type=Path, default=None)
    pr_cmd.add_argument("--qualification-dir", type=Path, default=None)
    pr_cmd.add_argument("--qualification-inputs", type=Path, default=None)
    pr_cmd.add_argument("--inrun-root", type=Path, default=None)
    pr_cmd.add_argument("--api-dir", type=Path, required=True)
    pr_cmd.add_argument("--archives-dir", type=Path, required=True)
    pr_cmd.add_argument("--output", type=Path, required=True)

    sm_cmd = sub.add_parser("stage-metadata")
    sm_cmd.add_argument("--publisher-dir", type=Path, required=True)
    sm_cmd.add_argument("--qualification-dir", type=Path, required=True)

    sel_cmd = sub.add_parser("select-missing")
    sel_cmd.add_argument("--dist", type=Path, default=Path("dist"))
    sel_cmd.add_argument("--upload-dir", type=Path, default=Path("upload"))
    sel_cmd.add_argument("--candidate-receipt", type=Path, required=True)
    sel_cmd.add_argument("--expected-artifacts", type=Path, required=True)
    sel_cmd.add_argument("--receipts-dir", type=Path, required=True)
    sel_cmd.add_argument("--attempt-marker", type=Path, default=None)
    sel_cmd.add_argument("--manylinux-admission", type=Path, default=None)
    sel_cmd.add_argument("--payload-portability", type=Path, default=None)
    sel_cmd.add_argument("--manylinux-consumer-receipts", type=Path, default=None)
    sel_cmd.add_argument("--qualification-inputs", type=Path, default=None)
    sel_cmd.add_argument("--inrun-root", type=Path, default=None)
    sel_cmd.add_argument("--tf-producer-commit", default=None)
    sel_cmd.add_argument("--tf-producer-tree", default=None)

    vu_cmd = sub.add_parser("verify-upload")
    vu_cmd.add_argument("--dist", type=Path, default=Path("dist"))
    vu_cmd.add_argument("--upload-dir", type=Path, default=Path("upload"))
    vu_cmd.add_argument("--manylinux-admission", type=Path, default=None)
    vu_cmd.add_argument("--payload-portability", type=Path, default=None)
    vu_cmd.add_argument("--manylinux-consumer-receipts", type=Path, default=None)
    vu_cmd.add_argument("--matrix-receipt", type=Path, default=None)
    vu_cmd.add_argument("--qualification-inputs", type=Path, default=None)
    vu_cmd.add_argument("--inrun-root", type=Path, default=None)
    vu_cmd.add_argument("--tf-producer-commit", default=None)
    vu_cmd.add_argument("--tf-producer-tree", default=None)

    rb_cmd = sub.add_parser("readback")
    rb_cmd.add_argument("--dist", type=Path, default=Path("dist"))

    ms_cmd = sub.add_parser("resolve-manylinux-source")
    ms_cmd.add_argument("--payload-portability", type=Path, required=True)

    vd_cmd = sub.add_parser("validate-dispatch")
    vd_cmd.add_argument("--release", required=True)
    vd_cmd.add_argument("--mode", required=True)

    wf_cmd = sub.add_parser("workflow")
    wf_cmd.add_argument("--release", choices=("0.6.1", "0.7.0"), default="0.7.0")
    return p


def main(
    argv: Sequence[str] | None = None,
    *,
    get: Callable[[str], bytes] | None = None,
) -> int:
    """CLI entrypoint for tf_pypi_nebular070_publish; emits code-only stderr on failure."""
    args = parser().parse_args(argv)
    try:
        if args.operation == "build-candidates":
            res = build_candidates_bundle(
                args.output,
                expected_commit=args.expected_commit,
                evidence_dir=args.evidence,
                inrun_root=args.inrun_root,
                release_binding=args.release_binding,
                qualification_inputs=args.qualification_inputs,
                payload_portability=args.payload_portability,
                tf_producer_source=(
                    {"commit": args.tf_producer_commit, "tree": args.tf_producer_tree}
                    if args.tf_producer_commit and args.tf_producer_tree else None
                ),
                require_manylinux=args.require_manylinux,
                require_clean=args.require_clean,
            )
            sys.stdout.write(canonical(res).decode("utf-8"))
            return 0
        if args.operation == "check-system-webkit-missing":
            from rs9.nebular070_system_webkit import check_missing_runtime
            bundle = _require_real_directory(args.bundle, "BUNDLE_DIR")
            _validate_bundle_file_set(bundle)
            candidate = _read_json_object(bundle / "candidate_receipt.json", "CANDIDATE_RECEIPT_SCHEMA")
            if candidate.get("profile") != gate1_profile_record(SYSTEM_WEBKIT_PROFILE):
                fail("SYSTEM_WEBKIT_INPUT")
            root = repo_root()
            commit = _git_output(root, ["rev-parse", "--verify", "HEAD^{commit}"], "HOSTED_COMMIT")
            tree = _git_output(root, ["rev-parse", "--verify", "HEAD^{tree}"], "HOSTED_COMMIT")
            if commit != args.expected_commit:
                fail("HOSTED_COMMIT_MISMATCH")
            if (args.run_attempt != "1" or not re.fullmatch(r"[1-9][0-9]*", args.run_id)):
                fail("HOSTED_COMMIT_RUN_COORDINATES")
            row = next(row for row in candidate["rows"] if row["system"] == SYSTEM_BY_TARGET[args.target])
            wheel = bundle / "dist" / row["wheel"]["filename"]
            if sha256(physical_bytes(wheel, limit=MAX_WHEEL_FILE_BYTES)) != row["wheel"]["sha256"]:
                fail("WHEEL_SHA256")
            result = check_missing_runtime(
                wheel, args.work, target=args.target, source={"commit": commit, "tree": tree},
                run_id=args.run_id, run_attempt=args.run_attempt,
                prefix=default_sandbox_prefix(args.target),
            )
            output = args.output
            _check_no_symlinks(output, "QUALIFY_OUTPUT")
            output.parent.mkdir(parents=True, exist_ok=True)
            with output.open("xb") as stream:
                stream.write(canonical(result))
            return 0
        if args.operation == "prepare-public-inputs-070":
            res = prepare_public_inputs_070(
                args.manifest,
                args.output,
                repository=args.repository,
                stage_a_spec=args.stage_a_spec,
                rs9_source={"commit": args.rs9_commit, "tree": args.rs9_tree},
                tf_producer_source={
                    "commit": args.tf_producer_commit,
                    "tree": args.tf_producer_tree,
                },
            )
            sys.stdout.write(canonical(res).decode("utf-8"))
            return 0
        if args.operation == "materialize-manylinux-inputs":
            res = materialize_manylinux_inputs(
                args.qualification_inputs,
                args.evidence,
                phase=args.phase,
                inrun_root=args.inrun_root,
            )
            for key in ("stage_a", "stage_b", "tf_producer_commit", "tf_producer_tree"):
                if key in res:
                    sys.stdout.write(f"{key}={res[key]}\n")
            return 0
        if args.operation == "materialize-manylinux-consumers":
            materialize_manylinux_consumer_receipts(args.admission, args.output)
            return 0
        if args.operation == "qualify-native":
            qualify_native_target(
                args.bundle,
                args.work,
                args.output,
                target=args.target,
                expected_commit=args.expected_commit,
                run_id=args.run_id,
                run_attempt=args.run_attempt,
                raw_release_path=args.raw_release,
                qualification_inputs=args.qualification_inputs,
                inrun_root=args.inrun_root,
                consumer_host_role=args.consumer_host_role,
                consumer_capture_output=args.consumer_capture_output,
            )
            return 0
        if args.operation == "admit-matrix":
            bundle = _require_real_directory(args.bundle, "BUNDLE_DIR")
            _validate_bundle_file_set(bundle)
            cand_file = bundle / "candidate_receipt.json"
            exp_file = bundle / "expected_artifacts.json"
            candidate = strict_json(physical_bytes(cand_file, limit=4 * 1024 * 1024))
            expected = strict_json(physical_bytes(exp_file, limit=1024 * 1024))
            prof_sha = _require_candidate_profile_sha(candidate)
            root = repo_root()
            tree = _git_output(root, ["rev-parse", "--verify", "HEAD^{tree}"], "HOSTED_COMMIT")
            descriptor = (
                load_qualification_inputs_descriptor(
                    args.qualification_inputs,
                    repository=root,
                    pending_code="RELEASE_INPUTS_PENDING",
                    phase=QUALIFICATION_INPUT_PHASE_PREP,
                    inrun_root=args.inrun_root,
                )
                if args.qualification_inputs is not None
                else None
            )
            manylinux_stage_a = _load_candidate_stage_a(
                bundle,
                descriptor,
                expected_commit=args.expected_commit,
                expected_tree=tree,
            )
            matrix = admit_nebular070_matrix(
                candidate,
                expected,
                args.receipts_dir,
                expected_commit=args.expected_commit,
                expected_tree=tree,
                profile_sha256=prof_sha,
                candidate_receipt_sha256=sha256(canonical(candidate)),
                run_id=args.run_id,
                run_attempt=args.run_attempt,
                system_floor_receipts=_load_system_floor_receipts(args.system_floor_receipts),
                manylinux_stage_a=manylinux_stage_a,
            )
            out_path = Path(args.output)
            _check_no_symlinks(out_path.parent, "MATRIX_OUTPUT")
            out_path.parent.mkdir(parents=True, exist_ok=True)
            with out_path.open("xb") as stream:
                stream.write(canonical(matrix))
            return 0
        if args.operation == "admit-manylinux":
            approval = load_approval(path=args.approval)
            result = _validate_manylinux_admission_files(
                args.manylinux_admission,
                payload_portability=args.payload_portability,
                consumer_receipts=args.manylinux_consumer_receipts,
                tf_producer_source={"commit": args.tf_producer_commit, "tree": args.tf_producer_tree},
                approved=approval,
                dist=args.dist,
            )
            out_path = Path(args.output)
            _check_no_symlinks(out_path.parent, "MANYLINUX_ADMISSION_OUTPUT")
            out_path.parent.mkdir(parents=True, exist_ok=True)
            with out_path.open("xb") as stream:
                stream.write(canonical(result.record))
            return 0
        if args.operation == "validate-portability":
            stage_a = load_payload_portability_bundle(
                args.input,
                expected_tf_producer_source={"commit": args.tf_producer_commit, "tree": args.tf_producer_tree},
                expected_rs9_tool_source={"commit": args.rs9_commit, "tree": args.rs9_tree},
            )
            sys.stdout.write(canonical({
                "schema": "rs9.nebular070-payload-portability-validation-v1",
                "status": "validated",
                "digest": stage_a.digest,
                "targets": [row["target"] for row in stage_a.record["targets"]],
            }).decode("utf-8"))
            return 0
        if args.operation == "verify-source":
            res = verify_source_lineage(
                args.publisher_dir,
                args.qualification_dir,
                publisher_revision=args.publisher_revision,
            )
            sys.stdout.write(canonical(res).decode("utf-8"))
            return 0
        if args.operation == "prepare-resume":
            res = prepare_resume(
                args.api_dir,
                args.archives_dir,
                args.output,
                publisher_dir=args.publisher_dir,
                qualification_dir=args.qualification_dir,
                qualification_inputs=args.qualification_inputs,
                inrun_root=args.inrun_root,
            )
            sys.stdout.write(canonical(res).decode("utf-8"))
            return 0
        if args.operation == "stage-metadata":
            res = stage_metadata(args.publisher_dir, args.qualification_dir)
            sys.stdout.write(canonical(res).decode("utf-8"))
            return 0
        if args.operation == "select-missing":
            res = select_missing(
                args.dist,
                args.upload_dir,
                candidate_receipt=args.candidate_receipt,
                expected_artifacts=args.expected_artifacts,
                receipts_dir=args.receipts_dir,
                get=get,
                attempt_marker=args.attempt_marker,
                manylinux_admission=args.manylinux_admission,
                payload_portability=args.payload_portability,
                manylinux_consumer_receipts=args.manylinux_consumer_receipts,
                qualification_inputs=args.qualification_inputs,
                inrun_root=args.inrun_root,
                tf_producer_source=(
                    {"commit": args.tf_producer_commit, "tree": args.tf_producer_tree}
                    if args.tf_producer_commit and args.tf_producer_tree else None
                ),
            )
            print(f"upload={'true' if res['upload'] else 'false'}")
            print(f"state={res['state']}")
            return 0
        if args.operation == "verify-upload":
            captured_matrix = (
                load_captured_matrix_receipt(args.matrix_receipt)
                if args.matrix_receipt is not None
                else None
            )
            verify_upload_dir(
                args.dist,
                args.upload_dir,
                manylinux_admission=args.manylinux_admission,
                payload_portability=args.payload_portability,
                manylinux_consumer_receipts=args.manylinux_consumer_receipts,
                captured_matrix=captured_matrix,
                qualification_inputs=args.qualification_inputs,
                inrun_root=args.inrun_root,
                tf_producer_source=(
                    {"commit": args.tf_producer_commit, "tree": args.tf_producer_tree}
                    if args.tf_producer_commit and args.tf_producer_tree else None
                ),
            )
            return 0
        if args.operation == "readback":
            res = readback(args.dist, get=get)
            sys.stdout.write(canonical(res).decode("utf-8"))
            return 0
        if args.operation == "resolve-manylinux-source":
            path = Path(args.payload_portability)
            _check_no_symlinks(path, "MANYLINUX_INPUT")
            envelope = _read_json_object(path, "MANYLINUX_INPUT", limit=16 * 1024 * 1024)
            record = envelope.get("record")
            source = record.get("tf_producer_source") if isinstance(record, Mapping) else None
            if (
                not isinstance(source, Mapping)
                or not _is_hex40(source.get("commit"))
                or not _is_hex40(source.get("tree"))
            ):
                fail("MANYLINUX_INPUT")
            sys.stdout.write(f"tf_producer_commit={source['commit']}\n")
            sys.stdout.write(f"tf_producer_tree={source['tree']}\n")
            return 0
        if args.operation == "validate-dispatch":
            res = validate_workflow_dispatch(args.release, args.mode)
            sys.stdout.write(canonical(res).decode("utf-8"))
            return 0
        if args.operation == "workflow":
            sys.stdout.write(workflow_text(release=args.release))
            return 0
        fail("CLI_OPERATION")
    except AdmissionError as exc:
        sys.stderr.write(f"{exc.code}\n")
        return 1
    except ContractError as exc:
        sys.stderr.write(f"TF_PYPI_{exc.code}\n")
        return 1
    except (OSError, ValueError, KeyError, TypeError, RuntimeError, subprocess.SubprocessError):
        sys.stderr.write("TF_PYPI_OPERATION_FAILED\n")
        return 1
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
