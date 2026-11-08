"""Closed publication coordinates for the Nebular 0.8 universal route."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from rs9.nebular080_universal_profile import (
    ARTIFACT_PREFIX,
    DIST,
    LINUX_TARGETS,
    PRODUCT,
    REPOSITORY,
    SCHEMAS,
    TAG,
    TARGETS,
    VERSION,
    WORKFLOW,
)


PROJECT = PRODUCT
PACKAGE_NAME = DIST
DISTRIBUTION_NAME = "theme-forge-nebular-fusion"
DISTRIBUTION_WHEEL_PREFIX = DIST
DISTRIBUTION_VERSION = VERSION
ENVIRONMENT = "pypi"
DEFAULT_GITHUB_REPOSITORY = "Knowledge-Forge-AI/release-starport-9"
UNIVERSAL_DISPATCH_REF = "refs/heads/main"
WORKFLOW_PUSH_BRANCH = "rs9-tfnf-pypi-hostqual1"
QUALIFY_BRANCH = WORKFLOW_PUSH_BRANCH

EXPECTED_COMMAND = "tfnf"
EXPECTED_REQUIRES_PYTHON = ">=3.11"
EXPECTED_LICENSE_EXPRESSION = "AGPL-3.0-or-later"
EXPECTED_REQUIRED_LICENSE_FILES = ("LICENSE", "NOTICE")
EXPECTED_OPTIONAL_LICENSE_FILES = ("COMMERCIAL-LICENSE.md",)
# Compatibility names consumed by the actual publication owner.  The
# EXPECTED_* names remain the source of truth for descriptor validation.
REQUIRES_PYTHON = EXPECTED_REQUIRES_PYTHON
LICENSE_EXPRESSION = EXPECTED_LICENSE_EXPRESSION

DESCRIPTION_BASENAME = "nebular-fusion-0.8.0.md"
DESCRIPTION_PATH = Path("operators/tf-pypi/descriptions") / DESCRIPTION_BASENAME
RUNTIME_INPUTS = Path("operators/tf-pypi/nebular-fusion-0.8.0-universal-runtime-inputs.json")
DESCRIPTION = Path("operators/tf-pypi/descriptions/nebular-fusion-0.8.0-universal.md")
SYSTEM_WEBKIT_DESCRIPTION_PATH = Path(
    "operators/tf-pypi/descriptions/nebular-fusion-0.8.0-system-webkitgtk.md"
)
GATE1_PROFILE_PATH = Path("operators/tf-pypi/theme-forge-nebular-fusion-0.8.0-gate1.json")
PIN_BASENAME = "theme-forge-nebular-fusion-0.8.0.json"
PIN_PATH = Path("operators/tf-pypi") / PIN_BASENAME
APPROVAL_BASENAME = "theme-forge-nebular-fusion-0.8.0-artifacts.json"
APPROVAL_PATH = Path("operators/tf-pypi") / APPROVAL_BASENAME
CAPTURE_BASENAME = "theme-forge-nebular-fusion-0.8.0-qualification.json"
CAPTURE_PATH = Path("operators/tf-pypi") / CAPTURE_BASENAME
QUALIFICATION_INPUTS_BASENAME = "theme-forge-nebular-fusion-0.8.0-qualification-inputs.json"
QUALIFICATION_INPUTS_PATH = Path("operators/tf-pypi") / QUALIFICATION_INPUTS_BASENAME
PUBLIC_INPUTS_MANIFEST_PATH = Path(
    "operators/tf-pypi/theme-forge-nebular-fusion-0.8.0-public-inputs.json"
)
PUBLIC_INPUTS_ARTIFACT = "tfnf-080-public-inputs"
PUBLIC_INPUTS_TEMPLATE_DESCRIPTOR = "qualification-inputs.json"
PUBLIC_INPUTS_DESCRIPTOR = "qualification-inputs-prep.json"
PUBLIC_STAGE_A_SPEC = "stage-a-files.json"
PUBLIC_STAGE_A_OUTPUT = "evidence/public-release/generated-stage-a"
PUBLIC_INPUTS_PREPARATION_RECEIPT = "public-inputs-preparation.json"
PUBLIC_INPUTS_PREPARATION_SCHEMA = "rs9.tf-pypi-nebular080-public-inputs-preparation.v1"
SYSTEM_PUBLIC_INPUTS_PREPARATION_SCHEMA = "rs9.tf-pypi-nebular080-public-inputs-preparation.v2"

PIN_SCHEMA = "rs9.tf-pypi-nebular-publication.v1"
APPROVAL_SCHEMA = "rs9.tf-pypi-nebular080-artifacts.v1"
CAPTURE_SCHEMA = "rs9.tf-pypi-nebular080-qualification-capture.v1"
QUALIFICATION_INPUTS_SCHEMA = "rs9.tf-pypi-nebular080-qualification-inputs.v1"
RAW_RELEASE_HANDOFF_SCHEMA = "rs9.tf-pypi-nebular080-raw-release-handoff.v1"
CANDIDATE_RECEIPT_SCHEMA = "rs9.nebular080-successor-candidate.v2alpha1"
EXPECTED_ARTIFACT_SCHEMA = SCHEMAS["bundle"]
MATRIX_RECEIPT_SCHEMA = SCHEMAS["matrix"]
BUNDLE_SCHEMA = EXPECTED_ARTIFACT_SCHEMA
MATRIX_SCHEMA = MATRIX_RECEIPT_SCHEMA
PROVENANCE_SCHEMA = "rs9.wheel-provenance.v3alpha1"

SYSTEM_BY_TARGET = {
    "darwin-arm64": "aarch64-darwin",
    "linux-arm64-gnu": "aarch64-linux",
    "linux-x64-gnu": "x86_64-linux",
}
TARGET_BY_SYSTEM = {value: key for key, value in SYSTEM_BY_TARGET.items()}
TARGET_TRIPLE_BY_TARGET = {
    "darwin-arm64": "aarch64-apple-darwin",
    "linux-arm64-gnu": "aarch64-unknown-linux-gnu",
    "linux-x64-gnu": "x86_64-unknown-linux-gnu",
}
TAG_BY_TARGET = {
    "darwin-arm64": "py3-none-macosx_13_3_arm64",
    "linux-arm64-gnu": "py3-none-linux_aarch64",
    "linux-x64-gnu": "py3-none-linux_x86_64",
}
EXPECTED_WHEEL_FILENAMES = {
    target: f"{DISTRIBUTION_WHEEL_PREFIX}-{DISTRIBUTION_VERSION}-{TAG_BY_TARGET[target]}.whl"
    for target in TARGETS
}
TARGET_BY_FILENAME = {value: key for key, value in EXPECTED_WHEEL_FILENAMES.items()}

CANDIDATE_BUNDLE_ARTIFACT = f"{ARTIFACT_PREFIX}candidate-bundle"
TARGET_QUALIFICATION_ARTIFACTS = {
    target: f"{ARTIFACT_PREFIX}qualification-{target}" for target in TARGETS
}
FLOOR_TARGET_QUALIFICATION_ARTIFACTS = {
    target: f"{ARTIFACT_PREFIX}qualification-{target}-floor" for target in LINUX_TARGETS
}
MATRIX_RECEIPT_ARTIFACT = f"{ARTIFACT_PREFIX}matrix-receipt"
MATRIX_RECEIPT_MEMBER = "matrix_receipt.json"
REQUIRED_CAPTURE_ARTIFACTS = (
    CANDIDATE_BUNDLE_ARTIFACT,
    TARGET_QUALIFICATION_ARTIFACTS["darwin-arm64"],
    TARGET_QUALIFICATION_ARTIFACTS["linux-arm64-gnu"],
    TARGET_QUALIFICATION_ARTIFACTS["linux-x64-gnu"],
    MATRIX_RECEIPT_ARTIFACT,
)
REQUIRED_RESUME_FILES = (PIN_BASENAME, APPROVAL_BASENAME, CAPTURE_BASENAME)
QUALIFICATION_SOURCE_HELPERS = (
    "src/rs9/tf_pypi_nebular080_publish.py",
    "src/rs9/nebular080_universal_profile.py",
    "src/rs9/nebular080_universal_consumer.py",
    "src/rs9/nebular080_smoke_support.py",
)

REQUIRED_QUALIFICATION_INPUTS_KEYS = frozenset({
    "schema", "project", "version", "distribution_version", "workflow", "status",
    "upstream_origin", "release_binding", "release_binding_sha256", "evidence", "raw_release",
})
OPTIONAL_QUALIFICATION_INPUTS_KEYS = frozenset({"system_webkit", "manylinux"})
SYSTEM_WEBKIT_INPUT_SCHEMA = "rs9.tf-pypi-nebular080-public-inrun-system-webkit.v1"
SYSTEM_WEBKIT_PROFILE_ID = "nebular-fusion-0.8.0-system-webkitgtk-4.1-v1"
SYSTEM_WEBKIT_RUNTIME_PROFILE = "system-webkitgtk-4.1"
SYSTEM_WEBKIT_INPUT_KEYS = frozenset({"schema", "origin_kind", "profile_id"})
MANYLINUX_INPUT_SPEC_KEYS = frozenset({"stage_a", "stage_b", "tf_producer_source"})
PUBLIC_INRUN_MANYLINUX_SCHEMA = "rs9.tf-pypi-nebular080-public-inrun-manylinux.v1"
PUBLIC_INRUN_MANYLINUX_ORIGIN_KIND = "public-in-run"
QUALIFICATION_INPUT_PHASE_PREP = "qualification-prep"
QUALIFICATION_INPUT_PHASE_PUBLICATION = "publication"
QUALIFICATION_INPUT_PHASES = frozenset({QUALIFICATION_INPUT_PHASE_PREP, QUALIFICATION_INPUT_PHASE_PUBLICATION})

PUBLIC_INPUTS_ARTIFACT_MAX_BYTES = 1024 * 1024 * 1024 + 64 * 1024 * 1024
MAX_WHEEL_FILE_BYTES = 512 * 1024 * 1024
MAX_PAYLOAD_UNCOMPRESSED_BYTES = 2 * 1024 * 1024 * 1024
MAX_TOTAL_UNCOMPRESSED_BYTES = 3 * 1024 * 1024 * 1024
MAX_ZIP_MEMBERS = 64
MAX_AUTHORITY_BYTES = 2 * 1024 * 1024
MAX_API_BYTES = 4 * 1024 * 1024
MAX_MARKER_BYTES = 256 * 1024
MAX_METADATA_BYTES = 4 * 1024 * 1024
MAX_SMALL_ARCHIVE_BYTES = 32 * 1024 * 1024
MAX_SMALL_MEMBER_BYTES = 8 * 1024 * 1024
MAX_INPUTS_ARCHIVE_BYTES = 1024 * 1024 * 1024 + 64 * 1024 * 1024
# The public-inputs archive carries the three authenticated native payloads;
# each is below 64 MiB but above the legacy 32 MiB member ceiling.  This is
# isolated to the 0.8 public-input artifact; small-artifact and aggregate
# limits remain unchanged.
MAX_INPUTS_MEMBER_BYTES = 64 * 1024 * 1024
MAX_INPUTS_FILES = 4096
MAX_JOBS = 64
READBACK_SCHEDULE_SECONDS = (0, 15, 30, 60, 120, 180)
READBACK_SCHEDULE = READBACK_SCHEDULE_SECONDS
PRIOR_RUN_PAGE_SIZE = 100
PRIOR_RUN_MAX_PAGES = 20

AUTHORITY = "rs9.nebular080-universal-publication"
SCHEMA = SCHEMAS["publication"]
MARKER_SCHEMA = "rs9.nebular080-publication-marker.v1"
READBACK_SCHEMA = SCHEMAS["readback"]
PUBLIC_INPUTS = PUBLIC_INPUTS_ARTIFACT
BUNDLE = CANDIDATE_BUNDLE_ARTIFACT
QUALIFICATION = TARGET_QUALIFICATION_ARTIFACTS
FLOOR = FLOOR_TARGET_QUALIFICATION_ARTIFACTS
MATRIX = MATRIX_RECEIPT_ARTIFACT
MATRIX_MEMBER = MATRIX_RECEIPT_MEMBER
DESCRIPTOR_MEMBER = PUBLIC_INPUTS_DESCRIPTOR
ARTIFACTS = REQUIRED_CAPTURE_ARTIFACTS
PUBLISH_JOB = "Trusted Publishing to PyPI (Nebular 0.8.0)"
UPLOAD_STEP = "Upload Nebular 0.8.0 distribution"
GUARD_JOB = "reject_unsupported_dispatch"
VALID_WORKFLOW_RUN_CONCLUSIONS = frozenset({"success", "failure", "cancelled", "timed_out"})
VALID_WORKFLOW_JOB_CONCLUSIONS = frozenset({"success", "failure", "cancelled", "skipped", "timed_out"})
ACTIVE_FAILURE_CONCLUSIONS = frozenset({"failure", "cancelled", "timed_out"})


@dataclass(frozen=True)
class PublicationCoordinates:
    project: str
    package_name: str
    distribution: str
    version: str
    tag: str
    repository: str
    workflow: str
    dispatch_ref: str
    environment: str


NEBULAR080_COORDINATES = PublicationCoordinates(
    PROJECT, PACKAGE_NAME, DISTRIBUTION_NAME, VERSION, TAG, DEFAULT_GITHUB_REPOSITORY,
    WORKFLOW, UNIVERSAL_DISPATCH_REF, ENVIRONMENT,
)

