"""Version-closed publication and universal route for Nebular 0.8.0."""

from __future__ import annotations

import argparse
import os
from collections.abc import Callable, Mapping, Sequence
from pathlib import Path
import re
import sys
from typing import Any

from rs9.nebular_history_guard import (
    KNOWN_HISTORY_ANCHOR_RUN_IDS,
    MAX_PAGES as PRIOR_RUN_MAX_PAGES,
    PAGE_SIZE as PRIOR_RUN_PAGE_SIZE,
    _parse_title_and_inputs,
    check_prior_runs,
    fetch_paginated_github_list,
)
from rs9.tf_pypi_archive import AdmissionError, canonical

from rs9.nebular080_publication_coordinates import (
    ACTIVE_FAILURE_CONCLUSIONS,
    APPROVAL_BASENAME,
    APPROVAL_PATH,
    APPROVAL_SCHEMA,
    ARTIFACTS,
    AUTHORITY,
    BUNDLE_SCHEMA,
    BUNDLE,
    CANDIDATE_BUNDLE_ARTIFACT,
    CANDIDATE_RECEIPT_SCHEMA,
    CAPTURE_BASENAME,
    CAPTURE_PATH,
    CAPTURE_SCHEMA,
    DEFAULT_GITHUB_REPOSITORY,
    DESCRIPTION_BASENAME,
    DESCRIPTION,
    DESCRIPTION_PATH,
    DESCRIPTOR_MEMBER,
    DISTRIBUTION_NAME,
    DISTRIBUTION_VERSION,
    DISTRIBUTION_WHEEL_PREFIX,
    ENVIRONMENT,
    EXPECTED_ARTIFACT_SCHEMA,
    EXPECTED_COMMAND,
    EXPECTED_LICENSE_EXPRESSION,
    EXPECTED_OPTIONAL_LICENSE_FILES,
    EXPECTED_REQUIRED_LICENSE_FILES,
    EXPECTED_REQUIRES_PYTHON,
    EXPECTED_WHEEL_FILENAMES,
    FLOOR,
    FLOOR_TARGET_QUALIFICATION_ARTIFACTS,
    GATE1_PROFILE_PATH,
    GUARD_JOB,
    LINUX_TARGETS,
    MARKER_SCHEMA,
    MATRIX,
    MATRIX_MEMBER,
    MATRIX_SCHEMA,
    MATRIX_RECEIPT_ARTIFACT,
    MATRIX_RECEIPT_SCHEMA,
    MANYLINUX_INPUT_SPEC_KEYS,
    MAX_API_BYTES,
    MAX_AUTHORITY_BYTES,
    MAX_INPUTS_ARCHIVE_BYTES,
    MAX_INPUTS_FILES,
    MAX_INPUTS_MEMBER_BYTES,
    MAX_JOBS,
    MAX_MARKER_BYTES,
    MAX_METADATA_BYTES,
    MAX_PAYLOAD_UNCOMPRESSED_BYTES,
    MAX_SMALL_ARCHIVE_BYTES,
    MAX_SMALL_MEMBER_BYTES,
    MAX_TOTAL_UNCOMPRESSED_BYTES,
    MAX_WHEEL_FILE_BYTES,
    MAX_ZIP_MEMBERS,
    NEBULAR080_COORDINATES,
    PACKAGE_NAME,
    PIN_BASENAME,
    PIN_PATH,
    PIN_SCHEMA,
    PROJECT,
    PUBLIC_INPUTS,
    PUBLIC_INPUTS_ARTIFACT,
    PUBLIC_INPUTS_ARTIFACT_MAX_BYTES,
    PUBLIC_INPUTS_DESCRIPTOR,
    PUBLIC_INPUTS_MANIFEST_PATH,
    PUBLIC_INPUTS_PREPARATION_RECEIPT,
    PUBLIC_INPUTS_PREPARATION_SCHEMA,
    PUBLIC_INPUTS_TEMPLATE_DESCRIPTOR,
    RUNTIME_INPUTS,
    PUBLIC_STAGE_A_OUTPUT,
    QUALIFICATION,
    QUALIFICATION_INPUTS_BASENAME,
    QUALIFICATION_INPUTS_PATH,
    QUALIFICATION_INPUTS_SCHEMA,
    QUALIFICATION_INPUT_PHASE_PREP,
    QUALIFICATION_INPUT_PHASE_PUBLICATION,
    QUALIFY_BRANCH,
    RAW_RELEASE_HANDOFF_SCHEMA,
    READBACK_SCHEDULE_SECONDS,
    READBACK_SCHEMA,
    REPOSITORY as PRODUCT_REPOSITORY,
    REQUIRED_CAPTURE_ARTIFACTS,
    REQUIRED_QUALIFICATION_INPUTS_KEYS,
    REQUIRED_RESUME_FILES,
    SCHEMA,
    SYSTEM_BY_TARGET,
    SYSTEM_WEBKIT_DESCRIPTION_PATH,
    SYSTEM_WEBKIT_INPUT_KEYS,
    SYSTEM_WEBKIT_INPUT_SCHEMA,
    SYSTEM_WEBKIT_PROFILE_ID,
    SYSTEM_WEBKIT_RUNTIME_PROFILE,
    SYSTEM_PUBLIC_INPUTS_PREPARATION_SCHEMA,
    TAG,
    TAG_BY_TARGET,
    TARGETS,
    TARGET_QUALIFICATION_ARTIFACTS,
    TARGET_TRIPLE_BY_TARGET,
    TARGET_BY_FILENAME,
    TARGET_BY_SYSTEM,
    UNIVERSAL_DISPATCH_REF,
    UPLOAD_STEP,
    VALID_WORKFLOW_JOB_CONCLUSIONS,
    VALID_WORKFLOW_RUN_CONCLUSIONS,
    VERSION,
    WORKFLOW,
    WORKFLOW_PUSH_BRANCH,
)
from rs9.nebular080_public_inputs import (
    _validate_descriptor_target_raw_release,
    _validate_qualification_input_phase,
    _validate_system_webkit_input_spec,
    load_qualification_inputs_descriptor,
    validate_descriptor_target_raw_release,
    validate_qualification_inputs_descriptor,
    validate_qualification_input_phase,
    validate_system_webkit_input_spec,
)
from rs9.nebular080_github_provider import github_public_client
from rs9.errors import ContractError
from rs9.tf_pypi_universal_support import (
    _check_no_symlinks,
    _git_output,
    _resolve_inrun_artifact_root,
    _resolve_repo_contained_dir,
    _validate_file_digest_entry,
    check_no_symlinks,
    default_sandbox_prefix,
    fail,
    git_output,
    make_real_user_state_snapshotter,
    validate_file_digest_entry,
    validate_repo_relative_dir_spec,
)


TARGET_SET = frozenset(TARGETS)
QUALIFY_MODE = "universal-qualify"
PUBLISH_MODE = "universal-publish"
RELEASE_OPTION = VERSION
PREDECESSOR_VERSION = "0.7.1"
PREDECESSOR_TAG = "v0.7.1"
REPOSITORY = DEFAULT_GITHUB_REPOSITORY
_HEX40 = re.compile(r"^[0-9a-f]{40}$")
_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_RUN_TITLE = re.compile(
    r"^RS9 theme-forge-nebular-fusion (?P<release>0\.[0-9]+\.[0-9]+) "
    r"(?P<mode>[a-z-]+) / (?P<dispatch>[A-Za-z0-9._-]+)$"
)


def _hex(value: Any, width: int) -> bool:
    return isinstance(value, str) and bool((_HEX40 if width == 40 else _HEX64).fullmatch(value))


def validate_workflow_dispatch(release: str, mode: str) -> dict[str, str]:
    if release != VERSION:
        fail("WORKFLOW_RELEASE")
    if mode not in (QUALIFY_MODE, PUBLISH_MODE):
        fail("WORKFLOW_MODE_UNSUPPORTED")
    return {"release": release, "mode": mode}


def workflow_080_qualify_jobs_text() -> str:
    """Delegate the appended route to the single authoritative workflow owner."""
    from rs9 import nebular080_universal_workflow as workflow080

    return (
        workflow080.dispatch_guard_text()
        + "\n"
        + workflow080.workflow_080_qualify_jobs_text()
        + workflow080.publication_job_text()
    )


workflow_text = workflow_080_qualify_jobs_text


def _split_jobs(text: str) -> tuple[str, ...]:
    if not isinstance(text, str):
        fail("WORKFLOW_TEXT")
    return tuple(match.group(1) for match in re.finditer(r"^  ([A-Za-z0-9_-]+):\s*$", text, re.MULTILINE))


def rendered_qualification_job_ids(text: str | None = None) -> tuple[str, ...]:
    jobs = _split_jobs(workflow_080_qualify_jobs_text() if text is None else text)
    from rs9 import nebular080_universal_workflow as workflow080

    expected = {
        "reject_unsupported_dispatch",
        *workflow080.QUALIFICATION_JOB_IDS,
        workflow080.PUBLICATION_JOB_ID,
    }
    if not expected.issubset(jobs):
        fail("WORKFLOW_TEXT")
    return jobs


def classify_history_run(run: Mapping[str, Any]) -> str:
    if not isinstance(run, Mapping):
        fail("PRIOR_ATTEMPT_UNCONFIRMED")
    release, mode, _ = _parse_title_and_inputs(run)
    if run.get("event") not in (None, "workflow_dispatch") or run.get("path") not in (None, f".github/workflows/{WORKFLOW}"):
        fail("PRIOR_ATTEMPT_UNCONFIRMED")
    if release == VERSION:
        if mode not in (QUALIFY_MODE, PUBLISH_MODE):
            fail("PRIOR_ATTEMPT_UNCONFIRMED")
        if run.get("head_branch") not in (None, "main"):
            fail("PRIOR_ATTEMPT_UNCONFIRMED")
        return "080-" + mode
    if release in {PREDECESSOR_VERSION, "0.7.0", "0.6.1"}:
        return "predecessor"
    fail("PRIOR_ATTEMPT_UNCONFIRMED")
    raise AssertionError("unreachable")


def check_prior_publish_runs(
    *,
    runs: Sequence[Mapping[str, Any]] | None = None,
    api_get: Callable[[str], Any] | None = None,
    environ: Mapping[str, str] | None = None,
    additional_run_validator: Callable[[Mapping[str, Any], Callable[[str], Any]], bool],
) -> None:
    return check_prior_runs(
        runs=runs,
        api_get=api_get,
        environ=environ,
        additional_run_validator=additional_run_validator,
        repository=DEFAULT_GITHUB_REPOSITORY,
        workflow=WORKFLOW,
    )


def _fetch_paginated_github_list(
    base_url: str,
    list_key: str,
    client_json: Callable[[str], Any],
) -> list[dict[str, Any]]:
    """Compatibility alias for the single history-owner paginator."""
    return fetch_paginated_github_list(base_url, list_key, client_json)


def verify_history_fixture(
    rows: Sequence[Mapping[str, Any]],
    *,
    api_get: Callable[[str], Any],
    additional_run_validator: Callable[[Mapping[str, Any], Callable[[str], Any]], bool],
) -> dict[str, int]:
    counts = {"080": 0, "predecessor": 0}
    selected_runs = (
        None
        if any(row.get("id") in KNOWN_HISTORY_ANCHOR_RUN_IDS for row in rows)
        else rows
    )
    check_prior_publish_runs(
        runs=selected_runs,
        api_get=api_get,
        environ={"GITHUB_RUN_ATTEMPT": "1"},
        additional_run_validator=additional_run_validator,
    )
    for row in rows:
        category = classify_history_run(row)
        counts["080" if category.startswith("080-") else "predecessor"] += 1
    return counts


def _acquire_public_inputs_080(
    *,
    source_manifest: str | Path,
    release_binding: str | Path,
    output: Path,
    repository: Path,
    environ: Mapping[str, str],
) -> dict[str, Any]:
    """Dispatch the real public acquisition owner with one bounded client.

    The old local descriptor preparer is intentionally not reachable from this
    command.  The acquisition owner validates the source manifest and binding,
    then uses the same authenticated GitHub client for product and relay reads.
    """
    client = github_public_client(environ=environ)
    try:
        from rs9.nebular080_public_input_acquisition import (
            PublicRelayNativeEvidenceTransport,
            acquire_public_inputs_080,
            resolve_clean_source_identity,
        )
        from rs9.nebular080_public_input_manifest import load_json
    except ImportError:
        raise ContractError(
            "NEBULAR_PUBLIC_INPUTS_ACQUISITION_UNAVAILABLE",
            "Bounded public-input acquisition owner is required",
        ) from None
    manifest = load_json(source_manifest)
    binding = load_json(release_binding)
    source_identity = resolve_clean_source_identity(
        repository,
        commit=environ.get("GITHUB_SHA", ""),
    )
    native_transport = PublicRelayNativeEvidenceTransport(client)
    return acquire_public_inputs_080(
        output,
        repository=repository,
        source_manifest=manifest,
        release_client=client,
        native_transport=native_transport,
        release_binding=binding,
        source_identity=source_identity,
    )


def parser() -> argparse.ArgumentParser:
    """Parse the bounded local 0.8 preparation command used by the route."""
    result = argparse.ArgumentParser(description=__doc__)
    commands = result.add_subparsers(dest="operation", required=True)
    dispatch = commands.add_parser("validate-dispatch")
    dispatch.add_argument("--release", required=True)
    dispatch.add_argument("--mode", required=True)
    prepare = commands.add_parser("prepare-public-inputs-080")
    prepare.add_argument("--source-manifest", required=True)
    prepare.add_argument("--release-binding", required=True)
    prepare.add_argument("--output", type=Path, required=True)
    prepare.add_argument("--repository", type=Path, required=True)
    return result


def main(argv: Sequence[str] | None = None, *, environ: Mapping[str, str] | None = None) -> int:
    args = parser().parse_args(argv)
    environ = os.environ if environ is None else environ
    try:
        if args.operation == "validate-dispatch":
            value = validate_workflow_dispatch(args.release, args.mode)
        else:
            value = _acquire_public_inputs_080(
                source_manifest=args.source_manifest,
                release_binding=args.release_binding,
                output=args.output,
                repository=args.repository,
                environ=environ,
            )
        sys.stdout.buffer.write(canonical(value))
        return 0
    except ContractError as error:
        sys.stderr.write(str(getattr(error, "code", "NEBULAR_PUBLIC_INPUTS_CONTRACT")) + "\n")
        return 1
    except (AdmissionError, OSError, TypeError, ValueError, KeyError):
        sys.stderr.write("NEBULAR_PUBLIC_INPUTS_CONTRACT\n")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())

