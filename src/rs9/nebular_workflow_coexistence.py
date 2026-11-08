"""Strict 0.7.1/0.8.0 Actions-job coexistence boundary.

The maintained 0.7.1 predicates intentionally retain their exact historical
profile set.  This boundary authenticates the common run/job identity first,
consumes only the exact 0.8.0 jobs when they are explicitly skipped, and then
returns the unchanged predecessor rows to the historical reader.
"""
from __future__ import annotations

from collections.abc import Mapping
import re

from rs9.errors import ContractError


KNOWN_080_JOB_IDS = frozenset({
    "universal_prepare_public_inputs_080",
    "universal_build_verify_080",
    "universal_native_consumer_080_darwin_arm64",
    "universal_native_consumer_080_linux_arm64_gnu",
    "universal_native_consumer_080_linux_x64_gnu",
    "universal_native_consumer_080_linux_arm64_gnu_floor",
    "universal_native_consumer_080_linux_x64_gnu_floor",
    "universal_qualification_gate_080",
    "universal_publication_080",
})
VALID_RUN_CONCLUSIONS = frozenset({"success", "failure", "cancelled", "timed_out"})
VALID_JOB_CONCLUSIONS = frozenset({
    "success", "failure", "cancelled", "skipped", "timed_out",
})
_HEX40 = re.compile(r"[0-9a-f]{40}")


def _fail(code: str) -> None:
    raise ContractError(
        "NEBULAR_WORKFLOW_COEXISTENCE_" + code,
        "The retained workflow job history is not conclusive",
    )


def select_080_profiles(all_profiles: Mapping) -> dict:
    """Select and bind exactly the appended 0.8.0 profile set."""
    if not isinstance(all_profiles, Mapping):
        _fail("PROFILE_SCHEMA")
    selected = {}
    for name, profile in all_profiles.items():
        if not isinstance(name, str) or not isinstance(profile, Mapping):
            _fail("PROFILE_SCHEMA")
        if profile.get("id") in KNOWN_080_JOB_IDS:
            if name in selected:
                _fail("PROFILE_DUPLICATE")
            selected[name] = profile
    ids = {profile.get("id") for profile in selected.values()}
    if ids != KNOWN_080_JOB_IDS or len(selected) != len(KNOWN_080_JOB_IDS):
        _fail("PROFILE_SET")
    return selected


def _validate_run_identity(
    run: Mapping,
    *,
    repository: str,
    workflow: str,
) -> int:
    if (
        not isinstance(run, Mapping)
        or type(run.get("id")) is not int or run["id"] <= 0
        or type(run.get("workflow_id")) is not int or run["workflow_id"] <= 0
        or not isinstance(run.get("head_sha"), str)
        or not _HEX40.fullmatch(run["head_sha"])
        or run.get("head_branch") != "main"
        or run.get("event") != "workflow_dispatch"
        or run.get("status") != "completed"
        or run.get("conclusion") not in VALID_RUN_CONCLUSIONS
        or not isinstance(run.get("repository"), Mapping)
        or run["repository"].get("full_name") != repository
        or type(run.get("run_attempt")) is not int
        or run["run_attempt"] < 1
    ):
        _fail("RUN_IDENTITY")
    expected = ".github/workflows/" + workflow
    path = run.get("path")
    if path not in {
        expected,
        expected + "@main",
        expected + "@refs/heads/main",
        expected + "@" + run["head_sha"],
    }:
        _fail("RUN_WORKFLOW")
    return run["run_attempt"]


def _validate_steps(job: Mapping) -> None:
    conclusion = job["conclusion"]
    steps = job.get("steps", [])
    if not isinstance(steps, list) or (conclusion != "skipped" and not steps):
        _fail("JOB_STEPS")
    names, numbers = set(), set()
    for step in steps:
        if not isinstance(step, Mapping):
            _fail("JOB_STEP_SCHEMA")
        name, number, step_conclusion = (
            step.get("name"), step.get("number"), step.get("conclusion")
        )
        if (
            not isinstance(name, str) or not name or name in names
            or type(number) is not int or number <= 0 or number in numbers
            or step.get("status") != "completed"
            or step_conclusion not in VALID_JOB_CONCLUSIONS
            or (conclusion == "skipped" and step_conclusion != "skipped")
        ):
            _fail("JOB_STEP_IDENTITY")
        names.add(name)
        numbers.add(number)


def project_skipped_080_rows(
    run: Mapping,
    jobs: list,
    *,
    legacy_profiles: Mapping,
    profiles_080: Mapping,
    repository: str,
    workflow: str,
) -> list:
    """Validate a combined response and project only skipped 0.8.0 rows.

    A historical 13-row response remains valid when no 0.8.0 row is present.
    Once any appended row is present, all nine exact appended jobs must be
    present and skipped for every attempt; this distinguishes old hosted runs
    from incomplete or tampered combined responses.
    """
    maximum = _validate_run_identity(run, repository=repository, workflow=workflow)
    if not isinstance(jobs, list) or not jobs:
        _fail("JOB_LIST")
    if not isinstance(legacy_profiles, Mapping):
        _fail("LEGACY_PROFILE_SCHEMA")
    selected = select_080_profiles(profiles_080)
    new_names = set(selected)
    old_names = set(legacy_profiles)
    if new_names & old_names:
        _fail("PROFILE_OVERLAP")

    retained = []
    seen_ids = set()
    names_by_attempt = {}
    new_ids_by_attempt = {}
    for job in jobs:
        if not isinstance(job, Mapping):
            _fail("JOB_SCHEMA")
        attempt, name, identity = job.get("run_attempt"), job.get("name"), job.get("id")
        if (
            type(attempt) is not int or not 1 <= attempt <= maximum
            or type(identity) is not int or identity <= 0 or identity in seen_ids
            or not isinstance(name, str) or not name
            or job.get("run_id") != run["id"]
            or job.get("head_sha") != run["head_sha"]
            or job.get("status") != "completed"
            or job.get("conclusion") not in VALID_JOB_CONCLUSIONS
        ):
            _fail("JOB_IDENTITY")
        names = names_by_attempt.setdefault(attempt, set())
        if name in names:
            _fail("JOB_DUPLICATE")
        names.add(name)
        seen_ids.add(identity)
        _validate_steps(job)

        if name in new_names:
            if job["conclusion"] != "skipped":
                _fail("ACTIVE_080_JOB")
            new_ids_by_attempt.setdefault(attempt, set()).add(selected[name]["id"])
            continue
        if name not in old_names:
            _fail("UNKNOWN_JOB")
        retained.append(job)

    if new_ids_by_attempt:
        expected_attempts = set(range(1, maximum + 1))
        if set(new_ids_by_attempt) != expected_attempts:
            _fail("MISSING_080_JOB")
        if any(ids != KNOWN_080_JOB_IDS for ids in new_ids_by_attempt.values()):
            _fail("MISSING_080_JOB")
    return retained
