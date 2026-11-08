"""Ported 0.7.1 predecessor-history reader for the 0.8.0 route.

This owner deliberately contains only the predecessor's public title, input,
job and acceptance facts.  It does not import or execute a 0.7.1 module.  A
0.7.1 record is historical evidence; it can never satisfy an 0.8.0 route.
"""
from __future__ import annotations

from collections.abc import Mapping
import copy
import re

from rs9 import nebular080_universal_workflow as workflow
from rs9 import nebular_workflow_coexistence as coexistence
from rs9 import nebular_history_guard as history
from rs9 import tf_pypi_nebular080_publish as publish
from rs9.errors import ContractError


PREDECESSOR_RELEASE = "0.7.1"
PREDECESSOR_TAG = "v0.7.1"
PREDECESSOR_TITLE_PREFIX = "RS9 theme-forge-nebular-fusion 0.7.1 "
PREDECESSOR_INPUT_KEYS = frozenset({"release", "mode", "dispatch_id"})
PREDECESSOR_MODES = frozenset({"universal-qualify", "universal-publish"})
PREDECESSOR_UNIVERSAL_JOB_IDS = (
    "universal_prepare_public_inputs_071", "universal_build_verify_071",
    "universal_native_consumer_071_darwin_arm64",
    "universal_native_consumer_071_linux_arm64_gnu",
    "universal_native_consumer_071_linux_x64_gnu",
    "universal_native_consumer_071_linux_arm64_gnu_floor",
    "universal_native_consumer_071_linux_x64_gnu_floor",
    "universal_qualification_gate_071",
)
PREDECESSOR_PUBLISH_JOB_ID = "universal_publication_071"
PREDECESSOR_GUARD_JOB_ID = "reject_unsupported_dispatch"
PREDECESSOR_PUBLISH_JOB = "Attended Nebular 0.7.1 universal PyPI publication"
PREDECESSOR_UPLOAD_STEP = "Publish universal launcher distribution to PyPI"
VALID_RUN_CONCLUSIONS = frozenset({"success", "failure", "cancelled", "timed_out"})
VALID_JOB_CONCLUSIONS = frozenset({
    "success", "failure", "cancelled", "skipped", "timed_out",
})
ACTIVE_FAILURE_CONCLUSIONS = frozenset({"failure", "cancelled", "timed_out"})


def _fail() -> None:
    raise ContractError(
        "NEBULAR_UNIVERSAL_PRIOR_ATTEMPT_UNCONFIRMED",
        "The retained predecessor workflow history is not conclusive",
    )


def _mode(run: Mapping) -> str | None:
    title = run.get("display_title", run.get("name"))
    if not isinstance(title, str):
        _fail()
    if not title.startswith(PREDECESSOR_TITLE_PREFIX + "universal-"):
        return None
    head, separator, tail = title.partition(" /")
    mode = head.removeprefix(PREDECESSOR_TITLE_PREFIX)
    if (
        separator != " /"
        or mode not in PREDECESSOR_MODES
        or (tail not in {"", " "}
            and (not tail.startswith(" ") or tail[1:] != tail[1:].strip()))
    ):
        _fail()
    inputs = run.get("inputs")
    if inputs is not None and (
        not isinstance(inputs, Mapping)
        or not {"release", "mode"}.issubset(inputs)
        or set(inputs) - PREDECESSOR_INPUT_KEYS
        or inputs["release"] != PREDECESSOR_RELEASE
        or inputs["mode"] != mode
    ):
        _fail()
    return mode


def _declared_source_steps(source_steps: list[str]) -> set[str]:
    """Remove GitHub-injected lifecycle/post records from declared YAML steps."""
    return {
        step for step in source_steps
        if step not in {"Set up job", "Complete job", "Initialize containers", "Stop containers"}
        and not step.startswith("Post ")
    }


def _profiles() -> dict:
    """Filter the source-bound 0.7.1 table projection to its declared set."""
    all_profiles = copy.deepcopy(workflow.workflow_job_profiles())
    wanted = {"build_verify", "native_consumer", "publish",
              *PREDECESSOR_UNIVERSAL_JOB_IDS, PREDECESSOR_PUBLISH_JOB_ID,
              PREDECESSOR_GUARD_JOB_ID}
    profiles = {name: row for name, row in all_profiles.items() if row["id"] in wanted}
    if {row["id"] for row in profiles.values()} != wanted:
        _fail()
    source_table = history.profile_table("0.7.1", universal=True)
    for name, row in profiles.items():
        source_steps = source_table["profiles"].get(name)
        if not isinstance(source_steps, list):
            _fail()
        row["declared"] = _declared_source_steps(source_steps)
        row["allowed"] = set(source_steps)
    return profiles


def _project_coexistence(run: Mapping, jobs: list, profiles: Mapping) -> list:
    """Authenticate appended 0.8.0 rows before predecessor validation."""
    return coexistence.project_skipped_080_rows(
        run,
        jobs,
        legacy_profiles=profiles,
        profiles_080=coexistence.select_080_profiles(
            workflow.workflow_job_profiles()
        ),
        repository=publish.DEFAULT_GITHUB_REPOSITORY,
        workflow=workflow.WORKFLOW,
    )


def _attempt_jobs(run: Mapping, jobs: list, *, profiles: Mapping) -> dict:
    if not isinstance(jobs, list) or not jobs:
        _fail()
    maximum = run.get("run_attempt")
    if type(maximum) is not int or maximum < 1:
        _fail()
    attempts, seen_ids = {}, set()
    for job in jobs:
        if not isinstance(job, Mapping):
            _fail()
        attempt, name, identity = job.get("run_attempt"), job.get("name"), job.get("id")
        if (
            type(attempt) is not int or not 1 <= attempt <= maximum
            or type(identity) is not int or identity <= 0 or identity in seen_ids
            or not isinstance(name, str) or name not in profiles
            or name in attempts.get(attempt, {})
            or job.get("run_id") != run["id"] or type(job.get("run_id")) is not int
            or job.get("head_sha") != run["head_sha"]
            or job.get("status") != "completed"
            or job.get("conclusion") not in VALID_JOB_CONCLUSIONS
        ):
            _fail()
        seen_ids.add(identity)
        attempts.setdefault(attempt, {})[name] = job
        steps = job.get("steps", [])
        if not isinstance(steps, list) or (job["conclusion"] != "skipped" and not steps):
            _fail()
        seen_steps, seen_numbers = set(), set()
        for step in steps:
            if not isinstance(step, Mapping):
                _fail()
            step_name, number = step.get("name"), step.get("number")
            if (
                not isinstance(step_name, str) or not step_name or step_name in seen_steps
                or type(number) is not int or number <= 0 or number in seen_numbers
                or step.get("status") != "completed"
                or step.get("conclusion") not in VALID_JOB_CONCLUSIONS
                or (job["conclusion"] == "skipped" and step["conclusion"] != "skipped")
                or (step["conclusion"] != "skipped"
                    and step_name not in profiles[name]["allowed"])
            ):
                _fail()
            seen_steps.add(step_name)
            seen_numbers.add(number)
    if set(attempts) != set(range(1, maximum + 1)):
        _fail()
    for rows in attempts.values():
        if set(rows) != set(profiles):
            _fail()
    return attempts


def _run_context(run: Mapping) -> None:
    if (
        not isinstance(run, Mapping)
        or type(run.get("id")) is not int or run["id"] <= 0
        or type(run.get("workflow_id")) is not int or run["workflow_id"] <= 0
        or not isinstance(run.get("head_sha"), str)
        or not re.fullmatch(r"[0-9a-f]{40}", run["head_sha"])
        or run.get("head_branch") != "main"
        or run.get("event") != "workflow_dispatch"
        or run.get("status") != "completed"
        or run.get("conclusion") not in VALID_RUN_CONCLUSIONS
        or not isinstance(run.get("repository"), Mapping)
        or run["repository"].get("full_name") != publish.DEFAULT_GITHUB_REPOSITORY
    ):
        _fail()
    expected = ".github/workflows/" + workflow.WORKFLOW
    if run.get("path") not in {
        expected, expected + "@main", expected + "@refs/heads/main",
        expected + "@" + run["head_sha"],
    }:
        _fail()


def _published_history(run: Mapping, jobs: Mapping, profiles: Mapping) -> None:
    publish_job = jobs[PREDECESSOR_PUBLISH_JOB]
    if any(job["conclusion"] != "skipped"
           for key, job in jobs.items() if key != PREDECESSOR_PUBLISH_JOB):
        _fail()
    if publish_job["conclusion"] != run["conclusion"]:
        _fail()
    if publish_job["conclusion"] not in {"success"} | ACTIVE_FAILURE_CONCLUSIONS:
        _fail()
    observed = {step["name"] for step in publish_job["steps"]}
    if not profiles[PREDECESSOR_PUBLISH_JOB]["declared"].issubset(observed):
        _fail()


def _non_upload_attempt(mode: str, jobs: Mapping, profiles: Mapping) -> None:
    qualifier_ids = set(PREDECESSOR_UNIVERSAL_JOB_IDS)
    qualifier_names = {name for name, row in profiles.items() if row["id"] in qualifier_ids}
    if mode == "universal-qualify":
        if any(jobs[name]["conclusion"] != "skipped"
               for name in set(profiles) - qualifier_names):
            _fail()
        return
    if any(jobs[name]["conclusion"] != "skipped"
           for name in set(profiles) - {PREDECESSOR_PUBLISH_JOB}):
        _fail()
    upload = [step for step in jobs[PREDECESSOR_PUBLISH_JOB].get("steps", [])
              if step.get("name") == PREDECESSOR_UPLOAD_STEP]
    if len(upload) != 1 or upload[0].get("conclusion") != "skipped":
        _fail()


def _published_older_history(run: Mapping, jobs: Mapping, profile: Mapping) -> None:
    """Admit one completed older-version publish without treating it as 0.8."""
    publish_name = profile["publish"][0]
    if any(job["conclusion"] != "skipped" for key, job in jobs.items() if key != publish_name):
        _fail()
    publish = jobs[publish_name]
    if (
        publish["conclusion"] != run["conclusion"]
        or publish["conclusion"] not in {"success"} | history.ACTIVE_FAILURE_CONCLUSIONS
        or not _declared_source_steps(profile["profiles"][publish_name]).issubset(
            {step["name"] for step in publish["steps"]}
        )
    ):
        _fail()


def _check_070_universal(run: Mapping, client_json, mode: str) -> bool:
    """Use the source-bound 0.7.0 universal table as predecessor history."""
    history._run_context(
        run,
        repository=publish.DEFAULT_GITHUB_REPOSITORY,
        workflow=workflow.WORKFLOW,
    )
    if mode == "universal-publish" and run.get("run_attempt") != 1:
        _fail()
    rows = history.fetch_paginated_github_list(
        f"https://api.github.com/repos/{publish.DEFAULT_GITHUB_REPOSITORY}"
        f"/actions/runs/{run['id']}/jobs?filter=all&per_page={publish.PRIOR_RUN_PAGE_SIZE}",
        "jobs",
        client_json,
    )
    profile = history.profile_table("0.7.0", universal=True)
    for jobs in history._jobs_by_attempt(
        rows,
        run=run,
        profile=profile,
        strict_step_identity=True,
    ).values():
        if mode == "universal-publish":
            _published_older_history(run, jobs, profile)
        else:
            history._universal_attempt(mode, jobs, profile)
    return True


def check_predecessor_run(run: Mapping, client_json) -> bool:
    """Recognize source-bound 0.7.1 and 0.7.0 history domains."""
    mode = _mode(run)
    if mode is None:
        release, older_mode, _ = history._parse_title_and_inputs(run)
        if release == "0.7.0" and older_mode in {"universal-qualify", "universal-publish"}:
            return _check_070_universal(run, client_json, older_mode)
        return False
    _run_context(run)
    if mode == "universal-publish" and run.get("run_attempt") != 1:
        _fail()
    profiles = _profiles()
    rows = history.fetch_paginated_github_list(
        f"https://api.github.com/repos/{publish.DEFAULT_GITHUB_REPOSITORY}"
        f"/actions/runs/{run['id']}/jobs?filter=all&per_page={publish.PRIOR_RUN_PAGE_SIZE}",
        "jobs", client_json,
    )
    rows = _project_coexistence(run, rows, profiles)
    for jobs in _attempt_jobs(run, rows, profiles=profiles).values():
        if mode == "universal-publish":
            _published_history(run, jobs, profiles)
        else:
            _non_upload_attempt(mode, jobs, profiles)
    return True
