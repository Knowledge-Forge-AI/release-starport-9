"""History-only guard extracted from the frozen 0.7.0/0.7.1 readers.

This module owns only Actions workflow/job history authentication. It does not
import a release publisher, runtime, hosted, materialization, or workflow
renderer. The caller supplies the 0.8 callback; unclaimed rows go through the
source-bound 0.7.0/0.7.1/0.6.1 predicates here and unknown history fails closed.
"""
from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
import os
import re
from typing import Any

from rs9.nebular_history_profiles import (
    ACTIVE_FAILURE_CONCLUSIONS,
    LEGACY_061_JOB_NAMES,
    VALID_JOB_CONCLUSIONS,
    VALID_RUN_CONCLUSIONS,
    profile_table,
)
from rs9.tf_pypi_archive import AdmissionError


PROJECT = "theme-forge-nebular-fusion"
WORKFLOW = "rs9-tfnf-pypi-publish.yml"
REPOSITORY = "Knowledge-Forge-AI/release-starport-9"
PAGE_SIZE = 100
MAX_PAGES = 20
KNOWN_HISTORY_ANCHOR_RUN_IDS = frozenset({
    41232938111,
    41204421318,
    40983452395,
    40982973164,
})
UPLOAD_STEP = "Publish universal launcher distribution to PyPI"
PUBLISH_STEP = "Publish package distribution to PyPI"
_HEX40 = re.compile(r"^[0-9a-f]{40}$")
_RUN_ID = re.compile(r"^[0-9]+$")


def _fail() -> None:
    raise AdmissionError("TF_PYPI_PRIOR_ATTEMPT_UNCONFIRMED")


def fetch_paginated_github_list(
    base_url: str,
    list_key: str,
    client_json: Callable[[str], Any],
) -> list[dict[str, Any]]:
    """Fetch a bounded list with stable total-count and page semantics."""
    items: list[dict[str, Any]] = []
    total_count: int | None = None
    for page in range(1, MAX_PAGES + 1):
        separator = "&" if "?" in base_url else "?"
        page_url = base_url if page == 1 else f"{base_url}{separator}page={page}"
        document = client_json(page_url)
        if not isinstance(document, dict):
            _fail()
        page_total = document.get("total_count")
        if type(page_total) is not int or page_total < 0:
            _fail()
        if total_count is None:
            total_count = page_total
        elif page_total != total_count:
            _fail()
        page_items = document.get(list_key)
        if not isinstance(page_items, list):
            _fail()
        items.extend(page_items)
        if len(items) > total_count:
            _fail()
        if len(items) == total_count:
            return items
        if not page_items:
            _fail()
    _fail()
    raise AssertionError("unreachable")


def _normalize_workflow_path(raw_path: Any, *, head_sha: str, workflow: str) -> None:
    expected = f".github/workflows/{workflow}"
    if raw_path == expected:
        return
    path, separator, ref = str(raw_path).partition("@") if isinstance(raw_path, str) else ("", "", "")
    if separator != "@" or path != expected or ref not in {"main", "refs/heads/main", head_sha}:
        _fail()


def _allowed_dispatch(release: str, mode: str) -> bool:
    return (release, mode) in {
        ("0.6.1", "qualify"),
        ("0.6.1", "publish"),
        ("0.7.0", "qualify"),
        ("0.7.0", "resume"),
        ("0.7.0", "universal-qualify"),
        ("0.7.0", "universal-publish"),
        ("0.7.1", "qualify"),
        ("0.7.1", "resume"),
        ("0.7.1", "universal-qualify"),
        ("0.7.1", "universal-publish"),
        ("0.8.0", "universal-qualify"),
        ("0.8.0", "universal-publish"),
    }


def _parse_title_and_inputs(run: Mapping[str, Any]) -> tuple[str, str | None, bool]:
    raw_title = run.get("display_title")
    if raw_title is None:
        raw_title = run.get("name")
    if not isinstance(raw_title, str) or not raw_title.strip() or raw_title != raw_title.lstrip():
        _fail()

    historical_061 = raw_title == f"RS9 {PROJECT} PyPI Publish"
    if historical_061:
        release, title_mode = "0.6.1", None
    else:
        head, separator, dispatch_tail = raw_title.partition(" /")
        if separator != " /":
            _fail()
        if dispatch_tail not in ("", " "):
            if not dispatch_tail.startswith(" ") or not dispatch_tail[1:].strip():
                _fail()
        tokens = head.split(" ")
        if len(tokens) == 4 and tokens[:2] == ["RS9", PROJECT]:
            release, title_mode = tokens[2], tokens[3]
            if not _allowed_dispatch(release, title_mode):
                _fail()
        elif len(tokens) == 3 and tokens[:2] == ["RS9", PROJECT] and tokens[2] in {"qualify", "publish"}:
            release, title_mode, historical_061 = "0.6.1", tokens[2], True
        else:
            _fail()

    if "inputs" in run and run.get("inputs") is not None:
        inputs = run.get("inputs")
        if not isinstance(inputs, Mapping) or not inputs:
            _fail()
        input_mode = inputs.get("mode")
        input_release = inputs.get("release")
        if not isinstance(input_mode, str) or not input_mode.strip():
            _fail()
        if historical_061 and input_release is None:
            effective_release = "0.6.1"
        elif isinstance(input_release, str) and input_release.strip():
            effective_release = input_release
        else:
            _fail()
        if not _allowed_dispatch(effective_release, input_mode) or effective_release != release:
            _fail()
        if title_mode is not None and input_mode != title_mode:
            _fail()
        title_mode = input_mode

    return release, title_mode, historical_061


def _run_context(
    run: Mapping[str, Any],
    *,
    repository: str,
    workflow: str,
) -> None:
    if (
        not isinstance(run, Mapping)
        or type(run.get("id")) is not int
        or run["id"] <= 0
        or type(run.get("workflow_id")) is not int
        or run["workflow_id"] <= 0
        or not isinstance(run.get("head_sha"), str)
        or not _HEX40.fullmatch(run["head_sha"])
        or run.get("head_branch") != "main"
        or run.get("event") != "workflow_dispatch"
        or run.get("status") != "completed"
        or run.get("conclusion") not in VALID_RUN_CONCLUSIONS
        or type(run.get("run_attempt")) is not int
        or run["run_attempt"] < 1
    ):
        _fail()
    for repository_key in ("repository", "head_repository"):
        if repository_key in run and run.get(repository_key) is not None:
            repository_value = run.get(repository_key)
            if not isinstance(repository_value, Mapping) or repository_value.get("full_name") != repository:
                _fail()
    _normalize_workflow_path(run.get("path"), head_sha=run["head_sha"], workflow=workflow)


def _validate_steps(
    job_name: str,
    conclusion: str,
    job: Mapping[str, Any],
    *,
    current_names: set[str],
    allowed_names: set[str],
    strict_identity: bool,
) -> None:
    if "steps" not in job:
        if job_name in current_names and conclusion != "skipped":
            _fail()
        return
    steps = job.get("steps")
    if not isinstance(steps, list):
        _fail()
    if job_name in current_names and conclusion != "skipped" and not steps:
        _fail()
    seen_step_names: set[str] = set()
    seen_step_numbers: set[int] = set()
    for step in steps:
        if not isinstance(step, dict):
            _fail()
        step_name = step.get("name")
        step_number = step.get("number")
        step_conclusion = step.get("conclusion")
        if (
            not isinstance(step_name, str)
            or not step_name.strip()
            or (
                strict_identity
                and (
                    type(step_number) is not int
                    or step_number <= 0
                    or step_name in seen_step_names
                    or step_number in seen_step_numbers
                )
            )
            or step.get("status") != "completed"
            or not isinstance(step_conclusion, str)
            or step_conclusion not in VALID_JOB_CONCLUSIONS
            or (conclusion == "skipped" and step_conclusion != "skipped")
            or (step_conclusion != "skipped" and step_name not in allowed_names)
        ):
            _fail()
        if strict_identity:
            seen_step_names.add(step_name)
            seen_step_numbers.add(step_number)


def _jobs_by_attempt(
    jobs: list[dict[str, Any]],
    *,
    run: Mapping[str, Any],
    profile: Mapping[str, Any],
    allow_legacy_subset: bool = False,
    strict_step_identity: bool = False,
) -> dict[int, dict[str, dict[str, Any]]]:
    if not jobs:
        _fail()
    maximum = run.get("run_attempt")
    if type(maximum) is not int or maximum < 1:
        _fail()
    all_names = set(profile["all"])
    current_names = set(profile["all"]) - set(profile["legacy061"])
    allowed = {name: set(steps) for name, steps in profile["profiles"].items()}
    grouped: dict[int, list[dict[str, Any]]] = {}
    for job in jobs:
        if not isinstance(job, dict):
            _fail()
        attempt = job.get("run_attempt")
        if type(attempt) is not int or not 1 <= attempt <= maximum:
            _fail()
        grouped.setdefault(attempt, []).append(job)
    if set(grouped) != set(range(1, maximum + 1)):
        _fail()

    seen_ids: set[int] = set()
    result: dict[int, dict[str, dict[str, Any]]] = {}
    for attempt in range(1, maximum + 1):
        rows = grouped[attempt]
        by_name: dict[str, dict[str, Any]] = {}
        for job in rows:
            name = job.get("name")
            identity = job.get("id")
            conclusion = job.get("conclusion")
            if (
                not isinstance(name, str)
                or name not in all_names
                or name in by_name
                or type(identity) is not int
                or identity <= 0
                or identity in seen_ids
                or job.get("run_id") != run["id"]
                or job.get("run_attempt") != attempt
                or job.get("head_sha") != run["head_sha"]
                or job.get("status") != "completed"
                or not isinstance(conclusion, str)
                or conclusion not in VALID_JOB_CONCLUSIONS
            ):
                _fail()
            seen_ids.add(identity)
            _validate_steps(
                name,
                conclusion,
                job,
                current_names=current_names,
                allowed_names=allowed[name],
                strict_identity=strict_step_identity,
            )
            by_name[name] = job
        if set(by_name) != all_names and not (
            allow_legacy_subset and set(by_name) == set(LEGACY_061_JOB_NAMES)
        ):
            _fail()
        result[attempt] = by_name
    return result


def _universal_attempt(mode: str, jobs: Mapping[str, Mapping[str, Any]], profile: Mapping[str, Any]) -> None:
    publish_name = profile["publish"][0]
    qualify_names = set(profile["qualify"])
    all_names = set(profile["all"])
    if mode == "universal-qualify":
        if any(jobs[name]["conclusion"] != "skipped" for name in all_names - qualify_names):
            _fail()
        return
    if mode != "universal-publish":
        _fail()
    if any(jobs[name]["conclusion"] != "skipped" for name in all_names - {publish_name}):
        _fail()
    publish = jobs[publish_name]
    if publish["conclusion"] not in ACTIVE_FAILURE_CONCLUSIONS:
        _fail()
    upload_steps = [step for step in publish.get("steps", []) if step.get("name") == UPLOAD_STEP]
    if len(upload_steps) != 1 or upload_steps[0].get("conclusion") != "skipped":
        _fail()


def _legacy_qualify_attempt(
    jobs: Mapping[str, Mapping[str, Any]],
    run_conclusion: str,
    profile: Mapping[str, Any],
    *,
    check_run_conclusion: bool,
) -> None:
    all_names = set(profile["all"])
    qualify_names = set(profile["qualify"])
    nonqualify = all_names - qualify_names
    if set(jobs) != all_names or any(jobs[name]["conclusion"] != "skipped" for name in nonqualify):
        _fail()
    build_name = next(name for name in qualify_names if "Candidate Bundle" in name)
    native_names = [
        name for name in qualify_names
        if name.startswith("Native consumer ") or name.startswith("Universal installed consumer ")
    ]
    matrix_name = next(name for name in qualify_names if "matrix gate" in name.lower())
    build_conclusion = jobs[build_name]["conclusion"]
    native_conclusions = [jobs[name]["conclusion"] for name in sorted(native_names)]
    matrix_conclusion = jobs[matrix_name]["conclusion"]
    if build_conclusion in ACTIVE_FAILURE_CONCLUSIONS:
        if any(c != "skipped" for c in native_conclusions) or matrix_conclusion != "skipped":
            _fail()
        if check_run_conclusion and run_conclusion not in ACTIVE_FAILURE_CONCLUSIONS:
            _fail()
        return
    if build_conclusion != "success":
        _fail()
    if any(c not in {"success"} | ACTIVE_FAILURE_CONCLUSIONS for c in native_conclusions):
        _fail()
    if any(c in ACTIVE_FAILURE_CONCLUSIONS for c in native_conclusions):
        if matrix_conclusion != "skipped" or (
            check_run_conclusion and run_conclusion not in ACTIVE_FAILURE_CONCLUSIONS
        ):
            _fail()
        return
    if matrix_conclusion == "success":
        if check_run_conclusion and run_conclusion != "success":
            _fail()
        return
    if matrix_conclusion in ACTIVE_FAILURE_CONCLUSIONS:
        if check_run_conclusion and run_conclusion not in ACTIVE_FAILURE_CONCLUSIONS:
            _fail()
        return
    _fail()


def _resume_attempt(jobs: Mapping[str, Mapping[str, Any]], run: Mapping[str, Any], profile: Mapping[str, Any]) -> None:
    if run["run_attempt"] != 1:
        _fail()
    all_names = set(profile["all"])
    publish_name = profile["publish"][0]
    if set(jobs) != all_names or any(jobs[name]["conclusion"] != "skipped" for name in all_names - {publish_name}):
        _fail()
    publish = jobs[publish_name]
    if publish["conclusion"] not in ACTIVE_FAILURE_CONCLUSIONS or run["conclusion"] not in ACTIVE_FAILURE_CONCLUSIONS:
        _fail()
    steps = publish.get("steps")
    if not isinstance(steps, list) or not steps:
        _fail()
    upload_steps = [step for step in steps if step.get("name") == PUBLISH_STEP]
    if not upload_steps or any(step.get("status") != "completed" or step.get("conclusion") != "skipped" for step in upload_steps):
        _fail()


def _legacy_061_attempt(
    jobs: Mapping[str, Mapping[str, Any]],
    run_conclusion: str,
    profile: Mapping[str, Any],
    *,
    title_mode: str | None,
    historical_061: bool,
    check_run_conclusion: bool,
) -> None:
    all_names = set(profile["all"])
    legacy_names = set(profile["legacy061"])
    job_names = set(jobs)
    if job_names == all_names:
        if any(jobs[name]["conclusion"] != "skipped" for name in all_names - legacy_names):
            _fail()
    elif historical_061 and job_names == set(LEGACY_061_JOB_NAMES):
        pass
    else:
        _fail()
    build_name, consumer_name, publish_name = LEGACY_061_JOB_NAMES
    build = jobs[build_name]["conclusion"]
    consumer = jobs[consumer_name]["conclusion"]
    publish = jobs[publish_name]["conclusion"]
    if build in ACTIVE_FAILURE_CONCLUSIONS:
        if consumer != "skipped" or publish != "skipped" or (
            check_run_conclusion and run_conclusion not in ACTIVE_FAILURE_CONCLUSIONS
        ):
            _fail()
        return
    if build != "success":
        _fail()
    if consumer in ACTIVE_FAILURE_CONCLUSIONS:
        if publish != "skipped" or (
            check_run_conclusion and run_conclusion not in ACTIVE_FAILURE_CONCLUSIONS
        ):
            _fail()
        return
    if consumer != "success":
        _fail()
    if title_mode == "qualify":
        if publish != "skipped" or (check_run_conclusion and run_conclusion != "success"):
            _fail()
        return
    if title_mode == "publish":
        if publish == "success":
            if check_run_conclusion and run_conclusion != "success":
                _fail()
            return
        if publish in ACTIVE_FAILURE_CONCLUSIONS:
            if check_run_conclusion and run_conclusion not in ACTIVE_FAILURE_CONCLUSIONS:
                _fail()
            return
        _fail()
    if publish in {"skipped", "success"}:
        if check_run_conclusion and run_conclusion != "success":
            _fail()
        return
    if publish in ACTIVE_FAILURE_CONCLUSIONS:
        if check_run_conclusion and run_conclusion not in ACTIVE_FAILURE_CONCLUSIONS:
            _fail()
        return
    _fail()


def _fallback_validate(
    run: Mapping[str, Any],
    jobs: list[dict[str, Any]],
    *,
    release: str,
    mode: str | None,
    historical_061: bool,
) -> None:
    if release == "0.6.1":
        candidates = ("0.7.1", "0.7.0")
        for candidate in candidates:
            try:
                attempts = _jobs_by_attempt(
                    jobs,
                    run=run,
                    profile=profile_table(candidate, universal=False),
                    allow_legacy_subset=historical_061,
                )
                for attempt, rows in attempts.items():
                    _legacy_061_attempt(
                        rows,
                        run["conclusion"],
                        profile_table(candidate, universal=False),
                        title_mode=mode,
                        historical_061=historical_061,
                        check_run_conclusion=attempt == run["run_attempt"],
                    )
                return
            except AdmissionError:
                continue
        _fail()
    profile = profile_table(
        release,
        universal=mode in {"universal-qualify", "universal-publish"},
    )
    attempts = _jobs_by_attempt(
        jobs,
        run=run,
        profile=profile,
        strict_step_identity=mode in {"universal-qualify", "universal-publish"},
    )
    for attempt, rows in attempts.items():
        check = attempt == run["run_attempt"]
        if mode in {"universal-qualify", "universal-publish"}:
            _universal_attempt(mode, rows, profile)
        elif mode == "qualify":
            _legacy_qualify_attempt(rows, run["conclusion"], profile, check_run_conclusion=check)
        elif mode == "resume":
            _resume_attempt(rows, run, profile)
        else:
            _fail()


def _check_prior_runs_unwrapped(
    *,
    runs: Sequence[Mapping[str, Any]] | None = None,
    api_get: Callable[[str], Any] | None = None,
    environ: Mapping[str, str] | None = None,
    additional_run_validator: Callable[[Mapping[str, Any], Callable[[str], Any]], bool],
    repository: str = REPOSITORY,
    workflow: str = WORKFLOW,
) -> None:
    """Authenticate all prior runs; absent API/callback evidence fails closed."""
    env = os.environ if environ is None else environ
    if env.get("RS9_TFNF_PRIOR_UPLOAD_UNCONFIRMED", "").strip():
        _fail()
    if env.get("GITHUB_RUN_ATTEMPT", "1").strip() != "1":
        _fail()
    if api_get is None:
        _fail()
    if additional_run_validator is None:
        _fail()
    repo_slug = env.get("GITHUB_REPOSITORY", repository).strip()
    if repo_slug != repository:
        _fail()
    current_raw = env.get("GITHUB_RUN_ID", "").strip()
    if current_raw and not _RUN_ID.fullmatch(current_raw):
        _fail()
    if current_raw and (
        env.get("GITHUB_ACTIONS", "").strip().lower() != "true"
        or not env.get("GITHUB_SHA", "").strip()
    ):
        _fail()
    current_run_id = int(current_raw) if current_raw else None
    current_sha = env.get("GITHUB_SHA", "").strip()
    if current_sha and not _HEX40.fullmatch(current_sha):
        _fail()

    selected: Any = runs
    fetched_full_inventory = selected is None
    if selected is None:
        selected = fetch_paginated_github_list(
            f"https://api.github.com/repos/{repository}/actions/workflows/{workflow}/runs"
            f"?branch=main&event=workflow_dispatch&per_page={PAGE_SIZE}",
            "workflow_runs",
            api_get,
        )
    elif isinstance(selected, Mapping):
        selected = selected.get("workflow_runs")
    if not isinstance(selected, Sequence) or isinstance(selected, (str, bytes)):
        _fail()
    if len(selected) > PAGE_SIZE * MAX_PAGES:
        _fail()

    seen_run_ids: set[int] = set()
    expected_workflow_id: int | None = None
    for run in selected:
        if not isinstance(run, Mapping):
            _fail()
        run_id = run.get("id")
        if type(run_id) is not int or run_id <= 0 or run_id in seen_run_ids:
            _fail()
        seen_run_ids.add(run_id)
        if current_run_id is not None and run_id == current_run_id:
            if run.get("status") == "completed":
                _fail()
            if current_sha and run.get("head_sha") != current_sha:
                _fail()
            continue
        workflow_id = run.get("workflow_id")
        if type(workflow_id) is not int or workflow_id <= 0:
            _fail()
        if expected_workflow_id is None:
            expected_workflow_id = workflow_id
        elif workflow_id != expected_workflow_id:
            _fail()
        _run_context(run, repository=repository, workflow=workflow)
        if additional_run_validator(run, api_get):
            continue
        release, mode, historical_061 = _parse_title_and_inputs(run)
        jobs = fetch_paginated_github_list(
            f"https://api.github.com/repos/{repository}/actions/runs/{run_id}/jobs"
            f"?filter=all&per_page={PAGE_SIZE}",
            "jobs",
            api_get,
        )
        _fallback_validate(run, jobs, release=release, mode=mode, historical_061=historical_061)
    if fetched_full_inventory and not KNOWN_HISTORY_ANCHOR_RUN_IDS.issubset(seen_run_ids):
        _fail()


def check_prior_runs(
    *,
    runs: Sequence[Mapping[str, Any]] | None = None,
    api_get: Callable[[str], Any] | None = None,
    environ: Mapping[str, str] | None = None,
    additional_run_validator: Callable[[Mapping[str, Any], Callable[[str], Any]], bool],
    repository: str = REPOSITORY,
    workflow: str = WORKFLOW,
) -> None:
    """Run the bounded guard and convert non-contract API failures to one refusal."""
    try:
        _check_prior_runs_unwrapped(
            runs=runs,
            api_get=api_get,
            environ=environ,
            additional_run_validator=additional_run_validator,
            repository=repository,
            workflow=workflow,
        )
    except AdmissionError:
        raise
    except Exception:
        _fail()

