"""Closed Actions job history for the universal Nebular publication domain.

Historical wheel profiles retain their own reader. New-mode records do not
disappear from pagination and cannot substitute for historical evidence.
"""
from __future__ import annotations

from collections.abc import Mapping
import re

from rs9 import tf_pypi_nebular071_publish as legacy
from rs9 import nebular071_universal_workflow as workflow
from rs9 import nebular071_predecessor_history as predecessor
from rs9.errors import ContractError


PUBLISH_JOB = "Attended Nebular 0.7.1 universal PyPI publication"
UPLOAD_STEP = "Publish universal launcher distribution to PyPI"
GUARD_JOB = "Reject unsupported release and mode combination"


def _fail():
    raise ContractError("NEBULAR_UNIVERSAL_PRIOR_ATTEMPT_UNCONFIRMED",
                        "The retained workflow history is not conclusive")


def _mode(run: Mapping) -> str | None:
    title = run.get("display_title", run.get("name"))
    if not isinstance(title, str):
        _fail()
    prefix = "RS9 theme-forge-nebular-fusion 0.7.1 "
    if not title.startswith(prefix + "universal-"):
        return None
    head, separator, tail = title.partition(" /")
    mode = head.removeprefix(prefix)
    if (separator != " /" or mode not in {workflow.QUALIFY_MODE, workflow.PUBLISH_MODE}
            or (tail not in {"", " "} and (not tail.startswith(" ") or tail[1:] != tail[1:].strip()))):
        _fail()
    if run.get("inputs") is not None:
        inputs = run["inputs"]
        if (not isinstance(inputs, Mapping) or not {"release", "mode"}.issubset(inputs)
                or set(inputs) - {"release", "mode", "dispatch_id"}
                or inputs["release"] != "0.7.1" or inputs["mode"] != mode):
            _fail()
    return mode


def _profiles() -> dict:
    """Derive fixed names from maintained source, never from API-supplied YAML."""
    from rs9.tf_pypi_nebular071_publish import workflow_text
    document = workflow_text("0.7.1")
    if document.count("\njobs:\n") != 1:
        _fail()
    jobs = workflow._split_jobs(document.partition("\njobs:\n")[2])
    profiles = {}
    for job_id, text in jobs.items():
        names = re.findall(r"(?m)^    name: (.+)$", text)
        if len(names) != 1 or names[0] in profiles:
            _fail()
        declared, actions = set(), set()
        steps = list(re.finditer(r"(?m)^      - name: (.+)$", text))
        for index, match in enumerate(steps):
            name = match[1]
            if name in declared:
                _fail()
            declared.add(name)
            block = text[match.end():steps[index + 1].start() if index + 1 < len(steps) else len(text)]
            if re.search(r"(?m)^        uses: ", block):
                actions.add(name)
        labels = re.findall(r"(?m)^    runs-on: ([a-z0-9.-]+)$", text)
        if len(labels) != 1:
            _fail()
        container_lifecycle = ({"Initialize containers", "Stop containers"}
                               if re.search(r"(?m)^    container:\s*$", text) else set())
        profiles[names[0]] = {
            "id": job_id, "declared": declared,
            "allowed": declared | {"Post " + item for item in actions}
            | {"Set up job", "Complete job"} | container_lifecycle,
            "label": labels[0],
        }
    expected_qualifiers = workflow.rendered_qualification_job_ids(document)
    actual_qualifiers = tuple(sorted(
        row["id"] for row in profiles.values()
        if row["id"].startswith("universal_") and row["id"] != "universal_publication_071"
    ))
    if (PUBLISH_JOB not in profiles or GUARD_JOB not in profiles
            or actual_qualifiers != expected_qualifiers):
        _fail()
    return profiles


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
        if (type(attempt) is not int or not 1 <= attempt <= maximum
                or type(identity) is not int or identity <= 0 or identity in seen_ids
                or not isinstance(name, str) or name not in profiles or name in attempts.get(attempt, {})
                or job.get("run_id") != run["id"] or type(job.get("run_id")) is not int
                or job.get("head_sha") != run["head_sha"] or job.get("status") != "completed"
                or job.get("conclusion") not in legacy.VALID_WORKFLOW_JOB_CONCLUSIONS):
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
            if (not isinstance(step_name, str) or not step_name or step_name in seen_steps
                    or type(number) is not int or number <= 0 or number in seen_numbers
                    or step.get("status") != "completed"
                    or step.get("conclusion") not in legacy.VALID_WORKFLOW_JOB_CONCLUSIONS
                    or (job["conclusion"] == "skipped" and step["conclusion"] != "skipped")
                    or (step["conclusion"] != "skipped" and step_name not in profiles[name]["allowed"])):
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
    if (not isinstance(run, Mapping) or type(run.get("id")) is not int or run["id"] <= 0
            or type(run.get("workflow_id")) is not int or run["workflow_id"] <= 0
            or not isinstance(run.get("head_sha"), str)
            or not re.fullmatch(r"[0-9a-f]{40}", run["head_sha"])
            or run.get("head_branch") != "main" or run.get("event") != "workflow_dispatch"
            or run.get("status") != "completed"
            or run.get("conclusion") not in legacy.VALID_WORKFLOW_RUN_CONCLUSIONS
            or not isinstance(run.get("repository"), Mapping)
            or run["repository"].get("full_name") != legacy.DEFAULT_GITHUB_REPOSITORY):
        _fail()
    legacy._normalize_workflow_run_path(run.get("path"), head_sha=run["head_sha"])


def _non_upload_attempt(mode: str, jobs: Mapping, profiles: Mapping) -> None:
    qualifier_names = {name for name, row in profiles.items()
                       if row["id"].startswith("universal_") and name != PUBLISH_JOB}
    if mode == workflow.QUALIFY_MODE:
        if any(jobs[name]["conclusion"] != "skipped" for name in set(profiles) - qualifier_names):
            _fail()
        return
    if any(jobs[name]["conclusion"] != "skipped" for name in set(profiles) - {PUBLISH_JOB}):
        _fail()
    publish = jobs[PUBLISH_JOB]
    if publish["conclusion"] not in legacy.ACTIVE_FAILURE_CONCLUSIONS:
        _fail()
    upload = [step for step in publish.get("steps", []) if step.get("name") == UPLOAD_STEP]
    if len(upload) != 1 or upload[0].get("conclusion") != "skipped":
        _fail()


def check_prior_universal_run(run: Mapping, client_json) -> bool:
    """Handle only recognized new modes; preserve the legacy full-list fallback."""
    mode = _mode(run)
    if mode is None:
        return predecessor.check_predecessor_run(run, client_json)
    _run_context(run)
    if mode == workflow.PUBLISH_MODE and run.get("run_attempt") != 1:
        _fail()
    profiles = _profiles()
    rows = legacy._fetch_paginated_github_list(
        f"https://api.github.com/repos/{legacy.DEFAULT_GITHUB_REPOSITORY}/actions/runs/{run['id']}/jobs"
        f"?filter=all&per_page={legacy.PRIOR_RUN_PAGE_SIZE}", "jobs", client_json)
    for jobs in _attempt_jobs(run, rows, profiles=profiles).values():
        _non_upload_attempt(mode, jobs, profiles)
    return True


def validate_qualification_jobs(run: Mapping, jobs: list) -> dict:
    """Require all eight source-bound jobs, including each native lane, to pass."""
    _run_context(run)
    if (run.get("conclusion") != "success" or run.get("run_attempt") != 1
            or _mode(run) != workflow.QUALIFY_MODE):
        _fail()
    profiles = _profiles()
    observed = _attempt_jobs(run, jobs, profiles=profiles)[1]
    _non_upload_attempt(workflow.QUALIFY_MODE, observed, profiles)
    qualifier_names = {
        profile["id"] for name, profile in profiles.items()
        if profile["id"].startswith("universal_") and name != PUBLISH_JOB
    }
    qualified = {}
    for name, profile in profiles.items():
        if not profile["id"].startswith("universal_") or name == PUBLISH_JOB:
            continue
        job = observed[name]
        if (job["conclusion"] != "success" or not isinstance(job.get("labels"), list)
                or profile["label"] not in job["labels"]):
            _fail()
        # Diagnostic uploads are optional; qualification/upload steps are not.
        required = {
            step for step in profile["declared"]
            if (
                step.startswith(("Qualify native consumer ", "Upload ", "Prepare held ",
                                 "Build and verify one universal launcher wheel",
                                 "Validate all five universal installed consumer lanes"))
                or step == "Check Bookworm installed tfnf missing system WebKit before runtime install"
            )
        }
        by_name = {step["name"]: step for step in job["steps"]}
        if any(by_name.get(step, {}).get("conclusion") != "success" for step in required
               if step != "Upload failed native harness report"):
            _fail()
        qualified[profile["id"]] = job["id"]
    if len(qualified) != len(qualifier_names):
        _fail()
    return qualified
