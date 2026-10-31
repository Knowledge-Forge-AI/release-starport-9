"""Read the closed 0.7.0 history domain during 0.7.1 upload admission.

This module reuses predecessor job/step validators only. It cannot provide a
current wheel, consumer receipt, qualification source or publication authority.
An earlier version's completed upload is history, not a repeat current upload.
"""
from collections.abc import Mapping

from rs9 import nebular070_universal_history as predecessor_history
from rs9 import tf_pypi_nebular070_publish as predecessor
from rs9.errors import ContractError


def _fail():
    raise ContractError("NEBULAR_UNIVERSAL_PRIOR_ATTEMPT_UNCONFIRMED",
                        "The predecessor workflow history is not conclusive")


def _published_history(run: Mapping, jobs: Mapping, profiles: Mapping) -> None:
    """Validate a past-version publisher, including an already executed upload."""
    name = predecessor_history.PUBLISH_JOB
    if any(job["conclusion"] != "skipped" for key, job in jobs.items() if key != name):
        _fail()
    publish = jobs[name]
    if publish["conclusion"] != run["conclusion"]:
        _fail()
    if publish["conclusion"] not in {"success"} | predecessor.ACTIVE_FAILURE_CONCLUSIONS:
        _fail()
    observed = {step["name"] for step in publish["steps"]}
    if not profiles[name]["declared"].issubset(observed):
        _fail()


def check_predecessor_run(run: Mapping, client_json) -> bool:
    """Consume exactly the predecessor release; unknown releases keep falling back."""
    title = run.get("display_title", run.get("name"))
    if not isinstance(title, str) or not title.startswith("RS9 theme-forge-nebular-fusion 0.7.0 "):
        return False
    predecessor_history._run_context(run)
    mode = predecessor_history._mode(run)
    jobs = predecessor._fetch_paginated_github_list(
        f"https://api.github.com/repos/{predecessor.DEFAULT_GITHUB_REPOSITORY}/actions/runs/{run['id']}/jobs"
        f"?filter=all&per_page={predecessor.PRIOR_RUN_PAGE_SIZE}", "jobs", client_json)
    if mode is not None:
        profiles = predecessor_history._profiles()
        attempts = predecessor_history._attempt_jobs(run, jobs, profiles=profiles)
        if mode == "universal-publish" and run["run_attempt"] != 1:
            _fail()
        for rows in attempts.values():
            if mode == "universal-publish":
                _published_history(run, rows, profiles)
            else:
                predecessor_history._non_upload_attempt(mode, rows, profiles)
        return True
    release, mode, _ = predecessor._parse_prior_run_title_and_inputs(run)
    if release != "0.7.0" or mode not in {"qualify", "resume"}:
        _fail()
    attempts = predecessor._validate_prior_run_jobs_by_attempt(
        jobs, run_id=run["id"], run_attempt=run["run_attempt"], head_sha=run["head_sha"])
    for attempt, rows in attempts.items():
        if mode == "qualify":
            predecessor._validate_070_qualify_prior_run(
                run, rows, check_run_conclusion=attempt == run["run_attempt"])
        else:
            predecessor._validate_070_resume_prior_run(run, rows)
    return True
