"""Pure API fixtures for the distinct universal workflow history domain."""
import copy
import unittest
from unittest.mock import patch

from rs9 import nebular070_universal_history as history
from rs9 import nebular070_universal_workflow as workflow
from rs9 import tf_pypi_nebular070_publish as legacy
from rs9.errors import ContractError
from rs9.tf_pypi_archive import AdmissionError


def fixtures(mode=workflow.QUALIFY_MODE):
    run = {
        "id": 37, "run_attempt": 1, "workflow_id": 11, "head_sha": "a" * 40,
        "head_branch": "main", "event": "workflow_dispatch", "status": "completed",
        "conclusion": "success" if mode == workflow.QUALIFY_MODE else "failure",
        "path": ".github/workflows/rs9-tfnf-pypi-publish.yml",
        "repository": {"full_name": legacy.DEFAULT_GITHUB_REPOSITORY},
        "display_title": "RS9 theme-forge-nebular-fusion 0.7.0 " + mode + " / fixture-intent",
    }
    jobs = []
    for number, (name, profile) in enumerate(history._profiles().items(), 1):
        active = ((profile["id"].startswith("universal_") and name != history.PUBLISH_JOB)
                  if mode == workflow.QUALIFY_MODE else name == history.PUBLISH_JOB)
        steps = []
        if active:
            for step_number, step in enumerate(sorted(profile["declared"]), 1):
                skipped = step == "Upload failed native harness report" or (
                    mode == workflow.PUBLISH_MODE and step == history.UPLOAD_STEP)
                steps.append({"name": step, "number": step_number, "status": "completed",
                              "conclusion": "skipped" if skipped else "success"})
        jobs.append({
            "id": 100 + number, "run_id": 37, "run_attempt": 1, "head_sha": "a" * 40,
            "name": name, "status": "completed", "labels": [profile["label"]], "steps": steps,
            "conclusion": ("success" if mode == workflow.QUALIFY_MODE else "failure") if active else "skipped",
        })
    return run, jobs


class UniversalWorkflowHistoryTests(unittest.TestCase):
    def test_real_container_lifecycle_is_scoped_to_the_two_bookworm_jobs(self):
        run, jobs = fixtures()
        for job in jobs:
            if "floor)" in job["name"]:
                job["steps"] += [
                    {"name": "Initialize containers", "number": 900, "status": "completed", "conclusion": "success"},
                    {"name": "Stop containers", "number": 901, "status": "completed", "conclusion": "success"},
                ]
        self.assertEqual(len(history.validate_qualification_jobs(run, jobs)), 8)
        for name in ("Initialize containers", "Stop containers", "Post Initialize containers"):
            observed = copy.deepcopy(jobs)
            newer = next(job for job in observed if job["name"] == "Universal installed consumer 0.7.0 (linux-x64-gnu)")
            newer["steps"].append({"name": name, "number": 900, "status": "completed", "conclusion": "success"})
            with self.subTest(name=name), self.assertRaises(ContractError):
                history.validate_qualification_jobs(run, observed)

    def test_all_eight_source_native_and_matrix_jobs_are_required(self):
        run, jobs = fixtures()
        result = history.validate_qualification_jobs(run, jobs)
        self.assertEqual(len(result), 8)
        self.assertEqual(len([name for name in result if name.startswith("universal_native_consumer")]), 5)
        for mutation in ("lane", "label", "step", "upload", "extra", "source", "rerun"):
            observed = copy.deepcopy(jobs)
            observed_run = copy.deepcopy(run)
            native = next(row for row in observed if "floor)" in row["name"])
            if mutation == "lane": native["conclusion"] = "skipped"
            elif mutation == "label": native["labels"] = ["wrong-runner"]
            elif mutation == "step":
                next(step for step in native["steps"] if step["name"].startswith("Qualify native"))["conclusion"] = "skipped"
            elif mutation == "upload":
                next(row for row in observed if row["name"] == history.PUBLISH_JOB)["conclusion"] = "success"
            elif mutation == "extra":
                native["steps"].append({"name": "Injected upload", "number": 999,
                                         "status": "completed", "conclusion": "success"})
            elif mutation == "source": native["head_sha"] = "b" * 40
            else: observed_run["run_attempt"] = 2
            with self.subTest(mutation=mutation), self.assertRaises(ContractError):
                history.validate_qualification_jobs(observed_run, observed)

    def test_history_does_not_drop_new_runs_or_accept_an_uncertain_upload(self):
        for mode in (workflow.QUALIFY_MODE, workflow.PUBLISH_MODE):
            run, jobs = fixtures(mode)
            reader = lambda _url: {"total_count": len(jobs), "jobs": jobs}
            self.assertTrue(history.check_prior_universal_run(run, reader))
            if mode == workflow.PUBLISH_MODE:
                publish = next(row for row in jobs if row["name"] == history.PUBLISH_JOB)
                step = next(row for row in publish["steps"] if row["name"] == history.UPLOAD_STEP)
                for outcome in ("success", "failure", "cancelled"):
                    step["conclusion"] = outcome
                    with self.subTest(outcome=outcome), self.assertRaises(ContractError):
                        history.check_prior_universal_run(run, reader)

    def test_legacy_titles_are_left_to_the_historical_reader(self):
        run, _jobs = fixtures()
        run["display_title"] = "RS9 theme-forge-nebular-fusion 0.7.0 qualify / historical"
        with patch.object(legacy, "_fetch_paginated_github_list") as fetch:
            self.assertFalse(history.check_prior_universal_run(run, object()))
            fetch.assert_not_called()

    def test_unknown_names_duplicate_jobs_and_invalid_new_mode_are_refused(self):
        for mutation in ("unknown", "duplicate", "bool_id", "incomplete", "inputs", "mode"):
            run, jobs = fixtures()
            if mutation == "unknown": jobs[0]["name"] = "Unknown active job"
            elif mutation == "duplicate": jobs.append(copy.deepcopy(jobs[0]))
            elif mutation == "bool_id": jobs[0]["id"] = True
            elif mutation == "incomplete": jobs.pop()
            elif mutation == "inputs": run["inputs"] = {"release": "0.6.1", "mode": workflow.QUALIFY_MODE}
            else: run["display_title"] = run["display_title"].replace("universal-qualify", "universal-resume")
            with self.subTest(mutation=mutation), self.assertRaises(ContractError):
                history.check_prior_universal_run(run, lambda _url: {"total_count": len(jobs), "jobs": jobs})

    def test_full_history_hook_runs_after_common_guards_and_preserves_unknown_fallback(self):
        run, jobs = fixtures()
        env = {"GITHUB_ACTIONS": "true", "GITHUB_RUN_ATTEMPT": "1", "GITHUB_RUN_ID": "38",
               "GITHUB_REPOSITORY": legacy.DEFAULT_GITHUB_REPOSITORY}
        def api(url):
            if "/jobs?" in url: return {"total_count": len(jobs), "jobs": jobs}
            return {"total_count": 1, "workflow_runs": [run]}
        legacy.check_prior_publish_runs(api_get=api, environ=env,
                                       additional_run_validator=history.check_prior_universal_run)
        run["repository"] = {"full_name": "untrusted/repository"}
        with patch.object(history, "check_prior_universal_run") as hook, self.assertRaises(AdmissionError):
            legacy.check_prior_publish_runs(api_get=api, environ=env, additional_run_validator=hook)
        hook.assert_not_called()
