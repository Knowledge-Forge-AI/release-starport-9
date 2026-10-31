"""Earlier-release history stays visible without becoming current admission."""
import copy
import unittest

from rs9 import nebular071_universal_history as current
from rs9 import tf_pypi_nebular071_publish as publisher
from rs9 import tf_pypi_nebular070_publish as predecessor
from rs9.errors import ContractError
from rs9.tf_pypi_archive import AdmissionError
from tests.test_nebular070_universal_history import fixtures


def api_for(run, jobs):
    def api(url):
        key = "jobs" if "/jobs?" in url else "workflow_runs"
        rows = jobs if key == "jobs" else [run]
        return {"total_count": len(rows), key: rows}
    return api


def check_full(run, jobs):
    publisher.check_prior_publish_runs(
        api_get=api_for(run, jobs),
        environ={"GITHUB_ACTIONS": "true", "GITHUB_RUN_ATTEMPT": "1",
                 "GITHUB_RUN_ID": "38", "GITHUB_REPOSITORY": publisher.DEFAULT_GITHUB_REPOSITORY},
        additional_run_validator=current.check_prior_universal_run,
    )


def legacy_qualify():
    run, _ = fixtures()
    run["display_title"] = "RS9 theme-forge-nebular-fusion 0.7.0 qualify / earlier"
    jobs = []
    for number, name in enumerate(sorted(predecessor.ALL_KNOWN_WORKFLOW_JOB_NAMES), 1):
        active = name in predecessor.QUALIFY_070_JOB_NAMES
        steps = [{"name": step, "number": index, "status": "completed", "conclusion": "success"}
                 for index, (step, _) in enumerate(predecessor.WORKFLOW_STEP_PROFILES[name], 1)] if active else []
        jobs.append({"id": 100 + number, "run_id": run["id"], "run_attempt": 1,
                     "head_sha": run["head_sha"], "name": name, "status": "completed",
                     "conclusion": "success" if active else "skipped", "steps": steps})
    return run, jobs


def current_publisher():
    run, _ = fixtures("universal-publish")
    run["display_title"] = run["display_title"].replace("0.7.0", "0.7.1")
    jobs = []
    for number, (name, profile) in enumerate(current._profiles().items(), 1):
        active = name == current.PUBLISH_JOB
        steps = [{"name": step, "number": index, "status": "completed",
                  "conclusion": "skipped" if step == current.UPLOAD_STEP else "success"}
                 for index, step in enumerate(sorted(profile["declared"]), 1)] if active else []
        jobs.append({"id": 100 + number, "run_id": run["id"], "run_attempt": 1,
                     "head_sha": run["head_sha"], "name": name, "status": "completed",
                     "labels": [profile["label"]], "conclusion": "failure" if active else "skipped",
                     "steps": steps})
    return run, jobs


class PredecessorHistoryTests(unittest.TestCase):
    def test_completed_predecessor_qualification_is_still_read(self):
        for pair in (fixtures(), legacy_qualify()):
            with self.subTest(title=pair[0]["display_title"]):
                check_full(*pair)

    def test_predecessor_upload_and_exact_readback_do_not_block_a_new_version(self):
        for uploaded, conclusion in (("success", "failure"), ("skipped", "success")):
            run, jobs = fixtures("universal-publish")
            run["conclusion"] = conclusion
            publish = next(job for job in jobs if job["name"].startswith("Attended Nebular"))
            publish["conclusion"] = conclusion
            next(step for step in publish["steps"] if step["name"] == current.UPLOAD_STEP)["conclusion"] = uploaded
            check_full(run, jobs)

    def test_current_version_upload_remains_unconfirmed(self):
        check_full(*current_publisher())
        for outcome in ("success", "failure", "cancelled"):
            run, jobs = current_publisher()
            publish = next(job for job in jobs if job["name"] == current.PUBLISH_JOB)
            next(step for step in publish["steps"] if step["name"] == current.UPLOAD_STEP)["conclusion"] = outcome
            with self.subTest(outcome=outcome), self.assertRaises((ContractError, AdmissionError)):
                check_full(run, jobs)

    def test_unknown_or_unbound_predecessor_evidence_is_refused(self):
        for mutation in ("job", "step", "missing", "duplicate", "head", "mode", "inputs", "attempt", "running", "repository"):
            run, jobs = fixtures()
            if mutation == "job": jobs[0]["name"] = "Injected job"
            elif mutation == "step":
                active = next(job for job in jobs if job["steps"])
                active["steps"].append({"name": "Injected upload", "number": 999, "status": "completed", "conclusion": "success"})
            elif mutation == "missing": jobs.pop()
            elif mutation == "duplicate": jobs.append(copy.deepcopy(jobs[0]))
            elif mutation == "head": jobs[0]["head_sha"] = "b" * 40
            elif mutation == "mode": run["display_title"] = run["display_title"].replace("universal-qualify", "universal-surprise")
            elif mutation == "inputs": run["inputs"] = {"release": "0.7.1", "mode": "universal-qualify"}
            elif mutation == "attempt": run["run_attempt"] = 2
            elif mutation == "running": run["status"] = "in_progress"
            else: run["repository"] = {"full_name": "untrusted/repository"}
            with self.subTest(mutation=mutation), self.assertRaises((ContractError, AdmissionError)):
                check_full(run, jobs)

    def test_unrecognized_release_is_not_silently_filtered(self):
        run, jobs = fixtures()
        run["display_title"] = run["display_title"].replace("0.7.0", "0.8.0")
        with self.assertRaises(AdmissionError):
            check_full(run, jobs)

    def test_predecessor_publisher_still_requires_complete_closed_evidence(self):
        for mutation in ("active-other", "contradiction", "missing-step", "extra-step", "repeat"):
            run, jobs = fixtures("universal-publish")
            publish = next(job for job in jobs if job["name"].startswith("Attended Nebular"))
            if mutation == "active-other":
                next(job for job in jobs if job is not publish)["conclusion"] = "success"
            elif mutation == "contradiction": run["conclusion"] = "success"
            elif mutation == "missing-step": publish["steps"].pop()
            elif mutation == "extra-step":
                publish["steps"].append({"name": "Injected upload", "number": 999,
                                         "status": "completed", "conclusion": "success"})
            else: run["run_attempt"] = 2
            with self.subTest(mutation=mutation), self.assertRaises((ContractError, AdmissionError)):
                check_full(run, jobs)


if __name__ == "__main__":
    unittest.main()
