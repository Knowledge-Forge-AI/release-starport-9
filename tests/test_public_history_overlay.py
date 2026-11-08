"""Public-layout replay for the extracted common history seam."""
from __future__ import annotations

import copy
import json
from pathlib import Path
from urllib.parse import parse_qs, urlparse
import unittest

from rs9 import nebular080_universal_history as callback
from rs9 import nebular080_universal_workflow as workflow
from rs9 import nebular_history_guard as history
from rs9 import tf_pypi_nebular080_publish as support
from rs9.errors import ContractError
from rs9.tf_pypi_archive import AdmissionError


FIXTURE = Path(__file__).with_name("fixtures") / "github-history-fixture.json"
REPOSITORY = "Knowledge-Forge-AI/release-starport-9"


class FixtureApi:
    """Bounded, read-only replay of the public workflow/jobs responses."""

    def __init__(self, document: dict, *, total_count_delta: int = 0) -> None:
        self.document = document
        self.total_count_delta = total_count_delta
        self.calls: list[str] = []
        self.run_calls: list[str] = []
        self.job_calls: list[str] = []

    def __call__(self, url: str) -> dict:
        self.calls.append(url)
        parsed = urlparse(url)
        if "/actions/workflows/" in parsed.path and parsed.path.endswith("/runs"):
            self.run_calls.append(url)
            page = int(parse_qs(parsed.query).get("page", ["1"])[0])
            expected = "branch=main&event=workflow_dispatch&per_page=100"
            if page == 1:
                self.assert_query(parsed.query, expected)
            else:
                self.assert_query(parsed.query, expected + f"&page={page}")
            rows = self.document["workflow_runs"] if page == 1 else []
            return {
                "total_count": len(self.document["workflow_runs"]) + self.total_count_delta,
                "workflow_runs": rows,
            }
        if "/actions/runs/" in parsed.path and parsed.path.endswith("/jobs"):
            self.job_calls.append(url)
            page = int(parse_qs(parsed.query).get("page", ["1"])[0])
            expected = "filter=all&per_page=100"
            if page == 1:
                self.assert_query(parsed.query, expected)
            else:
                self.assert_query(parsed.query, expected + f"&page={page}")
            run_id = int(parsed.path.split("/actions/runs/", 1)[1].split("/", 1)[0])
            for row in self.document["workflow_runs"]:
                if row["id"] == run_id:
                    return {"total_count": len(row["jobs"]), "jobs": row["jobs"]}
        raise AssertionError("fixture endpoint outside workflow-runs/jobs scope")

    @staticmethod
    def assert_query(actual: str, expected: str) -> None:
        if actual != expected:
            raise AssertionError(f"unexpected public API query: {actual!r}")


def _family(row: dict) -> str:
    title = row.get("display_title", row.get("name", ""))
    head = title.split(" /", 1)[0]
    if "0.7.1 universal-publish" in head:
        return "0.7.1 universal-publish"
    if "0.7.1 universal-qualify" in head:
        return "0.7.1 universal-qualify"
    if "0.7.0 universal-publish" in head:
        return "0.7.0 universal-publish"
    if "0.7.0 universal-qualify" in head:
        return "0.7.0 universal-qualify"
    if "0.7.0 qualify" in head:
        return "0.7.0 qualify"
    return "historical 0.6.1 title"


class PublicHistoryOverlayTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.document = json.loads(FIXTURE.read_text())
        cls.rows = cls.document["workflow_runs"]

    def _check_one(self, row: dict) -> str:
        api = FixtureApi({"workflow_runs": [row]})
        try:
            support.check_prior_publish_runs(
                runs=[row],
                api_get=api,
                environ={"GITHUB_RUN_ATTEMPT": "1", "GITHUB_REPOSITORY": REPOSITORY},
                additional_run_validator=callback.check_prior_universal_run,
            )
        except AdmissionError:
            return "refused"
        return "accepted"

    @staticmethod
    def _synthetic_080_qualify_run() -> dict:
        head_sha = "b" * 40
        run = {
            "id": 88000000001,
            "workflow_id": 389101203,
            "display_title": "RS9 theme-forge-nebular-fusion 0.8.0 universal-qualify / synthetic-080",
            "name": "RS9 theme-forge-nebular-fusion 0.8.0 universal-qualify / synthetic-080",
            "head_sha": head_sha,
            "head_branch": "main",
            "event": "workflow_dispatch",
            "status": "completed",
            "conclusion": "success",
            "repository": {"full_name": REPOSITORY},
            "path": ".github/workflows/rs9-tfnf-pypi-publish.yml",
            "run_attempt": 1,
            "inputs": {"release": "0.8.0", "mode": "universal-qualify"},
        }
        qualification_ids = set(workflow.QUALIFICATION_JOB_IDS)
        jobs = []
        for number, (name, profile) in enumerate(workflow.workflow_job_profiles().items(), 1):
            active = profile["id"] in qualification_ids
            conclusion = "success" if active else "skipped"
            step_names = sorted(profile["declared"]) if active else []
            if active and profile["id"] in qualification_ids and "floor" in name:
                step_names.extend(("Initialize containers", "Stop containers"))
            steps = [
                {
                    "name": step_name,
                    "number": index,
                    "status": "completed",
                    "conclusion": "success",
                }
                for index, step_name in enumerate(step_names, 1)
            ]
            jobs.append({
                "id": 88000000000 + number,
                "run_id": run["id"],
                "run_attempt": 1,
                "head_sha": head_sha,
                "name": name,
                "status": "completed",
                "conclusion": conclusion,
                "labels": [profile["label"]] if active else [],
                "steps": steps,
            })
        run["jobs"] = jobs
        return run

    def test_actual_22_run_inventory_replay_and_version_disposition(self) -> None:
        self.assertEqual(self.document["source"]["logs"], "not fetched")
        self.assertEqual(self.document["source"]["artifacts"], "not fetched")
        self.assertEqual(len(self.rows), 22)
        api = FixtureApi(self.document)
        support.check_prior_publish_runs(
            api_get=api,
            environ={"GITHUB_RUN_ATTEMPT": "1", "GITHUB_REPOSITORY": REPOSITORY},
            additional_run_validator=callback.check_prior_universal_run,
        )
        self.assertEqual(len(api.run_calls), 1)
        self.assertEqual(len(api.job_calls), 22)
        self.assertEqual(
            {support.classify_history_run(row) for row in self.rows},
            {"predecessor"},
        )
        self.assertEqual(
            {row["order"] for row in self.rows if _family(row) == "0.7.1 universal-qualify"},
            {2, 4},
        )
        self.assertEqual(
            {row["order"] for row in self.rows if _family(row) == "0.7.0 universal-publish"},
            {5, 6},
        )
        self.assertEqual(history.PAGE_SIZE, 100)
        self.assertEqual(history.MAX_PAGES, 20)
        rendered = support.rendered_qualification_job_ids()
        self.assertIn("universal_qualification_gate_080", rendered)
        self.assertIn("universal_publication_080", rendered)
        self.assertNotIn("prepare_public_inputs_080", rendered)
        self.assertNotIn("build_universal_bundle_080", rendered)
        predecessor_profiles = callback.predecessor._profiles()
        for name, profile in predecessor_profiles.items():
            if "floor" in name:
                self.assertIn("Initialize containers", profile["allowed"])
                self.assertIn("Stop containers", profile["allowed"])

    def test_verify_history_fixture_requires_explicit_api_and_callback(self) -> None:
        row = next(row for row in self.rows if row["order"] == 1)
        with self.assertRaises(TypeError):
            support.verify_history_fixture([row])
        with self.assertRaises(TypeError):
            support.check_prior_publish_runs(
                runs=[],
                api_get=FixtureApi({"workflow_runs": []}),
                environ={"GITHUB_RUN_ATTEMPT": "1", "GITHUB_REPOSITORY": REPOSITORY},
            )
        result = support.verify_history_fixture(
            self.rows,
            api_get=FixtureApi(self.document),
            additional_run_validator=callback.check_prior_universal_run,
        )
        self.assertEqual(result, {"080": 0, "predecessor": 22})

    def test_pagination_total_duplicate_and_multi_attempt_refuse(self) -> None:
        accepted_row = next(row for row in self.rows if row["order"] == 7)
        duplicate_api = FixtureApi({"workflow_runs": [accepted_row]})
        with self.assertRaises(AdmissionError):
            support.check_prior_publish_runs(
                runs=[accepted_row, copy.deepcopy(accepted_row)],
                api_get=duplicate_api,
                environ={"GITHUB_RUN_ATTEMPT": "1", "GITHUB_REPOSITORY": REPOSITORY},
                additional_run_validator=callback.check_prior_universal_run,
            )
        changing_total = FixtureApi(self.document, total_count_delta=1)
        with self.assertRaises(AdmissionError):
            support.check_prior_publish_runs(
                api_get=changing_total,
                environ={"GITHUB_RUN_ATTEMPT": "1", "GITHUB_REPOSITORY": REPOSITORY},
                additional_run_validator=callback.check_prior_universal_run,
            )
        self.assertTrue(any("page=2" in call for call in changing_total.calls))

        missing_anchor = {
            "workflow_runs": [
                row for row in self.rows if row["id"] != 41232938111
            ]
        }
        with self.assertRaises(AdmissionError):
            support.check_prior_publish_runs(
                api_get=FixtureApi(missing_anchor),
                environ={"GITHUB_RUN_ATTEMPT": "1", "GITHUB_REPOSITORY": REPOSITORY},
                additional_run_validator=callback.check_prior_universal_run,
            )

        multi_attempt = copy.deepcopy(accepted_row)
        multi_attempt["run_attempt"] = 2
        with self.assertRaises(AdmissionError):
            support.check_prior_publish_runs(
                runs=[multi_attempt],
                api_get=FixtureApi({"workflow_runs": [multi_attempt]}),
                environ={"GITHUB_RUN_ATTEMPT": "1", "GITHUB_REPOSITORY": REPOSITORY},
                additional_run_validator=callback.check_prior_universal_run,
            )

    def test_current_run_skip_requires_actions_and_active_matching_sha(self) -> None:
        row = copy.deepcopy(next(row for row in self.rows if row["order"] == 7))
        outside_actions = copy.deepcopy(row)
        outside_actions["status"] = "in_progress"
        base = {
            "GITHUB_RUN_ATTEMPT": "1",
            "GITHUB_REPOSITORY": REPOSITORY,
            "GITHUB_RUN_ID": str(row["id"]),
        }
        outside_env = {**base, "GITHUB_SHA": outside_actions["head_sha"]}
        with self.assertRaises(AdmissionError):
            support.check_prior_publish_runs(
                runs=[outside_actions],
                api_get=FixtureApi({"workflow_runs": [outside_actions]}),
                environ=outside_env,
                additional_run_validator=callback.check_prior_universal_run,
            )

        active = copy.deepcopy(row)
        active["status"] = "in_progress"
        active_env = {
            **base,
            "GITHUB_ACTIONS": "true",
            "GITHUB_SHA": active["head_sha"],
        }
        support.check_prior_publish_runs(
            runs=[active],
            api_get=FixtureApi({"workflow_runs": [active]}),
            environ=active_env,
            additional_run_validator=callback.check_prior_universal_run,
        )

        with self.assertRaises(AdmissionError):
            support.check_prior_publish_runs(
                runs=[active],
                api_get=FixtureApi({"workflow_runs": [active]}),
                environ={**base, "GITHUB_ACTIONS": "true"},
                additional_run_validator=callback.check_prior_universal_run,
            )

        with self.assertRaises(AdmissionError):
            support.check_prior_publish_runs(
                runs=[row],
                api_get=FixtureApi({"workflow_runs": [row]}),
                environ=active_env,
                additional_run_validator=callback.check_prior_universal_run,
            )
        mismatched = copy.deepcopy(active)
        mismatched["head_sha"] = "f" * 40
        with self.assertRaises(AdmissionError):
            support.check_prior_publish_runs(
                runs=[mismatched],
                api_get=FixtureApi({"workflow_runs": [mismatched]}),
                environ=active_env,
                additional_run_validator=callback.check_prior_universal_run,
            )

    def test_080_container_lifecycle_is_block_derived_only(self) -> None:
        profiles = workflow.workflow_job_profiles()
        qualification_ids = set(workflow.QUALIFICATION_JOB_IDS)
        lifecycle = {"Initialize containers", "Stop containers"}
        floor = [
            (name, row) for name, row in profiles.items()
            if row["id"] in qualification_ids and "floor" in name
        ]
        non_floor = [
            (name, row) for name, row in profiles.items()
            if (
                row["id"] in qualification_ids and "floor" not in name
            ) or row["id"] == workflow.PUBLICATION_JOB_ID
        ]
        self.assertEqual(len(floor), 2)
        for _, row in floor:
            self.assertTrue(lifecycle <= row["allowed"])
            self.assertTrue(lifecycle.isdisjoint(row["declared"]))
        for _, row in non_floor:
            self.assertTrue(lifecycle.isdisjoint(row["allowed"]))
            self.assertTrue(lifecycle.isdisjoint(row["declared"]))

    def test_080_floor_lifecycle_accepts_callback_and_qualification_validator(self) -> None:
        """Synthetic job shape proof only; hosted qualification remains separate."""
        run = self._synthetic_080_qualify_run()
        api = FixtureApi({"workflow_runs": [run]})
        self.assertTrue(callback.check_prior_universal_run(run, api))
        qualified = callback.validate_qualification_jobs(run, run["jobs"])
        self.assertEqual(set(qualified), set(workflow.QUALIFICATION_JOB_IDS))

    def test_080_nonfloor_lifecycle_injection_refuses(self) -> None:
        run = self._synthetic_080_qualify_run()
        target = next(
            job for job in run["jobs"]
            if job["name"].startswith("Universal installed consumer 0.8.0")
            and "floor" not in job["name"]
        )
        target["steps"].append({
            "name": "Initialize containers",
            "number": len(target["steps"]) + 1,
            "status": "completed",
            "conclusion": "success",
        })
        with self.assertRaises(ContractError):
            callback.check_prior_universal_run(
                run,
                FixtureApi({"workflow_runs": [run]}),
            )
        with self.assertRaises(ContractError):
            callback.validate_qualification_jobs(run, run["jobs"])

    def test_nonfloor_container_lifecycle_step_is_rejected(self) -> None:
        run = copy.deepcopy(next(row for row in self.rows if row["order"] == 2))
        target = next(
            job for job in run["jobs"]
            if "floor" not in job["name"] and job["conclusion"] == "success"
        )
        target["steps"][0]["name"] = "Initialize containers"
        with self.assertRaises(AdmissionError):
            support.check_prior_publish_runs(
                runs=[run],
                api_get=FixtureApi({"workflow_runs": [run]}),
                environ={"GITHUB_RUN_ATTEMPT": "1", "GITHUB_REPOSITORY": REPOSITORY},
                additional_run_validator=callback.check_prior_universal_run,
            )

    def test_predecessor_profiles_are_deep_copied(self) -> None:
        first = callback.predecessor._profiles()
        name = next(iter(first))
        first[name]["declared"].add("test-only mutation")
        second = callback.predecessor._profiles()
        self.assertNotIn("test-only mutation", second[name]["declared"])
        universal_first = callback._profiles()
        universal_name = next(iter(universal_first))
        universal_first[universal_name]["declared"].add("test-only mutation")
        universal_second = callback._profiles()
        self.assertNotIn("test-only mutation", universal_second[universal_name]["declared"])


if __name__ == "__main__":
    unittest.main()

