"""Closed Actions lifecycle steps for the two maintained Bookworm jobs."""
from __future__ import annotations

import re
import unittest

from rs9 import tf_pypi_nebular070_publish as publish
from rs9.tf_pypi_archive import AdmissionError


FLOOR_JOBS = {
    "Native consumer 0.7.0 (linux-arm64-gnu floor)",
    "Native consumer 0.7.0 (linux-x64-gnu floor)",
}


def step(name, conclusion="success"):
    return {"name": name, "status": "completed", "conclusion": conclusion}


class ContainerJobStepTests(unittest.TestCase):
    def test_intermediate_observations_stay_outside_the_qualification_artifact_root(self):
        paths = re.findall(r'--consumer-capture-output\s+"([^"]+)"', publish.workflow_070_qualify_jobs_text())
        self.assertEqual(len(paths), 4)  # two primary and two floor captures
        for path in paths:
            with self.subTest(path=path):
                self.assertNotIn("/tfnf-070-qual/", path)
                self.assertTrue(path.startswith(("${{ runner.temp }}/", "${{ env.TFNF_CI_TEMP }}/")))
        workflow = publish.workflow_070_qualify_jobs_text()
        for target in ("linux-arm64-gnu", "linux-x64-gnu"):
            self.assertIn(f"/tfnf-070-qual/{target}/result.json", workflow)

    def test_real_container_lifecycle_is_admitted_only_in_floor_jobs(self):
        for job in FLOOR_JOBS:
            with self.subTest(job=job):
                publish._validate_prior_run_job_steps(job, "success", {
                    "steps": [step("Set up job"), step("Initialize containers"),
                              step("Install pinned Bookworm floor tools"),
                              step("Stop containers"), step("Complete job")],
                })
        for job in publish.ALL_KNOWN_WORKFLOW_JOB_NAMES - FLOOR_JOBS:
            for name in ("Initialize containers", "Stop containers"):
                with self.subTest(job=job, name=name), self.assertRaises(AdmissionError):
                    publish._validate_prior_run_job_steps(job, "success", {"steps": [step(name)]})

    def test_observed_bookworm_sequence_retains_required_step_validation(self):
        # Names and conclusions observed in the genuine main qualification run.
        for target in ("linux-arm64-gnu", "linux-x64-gnu"):
            names = [
                "Set up job", "Initialize containers", "Install pinned Bookworm floor tools",
                "Verify Bookworm display tool class", "Checkout exact source",
                "Select pinned Bookworm Python 3.11", "Set up Node 22",
                "Download 0.7.0 candidate bundle", "Download 0.7.0 public inputs",
                "Resolve explicit Linux runtime profile",
                "Check Bookworm installed tfnf missing system WebKit before runtime install",
                "Install Bookworm system WebKit runtime packages",
                "Verify Bookworm system WebKit runtime packages",
                f"Qualify native consumer on {target} floor",
                f"Upload {target} floor qualification receipt",
                "Upload failed native harness report", "Post Set up Node 22",
                "Post Checkout exact source", "Stop containers", "Complete job",
            ]
            job = f"Native consumer 0.7.0 ({target} floor)"
            steps = [step(name, "skipped" if name == "Upload failed native harness report" else "success")
                     for name in names]
            publish._validate_prior_run_job_steps(job, "success", {"steps": steps})
            for injected in ("Execute arbitrary upload", "Post Initialize containers", "Stop unowned containers"):
                with self.subTest(job=job, injected=injected), self.assertRaises(AdmissionError):
                    publish._validate_prior_run_job_steps(job, "success", {"steps": [*steps, step(injected)]})

    def test_container_lifecycle_does_not_relax_status_or_skipped_job_checks(self):
        for job in FLOOR_JOBS:
            for malformed in ({**step("Initialize containers"), "status": "in_progress"},
                              {**step("Stop containers"), "conclusion": "unknown"}):
                with self.subTest(job=job, malformed=malformed), self.assertRaises(AdmissionError):
                    publish._validate_prior_run_job_steps(job, "success", {"steps": [malformed]})
            with self.subTest(job=job), self.assertRaises(AdmissionError):
                publish._validate_prior_run_job_steps(job, "skipped", {"steps": [step("Stop containers")]})


if __name__ == "__main__":
    unittest.main()
