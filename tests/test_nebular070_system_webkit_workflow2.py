"""Focused [SYNTHETIC] checks for Linux system-WebKit workflow routing."""

from __future__ import annotations

import unittest

from rs9.tf_pypi_archive import AdmissionError
from rs9.tf_pypi_nebular070_publish import (
    NATIVE_CONSUMER_070_FLOOR_JOB_NAMES,
    NATIVE_CONSUMER_070_JOB_NAMES,
    WORKFLOW_STEP_PROFILES,
    _validate_prior_run_job_steps,
    workflow_070_jobs_text,
)


class SystemWebKitWorkflow2Tests(unittest.TestCase):
    def test_added_steps_are_admitted_for_each_linux_job(self) -> None:
        for job_name in sorted(NATIVE_CONSUMER_070_JOB_NAMES):
            added = {
                name
                for name, _uses in WORKFLOW_STEP_PROFILES[job_name]
                if name.startswith((
                    "Resolve explicit Linux runtime profile",
                    "Install Ubuntu system WebKit runtime packages",
                    "Verify Ubuntu system WebKit runtime packages",
                    "Check Bookworm installed tfnf missing system WebKit",
                    "Install Bookworm system WebKit runtime packages",
                    "Verify Bookworm system WebKit runtime packages",
                ))
            }
            if job_name in NATIVE_CONSUMER_070_FLOOR_JOB_NAMES:
                self.assertEqual(len(added), 4)
            elif job_name != "Native consumer 0.7.0 (darwin-arm64)":
                self.assertEqual(len(added), 3)
            else:
                self.assertEqual(added, set())
                continue
            steps = [
                {"name": name, "status": "completed", "conclusion": "success"}
                for name in added
            ]
            _validate_prior_run_job_steps(job_name, "success", {"steps": steps})

    def test_active_unknown_step_is_rejected_but_skipped_is_historical(self) -> None:
        job_name = "Native consumer 0.7.0 (linux-arm64-gnu floor)"
        unknown = {
            "steps": [
                {
                    "name": "Untrusted injected active step",
                    "status": "completed",
                    "conclusion": "success",
                }
            ]
        }
        with self.assertRaises(AdmissionError):
            _validate_prior_run_job_steps(job_name, "success", unknown)
        skipped = {
            "steps": [
                {
                    "name": "Untrusted historical skipped step",
                    "status": "completed",
                    "conclusion": "skipped",
                }
            ]
        }
        _validate_prior_run_job_steps(job_name, "success", skipped)

    def test_failure_reports_are_separate_and_only_collected_after_failure(self) -> None:
        text = workflow_070_jobs_text()
        self.assertEqual(text.count("- name: Upload failed native harness report"), 5)
        self.assertEqual(text.count("/installed-native-smoke/**/*.run.json"), 5)
        for section in text.split("- name: Upload failed native harness report")[1:]:
            diagnostic = section.split("\n\n", 1)[0]
            self.assertIn("if: failure()", diagnostic)
            self.assertIn("-failure-diagnostic", diagnostic)
            self.assertIn("if-no-files-found: ignore", diagnostic)
            self.assertNotIn("stdout.log", diagnostic)
            self.assertNotIn("stderr.log", diagnostic)
        for job in NATIVE_CONSUMER_070_JOB_NAMES:
            self.assertIn(("Upload failed native harness report", True), WORKFLOW_STEP_PROFILES[job])

    def test_generated_linux_routes_keep_five_jobs_and_runtime_guards(self) -> None:
        text = workflow_070_jobs_text()
        self.assertEqual(text.count("\n  native_consumer_070_"), 5)
        self.assertEqual(
            text.count("Resolve explicit Linux runtime profile"), 4
        )
        self.assertEqual(
            text.count("Install Ubuntu system WebKit runtime packages"), 2
        )
        self.assertEqual(
            text.count("Check Bookworm installed tfnf missing system WebKit before runtime install"),
            2,
        )
        self.assertEqual(
            text.count("Install Bookworm system WebKit runtime packages"),
            2,
        )
        self.assertIn(
            "if: steps.linux_runtime_profile.outputs.profile == 'system-webkitgtk-4.1'",
            text,
        )
        self.assertEqual(text.count(" check-system-webkit-missing "), 2)
        self.assertIn("--system-floor-receipts", text)
        self.assertNotIn("test \"$status\" -ne 0", text)
        self.assertIn("libwebkit2gtk-4.1-0", text)
        self.assertIn("libjavascriptcoregtk-4.1-0", text)
        floor_jobs = (
            "native_consumer_070_linux_arm64_gnu_floor:",
            "native_consumer_070_linux_x64_gnu_floor:",
        )
        for index, job_name in enumerate(floor_jobs):
            start = text.index(f"  {job_name}")
            if index + 1 < len(floor_jobs):
                end = text.index(f"  {floor_jobs[index + 1]}", start)
                section = text[start:end]
            else:
                section = text[start:].split("\n  qualification_gate_070:", 1)[0]
            self.assertIn("defaults:\n      run:\n        shell: bash", section)
            self.assertIn("TFNF_CI_TEMP: /__w/_temp", section)
            self.assertIn("working-directory: qualification-source", section)
            self.assertIn("path: qualification-source", section)
            self.assertEqual(section.count("working-directory: ${{ github.workspace }}"), 2)
            self.assertIn('repository=Path(os.environ["GITHUB_WORKSPACE"]) / "qualification-source"', section)
            self.assertNotIn("safe.directory", section)
            self.assertNotIn("chown", section)
            self.assertNotIn("runner.temp", section)
            self.assertIn("Select pinned Bookworm Python 3.11", section)
            self.assertIn("python-path=/usr/bin/python3", section)
            self.assertNotIn("actions/setup-python@", section)
            target = "linux-arm64-gnu" if index == 0 else "linux-x64-gnu"
            self.assertIn(("Select pinned Bookworm Python 3.11", False),
                          WORKFLOW_STEP_PROFILES[f"Native consumer 0.7.0 ({target} floor)"])
            tools = section.split("- name: Install pinned Bookworm floor tools", 1)[1]
            self.assertLess(
                tools.index('mkdir -p "${{ env.TFNF_CI_TEMP }}"'),
                tools.index("apt-get update"),
            )
            self.assertLess(
                section.index("Check Bookworm installed tfnf missing system WebKit"),
                section.index("Install Bookworm system WebKit runtime packages"),
            )


if __name__ == "__main__":
    unittest.main()
