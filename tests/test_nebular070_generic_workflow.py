"""Focused routing contracts for the generic 0.7.0 workflow profile."""
from __future__ import annotations

import unittest
from pathlib import Path

from rs9.tf_pypi_nebular import workflow_text as combined_workflow_text
from rs9.tf_pypi_nebular070_publish import (
    publication_resume_job_text,
    workflow_070_jobs_text,
    workflow_070_qualify_jobs_text,
)


class Nebular070GenericWorkflowTests(unittest.TestCase):
    def test_default_route_is_generic_and_keeps_native_matrix(self) -> None:
        qualification = workflow_070_qualify_jobs_text()
        resume = publication_resume_job_text()
        rendered = combined_workflow_text("0.7.0")
        checked_in = (
            Path(__file__).resolve().parents[1]
            / ".github/workflows/rs9-tfnf-pypi-publish.yml"
        ).read_text(encoding="utf-8")

        for text in (qualification, resume, rendered):
            self.assertNotIn("manylinux", text)
            self.assertNotIn("payload-portability", text)
            self.assertNotIn("require-manylinux", text)
            self.assertNotIn("tf-producer-commit", text)
            self.assertNotIn("tf-producer-tree", text)
        self.assertNotIn("manylinux", checked_in)
        self.assertEqual(rendered, checked_in)
        self.assertEqual(qualification.count("Qualify native consumer on "), 3)
        self.assertEqual(qualification.count("--raw-release "), 3)
        self.assertIn("Admit complete 3-platform 0.7.0 qualification matrix", qualification)
        self.assertIn("--matrix-receipt", resume)
        self.assertNotIn("id-token: write", qualification)
        self.assertIn("id-token: write", resume)

    def test_manylinux_is_explicit_opt_in(self) -> None:
        advanced = workflow_070_jobs_text(require_manylinux=True)
        generic = workflow_070_jobs_text()
        self.assertIn("Materialize authenticated 0.7.0 manylinux inputs", advanced)
        self.assertIn("Materialize authenticated 0.7.0 Stage-B admission input", advanced)
        self.assertIn("Resolve captured 0.7.0 manylinux source coordinates", advanced)
        self.assertIn("--require-manylinux", advanced)
        self.assertNotIn("manylinux", generic)
        self.assertIn("Native consumer 0.7.0 (linux-arm64-gnu)", advanced)
        self.assertIn("Native consumer 0.7.0 (linux-x64-gnu)", advanced)

    def test_legacy_workflow_remains_registered(self) -> None:
        legacy = combined_workflow_text("0.6.1")
        self.assertIn("Build and Verify Native Darwin Wheel", legacy)
        self.assertIn("Native macOS ARM64 installed consumer and Scenario A", legacy)
        self.assertIn("build_verify_070:", legacy)


if __name__ == "__main__":
    unittest.main()
