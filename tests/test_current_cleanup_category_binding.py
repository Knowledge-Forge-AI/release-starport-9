"""Existing category-only cleanup diagnostics without observer activation."""
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from rs9 import application_smoke_diagnostic as diagnostic
from rs9.smoke_stream_tokens import project_problem_categories

CLEANUP = "harness cleanup of the owned scratch directory failed"
CATEGORY = [{"category": "harness-cleanup-failed", "count": 1}]


def failed_record(problem=CLEANUP):
    return {"status": "fail", "problems": [problem],
            "executable": {"sha256": "a" * 64},
            "finalization": {"schema": "nebular.native-rc-finalization-v1",
                "status": "failed", "phase": "cleanup", "exceptionFamily": "filesystem",
                "spawned": True, "exitObserved": True,
                "applicationReceiptObservation": "present-at-read",
                "applicationReceiptCopy": "written"}}


class CurrentCleanupCategoryTests(unittest.TestCase):
    def attempt(self, root, record):
        (root / "linux-arm64-B.run.json").write_text(json.dumps(record))
        prepared = {"tools": root, "source": root, "scratch": root,
                    "source_generation": "theme-forge-current-202610"}
        completed = subprocess.CompletedProcess([], 1 if record["status"] == "fail" else 0, b"", b"")
        with patch.object(diagnostic.subprocess, "run", return_value=completed) as run:
            result = diagnostic._attempt(prepared, "linux-arm64", "B", root, root,
                                         [], {}, False, system="aarch64-linux")
        self.assertEqual(run.call_count, 1)
        self.assertEqual(run.call_args.kwargs["timeout"], 240)
        self.assertNotIn("--rs9-initial-observation-kind", run.call_args.args[0])
        return result

    def test_authenticated_source_enables_category_without_observer_or_finalization(self):
        with tempfile.TemporaryDirectory() as directory:
            with patch.object(diagnostic, "_current_replay_progress_profile",
                              return_value=diagnostic.CURRENT071_REPLAY_PROGRESS_PROFILE):
                result = self.attempt(Path(directory), failed_record())
        self.assertTrue(result["failed"])
        self.assertEqual(result["receipt_error"], "receipt-failed")
        categories = result["harness_problem_categories"]
        self.assertEqual(categories["problems"]["categories"], CATEGORY)
        self.assertEqual(categories["problems"]["unrecognized"], 0)
        self.assertNotIn("finalization", categories)
        self.assertNotIn("initial_observation", result)

    def test_absent_historical_and_partial_profile_withhold_category(self):
        for profile in (None, diagnostic.CURRENT_REPLAY_PROGRESS_PROFILE, {"id": "nebular071"}):
            with self.subTest(profile_present=profile is not None):
                with tempfile.TemporaryDirectory() as directory:
                    with patch.object(diagnostic, "_current_replay_progress_profile", return_value=profile):
                        result = self.attempt(Path(directory), failed_record())
                self.assertEqual(result["harness_problem_categories"]["problems"]["categories"], [])
                self.assertEqual(result["harness_problem_categories"]["problems"]["unrecognized"], 1)

    def test_generation_label_alone_cannot_authenticate_source(self):
        with tempfile.TemporaryDirectory() as directory:
            result = self.attempt(Path(directory), failed_record())
        self.assertEqual(result["harness_problem_categories"]["problems"]["unrecognized"], 1)

    def test_optional_authentication_failure_preserves_other_diagnostics_and_gate(self):
        with tempfile.TemporaryDirectory() as directory:
            with patch.object(diagnostic, "_current_replay_progress_profile", side_effect=RuntimeError):
                result = self.attempt(Path(directory), failed_record())
        self.assertTrue(result["failed"])
        self.assertIn("stderr_diagnostic", result)
        self.assertIn("evidence_inventory", result)
        self.assertEqual(result["harness_problem_categories"]["problems"]["unrecognized"], 1)

    def test_passing_attempt_does_not_authenticate_optional_problem_source(self):
        record = {"status": "pass", "problems": [], "executable": {"sha256": "a" * 64}}
        with tempfile.TemporaryDirectory() as directory:
            with patch.object(diagnostic, "_current_replay_progress_profile", side_effect=AssertionError) as profile:
                result = self.attempt(Path(directory), record)
        self.assertFalse(result["failed"])
        profile.assert_not_called()

    def test_exact_token_and_strict_boolean_preserve_withholding_and_field_inventory(self):
        identity = {"present": True, "bytes": 100, "sha256": "c" * 64}
        for flag, problem, expected in ((True, CLEANUP, CATEGORY), (False, CLEANUP, []),
                                        (1, CLEANUP, []), (True, CLEANUP + " private-suffix", []),
                                        (True, "private-prefix " + CLEANUP, [])):
            with self.subTest(enabled=flag is True, exact=problem == CLEANUP):
                projected = project_problem_categories(failed_record(problem), identity,
                    system="aarch64-linux", platform="linux-arm64", scenario="B",
                    current071_problems=flag)
                self.assertEqual(projected["problems"]["categories"], expected)
                self.assertEqual(set(projected), {"schema", "stage", "system", "scenario", "receipt", "problems"})
                self.assertNotIn("private-suffix", json.dumps(projected))
                self.assertNotIn("private-prefix", json.dumps(projected))


if __name__ == "__main__":
    unittest.main()
