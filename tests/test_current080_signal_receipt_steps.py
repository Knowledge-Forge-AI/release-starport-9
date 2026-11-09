"""Closed signal-step observations after a failed original, without observer execution."""
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from rs9 import application_smoke_diagnostic as diagnostic
from rs9 import smoke_stream_tokens as tokens
from rs9.pages_smoke_diagnostic import validate_smoke_observation

SENTINEL = "PRIVATE_SENTINEL_NOT_FOR_RETENTION"


def failed_record():
    return {"status": "fail", "problems": ["the signal scenario never reached its signal point"],
            "executable": {"sha256": "a" * 64},
            "receipt": {"steps": [
                {"id": "app-shell", "ok": True, "detail": SENTINEL},
                {"id": "host-start", "ok": False, "error": SENTINEL},
                {"id": SENTINEL, "ok": False},
            ]}}


class SignalReceiptStepTests(unittest.TestCase):
    def attempt(self, root, record, *, platform="linux-x64", scenario="C-signal", system="x86_64-linux", extras=False):
        (root / f"{platform}-{scenario}.run.json").write_text(json.dumps(record))
        prepared = {"tools": root, "source": root, "scratch": root,
                    "source_generation": "theme-forge-current-202610"}
        completed = subprocess.CompletedProcess([], 1 if record["status"] == "fail" else 0, b"", b"")
        with patch.object(diagnostic.subprocess, "run", return_value=completed) as run:
            result = diagnostic._attempt(prepared, platform, scenario, root, root,
                                         [], {}, extras, system=system)
        self.assertEqual(run.call_count, 1)
        self.assertEqual(run.call_args.kwargs["timeout"], 240)
        self.assertNotIn("--rs9-initial-observation-kind", run.call_args.args[0])
        return result

    def test_authenticated_original_signal_failure_retains_only_closed_step_states(self):
        with tempfile.TemporaryDirectory() as directory:
            with patch.object(diagnostic, "_current_replay_progress_profile",
                              return_value=diagnostic.CURRENT080_REPLAY_PROGRESS_PROFILE):
                result = self.attempt(Path(directory), failed_record())
        self.assertTrue(result["failed"])
        self.assertEqual(result["receipt_error"], "receipt-failed")
        categories = result["harness_problem_categories"]
        self.assertIn("receipt_steps", categories)
        observed = categories["receipt_steps"]
        self.assertEqual(observed["steps"], [
            {"id": name, "state": "pass" if name == "app-shell" else "fail" if name == "host-start" else "missing"}
            for name in tokens.SCENARIO_C_STEPS])
        self.assertEqual(observed["entries_observed"], 3)
        self.assertEqual(observed["entries_unlisted"], 1)
        self.assertEqual(observed["entries_omitted"], 0)
        self.assertNotIn(SENTINEL, json.dumps(categories))
        self.assertNotIn("finalization", categories)
        self.assertNotIn("cleanup_observation", result)
        self.assertNotIn("initial_observation", result)
        self.assertEqual(tokens._closed_categories(categories), categories)
        retained = validate_smoke_observation(result, system="x86_64-linux")
        self.assertEqual(retained["harness_problem_categories"], categories)

    def test_other_source_profiles_and_generation_label_alone_withhold_steps(self):
        for profile in (None, diagnostic.CURRENT_REPLAY_PROGRESS_PROFILE,
                        diagnostic.CURRENT071_REPLAY_PROGRESS_PROFILE, {"id": "nebular080"}):
            with self.subTest(profile_id=profile.get("id") if isinstance(profile, dict) else None):
                with tempfile.TemporaryDirectory() as directory:
                    with patch.object(diagnostic, "_current_replay_progress_profile", return_value=profile):
                        result = self.attempt(Path(directory), failed_record())
                self.assertTrue(result["failed"])
                self.assertNotIn("receipt_steps", result["harness_problem_categories"])
        with tempfile.TemporaryDirectory() as directory:
            result = self.attempt(Path(directory), failed_record())
        self.assertNotIn("receipt_steps", result["harness_problem_categories"])

    def test_other_system_platform_scenario_and_passing_outcomes_do_not_enable(self):
        for system, platform, scenario in (("aarch64-linux", "linux-arm64", "B"),
                ("x86_64-linux", "linux-x64", "C"), (None, "linux-x64", "C-signal"),
                ("aarch64-darwin", "darwin-arm64", "A")):
            with self.subTest(system=system, platform=platform, scenario=scenario):
                with patch.object(diagnostic, "_current_replay_progress_profile", side_effect=AssertionError) as source:
                    self.assertFalse(diagnostic._current080_signal_receipt_steps({}, platform, scenario, system=system))
                source.assert_not_called()
        record = {"status": "pass", "problems": [], "executable": {"sha256": "a" * 64}}
        with tempfile.TemporaryDirectory() as directory:
            with patch.object(diagnostic, "_current_replay_progress_profile", side_effect=AssertionError) as source:
                result = self.attempt(Path(directory), record)
        self.assertFalse(result["failed"])
        source.assert_not_called()

    def test_optional_source_error_preserves_failed_outcome_and_existing_observations(self):
        with tempfile.TemporaryDirectory() as directory:
            with patch.object(diagnostic, "_current_replay_progress_profile", side_effect=RuntimeError(SENTINEL)):
                result = self.attempt(Path(directory), failed_record())
        self.assertTrue(result["failed"])
        self.assertIn("stderr_diagnostic", result)
        self.assertIn("evidence_inventory", result)
        self.assertNotIn("receipt_steps", result["harness_problem_categories"])
        self.assertNotIn(SENTINEL, json.dumps(result))

    def test_strict_boolean_and_original_binding_preserve_default_projection(self):
        record = failed_record()
        identity = {"present": True, "bytes": 100, "sha256": "b" * 64}
        binding = {"system": "x86_64-linux", "platform": "linux-x64", "scenario": "C-signal"}
        baseline = tokens.project_problem_categories(record, identity, **binding)
        for flag in (False, 1, "true", None):
            self.assertEqual(tokens.project_problem_categories(record, identity, **binding,
                             current080_receipt_steps=flag), baseline)
        for changed in ({"system": "aarch64-linux", "platform": "linux-arm64", "scenario": "B"},
                        {"scenario": "C"}):
            actual = {**binding, **changed}
            self.assertEqual(tokens.project_problem_categories(record, identity, **actual,
                             current080_receipt_steps=True),
                             tokens.project_problem_categories(record, identity, **actual))

    def test_existing_bounds_and_duplicate_states_survive_new_projection_route(self):
        record = failed_record()
        record["receipt"]["steps"] = [{"id": "app-shell", "ok": True}] * (tokens.MAX_STEP_ENTRIES + 1)
        projected = tokens.project_problem_categories(record,
            {"present": True, "bytes": 100, "sha256": "b" * 64},
            system="x86_64-linux", platform="linux-x64", scenario="C-signal", current080_receipt_steps=True)
        steps = projected["receipt_steps"]
        self.assertEqual(steps["entries_observed"], tokens.MAX_STEP_ENTRIES)
        self.assertEqual(steps["entries_omitted"], 1)
        self.assertEqual(steps["steps"][0]["state"], "duplicate")
        self.assertTrue(all(row["state"] == "unknown" for row in steps["steps"][1:]))
        self.assertEqual(tokens._closed_categories(projected), projected)


if __name__ == "__main__":
    unittest.main()
