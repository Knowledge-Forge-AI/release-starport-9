import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from rs9.application_smoke_diagnostic import (
    MAX_DIAGNOSTIC,
    _retain_failure,
    project_replay_receipt_stage,
    run_replay,
)


STEPS = (
    "app-shell", "host-start", "host-start-idempotent", "host-stop",
    "host-start-again", "host-status", "project-open-case", "derive-plan-cancel",
    "derive-plan-apply", "host-status-final",
)


def _run_record(*, status="fail", problems=None, private=False):
    problems = list(problems or [])
    if private:
        problems.append("persistent user state changed: /private/never-retain/sentinel")
    return {
        "schema": "nebular.native-rc-smoke-run-v1",
        "label": "linux-x64-C",
        "platform": "linux-x64",
        "scenario": "C",
        "status": status,
        "source": "raw-archive",
        "executable": {"sha256": "a" * 64, "size": 100},
        "receipt": {
            "sha256": "b" * 64,
            "status": status,
            "steps": [{"id": step, "ok": step != "derive-plan-apply"} for step in STEPS],
        },
        "problems": problems,
        "finalization": {
            "schema": "nebular.native-rc-finalization-v1",
            "status": "complete",
            "phase": "complete",
            "exceptionFamily": None,
            "spawned": True,
            "exitObserved": True,
            "applicationReceiptObservation": "present-at-read",
            "applicationReceiptCopy": "written",
        },
    }


def _receipt(*, status="fail", private=False):
    value = {
        "schema": "nebular.release-smoke-receipt-v1",
        "applicationVersion": "0.7.0",
        "scenario": "C",
        "status": status,
        "failure": None if status == "pass" else "withheld",
        "target": "x86_64-unknown-linux-gnu",
        "awaitingSignal": False,
        "executable": {"sha256": "a" * 64},
        "driver": {
            "status": status, "scenario": "C", "facts": [],
            "steps": [{"id": step, "ok": step != "derive-plan-cancel"} for step in STEPS],
        },
    }
    if private:
        value["privateDetail"] = "/Users/never-retain/sentinel"
    return value


class ReplayReceiptProjectionTests(unittest.TestCase):
    def test_valid_failure_projects_steps_and_closed_derived_category_only(self):
        with tempfile.TemporaryDirectory() as directory:
            evidence = Path(directory)
            run = _run_record(problems=["the derived asset was not written to the case-exact project"], private=True)
            receipt = _receipt(private=True)
            (evidence / "linux-x64-C.run.json").write_text(json.dumps(run), encoding="utf-8")
            (evidence / "linux-x64-C.receipt.json").write_text(json.dumps(receipt), encoding="utf-8")

            projection = project_replay_receipt_stage(evidence, "linux-x64", "C")

        self.assertEqual(projection["status"], "observed")
        self.assertFalse(projection["qualification_authority"])
        self.assertFalse(projection["application_qualified"])
        self.assertTrue(projection["receipt"]["valid"])
        self.assertEqual(projection["receipt"]["status"], "fail")
        self.assertEqual(projection["receipt"]["steps"][7], {"id": "derive-plan-cancel", "state": "fail"})
        self.assertEqual(projection["run_record"]["derived_output"], {
            "status": "missing", "type": None, "sha256": None,
        })
        self.assertNotIn("never-retain", json.dumps(projection))
        self.assertNotIn("privateDetail", json.dumps(projection))

    def test_missing_and_malformed_inputs_are_partial_without_raw_data(self):
        with tempfile.TemporaryDirectory() as directory:
            evidence = Path(directory)
            (evidence / "linux-arm64-B.run.json").write_bytes(b"not-json")
            projection = project_replay_receipt_stage(evidence, "linux-arm64", "B")
            self.assertEqual(projection["status"], "partial")
            self.assertFalse(projection["run_record"]["valid"])
            self.assertEqual(projection["run_record"]["read_error"], "malformed")
            self.assertFalse(projection["receipt"]["present"])
            self.assertEqual(projection["receipt"]["read_error"], "missing")
            self.assertNotIn("not-json", json.dumps(projection))

    def test_symlink_is_not_followed_and_unknown_scenario_has_no_authority(self):
        with tempfile.TemporaryDirectory() as directory:
            evidence = Path(directory)
            target = evidence / "private.json"
            target.write_text(json.dumps(_run_record()), encoding="utf-8")
            (evidence / "linux-x64-C.run.json").symlink_to(target)
            projection = project_replay_receipt_stage(evidence, "linux-x64", "C")
            self.assertFalse(projection["run_record"]["valid"])
            self.assertEqual(projection["run_record"]["read_error"], "invalid")
            unknown = project_replay_receipt_stage(evidence, "linux-x64", "A")
            self.assertEqual(unknown["status"], "unavailable")
            self.assertFalse(unknown["qualification_authority"])

    def test_replay_consumer_receives_projection_without_changing_gate(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            evidence = root / "evidence-replay-C"

            def bounded(_argv, **_kwargs):
                evidence.mkdir(parents=True, exist_ok=True)
                (evidence / "linux-x64-C.run.json").write_text(
                    json.dumps(_run_record(problems=["the derived asset was not written to the case-exact project"])),
                    encoding="utf-8",
                )
                (evidence / "linux-x64-C.receipt.json").write_text(json.dumps(_receipt()), encoding="utf-8")
                (evidence / "xvfb-error.log").write_bytes(b"")
                return SimpleNamespace(
                    returncode=1, stdout=b"", stderr=b"", stream_sizes=(0, 0),
                    capture_error=None, cleanup_error=None, child_reaped=True,
                )

            with patch("rs9.application_smoke_diagnostic._bounded_run", side_effect=bounded):
                label, replay = run_replay(
                    scenario="C", platform="linux-x64", launch_root=root / "launch",
                    checkout=root / "checkout", tools=root / "tools", prefix=(), env={},
                    scratch=root, system="x86_64-linux",
                )

        self.assertEqual(label, "replay-reproduced")
        projection = replay["replay_receipt_projection"]
        self.assertEqual(projection["status"], "observed")
        self.assertFalse(projection["qualification_authority"])
        self.assertEqual(projection["run_record"]["derived_output"]["status"], "missing")

    def test_malformed_nested_shapes_are_closed_without_type_errors(self):
        with tempfile.TemporaryDirectory() as directory:
            evidence = Path(directory)
            run = _run_record()
            run["status"] = []
            run["receipt"]["status"] = {}
            run["receipt"]["steps"] = {"unexpected": True}
            run["finalization"]["status"] = False
            run["finalization"]["phase"] = []
            run["finalization"]["applicationReceiptObservation"] = {"unexpected": True}
            receipt = _receipt()
            receipt["status"] = []
            receipt["driver"]["status"] = {}
            receipt["driver"]["steps"] = False
            receipt["executable"] = {"sha256": []}
            (evidence / "linux-x64-C.run.json").write_text(json.dumps(run), encoding="utf-8")
            (evidence / "linux-x64-C.receipt.json").write_text(json.dumps(receipt), encoding="utf-8")

            projection = project_replay_receipt_stage(evidence, "linux-x64", "C")

        self.assertEqual(projection["status"], "observed")
        self.assertEqual(projection["run_record"]["status"], "unknown")
        self.assertEqual(projection["run_record"]["receipt_status"], "unknown")
        self.assertEqual(projection["run_record"]["finalization"]["status"], "unknown")
        self.assertEqual(projection["receipt"]["status"], "unknown")
        self.assertEqual(projection["receipt"]["driver_status"], "unknown")
        self.assertFalse(projection["receipt"]["valid"])

    def test_projection_fault_is_typed_optional_fallback(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            evidence = root / "evidence-replay-C"

            def bounded(_argv, **_kwargs):
                evidence.mkdir(parents=True, exist_ok=True)
                (evidence / "linux-x64-C.run.json").write_text(json.dumps(_run_record()), encoding="utf-8")
                (evidence / "linux-x64-C.receipt.json").write_text(json.dumps(_receipt()), encoding="utf-8")
                return SimpleNamespace(
                    returncode=1, stdout=b"", stderr=b"", stream_sizes=(0, 0),
                    capture_error=None, cleanup_error=None, child_reaped=True,
                )

            with patch("rs9.application_smoke_diagnostic._bounded_run", side_effect=bounded), \
                    patch("rs9.application_smoke_diagnostic.project_replay_receipt_stage",
                          side_effect=RuntimeError("injected")):
                label, replay = run_replay(
                    scenario="C", platform="linux-x64", launch_root=root / "launch",
                    checkout=root / "checkout", tools=root / "tools", prefix=(), env={},
                    scratch=root, system="x86_64-linux",
                )

        self.assertEqual(label, "replay-reproduced")
        self.assertEqual(replay["replay_receipt_projection"], {
            "schema": "rs9.application-smoke-replay-receipt-stage.v1",
            "status": "unavailable", "reason": "projection-failed",
            "qualification_authority": False, "application_qualified": False,
        })

    def test_malformed_projection_stays_inside_optional_replay_retention(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            evidence = root / "evidence-replay-C"

            def bounded(_argv, **_kwargs):
                evidence.mkdir(parents=True, exist_ok=True)
                run = _run_record()
                run["status"] = []
                run["receipt"]["status"] = {}
                run["finalization"]["phase"] = False
                (evidence / "linux-x64-C.run.json").write_text(json.dumps(run), encoding="utf-8")
                receipt = _receipt()
                receipt["driver"]["status"] = []
                (evidence / "linux-x64-C.receipt.json").write_text(json.dumps(receipt), encoding="utf-8")
                return SimpleNamespace(
                    returncode=1, stdout=b"", stderr=b"", stream_sizes=(0, 0),
                    capture_error=None, cleanup_error=None, child_reaped=True,
                )

            with patch("rs9.application_smoke_diagnostic._bounded_run", side_effect=bounded):
                label, replay = run_replay(
                    scenario="C", platform="linux-x64", launch_root=root / "launch",
                    checkout=root / "checkout", tools=root / "tools", prefix=(), env={},
                    scratch=root, system="x86_64-linux",
                )

        self.assertEqual(label, "replay-reproduced")
        self.assertEqual(replay["replay_receipt_projection"]["status"], "observed")
        self.assertEqual(replay["replay_receipt_projection"]["run_record"]["status"], "unknown")
        self.assertEqual(replay["replay_receipt_projection"]["receipt"]["driver_status"], "unknown")

    def test_near_bound_output_replaces_projection_with_omission_marker(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            prepared = {"scratch": root / "scratch", "tools": root / "tools", "source": root / "source"}
            fields = {
                "scenario": "C", "cause": "process-timeout", "problem_codes": [],
                "diagnostic_filler": "x" * 54_000,
            }
            replay = {
                "status": "replay-reproduced",
                "replay_receipt_projection": {"payload": "y" * 8_000},
            }
            with patch("rs9.application_smoke_diagnostic.run_replay", return_value=("replay-reproduced", replay)):
                _retain_failure(prepared, "x86_64-linux", "linux-x64", "C", root / "launch", (), {}, fields, [])
            output = root / "diagnostics" / "application-smoke-diagnostic.json"
            raw = output.read_bytes()
            record = json.loads(raw)

        self.assertLessEqual(len(raw), MAX_DIAGNOSTIC)
        self.assertGreater(len(raw), 55_000)
        self.assertEqual(record["replay"]["replay_receipt_projection"], {
            "schema": "rs9.application-smoke-replay-receipt-stage.v1",
            "status": "unavailable", "reason": "diagnostic-size-cap",
            "qualification_authority": False, "application_qualified": False,
        })
        self.assertNotIn("payload", json.dumps(record))


    def test_invalid_directory_input_always_closes_opened_descriptor(self):
        import os
        from rs9.application_smoke_diagnostic import _read_stable_json
        opened = []
        actual_open = os.open
        def remember(*args, **kwargs):
            fd = actual_open(*args, **kwargs)
            opened.append(fd)
            return fd
        with tempfile.TemporaryDirectory() as directory:
            with patch("rs9.application_smoke_diagnostic.os.open", side_effect=remember):
                value, meta, reason = _read_stable_json(Path(directory), 4096)
            self.assertIsNone(value)
            self.assertEqual(reason, "invalid")
            self.assertEqual(len(opened), 1)
            with self.assertRaises(OSError):
                os.fstat(opened[0])

    def test_original_record_with_less_than_marker_room_remains_retained(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            prepared = {"scratch": root / "scratch", "tools": root / "tools", "source": root / "source"}
            fields = {"scenario": "C", "cause": "process-timeout", "problem_codes": [], "diagnostic_filler": ""}
            baseline_replay = {"status": "replay-reproduced", "harness_problem_categories": {
                "origin": "diagnostic-replay", "receipt": {"status": "fail"},
                "problems": {"derived-asset-not-written": 1},
            }}
            with patch("rs9.application_smoke_diagnostic.run_replay", return_value=("replay-reproduced", baseline_replay)):
                _retain_failure(prepared, "x86_64-linux", "linux-x64", "C", root / "launch", (), {}, fields, [])
            output = root / "diagnostics" / "application-smoke-diagnostic.json"
            base_size = len(output.read_bytes())
            fields["diagnostic_filler"] = "x" * (MAX_DIAGNOSTIC - base_size - 100)
            with patch("rs9.application_smoke_diagnostic.run_replay", return_value=("replay-reproduced", baseline_replay)):
                _retain_failure(prepared, "x86_64-linux", "linux-x64", "C", root / "launch", (), {}, fields, [])
            expected = output.read_bytes()
            self.assertEqual(len(expected), MAX_DIAGNOSTIC - 100)
            replay = {**baseline_replay, "replay_receipt_projection": {"payload": "y" * 8_000}}
            with patch("rs9.application_smoke_diagnostic.run_replay", return_value=("replay-reproduced", replay)):
                _retain_failure(prepared, "x86_64-linux", "linux-x64", "C", root / "launch", (), {}, fields, [])
            self.assertEqual(output.read_bytes(), expected)
            self.assertNotIn("replay_receipt_projection", json.loads(output.read_bytes())["replay"])


if __name__ == "__main__":
    unittest.main()
