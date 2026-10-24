"""Original-attempt behavior and host system binding across shared smoke consumers."""
from contextlib import ExitStack
import json
from pathlib import Path
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from rs9.application_smoke_diagnostic import execute_application_smoke
from rs9.errors import ContractError
from rs9.pages_smoke_diagnostic import validate_smoke_observation, retain_host_smoke_diagnostic
from rs9.release_core import digest
from rs9.smoke_stream_tokens import stream_tokens


class OriginalAttemptTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name).resolve()
        self.prepared = {"scratch": self.root, "tools": self.root / "tools", "source": self.root / "source"}

    def test_single_nonzero_cannot_qualify_with_fabricated_receipt(self):
        for system, platform, scenario in (("x86_64-linux", "linux-x64", "C"),
                                           ("aarch64-linux", "linux-arm64", "B")):
            with self.subTest(system=system):
                def fail(argv, **kwargs):
                    evidence = Path(argv[argv.index("--evidence") + 1])
                    (evidence / (platform + "-" + scenario + ".run.json")).write_text(json.dumps({
                        "status": "pass", "executable": {"sha256": "a" * 64}}))
                    return SimpleNamespace(returncode=1, stdout=b"", stderr=b"x" * 96 + b"\n")
                with patch("rs9.application_smoke_diagnostic.subprocess.run", side_effect=fail) as run, \
                        patch("rs9.application_smoke_diagnostic.run_replay") as replay:
                    with self.assertRaises(ContractError) as caught:
                        execute_application_smoke(prepared=self.prepared, system=system, launch_root=self.root)
                run.assert_called_once()
                replay.assert_not_called()
                obs = caught.exception.smoke_observation
                self.assertEqual(caught.exception.code, "APPLICATION_SMOKE")
                self.assertEqual(obs["raw_returncode"], 1)
                self.assertEqual(obs["cause"], "process-nonzero")
                self.assertEqual(obs["scenario"], scenario)
                self.assertEqual(obs["stderr_bytes"], 97)
                self.assertEqual(obs["log_categories"], ["unclassified"])

    def test_shared_smoke_passing_control_per_system_has_no_added_observation(self):
        for system, platform in (("x86_64-linux", "linux-x64"),
                ("aarch64-linux", "linux-arm64"), ("aarch64-darwin", "darwin-arm64")):
            with self.subTest(system=system):
                def passed(argv, **kwargs):
                    scenario = argv[argv.index("--scenario") + 1]
                    evidence = Path(argv[argv.index("--evidence") + 1])
                    (evidence / (platform + "-" + scenario + ".run.json")).write_text(json.dumps({
                        "status": "pass", "executable": {"sha256": "a" * 64}}))
                    return SimpleNamespace(returncode=0, stdout=b"", stderr=b"")
                with patch("rs9.application_smoke_diagnostic.subprocess.run", side_effect=passed), \
                        patch("rs9.smoke_stream_tokens.collect_failure_diagnostics") as diagnostic, \
                        patch("rs9.application_smoke_diagnostic.run_replay") as replay:
                    runs = execute_application_smoke(prepared=self.prepared,
                        system=system, launch_root=self.root)
                diagnostic.assert_not_called()
                replay.assert_not_called()
                self.assertTrue(runs)
                self.assertTrue(all(set(r) == {"scenario", "receipt_sha256", "executable_sha256"} for r in runs))

    def test_diagnostic_fault_does_not_mask_original_failure(self):
        with patch("rs9.application_smoke_diagnostic.subprocess.run", return_value=SimpleNamespace(
                returncode=1, stdout=b"", stderr=b"error\n")), \
                patch("rs9.smoke_stream_tokens.collect_failure_diagnostics", side_effect=RuntimeError("private")):
            with self.assertRaises(ContractError) as caught:
                execute_application_smoke(prepared=self.prepared, system="x86_64-linux", launch_root=self.root)
        self.assertEqual(caught.exception.code, "APPLICATION_SMOKE")
        self.assertEqual(caught.exception.smoke_observation["raw_returncode"], 1)

    def test_optional_diagnostic_cannot_overwrite_fixed_outcome(self):
        with patch("rs9.application_smoke_diagnostic.subprocess.run", return_value=SimpleNamespace(
                returncode=1, stdout=b"", stderr=b"error\n")), \
                patch("rs9.smoke_stream_tokens.collect_failure_diagnostics", return_value={
                    "failed": False, "cause": "unknown", "reason_token": "pass", "raw_returncode": 0}):
            with self.assertRaises(ContractError) as caught:
                execute_application_smoke(prepared=self.prepared, system="x86_64-linux", launch_root=self.root)
        self.assertEqual(caught.exception.smoke_observation["cause"], "process-nonzero")
        self.assertEqual(caught.exception.smoke_observation["reason_token"], "process-nonzero")
        self.assertEqual(caught.exception.smoke_observation["raw_returncode"], 1)

    def test_timeout_withholds_partial_stream_and_never_retries(self):
        with patch("rs9.application_smoke_diagnostic.subprocess.run", side_effect=subprocess.TimeoutExpired(
                ["node"], 240, output=b"", stderr=b"TypeError: partial\n")) as run:
            with self.assertRaises(ContractError) as caught:
                execute_application_smoke(prepared=self.prepared, system="aarch64-linux", launch_root=self.root)
        run.assert_called_once()
        self.assertEqual(caught.exception.smoke_observation["stderr_diagnostic"]["withheld_reason"], "incomplete")


class BindingTests(unittest.TestCase):
    def observation(self):
        raw = b"TypeError: ordinary\n"
        return {"scenario": "B", "raw_returncode": 1, "cause": "process-nonzero",
                "stderr_bytes": len(raw), "stderr_sha256": digest(raw), "stdout_bytes": 0,
                "stdout_sha256": digest(b""), "stream_capture_complete": True,
                "stderr_diagnostic": stream_tokens(raw, complete=True)}

    def test_host_system_binding_and_idempotent_reprojection(self):
        raw = {**self.observation(), "system": "x86_64-linux"}
        good = validate_smoke_observation(raw, system="aarch64-linux")
        self.assertEqual(good["scenario"], "B")
        self.assertEqual(validate_smoke_observation(good, system="aarch64-linux"), good)
        swapped = validate_smoke_observation(raw, system="x86_64-linux")
        self.assertEqual(swapped["scenario"], "unknown")
        self.assertTrue(swapped["binding_mismatch"])
        self.assertEqual(swapped["stderr_diagnostic"]["tokens"], [])
        self.assertEqual(validate_smoke_observation(swapped, system="x86_64-linux"), swapped)
        self.assertEqual(validate_smoke_observation(good, system="unexpected")["scenario"], "unknown")

    def test_missing_fields_and_untrusted_response_do_not_inject_tokens(self):
        raw = self.observation()
        raw["stderr_diagnostic"]["tokens"] = ["private-response-text"]
        for doc in (raw, {k: v for k, v in self.observation().items() if k != "stderr_sha256"}):
            projected = validate_smoke_observation(doc, system="aarch64-linux")
            self.assertEqual(projected["stderr_diagnostic"]["tokens"], [])
            self.assertNotIn("private-response-text", json.dumps(projected))

    def test_first_failure_exclusive_mode_and_scenario_binding(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            sha = retain_host_smoke_diagnostic(root, self.observation(), family="apt", system="aarch64-linux")
            path = root / "application-smoke-failure-apt.json"
            before = path.read_bytes()
            self.assertEqual(digest(before), sha)
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            self.assertIsNone(retain_host_smoke_diagnostic(root, {**self.observation(), "raw_returncode": 255},
                family="apt", system="aarch64-linux"))
            self.assertEqual(path.read_bytes(), before)

    def test_exact_original_observations_retain_distinct_hashes(self):
        source = Path(__file__).resolve().parents[1] / "evidence/live1/cont22-input-evidence.json"
        records = json.loads(source.read_bytes())["apt_original_failures"]
        expected = {"x86_64-linux": ("C", "74321a45144b837ebc71a285eb26f4d88ee2499ae4bb83134ed35c18904ad490"),
                    "aarch64-linux": ("B", "a7562a866e0f427712cba33f84a687eb489680f903cc09bb220513602df37aab")}
        for record in records:
            obs = validate_smoke_observation(record["initial_run"], system=record["system"])
            self.assertEqual(obs, record["initial_run"])
            self.assertEqual((obs["scenario"], obs["stderr_sha256"]), expected[record["system"]])
            self.assertEqual(obs["stderr_bytes"], 97)
            self.assertEqual(obs["raw_returncode"], 1)
            self.assertEqual(obs["receipt_error"], "receipt-missing")
            self.assertFalse(record["diagnostic_replay"])


class HostBoundaryTests(unittest.TestCase):
    def test_bound_host_rejects_guest_scenario_and_response_tokens(self):
        from tests.test_hosted_container_smoke import DisjointFilesystemTests
        from rs9.build_native import CommandReceipt
        from rs9.hosted_container_smoke import SCHEMA, _accept_container_output
        fixture = DisjointFilesystemTests()
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        binding = fixture.binding
        obs = BindingTests().observation()
        obs["system"] = "aarch64-linux"
        obs["stderr_diagnostic"]["tokens"] = ["private-response-text"]
        doc = {"schema": SCHEMA, "request_sha256": binding["request_sha256"],
               "family": binding["family"], "system": binding["system"], "uid": 65534,
               "status": "fail", "code": "APPLICATION_SMOKE", "smoke_observation": obs}
        (binding["output"] / "result.json").write_text(json.dumps(doc))
        with self.assertRaises(ContractError) as caught:
            _accept_container_output(binding, CommandReceipt(["guest"], 1, b"", b"", executed=True))
        self.assertEqual(caught.exception.code, "APPLICATION_SMOKE")
        projected = caught.exception.smoke_observation
        self.assertTrue(projected["binding_mismatch"])
        self.assertEqual(projected["scenario"], "unknown")
        self.assertEqual(projected["stderr_diagnostic"]["tokens"], [])
        self.assertNotIn("private-response-text", json.dumps(projected))


class LinuxProblemCategoryFlowTests(unittest.TestCase):
    PRIV = "/" + "home/" + "private-runner/work"
    RUN_BYTES = json.dumps({"status": "fail", "executable": {"sha256": "a" * 64}, "problems": [
        "receipt status fail: " + PRIV,
        "required step project-open failed: " + PRIV + " SENTINEL_PROBLEM",
        "application ended by exit 1 instead of SIGTERM",
        "unrecognized SENTINEL_UNKNOWN " + PRIV,
        7,
    ]}).encode()
    PASS_BYTES = json.dumps({"status": "pass", "problems": [], "executable": {"sha256": "a" * 64}}).encode()
    MISSING = object()
    SENTINELS = ("private-runner", "SENTINEL_PROBLEM", "SENTINEL_UNKNOWN", "project-open", "SIGTERM")
    CASES = (("x86_64-linux", "linux-x64", "C", {"C": 1}),
             ("x86_64-linux", "linux-x64", "C-signal", {"C": 0, "C-signal": 1}),
             ("aarch64-linux", "linux-arm64", "B", {"B": 1}))

    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name).resolve()
        scratch = self.root / "scratch"
        scratch.mkdir()
        self.prepared = {"scratch": scratch, "tools": self.root / "tools", "source": self.root / "source"}

    def envelope(self, system, scenario):
        from rs9.smoke_stream_tokens import CATEGORY_SCHEMA, CATEGORY_STAGE
        return {"schema": CATEGORY_SCHEMA, "stage": CATEGORY_STAGE, "system": system, "scenario": scenario,
                "receipt": {"bytes": len(self.RUN_BYTES), "sha256": digest(self.RUN_BYTES)},
                "problems": {"total": 5, "scanned": 5, "categories": [
                    {"category": "receipt-status", "count": 1}, {"category": "required-step", "count": 1},
                    {"category": "signal-termination-mismatch", "count": 1}],
                    "unrecognized": 1, "non_string": 1, "omitted": 0, "unavailable": 0}}

    def runner(self, platform, codes, payload=None, inner=None):
        def run(argv, **kwargs):
            scenario = argv[argv.index("--scenario") + 1]
            ev = Path(argv[argv.index("--evidence") + 1])
            path = ev / (platform + "-" + scenario + ".run.json")
            data = self.PASS_BYTES if not codes[scenario] else self.RUN_BYTES if payload is None else payload
            if data is self.MISSING:
                path.unlink(missing_ok=True)
            else:
                path.write_bytes(data)
            inner_path = ev / (platform + "-" + scenario + ".stderr.log")
            if codes[scenario] and inner is not None:
                inner_path.write_bytes(inner)
            else:
                inner_path.unlink(missing_ok=True)
            return SimpleNamespace(returncode=codes[scenario], stdout=b"", stderr=b"x" * 96 + b"\n")
        return run

    def failure(self, system, platform, codes, *patches, payload=None, inner=None, **kwargs):
        with ExitStack() as stack:
            stack.enter_context(patch("rs9.application_smoke_diagnostic.subprocess.run",
                                      side_effect=self.runner(platform, codes, payload, inner=inner)))
            replay = stack.enter_context(patch("rs9.application_smoke_diagnostic.run_replay",
                                               return_value=("replay-reproduced", {"status": "replay-reproduced"})))
            for extra in patches:
                stack.enter_context(extra)
            with self.assertRaises(ContractError) as caught:
                execute_application_smoke(prepared=self.prepared, system=system, launch_root=self.root, **kwargs)
        return caught.exception, replay

    @staticmethod
    def without(doc, *keys):
        return {k: v for k, v in doc.items() if k not in {"elapsed_ms", *keys}}

    def test_linux_categories_flow_from_original_read_through_reprojection_and_retention(self):
        from rs9.smoke_stream_tokens import INNER_STAGE
        missing_inner = {
            "stage": INNER_STAGE, "bytes": None, "sha256": None, "complete": False,
            "read_error": "missing", "line_count": None, "utf8_valid": None,
            "tokens": [], "tokens_omitted": 0, "withheld_reason": "missing",
        }
        for system, platform, scenario, codes in self.CASES:
            with self.subTest(system=system, scenario=scenario):
                error, replay = self.failure(system, platform, codes)
                replay.assert_not_called()
                obs = error.smoke_observation
                self.assertEqual(error.code, "APPLICATION_SMOKE")
                self.assertEqual(obs["harness_problem_categories"], self.envelope(system, scenario))
                self.assertEqual(obs["receipt"], {"bytes": len(self.RUN_BYTES), "sha256": digest(self.RUN_BYTES)})
                self.assertEqual((obs["scenario"], obs["cause"], obs["reason_token"], obs["raw_returncode"],
                                  obs["receipt_error"]), (scenario, "process-nonzero", "process-nonzero", 1, "receipt-failed"))
                self.assertNotIn("harness_run_record", obs)
                self.assertEqual(obs["inner_stderr_diagnostic"], missing_inner)
                run_row = [a for a in obs["evidence_inventory"]["artifacts"] if a["kind"] == "run.json"]
                self.assertEqual(run_row, [{"kind": "run.json", "bytes": len(self.RUN_BYTES),
                                            "regular": True, "symlink": False}])
                p2 = validate_smoke_observation(obs, system=system)
                p3 = validate_smoke_observation(p2, system=system)
                self.assertEqual(p2, obs)
                self.assertEqual(p3, p2)
                with tempfile.TemporaryDirectory() as tmp:
                    directory = Path(tmp).resolve()
                    sha = retain_host_smoke_diagnostic(directory, obs, family="apt", system=system)
                    retained = (directory / "application-smoke-failure-apt.json").read_bytes()
                self.assertEqual(digest(retained), sha)
                initial = json.loads(retained)["initial_run"]
                self.assertEqual(initial["harness_problem_categories"], obs["harness_problem_categories"])
                self.assertEqual(initial["inner_stderr_diagnostic"], missing_inner)
                self.assertEqual(initial["receipt"], obs["receipt"])
                for sentinel in self.SENTINELS:
                    self.assertNotIn(sentinel, json.dumps(obs))
                    self.assertNotIn(sentinel.encode(), retained)

    def test_classification_never_changes_original_outcome_or_masks_failure(self):
        from rs9.smoke_stream_tokens import CATEGORY_SCHEMA, CATEGORY_STAGE
        system, platform, scenario, codes = self.CASES[0]
        baseline, _ = self.failure(system, platform, codes)
        added = ("harness_problem_categories", "receipt")
        withheld = {"schema": CATEGORY_SCHEMA, "stage": CATEGORY_STAGE, "withheld_reason": "invalid-observation"}
        producer_fault, _ = self.failure(system, platform, codes, patch(
            "rs9.smoke_stream_tokens.project_problem_categories", side_effect=RuntimeError("private boom")))
        consumer_fault, _ = self.failure(system, platform, codes, patch(
            "rs9.smoke_stream_tokens.validate_problem_categories", side_effect=RuntimeError("private boom")))
        for name, error in (("producer", producer_fault), ("consumer", consumer_fault)):
            with self.subTest(fault=name):
                self.assertEqual(error.code, baseline.code)
                self.assertEqual(self.without(error.details), self.without(baseline.details))
                self.assertEqual(self.without(error.smoke_observation, *added),
                                 self.without(baseline.smoke_observation, *added))
                self.assertNotIn("receipt", error.smoke_observation)
                self.assertNotIn("private boom", json.dumps(error.smoke_observation))
        self.assertNotIn("harness_problem_categories", producer_fault.smoke_observation)
        self.assertEqual(consumer_fault.smoke_observation["harness_problem_categories"], withheld)
        obs = baseline.smoke_observation
        forged = self.envelope(system, scenario)
        forged["receipt"]["sha256"] = "f" * 64
        raw_text = self.envelope(system, scenario)
        raw_text["problems"]["categories"][0]["category"] = "receipt status fail: " + self.PRIV
        bool_count = self.envelope(system, scenario)
        bool_count["problems"]["categories"][0]["count"] = True
        other_system = self.envelope("aarch64-linux", "B")
        hostile_cases = (("string", "receipt status fail", "invalid-observation"),
                         ("list", [], "invalid-observation"),
                         ("schema-only", {"schema": CATEGORY_SCHEMA}, "invalid-observation"),
                         ("private-withheld", {**withheld, "withheld_reason": self.PRIV}, "invalid-observation"),
                         ("raw-text-category", raw_text, "invalid-observation"),
                         ("bool-count", bool_count, "invalid-observation"),
                         ("forged-sha", forged, "binding-mismatch"),
                         ("other-system", other_system, "binding-mismatch"))
        for name, hostile, reason in hostile_cases:
            with self.subTest(hostile=name):
                projected = validate_smoke_observation({**obs, "harness_problem_categories": hostile}, system=system)
                self.assertEqual(projected["harness_problem_categories"]["withheld_reason"], reason)
                self.assertNotIn("receipt", projected)
                self.assertEqual(self.without(projected, *added), self.without(obs, *added))
                for key in ("cause", "reason_token", "raw_returncode", "receipt_error", "problem_codes", "scenario"):
                    self.assertEqual(projected[key], obs[key])
                self.assertNotIn(self.PRIV, json.dumps(projected))

    def test_absent_optional_field_and_unreadable_receipt_add_no_keys(self):
        for system, platform, scenario, codes in self.CASES:
            for name, payload in (("receipt-missing", self.MISSING), ("receipt-corrupt", b"{" + self.PRIV.encode())):
                with self.subTest(system=system, scenario=scenario, receipt=name):
                    error, _ = self.failure(system, platform, codes, payload=payload)
                    obs = error.smoke_observation
                    self.assertEqual(error.code, "APPLICATION_SMOKE")
                    self.assertEqual((obs["scenario"], obs["receipt_error"], obs["cause"], obs["raw_returncode"]),
                                     (scenario, name, "process-nonzero", 1))
                    self.assertNotIn("harness_problem_categories", obs)
                    self.assertNotIn("receipt", obs)
                    self.assertNotIn("private-runner", json.dumps(obs))
        plain = BindingTests().observation()
        self.assertNotIn("harness_problem_categories", validate_smoke_observation(plain, system="aarch64-linux"))
        # A top-level identity without the optional field is never carried forward.
        forged = validate_smoke_observation({**plain, "receipt": {"bytes": 1, "sha256": "a" * 64}}, system="aarch64-linux")
        self.assertNotIn("receipt", forged)
        self.assertNotIn("harness_problem_categories", forged)

    def test_wrong_system_withholds_and_non_linux_consumers_ignore_field(self):
        system, platform, _scenario, codes = self.CASES[0]
        error, _ = self.failure(system, platform, codes)
        obs = error.smoke_observation
        swapped = validate_smoke_observation(obs, system="aarch64-linux")
        self.assertTrue(swapped["binding_mismatch"])
        self.assertEqual(swapped["scenario"], "unknown")
        self.assertEqual(swapped["harness_problem_categories"]["withheld_reason"], "binding-mismatch")
        self.assertEqual(set(swapped["harness_problem_categories"]), {"schema", "stage", "withheld_reason"})
        self.assertNotIn("receipt", swapped)
        self.assertEqual(validate_smoke_observation(swapped, system="aarch64-linux"), swapped)
        for other in ("aarch64-darwin", None):
            with self.subTest(system=other):
                projected = validate_smoke_observation(obs, system=other)
                self.assertNotIn("harness_problem_categories", projected)
                self.assertNotIn("receipt", projected)

    def test_diagnostic_extras_initial_run_keeps_bounded_field_without_masking(self):
        system, platform, scenario, codes = self.CASES[0]
        error, replay = self.failure(system, platform, codes, diagnostic_extras=True)
        replay.assert_called_once()
        self.assertEqual(error.code, "APPLICATION_SMOKE")
        self.assertEqual(error.details["cause"], "process-nonzero")
        raw = (self.root / "diagnostics" / "application-smoke-diagnostic.json").read_bytes()
        self.assertEqual(error.details["diagnostic_sha256"], digest(raw))
        self.assertLessEqual(len(raw), 60 * 1024)
        initial = json.loads(raw)["initial_run"]
        self.assertEqual(initial["harness_problem_categories"], self.envelope(system, scenario))
        self.assertEqual(error.smoke_observation["harness_problem_categories"], self.envelope(system, scenario))
        for sentinel in self.SENTINELS:
            self.assertNotIn(sentinel.encode(), raw)

    def test_missing_or_uncorroborated_inventory_never_retains_positive_categories(self):
        from rs9.smoke_stream_tokens import (
            CATEGORY_SCHEMA,
            CATEGORY_STAGE,
            INVENTORY_STAGE,
            MAX_ENTRIES,
        )
        system, platform, _scenario, codes = self.CASES[0]
        original, _ = self.failure(system, platform, codes)
        obs = original.smoke_observation
        withheld = {"schema": CATEGORY_SCHEMA, "stage": CATEGORY_STAGE, "withheld_reason": "binding-mismatch"}
        unavailable = {"stage": INVENTORY_STAGE, "status": "unavailable", "artifacts": [],
                       "entries_observed": 0, "unlisted": 0}
        outside_window = {**unavailable, "status": "limit-exceeded", "entries_observed": MAX_ENTRIES,
                          "unlisted": MAX_ENTRIES}
        for name, inventory in (("absent", None), ("unavailable", unavailable), ("outside-window", outside_window)):
            with self.subTest(inventory=name):
                raw = dict(obs)
                if inventory is None:
                    raw.pop("evidence_inventory", None)
                else:
                    raw["evidence_inventory"] = inventory
                projected = validate_smoke_observation(raw, system=system)
                self.assertEqual(projected["harness_problem_categories"], withheld)
                self.assertNotIn("receipt", projected)
                for key in ("cause", "reason_token", "raw_returncode", "receipt_error", "problem_codes", "scenario"):
                    self.assertEqual(projected[key], obs[key])
                self.assertEqual(validate_smoke_observation(projected, system=system), projected)

    def test_optional_category_growth_cannot_mask_original_at_diagnostic_cap(self):
        from rs9.application_smoke_diagnostic import _retain_failure
        from rs9.scratch import canonical
        system, platform, scenario, codes = self.CASES[0]
        original, _ = self.failure(system, platform, codes, diagnostic_extras=True)
        path = self.root / "diagnostics" / "application-smoke-diagnostic.json"
        full = json.loads(path.read_bytes())
        initial = full["initial_run"]
        reduced = {**full, "initial_run": {k: v for k, v in initial.items() if k != "harness_problem_categories"}}
        limit = len(canonical(reduced))
        self.assertGreater(len(canonical(full)), limit)
        with patch("rs9.application_smoke_diagnostic.run_replay", return_value=("replay-reproduced", full["replay"])) as replay, \
                patch("rs9.application_smoke_diagnostic.MAX_DIAGNOSTIC", limit):
            sha = _retain_failure(self.prepared, system, platform, scenario, self.root, (), None,
                                  initial, full["scenarios_not_run"])
        replay.assert_called_once()
        retained = path.read_bytes()
        self.assertEqual(retained, canonical(reduced))
        self.assertEqual(digest(retained), sha)
        self.assertLessEqual(len(retained), limit)
        self.assertIn("harness_problem_categories", initial)
        self.assertIn("harness_problem_categories", original.smoke_observation)
        self.assertEqual(original.code, "APPLICATION_SMOKE")
        self.assertEqual(original.details["cause"], "process-nonzero")
        with patch("rs9.application_smoke_diagnostic.run_replay", return_value=("replay-reproduced", full["replay"])), \
                patch("rs9.application_smoke_diagnostic.MAX_DIAGNOSTIC", limit - 1), \
                self.assertRaisesRegex(ContractError, "Smoke diagnostic bound exceeded"):
            _retain_failure(self.prepared, system, platform, scenario, self.root, (), None,
                            initial, full["scenarios_not_run"])

    def test_host_boundary_retains_matching_field_and_withholds_swapped_scenario(self):
        from rs9.build_native import CommandReceipt
        from rs9.hosted_container_smoke import SCHEMA, _accept_container_output
        from tests.test_hosted_container_smoke import DisjointFilesystemTests
        fixture = DisjointFilesystemTests()
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        binding = fixture.binding
        system = binding["system"]
        case = next(c for c in self.CASES if c[0] == system)
        _, platform, scenario, codes = case
        guest = self.failure(system, platform, codes)[0].smoke_observation
        swapped_scenario = next(c[2] for c in self.CASES if c[0] == system and c[2] != scenario)
        for name, obs, positive in (("matching", guest, True),
                                    ("swapped", {**guest, "scenario": swapped_scenario}, False),
                                    ("other-system-scenario", {**guest, "scenario": "B"}, False)):
            with self.subTest(case=name):
                doc = {"schema": SCHEMA, "request_sha256": binding["request_sha256"],
                       "family": binding["family"], "system": system, "uid": 65534,
                       "status": "fail", "code": "APPLICATION_SMOKE", "smoke_observation": obs}
                (binding["output"] / "result.json").write_text(json.dumps(doc))
                with self.assertRaises(ContractError) as caught:
                    _accept_container_output(binding, CommandReceipt(["guest"], 1, b"", b"", executed=True))
                self.assertEqual(caught.exception.code, "APPLICATION_SMOKE")
                projected = caught.exception.smoke_observation
                self.assertEqual(projected["cause"], guest["cause"])
                self.assertEqual(projected["raw_returncode"], guest["raw_returncode"])
                if positive:
                    self.assertEqual(projected["harness_problem_categories"], guest["harness_problem_categories"])
                    self.assertEqual(projected["receipt"], guest["receipt"])
                else:
                    self.assertEqual(projected["harness_problem_categories"]["withheld_reason"], "binding-mismatch")
                    self.assertNotIn("receipt", projected)

    def test_linux_inner_stderr_flows_without_changing_original_outcome(self):
        from rs9.smoke_stream_tokens import INNER_STAGE
        inner_bytes = b"TypeError: inner failure\nEACCES: permission denied, open '/tmp/work'\n"
        expected_inner = {
            "stage": INNER_STAGE,
            "bytes": len(inner_bytes),
            "sha256": digest(inner_bytes),
            "complete": True,
            "read_error": None,
            "line_count": 2,
            "utf8_valid": True,
            "tokens": ["node-errno-eacces", "node-syscall-open", "node-type-error"],
            "tokens_omitted": 0,
            "withheld_reason": None,
        }
        ev = self.prepared["scratch"] / "evidence"
        for system, platform, scenario, codes in self.CASES:
            with self.subTest(system=system, scenario=scenario):
                if ev.exists():
                    for child in ev.iterdir():
                        child.unlink()
                baseline_err, _ = self.failure(system, platform, codes)
                baseline_obs = baseline_err.smoke_observation
                if ev.exists():
                    for child in ev.iterdir():
                        child.unlink()
                error, replay = self.failure(system, platform, codes, inner=inner_bytes)
                replay.assert_not_called()
                obs = error.smoke_observation
                self.assertEqual(error.code, "APPLICATION_SMOKE")
                self.assertEqual(self.without(error.details), self.without(baseline_err.details))
                self.assertEqual(obs["inner_stderr_diagnostic"], expected_inner)
                self.assertEqual(obs["harness_problem_categories"], self.envelope(system, scenario))
                self.assertEqual(obs["receipt"], {"bytes": len(self.RUN_BYTES), "sha256": digest(self.RUN_BYTES)})
                self.assertEqual((obs["scenario"], obs["cause"], obs["reason_token"], obs["raw_returncode"],
                                  obs["receipt_error"]), (scenario, "process-nonzero", "process-nonzero", 1, "receipt-failed"))
                self.assertEqual(
                    self.without(obs, "inner_stderr_diagnostic", "evidence_inventory"),
                    self.without(baseline_obs, "inner_stderr_diagnostic", "evidence_inventory"),
                )
                inv = obs["evidence_inventory"]
                base_inv = baseline_obs["evidence_inventory"]
                self.assertEqual(inv["status"], "observed")
                self.assertEqual(inv["entries_observed"], base_inv["entries_observed"] + 1)
                self.assertEqual(inv["unlisted"], base_inv["unlisted"])
                self.assertEqual(
                    [a for a in inv["artifacts"] if a["kind"] != "stderr.log"],
                    base_inv["artifacts"],
                )
                self.assertEqual(
                    [a for a in inv["artifacts"] if a["kind"] == "stderr.log"],
                    [{"kind": "stderr.log", "bytes": len(inner_bytes), "regular": True, "symlink": False}],
                )
                p1 = validate_smoke_observation(obs, system=system)
                p2 = validate_smoke_observation(p1, system=system)
                p3 = validate_smoke_observation(p2, system=system)
                self.assertEqual(p1, obs)
                self.assertEqual(p2, p1)
                self.assertEqual(p3, p2)
                with tempfile.TemporaryDirectory() as tmp:
                    directory = Path(tmp).resolve()
                    sha = retain_host_smoke_diagnostic(directory, obs, family="apt", system=system)
                    retained = (directory / "application-smoke-failure-apt.json").read_bytes()
                self.assertEqual(digest(retained), sha)
                initial = json.loads(retained)["initial_run"]
                self.assertEqual(initial["inner_stderr_diagnostic"], expected_inner)
                for sentinel in (*self.SENTINELS, "/tmp/work", "inner failure"):
                    self.assertNotIn(sentinel, json.dumps(obs))
                    self.assertNotIn(sentinel.encode(), retained)

    def test_linux_inner_stderr_hostile_projection_and_inventory_mismatch(self):
        from rs9.smoke_stream_tokens import (
            INNER_STAGE,
            INVENTORY_STAGE,
            MAX_ENTRIES,
        )
        system, platform, _scenario, codes = self.CASES[0]
        inner_bytes = b"TypeError: inner failure\n"
        error, _ = self.failure(system, platform, codes, inner=inner_bytes)
        obs = error.smoke_observation
        good_inner = obs["inner_stderr_diagnostic"]
        good_inv = obs["evidence_inventory"]
        self.assertEqual(good_inner["tokens"], ["node-type-error"])

        def expected_withheld(reason):
            return {
                "stage": INNER_STAGE, "bytes": None, "sha256": None, "complete": False,
                "read_error": None, "line_count": None, "utf8_valid": None,
                "tokens": [], "tokens_omitted": 0, "withheld_reason": reason,
            }

        hostile_inner_cases = (
            ("extra-eof-key", {**good_inner, "eof": True}, "invalid-observation"),
            ("private-token", {**good_inner, "tokens": [self.PRIV]}, "invalid-observation"),
            ("non-bool-complete", {**good_inner, "complete": 1}, "invalid-observation"),
            ("complete-incomplete", {**good_inner, "tokens": [], "withheld_reason": "incomplete"},
             "invalid-observation"),
            ("forged-bytes", {**good_inner, "bytes": len(inner_bytes) + 1}, "binding-mismatch"),
        )
        for name, hostile_inner, reason in hostile_inner_cases:
            with self.subTest(hostile_inner=name):
                projected = validate_smoke_observation({**obs, "inner_stderr_diagnostic": hostile_inner},
                                                       system=system)
                self.assertEqual(projected["inner_stderr_diagnostic"], expected_withheld(reason))
                self.assertEqual(validate_smoke_observation(projected, system=system), projected)
                self.assertEqual(
                    self.without(projected, "inner_stderr_diagnostic"),
                    self.without(obs, "inner_stderr_diagnostic"),
                )
                self.assertNotIn(self.PRIV, json.dumps(projected))

        run_row = next(a for a in good_inv["artifacts"] if a["kind"] == "run.json")
        err_row = next(a for a in good_inv["artifacts"] if a["kind"] == "stderr.log")
        unavailable_inv = {"stage": INVENTORY_STAGE, "status": "unavailable", "artifacts": [],
                           "entries_observed": 0, "unlisted": 0}
        limit_inv = {"stage": INVENTORY_STAGE, "status": "limit-exceeded",
                     "artifacts": [run_row, err_row], "entries_observed": MAX_ENTRIES,
                     "unlisted": MAX_ENTRIES - 2}
        no_err_inv = {"stage": INVENTORY_STAGE, "status": "observed", "artifacts": [run_row],
                      "entries_observed": 2, "unlisted": 1}
        nonreg_inv = {**good_inv, "artifacts": [run_row, {**err_row, "regular": False}]}
        symlink_inv = {**good_inv, "artifacts": [run_row, {**err_row, "regular": False, "symlink": True}]}
        bad_bytes_inv = {**good_inv, "artifacts": [run_row, {**err_row, "bytes": len(inner_bytes) + 1}]}
        dup_inv = {**good_inv, "artifacts": [run_row, err_row, err_row], "entries_observed": 3}
        bad_unlisted_inv = {**good_inv, "unlisted": 5}
        inventory_cases = (
            ("absent", None),
            ("unavailable", unavailable_inv),
            ("limit-exceeded", limit_inv),
            ("missing-stderr-row", no_err_inv),
            ("nonregular", nonreg_inv),
            ("symlink", symlink_inv),
            ("byte-mismatch", bad_bytes_inv),
            ("duplicate-rows", dup_inv),
            ("bad-unlisted-count", bad_unlisted_inv),
        )
        for name, bad_inv in inventory_cases:
            with self.subTest(inventory=name):
                raw_doc = dict(obs)
                if bad_inv is None:
                    raw_doc.pop("evidence_inventory", None)
                else:
                    raw_doc["evidence_inventory"] = bad_inv
                projected = validate_smoke_observation(raw_doc, system=system)
                self.assertEqual(projected["inner_stderr_diagnostic"], expected_withheld("binding-mismatch"))
                self.assertEqual(validate_smoke_observation(projected, system=system), projected)
                for key in ("cause", "reason_token", "raw_returncode", "receipt_error", "problem_codes", "scenario"):
                    self.assertEqual(projected[key], obs[key])

        for wrong_sys in ("aarch64-linux", "aarch64-darwin"):
            with self.subTest(wrong_system=wrong_sys):
                swapped = validate_smoke_observation(obs, system=wrong_sys)
                self.assertTrue(swapped["binding_mismatch"])
                self.assertEqual(swapped["scenario"], "unknown")
                self.assertEqual(swapped["inner_stderr_diagnostic"], expected_withheld("binding-mismatch"))
                self.assertEqual(validate_smoke_observation(swapped, system=wrong_sys), swapped)

        for dropped_sys in ("riscv64-linux", None):
            with self.subTest(dropped_system=dropped_sys):
                dropped = validate_smoke_observation(obs, system=dropped_sys)
                self.assertNotIn("inner_stderr_diagnostic", dropped)

        with patch("rs9.smoke_stream_tokens.validate_inner_stream_tokens",
                   side_effect=RuntimeError("private inner boom")):
            faulted = validate_smoke_observation(obs, system=system)
        self.assertEqual(faulted["inner_stderr_diagnostic"], expected_withheld("invalid-observation"))
        self.assertEqual(
            self.without(faulted, "inner_stderr_diagnostic"),
            self.without(obs, "inner_stderr_diagnostic"),
        )
        self.assertNotIn("private inner boom", json.dumps(faulted))

        priv_err, _ = self.failure(system, platform, codes,
                                   inner=f"TypeError: {self.PRIV}\n".encode())
        priv_obs = priv_err.smoke_observation
        self.assertEqual(priv_obs["inner_stderr_diagnostic"]["withheld_reason"], "private")
        self.assertEqual(priv_obs["inner_stderr_diagnostic"]["tokens"], [])
        self.assertNotIn(self.PRIV, json.dumps(priv_obs))
        self.assertNotIn("private-runner", json.dumps(priv_obs))
