"""Original-attempt behavior and host system binding across shared smoke consumers."""
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
