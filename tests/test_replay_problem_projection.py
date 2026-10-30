"""Controlled receipt/child fixtures; no application or native runtime execution."""
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from rs9 import application_smoke_diagnostic as smoke
from rs9.errors import ContractError
from rs9.release_core import digest
from rs9.scratch import canonical
from rs9.smoke_stream_tokens import PROBLEM_CATEGORIES


class ReplayProblemProjectionTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.scratch = self.root / "scratch"; self.scratch.mkdir()
        self.tools = self.root / "tools"; self.tools.mkdir()
        (self.tools / "native-rc-smoke.mjs").write_text("synthetic fixture; never executed")
        self.source = self.root / "source"; self.source.mkdir()
        self.launch = self.root / "runtime"; self.launch.mkdir()
        self.prepared = dict(scratch=self.scratch, tools=self.tools, source=self.source, records=[])
        store = "/nix/store/" + "a" * 32 + "-dbus-1.16.2"
        self.bus = [store + "/bin/dbus-run-session", "--dbus-daemon=" + store + "/bin/dbus-daemon",
                    "--config-file=" + store + "/share/dbus-1/session.conf", "--"]
        self.secret = "INJECTED_PRIVATE_NONCE_947129"
        self.problems = ["no receipt was written", "harness error: " + self.secret,
                         "persistent user state changed: /private/" + self.secret,
                         "unknown problem /private/" + self.secret, {"pid": 938271, "secret": self.secret}]
        self.calls = []
        self.replay_status = "fail"
        self.receipt_raw = None

    def original(self, argv, **kwargs):
        self.calls.append(("original", list(argv), kwargs))
        raise subprocess.TimeoutExpired(argv, kwargs["timeout"], output=self.secret.encode(), stderr=self.secret.encode())

    def replay(self, argv, **kwargs):
        self.calls.append(("replay", list(argv), kwargs))
        evidence = Path(argv[argv.index("--evidence") + 1])
        platform = argv[argv.index("--platform") + 1]
        scenario = argv[argv.index("--scenario") + 1]
        record = {"status": self.replay_status, "executable": {"sha256": "a" * 64},
                  "problems": self.problems if self.replay_status == "fail" else []}
        self.receipt_raw = canonical(record)
        (evidence / (platform + "-" + scenario + ".run.json")).write_bytes(self.receipt_raw)
        return SimpleNamespace(returncode=1 if self.replay_status == "fail" else 0,
                               stdout=self.secret.encode(), stderr=self.secret.encode())

    def execute(self, system):
        with patch.object(smoke.subprocess, "run", side_effect=self.original), patch.object(
                smoke, "_bounded_run", side_effect=self.replay), patch.object(smoke.time, "monotonic", return_value=0):
            with self.assertRaises(ContractError) as caught:
                smoke.execute_application_smoke(prepared=self.prepared, system=system, launch_root=self.launch,
                    prefix=["controlled-fhs-prefix"], env={"PRIVATE_FIXTURE": self.secret},
                    diagnostic_replay=True, session_bus_argv=self.bus)
        self.assertEqual(caught.exception.code, "APPLICATION_SMOKE")
        self.assertEqual(caught.exception.details["cause"], "process-timeout")
        raw = (self.root / "diagnostics/application-smoke-diagnostic.json").read_bytes()
        self.assertNotIn(self.secret.encode(), raw)
        self.assertNotIn(str(self.root).encode(), raw)
        self.assertNotIn(b"938271", raw)
        return json.loads(raw)

    def test_replay_inner_categories_available_but_original_timeout_stays_failed(self):
        for system, platform, scenario, not_run in (("aarch64-linux", "linux-arm64", "B", []),
                ("x86_64-linux", "linux-x64", "C", ["C-signal"])):
            with self.subTest(system=system):
                if self.calls:
                    shutil.rmtree(self.scratch / "evidence-replay-B")
                    self.calls.clear()
                doc = self.execute(system)
                self.assertEqual(doc["gate_status"], "fail")
                self.assertFalse(doc["replay_equivalent_to_original"])
                self.assertEqual(doc["scenarios_not_run"], not_run)
                self.assertEqual(doc["initial_run"]["cause"], "process-timeout")
                self.assertEqual(doc["replay"]["status"], "replay-reproduced")
                self.assertNotIn("harness_problem_categories", doc["initial_run"])
                projection = doc["replay"]["harness_problem_categories"]
                self.assertEqual(set(projection), {"origin", "receipt", "problems"})
                self.assertEqual(projection["origin"], "diagnostic-replay")
                self.assertEqual(projection["receipt"], {"bytes": len(self.receipt_raw), "sha256": digest(self.receipt_raw)})
                counts = projection["problems"]
                self.assertEqual(counts["total"], 5)
                self.assertEqual(counts["unrecognized"], 1)
                self.assertEqual(counts["non_string"], 1)
                self.assertEqual({row["category"] for row in counts["categories"]},
                                 {"receipt-not-written", "harness-error", "persistent-user-state-changed"})
                self.assertTrue(all(row["category"] in set(PROBLEM_CATEGORIES.values()) for row in counts["categories"]))
                self.assertEqual([c[0] for c in self.calls], ["original", "replay"])
                for kind, argv, kwargs in self.calls:
                    self.assertEqual(kwargs["timeout"], 240)
                    self.assertEqual(argv[0], "controlled-fhs-prefix")
                    self.assertEqual(argv[argv.index(self.bus[0]):argv.index(self.bus[0])+4], self.bus)
                    self.assertEqual(argv[argv.index("--scenario") + 1], scenario)
                    self.assertEqual(argv[argv.index("--platform") + 1], platform)
                self.assertNotIn("--timeout-ms", self.calls[0][1])
                self.assertEqual(self.calls[1][1][self.calls[1][1].index("--timeout-ms") + 1], "180000")

    def test_passing_replay_never_promotes_or_supplants_original(self):
        self.replay_status = "pass"
        doc = self.execute("x86_64-linux")
        self.assertEqual(doc["status"], "fail")
        self.assertEqual(doc["gate_status"], "fail")
        self.assertFalse(doc["replay_equivalent_to_original"])
        self.assertEqual(doc["replay"]["status"], "replay-passed")
        self.assertNotIn("harness_problem_categories", doc["replay"])
        self.assertEqual(doc["initial_run"]["receipt_error"], "receipt-missing")

    def test_legacy_missing_and_mixed_system_context_emit_no_projection(self):
        for context in ({}, {"system": "aarch64-linux"}, {"system": "unknown-private-context"}):
            with self.subTest(context=context):
                with patch.object(smoke, "_bounded_run", side_effect=self.replay):
                    label, result = smoke.run_replay(scenario="C", platform="linux-x64", launch_root=self.launch,
                        checkout=self.source, tools=self.tools, prefix=[], env={}, scratch=self.scratch, **context)
                self.assertEqual(label, "replay-reproduced")
                self.assertNotIn("harness_problem_categories", result)
                shutil.rmtree(self.scratch / "evidence-replay-C")

    def test_optional_projection_fault_does_not_mask_original_failure(self):
        with patch("rs9.smoke_stream_tokens.project_problem_categories", side_effect=ValueError(self.secret)):
            doc = self.execute("x86_64-linux")
        self.assertEqual(doc["replay"]["status"], "replay-reproduced")
        self.assertNotIn("harness_problem_categories", doc["replay"])

    def test_optional_projection_is_dropped_before_existing_diagnostic_bound(self):
        doc = self.execute("x86_64-linux")
        doc["replay"].pop("harness_problem_categories")
        legacy_size = len(canonical(doc))
        shutil.rmtree(self.scratch / "evidence-replay-C")
        with patch.object(smoke, "MAX_DIAGNOSTIC", legacy_size):
            bounded = self.execute("x86_64-linux")
        self.assertNotIn("harness_problem_categories", bounded["replay"])
        self.assertEqual(bounded["gate_status"], "fail")
