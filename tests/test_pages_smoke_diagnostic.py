"""Tests for Pages Nebular application smoke diagnostic retention and controls.

Verifies:
- Closed, bounded, privacy-safe smoke failure observation validation host-side.
- Withhold unknown/secret values; no raw process output excerpts.
- Exit code vs signal distinction: 143 and 255 are exits, negative rc is outer signal only.
- Separate --network none --rm image probe; unavailable never changes gate.
- Deterministic smoke context and asset identities.
- Actual last inventory stage recorded as counters_source.
- Writer failure cannot mask original smoke failure.
- Failing Pages Nebular all-other-clients-pass control: incumbent gates, one attempt.
- All-pass control.
"""
from __future__ import annotations

import hashlib
import json
import os
import signal
import subprocess
import sys
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import MagicMock, patch

from rs9.build_native import CommandReceipt
from rs9.errors import ContractError
from rs9 import hosted_deb as hd
from rs9.pages_smoke_diagnostic import (
    determine_counters_source,
    extract_smoke_context,
    probe_apt_runtime_image,
    retain_host_smoke_diagnostic,
    validate_smoke_observation,
    RUNTIME_PACKAGES, parse_runtime_packages,
)
from rs9.release_core import digest
from rs9.scratch import canonical


class ConnectedPagesControls(unittest.TestCase):
    """Actual Pages family orchestration and client cycles over scripted tool receipts."""

    def exercise(self, fail):
        from tests.test_hosted_deb import PagesLaneTests, FixtureSigner, ScriptedDocker, ExecutedMock, host_runner
        fixture = PagesLaneTests()
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        context = fixture.context()

        bindings, attempts = {}, []

        class PagesDocker(ScriptedDocker):
            def _exec(self, argv):
                if any("from rs9.hosted_container_smoke import guest_main" in arg for arg in argv):
                    family = bindings["current"]
                    binding = bindings[family]
                    attempts.append(family)
                    failed = fail and family == "apt"
                    doc = {"schema": "rs9.container-nebular-smoke.v1", "uid": 65534,
                           "request_sha256": binding["request_sha256"], "family": family,
                           "system": binding["system"], "status": "fail" if failed else "pass"}
                    if failed:
                        doc.update(code="APPLICATION_SMOKE", details={
                            "exit_code": 143, "stdout_sha256": "c" * 64, "stderr_sha256": "d" * 64,
                            "cause": "process-nonzero", "scenario": "C", "elapsed_ms": 25})
                        doc["smoke_observation"] = {**doc["details"], "raw_returncode": 143,
                            "stdout_bytes": 0, "stderr_bytes": 4, "stream_capture_complete": True}
                    else:
                        doc["result"] = {"sidecar": {"verified": True},
                            "source_bindings_sha256": digest(canonical([])),
                            "scenarios": [{"scenario": s, "receipt_sha256": "e" * 64,
                                           "executable_sha256": "f" * 64} for s in ("C", "C-signal")]}
                    (binding["output"] / "result.json").write_bytes(canonical(doc))
                    return self.receipt(argv, 1 if failed else 0)
                result = super()._exec(argv)
                if "rpm" in argv and "-q" in argv and result.exit_code == 1:
                    return self.receipt(argv, 1, ("package " + argv[-1] + " is not installed\n").encode())
                return result

        host = hd.RecordingRunner(host_runner(PagesDocker(), ExecutedMock))
        tree = fixture.root / "assembled"
        for name in ("keys", "apt", "rpm", "pacman"):
            (tree / name).mkdir(parents=True, exist_ok=True)
        package = fixture.root / "control.deb"
        package.write_bytes(b"synthetic package boundary")
        bundles = {("deb", "amd64"): {"packages": {"control": package}}}
        def bind(prepared, system, family):
            prepared["scratch"].mkdir(parents=True, exist_ok=True)
            output = fixture.scratch / ("smoke-output-" + family)
            output.mkdir()
            bindings[family] = {"prepared": prepared, "family": family, "system": system,
                "mounts": [], "output": output, "request_sha256": "a" * 64,
                "request": {"manifest_sha256": "b" * 64, "records": []}}
            bindings["current"] = family
            return bindings[family]

        gates, details = [], {}
        with patch("rs9.hosted_deb.prepare_environment", return_value={"image_ref": "fixture"}), \
                patch("rs9.hosted_deb.provision_image"), \
                patch("rs9.hosted_deb.provision_native", return_value={"image_ref": "fixture", "preprovisioned_packages": []}), \
                patch("rs9.hosted_deb._dependency_names", return_value=[]), \
                patch("rs9.hosted_deb.execute_probes", return_value=[]), \
                patch("rs9.hosted_deb.tamper_cycle", return_value=[]), \
                patch("rs9.hosted_smoke.prepare_smoke", side_effect=lambda neb, captures, client, scratch:
                      {"fixture": True, "scratch": scratch}), \
                patch("rs9.hosted_container_smoke.prepare_container_smoke", side_effect=bind), \
                patch("rs9.dnf_diagnostics.probe_dnf_client", return_value={"status": "pass"}):
            hd._pages_client_tests(context, host, fixture.repository, fixture.scratch, context["pins"],
                                   tree, bundles, FixtureSigner("A" * 40), gates, details, [], [], "fixture-rpm")
        self.assertEqual(attempts, ["apt", "dnf", "pacman"])
        self.assertEqual(set(details["client"]), {"apt", "dnf", "pacman"})
        diagnostics = Path(bindings["apt"]["prepared"]["scratch"]).parent / "diagnostics"
        if fail:
            path = diagnostics / "application-smoke-failure-apt.json"
            retained = json.loads(path.read_bytes())
            self.assertEqual(retained["initial_run"]["exit_code"], 143)
            self.assertIs(retained["diagnostic_replay"], False)
            product = details["client"]["apt"][hd.NATIVE_PRODUCT]
            self.assertEqual(product["smoke_failure"]["diagnostic_sha256"], digest(path.read_bytes()))
            self.assertEqual(sorted(p.name for p in diagnostics.glob("application-smoke-failure-*.json")),
                             [path.name])
        else:
            self.assertFalse(list(diagnostics.glob("application-smoke-failure-*.json")))
        return gates, details

    def test_nebular_fails_once_while_every_other_client_succeeds(self):
        gates, details = self.exercise(True)
        self.assertEqual({g["name"] for g in gates if g["status"] == "fail"},
                         {"pages-client.apt.theme-forge-nebular-fusion.client", "pages-client.apt"})
        self.assertTrue(all(g["status"] == "pass" for g in gates if g["status"] != "fail"))
        product = details["client"]["apt"][hd.NATIVE_PRODUCT]
        self.assertEqual(product["counters_source"], "post-remove")
        self.assertEqual(product["smoke_failure"]["exit_code"], 143)
        self.assertEqual(product["smoke_failure"]["stderr_sha256"], "d" * 64)
        self.assertEqual(product["smoke_observation"]["exit_code"], 143)
        self.assertIsNone(product["smoke_observation"]["signal"])
        self.assertEqual(product["cleanup"]["status"], "pass")
        self.assertEqual(product["positive_control"]["success"], True)

    def test_passing_control_has_no_failure_fields(self):
        gates, details = self.exercise(False)
        self.assertTrue(all(g["status"] == "pass" for g in gates))
        for family in details["client"].values():
            for product in hd.REQUIRED_PRODUCTS:
                self.assertNotIn("smoke_failure", family[product])
                self.assertNotIn("smoke_observation", family[product])


class PagesSmokeDiagnosticUnitTests(unittest.TestCase):
    def test_real_process_exit_255_and_sigterm_remain_distinct(self):
        # Native Python controls prove outer return-code semantics only.
        # They provide no PRoot or inner application signal evidence.
        exit_result = subprocess.run([sys.executable, "-B", "-c", "raise SystemExit(255)"],
                                     capture_output=True, timeout=10)
        term_result = subprocess.run([sys.executable, "-B", "-c",
            "import os,signal;os.kill(os.getpid(),signal.SIGTERM)"], capture_output=True, timeout=10)
        exited = validate_smoke_observation({"raw_returncode": exit_result.returncode})
        terminated = validate_smoke_observation({"raw_returncode": term_result.returncode})
        self.assertEqual(exited["exit_code"], 255)
        self.assertIsNone(exited["signal"])
        self.assertIsNone(terminated["exit_code"])
        self.assertEqual(terminated["signal"], signal.SIGTERM)

    def test_malformed_and_absent_observations_never_invent_metadata(self):
        for raw in (None, [], {}, {"scenario": [], "cause": {}, "stream_capture_complete": "true"},
                    {"cause": "arbitrary-safe-slug", "raw_returncode": True, "signal": 15,
                     "stdout_sha256": "missing", "stdout_bytes": False}):
            with self.subTest(shape=type(raw).__name__):
                result = validate_smoke_observation(raw)
                self.assertEqual(result["cause"], "unknown")
                self.assertIsNone(result["raw_returncode"])
                self.assertIsNone(result["signal"])
                self.assertIsNone(result["stdout_sha256"])
                self.assertIsNone(result["stdout_bytes"])
                self.assertIs(result["stream_capture_complete"], False)
        timeout = validate_smoke_observation({"cause": "process-timeout", "stream_capture_complete": True,
            "stdout_sha256": "a" * 64, "stderr_sha256": "b" * 64, "stdout_bytes": 0, "stderr_bytes": 1})
        self.assertIs(timeout["stream_capture_complete"], False)

    def test_runtime_packages_reject_partial_malformed_and_hostile_output(self):
        raw = "".join(p + "\t1:2.3-4ubuntu1\n" for p in RUNTIME_PACKAGES).encode()
        self.assertEqual(set(parse_runtime_packages(raw, "linux/amd64")), set(RUNTIME_PACKAGES))
        for broken in (b"", raw[:-1] + b"\tbad", raw + raw, b"\xff", b"x" * (16 * 1024 + 1),
                       raw.replace(b"\t1:", b" 1:"), raw.replace(b"python3\t", b"unknown\t"),
                       raw.replace(b"1:2.3-4ubuntu1", ("ghp_" + "a" * 36).encode())):
            with self.subTest(bytes=len(broken)), self.assertRaises((ValueError, ContractError)):
                parse_runtime_packages(broken, "linux/amd64")

    def test_first_failure_file_is_exclusive_and_family_specific(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            observation = {"scenario": "C", "cause": "process-nonzero", "raw_returncode": 255}
            first = retain_host_smoke_diagnostic(root, observation, family="apt", system="x86_64-linux")
            path = root / "application-smoke-failure-apt.json"
            raw = path.read_bytes()
            self.assertEqual(first, digest(raw))
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            self.assertIsNone(retain_host_smoke_diagnostic(root, {"raw_returncode": 0}, family="apt", system="x86_64-linux"))
            self.assertEqual(path.read_bytes(), raw)
            self.assertIsNotNone(retain_host_smoke_diagnostic(root, observation, family="dnf", system="x86_64-linux"))
            other = root / "preserved"
            other.write_bytes(b"preserved")
            (root / "application-smoke-failure-pacman.json").symlink_to(other)
            self.assertIsNone(retain_host_smoke_diagnostic(root, observation, family="pacman", system="x86_64-linux"))
            self.assertEqual(other.read_bytes(), b"preserved")

    def test_image_probe_is_excluded_from_gate_execution_receipts(self):
        class Runner:
            def run(self, cmd, **kwargs):
                out = ("sha256:" + "a" * 64 + "\n").encode() if "inspect" in cmd else b"malformed"
                return CommandReceipt(cmd, 0, out, b"", executed=True)
        host = hd.RecordingRunner(Runner())
        marker = host.mark()
        result = probe_apt_runtime_image(host, "fixture")
        self.assertEqual(result["status"], "unavailable")
        self.assertEqual(host.records_since(marker), [])
        self.assertIs(host.real_since(marker), False)

    def test_image_probe_cleans_exact_named_container_after_timeout(self):
        class Runner:
            def __init__(self, cleanup_fails):
                self.calls = []
                self.cleanup_fails = cleanup_fails

            def run(self, cmd, **kwargs):
                self.calls.append(cmd)
                if "inspect" in cmd:
                    return CommandReceipt(cmd, 0, ("sha256:" + "a" * 64 + "\n").encode(), b"", executed=True)
                if cmd[1] == "run":
                    raise subprocess.TimeoutExpired(cmd, 30)
                return CommandReceipt(cmd, int(self.cleanup_fails), b"", b"", executed=True)

        for cleanup_fails in (False, True):
            with self.subTest(cleanup_fails=cleanup_fails):
                runner = Runner(cleanup_fails)
                host = hd.RecordingRunner(runner)
                marker = host.mark()
                result = probe_apt_runtime_image(host, "fixture")
                self.assertEqual(result["status"], "unavailable")
                self.assertEqual(result["cleanup"], "unconfirmed" if cleanup_fails else "complete")
                run = runner.calls[1]
                name = run[run.index("--name") + 1]
                self.assertTrue(name.startswith("rs9-apt-image-probe-"))
                self.assertEqual(runner.calls[2], ["docker", "rm", "-f", name])
                self.assertEqual(host.records_since(marker), [])

    def test_exit_code_signal_distinction(self):
        # 143 is an exit, not a signal
        obs_143 = validate_smoke_observation({
            "scenario": "C", "cause": "process-nonzero", "raw_returncode": 143,
            "stdout_sha256": "0" * 64, "stderr_sha256": "1" * 64,
        })
        self.assertEqual(obs_143["exit_code"], 143)
        self.assertIsNone(obs_143["signal"])
        self.assertEqual(obs_143["raw_returncode"], 143)
        self.assertEqual(obs_143["cause"], "process-nonzero")

        # 255 is an exit, not a signal
        obs_255 = validate_smoke_observation({
            "scenario": "C", "cause": "process-nonzero", "raw_returncode": 255,
            "stdout_sha256": "0" * 64, "stderr_sha256": "1" * 64,
        })
        self.assertEqual(obs_255["exit_code"], 255)
        self.assertIsNone(obs_255["signal"])
        self.assertEqual(obs_255["raw_returncode"], 255)
        self.assertEqual(obs_255["cause"], "process-nonzero")

        # Negative returncode is outer signal only
        obs_sig15 = validate_smoke_observation({
            "scenario": "C", "cause": "process-signal", "raw_returncode": -15,
            "stdout_sha256": "0" * 64, "stderr_sha256": "1" * 64,
        })
        self.assertIsNone(obs_sig15["exit_code"])
        self.assertEqual(obs_sig15["signal"], 15)
        self.assertEqual(obs_sig15["raw_returncode"], -15)
        self.assertEqual(obs_sig15["cause"], "process-signal")

        obs_sig9 = validate_smoke_observation({
            "scenario": "C", "cause": "process-signal", "raw_returncode": -9,
            "stdout_sha256": "0" * 64, "stderr_sha256": "1" * 64,
        })
        self.assertIsNone(obs_sig9["exit_code"])
        self.assertEqual(obs_sig9["signal"], 9)
        self.assertEqual(obs_sig9["raw_returncode"], -9)

    def test_hostile_observation_withholds_secrets_and_raw_excerpts(self):
        hostile = {
            "scenario": "MALICIOUS",
            "cause": "secret_token_ghp_" + "A" * 36,
            "raw_returncode": "not-an-int",
            "exit_code": 999999,
            "stdout_bytes": -50,
            "stderr_bytes": 1024,
            "stdout_sha256": "bad-sha",
            "stderr_sha256": "a" * 64,
            "log_categories": ["malicious-cat", "dbus-session-conf-missing", "ghp_1234"],
            "problem_codes": ["valid-code", "ghp_" + "B" * 36, "/private/operator/secret"],
            "raw_output": "should-never-be-retained",
            "stdout": "leaked-data",
            "stderr": "leaked-errors",
            "message": "secret-message",
            "elapsed_ms": 1500,
        }
        validated = validate_smoke_observation(hostile)
        self.assertEqual(validated["scenario"], "unknown")
        self.assertEqual(validated["cause"], "unknown")
        self.assertIsNone(validated["raw_returncode"])
        self.assertIsNone(validated["stdout_bytes"])
        self.assertEqual(validated["stderr_bytes"], 1024)
        self.assertIsNone(validated["stdout_sha256"])
        self.assertEqual(validated["stderr_sha256"], "a" * 64)
        self.assertEqual(validated["log_categories"], ["dbus-session-conf-missing"])
        self.assertEqual(validated["problem_codes"], ["valid-code", "withheld-token", "withheld-token"])
        self.assertEqual(validated["elapsed_ms"], 1500)
        for forbidden in ("raw_output", "stdout", "stderr", "message", "excerpt"):
            self.assertNotIn(forbidden, validated)

    def test_retain_host_smoke_diagnostic_writer_failure_cannot_mask(self):
        with tempfile.TemporaryDirectory() as td:
            diag_dir = Path(td).resolve() / "diagnostics"
            obs = {
                "scenario": "C", "cause": "dbus-session-failure", "raw_returncode": 127,
                "exit_code": 127, "signal": None, "stdout_bytes": 0, "stderr_bytes": 50,
                "stdout_sha256": "0" * 64, "stderr_sha256": "1" * 64,
                "stream_capture_complete": True, "log_categories": ["dbus-session-conf-missing"],
                "problem_codes": [], "elapsed_ms": 120, "reason_token": "dbus-session-failure",
            }
            # Normal write succeeds
            sha = retain_host_smoke_diagnostic(diag_dir, obs, family="apt", system="x86_64-linux")
            self.assertIsNotNone(sha)
            self.assertTrue((diag_dir / "application-smoke-failure-apt.json").is_file())
            content = json.loads((diag_dir / "application-smoke-failure-apt.json").read_bytes())
            self.assertEqual(content["schema"], "rs9.application-smoke-diagnostic.v1alpha1")
            self.assertEqual(content["cause"], "dbus-session-failure")
            self.assertEqual(content["family"], "apt")
            self.assertTrue(content["single_attempt"])

            # Writer failure (e.g. os.open raises OSError) returns None and does not raise
            with patch("os.open", side_effect=OSError("Read-only filesystem")):
                res = retain_host_smoke_diagnostic(diag_dir, obs, family="apt", system="x86_64-linux")
                self.assertIsNone(res)

    def test_probe_apt_runtime_image_uses_network_none_rm_and_never_fails_gate(self):
        class MockRunner:
            def __init__(self, succeed=True):
                self.succeed = succeed
                self.calls = []

            def run(self, cmd, **kwargs):
                self.calls.append(list(cmd))
                if self.succeed:
                    out = (b"sha256:" + b"a" * 64 + b"\n") if "inspect" in cmd else "".join(p + "\t1.0\n" for p in RUNTIME_PACKAGES).encode()
                    return CommandReceipt(cmd, 0, out, b"", executed=True)
                raise ContractError("TOOL_EXECUTION", "Docker daemon unavailable")

        # Success case
        runner = MockRunner(succeed=True)
        res = probe_apt_runtime_image(runner, "test-apt:tag")
        self.assertEqual(res["status"], "observed")
        self.assertIn("docker", runner.calls[0])
        self.assertIn("--network", runner.calls[1])
        self.assertEqual(runner.calls[1][runner.calls[1].index("--network") + 1], "none")
        self.assertIn("--rm", runner.calls[1])

        # Unavailable case: never raises, returns unavailable status
        failing_runner = MockRunner(succeed=False)
        res_fail = probe_apt_runtime_image(failing_runner, "test-apt:tag")
        self.assertEqual(res_fail["status"], "unavailable")

    def test_extract_smoke_context_deterministic(self):
        cs = {
            "request_sha256": "a" * 64,
            "family": "apt",
            "system": "x86_64-linux",
            "request": {
                "manifest_sha256": "b" * 64,
                "records": [{"id": "pkg1", "version": "1.0"}],
            }
        }
        ctx = extract_smoke_context(cs)
        self.assertEqual(ctx["request_sha256"], "a" * 64)
        self.assertEqual(ctx["manifest_sha256"], "b" * 64)
        self.assertEqual(ctx["family"], "apt")
        self.assertEqual(ctx["system"], "x86_64-linux")
        self.assertEqual(ctx["source_records_sha256"], digest(canonical([{"id": "pkg1", "version": "1.0"}])))

    def test_determine_counters_source(self):
        client = SimpleNamespace(last_inventory_stage="post-remove")
        self.assertEqual(determine_counters_source(client, None, "smoke"), "post-remove")

        client_pre = SimpleNamespace(last_inventory_stage="pre-install")
        self.assertEqual(determine_counters_source(client_pre, None, "install"), "pre-install")

        err = ContractError("INVENTORY_LIMIT", "Limit exceeded", details={"stage": "pre-install"})
        self.assertEqual(determine_counters_source(None, err, "pre-install"), "pre-install")

    def test_validate_smoke_observation_triple_idempotence_and_darwin_only_projection(self):
        from rs9.smoke_stream_tokens import (
            evidence_inventory, project_run_record, read_inner_stderr, stream_tokens,
        )

        with tempfile.TemporaryDirectory() as tmp:
            ev = Path(tmp).resolve()
            run_bytes = (
                b'{"status":"fail","receipt":{"steps":[{"id":"app-shell","ok":true},'
                b'{"id":"host-start","ok":false}]},"problems":["receipt schema"]}'
            )
            inner_bytes = b"TypeError: inner error\n"
            (ev / "darwin-arm64-A.run.json").write_bytes(run_bytes)
            (ev / "darwin-arm64-A.stderr.log").write_bytes(inner_bytes)

            inv = evidence_inventory(ev, "darwin-arm64", "A")
            run_rec = project_run_record(
                json.loads(run_bytes),
                {"present": True, "bytes": len(run_bytes), "sha256": digest(run_bytes)},
            )
            inner_rec = read_inner_stderr(ev, "darwin-arm64", "A")
            raw_darwin = {
                "scenario": "A",
                "cause": "process-nonzero",
                "raw_returncode": 1,
                "stdout_bytes": 427,
                "stderr_bytes": 0,
                "stdout_sha256": "a" * 64,
                "stderr_sha256": digest(b""),
                "stream_capture_complete": True,
                "log_categories": ["unclassified"],
                "receipt_error": "receipt-failed",
                "problem_codes": ["withheld-token"],
                "elapsed_ms": 9382,
                "reason_token": "process-nonzero",
                "stderr_diagnostic": stream_tokens(b"", complete=True),
                "evidence_inventory": inv,
                "harness_run_record": run_rec,
                "inner_stderr_diagnostic": inner_rec,
            }

            # Triple validation on Darwin Scenario A is idempotent
            p1 = validate_smoke_observation(raw_darwin, system="aarch64-darwin")
            p2 = validate_smoke_observation(p1, system="aarch64-darwin")
            p3 = validate_smoke_observation(p2, system="aarch64-darwin")
            self.assertIn("harness_run_record", p1)
            self.assertIn("inner_stderr_diagnostic", p1)
            self.assertEqual(p1["harness_run_record"]["status"], "observed")
            self.assertEqual(p1["inner_stderr_diagnostic"]["tokens"], ["node-type-error"])
            self.assertEqual(p1, p2)
            self.assertEqual(p2, p3)

            # System mismatch on Darwin produces persistent binding-mismatch fixed point across 3 passes
            mismatched_input = {**raw_darwin, "scenario": "C"}
            m1 = validate_smoke_observation(mismatched_input, system="aarch64-darwin")
            m2 = validate_smoke_observation(m1, system="aarch64-darwin")
            m3 = validate_smoke_observation(m2, system="aarch64-darwin")
            self.assertTrue(m1["binding_mismatch"])
            self.assertEqual(m1["harness_run_record"]["status"], "unavailable")
            self.assertEqual(m1["harness_run_record"]["withheld_reason"], "binding-mismatch")
            self.assertEqual(m1["inner_stderr_diagnostic"]["withheld_reason"], "binding-mismatch")
            self.assertEqual(m1["inner_stderr_diagnostic"]["tokens"], [])
            self.assertEqual(m1, m2)
            self.assertEqual(m2, m3)

            # Absent new keys on Darwin keep exact legacy key set
            legacy_input = {
                k: v for k, v in raw_darwin.items()
                if k not in ("harness_run_record", "inner_stderr_diagnostic")
            }
            legacy_out = validate_smoke_observation(legacy_input, system="aarch64-darwin")
            self.assertNotIn("harness_run_record", legacy_out)
            self.assertNotIn("inner_stderr_diagnostic", legacy_out)

            # Hostile Linux inputs carrying Darwin projections drop them completely
            for linux_sys, linux_scen in (("x86_64-linux", "C"), ("aarch64-linux", "B")):
                hostile_linux = {**raw_darwin, "scenario": linux_scen}
                baseline_linux = {**legacy_input, "scenario": linux_scen}
                self.assertEqual(
                    validate_smoke_observation(hostile_linux, system=linux_sys),
                    validate_smoke_observation(baseline_linux, system=linux_sys),
                )


class PagesNebularControlTests(unittest.TestCase):
    """Failing Pages Nebular all-other-clients-pass and all-pass controls, incumbent gates, one attempt."""

    def test_failing_pages_nebular_all_other_clients_pass_control(self):
        """When Nebular application smoke fails in apt client:

        The incumbent client gate fails. Aggregate Pages folding is checked separately.
        Single attempt (no replay).
        Evidence retains smoke_observation and counters_source='post-remove'.
        """
        from tests.test_hosted_deb import ScriptedDocker, ExecutedMock, host_runner
        with tempfile.TemporaryDirectory() as td:
            work = Path(td).resolve()
            host = hd.RecordingRunner(host_runner(ScriptedDocker(), ExecutedMock))
            spec = hd.apt_spec(work / "apt", work / "key.gpg", "amd64", public_fingerprint="A" * 40)
            spec["query"] = lambda p: ["dpkg-query", "-W", p]

            binding = {
                "output": work / "output",
                "request_sha256": "0" * 64,
                "family": "apt",
                "system": "x86_64-linux",
                "mounts": [],
                "prepared": {"scratch": work / "scratch/smoke-apt", "source": work, "tools": work, "records": []},
            }
            binding["output"].mkdir(parents=True)
            binding["prepared"]["scratch"].mkdir(parents=True)

            smoke_obs = {
                "scenario": "C",
                "cause": "dbus-session-failure",
                "raw_returncode": 127,
                "exit_code": 127,
                "signal": None,
                "stdout_bytes": 0,
                "stderr_bytes": 48,
                "stdout_sha256": "0" * 64,
                "stderr_sha256": "1" * 64,
                "stream_capture_complete": True,
                "log_categories": ["dbus-session-conf-missing"],
                "problem_codes": [],
                "elapsed_ms": 110,
                "reason_token": "dbus-session-failure",
            }
            smoke_error = ContractError("APPLICATION_SMOKE", "Released application-aware smoke failed",
                                        details={"scenario": "C", "cause": "dbus-session-failure", "exit_code": 127})
            smoke_error.smoke_observation = smoke_obs

            attempt_counter = {"attempts": 0}
            def count_smoke(*args, **kwargs):
                attempt_counter["attempts"] += 1
                raise smoke_error

            with patch("rs9.hosted_container_smoke.prepare_container_smoke", return_value=binding), \
                 patch("rs9.hosted_container_smoke.verify_container_nebular", side_effect=count_smoke), \
                 patch("rs9.hosted_deb.execute_probes", return_value=[]):
                rows, evidence = hd.client_cycle(
                    host, spec, image="rs9-pages-apt:tag", platform="linux/amd64",
                    products=[hd.NATIVE_PRODUCT], repository=work, prefix="pages-client.apt",
                    smoke={"fixture": True}, system="x86_64-linux",
                )

            # 1. Exactly one attempt (no retry/replay)
            self.assertEqual(attempt_counter["attempts"], 1)

            # 2. The incumbent client gate fails for Nebular
            failed_gates = [r for r in rows if r["status"] == "fail"]
            self.assertEqual(len(failed_gates), 1)
            gate_names = {r["name"] for r in failed_gates}
            self.assertEqual(gate_names, {
                f"pages-client.apt.{hd.NATIVE_PRODUCT}.client",
            })

            # 3. All other product gates pass (install, network-denial, native-closure, uninstall, inventory, cleanup)
            passing_gates = [r for r in rows if r["status"] == "pass"]
            passing_names = {r["name"].split(".")[-1] for r in passing_gates}
            self.assertIn("network-denial", passing_names)
            self.assertIn("install", passing_names)
            self.assertIn("native-closure", passing_names)
            self.assertIn("uninstall", passing_names)
            self.assertIn("inventory", passing_names)
            self.assertIn("cleanup", passing_names)

            # 4. Evidence retains smoke observation and counters_source
            product = evidence[hd.NATIVE_PRODUCT]
            self.assertEqual(product["error"], "APPLICATION_SMOKE")
            self.assertEqual(product["stage"], "smoke")
            self.assertEqual(product["counters_source"], "post-remove")
            self.assertEqual(product["smoke_observation"]["cause"], "dbus-session-failure")
            self.assertEqual(product["smoke_observation"]["scenario"], "C")
            self.assertEqual(product["smoke_observation"]["exit_code"], 127)

            # 5. Gate extra on client gate has counters_source and smoke observation
            client_gate = next(r for r in failed_gates if r["name"].endswith(".client"))
            self.assertEqual(client_gate["counters_source"], "post-remove")
            self.assertEqual(client_gate["scenario"], "C")
            self.assertEqual(client_gate["cause"], "dbus-session-failure")
            self.assertEqual(client_gate["smoke_observation"]["raw_returncode"], 127)

    def test_all_pass_control(self):
        """All-pass control: all clients and products succeed; exactly 0 gates fail."""
        from tests.test_hosted_deb import ScriptedDocker, ExecutedMock, host_runner
        with tempfile.TemporaryDirectory() as td:
            work = Path(td).resolve()
            host = hd.RecordingRunner(host_runner(ScriptedDocker(), ExecutedMock))
            spec = hd.apt_spec(work / "apt", work / "key.gpg", "amd64", public_fingerprint="A" * 40)
            spec["query"] = lambda p: ["dpkg-query", "-W", p]

            binding = {
                "output": work / "output",
                "request_sha256": "0" * 64,
                "family": "apt",
                "system": "x86_64-linux",
                "mounts": [],
                "prepared": {"scratch": work / "scratch/smoke-apt", "source": work, "tools": work, "records": []},
            }
            binding["output"].mkdir(parents=True)
            binding["prepared"]["scratch"].mkdir(parents=True)

            with patch("rs9.hosted_container_smoke.prepare_container_smoke", return_value=binding), \
                 patch("rs9.hosted_container_smoke.verify_container_nebular", return_value={"verified": True}), \
                 patch("rs9.hosted_deb.execute_probes", return_value=[]):
                rows, evidence = hd.client_cycle(
                    host, spec, image="rs9-pages-apt:tag", platform="linux/amd64",
                    products=[hd.NATIVE_PRODUCT], repository=work, prefix="pages-client.apt",
                    smoke={"fixture": True}, system="x86_64-linux",
                )

            failed_gates = [r for r in rows if r["status"] == "fail"]
            self.assertEqual(failed_gates, [])
            product = evidence[hd.NATIVE_PRODUCT]
            self.assertEqual(product["counters_source"], "post-remove")
            self.assertIn("application_smoke", product)
