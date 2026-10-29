"""Focused installed-wheel native-driver contract tests.

The child process is a bounded fake only; the released harness and application
are not run in this unit module.  Receipt bytes still cross the real adapter
and public-consumer validation boundary.
"""
from __future__ import annotations

import base64
import copy
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from rs9.tf_pypi_archive import AdmissionError
from rs9.nebular070_installed_smoke import (
    _STEPS,
    run_installed_smoke,
    validate_installed_smoke_summary,
)
from rs9.nebular070_public_consumers import validate_actual_consumer_result
from rs9.tf_pypi_archive import sha256


class InstalledSmokeDriverTests(unittest.TestCase):
    @staticmethod
    def _rewrite_run_artifact(smoke, mutate):
        entry = smoke["scenarios"][0]
        artifact = entry["run_artifact"]
        raw = base64.b64decode(artifact["utf8_base64"], validate=True)
        value = json.loads(raw)
        mutate(value)
        updated = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
        digest = sha256(updated)
        artifact.update({
            "size": len(updated), "sha256": digest,
            "utf8_base64": base64.b64encode(updated).decode("ascii"),
        })
        entry["run"].update({"size": len(updated), "sha256": digest})
        smoke["native_probe"]["runs"][entry["scenario"]] = digest

    def _fixture(self, *, mutate=None, target="linux-x64-gnu"):
        temporary = tempfile.TemporaryDirectory(prefix="nebular-installed-smoke-")
        # macOS may expose the temporary directory through a symlinked /tmp;
        # the production custody reader intentionally rejects symlinked
        # ancestors, so fixtures must use the physical path as well.
        root = Path(temporary.name).resolve()
        source = root / "source"
        tools = source / "tools"
        tools.mkdir(parents=True)
        harness = tools / "native-rc-smoke.mjs"
        harness.write_text("export const runSmoke = () => {};\n", encoding="utf-8")
        runtime = root / "runtime"
        runtime.mkdir()
        target_info = {
            "darwin-arm64": {
                "platform": "darwin-arm64", "triple": "aarch64-apple-darwin",
                "scenarios": ("A",),
                "smoke_path": "Theme Forge Nebular Fusion.app/Contents/MacOS/theme-forge-nebular-fusion",
            },
            "linux-arm64-gnu": {
                "platform": "linux-arm64", "triple": "aarch64-unknown-linux-gnu",
                "scenarios": ("B",), "smoke_path": "bin/theme-forge-nebular-fusion",
            },
            "linux-x64-gnu": {
                "platform": "linux-x64", "triple": "x86_64-unknown-linux-gnu",
                "scenarios": ("C", "C-signal"), "smoke_path": "bin/theme-forge-nebular-fusion",
            },
        }[target]
        gui_sha = "1" * 64
        native = {"command": "tfnf", "scenario": target_info["scenarios"][0], "timeout_seconds": 20}
        gui = {
            "status": "verified", "type": "file", "executable": True, "label": "gui",
            "smoke_path": target_info["smoke_path"], "sha256": gui_sha,
        }
        def pair(scenario):
            run_steps = [{"id": step, "ok": True, "via": "native-rc-smoke", "ms": 1}
                         for step in _STEPS[scenario]]
            receipt = {
                "schema": "nebular.release-smoke-receipt-v1", "applicationVersion": "0.7.0",
                "scenario": scenario, "status": "pass", "failure": None,
                "target": target_info["triple"], "awaitingSignal": scenario == "C-signal",
                "executable": {"sha256": gui_sha},
                "driver": {"status": "pass", "scenario": scenario, "facts": [], "steps": run_steps},
            }
            receipt_bytes = json.dumps(receipt, sort_keys=True, separators=(",", ":")).encode()
            checks = {"orphans": [], "persistentUserState": {"changed": []}, "scratchHomeWrites": 1}
            if scenario == "C-signal":
                checks["sidecarRunningBeforeSignal"] = True
            run = {
                "schema": "nebular.native-rc-smoke-run-v1", "status": "pass",
                "platform": target_info["platform"], "scenario": scenario, "source": "raw-archive", "problems": [],
                "executable": {"path": gui["smoke_path"], "sha256": gui_sha, "size": 1},
                "checks": checks,
                "exit": ({"code": None, "signal": "SIGTERM",
                          "signalSent": {"signal": "SIGTERM", "at": 2}, "durationMs": 5}
                         if scenario == "C-signal" else
                         {"code": 0, "signal": None, "signalSent": None, "durationMs": 5}),
                "finalization": {"schema": "nebular.native-rc-finalization-v1", "status": "complete",
                                "phase": "complete", "exceptionFamily": None, "spawned": True,
                                "exitObserved": True,
                                "applicationReceiptObservation": "present-at-read",
                                "applicationReceiptCopy": "written"},
                "receipt": {"status": "pass", "sha256": sha256(receipt_bytes),
                            "steps": run_steps},
            }
            if mutate and scenario == target_info["scenarios"][0]:
                mutate(run, receipt)
                receipt_bytes = json.dumps(receipt, sort_keys=True, separators=(",", ":")).encode()
                run["receipt"]["sha256"] = sha256(receipt_bytes)
            run_bytes = json.dumps(run, sort_keys=True, separators=(",", ":")).encode()
            return run_bytes, receipt_bytes

        def fake_run(command, _env, _cwd, _prefix, _timeout, *, runner):
            evidence = Path(command[command.index("--evidence") + 1])
            label = command[command.index("--label") + 1]
            scenario = command[command.index("--scenario") + 1]
            run_bytes, receipt_bytes = pair(scenario)
            evidence.mkdir(parents=True, exist_ok=True)
            (evidence / f"{label}.run.json").write_bytes(run_bytes)
            (evidence / f"{label}.receipt.json").write_bytes(receipt_bytes)
            return {"exit_code": 0, "signal": None, "stdout_sha256": "2" * 64,
                    "stderr_sha256": "3" * 64, "duration_ms": 5,
                    "cleanup_known": True, "output_complete": True, "forced_cleanup": False}

        prepared = {"source": source, "tools": tools,
                    "records": [{"path": "tools/native-rc-smoke.mjs", "sha256": sha256(harness.read_bytes())}]}
        return temporary, prepared, runtime, native, gui, fake_run

    def test_installed_harness_receipt_crosses_public_consumer_boundary(self):
        temporary, prepared, runtime, native, gui, fake_run = self._fixture()
        self.addCleanup(temporary.cleanup)
        with patch("rs9.tf_pypi_consumer._nebular_run", side_effect=fake_run), \
                patch("rs9.nebular070_installed_smoke.node_binary", return_value="/usr/bin/true"):
            smoke = run_installed_smoke(
                prepared=prepared, target="linux-x64-gnu", runtime_root=runtime,
                env={"PATH": "/usr/bin:/bin"}, prefix=(), evidence=Path(temporary.name) / "evidence",
                native=native, gui=gui, runner=object(), timeout=20,
            )
        consumer = {
            "schema": "rs9.nebular070-native-consumer.v1", "status": "native-consumer-passed",
            "fixture_only": False, "native_qualified": True, "target": "linux-x64-gnu",
            "wheel": {"target": "linux-x64-gnu", "sha256": "4" * 64, "tag": "x"},
            "sandbox": {"network_disabled": True, "method": "explicit-isolation-prefix"},
            "process_observer": {"orphan_count": 0}, "user_state": {"unchanged": True},
            "provider_closure": {"status": "verified"},
            "cleanup": {"pip_uninstall_exit": 0, "orphan_processes": 0},
            "probes": {"native": smoke["native_probe"]}, "application_smoke": smoke,
            "gui": {
                "status": "verified", "type": "file", "executable": True,
                "label": "gui", "smoke_path": gui["smoke_path"], "sha256": gui["sha256"],
            },
            "publication_admitted": False, "public_writes": 0,
        }
        result = {
            "schema": "rs9.nebular070-hosted-consumer.v1", "status": "native-consumer-passed",
            "fixture_only": False, "native_qualified": True, "target": "linux-x64-gnu",
            "consumer": consumer, "publication_admitted": False, "public_writes": 0,
            "qualification_rs9_source": {"status": "executing-qualification-source",
                                          "run_id": "1", "run_attempt": "1"},
        }
        validate_actual_consumer_result(result, target="linux-x64-gnu")

    def test_installed_receipt_step_tamper_fails_closed(self):
        def tamper(_run, receipt):
            receipt["driver"]["steps"][0]["ok"] = False

        temporary, prepared, runtime, native, gui, fake_run = self._fixture(mutate=tamper)
        self.addCleanup(temporary.cleanup)
        with patch("rs9.tf_pypi_consumer._nebular_run", side_effect=fake_run), \
                patch("rs9.nebular070_installed_smoke.node_binary", return_value="/usr/bin/true"):
            with self.assertRaises(AdmissionError):
                run_installed_smoke(
                    prepared=prepared, target="linux-x64-gnu", runtime_root=runtime,
                    env={"PATH": "/usr/bin:/bin"}, prefix=(), evidence=Path(temporary.name) / "evidence",
                    native=native, gui=gui, runner=object(), timeout=20,
                )

    def test_arbitrary_native_command_is_rejected_before_runner(self):
        temporary, prepared, runtime, native, gui, fake_run = self._fixture()
        self.addCleanup(temporary.cleanup)
        native["command"] = "other-tool"
        with patch("rs9.tf_pypi_consumer._nebular_run", side_effect=fake_run), \
                patch("rs9.nebular070_installed_smoke.node_binary", return_value="/usr/bin/true"):
            with self.assertRaises(AdmissionError):
                run_installed_smoke(
                    prepared=prepared, target="linux-x64-gnu", runtime_root=runtime,
                    env={"PATH": "/usr/bin:/bin"}, prefix=(), evidence=Path(temporary.name) / "evidence",
                    native=native, gui=gui, runner=object(), timeout=20,
                )

    def test_signal_case_is_required_for_x64(self):
        temporary, prepared, runtime, native, gui, fake_run = self._fixture()
        self.addCleanup(temporary.cleanup)
        with patch("rs9.tf_pypi_consumer._nebular_run", side_effect=fake_run), \
                patch("rs9.nebular070_installed_smoke.node_binary", return_value="/usr/bin/true"):
            smoke = run_installed_smoke(
                prepared=prepared, target="linux-x64-gnu", runtime_root=runtime,
                env={"PATH": "/usr/bin:/bin"}, prefix=(), evidence=Path(temporary.name) / "evidence",
                native=native, gui=gui, runner=object(), timeout=20,
            )
        smoke["scenarios"] = smoke["scenarios"][:1]
        with self.assertRaises(AdmissionError):
            validate_installed_smoke_summary(
                smoke, target="linux-x64-gnu", authenticated_gui=gui,
            )

    def test_forged_signal_digest_is_rejected(self):
        temporary, prepared, runtime, native, gui, fake_run = self._fixture()
        self.addCleanup(temporary.cleanup)
        with patch("rs9.tf_pypi_consumer._nebular_run", side_effect=fake_run), \
                patch("rs9.nebular070_installed_smoke.node_binary", return_value="/usr/bin/true"):
            smoke = run_installed_smoke(
                prepared=prepared, target="linux-x64-gnu", runtime_root=runtime,
                env={"PATH": "/usr/bin:/bin"}, prefix=(), evidence=Path(temporary.name) / "evidence",
                native=native, gui=gui, runner=object(), timeout=20,
            )
        smoke["scenarios"][1]["receipt"]["sha256"] = "f" * 64
        with self.assertRaises(AdmissionError):
            validate_installed_smoke_summary(
                smoke, target="linux-x64-gnu", authenticated_gui=gui,
            )

    def test_stale_signal_case_is_rejected(self):
        temporary, prepared, runtime, native, gui, fake_run = self._fixture()
        self.addCleanup(temporary.cleanup)
        with patch("rs9.tf_pypi_consumer._nebular_run", side_effect=fake_run), \
                patch("rs9.nebular070_installed_smoke.node_binary", return_value="/usr/bin/true"):
            smoke = run_installed_smoke(
                prepared=prepared, target="linux-x64-gnu", runtime_root=runtime,
                env={"PATH": "/usr/bin:/bin"}, prefix=(), evidence=Path(temporary.name) / "evidence",
                native=native, gui=gui, runner=object(), timeout=20,
            )
        smoke["scenarios"][1]["receipt"]["scenario"] = "C"
        with self.assertRaises(AdmissionError):
            validate_installed_smoke_summary(
                smoke, target="linux-x64-gnu", authenticated_gui=gui,
            )

    def test_signal_sidecar_observation_is_required(self):
        temporary, prepared, runtime, native, gui, fake_run = self._fixture()
        self.addCleanup(temporary.cleanup)
        with patch("rs9.tf_pypi_consumer._nebular_run", side_effect=fake_run), \
                patch("rs9.nebular070_installed_smoke.node_binary", return_value="/usr/bin/true"):
            smoke = run_installed_smoke(
                prepared=prepared, target="linux-x64-gnu", runtime_root=runtime,
                env={"PATH": "/usr/bin:/bin"}, prefix=(), evidence=Path(temporary.name) / "evidence",
                native=native, gui=gui, runner=object(), timeout=20,
            )
        smoke["scenarios"][1]["checks"].pop("sidecarRunningBeforeSignal")
        with self.assertRaises(AdmissionError):
            validate_installed_smoke_summary(
                smoke, target="linux-x64-gnu", authenticated_gui=gui,
            )

    def test_matrix_reloads_complete_run_artifact_fields(self):
        temporary, prepared, runtime, native, gui, fake_run = self._fixture()
        self.addCleanup(temporary.cleanup)
        with patch("rs9.tf_pypi_consumer._nebular_run", side_effect=fake_run), \
                patch("rs9.nebular070_installed_smoke.node_binary", return_value="/usr/bin/true"):
            baseline = run_installed_smoke(
                prepared=prepared, target="linux-x64-gnu", runtime_root=runtime,
                env={"PATH": "/usr/bin:/bin"}, prefix=(), evidence=Path(temporary.name) / "evidence",
                native=native, gui=gui, runner=object(), timeout=20,
            )
        mutations = {
            "schema": lambda run: run.update({"schema": "wrong"}),
            "case": lambda run: run.update({"scenario": "A"}),
            "steps": lambda run: run["receipt"]["steps"][0].update({"ok": False}),
            "target": lambda run: run.update({"platform": "darwin-arm64"}),
            "finalization": lambda run: run["finalization"].update({"status": "partial"}),
            "gui-path": lambda run: run["executable"].update({"path": "wrong/path"}),
        }
        for label, mutate in mutations.items():
            with self.subTest(label=label):
                candidate = copy.deepcopy(baseline)
                self._rewrite_run_artifact(candidate, mutate)
                with self.assertRaises(AdmissionError):
                    validate_installed_smoke_summary(
                        candidate, target="linux-x64-gnu", authenticated_gui=gui,
                    )

        candidate = copy.deepcopy(baseline)
        candidate["scenarios"][0]["run_artifact"]["sha256"] = "f" * 64
        with self.assertRaises(AdmissionError):
            validate_installed_smoke_summary(
                candidate, target="linux-x64-gnu", authenticated_gui=gui,
            )
        candidate = copy.deepcopy(baseline)
        candidate["scenarios"][0]["receipt_artifact"]["utf8_base64"] = "!"
        with self.assertRaises(AdmissionError):
            validate_installed_smoke_summary(
                candidate, target="linux-x64-gnu", authenticated_gui=gui,
            )

    def test_strict_reloaded_matrix_covers_all_primary_targets(self):
        for target in ("darwin-arm64", "linux-arm64-gnu", "linux-x64-gnu"):
            with self.subTest(target=target):
                temporary, prepared, runtime, native, gui, fake_run = self._fixture(target=target)
                self.addCleanup(temporary.cleanup)
                with patch("rs9.tf_pypi_consumer._nebular_run", side_effect=fake_run), \
                        patch("rs9.nebular070_installed_smoke.node_binary", return_value="/usr/bin/true"):
                    smoke = run_installed_smoke(
                        prepared=prepared, target=target, runtime_root=runtime,
                        env={"PATH": "/usr/bin:/bin"}, prefix=(), evidence=Path(temporary.name) / "evidence",
                        native=native, gui=gui, runner=object(), timeout=20,
                    )
                self.assertTrue(smoke["scenarios"])
                validate_installed_smoke_summary(
                    smoke, target=target, authenticated_gui=gui,
                )

        temporary, prepared, runtime, native, gui, fake_run = self._fixture()
        self.addCleanup(temporary.cleanup)
        with patch("rs9.tf_pypi_consumer._nebular_run", side_effect=fake_run), \
                patch("rs9.nebular070_installed_smoke.node_binary", return_value="/usr/bin/true"):
            smoke = run_installed_smoke(
                prepared=prepared, target="linux-x64-gnu", runtime_root=runtime,
                env={"PATH": "/usr/bin:/bin"}, prefix=(), evidence=Path(temporary.name) / "evidence",
                native=native, gui=gui, runner=object(), timeout=20,
            )
        with self.assertRaises(AdmissionError):
            validate_installed_smoke_summary(
                smoke, target="darwin-arm64", authenticated_gui=gui,
            )


if __name__ == "__main__":
    unittest.main()
