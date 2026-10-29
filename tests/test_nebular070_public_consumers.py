"""Focused contract tests for the public Stage-B consumer producer.

The fixture uses the existing manylinux contract fixture only; no native
process, package install, Docker invocation, or network access is performed.
The release validator and maintained receipt materializer are still exercised
as the production assembler calls them.
"""
from __future__ import annotations

import base64
import copy
from dataclasses import replace
import inspect
import json
import unittest
from pathlib import Path
from unittest import mock

from rs9.errors import ContractError
from rs9.nebular070_installed_smoke import _STEPS
import rs9.nebular070_host_observation as host_observation
from rs9.nebular070_manylinux import _digest, _wheel_snapshot
from rs9.nebular070_payload import ARCHIVE_PORTABILITY_SCHEMA
from rs9.tf_pypi_archive import canonical as archive_canonical, sha256
from rs9.nebular070_public_consumers import (
    CONSUMER_KINDS,
    LINUX_CONSUMER_TARGETS,
    _actual_capture_body,
    assemble_stage_b,
    _assemble_stage_b_for_tests,
    capture_public_consumer,
    consumer_body_from_actual,
    validate_actual_consumer_result,
    _wheel,
)
import tests.test_nebular070_host_observation as host_fixture
import tests.test_nebular070_manylinux as fixture_module


class PublicStageBConsumerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.fixture = fixture_module.Nebular070ManylinuxContractTests(
            "test_stage_a_builds_manylinux_wheels_and_stage_b_reads_real_record"
        )
        self.fixture.setUp()
        self.addCleanup(self.fixture.tearDown)
        self.wheels = self.fixture._build_linux_wheels()
        (
            self.admission,
            self.bodies,
            self.approval,
            self.matrix,
        ) = self.fixture._stage_b_record(self.wheels)
        darwin = self.fixture._build_darwin_wheel()
        self.fixture._bind_darwin_fixture(self.admission, self.approval, self.matrix, darwin)
        self.expected_source = dict(self.admission["rs9_release_source"])

    def _captures(self, bodies=None):
        bodies = bodies or self.bodies
        return {
            target: {
                kind: {
                    "schema": "rs9.nebular070-public-consumer-capture.v1",
                    "evidence_mode": "fixture-test-only",
                    "target": target,
                    "kind": kind,
                    "body": copy.deepcopy(bodies[target][kind]),
                }
                for kind in CONSUMER_KINDS
            }
            for target in LINUX_CONSUMER_TARGETS
        }

    def _assemble(self, *, matrix=None, bodies=None, expected_source=None, allow_fixture=True):
        output = self.fixture.root / "stage-b-output"
        assembler = _assemble_stage_b_for_tests if allow_fixture else assemble_stage_b
        return assembler(
            stage_a=self.fixture.stage_a,
            wheel_bytes_by_target=self.wheels,
            wheel_filenames_by_target=self.fixture._filenames(self.wheels),
            consumer_captures=self._captures(bodies),
            existing_three_target_approval=self.approval,
            existing_matrix_receipt=self.matrix if matrix is None else matrix,
            expected_rs9_release_source=self.expected_source if expected_source is None else expected_source,
            output_dir=output,
        )

    def test_assembler_calls_real_admission_and_materializes_four_members(self) -> None:
        result = self._assemble()
        self.assertEqual(result["status"], "validated-and-materialized")
        output = Path(result["output_dir"])
        self.assertEqual(
            {path.relative_to(output).as_posix() for path in output.rglob("*") if path.is_file()},
            {
                "manylinux_admission.json",
                "consumers/linux-arm64-gnu/floor.json",
                "consumers/linux-arm64-gnu/newer.json",
                "consumers/linux-x64-gnu/floor.json",
                "consumers/linux-x64-gnu/newer.json",
            },
        )
        for target in LINUX_CONSUMER_TARGETS:
            for kind in CONSUMER_KINDS:
                self.assertEqual(
                    (output / "consumers" / target / f"{kind}.json").read_bytes(),
                    archive_canonical(result["consumer_bodies"][target][kind]),
                )

    def test_wrong_wheel_source_host_or_matrix_is_rejected(self) -> None:
        wrong_wheel = copy.deepcopy(self.bodies)
        wrong_wheel["linux-x64-gnu"]["floor"]["wheel_sha256"] = "0" * 64
        wrong_wheel["linux-x64-gnu"]["floor"]["identity"] = _digest({
            key: value for key, value in wrong_wheel["linux-x64-gnu"]["floor"].items()
            if key != "identity"
        })
        with self.assertRaises(ContractError):
            self._assemble(bodies=wrong_wheel)

        wrong_source = copy.deepcopy(self.admission)
        wrong_source["rs9_release_source"] = {"commit": "3" * 40, "tree": "4" * 40}
        with self.assertRaises(ContractError):
            self._assemble(expected_source=wrong_source["rs9_release_source"])

        wrong_host = copy.deepcopy(self.bodies)
        wrong_host["linux-arm64-gnu"]["newer"]["host"]["glibc"] = "2.36"
        wrong_host["linux-arm64-gnu"]["newer"]["identity"] = _digest({
            key: value for key, value in wrong_host["linux-arm64-gnu"]["newer"].items()
            if key != "identity"
        })
        with self.assertRaises(ContractError):
            self._assemble(bodies=wrong_host)

        with self.assertRaises(ContractError):
            self._assemble(matrix={})

    def test_fixture_capture_cannot_enter_production_assembler(self) -> None:
        with self.assertRaises(ContractError):
            self._assemble(allow_fixture=False)

    def test_production_rejects_fixture_record_even_if_dataclass_flag_is_forged(self) -> None:
        forged = replace(self.fixture.stage_a, fixture_only=False)
        with self.assertRaises(ContractError):
            assemble_stage_b(
                stage_a=forged,
                wheel_bytes_by_target=self.wheels,
                wheel_filenames_by_target=self.fixture._filenames(self.wheels),
                consumer_captures=self._captures(),
                existing_three_target_approval=self.approval,
                existing_matrix_receipt=self.matrix,
                expected_rs9_release_source=self.expected_source,
                output_dir=self.fixture.root / "stage-b-output",
            )

    def test_production_assembler_has_no_fixture_switch(self) -> None:
        self.assertNotIn("record", inspect.signature(assemble_stage_b).parameters)
        with self.assertRaises(TypeError):
            assemble_stage_b(
                stage_a=self.fixture.stage_a,
                wheel_bytes_by_target=self.wheels,
                wheel_filenames_by_target=self.fixture._filenames(self.wheels),
                consumer_captures=self._captures(),
                existing_three_target_approval=self.approval,
                existing_matrix_receipt=self.matrix,
                expected_rs9_release_source=self.expected_source,
                output_dir=self.fixture.root / "stage-b-output",
                allow_fixture=True,
            )

    def test_assembler_derives_post_consumer_record(self) -> None:
        result = self._assemble()
        self.assertEqual(result["record"]["stage_a_sha256"], self.fixture.stage_a.digest)
        self.assertEqual(result["record"]["rs9_release_source"], self.expected_source)
        self.assertEqual(result["record"]["identity"], result["admission_sha256"])

    def test_production_capture_has_no_injected_observer_or_runner_hooks(self) -> None:
        parameters = inspect.signature(capture_public_consumer).parameters
        for name in (
            "sandbox_prefix",
            "host_identity",
            "runner",
            "process_observer",
            "state_snapshot",
            "real_user_state_snapshot",
            "offline_pip_bootstrap",
        ):
            self.assertNotIn(name, parameters)


    def test_capture_derives_maintained_sandbox_and_user_state_guard(self) -> None:
        # Stop at the real consumer call: this proves wiring without installing
        # a wheel, inspecting user state, or invoking the native application.
        target = "linux-x64-gnu"
        actual_record = copy.deepcopy(self.fixture.stage_a.record)
        actual_record["schema"] = ARCHIVE_PORTABILITY_SCHEMA
        for row in actual_record["targets"]:
            row["archive_member_manifest_sha256"] = self.fixture.manifest["manifest_sha256"]
        actual_record["identity"] = _digest({key: value for key, value in actual_record.items() if key != "identity"})
        stage_a = replace(
            self.fixture.stage_a,
            fixture_only=False,
            record={**actual_record, "evidence_mode": "actual"},
        )
        wheel_path = self.fixture.root / "capture-wiring.whl"
        wheel_path.write_bytes(self.wheels[target])
        guard = mock.Mock(name="maintained_user_state_guard")
        prefix = ("maintained-network-denial",)
        module = "rs9.nebular070_public_consumers"
        with (
            mock.patch(module + ".observe_host", return_value=({}, {})),
            mock.patch(module + ".default_sandbox_prefix", return_value=prefix) as sandbox,
            mock.patch(module + ".make_real_user_state_snapshotter", return_value=guard) as snapshotter,
            mock.patch(module + ".qualify_nebular070", side_effect=RuntimeError("consumer call reached")) as qualify,
        ):
            with self.assertRaisesRegex(RuntimeError, "consumer call reached"):
                capture_public_consumer(
                    {}, wheel_path, {}, self.fixture.root / "capture-work",
                    expected_artifacts={}, expected_commit="a" * 40,
                    expected_tree="b" * 40, profile_sha256="c" * 64,
                    candidate_receipt_sha256="d" * 64, target=target, kind="floor",
                    run_id="101", run_attempt="1", manylinux_stage_a=stage_a,
                )
        sandbox.assert_called_once_with(target)
        snapshotter.assert_called_once_with(target)
        self.assertEqual(qualify.call_args.kwargs["sandbox_prefix"], prefix)
        self.assertIs(qualify.call_args.kwargs["real_user_state_snapshot"], guard)
        self.assertIs(qualify.call_args.kwargs["fixture_only"], False)
        guard.assert_not_called()


    def _actual_result(self, target="linux-x64-gnu"):
        wheel = self.wheels[target]
        snapshot = _wheel_snapshot(wheel, target, self.fixture.stage_a.digest)
        scenarios = ("C", "C-signal") if target == "linux-x64-gnu" else ("B",)
        gui_path = "bin/theme-forge-nebular-fusion"
        gui_sha = "1" * 64
        triple = {
            "linux-arm64-gnu": "aarch64-unknown-linux-gnu",
            "linux-x64-gnu": "x86_64-unknown-linux-gnu",
        }[target]

        def artifact(data):
            return {
                "schema": "rs9.nebular070-installed-smoke-json-artifact.v1",
                "encoding": "base64", "media_type": "application/json",
                "size": len(data), "sha256": sha256(data),
                "utf8_base64": base64.b64encode(data).decode("ascii"),
            }

        smoke_cases = []
        for scenario in scenarios:
            steps = [
                {"id": step, "ok": True, "via": "native-rc-smoke", "ms": 1}
                for step in _STEPS[scenario]
            ]
            receipt = {
                "schema": "nebular.release-smoke-receipt-v1",
                "applicationVersion": "0.7.0", "scenario": scenario,
                "status": "pass", "failure": None, "target": triple,
                "awaitingSignal": scenario == "C-signal",
                "executable": {"sha256": gui_sha, "size": 1},
                "driver": {
                    "status": "pass", "scenario": scenario, "facts": [], "steps": steps,
                },
            }
            receipt_data = json.dumps(receipt, sort_keys=True, separators=(",", ":")).encode()
            receipt_sha = sha256(receipt_data)
            checks = {
                "orphans": [], "persistentUserState": {"changed": []},
                "scratchHomeWrites": 1,
                **({"sidecarRunningBeforeSignal": True} if scenario == "C-signal" else {}),
            }
            exit_info = (
                {"code": None, "signal": "SIGTERM",
                 "signalSent": {"signal": "SIGTERM", "at": 1}, "durationMs": 1}
                if scenario == "C-signal" else
                {"code": 0, "signal": None, "signalSent": None, "durationMs": 1}
            )
            run = {
                "schema": "nebular.native-rc-smoke-run-v1", "status": "pass",
                "platform": "linux-arm64" if target == "linux-arm64-gnu" else "linux-x64",
                "scenario": scenario, "source": "raw-archive", "problems": [],
                "executable": {"path": gui_path, "sha256": gui_sha, "size": 1},
                "checks": checks, "exit": exit_info,
                "finalization": {
                    "schema": "nebular.native-rc-finalization-v1", "status": "complete",
                    "phase": "complete", "exceptionFamily": None, "spawned": True,
                    "exitObserved": True,
                    "applicationReceiptObservation": "present-at-read",
                    "applicationReceiptCopy": "written",
                },
                "receipt": {"status": "pass", "sha256": receipt_sha, "steps": steps},
            }
            run_data = json.dumps(run, sort_keys=True, separators=(",", ":")).encode()
            run_sha = sha256(run_data)
            smoke_cases.append({
                "schema": "rs9.nebular070-installed-native-smoke.v1",
                "status": "pass", "qualification_authority": True,
                "target": target, "scenario": scenario, "source": "raw-archive",
                "executable": {"path": gui_path, "sha256": gui_sha, "size": 1},
                "run": {"schema": run["schema"], "status": run["status"],
                        "sha256": run_sha, "size": len(run_data)},
                "run_artifact": artifact(run_data),
                "exit": exit_info, "finalization": run["finalization"],
                "receipt": {"schema": receipt["schema"], "status": receipt["status"],
                            "scenario": scenario, "sha256": receipt_sha,
                            "awaitingSignal": scenario == "C-signal", "steps": steps},
                "receipt_artifact": artifact(receipt_data),
                "checks": {
                    "orphans": [], "persistentUserStateChanged": [], "scratchHomeWrites": 1,
                    **({"sidecarRunningBeforeSignal": True} if scenario == "C-signal" else {}),
                },
                "native_probe": {"status": "pass", "scenario": scenario,
                                 "cleanup_known": True, "output_complete": True,
                                 "forced_cleanup": False},
            })
        application_smoke = {
            "schema": "rs9.nebular070-installed-native-smoke.v1",
            "status": "pass", "qualification_authority": True,
            "target": target, "source": "raw-archive", "scenarios": smoke_cases,
            "native_probe": {"status": "pass", "protocol": "nebular.native-rc-smoke",
                             "scenarios": list(scenarios), "cleanup_known": True,
                             "output_complete": True, "forced_cleanup": False,
                             "runs": {entry["scenario"]: entry["run"]["sha256"] for entry in smoke_cases},
                             "receipts": {entry["scenario"]: entry["receipt"]["sha256"] for entry in smoke_cases}},
        }
        consumer = {
            "schema": "rs9.nebular070-native-consumer.v1",
            "status": "native-consumer-passed",
            "fixture_only": False,
            "native_qualified": True,
            "target": target,
            "candidate_rs9_source": copy.deepcopy(self.matrix["candidate_rs9_source"]),
            "wheel": {
                "target": target,
                "filename": self.fixture._filenames({target: wheel})[target],
                "size": snapshot["size"],
                "sha256": snapshot["archive_sha256"],
                "tag": snapshot["tag"],
                "version": "0.7.0",
            },
            "sandbox": {"network_disabled": True, "method": "explicit-isolation-prefix"},
            "process_observer": {"orphan_count": 0},
            "user_state": {"unchanged": True},
            "provider_closure": {"status": "verified"},
            "cleanup": {"pip_uninstall_exit": 0, "orphan_processes": 0},
            "probes": {"native": {
                "exit_code": 0, "cleanup_known": True, "output_complete": True,
                "forced_cleanup": False,
            }},
            "gui": {
                "status": "verified", "type": "file", "executable": True,
                "label": "gui", "smoke_path": gui_path, "sha256": gui_sha,
            },
            "application_smoke": application_smoke,
            "publication_admitted": False,
            "public_writes": 0,
        }
        return {
            "schema": "rs9.nebular070-hosted-consumer.v1",
            "status": "native-consumer-passed",
            "fixture_only": False,
            "native_qualified": True,
            "target": target,
            "consumer": consumer,
            "publication_admitted": False,
            "public_writes": 0,
            "candidate_receipt_sha256": self.approval["candidate_receipt_sha256"],
            "expected_artifact_record_sha256": self.approval["expected_artifact_record_sha256"],
            "candidate_rs9_source": copy.deepcopy(self.matrix["candidate_rs9_source"]),
            "manylinux_stage_a_sha256": self.fixture.stage_a.digest,
            "run_id": "1",
            "run_attempt": "1",
            "qualification_rs9_source": copy.deepcopy(
                self.matrix["qualification_rs9_source"][target]
            ),
        }

    def _actual_host(self, target, kind):
        glibc = "2.36" if kind == "floor" else "2.39"
        is_arm = target == "linux-arm64-gnu"
        machine = "aarch64" if is_arm else "x86_64"
        readelf_machine = "AArch64" if is_arm else "Advanced Micro Devices X86-64"
        runner = host_fixture.ProbeRunner(machine=readelf_machine, ldd=glibc, loader=glibc)
        with mock.patch.object(host_observation.platform, "system", return_value="Linux"), \
                mock.patch.object(host_observation.platform, "machine", return_value=machine):
            body, extras = host_observation.observe_host(
                kind,
                command_runner=runner,
                python_libc_probe=lambda: glibc,
                platform_libc_probe=lambda: ("glibc", glibc),
            )
        extras = copy.deepcopy(extras)
        extras["evidence_mode"] = "actual"
        extras["frame"] = "same-process-linux-host"
        for probe in extras["probes"]:
            probe["frame"] = "same-process-linux-host"
            probe["custody"] = {
                "termination": "exited",
                "reaped": True,
                "cleanup": "not-needed",
            }
        return body, extras

    def test_actual_body_is_recomputed_and_all_source_joins_are_bound(self) -> None:
        target, kind = "linux-x64-gnu", "floor"
        qualification = self._actual_result(target)
        host_body, host_extras = self._actual_host(target, kind)
        wheel = _wheel_snapshot(self.wheels[target], target, self.fixture.stage_a.digest)
        capture = {
            "schema": "rs9.nebular070-public-consumer-capture.v1",
            "evidence_mode": "actual",
            "target": target,
            "kind": kind,
            "qualification": qualification,
            "host_observation": host_body,
            "host_extras": host_extras,
        }
        capture["body"] = consumer_body_from_actual(
            qualification, host_body, host_extras, target=target, kind=kind, wheel=wheel
        )
        rebuilt = _actual_capture_body(
            capture,
            target=target,
            kind=kind,
            wheel=wheel,
            approval=self.approval,
            matrix=self.matrix,
        )
        self.assertEqual(rebuilt, capture["body"])

        wrong_slot = copy.deepcopy(capture)
        wrong_slot["kind"] = "newer"
        with self.assertRaises(ContractError):
            _actual_capture_body(
                wrong_slot,
                target=target,
                kind=kind,
                wheel=wheel,
                approval=self.approval,
                matrix=self.matrix,
            )

        tampered = copy.deepcopy(capture)
        tampered["body"]["wheel_sha256"] = "0" * 64
        with self.assertRaises(ContractError):
            _actual_capture_body(
                tampered,
                target=target,
                kind=kind,
                wheel=wheel,
                approval=self.approval,
                matrix=self.matrix,
            )

        stale_profile = copy.deepcopy(capture)
        stale_profile["qualification"]["qualification_rs9_source"]["profile_sha256"] = "0" * 64
        with self.assertRaises(ContractError):
            _actual_capture_body(
                stale_profile,
                target=target,
                kind=kind,
                wheel=wheel,
                approval=self.approval,
                matrix=self.matrix,
            )

    def test_actual_shaped_path_runs_real_validator_and_materializer(self) -> None:
        actual_record = copy.deepcopy(self.fixture.stage_a.record)
        actual_record["schema"] = ARCHIVE_PORTABILITY_SCHEMA
        for row in actual_record["targets"]:
            row["archive_member_manifest_sha256"] = self.fixture.manifest["manifest_sha256"]
        actual_record["evidence_mode"] = "actual"
        actual_stage_a = replace(self.fixture.stage_a, record=actual_record, fixture_only=False)
        captures = {}
        for target in LINUX_CONSUMER_TARGETS:
            captures[target] = {}
            for kind in CONSUMER_KINDS:
                qualification = self._actual_result(target)
                host_body, host_extras = self._actual_host(target, kind)
                wheel = _wheel_snapshot(self.wheels[target], target, actual_stage_a.digest)
                body = consumer_body_from_actual(
                    qualification, host_body, host_extras,
                    target=target, kind=kind, wheel=wheel,
                )
                captures[target][kind] = {
                    "schema": "rs9.nebular070-public-consumer-capture.v1",
                    "evidence_mode": "actual",
                    "target": target,
                    "kind": kind,
                    "qualification": qualification,
                    "host_observation": host_body,
                    "host_extras": host_extras,
                    "body": body,
                }
        result = assemble_stage_b(
            stage_a=actual_stage_a,
            wheel_bytes_by_target=self.wheels,
            wheel_filenames_by_target=self.fixture._filenames(self.wheels),
            consumer_captures=captures,
            existing_three_target_approval=self.approval,
            existing_matrix_receipt=self.matrix,
            expected_rs9_release_source=self.expected_source,
            output_dir=self.fixture.root / "actual-stage-b-output",
        )
        self.assertEqual(result["status"], "validated-and-materialized")
        self.assertEqual(
            sorted(path.name for path in Path(result["output_dir"]).rglob("*.json")),
            ["floor.json", "floor.json", "manylinux_admission.json", "newer.json", "newer.json"],
        )

    def test_production_wheel_consumer_rejects_archive_manifest_mismatch(self) -> None:
        actual_record = copy.deepcopy(self.fixture.stage_a.record)
        actual_record["schema"] = ARCHIVE_PORTABILITY_SCHEMA
        for row in actual_record["targets"]:
            row["archive_member_manifest_sha256"] = self.fixture.manifest["manifest_sha256"]
        actual_record["evidence_mode"] = "actual"
        actual_stage_a = replace(self.fixture.stage_a, record=actual_record, fixture_only=False)
        target = "linux-x64-gnu"
        next(row for row in actual_stage_a.record["targets"] if row["target"] == target)[
            "archive_member_manifest_sha256"
        ] = "0" * 64
        with self.assertRaises(ContractError):
            _wheel(self.wheels[target], target, actual_stage_a)

    def test_actual_result_rejects_failed_consumer_network_and_cleanup(self) -> None:
        for mutate in (
            lambda result: result["consumer"].update(status="failed"),
            lambda result: result["consumer"]["sandbox"].update(network_disabled=False),
            lambda result: result["consumer"]["sandbox"].update(method="unknown"),
            lambda result: result["consumer"]["cleanup"].update(pip_uninstall_exit=1),
            lambda result: result["consumer"]["cleanup"].update(orphan_processes=1),
            lambda result: result["consumer"]["gui"].update(
                smoke_path="bin/not-the-authenticated-gui",
            ),
            lambda result: result["consumer"]["gui"].update(sha256="0" * 64),
        ):
            result = self._actual_result()
            mutate(result)
            with self.assertRaises(ContractError):
                validate_actual_consumer_result(result, target="linux-x64-gnu")
        validate_actual_consumer_result(self._actual_result(), target="linux-x64-gnu")


if __name__ == "__main__":
    unittest.main()
