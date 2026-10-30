"""Non-admitting, byte-backed fixtures for universal receipt readback."""
import copy
from pathlib import Path
import unittest
from unittest.mock import patch

from rs9 import nebular070_universal_consumer as universal
from rs9 import tf_pypi_consumer as consumer
from rs9.errors import ContractError
from rs9.tf_pypi_archive import AdmissionError, sha256
from rs9.scratch import canonical
from tests.test_tf_pypi_nebular070_publish import _complete_smoke_summary


class UniversalConsumerReceiptTests(unittest.TestCase):
    def setUp(self):
        self.target = "darwin-arm64"
        self.source = {"commit": "a" * 40, "tree": "b" * 40}
        path = "Theme Forge Nebular Fusion.app/Contents/MacOS/theme-forge-nebular-fusion"
        self.gui = {"status": "verified", "type": "file", "executable": True,
                    "label": "gui", "smoke_path": path, "materialized_path": path,
                    "sha256": "1" * 64}
        self.capture = {"gui": self.gui, "manifest_sha256": "2" * 64,
                        "payload_sha256": "3" * 64, "release_record_sha256": "4" * 64,
                        "provenance_sha256": "5" * 64}
        self.snapshot = {"wheel": {"filename": "theme_forge_nebular_fusion-0.7.0-py3-none-any.whl",
                                   "sha256": "6" * 64, "size": 250000, "tag": "py3-none-any", "version": "0.7.0"},
                         "runtime_inputs_sha256": "7" * 64, "runtime_index_sha256": "8" * 64,
                         "runtime_inputs": {"targets": {self.target: {
                             "asset": {"sha256": "3" * 64, "size": 123}, "manifest_sha256": "2" * 64}}}}
        app = _complete_smoke_summary(self.target, ("A",), gui_path=path, gui_sha=self.gui["sha256"])
        def state(phase):
            return {"schema": "nebular.native-rc-persistent-user-state-v1",
                    "method": "native-rc-smoke.persistentStateLocations+snapshotLocations",
                    "scope": "real-user-state", "target": self.target, "phase": phase,
                    "locations": 1, "snapshot_sha256": "9" * 64, "changed": []}
        def process(code=0, stdout=b""):
            return {"exit_code": code, "signal": None, "stdout_sha256": sha256(stdout),
                    "stderr_sha256": sha256(b""), "duration_ms": 1,
                    "cleanup_known": True, "output_complete": True, "forced_cleanup": False,
                    "timed_out": False, "output_limit_exceeded": False}
        value = {
            "schema": "rs9.nebular070-universal-native-consumer.v1", "distribution": "universal-launcher",
            "status": "passed", "target": self.target, "consumer_host_role": "newer",
            "source": self.source, "run": {"id": "17", "attempt": "1"},
            **{key: self.snapshot[key] for key in ("wheel", "runtime_inputs_sha256", "runtime_index_sha256")},
            **{key: self.capture[key] for key in ("payload_sha256", "manifest_sha256", "release_record_sha256", "provenance_sha256")},
            "gui": self.gui,
            "host_identity": {"source": "runner", "system": consumer.NEBULAR070_TARGET_SYSTEMS[self.target], "machine": "arm64"},
            "host_observation": None, "host_extras": None,
            "sandbox": {"network_disabled": True, "method": "explicit-isolation-prefix"},
            "process_observer": {"before": {"orphan_count": 0}, "after": {"orphan_count": 0}, "orphan_count": 0},
            "user_state": {"unchanged": True,
                           "scratch": {"before": {}, "after": {}, "unchanged": True},
                           "real_user_state": {"before": state("before"), "after": state("after"), "unchanged": True}},
            "probes": {"version": process(stdout=b"theme-forge-nebular-fusion 0.7.0\n"),
                       "path": {**process(), "resolved_sha256": self.gui["sha256"],
                                "resolved_relative": ".cache/rs9/theme-forge-nebular-fusion/entries/" + "2" * 64 + "/payload/" + path},
                       "native": app["native_probe"]},
            "cleanup": {"pip_uninstall_exit": 0, "orphan_processes": 0}, "application_smoke": app,
            "runtime_setup": {"schema": "rs9.nebular070-universal-runtime-setup.v1", "status": "passed",
                              "target": self.target, "archive_sha256": "3" * 64, "archive_bytes": 123,
                              "manifest_sha256": "2" * 64, "cold_refusal": process(1),
                              "explicit_setup": process(), "offline_reuse": process(),
                              "archive_unchanged": True, "publication_admitted": False},
            "native_qualified": True, "fixture_only": False, "publication_admitted": False, "public_writes": 0,
        }
        self.value = self.sign(value)

    @staticmethod
    def sign(value):
        value = copy.deepcopy(value)
        value.pop("identity", None)
        return {**value, "identity": sha256(canonical(value))}

    def validate(self, value):
        return universal.validate_universal_consumer(
            value, self.snapshot, self.capture, target=self.target, role="newer",
            source=self.source, run_id="17", run_attempt="1")

    def test_complete_fixture_reads_back_without_publication_authority(self):
        self.assertEqual(self.validate(self.value), self.value)
        self.assertFalse(self.validate(self.value)["publication_admitted"])

    def test_legacy_domain_platform_wheel_source_run_and_flags_cannot_substitute(self):
        for change in ({"schema": "rs9.nebular070-native-consumer.v1"},
                       {"distribution": "platform-wheel"}, {"publication_admitted": True},
                       {"fixture_only": True}, {"source": {"commit": "c" * 40, "tree": "b" * 40}},
                       {"run": {"id": "18", "attempt": "1"}},
                       {"wheel": {**self.snapshot["wheel"], "tag": "py3-none-linux_x86_64"}},
                       {"runtime_index_sha256": "0" * 64}):
            with self.subTest(fields=tuple(change)), self.assertRaises(ContractError):
                self.validate(self.sign({**self.value, **change}))

    def test_lifecycle_guards_are_revalidated_after_outer_identity_is_resigned(self):
        for kind in ("sandbox", "orphan", "scratch", "real", "cleanup", "path", "setup", "native"):
            value = copy.deepcopy(self.value)
            if kind == "sandbox": value["sandbox"]["network_disabled"] = False
            elif kind == "orphan": value["process_observer"]["after"]["orphan_count"] = 1
            elif kind == "scratch": value["user_state"]["scratch"]["after"] = {"changed": True}
            elif kind == "real": value["user_state"]["real_user_state"]["after"]["snapshot_sha256"] = "0" * 64
            elif kind == "cleanup": value["cleanup"]["pip_uninstall_exit"] = 1
            elif kind == "path": value["probes"]["path"]["resolved_sha256"] = "0" * 64
            elif kind == "setup": value["runtime_setup"]["offline_reuse"]["forced_cleanup"] = True
            else: value["application_smoke"]["scenarios"] = []
            with self.subTest(kind=kind), self.assertRaises((ContractError, AdmissionError)):
                self.validate(self.sign(value))

    def test_unknown_setup_fields_and_invalid_outer_digest_are_refused(self):
        value = copy.deepcopy(self.value)
        value["runtime_setup"]["signed_url"] = "https://private.invalid/?token=PRIVATE"
        with self.assertRaises(ContractError): self.validate(self.sign(value))
        with self.assertRaises(ContractError): self.validate({**self.value, "identity": "0" * 64})

    def test_process_envelopes_reject_raw_fields_and_missing_failure_flags(self):
        for name in ("cold_refusal", "explicit_setup", "offline_reuse", "version", "path"):
            for kind in ("extra", "missing"):
                value = copy.deepcopy(self.value)
                process = value["probes"][name] if name in {"version", "path"} else value["runtime_setup"][name]
                if kind == "extra":
                    process["stderr_token"] = "PRIVATE_MARKER"
                else:
                    process.pop("timed_out")
                with self.subTest(process=name, kind=kind), self.assertRaises(ContractError):
                    self.validate(self.sign(value))

    def produce(self, *, invalid_version=False):
        installed = {key: copy.deepcopy(self.value[key]) for key in (
            "sandbox", "process_observer", "user_state", "probes", "cleanup", "application_smoke", "runtime_setup")}
        for key in ("version", "path"):
            installed["probes"][key]["stderr_token"] = "PRIVATE_MARKER"
            installed["probes"][key]["termination_reason"] = "PRIVATE_MARKER"
        if invalid_version:
            installed["probes"]["version"]["stdout_sha256"] = "0" * 64
        env = {"GITHUB_ACTIONS": "true", "GITHUB_REPOSITORY": "Knowledge-Forge-AI/release-starport-9",
               "GITHUB_REF": "refs/heads/main", "GITHUB_RUN_ID": "17", "GITHUB_RUN_ATTEMPT": "1",
               "GITHUB_SHA": "a" * 40}
        with patch.dict("os.environ", env, clear=True), patch(
                "rs9.tf_pypi_nebular070_publish._git_output", side_effect=["a" * 40, "b" * 40]), \
             patch.object(universal.builder, "_read", return_value=(b"synthetic wheel", ())), \
             patch.object(universal, "inspect_universal_wheel", return_value=self.snapshot), \
             patch.object(universal, "capture_universal_runtime", return_value=self.capture), \
             patch.object(consumer, "_nebular_identity_observed", return_value=self.value["host_identity"]), \
             patch.object(consumer, "_nebular_installed_consumer", return_value=installed), \
             patch("rs9.tf_pypi_nebular070_publish.default_sandbox_prefix", return_value=("deny",)), \
             patch("rs9.tf_pypi_nebular070_publish.make_real_user_state_snapshotter", return_value=object()):
            return universal.consume_universal_wheel(
                Path(self.snapshot["wheel"]["filename"]), b"synthetic pins", b"synthetic description",
                {"root": "."}, Path("unused-synthetic-work"), target=self.target,
                source=self.source, run_id="17", run_attempt="1", repository=Path("."))

    def test_producer_projects_raw_process_fields_and_reads_back_its_own_receipt(self):
        value = self.produce()
        self.assertNotIn("PRIVATE_MARKER", str(value))
        self.assertEqual(self.validate(value), value)
        with self.assertRaises(ContractError):
            self.produce(invalid_version=True)
