"""Controlled in-memory 0.8 receipt identity/readback checks.

These tests call the maintained consumer and matrix validators directly with
small, production-shaped unit receipts. The downstream application,
host-observation, Darwin-boundary, and missing-runtime leaves are explicitly
controlled so this file does not mint native admission, read product payloads,
write fixtures, or claim native/publication evidence.
"""
from __future__ import annotations

import copy
from contextlib import contextmanager
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import patch


REPOSITORY = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPOSITORY / "src"))

from rs9 import nebular080_consumer_core as consumer_core  # noqa: E402
from rs9 import nebular080_installed_smoke as installed_smoke  # noqa: E402
from rs9 import nebular080_universal_consumer as consumer  # noqa: E402
from rs9 import nebular080_universal_profile as profile  # noqa: E402
from rs9 import tf_pypi_nebular080_universal as universal  # noqa: E402
from rs9 import wheel_nebular080_universal as builder  # noqa: E402
from rs9.errors import ContractError  # noqa: E402
from rs9.nebular080_universal_missing import MISSING_LINE  # noqa: E402
from rs9.scratch import canonical  # noqa: E402
from rs9.tf_pypi_archive import AdmissionError  # noqa: E402


SOURCE = {"commit": "a" * 40, "tree": "b" * 40}
RUN_ID = "123456"
RUN_ATTEMPT = "1"
WHEEL = {
    "filename": builder.FILENAME,
    "tag": consumer.TAG,
    "version": builder.VERSION,
    "size": 1,
    "sha256": "c" * 64,
}


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _process(*, stdout: bytes = b"", stderr: bytes = b"", exit_code: int = 0,
             path: tuple[str, str] | None = None) -> dict[str, object]:
    value: dict[str, object] = {
        "exit_code": exit_code,
        "signal": None,
        "stdout_sha256": _sha(stdout),
        "stderr_sha256": _sha(stderr),
        "duration_ms": 1,
        "timed_out": False,
        "output_limit_exceeded": False,
        "cleanup_known": True,
        "output_complete": True,
        "forced_cleanup": False,
    }
    if path is not None:
        value.update({"resolved_relative": path[0], "resolved_sha256": path[1]})
    return value


def _runtime_setup(target: str, spec: dict[str, object]) -> dict[str, object]:
    def stdout(downloaded: bool) -> bytes:
        body = {
            "schema": "theme-forge-nebular-fusion.runtime-install.v1",
            "version": builder.VERSION,
            "target": target,
            "archive_sha256": spec["asset"]["sha256"],
            "archive_bytes": spec["asset"]["size"],
            "manifest_sha256": spec["manifest_sha256"],
            "downloaded": downloaded,
            "redirect_hosts": ["release-assets.githubusercontent.com"] if downloaded else [],
        }
        return (json.dumps(body, sort_keys=True) + "\n").encode()

    return {
        "schema": profile.SCHEMAS["runtime_setup"],
        "status": "passed",
        "target": target,
        "archive_sha256": spec["asset"]["sha256"],
        "archive_bytes": spec["asset"]["size"],
        "manifest_sha256": spec["manifest_sha256"],
        "cold_refusal": _process(stderr=MISSING_LINE.encode(), exit_code=1),
        "explicit_setup": _process(stdout=stdout(True)),
        "offline_reuse": _process(stdout=stdout(False)),
        "archive_unchanged": True,
        "publication_admitted": False,
    }


def _scenario(target: str, index: int) -> tuple[dict, dict]:
    manifest_sha = f"{index + 10:064x}"
    spec = {
        "asset": {"size": 32, "sha256": f"{index:064x}"},
        "manifest_sha256": manifest_sha,
    }
    capture = {
        "payload_sha256": spec["asset"]["sha256"],
        "manifest_sha256": manifest_sha,
        "manifest_record_sha256": f"{index + 20:064x}",
        "native_package_record_sha256": f"{index + 30:064x}",
        "release_record_sha256": f"{index + 40:064x}",
        "provenance_sha256": f"{index + 50:064x}",
        "gui": {"sha256": f"{index + 60:064x}", "materialized_path": "bin/gui"},
    }
    snapshot = {
        "wheel": dict(WHEEL),
        "runtime_inputs_sha256": "d" * 64,
        "runtime_index_sha256": "e" * 64,
        "runtime_inputs": {"targets": {target: spec}},
    }
    return snapshot, capture


def _real_state(target: str, phase: str, digest: str = "a" * 64) -> dict[str, object]:
    return {
        "schema": "nebular.native-rc-persistent-user-state-v1",
        "method": "native-rc-smoke.persistentStateLocations+snapshotLocations",
        "scope": "real-user-state",
        "target": target,
        "phase": phase,
        "locations": 1,
        "snapshot_sha256": digest,
        "changed": [],
        "unchanged": True,
    }


def _receipt(snapshot: dict, capture: dict, target: str, role: str) -> dict:
    probe = {"controlled_leaf": True}
    path = (
        ".cache/rs9/theme-forge-nebular-fusion/entries/"
        + capture["manifest_sha256"] + "/payload/" + capture["gui"]["materialized_path"]
    )
    if target == "darwin-arm64":
        host_identity = {
            "source": "runner",
            "system": consumer_core.NEBULAR080_TARGET_SYSTEMS[target],
            "machine": "arm64",
        }
        host_observation = None
        host_extras = None
    else:
        machine = "x86_64" if target == "linux-x64-gnu" else "aarch64"
        host_identity = {
            "source": "runner",
            "system": consumer_core.NEBULAR080_TARGET_SYSTEMS[target],
            "machine": machine,
        }
        host_observation = {"role": role, "identity": "h" * 64}
        host_extras = {"target": target}
    unsigned = {
        "schema": profile.SCHEMAS["consumer"],
        "distribution": consumer.DISTRIBUTION,
        "status": "passed",
        "target": target,
        "consumer_host_role": role,
        "source": dict(SOURCE),
        "run": {"id": RUN_ID, "attempt": RUN_ATTEMPT},
        "python_version": {"major": 3, "minor": 11},
        "wheel": dict(snapshot["wheel"]),
        "runtime_inputs_sha256": snapshot["runtime_inputs_sha256"],
        "runtime_index_sha256": snapshot["runtime_index_sha256"],
        "payload_sha256": capture["payload_sha256"],
        "manifest_sha256": capture["manifest_sha256"],
        "manifest_record_sha256": capture["manifest_record_sha256"],
        "native_package_record_sha256": capture["native_package_record_sha256"],
        "release_record_sha256": capture["release_record_sha256"],
        "provenance_sha256": capture["provenance_sha256"],
        "host_identity": host_identity,
        "host_observation": host_observation,
        "host_extras": host_extras,
        "gui": dict(capture["gui"]),
        "sandbox": {"network_disabled": True, "method": "explicit-isolation-prefix"},
        "process_observer": {"orphan_count": 0, "after": {"orphan_count": 0}},
        "user_state": {
            "unchanged": True,
            "scratch": {
                "before": consumer._empty_scratch_state(),
                "after": consumer._empty_scratch_state(),
                "unchanged": True,
                "observation": "not-observed",
            },
            "real_user_state": {
                "unchanged": True,
                "before": _real_state(target, "before"),
                "after": _real_state(target, "after"),
            },
        },
        "probes": {
            "version": _process(stdout=b"theme-forge-nebular-fusion 0.8.0\n"),
            "path": _process(path=(path, capture["gui"]["sha256"])),
            "native": probe,
        },
        "cleanup": {"pip_uninstall_exit": 0, "orphan_processes": 0},
        "application_smoke": {"native_probe": probe},
        "runtime_setup": _runtime_setup(target, snapshot["runtime_inputs"]["targets"][target]),
        "native_qualified": True,
        "fixture_only": False,
        "publication_admitted": False,
        "public_writes": 0,
    }
    return {**unsigned, "identity": _sha(canonical(unsigned))}


@contextmanager
def _controlled_leafs():
    def smoke(value, **_kwargs):
        return {"native_probe": value["native_probe"]}

    def observation(value):
        return dict(value)

    with (
        patch.object(installed_smoke, "validate_installed_smoke_summary", side_effect=smoke),
        patch.object(installed_smoke, "validate_system_webkit_preflight", return_value=None),
        patch.object(consumer, "_require_darwin_receipt_boundary", return_value=None),
        patch("rs9.nebular080_host_observation.validate_observation_body", side_effect=observation),
        patch("rs9.nebular080_host_observation._validate_extras", return_value=None),
    ):
        yield


class ControlledUniversalReceiptIdentityTests(unittest.TestCase):
    def test_consumer_validator_accepts_new_digest_fields_and_marker(self) -> None:
        snapshot, capture = _scenario("linux-x64-gnu", 1)
        receipt = _receipt(snapshot, capture, "linux-x64-gnu", "newer")
        with _controlled_leafs():
            result = consumer.validate_universal_consumer(
                receipt, snapshot, capture, target="linux-x64-gnu", role="newer",
                source=SOURCE, run_id=RUN_ID, run_attempt=RUN_ATTEMPT,
            )
        self.assertEqual(result["manifest_record_sha256"], capture["manifest_record_sha256"])
        self.assertEqual(result["native_package_record_sha256"], capture["native_package_record_sha256"])
        self.assertNotEqual(result["manifest_record_sha256"], result["native_package_record_sha256"])
        self.assertEqual(result["user_state"]["scratch"]["observation"], "not-observed")

    def test_digest_fields_are_required_and_capture_bound_even_when_resigned(self) -> None:
        snapshot, capture = _scenario("linux-x64-gnu", 1)
        baseline = _receipt(snapshot, capture, "linux-x64-gnu", "newer")
        with _controlled_leafs():
            for field in ("manifest_record_sha256", "native_package_record_sha256"):
                missing = copy.deepcopy(baseline)
                missing.pop(field)
                with self.subTest(missing=field), self.assertRaises(ContractError):
                    consumer.validate_universal_consumer(
                        missing, snapshot, capture, target="linux-x64-gnu", role="newer",
                        source=SOURCE, run_id=RUN_ID, run_attempt=RUN_ATTEMPT,
                    )
            for field in ("manifest_record_sha256", "native_package_record_sha256"):
                changed = copy.deepcopy(baseline)
                changed[field] = "f" * 64
                unsigned = dict(changed)
                unsigned.pop("identity")
                changed["identity"] = _sha(canonical(unsigned))
                with self.subTest(field=field), self.assertRaises(ContractError):
                    consumer.validate_universal_consumer(
                        changed, snapshot, capture, target="linux-x64-gnu", role="newer",
                        source=SOURCE, run_id=RUN_ID, run_attempt=RUN_ATTEMPT,
                    )

    def test_scratch_marker_and_real_user_state_remain_closed(self) -> None:
        snapshot, capture = _scenario("linux-x64-gnu", 1)
        baseline = _receipt(snapshot, capture, "linux-x64-gnu", "newer")
        mutations = {}
        missing_marker = copy.deepcopy(baseline)
        missing_marker["user_state"]["scratch"].pop("observation")
        mutations["missing-marker"] = missing_marker
        wrong_marker = copy.deepcopy(baseline)
        wrong_marker["user_state"]["scratch"]["observation"] = "observed"
        mutations["wrong-marker"] = wrong_marker
        changed_frame = copy.deepcopy(baseline)
        changed_frame["user_state"]["scratch"]["after"]["entry_count"] = 1
        mutations["changed-scratch-frame"] = changed_frame
        false_unchanged = copy.deepcopy(baseline)
        false_unchanged["user_state"]["unchanged"] = False
        mutations["false-unchanged"] = false_unchanged
        extra_key = copy.deepcopy(baseline)
        extra_key["user_state"]["scratch"]["extra"] = True
        mutations["extra-scratch-key"] = extra_key
        changed_real = copy.deepcopy(baseline)
        changed_real["user_state"]["real_user_state"]["after"]["changed"] = ["x"]
        mutations["changed-real-state"] = changed_real
        mismatched_real_digest = copy.deepcopy(baseline)
        mismatched_real_digest["user_state"]["real_user_state"]["after"]["snapshot_sha256"] = "b" * 64
        mutations["real-digest-mismatch"] = mismatched_real_digest
        empty_locations = copy.deepcopy(baseline)
        empty_locations["user_state"]["real_user_state"]["before"]["locations"] = 0
        mutations["empty-real-locations"] = empty_locations
        with _controlled_leafs():
            for name, value in mutations.items():
                unsigned = dict(value)
                unsigned.pop("identity")
                value["identity"] = _sha(canonical(unsigned))
                with self.subTest(name=name), self.assertRaises((ContractError, AdmissionError)):
                    consumer.validate_universal_consumer(
                        value, snapshot, capture, target="linux-x64-gnu", role="newer",
                        source=SOURCE, run_id=RUN_ID, run_attempt=RUN_ATTEMPT,
                    )

    def test_core_network_denial_and_empty_snapshot_projection_are_real(self) -> None:
        python = SimpleNamespace(stdout=b'{"1.1.1.1": 1, "registry.npmjs.org": 2}')
        node = SimpleNamespace(stdout=b"EPERM\nENOTFOUND\n")
        with patch.object(consumer_core, "_success", side_effect=[python, node]):
            result = consumer_core.network_denial(
                "python3", "node", {}, prefix=("unshare", "--net")
            )
        self.assertEqual(result["method"], "explicit-isolation-prefix")
        self.assertEqual(result["python_tcp_errno"], 1)
        self.assertEqual(result["python_dns_errno"], 2)
        self.assertEqual(set(result), {
            "method", "python_tcp_errno", "python_dns_errno", "node_denials", "network_disabled",
        })
        projected = {key: value for key, value in result.items()
                     if key in {"network_disabled", "method", "proof_sha256"}}
        self.assertEqual(projected, {
            "network_disabled": True, "method": "explicit-isolation-prefix",
        })
        with tempfile.TemporaryDirectory(prefix="nebular080-empty-") as home:
            observed = consumer_core._nebular_state_snapshot(Path(home), [])
        self.assertEqual(observed, consumer._empty_scratch_state())

    def test_controlled_producer_projects_only_the_exact_core_scratch_frame(self) -> None:
        target = "darwin-arm64"
        snapshot, capture = _scenario(target, 1)
        baseline = _receipt(snapshot, capture, target, "newer")

        def produce(scratch):
            installed = {key: copy.deepcopy(baseline[key]) for key in (
                "python_version", "sandbox", "process_observer", "user_state", "probes",
                "cleanup", "application_smoke", "runtime_setup")}
            installed["user_state"]["scratch"] = scratch
            environment = {
                "GITHUB_ACTIONS": "true", "GITHUB_REPOSITORY": "Knowledge-Forge-AI/release-starport-9",
                "GITHUB_REF": "refs/heads/main", "GITHUB_RUN_ID": RUN_ID,
                "GITHUB_RUN_ATTEMPT": RUN_ATTEMPT, "GITHUB_SHA": SOURCE["commit"],
            }
            with (
                _controlled_leafs(), patch.dict("os.environ", environment, clear=True),
                patch("rs9.tf_pypi_nebular080_publish._git_output", side_effect=list(SOURCE.values())),
                patch.object(builder, "_read", return_value=(b"controlled-wheel", ())),
                patch.object(consumer, "inspect_universal_wheel", return_value=snapshot),
                patch.object(consumer, "capture_universal_runtime", return_value=capture),
                patch.object(consumer_core, "_nebular_identity_observed", return_value=baseline["host_identity"]),
                patch.object(consumer_core, "_nebular_installed_consumer", return_value=installed),
                patch("rs9.tf_pypi_nebular080_publish.default_sandbox_prefix", return_value=("deny",)),
                patch("rs9.tf_pypi_nebular080_publish.make_real_user_state_snapshotter", return_value=object()),
            ):
                return consumer.consume_universal_wheel(
                    Path(builder.FILENAME), b"controlled-inputs", b"controlled-description",
                    {"root": "."}, Path("unused-controlled-work"), target=target,
                    source=SOURCE, run_id=RUN_ID, run_attempt=RUN_ATTEMPT, repository=Path("."))

        exact = {"before": consumer._empty_scratch_state(),
                 "after": consumer._empty_scratch_state(), "unchanged": True}
        self.assertEqual(produce(copy.deepcopy(exact))["user_state"]["scratch"], {
            **exact, "observation": "not-observed",
        })
        variants = [
            {**copy.deepcopy(exact), "extra": True},
            {**copy.deepcopy(exact), "observation": "not-observed"},
            {**copy.deepcopy(exact), "unchanged": False},
            {"before": consumer._empty_scratch_state(), "unchanged": True},
        ]
        changed = copy.deepcopy(exact)
        changed["before"]["entry_count"] = 1
        variants.append(changed)
        changed = copy.deepcopy(exact)
        changed["after"]["sha256"] = "f" * 64
        variants.append(changed)
        for index, scratch in enumerate(variants):
            with self.subTest(variant=index):
                with self.assertRaises(ContractError) as refused:
                    produce(scratch)
                self.assertEqual(refused.exception.code, "NEBULAR_UNIVERSAL_USER_STATE")

    def test_matrix_calls_real_consumer_validator_for_all_five_controlled_lanes(self) -> None:
        snapshot = {
            "wheel": dict(WHEEL),
            "runtime_inputs_sha256": "d" * 64,
            "runtime_index_sha256": "e" * 64,
            "runtime_inputs": {"targets": {}},
        }
        captures, positives = {}, {}
        for index, target in enumerate(builder.LAYOUTS, 1):
            target_snapshot, capture = _scenario(target, index)
            snapshot["runtime_inputs"]["targets"][target] = target_snapshot["runtime_inputs"]["targets"][target]
            captures[target] = capture
            for role in ("newer", "floor") if target in profile.LINUX_TARGETS else ("newer",):
                positives[target, role] = _receipt(snapshot, capture, target, role)
        negatives = {target: {"controlled": True} for target in profile.LINUX_TARGETS}

        with _controlled_leafs(), patch(
            "rs9.nebular080_universal_missing.validate_missing_runtime",
            return_value={"identity": "m" * 64, "python_version": {"major": 3, "minor": 11}},
        ):
            matrix = universal.validate_matrix_receipts(
                snapshot, captures, positives, negatives,
                source=SOURCE, run_id=RUN_ID, run_attempt=RUN_ATTEMPT,
            )
        self.assertEqual(len(matrix["lanes"]), 5)
        self.assertTrue(all("consumer_identity" in row for row in matrix["lanes"]))

        changed = copy.deepcopy(positives["linux-x64-gnu", "newer"])
        changed["user_state"]["scratch"]["observation"] = "observed"
        unsigned = dict(changed)
        unsigned.pop("identity")
        changed["identity"] = _sha(canonical(unsigned))
        positives["linux-x64-gnu", "newer"] = changed
        with _controlled_leafs(), patch(
            "rs9.nebular080_universal_missing.validate_missing_runtime",
            return_value={"identity": "m" * 64, "python_version": {"major": 3, "minor": 11}},
        ), self.assertRaises(ContractError):
            universal.validate_matrix_receipts(
                snapshot, captures, positives, negatives,
                source=SOURCE, run_id=RUN_ID, run_attempt=RUN_ATTEMPT,
            )


if __name__ == "__main__":
    unittest.main()
