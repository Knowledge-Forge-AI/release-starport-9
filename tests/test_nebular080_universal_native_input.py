"""Controlled-unit tests for the proposed universal native-input boundary."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest
from types import SimpleNamespace
from unittest import mock


REPOSITORY = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPOSITORY / "src"))

from rs9 import nebular080_consumer_core as consumer_core  # noqa: E402
from rs9 import nebular080_installed_smoke as installed_smoke  # noqa: E402
from rs9 import nebular080_universal_consumer as consumer  # noqa: E402
from rs9.errors import ContractError  # noqa: E402
from rs9.scratch import canonical  # noqa: E402
from rs9.tf_pypi_archive import AdmissionError  # noqa: E402
from rs9.materialize import parse_manifest_members  # noqa: E402


TARGET = "linux-x64-gnu"
ROOT_NAME = "theme-forge-nebular-fusion"
RELEASE = {
    "repository": "Knowledge-Forge-AI/theme-forge-nebular-fusion",
    "tag": "v0.8.0",
    "commit": "a" * 40,
    "tree": "b" * 40,
}
PAYLOAD = b"payload-bytes"


def _sha(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _members() -> list[dict[str, object]]:
    binary_sha = _sha(b"binary")
    return [
        {"path": ROOT_NAME, "type": "directory", "mode": 0o755},
        {"path": f"{ROOT_NAME}/bin", "type": "directory", "mode": 0o755},
        {"path": f"{ROOT_NAME}/bin/theme-forge-nebular-fusion", "type": "file",
         "mode": 0o755, "size": 6, "sha256": binary_sha},
        {"path": f"{ROOT_NAME}/bin/tfnf", "type": "file",
         "mode": 0o755, "size": 6, "sha256": binary_sha},
        {"path": f"{ROOT_NAME}/bin/tfsb-studio-service", "type": "file",
         "mode": 0o755, "size": 6, "sha256": binary_sha},
    ]


def _manifest() -> dict[str, object]:
    members = _members()
    _normalized, root, digest = parse_manifest_members({"members": members})
    return {"commands": {}, "root": root, "members": members, "manifest_sha256": digest}


def _record(asset: dict[str, object]) -> dict[str, object]:
    return {
        "schema": "rs9.release-record.v1alpha1",
        "repository": {"full_name": RELEASE["repository"]},
        "release": {"id": 17, "tag": RELEASE["tag"], "draft": False, "prerelease": False},
        "tag": {"commit": RELEASE["commit"], "tree": RELEASE["tree"]},
        "assets": [{
            "github_asset_id": asset["id"], "role": "payload", "checksum_covered": True,
            "name": asset["name"], "sha256": asset["sha256"], "size": asset["size"],
        }],
    }


def _provenance(asset: dict[str, object]) -> dict[str, object]:
    return {
        "schema": "nebular.public-native-ci-release-provenance.v1",
        "repository": RELEASE["repository"], "version": "0.8.0",
        "releaseCommit": RELEASE["commit"], "testedTree": RELEASE["tree"], "release": 17,
        "assets": [{
            "id": asset["id"], "role": "raw-archive", "unauthenticatedReadback": True,
            "httpStatus": 200, "bytes": asset["size"], "name": asset["name"],
            "sha256": asset["sha256"], "url": "https://example.invalid/payload.tgz",
        }],
    }


def _case(root: Path, native_rows: dict[str, object]) -> tuple[dict, dict]:
    manifest = _manifest()
    manifest_bytes = (json.dumps(manifest, indent=2) + "\n").encode("utf-8")
    payload_path = root / "payload.tgz"
    manifest_path = root / "manifest.json"
    record_path = root / "record.json"
    provenance_path = root / "provenance.json"
    payload_path.write_bytes(PAYLOAD)
    manifest_path.write_bytes(manifest_bytes)
    asset = {"id": 17, "name": payload_path.name, "size": len(PAYLOAD),
             "sha256": _sha(PAYLOAD), "url": "https://example.invalid/payload.tgz"}
    record_path.write_bytes(canonical(_record(asset)))
    provenance_path.write_bytes(canonical(_provenance(asset)))
    _members_value, parsed_root, semantic_digest = parse_manifest_members(manifest)
    spec = {
        "asset": asset, "manifest_sha256": semantic_digest, "root": ROOT_NAME,
        "shell_target": f"{ROOT_NAME}/bin/tfnf",
        "gui_target": f"{ROOT_NAME}/bin/theme-forge-nebular-fusion",
    }
    snapshot = {
        "runtime_inputs": {
            "targets": {TARGET: spec}, "upstream_release": RELEASE,
            "product_native_reference": {},
        },
        "manifests": {TARGET: {**_manifest(), "root": parsed_root}},
    }
    descriptor = lambda path: {"path": path.name, "size": path.stat().st_size,
                                "sha256": _sha(path.read_bytes())}
    raw_target = {
        "payload": descriptor(payload_path), "manifest": descriptor(manifest_path),
        "record": descriptor(record_path), "provenance": descriptor(provenance_path),
        "native_consumer": native_rows,
    }
    return snapshot, raw_target


class UniversalNativeInputTests(unittest.TestCase):
    def _capture_error(self, snapshot: dict, raw_target: dict, root: Path, *, target: str = TARGET):
        asset = snapshot["runtime_inputs"]["targets"][TARGET]["asset"]
        release_record = _record(asset)
        with (
            mock.patch.object(
                consumer,
                "authenticated_product_source",
                return_value={"record_sha256": _sha(canonical(release_record))},
            ),
            mock.patch.object(consumer, "join_product_native_release", return_value={}),
            mock.patch.object(
                consumer,
                "_native_package_record",
                return_value={"raw": {"executableSha256": _sha(b"binary")}},
            ),
        ):
            with self.assertRaises(ContractError) as raised:
                consumer.capture_universal_runtime(
                    snapshot, root, raw_target, target=target,
                    product_capture=SimpleNamespace(record=release_record),
                    native_admission=None,
                )
        return raised.exception

    def test_unknown_and_result_bearing_native_inputs_are_rejected(self) -> None:
        variants = (
            {TARGET: {"smoke_support": {}, "qualification": {}}},
            {TARGET: {"smoke_support": {}}, "darwin-arm64": {"smoke_support": {}}},
        )
        for native_rows in variants:
            with self.subTest(native_rows=native_rows):
                with tempfile.TemporaryDirectory() as temporary:
                    root = Path(temporary)
                    snapshot, raw_target = _case(root, native_rows)
                    error = self._capture_error(snapshot, raw_target, root)
                self.assertEqual(error.code, "NEBULAR_UNIVERSAL_NATIVE_CONTRACT")

    def test_invalid_support_is_rejected_before_invocation_derivation(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            snapshot, raw_target = _case(root, {TARGET: {"smoke_support": {}}})
            with mock.patch(
                "rs9.nebular080_smoke_support.validate_smoke_support",
                side_effect=ContractError("INVALID_SUPPORT", "controlled invalid support"),
            ):
                error = self._capture_error(snapshot, raw_target, root)
        self.assertEqual(error.code, "NEBULAR_UNIVERSAL_NATIVE_CONTRACT")

    def test_wrong_target_is_rejected_without_using_native_rows(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            snapshot, raw_target = _case(root, {TARGET: {"smoke_support": {}}})
            error = self._capture_error(snapshot, raw_target, root, target="linux-x64-gnu-wrong")
        self.assertEqual(error.code, "NEBULAR_UNIVERSAL_TARGET")

    def test_missing_darwin_installed_harness_still_refuses_null_legacy_slots(self) -> None:
        capture = {
            "native": {"smoke_support": {}},
            "system_static_input": None,
            "native_evidence": None,
        }
        with self.assertRaises(ContractError) as raised:
            consumer._require_darwin_receipt_boundary({"native_probe": {}}, capture)
        self.assertEqual(raised.exception.code, "NEBULAR_UNIVERSAL_DARWIN_HARNESS")

    def test_linux_preflight_rejects_missing_or_mismatched_input_with_null_legacy_slots(self) -> None:
        capture = {
            "system_static_input": None,
            "native_evidence": None,
        }
        self.assertIsNone(capture["system_static_input"])
        self.assertIsNone(capture["native_evidence"])
        for value in (None, {"schema": installed_smoke.UNIVERSAL_WEBKIT_PREFLIGHT_SCHEMA}):
            with self.subTest(value=value), self.assertRaises(AdmissionError) as raised:
                installed_smoke.validate_system_webkit_preflight(
                    value, target=TARGET, distribution="universal-launcher",
                )
            self.assertEqual(raised.exception.code, "TF_PYPI_NEBULAR_SYSTEM_WEBKIT_PREFLIGHT")


if __name__ == "__main__":
    unittest.main()
