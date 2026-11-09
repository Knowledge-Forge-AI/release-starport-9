"""Connected tests for raw manifest bytes versus semantic member identity."""
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
        {
            "path": f"{ROOT_NAME}/bin/theme-forge-nebular-fusion",
            "type": "file",
            "mode": 0o755,
            "size": 6,
            "sha256": binary_sha,
        },
        {
            "path": f"{ROOT_NAME}/bin/tfnf",
            "type": "file",
            "mode": 0o755,
            "size": 6,
            "sha256": binary_sha,
        },
        {
            "path": f"{ROOT_NAME}/bin/tfsb-studio-service",
            "type": "file",
            "mode": 0o755,
            "size": 6,
            "sha256": binary_sha,
        },
    ]


def _manifest(members: list[dict[str, object]], *, root: str = ROOT_NAME) -> dict[str, object]:
    _normalized, parsed_root, digest = parse_manifest_members({"members": members})
    assert parsed_root == ROOT_NAME
    return {
        "commands": {},
        "root": root,
        "members": members,
        "manifest_sha256": digest,
    }


def _descriptor(path: Path, *, digest: str | None = None) -> dict[str, object]:
    data = path.read_bytes()
    return {"path": path.name, "size": len(data), "sha256": digest or _sha(data)}


def _record(asset: dict[str, object]) -> dict[str, object]:
    return {
        "schema": "rs9.release-record.v1alpha1",
        "repository": {"full_name": RELEASE["repository"]},
        "release": {
            "id": 17,
            "tag": RELEASE["tag"],
            "draft": False,
            "prerelease": False,
        },
        "tag": {"commit": RELEASE["commit"], "tree": RELEASE["tree"]},
        "assets": [{
            "github_asset_id": asset["id"],
            "role": "payload",
            "checksum_covered": True,
            "name": asset["name"],
            "sha256": asset["sha256"],
            "size": asset["size"],
        }],
    }


def _provenance(asset: dict[str, object]) -> dict[str, object]:
    return {
        "schema": "nebular.public-native-ci-release-provenance.v1",
        "repository": RELEASE["repository"],
        "version": "0.8.0",
        "releaseCommit": RELEASE["commit"],
        "testedTree": RELEASE["tree"],
        "release": 17,
        "assets": [{
            "id": asset["id"],
            "role": "raw-archive",
            "unauthenticatedReadback": True,
            "httpStatus": 200,
            "bytes": asset["size"],
            "name": asset["name"],
            "sha256": asset["sha256"],
            "url": "https://example.invalid/payload.tgz",
        }],
    }


def _case(root: Path, manifest_bytes: bytes, *, manifest_digest: str | None = None,
          native_consumer: bool = False) -> tuple[dict, dict, str]:
    payload_path = root / "payload.tgz"
    manifest_path = root / "manifest.json"
    record_path = root / "record.json"
    provenance_path = root / "provenance.json"
    payload_path.write_bytes(PAYLOAD)
    manifest_path.write_bytes(manifest_bytes)
    asset = {
        "id": 17,
        "name": payload_path.name,
        "size": len(PAYLOAD),
        "sha256": _sha(PAYLOAD),
        "url": "https://example.invalid/payload.tgz",
    }
    record_path.write_bytes(canonical(_record(asset)))
    provenance_path.write_bytes(canonical(_provenance(asset)))
    manifest_value = json.loads(manifest_bytes)
    _members_value, parsed_root, semantic_digest = parse_manifest_members(manifest_value)
    spec = {
        "asset": asset,
        "manifest_sha256": semantic_digest,
        "root": ROOT_NAME,
        "shell_target": f"{ROOT_NAME}/bin/tfnf",
        "gui_target": f"{ROOT_NAME}/bin/theme-forge-nebular-fusion",
    }
    snapshot = {
        "runtime_inputs": {
            "targets": {TARGET: spec},
            "upstream_release": RELEASE,
            "product_native_reference": {},
        },
        "manifests": {TARGET: _manifest(_members_value, root=parsed_root)},
    }
    raw_target = {
        "payload": _descriptor(payload_path),
        "manifest": _descriptor(manifest_path, digest=manifest_digest),
        "record": _descriptor(record_path),
        "provenance": _descriptor(provenance_path),
    }
    if native_consumer:
        raw_target["native_consumer"] = {TARGET: {"smoke_support": {}}}
    return snapshot, raw_target, semantic_digest


class ManifestIdentityDomainTests(unittest.TestCase):
    def _capture(self, snapshot: dict, raw_target: dict, root: Path) -> ContractError:
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
                    snapshot,
                    root,
                    raw_target,
                    target=TARGET,
                    product_capture=SimpleNamespace(record=release_record),
                    native_admission=None,
                )
        return raised.exception

    def test_formatting_difference_uses_semantic_digest_and_reaches_next_gate(self) -> None:
        members = _members()
        manifest = _manifest(members)
        raw = (json.dumps(manifest, indent=2) + "\n").encode("utf-8")
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            snapshot, raw_target, semantic_digest = _case(root, raw, native_consumer=False)
            error = self._capture(snapshot, raw_target, root)
        self.assertEqual(error.code, "NEBULAR_UNIVERSAL_NATIVE_CONTRACT")
        self.assertEqual(snapshot["runtime_inputs"]["targets"][TARGET]["manifest_sha256"], semantic_digest)

    def test_static_boundary_receives_semantic_digest_not_raw_descriptor_digest(self) -> None:
        members = _members()
        manifest = _manifest(members)
        raw = (json.dumps(manifest, indent=2) + "\n").encode("utf-8")

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            snapshot, raw_target, semantic_digest = _case(root, raw, native_consumer=True)
            raw_record_digest = raw_target["manifest"]["sha256"]
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
                mock.patch.object(consumer_core, "_nebular_payload_member", return_value=b"binary"),
            ):
                with mock.patch(
                    "rs9.nebular080_smoke_support.validate_smoke_support",
                    return_value={},
                ):
                    capture = consumer.capture_universal_runtime(
                        snapshot,
                        root,
                        raw_target,
                        target=TARGET,
                        product_capture=SimpleNamespace(record=release_record),
                        native_admission=None,
                    )
        self.assertEqual(capture["manifest_sha256"], semantic_digest)
        self.assertEqual(capture["manifest_record_sha256"], raw_record_digest)
        self.assertEqual(capture["native_package_record_sha256"], raw_target["record"]["sha256"])
        self.assertEqual(capture["release_record_sha256"], _sha(canonical(release_record)))
        self.assertIsNone(capture["system_static_input"])
        self.assertIsNone(capture["native_evidence"])
        self.assertEqual(capture["native"]["command"], "tfnf")
        self.assertEqual(capture["native"]["scenario"], "C")
        self.assertEqual(capture["native"]["argv"], ["--nebular-release-smoke=C"])
        self.assertEqual(capture["native"]["timeout_seconds"], 60)
        self.assertEqual(capture["native"]["state_paths"], [])

    def test_changed_member_digest_and_root_are_rejected(self) -> None:
        members = _members()
        changed = [dict(item) for item in members]
        changed[-1]["sha256"] = "f" * 64
        cases = (
            _manifest(changed),
            _manifest(members, root="wrong-root"),
        )
        unknown = _manifest(members)
        unknown["unexpected"] = True
        cases += (unknown,)
        for manifest in cases:
            with self.subTest(root=manifest["root"], digest=manifest["manifest_sha256"]):
                raw = (json.dumps(manifest, indent=2) + "\n").encode("utf-8")
                with tempfile.TemporaryDirectory() as temporary:
                    root = Path(temporary)
                    snapshot, raw_target, _semantic_digest = _case(root, raw)
                    baseline = _manifest(members)
                    snapshot["manifests"][TARGET] = baseline
                    snapshot["runtime_inputs"]["targets"][TARGET]["manifest_sha256"] = baseline[
                        "manifest_sha256"
                    ]
                    error = self._capture(snapshot, raw_target, root)
                self.assertEqual(error.code, "NEBULAR_UNIVERSAL_MANIFEST")

    def test_raw_manifest_descriptor_sha_guard_remains_required(self) -> None:
        manifest = _manifest(_members())
        raw = (json.dumps(manifest, indent=2) + "\n").encode("utf-8")
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            snapshot, raw_target, _semantic_digest = _case(
                root,
                raw,
                manifest_digest="0" * 64,
            )
            asset = snapshot["runtime_inputs"]["targets"][TARGET]["asset"]
            release_record = _record(asset)
            with (
                mock.patch.object(
                    consumer,
                    "authenticated_product_source",
                    return_value={"record_sha256": _sha(canonical(release_record))},
                ),
                mock.patch.object(consumer, "join_product_native_release", return_value={}),
            ):
                with self.assertRaises(AdmissionError) as raised:
                    consumer.capture_universal_runtime(
                        snapshot,
                        root,
                        raw_target,
                        target=TARGET,
                        product_capture=SimpleNamespace(record=release_record),
                        native_admission=None,
                    )
        self.assertEqual(str(raised.exception), "TF_PYPI_NEBULAR_CAPTURE_BINDING")


if __name__ == "__main__":
    unittest.main()
