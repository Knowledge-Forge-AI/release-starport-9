"""Portable NativeRC evidence validators for the public Nebular 0.8 layout.

This overlay intentionally exercises only the public ``src`` package and the
small published NativeRC relay.  It does not construct a ``ReleaseCapture``,
read a product payload, or mint a native admission capability.  Those joins
remain separate tests because they require the three large product archives
and the authenticated product-source owner.
"""
from __future__ import annotations

import copy
from datetime import datetime, timedelta, timezone
import hashlib
import io
import json
from pathlib import Path
import sys
import tarfile
import unittest


REPO_ROOT = Path(__file__).resolve().parents[1]
FIXTURE_ROOT = Path(__file__).resolve().parent / "fixtures"
ARCHIVE_NAME = (
    "nebular-v0.8.0-native-evidence-run-42418673472-attempt-1.tar.gz"
)
INVENTORY_NAME = ARCHIVE_NAME.removesuffix(".tar.gz") + "-inventory.json"
ARCHIVE_SHA256 = "20f5aaf0dacad5437185981ab95448fb2f13f26001b19ac31fd83ac324795640"
ARCHIVE_BYTES = 216591
INVENTORY_SHA256 = "89067774cbdf7b4ce931e3df6b08029bdee97873b8083460fd5b249ee4f5ec72"
INVENTORY_BYTES = 17681
MEMBER_COUNT = 68
SOURCE_BYTES = 1514913
TESTED_COMMIT = "516f5a7d8a449946a0246ea23d37991f586dfc2c"
TESTED_TREE = "907163a09d2995c9080074294db54c54af626563"

sys.path.insert(0, str(REPO_ROOT / "src"))

from rs9 import nebular080_product_native as native  # noqa: E402
from rs9.errors import ContractError  # noqa: E402


class PortableProductNative080Tests(unittest.TestCase):
    """Run the evidence-owner validators without private preparation paths."""

    @classmethod
    def setUpClass(cls):
        archive_path = FIXTURE_ROOT / ARCHIVE_NAME
        inventory_path = FIXTURE_ROOT / INVENTORY_NAME
        cls.archive_bytes = archive_path.read_bytes()
        cls.inventory_bytes = inventory_path.read_bytes()
        cls.inventory = json.loads(cls.inventory_bytes)
        cls.members = cls._read_relay(cls.archive_bytes, cls.inventory)
        cls.api = {
            name: json.loads(cls.members["api/" + name])
            for name in ("run.json", "jobs.json", "compiler-commit.json", "artifacts.json")
        }
        cls.source_ci = json.loads(cls.members["api/source-run.json"])
        cls.evidence_bodies = {
            row["path"]: cls.members[row["path"]]
            for row in cls.inventory["files"]
            if row["role"] == "native-evidence-body"
        }
        cls.index_bytes = cls.members["rc-index-original.zip"]
        cls.expiry_bounds = cls._expiry_bounds(cls.api, cls.members["rc-index-original.zip"])

    @staticmethod
    def _sha(body: bytes) -> str:
        return hashlib.sha256(body).hexdigest()

    @classmethod
    def _read_relay(cls, archive_bytes: bytes, inventory: dict) -> dict[str, bytes]:
        """Verify the published 68-row relay before any validator consumes it."""
        if len(archive_bytes) != ARCHIVE_BYTES or cls._sha(archive_bytes) != ARCHIVE_SHA256:
            raise AssertionError("relay archive bytes or digest changed")
        if (not isinstance(inventory, dict)
                or inventory.get("archive", {}).get("file_count") != MEMBER_COUNT):
            raise AssertionError("relay inventory count is not the published 68-row record")
        rows = inventory.get("files")
        if not isinstance(rows, list) or len(rows) != MEMBER_COUNT:
            raise AssertionError("relay inventory member rows are incomplete")

        expected: dict[str, dict] = {}
        for row in rows:
            if set(row) != {"bytes", "path", "role", "sha256"}:
                raise AssertionError("relay inventory row is not closed")
            path = row["path"]
            if (not isinstance(path, str) or not path or path.startswith("/")
                    or "\\" in path or any(part in {"", ".", ".."} for part in path.split("/"))):
                raise AssertionError("relay member path is unsafe")
            if path in expected:
                raise AssertionError("relay inventory contains a duplicate member")
            expected[path] = row

        result: dict[str, bytes] = {}
        with tarfile.open(fileobj=io.BytesIO(archive_bytes), mode="r:gz") as archive:
            infos = archive.getmembers()
            if len(infos) != MEMBER_COUNT:
                raise AssertionError("relay member count changed")
            for info in infos:
                path = info.name
                if path not in expected or path in result:
                    raise AssertionError("relay archive member set disagrees with inventory")
                if (not info.isfile() or info.issym() or info.islnk()
                        or info.mode != 0o644 or info.uid != 0 or info.gid != 0
                        or info.mtime != 0):
                    raise AssertionError("relay member metadata is not the fixed safe form")
                stream = archive.extractfile(info)
                if stream is None:
                    raise AssertionError("relay regular member has no readable body")
                body = stream.read()
                row = expected[path]
                if len(body) != row["bytes"] or cls._sha(body) != row["sha256"]:
                    raise AssertionError("relay member bytes disagree with inventory")
                result[path] = body
        if set(result) != set(expected):
            raise AssertionError("relay archive is missing an inventory member")
        if sum(len(body) for body in result.values()) != SOURCE_BYTES:
            raise AssertionError("relay expanded byte total changed")
        return result

    @staticmethod
    def _expiry_bounds(api: dict[str, dict], index_bytes: bytes) -> tuple[datetime, datetime]:
        artifact_expiry = [
            datetime.fromisoformat(row["expires_at"].replace("Z", "+00:00"))
            for row in api["artifacts.json"]["artifacts"]
        ]
        index = native.catalog_index(index_bytes, check_expiry=False)
        index_expiry = [
            datetime.fromisoformat(row["artifact"]["expiresAt"].replace("Z", "+00:00"))
            for row in index["lanes"]
        ]
        return min(artifact_expiry + index_expiry), max(artifact_expiry + index_expiry)

    def _validate_frame(self, *, now: datetime, check_expiry: bool) -> dict:
        return native.validate_native_evidence(
            run=self.api["run.json"], jobs=self.api["jobs.json"],
            compiler=self.api["compiler-commit.json"],
            artifacts=self.api["artifacts.json"], index_bytes=self.index_bytes,
            evidence_bodies=self.evidence_bodies,
            now=now, check_expiry=check_expiry,
        )

    def test_relay_inventory_and_public_reference_are_closed(self):
        self.assertEqual(len(self.archive_bytes), ARCHIVE_BYTES)
        self.assertEqual(self._sha(self.archive_bytes), ARCHIVE_SHA256)
        self.assertEqual(len(self.inventory_bytes), INVENTORY_BYTES)
        self.assertEqual(self._sha(self.inventory_bytes), INVENTORY_SHA256)
        self.assertEqual(self.inventory["archive"]["file_count"], MEMBER_COUNT)
        self.assertEqual(self.inventory["archive"]["sha256"], ARCHIVE_SHA256)
        self.assertEqual(self.inventory["bindings"]["native"]["tested_commit"], TESTED_COMMIT)
        self.assertEqual(self.inventory["bindings"]["native"]["tested_tree"], TESTED_TREE)
        self.assertEqual(self.inventory["producer"]["native_run"], 42418673472)
        self.assertEqual(self.inventory["producer"]["source_run"], 42418673471)
        self.assertEqual(native.validate_reference(json.loads(self.members["native-reference.json"])), native.reference())

    def test_public_source_validators_accept_unchanged_relay(self):
        before, _ = self.expiry_bounds
        frame = self._validate_frame(now=before - timedelta(seconds=1), check_expiry=True)
        native.validate_source_ci_run(self.source_ci)
        self.assertEqual(frame["tested_commit"], TESTED_COMMIT)
        self.assertEqual(frame["tested_tree"], TESTED_TREE)
        self.assertEqual(frame["lanes"], list(native.LANES))
        self.assertEqual(frame["release_join"], "held-until-authenticated-product-capture")

    def test_retained_expiry_clock_has_positive_and_negative_boundaries(self):
        earliest, latest = self.expiry_bounds
        self._validate_frame(now=earliest - timedelta(seconds=1), check_expiry=True)
        with self.assertRaises(ContractError):
            self._validate_frame(now=latest + timedelta(seconds=1), check_expiry=True)
        self._validate_frame(now=latest + timedelta(seconds=1), check_expiry=False)

    def test_api_index_and_body_mutations_fail_closed(self):
        bad_api = copy.deepcopy(self.api)
        bad_api["compiler-commit.json"]["tree"]["sha"] = "0" * 40
        with self.assertRaises(ContractError):
            native.validate_api_snapshots(
                bad_api["run.json"], bad_api["jobs.json"],
                bad_api["compiler-commit.json"], bad_api["artifacts.json"],
                check_expiry=False,
            )

        bad_bodies = dict(self.evidence_bodies)
        key = "linux-x64/rc-evidence.json"
        changed = bytearray(bad_bodies[key])
        changed[-1] ^= 1
        bad_bodies[key] = bytes(changed)
        with self.assertRaises(ContractError):
            native.validate_evidence_bodies(bad_bodies)

        bad_index = native.catalog_index(self.index_bytes, check_expiry=False)
        bad_index["source"]["sha"] = "0" * 40
        with self.assertRaises(ContractError):
            native.validate_index(bad_index, check_expiry=False)


if __name__ == "__main__":
    unittest.main()
