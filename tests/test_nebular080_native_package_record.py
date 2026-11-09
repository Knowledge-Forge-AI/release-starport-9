"""Controlled tests for the authenticated 0.8 NativeRC package record."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import sys
import tarfile
import unittest
from unittest import mock


REPOSITORY = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPOSITORY / "src"))

from rs9 import nebular080_product_native as native  # noqa: E402
from rs9 import nebular080_universal_consumer as consumer  # noqa: E402
from rs9.errors import ContractError  # noqa: E402
from rs9.scratch import canonical  # noqa: E402


FIXTURE = (
    REPOSITORY
    / "tests"
    / "fixtures"
    / "nebular-v0.8.0-native-evidence-run-42418673472-attempt-1.tar.gz"
)
TARGET = "linux-x64-gnu"
PLATFORM = "linux-x64"
ASSET = {
    "name": "theme-forge-nebular-fusion-v0.8.0-x86_64-unknown-linux-gnu.tar.gz",
    "size": 56825312,
    "sha256": "498f0f6ff81c32200843e04016f86f7733905df0b0712c3f3639162ad5655abc",
}
MEMBER_COUNT = 1785


def _sha(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _fixture_bytes() -> bytes:
    with tarfile.open(FIXTURE, mode="r:gz") as archive:
        member = archive.getmember("linux-x64/package-record.json")
        stream = archive.extractfile(member)
        if stream is None:
            raise AssertionError("fixture package record is not readable")
        return stream.read()


def _fixture_pin(raw: bytes) -> dict[str, dict[str, dict[str, object]]]:
    return {
        PLATFORM: {
            "package-record.json": {"bytes": len(raw), "sha256": _sha(raw)}
        }
    }


class NativePackageRecordTests(unittest.TestCase):
    def test_approved_fixture_is_bound_to_platform_asset_and_executable(self) -> None:
        raw = _fixture_bytes()
        result = consumer._native_package_record(
            raw,
            _sha(raw),
            target=TARGET,
            asset=ASSET,
            member_count=MEMBER_COUNT,
        )
        self.assertEqual(result["schema"], "nebular.native-rc-package-v1")
        self.assertEqual(result["platform"], PLATFORM)
        self.assertEqual(result["version"], "0.8.0")
        self.assertEqual(result["raw"]["filename"], ASSET["name"])
        self.assertEqual(result["raw"]["size"], ASSET["size"])
        self.assertEqual(result["raw"]["sha256"], ASSET["sha256"])
        self.assertEqual(result["raw"]["members"], MEMBER_COUNT)
        self.assertRegex(result["raw"]["executableSha256"], r"^[0-9a-f]{64}$")

    def test_descriptor_digest_and_record_bytes_are_pin_bound(self) -> None:
        raw = _fixture_bytes()
        with self.assertRaises(ContractError) as wrong_digest:
            consumer._native_package_record(
                raw,
                "0" * 64,
                target=TARGET,
                asset=ASSET,
                member_count=MEMBER_COUNT,
            )
        self.assertEqual(wrong_digest.exception.code, "NEBULAR_UNIVERSAL_NATIVE_CONTRACT")

        tampered = raw.replace(b'"0.8.0"', b'"0.8.1"', 1)
        self.assertEqual(len(tampered), len(raw))
        with self.assertRaises(ContractError) as wrong_bytes:
            consumer._native_package_record(
                tampered,
                _sha(tampered),
                target=TARGET,
                asset=ASSET,
                member_count=MEMBER_COUNT,
            )
        self.assertEqual(wrong_bytes.exception.code, "NEBULAR_UNIVERSAL_NATIVE_CONTRACT")

    def test_wrong_target_and_asset_are_rejected(self) -> None:
        raw = _fixture_bytes()
        with self.assertRaises(ContractError) as wrong_target:
            consumer._native_package_record(
                raw,
                _sha(raw),
                target="linux-arm64-gnu",
                asset=ASSET,
                member_count=MEMBER_COUNT,
            )
        self.assertEqual(wrong_target.exception.code, "NEBULAR_UNIVERSAL_NATIVE_CONTRACT")

        wrong_asset = {**ASSET, "name": "other-native.tar.gz"}
        with self.assertRaises(ContractError) as wrong_asset_error:
            consumer._native_package_record(
                raw,
                _sha(raw),
                target=TARGET,
                asset=wrong_asset,
                member_count=MEMBER_COUNT,
            )
        self.assertEqual(wrong_asset_error.exception.code, "NEBULAR_UNIVERSAL_NATIVE_CONTRACT")

    def test_schema_and_platform_fields_remain_checked_after_pin_binding(self) -> None:
        original = _fixture_bytes()
        value = json.loads(original)
        value["schema"] = "wrong.package-record"
        altered = canonical(value)
        with mock.patch.object(native, "evidence_pins", return_value=_fixture_pin(altered)):
            with self.assertRaises(ContractError) as wrong_schema:
                consumer._native_package_record(
                    altered,
                    _sha(altered),
                    target=TARGET,
                    asset=ASSET,
                    member_count=MEMBER_COUNT,
                )
        self.assertEqual(wrong_schema.exception.code, "NEBULAR_UNIVERSAL_NATIVE_CONTRACT")

        value = json.loads(original)
        value["platform"] = "linux-arm64"
        altered = canonical(value)
        with mock.patch.object(native, "evidence_pins", return_value=_fixture_pin(altered)):
            with self.assertRaises(ContractError) as wrong_platform:
                consumer._native_package_record(
                    altered,
                    _sha(altered),
                    target=TARGET,
                    asset=ASSET,
                    member_count=MEMBER_COUNT,
                )
        self.assertEqual(wrong_platform.exception.code, "NEBULAR_UNIVERSAL_NATIVE_CONTRACT")


if __name__ == "__main__":
    unittest.main()
