"""Repository-layout tests for the optional Nebular 0.8 release inventory.

The release metadata fixture is a sanitized copy of the retained public API
body.  It is deliberately separate from expectations so these tests exercise
the source-facing inventory validator against metadata rather than rebuilding
API rows from expected hashes.
"""

from __future__ import annotations

import copy
import json
from pathlib import Path
import unittest
from unittest.mock import patch

from rs9 import operator, release_asset_inventory
from rs9.errors import ContractError


ROOT = Path(__file__).resolve().parents[1]
FIXTURE_PATH = Path(__file__).resolve().parent / "fixtures" / "nebular080-release-api-inventory.json"
EXPECTATIONS_PATH = ROOT / "operators" / "theme-forge-current-202610" / "expectations.json"
RETAINED_API_SHA256 = "61bf299406da05864ce1d66e98012d665fcf5230e5fc7a047b688103ad60e139"


def _load_json(path: Path) -> dict:
    return json.loads(path.read_bytes())


def _project_expectations() -> dict:
    projects = _load_json(EXPECTATIONS_PATH)["projects"]
    return next(row for row in projects if row["project"] == "theme-forge-nebular-fusion")


def _fixture() -> dict:
    value = _load_json(FIXTURE_PATH)
    if value["source_api_sha256"] != RETAINED_API_SHA256:
        raise AssertionError("fixture provenance changed")
    return value


def _api_by_name(fixture: dict) -> dict[str, dict]:
    return {row["name"]: row for row in fixture["release"]["assets"]}


def _record(fixture: dict, names: list[str]) -> dict:
    api_by_name = _api_by_name(fixture)
    return {
        "repository": copy.deepcopy(fixture["repository"]),
        "release": {
            "id": fixture["release"]["id"],
            "tag": fixture["release"]["tag_name"],
        },
        "tag": {
            "commit": fixture["commit"]["sha"],
            "tree": fixture["commit"]["tree"],
        },
        "source_times": {"published_at": fixture["release"]["published_at"]},
        "assets": [
            {
                "github_asset_id": api_by_name[name]["id"],
                "name": name,
                "size": api_by_name[name]["size"],
                "sha256": api_by_name[name]["digest"][len("sha256:"):],
            }
            for name in names
        ],
    }


class _Capture:
    def __init__(self, record: dict) -> None:
        self.record = record


class ReleaseAssetInventoryIntegrationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.fixture = _fixture()
        self.expected = _project_expectations()
        self.inventory = copy.deepcopy(self.expected["release_asset_inventory"])
        self.release = copy.deepcopy(self.fixture["release"])
        self.tree = copy.deepcopy(self.fixture["tree"])
        self.selected_names = [row["name"] for row in self.expected["assets"]]
        self.all_names = [row["name"] for row in self.release["assets"]]

    def _validate_inventory(self, *, inventory=None, release=None) -> None:
        release_asset_inventory.validate_release_asset_inventory(
            self.inventory if inventory is None else inventory,
            release_metadata=self.release if release is None else release,
            expected_assets=self.expected["assets"],
            actual_selected_assets=_record(self.fixture, self.selected_names)["assets"],
        )

    def _assert_mismatch(self, callback) -> None:
        with self.assertRaises(ContractError) as raised:
            callback()
        self.assertEqual(raised.exception.code, "LIVE1_RELEASE_MISMATCH")

    def test_candidate_source_integration_uses_fixture_and_legacy_path_remains(self):
        record = _record(self.fixture, self.selected_names)
        with patch.object(operator, "authenticated_release_metadata", return_value=self.release) as release_reader, \
                patch.object(operator, "authenticated_tree", return_value=self.tree) as tree_reader:
            operator.assert_release_expectations(_Capture(record), self.expected)
        release_reader.assert_called_once()
        tree_reader.assert_called_once()

        legacy_expected = copy.deepcopy(self.expected)
        legacy_expected.pop("release_asset_inventory")
        legacy_expected["assets"] = [
            {
                "id": row["id"],
                "name": row["name"],
                "sha256": row["sha256"],
                "size": row["size"],
            }
            for row in self.inventory["assets"]
        ]
        legacy_record = _record(self.fixture, self.all_names)
        with patch.object(operator, "authenticated_release_metadata", return_value=self.release), \
                patch.object(operator, "authenticated_tree", return_value=self.tree):
            operator.assert_release_expectations(_Capture(legacy_record), legacy_expected)

    def test_present_null_inventory_is_not_a_legacy_bypass(self):
        expected = copy.deepcopy(self.expected)
        expected["release_asset_inventory"] = None
        with patch.object(operator, "authenticated_release_metadata", return_value=self.release), \
                patch.object(operator, "authenticated_tree", return_value=self.tree):
            self._assert_mismatch(
                lambda: operator.assert_release_expectations(
                    _Capture(_record(self.fixture, self.selected_names)), expected
                )
            )

    def test_twelve_closed_negative_inventory_cases(self):
        cases = []

        extra_root_key = copy.deepcopy(self.inventory)
        extra_root_key["unexpected"] = True
        cases.append(extra_root_key)

        wrong_schema = copy.deepcopy(self.inventory)
        wrong_schema["schema"] = "rs9.release-asset-inventory.unknown"
        cases.append(wrong_schema)

        wrong_count = copy.deepcopy(self.inventory)
        wrong_count["assets"].pop()
        cases.append(wrong_count)

        duplicate_inventory_name = copy.deepcopy(self.inventory)
        duplicate_inventory_name["assets"][1]["name"] = duplicate_inventory_name["assets"][0]["name"]
        cases.append(duplicate_inventory_name)

        duplicate_inventory_id = copy.deepcopy(self.inventory)
        duplicate_inventory_id["assets"][1]["id"] = duplicate_inventory_id["assets"][0]["id"]
        cases.append(duplicate_inventory_id)

        missing_api_digest = copy.deepcopy(self.release)
        del missing_api_digest["assets"][0]["digest"]
        cases.append((self.inventory, missing_api_digest))

        wrong_api_algorithm = copy.deepcopy(self.release)
        wrong_api_algorithm["assets"][0]["digest"] = "sha512:" + wrong_api_algorithm["assets"][0]["digest"][7:]
        cases.append((self.inventory, wrong_api_algorithm))

        duplicate_api_name = copy.deepcopy(self.release)
        duplicate_api_name["assets"][1]["name"] = duplicate_api_name["assets"][0]["name"]
        cases.append((self.inventory, duplicate_api_name))

        unknown_api_name = copy.deepcopy(self.release)
        unknown_api_name["assets"][0]["name"] = "unknown-public-release-asset"
        cases.append((self.inventory, unknown_api_name))

        api_id_mismatch = copy.deepcopy(self.release)
        api_id_mismatch["assets"][0]["id"] += 1
        cases.append((self.inventory, api_id_mismatch))

        api_size_mismatch = copy.deepcopy(self.release)
        api_size_mismatch["assets"][0]["size"] += 1
        cases.append((self.inventory, api_size_mismatch))

        api_digest_mismatch = copy.deepcopy(self.release)
        original_digest = api_digest_mismatch["assets"][0]["digest"]
        api_digest_mismatch["assets"][0]["digest"] = "sha256:" + "0" * 64
        if api_digest_mismatch["assets"][0]["digest"] == original_digest:
            self.fail("digest negative fixture did not change")
        cases.append((self.inventory, api_digest_mismatch))

        self.assertEqual(len(cases), 12)
        for case in cases:
            inventory, release = (case, self.release) if isinstance(case, dict) and "schema" in case else case
            self._assert_mismatch(
                lambda inventory=inventory, release=release: self._validate_inventory(
                    inventory=inventory, release=release
                )
            )


if __name__ == "__main__":
    unittest.main()
