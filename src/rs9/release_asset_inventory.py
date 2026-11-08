"""Optional current-080 release metadata inventory validation.

This candidate validates the complete public release catalog from the already
authenticated API metadata while leaving selected-asset byte authentication to
the existing operator path.  It never downloads or reads unselected bodies.
"""

from __future__ import annotations

import re

from rs9.errors import ContractError


SCHEMA = "rs9.release-asset-inventory.v1alpha1"
ROOT_KEYS = frozenset({"schema", "assets"})
ENTRY_KEYS = frozenset({"id", "name", "size", "sha256"})
HEX64 = re.compile(r"[0-9a-f]{64}\Z")
SAFE_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._+-]{0,255}\Z")
INVENTORY_COUNT = 18


def _fail() -> None:
    raise ContractError("LIVE1_RELEASE_MISMATCH", "Authenticated release inventory differs from reviewed expectation")


def _require(condition: bool) -> None:
    if not condition:
        _fail()


def _entries(value: object) -> list[dict]:
    _require(isinstance(value, dict) and set(value) == ROOT_KEYS)
    _require(value.get("schema") == SCHEMA)
    assets = value.get("assets")
    _require(isinstance(assets, list) and len(assets) == INVENTORY_COUNT)
    for asset in assets:
        _require(isinstance(asset, dict) and set(asset) == ENTRY_KEYS)
        _require(type(asset["id"]) is int and asset["id"] > 0)
        _require(type(asset["size"]) is int and asset["size"] > 0)
        _require(isinstance(asset["name"], str) and SAFE_NAME.fullmatch(asset["name"]))
        _require(isinstance(asset["sha256"], str) and HEX64.fullmatch(asset["sha256"]))
    _require(len({asset["name"] for asset in assets}) == INVENTORY_COUNT)
    _require(len({asset["id"] for asset in assets}) == INVENTORY_COUNT)
    return assets


def _api_assets(release_metadata: object) -> dict[str, dict]:
    _require(isinstance(release_metadata, dict))
    actual = release_metadata.get("assets")
    _require(isinstance(actual, list) and len(actual) == INVENTORY_COUNT)
    result: dict[str, dict] = {}
    for asset in actual:
        _require(isinstance(asset, dict))
        name = asset.get("name")
        _require(isinstance(name, str) and SAFE_NAME.fullmatch(name) and name not in result)
        _require(type(asset.get("id")) is int and asset["id"] > 0)
        _require(type(asset.get("size")) is int and asset["size"] > 0)
        digest = asset.get("digest")
        _require(isinstance(digest, str) and digest.startswith("sha256:") and HEX64.fullmatch(digest[7:]))
        result[name] = asset
    return result


def validate_release_asset_inventory(
    inventory: object,
    *,
    release_metadata: object,
    expected_assets: object,
    actual_selected_assets: object,
) -> None:
    """Validate complete API metadata and preserve the selected eight gate."""

    inventory_assets = _entries(inventory)
    api_assets = _api_assets(release_metadata)
    inventory_names = {asset["name"] for asset in inventory_assets}
    _require(set(api_assets) == inventory_names)
    inventory_by_name = {asset["name"]: asset for asset in inventory_assets}
    for expected in inventory_assets:
        actual = api_assets[expected["name"]]
        _require(actual["id"] == expected["id"])
        _require(actual["size"] == expected["size"])
        _require(actual["digest"][7:] == expected["sha256"])

    _require(isinstance(expected_assets, list) and expected_assets)
    expected_names: set[str] = set()
    for expected in expected_assets:
        _require(isinstance(expected, dict) and set(expected) == ENTRY_KEYS)
        _require(expected["name"] not in expected_names)
        expected_names.add(expected["name"])
        pinned = inventory_by_name.get(expected["name"])
        _require(pinned is not None)
        _require(all(expected[field] == pinned[field] for field in ENTRY_KEYS))

    _require(isinstance(actual_selected_assets, list))
    actual_by_name: dict[str, dict] = {}
    for actual in actual_selected_assets:
        _require(isinstance(actual, dict))
        name = actual.get("name")
        _require(isinstance(name, str) and name not in actual_by_name)
        actual_by_name[name] = actual
    _require(set(actual_by_name) == expected_names)
    for expected in expected_assets:
        actual = actual_by_name[expected["name"]]
        _require(actual.get("github_asset_id") == expected["id"])
        _require(actual.get("size") == expected["size"])
        _require(actual.get("sha256") == expected["sha256"])
