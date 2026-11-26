"""Exact ArchARM graphics runtime qualified by the key-free native probe."""
from __future__ import annotations

from types import MappingProxyType

from rs9._archarm_support import pins, successor_20261120 as previous


PROFILE = "successor-20261126"
PACKAGE_PINS_NAME = "PACKAGE-PINS-successor-20261126.json"
PACKAGE_PINS_SHA256 = "1471e21504ac0edb5d1abf9602f0266e6efce42e8c9398aff7f5efadda6cb17a"
EXPECT = MappingProxyType({**previous.EXPECT, "packageBytes": 210849784})
INPUTS = MappingProxyType({
    **previous.INPUTS,
    "qualified_probe_run": 45865135627,
    "qualified_source": "ecb6f0604df2be711dd9e86f4f4fb38e8b46da4f",
    "package_pins_sha256": PACKAGE_PINS_SHA256,
})
PROOF = MappingProxyType({
    "repository": "Knowledge-Forge-AI/theme-forge-packages",
    "source_tree": "34a32ccb85b91afac087bfaa7ebdf9389ab4bc0a",
    "run_attempt": 1,
    "job_id": 140065914306,
    "artifact_id": 15140077079,
    "artifact_zip_sha256": "746847046863d7047775fed9e282d0603b441c6e5525f79c10b55747b19376b5",
    "result_sha256": "e3b0440e66d9fcbe15cdd4069b27fa4d9663c7e93e49d61398b674dbad332551",
    "qualification_scope": "key-free native ARM dependency runtime only",
})
_VERSIONS = MappingProxyType({**previous._VERSIONS, "webkit2gtk-4.1": "2.54.3-1"})


def load_successor_pins(root=pins.PIN_DIR):
    return previous._load_successor_pins(
        root, PACKAGE_PINS_NAME, PACKAGE_PINS_SHA256, EXPECT, _VERSIONS,
    )
