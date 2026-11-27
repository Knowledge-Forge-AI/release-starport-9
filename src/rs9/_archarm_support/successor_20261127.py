"""Exact ArchARM libcups transition qualified by the key-free native probe."""
from __future__ import annotations

from types import MappingProxyType

import rs9._archarm_support.successor_20261126 as previous
from rs9._archarm_support import pins, successor_20261120


PROFILE = "successor-20261127"
PACKAGE_PINS_NAME = "PACKAGE-PINS-successor-20261127.json"
PACKAGE_PINS_SHA256 = "c1b59ee9fa35a6af5062341e7261abfdbed0520f5b7c1f6121bf8bece8abd27a"
PACKAGE_PINS_BYTES = 79740
EXPECT = MappingProxyType({**previous.EXPECT, "packageBytes": 210849968})
INPUTS = MappingProxyType({
    **previous.INPUTS,
    "qualified_probe_run": 46041837561,
    "qualified_source": "351553ffda584a47ab49a4267118e2db92c7a657",
    "package_pins_sha256": PACKAGE_PINS_SHA256,
})
PROOF = MappingProxyType({
    "repository": "Knowledge-Forge-AI/theme-forge-packages",
    "source_tree": "d753f495caefa909aaf1a1255a11db5e03096abc",
    "run_attempt": 1,
    "job_id": 140651228707,
    "artifact_id": 15220192312,
    "artifact_zip_sha256": "45dc509d81b0611f016f6c2ab65510f70d66f70addec057ae89775d5b8a80989",
    "result_sha256": "d67b4298c2e7cdcd722ed323d5d353b1ab7c404a6d79be7240f71f413830b7fb",
    "qualification_scope": "key-free native ARM dependency runtime only",
})
_VERSIONS = MappingProxyType({**previous._VERSIONS, "libcups": "2:2.4.20-2"})


def load_successor_pins(root=pins.PIN_DIR):
    return successor_20261120._load_successor_pins(
        root, PACKAGE_PINS_NAME, PACKAGE_PINS_BYTES, PACKAGE_PINS_SHA256, EXPECT, _VERSIONS,
    )
