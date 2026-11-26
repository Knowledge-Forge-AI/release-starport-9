"""ArchARM inputs from the key-free OpenSSL transition probe."""
from __future__ import annotations

import hashlib
from pathlib import Path
from types import MappingProxyType

from rs9._archarm_support import pins
from rs9._archarm_support.origin import ORIGIN_FILES
from rs9._archarm_support.refusal import SdkRefusal, require


PROFILE = "successor-20261120"
PACKAGE_PINS_NAME = "PACKAGE-PINS-successor-20261120.json"
PACKAGE_PINS_SHA256 = "e3933f2d2ef013edc8d988e87b07c255d828e3c36d8e1152dad0911c8bd739ff"
PACKAGE_COUNT = 141
EXPECT = MappingProxyType({
    **pins.REAL_EXPECT, "packageCount": PACKAGE_COUNT, "packageBytes": 210600960,
})
INPUTS = MappingProxyType({
    "qualified_probe_run": 44739624049,
    "qualified_source": "32f9f4e29f735507446e1f3df74557df1496d54e",
    "rootfs_sha256": EXPECT["rootfsSha256"],
    "rootfs_pin_sha256": ORIGIN_FILES["ROOTFS-PIN.json"]["sha256"],
    "package_pins_sha256": PACKAGE_PINS_SHA256,
    "packages": PACKAGE_COUNT,
    "refresh_allowed": False,
})
PROOF = MappingProxyType({
    "repository": "Knowledge-Forge-AI/theme-forge-packages",
    "source_tree": "ea1ccd9da675ccd43a42700fe4578a1a86a7f509",
    "run_attempt": 1,
    "job_id": 136299685415,
    "artifact_id": 14629389868,
    "artifact_zip_sha256": "11692961d38bf786098967580129af09f5f9a2960a3614ab71684084bbd75854",
    "result_sha256": "a1e850e4f4874ab47443a58614ccee1cba0b1e544f3b9609d08a2445bc99e8ed",
    "qualification_scope": "key-free native ARM dependency runtime only",
})
_TOP_KEYS = (pins.PACKAGE_TOP_KEYS - {"noBasePackageUpgrades"}) | {"basePackageUpgrade"}
_UPGRADE = MappingProxyType({"name": "openssl", "from": "3.6.3-1", "to": "4.1.0-1"})
_VERSIONS = MappingProxyType({
    **pins.VERSION_PINS, "python": "3.14.10-1", "nodejs-lts-jod": "22.23.5-1",
    "openssl": _UPGRADE["to"], "openssl-3": "3.5.9-2",
})


def validate_package_pins(doc):
    return _validate_package_pins(doc, EXPECT, _VERSIONS)


def _validate_package_pins(doc, expected, versions):
    require(isinstance(doc, dict) and set(doc) == _TOP_KEYS, "PIN_SCHEMA")
    require(doc["schema"] == "tf.archarm-runtime-package-pins.v2"
            and doc["networkDuringInstallOrProbe"] is False
            and doc["basePackageUpgrade"] == _UPGRADE, "PIN_SCHEMA")
    require(doc["rootNames"] == list(pins.ROOT_NAMES), "PIN_ROOTS")
    require(doc["publicSigningFingerprint"] == pins.FINGERPRINT, "PIN_FINGERPRINT")
    require(doc["toolPythonVersion"] == "3.14.10" and doc["toolNodeVersion"] == "22.23.5",
            "PIN_VERSION")
    pins.validate_package_records(doc, expected, versions)
    require({"openssl", "openssl-3"} <= {record["name"] for record in doc["packages"]},
            "PIN_ROOTS")
    return doc


def load_successor_pins(root=pins.PIN_DIR):
    return _load_successor_pins(root, PACKAGE_PINS_NAME, PACKAGE_PINS_SHA256, EXPECT, _VERSIONS)


def _load_successor_pins(root, filename, digest, expected, versions):
    root = Path(root)
    package_raw = pins.read_bounded(root / filename, pins.MAX_PIN_FILE_BYTES)
    require(len(package_raw) == 79740
            and hashlib.sha256(package_raw).hexdigest() == digest, "PIN_FILE")
    rootfs_raw = pins._exact_origin(
        pins.read_bounded(root / pins.ROOTFS_PIN_NAME, pins.MAX_PIN_FILE_BYTES), pins.ROOTFS_PIN_NAME)
    cert = ORIGIN_FILES[pins.CERT_NAME]
    try:
        pins.check_file(root / pins.CERT_NAME, cert["bytes"], cert["sha256"])
    except SdkRefusal:
        raise SdkRefusal("PIN_FILE") from None

    package_doc = _validate_package_pins(pins.load_json(package_raw), expected, versions)
    rootfs_doc = pins.validate_rootfs_pin(pins.load_json(rootfs_raw), expected)
    digests = {
        "rootfsSha256": expected["rootfsSha256"],
        "rootfsPinSha256": ORIGIN_FILES[pins.ROOTFS_PIN_NAME]["sha256"],
        "packagePinsSha256": digest,
        "publicKeySha256": expected["publicKeySha256"],
        "publicKeyFingerprint": pins.FINGERPRINT,
    }
    return pins.PinBundle(package_doc, rootfs_doc, root / pins.CERT_NAME, dict(expected), digests, True)
