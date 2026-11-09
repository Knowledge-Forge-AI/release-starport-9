"""Exact successor ArchARM dependency-input identity and loader.

This profile is deliberately separate from the historical ``origin`` data.  It
binds the admitted public P run to one new package-pin file while reusing the
unchanged rootfs pin and public certificate.  The P result qualifies only the
key-free native ARM dependency-runtime input class; it does not qualify this
Python SDK module, a product, GUI behavior, signing, or publication.
"""
from __future__ import annotations

import hashlib
from pathlib import Path
from types import MappingProxyType
from typing import Any, Mapping

from rs9._archarm_support import pins as historical
from rs9._archarm_support.origin import ORIGIN_FILES
from rs9._archarm_support.refusal import SdkRefusal, require


PROFILE = "successor-20261109"
PACKAGE_PINS_NAME = "PACKAGE-PINS-successor-20261109.json"
PACKAGE_PINS_BYTES = 78588
PACKAGE_PINS_SHA256 = "a0896233d98b32fde260c6139321dfc64be4efa345585ee16bdbdd4ffdd2f207"
PIN_DIR = historical.PIN_DIR


def _freeze(value: Any) -> Any:
    if isinstance(value, Mapping):
        return MappingProxyType({key: _freeze(child) for key, child in value.items()})
    if isinstance(value, (list, tuple)):
        return tuple(_freeze(child) for child in value)
    return value


EXPECT = MappingProxyType({**historical.REAL_EXPECT, "packageBytes": 201488096})

# The old caller-facing shape is retained so the producer can select this
# profile without translating historical fields.  It is immutable and does
# not replace the historical QUALIFIED_INPUTS record.
INPUTS = MappingProxyType({
    "qualified_probe_run": 42653433050,
    "qualified_source": "0407736e2cf542a25cf521a45fbe95f11f30ccb6",
    "rootfs_sha256": "42a4eeaa038994ffd31fa173256ef2f0ef511358eeb41b9ea1f8626391b9b319",
    "rootfs_pin_sha256": "0d92f648e1f9bc2ef29846b7f37d7fae99ccbb4adc6fd918d797c2ac9054edff",
    "package_pins_sha256": PACKAGE_PINS_SHA256,
    "packages": 139,
    "refresh_allowed": False,
})

# Public, admitted proof identities.  These are facts of the retained source
# body/projection and original artifact, not a runtime claim about this module.
PROOF = _freeze({
    "schema": "tf.archarm-key-free-runtime-probe.v2",
    "repository": "Knowledge-Forge-AI/theme-forge-packages",
    "source_commit": "0407736e2cf542a25cf521a45fbe95f11f30ccb6",
    "source_tree": "c870ce8dda09fc0511e1cfbe98ffa1b12c155040",
    "run_id": 42653433050,
    "run_attempt": 1,
    "event": "workflow_dispatch",
    "workflow_path": ".github/workflows/probe-current-archarm-runtime-successor-20261109.yml",
    "workflow_bytes": 2179,
    "workflow_sha256": "ada652d68d4ee9108f80469358729528b9ec83a09855badac1d20b544c01dd54",
    "controller_path": "tools/verification/archarm_runtime_probe_successor_20261109/archarm_runtime_probe.py",
    "controller_bytes": 65403,
    "controller_sha256": "4a08a35b6fb2cb3f1c88fa4329362676982f38281ea9c3be74eb5d6cb0b6f4cb",
    "job_id": 129285536805,
    "artifact_id": 13691106928,
    "artifact_zip_bytes": 1081,
    "artifact_zip_sha256": "a6689b55e419fb36f33651b0da4636f26283d79670b1cd8fa4a489dc478b2c4f",
    "result_member": "result.json",
    "result_bytes": 2097,
    "result_sha256": "30515943aff4c1fd56021effa5ad9f7ce9d9a551c1d9179e34099a57b20a5616",
    "status": "pass",
    "stage": "complete",
    "source_bodies_authenticated": True,
    "controller_validation_passed": True,
    "all_runtime_flags_passed": 32,
    "cleanup_complete": True,
    "qualification_scope": "key-free native ARM dependency runtime only",
    "digests": {
        "packagePinsSha256": PACKAGE_PINS_SHA256,
        "publicKeyFingerprint": "68B3537F39A313B3E574D06777193F152BDBE6A6",
        "publicKeySha256": "4e4202772328674af68f90f675e077d192337fc8ced15cddcd35875a9de5b5f9",
        "rootfsPinSha256": "0d92f648e1f9bc2ef29846b7f37d7fae99ccbb4adc6fd918d797c2ac9054edff",
        "rootfsSha256": "42a4eeaa038994ffd31fa173256ef2f0ef511358eeb41b9ea1f8626391b9b319",
    },
    "assertions": {
        "productQualification": False,
        "fullGuiQualification": False,
        "moduleNativeQualified": False,
        "signingSecretsUsed": False,
        "publicationAuthority": False,
    },
})


def _exact_successor(raw: bytes) -> bytes:
    require(isinstance(raw, bytes) and len(raw) == PACKAGE_PINS_BYTES
            and hashlib.sha256(raw).hexdigest() == PACKAGE_PINS_SHA256, "PIN_FILE")
    return raw


def load_successor_pins(root=PIN_DIR):
    """Load the exact successor package pins with historical base inputs.

    The historical ``ORIGIN_FILES`` table and ``load_qualified_pins`` function
    are intentionally not consulted for the successor package file.  They are
    used only for the unchanged rootfs pin and public certificate.
    """
    root = Path(root)
    package_raw = _exact_successor(
        historical.read_bounded(root / PACKAGE_PINS_NAME, historical.MAX_PIN_FILE_BYTES))
    rootfs_raw = historical._exact_origin(
        historical.read_bounded(root / historical.ROOTFS_PIN_NAME, historical.MAX_PIN_FILE_BYTES),
        "ROOTFS-PIN.json",
    )
    cert = ORIGIN_FILES["archlinuxarm-builder-public.gpg"]
    try:
        historical.check_file(root / historical.CERT_NAME, cert["bytes"], cert["sha256"])
    except SdkRefusal:
        raise SdkRefusal("PIN_FILE") from None

    expect = dict(EXPECT)
    package_doc = historical.validate_package_pins(historical.load_json(package_raw), expect)
    rootfs_doc = historical.validate_rootfs_pin(historical.load_json(rootfs_raw), expect)
    digests = {
        "rootfsSha256": rootfs_doc["rootfsSha256"],
        "rootfsPinSha256": hashlib.sha256(rootfs_raw).hexdigest(),
        "packagePinsSha256": hashlib.sha256(package_raw).hexdigest(),
        "publicKeySha256": expect["publicKeySha256"],
        "publicKeyFingerprint": historical.FINGERPRINT,
    }
    return historical.PinBundle(package_doc, rootfs_doc, root / historical.CERT_NAME,
                                expect, digests, True)


__all__ = ["PROFILE", "EXPECT", "INPUTS", "PROOF", "PACKAGE_PINS_NAME", "load_successor_pins"]
