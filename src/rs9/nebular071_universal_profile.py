"""Closed coordinates for the version-isolated Nebular 0.7.1 owner family.

This module contains no producer facts.  Runtime, release, and source
coordinates are accepted only from authenticated input records at the
boundary that consumes them.
"""
from __future__ import annotations

import re
from collections.abc import Mapping

from rs9.tf_pypi_archive import AdmissionError


VERSION = "0.7.1"
TAG = "v0.7.1"
PRODUCT = "theme-forge-nebular-fusion"
REPOSITORY = "Knowledge-Forge-AI/theme-forge-nebular-fusion"
RUNTIME_PROFILE = "system_webkit-only"
# The dispatcher/history contract uses the established mode tokens.  The
# release and job/schema namespaces carry the 071 isolation; adding a second
# version suffix here would make rendered workflow inputs unreachable from the
# maintained dispatcher.
QUALIFY_MODE = "universal-qualify"
PUBLISH_MODE = "universal-publish"
# The existing trusted-publisher registration is attached to this workflow
# filename.  071 job/mode/artifact namespaces remain isolated inside it.
WORKFLOW = "rs9-tfnf-pypi-publish.yml"
ARTIFACT_PREFIX = "tfnf-071-universal-"
DIST = "theme_forge_nebular_fusion"
WHEEL_FILENAME = f"{DIST}-{VERSION}-py3-none-any.whl"

TARGETS = ("darwin-arm64", "linux-arm64-gnu", "linux-x64-gnu")
LINUX_TARGETS = ("linux-arm64-gnu", "linux-x64-gnu")
SCHEMAS = {
    "runtime_inputs": "rs9.nebular071-universal-runtime-inputs.v1",
    "runtime_index": "rs9.nebular071-universal-runtime-index.v1",
    "package": "rs9.nebular071-universal-package.v1",
    "build": "rs9.nebular071-universal-build.v1",
    "bundle": "rs9.nebular071-universal-bundle.v1",
    "matrix": "rs9.nebular071-universal-installed-matrix.v1",
    "missing": "rs9.nebular071-universal-missing-runtime.v1",
    "publication": "rs9.nebular071-universal-publication.v1",
    "upload": "rs9.nebular071-universal-upload-attempt.v1",
    "readback": "rs9.nebular071-universal-readback.v1",
    "source_offer": "rs9.nebular071-source-offer.v1",
    "smoke_support": "rs9.nebular071-smoke-support.v1",
    "system_webkit": "rs9.nebular071-system-webkit-input.v1",
    "consumer": "rs9.nebular071-universal-consumer.v1",
    "host": "rs9.nebular071-host-observation.v1",
    "system_preflight": "rs9.nebular071-system-webkit-preflight.v1",
    "installed_smoke": "rs9.nebular071-installed-smoke-json-artifact.v1",
    "system_native": "rs9.nebular071-system-native-consumer-input.v1",
    "darwin_harness": "rs9.nebular071-darwin-harness.v1",
    "launcher_result": "rs9.nebular071-launcher-result.v1",
    "native_receipt": "rs9.nebular071-universal-native-receipt.v1",
}
TARGET_LAYOUTS = {
    "darwin-arm64": {"raw_root": "Theme Forge Nebular Fusion.app", "executable": "Contents/MacOS/theme-forge-nebular-fusion"},
    "linux-arm64-gnu": {"raw_root": "theme-forge-nebular-fusion", "executable": "bin/theme-forge-nebular-fusion"},
    "linux-x64-gnu": {"raw_root": "theme-forge-nebular-fusion", "executable": "bin/theme-forge-nebular-fusion"},
}
_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_HEX40 = re.compile(r"^[0-9a-f]{40}$")
LEGACY_071_VALUES = frozenset({
    "0.7.0",
    "v0.7.0",
})


def fail(code: str, message: str = "071 contract failed") -> None:
    raise AdmissionError(f"TF_PYPI_NEBULAR071_{code}") from None


def digest(value: object, label: str = "digest") -> str:
    if type(value) is not str or not _HEX64.fullmatch(value):
        fail("DIGEST", f"{label} is invalid")
    return value


def coordinate(value: object, label: str = "coordinate") -> str:
    if type(value) is not str or not _HEX40.fullmatch(value):
        fail("COORDINATE", f"{label} is invalid")
    return value


def require_071_version(value: object, label: str = "version") -> str:
    if value != VERSION:
        fail("VERSION", f"{label} must be {VERSION}")
    return VERSION


def require_target(target: object) -> str:
    if target not in TARGETS:
        fail("TARGET", "unsupported target")
    return target


def require_profile(value: object) -> str:
    if value != RUNTIME_PROFILE:
        fail("PROFILE", "only system-WebKit profile is admitted")
    return RUNTIME_PROFILE


def validate_versioned_coordinates(value: Mapping[str, object], *, label: str = "coordinates") -> dict[str, object]:
    """Validate explicit 071 coordinates without filling any missing facts."""
    if not isinstance(value, Mapping):
        fail("SHAPE", f"{label} must be an object")
    version = require_071_version(value.get("version"), f"{label}.version")
    tag = value.get("tag")
    if tag != TAG:
        fail("TAG", f"{label}.tag must be {TAG}")
    target = require_target(value.get("target"))
    profile = require_profile(value.get("profile", RUNTIME_PROFILE))
    if "manylinux" in value or value.get("manylinux") is True:
        fail("PROFILE", "manylinux is outside the 071 system-WebKit profile")
    return {"version": version, "tag": tag, "target": target, "profile": profile}


def reject_071(value: object, *, label: str = "value") -> None:
    """Reject obvious 0.7.1 authority values instead of silently translating them."""
    text = repr(value)
    if "0.7.1" in text or "nebular071" in text or "v0.7.1" in text or any(value in text for value in LEGACY_071_VALUES):
        fail("LEGACY", f"{label} contains a 0.7.1 authority")
