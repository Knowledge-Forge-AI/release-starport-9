"""Exact qualified rootfs/package pins (ported validators; no refresh, no repin).

The three pin/key files are loaded from ``PIN_DIR`` and must match their origin
identities byte-exactly (see ``origin.ORIGIN_FILES``). A missing or different
file is a hard ``PIN_FILE`` refusal; nothing is fetched, regenerated or
re-pinned. ``PinBundle.qualified`` is True only for that exact-origin load.
"""
from __future__ import annotations

import copy
from dataclasses import dataclass, field
import hashlib
import json
from pathlib import Path
import re
import stat
from typing import Any, Mapping

from rs9._archarm_support.origin import ORIGIN_FILES
from rs9._archarm_support.refusal import SdkRefusal, require
from rs9._archarm_support.rootfs import FINGERPRINT, check_file

PIN_DIR = Path(__file__).resolve().parent / "pins"
PACKAGE_PINS_NAME = "PACKAGE-PINS.json"
ROOTFS_PIN_NAME = "ROOTFS-PIN.json"
CERT_NAME = "archlinuxarm-builder-public.gpg"

PACKAGE_PIN_SCHEMA = "tf.archarm-runtime-package-pins.v1"
ROOT_NAMES = ("fakeroot", "python", "nodejs-lts-jod", "gtk3", "webkit2gtk-4.1", "xorg-server-xvfb")
VERSION_PINS = {"python": "3.14.9-1", "nodejs-lts-jod": "22.23.4-1", "webkit2gtk-4.1": "2.54.2-1"}
TOOL_PYTHON_VERSION = "3.14.9"
TOOL_NODE_VERSION = "22.23.4"
PACKAGE_URL_PREFIX = "https://fl.us.mirror.archlinuxarm.org/aarch64/"
PACKAGE_REPOS = ("core", "extra", "alarm")
PACKAGE_URL_RE = re.compile(r"https://fl\.us\.mirror\.archlinuxarm\.org/aarch64/"
                            r"(?:core|extra|alarm)/[A-Za-z0-9@._+%~-]+\.pkg\.tar\.xz(?:\.sig)?")
ROOTFS_URL_PREFIX = "https://fl.us.mirror.archlinuxarm.org/os/"
NAME_RE = re.compile(r"[a-z0-9@_+][a-z0-9@._+-]{0,99}")
VERSION_RE = re.compile(r"(?:[0-9]{1,6}:)?[A-Za-z0-9._+~]{1,80}-[0-9]{1,6}(?:\.[0-9]{1,6})?")
HEX64_RE = re.compile(r"[0-9a-f]{64}")

MAX_PACKAGES = 256
MAX_PACKAGE_BYTES = 64 * 1024 * 1024
MAX_SIGNATURE_BYTES = 4096
MAX_PACKAGE_TOTAL_BYTES = 256 * 1024 * 1024
MAX_PIN_FILE_BYTES = 1024 * 1024

REAL_EXPECT = {
    "packageCount": 139,
    "packageBytes": 201499452,
    "rootfsUrl": "https://fl.us.mirror.archlinuxarm.org/os/ArchLinuxARM-aarch64-latest.tar.gz",
    "rootfsBytes": 829367415,
    "rootfsSha256": "42a4eeaa038994ffd31fa173256ef2f0ef511358eeb41b9ea1f8626391b9b319",
    "publicKeyBytes": 3857,
    "publicKeySha256": "4e4202772328674af68f90f675e077d192337fc8ced15cddcd35875a9de5b5f9",
}
EXPECT_KEYS = frozenset(REAL_EXPECT)


def _is_int(value):
    return type(value) is int


def read_bounded(path, limit):
    path = Path(path)
    try:
        info = path.lstat()
    except OSError:
        raise SdkRefusal("PIN_FILE") from None
    require(stat.S_ISREG(info.st_mode) and 0 < info.st_size <= limit, "PIN_FILE")
    with path.open("rb") as stream:
        data = stream.read(limit + 1)
    require(len(data) == info.st_size, "PIN_FILE")
    return data


def _exact_origin(raw, name):
    origin = ORIGIN_FILES[name]
    require(isinstance(raw, bytes) and len(raw) == origin["bytes"]
            and hashlib.sha256(raw).hexdigest() == origin["sha256"], "PIN_FILE")
    return raw


def load_json(raw):
    def pairs_hook(pairs):
        keys = [key for key, _ in pairs]
        if len(keys) != len(set(keys)):
            raise SdkRefusal("PIN_JSON")
        return dict(pairs)

    def reject_constant(_):
        raise SdkRefusal("PIN_JSON")

    try:
        return json.loads(raw.decode("utf-8"), object_pairs_hook=pairs_hook,
                          parse_constant=reject_constant)
    except SdkRefusal:
        raise
    except (UnicodeDecodeError, ValueError):
        raise SdkRefusal("PIN_JSON") from None


PACKAGE_TOP_KEYS = frozenset({"schema", "rootNames", "publicSigningFingerprint", "packages",
                              "packageCount", "totalBytes", "toolPythonVersion",
                              "toolNodeVersion", "networkDuringInstallOrProbe",
                              "noBasePackageUpgrades"})
PACKAGE_KEYS = frozenset({"name", "version", "architecture", "url", "filename", "bytes",
                          "sha256", "signatureBytes", "signatureSha256", "licenses"})


def _check_license_list(value):
    require(isinstance(value, list) and 1 <= len(value) <= 64, "PIN_PACKAGE")
    for item in value:
        require(isinstance(item, str) and 1 <= len(item) <= 256
                and all(ch.isprintable() for ch in item), "PIN_PACKAGE")


def validate_package_pins(doc, expect):
    require(isinstance(expect, dict) and set(expect) == EXPECT_KEYS, "PIN_SCHEMA")
    require(isinstance(doc, dict) and set(doc) == PACKAGE_TOP_KEYS, "PIN_SCHEMA")
    require(doc["schema"] == PACKAGE_PIN_SCHEMA, "PIN_SCHEMA")
    require(doc["rootNames"] == list(ROOT_NAMES), "PIN_ROOTS")
    require(doc["publicSigningFingerprint"] == FINGERPRINT, "PIN_FINGERPRINT")
    require(doc["toolPythonVersion"] == TOOL_PYTHON_VERSION
            and doc["toolNodeVersion"] == TOOL_NODE_VERSION, "PIN_VERSION")
    require(doc["networkDuringInstallOrProbe"] is False
            and doc["noBasePackageUpgrades"] is True, "PIN_SCHEMA")
    packages = doc["packages"]
    require(isinstance(packages, list) and 0 < len(packages) <= MAX_PACKAGES, "PIN_COUNT")
    require(_is_int(doc["packageCount"]) and doc["packageCount"] == len(packages)
            == expect["packageCount"], "PIN_COUNT")
    names, filenames, total = set(), set(), 0
    for record in packages:
        require(isinstance(record, dict) and set(record) == PACKAGE_KEYS, "PIN_PACKAGE")
        name, version, arch = record["name"], record["version"], record["architecture"]
        require(isinstance(name, str) and NAME_RE.fullmatch(name) is not None, "PIN_PACKAGE")
        require(isinstance(version, str) and VERSION_RE.fullmatch(version) is not None,
                "PIN_PACKAGE")
        require(arch in ("any", "aarch64"), "PIN_PACKAGE")
        require(name not in names, "PIN_PACKAGE")
        names.add(name)
        filename = record["filename"]
        require(filename == f"{name}-{version}-{arch}.pkg.tar.xz", "PIN_PACKAGE")
        require(filename.casefold() not in filenames, "PIN_PACKAGE")
        filenames.add(filename.casefold())
        url = record["url"]
        require(isinstance(url, str) and url.startswith(PACKAGE_URL_PREFIX)
                and PACKAGE_URL_RE.fullmatch(url) is not None, "PIN_URL")
        repo, _, encoded = url[len(PACKAGE_URL_PREFIX):].partition("/")
        require(repo in PACKAGE_REPOS and encoded == filename.replace(":", "%3A"), "PIN_URL")
        require(_is_int(record["bytes"]) and 0 < record["bytes"] <= MAX_PACKAGE_BYTES,
                "PIN_BYTES")
        require(_is_int(record["signatureBytes"])
                and 0 < record["signatureBytes"] <= MAX_SIGNATURE_BYTES, "PIN_BYTES")
        require(isinstance(record["sha256"], str) and HEX64_RE.fullmatch(record["sha256"])
                is not None, "PIN_PACKAGE")
        require(isinstance(record["signatureSha256"], str)
                and HEX64_RE.fullmatch(record["signatureSha256"]) is not None, "PIN_PACKAGE")
        _check_license_list(record["licenses"])
        if name in VERSION_PINS:
            require(version == VERSION_PINS[name], "PIN_VERSION")
        total += record["bytes"]
        require(total <= MAX_PACKAGE_TOTAL_BYTES, "PIN_BYTES")
    require(set(ROOT_NAMES) <= names, "PIN_ROOTS")
    require(_is_int(doc["totalBytes"]) and doc["totalBytes"] == total
            == expect["packageBytes"], "PIN_BYTES")
    return doc


ROOTFS_PIN_KEYS = frozenset({"schema", "rootfsUrl", "rootfsBytes", "rootfsSha256",
                             "signatureBytes", "signatureSha256", "publicKeySha256",
                             "publicKeyFingerprint", "members", "declaredBytes",
                             "literalEscapes", "setIdMembers", "rootDirectoryHeaders",
                             "literalEscapeLinks", "declaredBytesCorrection",
                             "publicKeyBytes"})


def validate_rootfs_pin(pin, expect):
    require(isinstance(pin, dict) and set(pin) == ROOTFS_PIN_KEYS, "ROOTFS_PIN")
    require(pin["rootfsUrl"] == expect["rootfsUrl"]
            and pin["rootfsBytes"] == expect["rootfsBytes"]
            and pin["rootfsSha256"] == expect["rootfsSha256"]
            and pin["publicKeyBytes"] == expect["publicKeyBytes"]
            and pin["publicKeySha256"] == expect["publicKeySha256"]
            and pin["publicKeyFingerprint"] == FINGERPRINT, "ROOTFS_PIN")
    require(isinstance(pin["rootfsUrl"], str) and pin["rootfsUrl"].startswith(ROOTFS_URL_PREFIX),
            "ROOTFS_PIN")
    require(_is_int(pin["signatureBytes"]) and 0 < pin["signatureBytes"] <= MAX_SIGNATURE_BYTES
            and isinstance(pin["signatureSha256"], str)
            and HEX64_RE.fullmatch(pin["signatureSha256"]) is not None, "ROOTFS_PIN")
    require(all(_is_int(pin[k]) and pin[k] >= 0
                for k in ("members", "declaredBytes", "rootDirectoryHeaders")), "ROOTFS_PIN")
    require(isinstance(pin["literalEscapes"], list) and len(pin["literalEscapes"]) == 3
            and isinstance(pin["setIdMembers"], list)
            and isinstance(pin["literalEscapeLinks"], list), "ROOTFS_PIN")
    return pin


@dataclass(frozen=True)
class PinBundle:
    """Validated pins. ``qualified`` is True only for the exact-origin bundle."""

    package_pins: Mapping[str, Any]
    rootfs_pin: Mapping[str, Any]
    certificate: Path
    expect: Mapping[str, Any]
    digests: Mapping[str, str]
    qualified: bool = field(default=False)

    @property
    def packages(self):
        return copy.deepcopy(self.package_pins["packages"])


def validated_bundle(*, package_doc, rootfs_doc, certificate, expect, digests):
    """Validate a (possibly synthetic) bundle with the same closed rules; never qualified."""
    expect = dict(expect)
    package_doc = validate_package_pins(copy.deepcopy(package_doc), expect)
    rootfs_doc = validate_rootfs_pin(copy.deepcopy(rootfs_doc), expect)
    check_file(Path(certificate), expect["publicKeyBytes"], expect["publicKeySha256"])
    return PinBundle(package_doc, rootfs_doc, Path(certificate), expect, dict(digests), False)


def load_qualified_pins(root=PIN_DIR):
    """Load the exact qualified pins/key; any byte difference or absence refuses."""
    root = Path(root)
    package_raw = _exact_origin(read_bounded(root / PACKAGE_PINS_NAME, MAX_PIN_FILE_BYTES),
                                "PACKAGE-PINS.json")
    rootfs_raw = _exact_origin(read_bounded(root / ROOTFS_PIN_NAME, MAX_PIN_FILE_BYTES),
                               "ROOTFS-PIN.json")
    cert = ORIGIN_FILES["archlinuxarm-builder-public.gpg"]
    try:
        check_file(root / CERT_NAME, cert["bytes"], cert["sha256"])
    except SdkRefusal:
        raise SdkRefusal("PIN_FILE") from None
    expect = dict(REAL_EXPECT)
    package_doc = validate_package_pins(load_json(package_raw), expect)
    rootfs_doc = validate_rootfs_pin(load_json(rootfs_raw), expect)
    digests = {"rootfsSha256": rootfs_doc["rootfsSha256"],
               "rootfsPinSha256": hashlib.sha256(rootfs_raw).hexdigest(),
               "packagePinsSha256": hashlib.sha256(package_raw).hexdigest(),
               "publicKeySha256": expect["publicKeySha256"],
               "publicKeyFingerprint": FINGERPRINT}
    return PinBundle(package_doc, rootfs_doc, root / CERT_NAME, expect, digests, True)
