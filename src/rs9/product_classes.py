"""Explicit exact-product packaging classification and architecture contracts."""

from __future__ import annotations

import types
from typing import Mapping, NamedTuple

from rs9.errors import ContractError

class NativePackagingMapping(NamedTuple):
    family: str
    format: str
    canonical_adapter: str
    revision_scheme: str
    qualification_gate: str


# Explicit centralized native family -> format/canonical publication adapter/revision scheme/qualification gate mapping
# (deb,debian,apt,apt-revision; rpm,rpm,dnf,rpm-release; pacman,pacman,pacman,pkgrel)
NATIVE_PACKAGING_MAPPINGS: tuple[NativePackagingMapping, ...] = (
    NativePackagingMapping(
        family="deb",
        format="debian",
        canonical_adapter="apt",
        revision_scheme="apt-revision",
        qualification_gate="apt",
    ),
    NativePackagingMapping(
        family="rpm",
        format="rpm",
        canonical_adapter="dnf",
        revision_scheme="rpm-release",
        qualification_gate="dnf",
    ),
    NativePackagingMapping(
        family="pacman",
        format="pacman",
        canonical_adapter="pacman",
        revision_scheme="pkgrel",
        qualification_gate="pacman",
    ),
)

_NATIVE_FAMILY_MAP: dict[str, NativePackagingMapping] = {
    m.family: m for m in NATIVE_PACKAGING_MAPPINGS
}
_NATIVE_FORMAT_MAP: dict[str, NativePackagingMapping] = {
    m.format: m for m in NATIVE_PACKAGING_MAPPINGS
}
_NATIVE_ADAPTER_MAP: dict[str, NativePackagingMapping] = {
    m.canonical_adapter: m for m in NATIVE_PACKAGING_MAPPINGS
}

NATIVE_FAMILY_TO_MAPPING: Mapping[str, NativePackagingMapping] = types.MappingProxyType(_NATIVE_FAMILY_MAP)
NATIVE_FORMAT_TO_MAPPING: Mapping[str, NativePackagingMapping] = types.MappingProxyType(_NATIVE_FORMAT_MAP)
NATIVE_ADAPTER_TO_MAPPING: Mapping[str, NativePackagingMapping] = types.MappingProxyType(_NATIVE_ADAPTER_MAP)

NATIVE_FAMILIES: frozenset[str] = frozenset(_NATIVE_FAMILY_MAP.keys())
NATIVE_FORMATS: frozenset[str] = frozenset(_NATIVE_FORMAT_MAP.keys())
CANONICAL_PUBLICATION_ADAPTERS: frozenset[str] = frozenset(_NATIVE_ADAPTER_MAP.keys())
NATIVE_REVISION_SCHEMES: frozenset[str] = frozenset(m.revision_scheme for m in NATIVE_PACKAGING_MAPPINGS)


def get_native_packaging_mapping(key: str) -> NativePackagingMapping:
    """Retrieve explicit native packaging mapping by family, format, or canonical adapter.

    Fails closed with UNKNOWN_ADAPTER for unrecognized identifiers.
    """
    if not isinstance(key, str):
        raise ContractError("UNKNOWN_ADAPTER", f"Invalid native packaging key type: {type(key)}")
    if key in _NATIVE_FAMILY_MAP:
        return _NATIVE_FAMILY_MAP[key]
    if key in _NATIVE_FORMAT_MAP:
        return _NATIVE_FORMAT_MAP[key]
    if key in _NATIVE_ADAPTER_MAP:
        return _NATIVE_ADAPTER_MAP[key]
    raise ContractError("UNKNOWN_ADAPTER", f"Unknown native packaging identifier: {key}")


def resolve_canonical_publication_adapter(key: str) -> str:
    """Resolve native family, format, or adapter to canonical publication adapter (apt, dnf, pacman)."""
    return get_native_packaging_mapping(key).canonical_adapter


def resolve_native_revision_scheme(key: str) -> str:
    """Resolve native family, format, or adapter to revision scheme (apt-revision, rpm-release, pkgrel)."""
    return get_native_packaging_mapping(key).revision_scheme


def resolve_qualification_gate(key: str) -> str:
    """Resolve native family, format, or adapter to qualification gate identity (apt, dnf, pacman)."""
    return get_native_packaging_mapping(key).qualification_gate


def resolve_qualification_scope(key: str) -> str:
    """Resolve native family, format, or adapter to qualification scope (debian.candidate-inventory, rpm.candidate-inventory, pacman.candidate-inventory)."""
    return f"{get_native_packaging_mapping(key).format}.candidate-inventory"


# Exact packaging classifications
PURE_JS_CLI: str = "pure-js-cli"
NATIVE_NODE_CLI: str = "native-node-cli"
NATIVE_DESKTOP: str = "native-desktop"

ALL_PACKAGING_CLASSES: frozenset[str] = frozenset({
    PURE_JS_CLI,
    NATIVE_NODE_CLI,
    NATIVE_DESKTOP,
})

# Exact product mapping - unknown identities fail closed
_RAW_PRODUCT_PACKAGING_CLASSES: dict[str, str] = {
    "theme-forge-stellar-loom": PURE_JS_CLI,
    "theme-forge-solar-sail": PURE_JS_CLI,
    "theme-forge-stellar-burst": NATIVE_NODE_CLI,
    "theme-forge-nebular-fusion": NATIVE_DESKTOP,
}

PRODUCT_PACKAGING_CLASSES: Mapping[str, str] = types.MappingProxyType(
    _RAW_PRODUCT_PACKAGING_CLASSES
)


def get_product_class(product_id: str) -> str:
    """Retrieve packaging classification for an exact product identity.

    Fails closed with UNKNOWN_PRODUCT for any unrecognized identity.
    """
    if not isinstance(product_id, str) or product_id not in PRODUCT_PACKAGING_CLASSES:
        raise ContractError(
            "UNKNOWN_PRODUCT",
            "Unknown product packaging identity",
        )
    return PRODUCT_PACKAGING_CLASSES[product_id]


def is_pure_js_cli(product_id: str) -> bool:
    """True if product is classified as pure-js-cli."""
    return get_product_class(product_id) == PURE_JS_CLI


def is_native_node_cli(product_id: str) -> bool:
    """True if product is classified as native-node-cli."""
    return get_product_class(product_id) == NATIVE_NODE_CLI


def is_native_desktop(product_id: str) -> bool:
    """True if product is classified as native-desktop."""
    return get_product_class(product_id) == NATIVE_DESKTOP


def is_native_product(product_id: str) -> bool:
    """True if product has native components (native-node-cli or native-desktop)."""
    cls = get_product_class(product_id)
    return cls in (NATIVE_NODE_CLI, NATIVE_DESKTOP)


_SUPPORTED_ARCHITECTURES: dict[str, dict[str, frozenset[str]]] = {
    "pypi": {
        PURE_JS_CLI: frozenset({"any"}),
        NATIVE_NODE_CLI: frozenset({"macosx_13_0_arm64", "linux_x86_64", "linux_aarch64"}),
        NATIVE_DESKTOP: frozenset({"macosx_13_0_arm64", "linux_x86_64", "linux_aarch64"}),
    },
    "nix": {kind: frozenset({"aarch64-darwin", "x86_64-linux", "aarch64-linux"}) for kind in ALL_PACKAGING_CLASSES},
    "pacman": {
        PURE_JS_CLI: frozenset({"any"}),
        NATIVE_NODE_CLI: frozenset({"x86_64"}),
        NATIVE_DESKTOP: frozenset({"x86_64"}),
    },
    "rpm": {
        PURE_JS_CLI: frozenset({"noarch"}),
        NATIVE_NODE_CLI: frozenset({"x86_64", "aarch64"}),
        NATIVE_DESKTOP: frozenset({"x86_64", "aarch64"}),
    },
    "debian": {
        PURE_JS_CLI: frozenset({"all"}),
        NATIVE_NODE_CLI: frozenset({"amd64", "arm64"}),
        NATIVE_DESKTOP: frozenset({"amd64", "arm64"}),
    },
}


def supported_architectures(product_id: str, adapter: str) -> frozenset[str]:
    """Return supported packaging architectures for an exact product and adapter."""
    p_class = get_product_class(product_id)
    adapter_key = "debian" if adapter in ("debian", "apt", "deb") else "rpm" if adapter == "dnf" else "pypi" if adapter == "wheels" else adapter
    if adapter_key not in _SUPPORTED_ARCHITECTURES:
        raise ContractError(
            "UNSUPPORTED_PLATFORM",
            f"Unsupported packaging adapter: {adapter}",
            details={"product": product_id},
        )
    return _SUPPORTED_ARCHITECTURES[adapter_key][p_class]


def packaging_system_for_arch(adapter: str, arch: str) -> str:
    """Resolve Linux platform system triple for a native packaging architecture."""
    arch_norm = arch.strip().lower()
    adapter_key = "debian" if adapter in ("debian", "apt", "deb") else adapter

    if adapter_key == "pacman":
        if arch_norm == "x86_64":
            return "x86_64-linux"
    elif adapter_key == "rpm":
        if arch_norm == "x86_64":
            return "x86_64-linux"
        elif arch_norm == "aarch64":
            return "aarch64-linux"
    elif adapter_key == "debian":
        if arch_norm == "amd64":
            return "x86_64-linux"
        elif arch_norm == "arm64":
            return "aarch64-linux"

    raise ContractError(
        "INVALID_ARCHITECTURE",
        f"Cannot resolve native system for adapter {adapter} and architecture {arch}",
        details={"system": arch},
    )


def extract_package_arch(filename: str) -> str | None:
    """Extract architecture string from package filename across pacman, RPM, and deb."""
    if filename.endswith(".deb"):
        parts = filename[:-4].split("_")
        return parts[-1] if len(parts) >= 2 else None
    if filename.endswith(".rpm"):
        parts = filename[:-4].rsplit(".", 1)
        return parts[-1] if len(parts) >= 2 else None
    if ".pkg.tar" in filename:
        base = filename.split(".pkg.tar")[0]
        parts = base.rsplit("-", 1)
        return parts[-1] if len(parts) >= 2 else None
    return None
