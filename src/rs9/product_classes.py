"""Explicit exact-product packaging classification and architecture contracts."""

from __future__ import annotations

import types
from typing import Mapping

from rs9.errors import ContractError

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
