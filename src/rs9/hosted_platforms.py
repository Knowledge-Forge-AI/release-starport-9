"""Explicit platform contract table and strict platforms-based payload selection.

Maintains an explicit one-way mapping from hosted system to native triple,
asset platform, and truthful wheel tag. Mechanically determines payload platform
labels strictly from record schema/fixtures without name substring matching.
"""
from __future__ import annotations

from dataclasses import dataclass
import types
from typing import Any, Mapping

from rs9.errors import ContractError


@dataclass(frozen=True)
class PlatformContract(Mapping):
    """Frozen one-way namespace row with read-only mapping compatibility."""
    system: str
    target_triple: str
    asset_platform: str
    wheel_tag: str
    platform_tag: str
    native_prebuild_key: str
    expected_binary_arch: str

    @property
    def binary_arch(self) -> str:
        return self.expected_binary_arch

    def __getitem__(self, key):
        if key not in (
            "system", "target_triple", "asset_platform", "wheel_tag", "platform_tag",
            "native_prebuild_key", "expected_binary_arch", "binary_arch",
        ):
            raise KeyError(key)
        return getattr(self, key)

    def __iter__(self):
        return iter((
            "system", "target_triple", "asset_platform", "wheel_tag", "platform_tag",
            "native_prebuild_key", "expected_binary_arch",
        ))

    def __len__(self):
        return 7


# Explicit one-way hosted system -> native triple -> asset platform -> wheel tag table.
# Darwin wheel_tag and platform_tag are marked 'pending' prior to Info.plist deployment floor computation.
_RAW_PLATFORM_TABLE: dict[str, PlatformContract] = {
    "aarch64-darwin": PlatformContract(
        system="aarch64-darwin",
        target_triple="aarch64-apple-darwin",
        asset_platform="aarch64-darwin",
        wheel_tag="pending",
        platform_tag="pending",
        native_prebuild_key="darwin-arm64",
        expected_binary_arch="arm64",
    ),
    "x86_64-linux": PlatformContract(
        system="x86_64-linux",
        target_triple="x86_64-unknown-linux-gnu",
        asset_platform="x86_64-linux",
        wheel_tag="py3-none-linux_x86_64",
        platform_tag="linux_x86_64",
        native_prebuild_key="linux-x64-gnu",
        expected_binary_arch="x86_64",
    ),
    "aarch64-linux": PlatformContract(
        system="aarch64-linux",
        target_triple="aarch64-unknown-linux-gnu",
        asset_platform="aarch64-linux",
        wheel_tag="py3-none-linux_aarch64",
        platform_tag="linux_aarch64",
        native_prebuild_key="linux-arm64-gnu",
        expected_binary_arch="aarch64",
    ),
}

PLATFORM_TABLE: Mapping[str, PlatformContract] = types.MappingProxyType(_RAW_PLATFORM_TABLE)

SUPPORTED_WHEEL_SYSTEMS: frozenset[str] = frozenset(PLATFORM_TABLE.keys())

TRIPLE_TO_SYSTEM: Mapping[str, str] = types.MappingProxyType({
    row.target_triple: row.system for row in PLATFORM_TABLE.values()
})


def platform_contract(system: str) -> PlatformContract:
    """Return explicit platform contract namespace row for a hosted system.

    Accepts only hosted systems ('aarch64-darwin', 'x86_64-linux', 'aarch64-linux').
    Native target triples are rejected to prevent namespace mixing.
    """
    if system in PLATFORM_TABLE:
        return PLATFORM_TABLE[system]
    raise ContractError(
        "INVALID_ARCHITECTURE",
        f"Unsupported wheel system: {system}",
        details={"system": system},
    )


def system_from_target_triple(target_triple: str) -> str:
    """Convert legacy target triple to hosted system namespace. Only used at legacy boundary."""
    if target_triple in TRIPLE_TO_SYSTEM:
        return TRIPLE_TO_SYSTEM[target_triple]
    raise ContractError(
        "INVALID_ARCHITECTURE",
        f"Unsupported target triple: {target_triple}",
        details={"target_triple": target_triple},
    )


def select_payload(
    capture: Any,
    system: str,
    allow_any: bool = False,
) -> dict[str, Any]:
    """Select release payload matching the exact platform contract without name substrings.

    Payload platform labels are mechanically determined from the record schema/fixtures.
    """
    contract = platform_contract(system)
    target_platform = contract.asset_platform

    # Extract payloads list from ReleaseCapture or record dictionary
    if hasattr(capture, "record"):
        payloads = capture.record.get("payloads", [])
    elif isinstance(capture, dict):
        if "payloads" in capture:
            payloads = capture["payloads"]
        elif "record" in capture and isinstance(capture["record"], dict):
            payloads = capture["record"].get("payloads", [])
        else:
            payloads = []
    else:
        raise ContractError("INVALID_CAPTURE", "Expected ReleaseCapture or release record dictionary")

    if (not isinstance(payloads, list) or any(not isinstance(p, dict)
            or not isinstance(p.get("platforms"), list)
            or any(not isinstance(label, str) for label in p["platforms"]) for p in payloads)):
        raise ContractError("INVALID_CAPTURE", "Payload platform label lists required")

    # Strict platforms-based selection (no name substrings)
    exact_matches = [
        p for p in payloads
        if isinstance(p, dict) and target_platform in p.get("platforms", [])
    ]

    if len(exact_matches) == 1:
        return exact_matches[0]
    elif len(exact_matches) > 1:
        raise ContractError(
            "DUPLICATE_ASSET",
            f"Multiple payloads matched platform {target_platform}",
            details={
                "system": system,
                "asset_platform": target_platform,
                "target_triple": contract.target_triple,
            },
        )

    if allow_any:
        any_matches = [
            p for p in payloads
            if isinstance(p, dict) and "any" in p.get("platforms", [])
        ]
        if len(any_matches) == 1:
            return any_matches[0]
        elif len(any_matches) > 1:
            raise ContractError(
                "DUPLICATE_ASSET",
                "Multiple payloads matched platform 'any'",
                details={
                    "system": system,
                    "asset_platform": target_platform,
                    "target_triple": contract.target_triple,
                },
            )

    raise ContractError(
        "MISSING_ASSET",
        f"No payload asset found matching platform '{target_platform}' in release capture",
        details={
            "system": system,
            "asset_platform": target_platform,
            "target_triple": contract.target_triple,
            "wheel_tag": contract.wheel_tag,
        },
    )
