"""Tests for explicit platform contract namespace and strict platform selector."""
from __future__ import annotations

import unittest

from rs9.errors import ContractError
from rs9.hosted_platforms import (
    PLATFORM_TABLE,
    SUPPORTED_WHEEL_SYSTEMS,
    TRIPLE_TO_SYSTEM,
    PlatformContract,
    platform_contract,
    select_payload,
    system_from_target_triple,
)


class HostedPlatformsTests(unittest.TestCase):
    def test_all_three_platform_contracts(self) -> None:
        """Verify explicit one-way hosted system -> native triple -> asset platform -> wheel tag for all 3."""
        self.assertEqual(SUPPORTED_WHEEL_SYSTEMS, {"aarch64-darwin", "x86_64-linux", "aarch64-linux"})

        # 1. aarch64-darwin (wheel_tag/platform_tag pending until Info.plist computation)
        darwin = platform_contract("aarch64-darwin")
        self.assertIsInstance(darwin, PlatformContract)
        self.assertEqual(darwin.system, "aarch64-darwin")
        self.assertEqual(darwin.target_triple, "aarch64-apple-darwin")
        self.assertEqual(darwin.asset_platform, "aarch64-darwin")
        self.assertEqual(darwin.wheel_tag, "pending")
        self.assertEqual(darwin.platform_tag, "pending")
        self.assertEqual(darwin.native_prebuild_key, "darwin-arm64")
        self.assertEqual(darwin.expected_binary_arch, "arm64")
        self.assertEqual(darwin.binary_arch, "arm64")
        # dict access parity
        self.assertEqual(darwin["system"], "aarch64-darwin")
        self.assertEqual(darwin["target_triple"], "aarch64-apple-darwin")
        self.assertEqual(darwin["asset_platform"], "aarch64-darwin")
        self.assertEqual(darwin["wheel_tag"], "pending")
        self.assertEqual(darwin["native_prebuild_key"], "darwin-arm64")
        self.assertEqual(darwin["expected_binary_arch"], "arm64")
        self.assertEqual(darwin["binary_arch"], "arm64")

        # Immutability verification
        with self.assertRaises(TypeError):
            darwin["wheel_tag"] = "tampered"
        with self.assertRaises(TypeError):
            PLATFORM_TABLE["aarch64-darwin"] = darwin  # type: ignore

        # 2. x86_64-linux
        x86_linux = platform_contract("x86_64-linux")
        self.assertIsInstance(x86_linux, PlatformContract)
        self.assertEqual(x86_linux.system, "x86_64-linux")
        self.assertEqual(x86_linux.target_triple, "x86_64-unknown-linux-gnu")
        self.assertEqual(x86_linux.asset_platform, "x86_64-linux")
        self.assertEqual(x86_linux.wheel_tag, "py3-none-linux_x86_64")
        self.assertEqual(x86_linux.platform_tag, "linux_x86_64")
        self.assertEqual(x86_linux.native_prebuild_key, "linux-x64-gnu")
        self.assertEqual(x86_linux.expected_binary_arch, "x86_64")
        self.assertEqual(x86_linux.binary_arch, "x86_64")
        self.assertEqual(x86_linux["system"], "x86_64-linux")
        self.assertEqual(x86_linux["target_triple"], "x86_64-unknown-linux-gnu")
        self.assertEqual(x86_linux["native_prebuild_key"], "linux-x64-gnu")
        self.assertEqual(x86_linux["expected_binary_arch"], "x86_64")
        self.assertEqual(x86_linux["binary_arch"], "x86_64")

        # 3. aarch64-linux
        arm_linux = platform_contract("aarch64-linux")
        self.assertIsInstance(arm_linux, PlatformContract)
        self.assertEqual(arm_linux.system, "aarch64-linux")
        self.assertEqual(arm_linux.target_triple, "aarch64-unknown-linux-gnu")
        self.assertEqual(arm_linux.asset_platform, "aarch64-linux")
        self.assertEqual(arm_linux.wheel_tag, "py3-none-linux_aarch64")
        self.assertEqual(arm_linux.platform_tag, "linux_aarch64")
        self.assertEqual(arm_linux.native_prebuild_key, "linux-arm64-gnu")
        self.assertEqual(arm_linux.expected_binary_arch, "aarch64")
        self.assertEqual(arm_linux.binary_arch, "aarch64")
        self.assertEqual(arm_linux["system"], "aarch64-linux")
        self.assertEqual(arm_linux["target_triple"], "aarch64-unknown-linux-gnu")
        self.assertEqual(arm_linux["native_prebuild_key"], "linux-arm64-gnu")
        self.assertEqual(arm_linux["expected_binary_arch"], "aarch64")
        self.assertEqual(arm_linux["binary_arch"], "aarch64")

    def test_native_triple_rejected_by_platform_contract(self) -> None:
        """Native target triples are strictly rejected by platform_contract to avoid namespace mixing."""
        for triple in ("aarch64-apple-darwin", "x86_64-unknown-linux-gnu", "aarch64-unknown-linux-gnu"):
            with self.assertRaises(ContractError) as ctx:
                platform_contract(triple)
            self.assertEqual(ctx.exception.code, "INVALID_ARCHITECTURE")

    def test_system_from_target_triple_conversion(self) -> None:
        """Explicit named conversion function converts target triples at the legacy API boundary."""
        self.assertEqual(system_from_target_triple("aarch64-apple-darwin"), "aarch64-darwin")
        self.assertEqual(system_from_target_triple("x86_64-unknown-linux-gnu"), "x86_64-linux")
        self.assertEqual(system_from_target_triple("aarch64-unknown-linux-gnu"), "aarch64-linux")
        with self.assertRaises(ContractError) as ctx:
            system_from_target_triple("x86_64-pc-windows-msvc")
        self.assertEqual(ctx.exception.code, "INVALID_ARCHITECTURE")

    def test_unsupported_system_raises_contract_error(self) -> None:
        with self.assertRaises(ContractError) as ctx:
            platform_contract("x86_64-windows")
        self.assertEqual(ctx.exception.code, "INVALID_ARCHITECTURE")
        self.assertEqual(ctx.exception.details.get("system"), "x86_64-windows")

    def test_select_payload_strict_platforms_matching(self) -> None:
        """Payload selection uses exact platforms list, not name substrings."""
        capture = {
            "payloads": [
                {
                    "id": "darwin-arm64",
                    "name": "theme-forge-nebular-fusion-v0.6.1-aarch64-apple-darwin.app.tar.gz",
                    "platforms": ["aarch64-darwin"],
                },
                {
                    "id": "linux-x64",
                    "name": "theme-forge-nebular-fusion-v0.6.1-x86_64-unknown-linux-gnu.tar.gz",
                    "platforms": ["x86_64-linux"],
                },
                {
                    "id": "linux-arm64",
                    "name": "theme-forge-nebular-fusion-v0.6.1-aarch64-unknown-linux-gnu.tar.gz",
                    "platforms": ["aarch64-linux"],
                },
            ]
        }

        # Darwin selection
        darwin_selected = select_payload(capture, "aarch64-darwin")
        self.assertEqual(darwin_selected["id"], "darwin-arm64")

        # Linux x86_64 selection
        x86_selected = select_payload(capture, "x86_64-linux")
        self.assertEqual(x86_selected["id"], "linux-x64")

        # Linux aarch64 selection
        arm_selected = select_payload(capture, "aarch64-linux")
        self.assertEqual(arm_selected["id"], "linux-arm64")

    def test_select_payload_no_name_substrings(self) -> None:
        """An asset with 'linux' in its name must NOT match if platforms doesn't contain the asset platform."""
        capture = {
            "payloads": [
                {
                    "id": "misleading-name",
                    "name": "something-linux-x86_64.tar.gz",
                    "platforms": ["unsupported-platform"],
                }
            ]
        }
        with self.assertRaises(ContractError) as ctx:
            select_payload(capture, "x86_64-linux")
        self.assertEqual(ctx.exception.code, "MISSING_ASSET")
        self.assertEqual(ctx.exception.details.get("asset_platform"), "x86_64-linux")

    def test_select_payload_allow_any(self) -> None:
        """Universal 'any' platforms payload behavior."""
        capture = {
            "payloads": [
                {
                    "id": "package",
                    "name": "pure-js-0.6.1.tgz",
                    "platforms": ["any"],
                }
            ]
        }
        # allow_any=False fails closed
        with self.assertRaises(ContractError) as ctx:
            select_payload(capture, "aarch64-darwin", allow_any=False)
        self.assertEqual(ctx.exception.code, "MISSING_ASSET")

        # allow_any=True succeeds
        selected = select_payload(capture, "aarch64-darwin", allow_any=True)
        self.assertEqual(selected["id"], "package")

    def test_select_payload_duplicate_fails_closed(self) -> None:
        capture = {
            "payloads": [
                {"id": "p1", "platforms": ["x86_64-linux"]},
                {"id": "p2", "platforms": ["x86_64-linux"]},
            ]
        }
        with self.assertRaises(ContractError) as ctx:
            select_payload(capture, "x86_64-linux")
        self.assertEqual(ctx.exception.code, "DUPLICATE_ASSET")


if __name__ == "__main__":
    unittest.main()
