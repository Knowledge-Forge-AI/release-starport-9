"""Unit tests for product packaging classification and architecture contracts."""

from __future__ import annotations

import unittest

from rs9.errors import ContractError
from rs9.product_classes import (
    ALL_PACKAGING_CLASSES,
    NATIVE_DESKTOP,
    NATIVE_NODE_CLI,
    PURE_JS_CLI,
    extract_package_arch,
    get_product_class,
    is_native_desktop,
    is_native_node_cli,
    is_native_product,
    is_pure_js_cli,
    packaging_system_for_arch,
    supported_architectures,
)


class ProductClassesTests(unittest.TestCase):
    def test_product_class_definitions(self):
        self.assertEqual(ALL_PACKAGING_CLASSES, {"pure-js-cli", "native-node-cli", "native-desktop"})
        self.assertEqual(get_product_class("theme-forge-stellar-loom"), PURE_JS_CLI)
        self.assertEqual(get_product_class("theme-forge-solar-sail"), PURE_JS_CLI)
        self.assertEqual(get_product_class("theme-forge-stellar-burst"), NATIVE_NODE_CLI)
        self.assertEqual(get_product_class("theme-forge-nebular-fusion"), NATIVE_DESKTOP)

    def test_unknown_product_fails_closed(self):
        with self.assertRaises(ContractError) as caught:
            get_product_class("unknown-product-xyz")
        self.assertEqual(caught.exception.code, "UNKNOWN_PRODUCT")

        with self.assertRaises(ContractError) as caught2:
            get_product_class("")
        self.assertEqual(caught2.exception.code, "UNKNOWN_PRODUCT")

    def test_product_classification_predicates(self):
        self.assertTrue(is_pure_js_cli("theme-forge-stellar-loom"))
        self.assertTrue(is_pure_js_cli("theme-forge-solar-sail"))
        self.assertFalse(is_pure_js_cli("theme-forge-stellar-burst"))
        self.assertFalse(is_pure_js_cli("theme-forge-nebular-fusion"))

        self.assertTrue(is_native_node_cli("theme-forge-stellar-burst"))
        self.assertFalse(is_native_node_cli("theme-forge-nebular-fusion"))
        self.assertFalse(is_native_node_cli("theme-forge-stellar-loom"))

        self.assertTrue(is_native_desktop("theme-forge-nebular-fusion"))
        self.assertFalse(is_native_desktop("theme-forge-stellar-burst"))

        self.assertTrue(is_native_product("theme-forge-stellar-burst"))
        self.assertTrue(is_native_product("theme-forge-nebular-fusion"))
        self.assertFalse(is_native_product("theme-forge-stellar-loom"))
        self.assertFalse(is_native_product("theme-forge-solar-sail"))

    def test_supported_architectures(self):
        # Pacman
        self.assertEqual(supported_architectures("theme-forge-stellar-loom", "pacman"), {"any"})
        self.assertEqual(supported_architectures("theme-forge-solar-sail", "pacman"), {"any"})
        self.assertEqual(supported_architectures("theme-forge-stellar-burst", "pacman"), {"x86_64"})
        self.assertEqual(supported_architectures("theme-forge-nebular-fusion", "pacman"), {"x86_64"})

        # RPM
        self.assertEqual(supported_architectures("theme-forge-stellar-loom", "rpm"), {"noarch"})
        self.assertEqual(supported_architectures("theme-forge-stellar-burst", "rpm"), {"x86_64", "aarch64"})
        self.assertEqual(supported_architectures("theme-forge-nebular-fusion", "rpm"), {"x86_64", "aarch64"})

        # Debian
        self.assertEqual(supported_architectures("theme-forge-stellar-loom", "debian"), {"all"})
        self.assertEqual(supported_architectures("theme-forge-stellar-burst", "debian"), {"amd64", "arm64"})
        self.assertEqual(supported_architectures("theme-forge-nebular-fusion", "debian"), {"amd64", "arm64"})
        self.assertEqual(supported_architectures("theme-forge-stellar-burst", "pypi"),
                         {"macosx_13_0_arm64", "linux_x86_64", "linux_aarch64"})
        self.assertEqual(supported_architectures("theme-forge-stellar-burst", "nix"),
                         {"aarch64-darwin", "x86_64-linux", "aarch64-linux"})

    def test_packaging_system_resolution(self):
        self.assertEqual(packaging_system_for_arch("pacman", "x86_64"), "x86_64-linux")
        self.assertEqual(packaging_system_for_arch("rpm", "x86_64"), "x86_64-linux")
        self.assertEqual(packaging_system_for_arch("rpm", "aarch64"), "aarch64-linux")
        self.assertEqual(packaging_system_for_arch("debian", "amd64"), "x86_64-linux")
        self.assertEqual(packaging_system_for_arch("debian", "arm64"), "aarch64-linux")

        with self.assertRaises(ContractError) as caught:
            packaging_system_for_arch("pacman", "any")
        self.assertEqual(caught.exception.code, "INVALID_ARCHITECTURE")

    def test_extract_package_arch(self):
        self.assertEqual(extract_package_arch("theme-forge-stellar-burst_0.6.1-1_amd64.deb"), "amd64")
        self.assertEqual(extract_package_arch("theme-forge-stellar-burst_0.6.1-1_arm64.deb"), "arm64")
        self.assertEqual(extract_package_arch("theme-forge-stellar-loom_0.4.0-1_all.deb"), "all")
        self.assertEqual(extract_package_arch("theme-forge-stellar-burst-0.6.1-1.fc43.x86_64.rpm"), "x86_64")
        self.assertEqual(extract_package_arch("theme-forge-stellar-burst-0.6.1-1.fc43.aarch64.rpm"), "aarch64")
        self.assertEqual(extract_package_arch("theme-forge-stellar-loom-0.4.0-1.fc43.noarch.rpm"), "noarch")
        self.assertEqual(extract_package_arch("theme-forge-stellar-burst-0.6.1-1-x86_64.pkg.tar.zst"), "x86_64")
        self.assertEqual(extract_package_arch("theme-forge-stellar-loom-0.4.0-1-any.pkg.tar.zst"), "any")
        self.assertIsNone(extract_package_arch("other-file.txt"))


if __name__ == "__main__":
    unittest.main()
