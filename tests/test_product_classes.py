"""Unit tests for product packaging classification and architecture contracts."""

from __future__ import annotations

import unittest

from rs9.adapter_gates import mandatory_gates
from rs9.errors import ContractError
from rs9.product_classes import (
    ALL_PACKAGING_CLASSES,
    CANONICAL_PUBLICATION_ADAPTERS,
    NATIVE_ADAPTER_TO_MAPPING,
    NATIVE_DESKTOP,
    NATIVE_FAMILIES,
    NATIVE_FAMILY_TO_MAPPING,
    NATIVE_FORMAT_TO_MAPPING,
    NATIVE_FORMATS,
    NATIVE_NODE_CLI,
    NATIVE_PACKAGING_MAPPINGS,
    NATIVE_REVISION_SCHEMES,
    PURE_JS_CLI,
    NativePackagingMapping,
    extract_package_arch,
    get_native_packaging_mapping,
    get_product_class,
    is_native_desktop,
    is_native_node_cli,
    is_native_product,
    is_pure_js_cli,
    packaging_system_for_arch,
    resolve_canonical_publication_adapter,
    resolve_native_revision_scheme,
    resolve_qualification_gate,
    resolve_qualification_scope,
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

    def test_native_packaging_mappings_centralized(self):
        self.assertEqual(len(NATIVE_PACKAGING_MAPPINGS), 3)
        self.assertEqual(
            NATIVE_PACKAGING_MAPPINGS,
            (
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
            ),
        )
        self.assertEqual(NATIVE_FAMILIES, {"deb", "rpm", "pacman"})
        self.assertEqual(NATIVE_FORMATS, {"debian", "rpm", "pacman"})
        self.assertEqual(CANONICAL_PUBLICATION_ADAPTERS, {"apt", "dnf", "pacman"})
        self.assertEqual(NATIVE_REVISION_SCHEMES, {"apt-revision", "rpm-release", "pkgrel"})

        # Mapping lookups by family, format, or canonical adapter return equivalent mappings
        deb_map = NATIVE_PACKAGING_MAPPINGS[0]
        self.assertEqual(get_native_packaging_mapping("deb"), deb_map)
        self.assertEqual(get_native_packaging_mapping("debian"), deb_map)
        self.assertEqual(get_native_packaging_mapping("apt"), deb_map)

        rpm_map = NATIVE_PACKAGING_MAPPINGS[1]
        self.assertEqual(get_native_packaging_mapping("rpm"), rpm_map)
        self.assertEqual(get_native_packaging_mapping("dnf"), rpm_map)

        pac_map = NATIVE_PACKAGING_MAPPINGS[2]
        self.assertEqual(get_native_packaging_mapping("pacman"), pac_map)

        # Resolution helpers
        self.assertEqual(resolve_canonical_publication_adapter("deb"), "apt")
        self.assertEqual(resolve_canonical_publication_adapter("debian"), "apt")
        self.assertEqual(resolve_canonical_publication_adapter("apt"), "apt")
        self.assertEqual(resolve_canonical_publication_adapter("rpm"), "dnf")
        self.assertEqual(resolve_canonical_publication_adapter("dnf"), "dnf")
        self.assertEqual(resolve_canonical_publication_adapter("pacman"), "pacman")

        self.assertEqual(resolve_native_revision_scheme("deb"), "apt-revision")
        self.assertEqual(resolve_native_revision_scheme("debian"), "apt-revision")
        self.assertEqual(resolve_native_revision_scheme("apt"), "apt-revision")
        self.assertEqual(resolve_native_revision_scheme("rpm"), "rpm-release")
        self.assertEqual(resolve_native_revision_scheme("dnf"), "rpm-release")
        self.assertEqual(resolve_native_revision_scheme("pacman"), "pkgrel")

        self.assertEqual(resolve_qualification_gate("deb"), "apt")
        self.assertEqual(resolve_qualification_gate("debian"), "apt")
        self.assertEqual(resolve_qualification_gate("apt"), "apt")
        self.assertEqual(resolve_qualification_gate("rpm"), "dnf")
        self.assertEqual(resolve_qualification_gate("dnf"), "dnf")
        self.assertEqual(resolve_qualification_gate("pacman"), "pacman")

        self.assertEqual(resolve_qualification_scope("deb"), "debian.candidate-inventory")
        self.assertEqual(resolve_qualification_scope("debian"), "debian.candidate-inventory")
        self.assertEqual(resolve_qualification_scope("apt"), "debian.candidate-inventory")
        self.assertEqual(resolve_qualification_scope("rpm"), "rpm.candidate-inventory")
        self.assertEqual(resolve_qualification_scope("dnf"), "rpm.candidate-inventory")
        self.assertEqual(resolve_qualification_scope("pacman"), "pacman.candidate-inventory")

        # Unknown identifiers rejected
        for bad in ("invented", "unknown", "pypi", "nix", "wheels", "", 42):
            with self.subTest(bad=bad), self.assertRaises(ContractError) as caught:
                get_native_packaging_mapping(bad)
            self.assertEqual(caught.exception.code, "UNKNOWN_ADAPTER")

    def test_supported_architectures_equivalence_and_rejections(self):
        products = (
            "theme-forge-stellar-loom",
            "theme-forge-solar-sail",
            "theme-forge-stellar-burst",
            "theme-forge-nebular-fusion",
        )
        for product in products:
            # debian, apt, deb equivalence
            deb_archs = supported_architectures(product, "debian")
            self.assertEqual(supported_architectures(product, "apt"), deb_archs)
            self.assertEqual(supported_architectures(product, "deb"), deb_archs)

            # rpm, dnf equivalence
            rpm_archs = supported_architectures(product, "rpm")
            self.assertEqual(supported_architectures(product, "dnf"), rpm_archs)

            # pypi, wheels equivalence
            pypi_archs = supported_architectures(product, "pypi")
            self.assertEqual(supported_architectures(product, "wheels"), pypi_archs)

            # rejection of unsupported / unknown adapters
            for bad in ("invented", "unknown", "pkg", "rpm-release", ""):
                with self.subTest(product=product, bad=bad), self.assertRaises(ContractError) as caught:
                    supported_architectures(product, bad)
                self.assertEqual(caught.exception.code, "UNSUPPORTED_PLATFORM")

    def test_packaging_system_for_arch_equivalence_and_rejections(self):
        # debian, apt, deb equivalence
        self.assertEqual(packaging_system_for_arch("debian", "amd64"), "x86_64-linux")
        self.assertEqual(packaging_system_for_arch("apt", "amd64"), "x86_64-linux")
        self.assertEqual(packaging_system_for_arch("deb", "amd64"), "x86_64-linux")
        self.assertEqual(packaging_system_for_arch("debian", "arm64"), "aarch64-linux")
        self.assertEqual(packaging_system_for_arch("apt", "arm64"), "aarch64-linux")
        self.assertEqual(packaging_system_for_arch("deb", "arm64"), "aarch64-linux")

        # rpm equivalence
        self.assertEqual(packaging_system_for_arch("rpm", "x86_64"), "x86_64-linux")
        self.assertEqual(packaging_system_for_arch("rpm", "aarch64"), "aarch64-linux")

        # pacman equivalence
        self.assertEqual(packaging_system_for_arch("pacman", "x86_64"), "x86_64-linux")

        # Rejection: architecture helper aliases remain unchanged, key sets differ.
        # Specifically, dnf is NOT an accepted alias for packaging_system_for_arch:
        with self.assertRaises(ContractError) as caught_dnf:
            packaging_system_for_arch("dnf", "x86_64")
        self.assertEqual(caught_dnf.exception.code, "INVALID_ARCHITECTURE")

        # Invalid architectures for adapter rejected
        for bad_adapter, bad_arch in (
            ("pacman", "any"),
            ("pacman", "aarch64"),
            ("rpm", "amd64"),
            ("rpm", "noarch"),
            ("debian", "x86_64"),
            ("debian", "all"),
            ("pypi", "any"),
            ("invented", "x86_64"),
        ):
            with self.subTest(adapter=bad_adapter, arch=bad_arch), self.assertRaises(ContractError) as caught:
                packaging_system_for_arch(bad_adapter, bad_arch)
            self.assertEqual(caught.exception.code, "INVALID_ARCHITECTURE")

    def test_adapter_gates_stays_canonical_only_and_rejects_format_names(self):
        # Native packaging format names (debian, rpm, deb) are rejected by mandatory_gates
        intent_cli = {"runtime": {"kind": "cli"}}
        intent_native = {"runtime": {"kind": "native"}}

        for format_name in ("debian", "rpm", "deb", "invented", "unknown"):
            with self.subTest(format_name=format_name), self.assertRaises(ContractError) as caught:
                mandatory_gates(intent_cli, format_name)
            self.assertEqual(caught.exception.code, "ADAPTER_GATES")

        # Canonical publication adapters (apt, dnf, pacman, pypi) succeed and return full gates
        apt_gates = mandatory_gates(intent_cli, "apt")
        dnf_gates = mandatory_gates(intent_cli, "dnf")
        pacman_gates = mandatory_gates(intent_cli, "pacman")
        pypi_gates = mandatory_gates(intent_cli, "pypi")

        self.assertIn("domain.tls", apt_gates)
        self.assertIn("domain.tls", dnf_gates)
        self.assertIn("domain.tls", pacman_gates)
        self.assertIn("pypi.trusted-publisher", pypi_gates)

        # Native runtime gates include desktop.integration
        apt_native_gates = mandatory_gates(intent_native, "apt")
        self.assertIn("desktop.integration", apt_native_gates)
        self.assertIn("nebular.sidecar-verifier", apt_native_gates)


if __name__ == "__main__":
    unittest.main()
