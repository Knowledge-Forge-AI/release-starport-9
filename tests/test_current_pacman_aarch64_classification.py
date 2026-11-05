"""Current-generation-only native pacman AArch64 classification and builder handoff.

Classification tests exercise the real product_classes functions. The handoff
tests run the real validate_build_inputs architecture/payload/prebuild selection
while patching only release authentication, bootstrap binding, archive inspection
and ELF parsing seams; they make no acceptance, native build or runtime claim.
"""

from __future__ import annotations

import hashlib
from pathlib import Path
import tempfile
import types
import unittest
from unittest.mock import patch

from rs9.build_native import validate_build_inputs
from rs9.burst_native import BURST_CLOSED_PREBUILDS, BURST_SYSTEM_TO_PREBUILD_KEY
from rs9.current_generation import CURRENT_GENERATION, HISTORICAL_GENERATION
from rs9.errors import ContractError
from rs9.product_classes import packaging_system_for_arch, supported_architectures

BURST = "theme-forge-stellar-burst"
NEBULAR = "theme-forge-nebular-fusion"
LOOM = "theme-forge-stellar-loom"
SOLAR = "theme-forge-solar-sail"
NATIVE = (BURST, NEBULAR)
PURE_JS = (LOOM, SOLAR)
ARM_PREBUILD = BURST_CLOSED_PREBUILDS["linux-arm64-gnu"]


class CurrentPacmanAarch64ClassificationTests(unittest.TestCase):
    def test_historical_default_is_unchanged(self):
        for product in NATIVE:
            with self.subTest(product=product):
                self.assertEqual(supported_architectures(product, "pacman"), {"x86_64"})
                self.assertEqual(
                    supported_architectures(product, "pacman", generation=HISTORICAL_GENERATION), {"x86_64"})
        for product in PURE_JS:
            with self.subTest(product=product):
                self.assertEqual(supported_architectures(product, "pacman"), {"any"})
                self.assertEqual(
                    supported_architectures(product, "pacman", generation=HISTORICAL_GENERATION), {"any"})

    def test_current_native_pacman_admits_aarch64(self):
        for product in NATIVE:
            with self.subTest(product=product):
                self.assertEqual(
                    supported_architectures(product, "pacman", generation=CURRENT_GENERATION),
                    {"x86_64", "aarch64"})

    def test_current_pure_js_pacman_stays_any(self):
        for product in PURE_JS:
            with self.subTest(product=product):
                archs = supported_architectures(product, "pacman", generation=CURRENT_GENERATION)
                self.assertEqual(archs, {"any"})
                self.assertNotIn("aarch64", archs)

    def test_current_does_not_widen_other_adapters(self):
        for product in (*NATIVE, *PURE_JS):
            for adapter in ("rpm", "dnf", "debian", "apt", "deb", "pypi", "wheels", "nix"):
                with self.subTest(product=product, adapter=adapter):
                    self.assertEqual(
                        supported_architectures(product, adapter, generation=CURRENT_GENERATION),
                        supported_architectures(product, adapter))

    def test_native_never_admits_any(self):
        for generation in (HISTORICAL_GENERATION, CURRENT_GENERATION):
            for product in NATIVE:
                with self.subTest(generation=generation, product=product):
                    self.assertNotIn("any", supported_architectures(product, "pacman", generation=generation))

    def test_pacman_system_mapping_historical(self):
        self.assertEqual(packaging_system_for_arch("pacman", "x86_64"), "x86_64-linux")
        self.assertEqual(
            packaging_system_for_arch("pacman", "x86_64", generation=HISTORICAL_GENERATION), "x86_64-linux")
        for arch in ("aarch64", "arm64", "any"):
            for kwargs in ({}, {"generation": HISTORICAL_GENERATION}):
                with self.subTest(arch=arch, kwargs=kwargs), self.assertRaises(ContractError) as caught:
                    packaging_system_for_arch("pacman", arch, **kwargs)
                self.assertEqual(caught.exception.code, "INVALID_ARCHITECTURE")

    def test_pacman_system_mapping_current(self):
        self.assertEqual(
            packaging_system_for_arch("pacman", "x86_64", generation=CURRENT_GENERATION), "x86_64-linux")
        self.assertEqual(
            packaging_system_for_arch("pacman", "aarch64", generation=CURRENT_GENERATION), "aarch64-linux")
        self.assertEqual(
            packaging_system_for_arch("pacman", " AArch64 ", generation=CURRENT_GENERATION), "aarch64-linux")
        self.assertEqual(BURST_SYSTEM_TO_PREBUILD_KEY["aarch64-linux"], "linux-arm64-gnu")
        for arch in ("arm64", "any", "armv7h", "riscv64"):
            with self.subTest(arch=arch), self.assertRaises(ContractError) as caught:
                packaging_system_for_arch("pacman", arch, generation=CURRENT_GENERATION)
            self.assertEqual(caught.exception.code, "INVALID_ARCHITECTURE")

    def test_other_adapter_system_mapping_unchanged_for_current(self):
        for adapter, arch in (("rpm", "x86_64"), ("rpm", "aarch64"), ("debian", "amd64"),
                              ("debian", "arm64"), ("apt", "arm64"), ("deb", "amd64")):
            with self.subTest(adapter=adapter, arch=arch):
                self.assertEqual(packaging_system_for_arch(adapter, arch, generation=CURRENT_GENERATION),
                                 packaging_system_for_arch(adapter, arch))
        with self.assertRaises(ContractError) as caught:
            packaging_system_for_arch("dnf", "aarch64", generation=CURRENT_GENERATION)
        self.assertEqual(caught.exception.code, "INVALID_ARCHITECTURE")

    def test_invalid_generation_fails_closed(self):
        for bad in ("theme-forge-current-202611", "", "current", None, 1):
            with self.subTest(generation=bad):
                with self.assertRaises(ContractError) as caught:
                    supported_architectures(BURST, "pacman", generation=bad)
                self.assertEqual(caught.exception.code, "GENERATION_SELECTION")
                with self.assertRaises(ContractError) as caught:
                    packaging_system_for_arch("pacman", "aarch64", generation=bad)
                self.assertEqual(caught.exception.code, "GENERATION_SELECTION")

    def test_unknown_product_and_adapter_still_fail_closed_for_current(self):
        with self.assertRaises(ContractError) as caught:
            supported_architectures("theme-forge-unknown", "pacman", generation=CURRENT_GENERATION)
        self.assertEqual(caught.exception.code, "UNKNOWN_PRODUCT")
        with self.assertRaises(ContractError) as caught:
            supported_architectures(BURST, "homebrew", generation=CURRENT_GENERATION)
        self.assertEqual(caught.exception.code, "UNSUPPORTED_PLATFORM")


def _payload(root: Path, payload_id: str, platforms: list[str]) -> dict:
    data = ("synthetic payload " + payload_id).encode()
    path = root / (payload_id + ".tar.gz")
    path.write_bytes(data)
    return {"id": payload_id, "name": path.name, "platforms": platforms, "root": "package",
            "sha256": hashlib.sha256(data).hexdigest(), "_path": path}


def _capture(root: Path, product: str, version: str, payloads: list[dict]):
    record = {"repository": {"full_name": "Knowledge-Forge-AI/" + product},
              "release": {"tag": "v" + version},
              "payloads": [{k: v for k, v in p.items() if k != "_path"} for p in payloads]}
    return types.SimpleNamespace(record=record, root=root, source={},
                                 archives={p["id"]: p["_path"] for p in payloads})


def _intent(product: str, version: str) -> dict:
    return {"project": {"id": product, "repository": "Knowledge-Forge-AI/" + product},
            "version": version, "tag": "v" + version,
            "license": {"expression": "AGPL-3.0-or-later"}}


class CurrentPacmanAarch64HandoffTests(unittest.TestCase):
    """Real selection logic in validate_build_inputs behind patched authentication seams."""

    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.systems: list[str] = []

        def prebuilds(files, origins, system, *, source_files=None):
            self.systems.append(system)
            return {"target_path": BURST_CLOSED_PREBUILDS[BURST_SYSTEM_TO_PREBUILD_KEY[system]]}

        def inspect(path, policy, *, on_file):
            for name in BURST_CLOSED_PREBUILDS.values():
                on_file(name, b"\x7fELF synthetic", 0o644)
            return {"members": []}

        versions = {BURST: "0.7.0", NEBULAR: "0.7.1", LOOM: "0.5.0"}
        for target in (
            patch("rs9.build_native.authenticated_record_hash", return_value="0" * 64),
            patch("rs9.build_native.require_configuration_authority", return_value=None),
            patch("rs9.build_native.bind_native_build_generation",
                  side_effect=lambda capture, intent, generation: versions[intent["project"]["id"]]),
            patch("rs9.build_native.inspect_archive", side_effect=inspect),
            patch("rs9.burst_native.validate_burst_native_prebuilds", side_effect=prebuilds),
            patch("rs9.elf.parse_elf", return_value={"needed": [], "interpreter": None}),
        ):
            target.start()
            self.addCleanup(target.stop)

    def test_current_burst_selects_linux_arm64_gnu(self):
        capture = _capture(self.root, BURST, "0.7.0", [_payload(self.root, "package", ["any"])])
        ctx = validate_build_inputs(capture, _intent(BURST, "0.7.0"), "aarch64",
                                    adapter="pacman", generation=CURRENT_GENERATION)
        self.assertEqual(ctx["arch"], "aarch64")
        self.assertEqual(ctx["payload"]["id"], "package")
        self.assertEqual(self.systems, ["aarch64-linux"])
        self.assertEqual(ctx["burst_prebuild_info"]["target_path"], ARM_PREBUILD)
        self.assertIn("/linux-arm64-gnu/", ctx["burst_prebuild_info"]["target_path"])

    def test_current_burst_x86_64_unchanged(self):
        capture = _capture(self.root, BURST, "0.7.0", [_payload(self.root, "package", ["any"])])
        ctx = validate_build_inputs(capture, _intent(BURST, "0.7.0"), "x86_64",
                                    adapter="pacman", generation=CURRENT_GENERATION)
        self.assertEqual(self.systems, ["x86_64-linux"])
        self.assertIn("/linux-x64-gnu/", ctx["burst_prebuild_info"]["target_path"])

    def test_current_gui_selects_exact_aarch64_payload_without_any_escape(self):
        payloads = [_payload(self.root, "universal", ["any"]),
                    _payload(self.root, "darwin-arm64", ["aarch64-darwin"]),
                    _payload(self.root, "linux-x64", ["x86_64-linux"]),
                    _payload(self.root, "linux-arm64", ["aarch64-linux"])]
        capture = _capture(self.root, NEBULAR, "0.7.1", payloads)
        ctx = validate_build_inputs(capture, _intent(NEBULAR, "0.7.1"), "aarch64",
                                    adapter="pacman", generation=CURRENT_GENERATION)
        self.assertEqual(ctx["payload"]["id"], "linux-arm64")
        self.assertEqual(ctx["arch"], "aarch64")
        self.assertTrue(ctx["is_native_desktop"])

    def test_current_gui_any_only_payload_rejected_for_aarch64(self):
        capture = _capture(self.root, NEBULAR, "0.7.1", [_payload(self.root, "universal", ["any"]),
                                                          _payload(self.root, "linux-x64", ["x86_64-linux"])])
        with self.assertRaises(ContractError) as caught:
            validate_build_inputs(capture, _intent(NEBULAR, "0.7.1"), "aarch64",
                                  adapter="pacman", generation=CURRENT_GENERATION)
        self.assertEqual(caught.exception.code, "UNSUPPORTED_PLATFORM")

    def test_current_native_rejects_any_and_arm64_alias(self):
        for product, version in ((BURST, "0.7.0"), (NEBULAR, "0.7.1")):
            (self.root / product).mkdir()
            capture = _capture(self.root / product, product, version,
                               [_payload(self.root / product, "linux-arm64", ["aarch64-linux"])])
            for arch in ("any", "arm64", "armv7h"):
                with self.subTest(product=product, arch=arch), self.assertRaises(ContractError) as caught:
                    validate_build_inputs(capture, _intent(product, version), arch,
                                          adapter="pacman", generation=CURRENT_GENERATION)
                self.assertEqual(caught.exception.code, "INVALID_ARCHITECTURE")

    def test_historical_native_pacman_still_rejects_aarch64(self):
        for product in NATIVE:
            (self.root / product).mkdir()
            capture = _capture(self.root / product, product, "0.6.1",
                               [_payload(self.root / product, "linux-arm64", ["aarch64-linux"])])
            with self.subTest(product=product), self.assertRaises(ContractError) as caught:
                validate_build_inputs(capture, _intent(product, "0.6.1"), "aarch64", adapter="pacman")
            self.assertEqual(caught.exception.code, "INVALID_ARCHITECTURE")
        self.assertEqual(self.systems, [])

    def test_current_pure_js_rejects_aarch64(self):
        capture = _capture(self.root, LOOM, "0.5.0", [_payload(self.root, "package", ["any"])])
        with self.assertRaises(ContractError) as caught:
            validate_build_inputs(capture, _intent(LOOM, "0.5.0"), "aarch64",
                                  adapter="pacman", generation=CURRENT_GENERATION)
        self.assertEqual(caught.exception.code, "INVALID_ARCHITECTURE")

    def test_invalid_generation_rejected_before_selection(self):
        capture = _capture(self.root, BURST, "0.7.0", [_payload(self.root, "package", ["any"])])
        with self.assertRaises(ContractError) as caught:
            validate_build_inputs(capture, _intent(BURST, "0.7.0"), "aarch64",
                                  adapter="pacman", generation="theme-forge-current-202611")
        self.assertEqual(caught.exception.code, "GENERATION_SELECTION")
        self.assertEqual(self.systems, [])


if __name__ == "__main__":
    unittest.main()
