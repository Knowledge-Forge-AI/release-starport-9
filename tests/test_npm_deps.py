"""Unit tests for npm_deps module and product-class offline dependency resolution."""
import hashlib
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import MagicMock

from rs9.errors import ContractError
from rs9.npm_deps import (
    authenticate_dependencies,
    closure_for_capture,
    resolve_offline_npm_archives,
    runtime_closure,
)
from rs9.release_core import digest
from tests.test_build_native import create_cli_fixture, make_npm_archive


class NpmDepsTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name).resolve()
        self.scratch = self.root / "scratch"
        self.scratch.mkdir()

    def test_native_desktop_always_returns_none_even_with_frontend_dependencies(self):
        capture = SimpleNamespace(
            source={
                "package.json": json.dumps({
                    "name": "@knowledge-forge-ai/theme-forge-nebular-fusion",
                    "version": "0.6.1",
                    "dependencies": {"vue": "3.3.4", "pinia": "2.1.6"},
                }),
            }
        )
        client = MagicMock()
        result = resolve_offline_npm_archives(
            capture,
            "theme-forge-nebular-fusion",
            self.scratch,
            inputs=self.root / "inputs",
            client=client,
        )
        self.assertIsNone(result)
        client.get.assert_not_called()

    def test_native_node_cli_always_returns_authenticated_closure_with_cached_inputs(self):
        capture, intent, offline_npm = create_cli_fixture(
            self.root / "burst_input", product="theme-forge-stellar-burst"
        )
        inputs = self.root / "burst_input/npm_archives"
        result = resolve_offline_npm_archives(
            capture,
            "theme-forge-stellar-burst",
            self.scratch,
            inputs=inputs,
            client=None,
        )
        self.assertIsNotNone(result)
        self.assertIn("node_modules/min-dep", result)
        self.assertTrue(result["node_modules/min-dep"].is_file())

    def test_native_node_cli_downloads_via_client_when_not_cached(self):
        capture, intent, offline_npm = create_cli_fixture(
            self.root / "burst_input", product="theme-forge-stellar-burst"
        )
        arch_file = offline_npm["node_modules/min-dep"]
        arch_bytes = Path(arch_file).read_bytes()

        client = MagicMock()
        client.get.return_value = arch_bytes

        result = resolve_offline_npm_archives(
            capture,
            "theme-forge-stellar-burst",
            self.scratch,
            inputs=None,
            client=client,
        )
        self.assertIsNotNone(result)
        self.assertIn("node_modules/min-dep", result)
        downloaded = result["node_modules/min-dep"]
        self.assertTrue(downloaded.is_file())
        self.assertEqual(downloaded.read_bytes(), arch_bytes)
        client.get.assert_called_once()

    def test_pure_js_cli_returns_none_when_no_dependencies(self):
        capture = SimpleNamespace(
            source={
                "package.json": json.dumps({
                    "name": "@knowledge-forge-ai/theme-forge-stellar-loom",
                    "version": "0.4.0",
                }),
                "package-lock.json": json.dumps({"lockfileVersion": 3, "packages": {}}),
            }
        )
        for product_id in ("theme-forge-stellar-loom", "theme-forge-solar-sail"):
            with self.subTest(product=product_id):
                result = resolve_offline_npm_archives(
                    capture,
                    product_id,
                    self.scratch,
                )
                self.assertIsNone(result)

    def test_pure_js_cli_returns_closure_when_dependencies_present(self):
        capture, intent, offline_npm = create_cli_fixture(
            self.root / "loom_input", product="theme-forge-stellar-loom"
        )
        inputs = self.root / "loom_input/npm_archives"
        result = resolve_offline_npm_archives(
            capture,
            "theme-forge-stellar-loom",
            self.scratch,
            inputs=inputs,
        )
        self.assertIsNotNone(result)
        self.assertIn("node_modules/min-dep", result)

    def test_unknown_product_raises_contract_error(self):
        capture = SimpleNamespace(source={"package.json": "{}"})
        with self.assertRaises(ContractError) as caught:
            resolve_offline_npm_archives(capture, "unrecognized-product", self.scratch)
        self.assertEqual(caught.exception.code, "UNKNOWN_PRODUCT")

    def test_runtime_closure_pin_validation(self):
        package = {"dependencies": {"foo": "^1.0.0"}}
        lock = {
            "lockfileVersion": 3,
            "packages": {
                "": {"dependencies": {"foo": "^1.0.0"}},
                "node_modules/foo": {
                    "version": "1.0.0",
                    "resolved": "https://registry.npmjs.org/foo/-/foo-1.0.0.tgz",
                    "integrity": "sha512-" + "A" * 86 + "==",
                },
            },
        }
        with self.assertRaises(ContractError) as caught:
            runtime_closure(package, lock)
        self.assertEqual(caught.exception.code, "NPM_PIN")

    def test_runtime_closure_lock_version_validation(self):
        package = {"dependencies": {}}
        lock = {"lockfileVersion": 1, "packages": {}}
        with self.assertRaises(ContractError) as caught:
            runtime_closure(package, lock)
        self.assertEqual(caught.exception.code, "NPM_LOCK")

    def test_closure_for_capture_missing_lock_fails(self):
        capture = SimpleNamespace(
            root=self.root,
            source={"package.json": "{}"},
            tree={"tree": []},
            source_tree_sha256="0" * 64,
        )
        with self.assertRaises(ContractError):
            closure_for_capture(capture)


if __name__ == "__main__":
    unittest.main()
