"""Portable checks for the held 0.8 public-input boundary."""

from __future__ import annotations

import copy
import json
from pathlib import Path
import shutil
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from rs9.errors import ContractError
from rs9.nebular080_public_input_acquisition import (
    PublicRelayNativeEvidenceTransport,
    acquire_public_inputs_080,
    resolve_clean_source_identity,
)
from rs9.nebular080_public_input_manifest import (
    load_json,
    validate_release_binding,
    validate_tracked080_manifest,
    validate_tracked_repository_rows,
    validate_runtime_source_identity,
    bind_runtime_source_identity,
)
ROOT = Path(__file__).resolve().parents[1]
MANIFEST_PATH = ROOT / "operators/theme-forge-current-202610/nebular080-public-input-manifest.json"
BINDING_PATH = ROOT / "operators/theme-forge-current-202610/nebular080-release-binding.json"


class PublicInputIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.manifest = load_json(MANIFEST_PATH)
        cls.binding = load_json(BINDING_PATH)

    def test_integrated_layout_validates_real_tracked_contract(self) -> None:
        checked = validate_tracked080_manifest(self.manifest)
        bound = validate_release_binding(self.binding, checked)
        self.assertEqual(checked["product_evidence"]["release_id"], 437909062)
        self.assertEqual(bound["native_relay"]["archive_asset_id"], 722806135)
        self.assertIsNone(bound["source_identity"]["commit"])

        for row in checked["tracked_inputs"].values():
            if "path" not in row:
                continue
            self.assertFalse(row["path"].startswith("/"))

    def test_product_identity_cannot_bind_the_r_source(self) -> None:
        candidate = copy.deepcopy(self.manifest)
        candidate["source"]["commit"] = candidate["product_evidence"]["commit"]
        candidate["source"]["tree"] = candidate["product_evidence"]["tree"]
        candidate["source"]["identity_status"] = "bound-clean-checkout"
        with self.assertRaises(ValueError):
            validate_tracked080_manifest(candidate)

    def test_acquisition_requires_runtime_identity_before_output_or_transport(self) -> None:
        class ForbiddenClient:
            def json(self, *_args, **_kwargs):
                raise AssertionError("held source must refuse before API reads")

            def get(self, *_args, **_kwargs):
                raise AssertionError("held source must refuse before asset reads")

        class ForbiddenTransport:
            spec = object()

            def fetch(self, *_args, **_kwargs):
                raise AssertionError("held source must refuse before relay reads")

        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            output = Path(directory) / "prepared"
            with self.assertRaises(ContractError):
                acquire_public_inputs_080(
                    output,
                    repository=ROOT,
                    source_manifest=self.manifest,
                    release_client=ForbiddenClient(),
                    native_transport=ForbiddenTransport(),
                    release_binding=self.binding,
                )
            self.assertFalse(output.exists())

    def test_clean_identity_binds_ephemerally_and_rechecks_real_rows(self) -> None:
        expected = {
            "repository": "Knowledge-Forge-AI/release-starport-9",
            "commit": "a" * 40,
            "tree": "b" * 40,
        }

        def resolver(repository, commit, *, generation):
            self.assertEqual(repository, ROOT)
            self.assertEqual(commit, expected["commit"])
            self.assertEqual(generation, "theme-forge-current-202610")
            return {"repository": expected["repository"], "source_commit": expected["commit"], "source_tree": expected["tree"]}

        identity = resolve_clean_source_identity(
            ROOT, commit=expected["commit"], resolver=resolver,
        )
        rows = validate_tracked_repository_rows(ROOT, self.manifest)
        bound = bind_runtime_source_identity(self.manifest, self.binding, identity)
        self.assertEqual(identity, expected)
        self.assertEqual(bound["source"], expected)
        self.assertEqual(bound["manifest"]["source"]["commit"], expected["commit"])
        self.assertEqual(bound["binding"]["source_identity"]["tree"], expected["tree"])
        self.assertEqual(rows["bootstrap"]["sha256"], self.manifest["tracked_inputs"]["bootstrap"]["sha256"])

    def test_identity_and_tracked_rows_reject_product_or_tampered_binding(self) -> None:
        with self.assertRaises(ValueError):
            validate_runtime_source_identity({
                "repository": "Knowledge-Forge-AI/release-starport-9",
                "commit": self.manifest["product_evidence"]["commit"],
                "tree": "b" * 40,
            })
        with self.assertRaises(ContractError):
            resolve_clean_source_identity(
                ROOT,
                commit="a" * 40,
                resolver=lambda *_args, **_kwargs: {
                    "repository": "other/repository",
                    "source_commit": "a" * 40,
                    "source_tree": "b" * 40,
                },
            )
        with self.assertRaisesRegex(ContractError, "HOSTED_SOURCE_TREE"):
            def dirty_resolver(*_args, **_kwargs):
                raise ContractError("HOSTED_SOURCE_TREE", "clean checkout required")
            resolve_clean_source_identity(
                ROOT,
                commit="a" * 40,
                resolver=dirty_resolver,
            )
        with self.assertRaises(ValueError):
            validate_runtime_source_identity({
                "repository": "Knowledge-Forge-AI/release-starport-9",
                "commit": "a" * 40,
                "tree": "not-a-tree",
            })
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            checkout = Path(directory) / "checkout"
            for row in self.manifest["tracked_inputs"].values():
                if "path" in row:
                    target = checkout / row["path"]
                    target.parent.mkdir(parents=True, exist_ok=True)
                    shutil.copy2(ROOT / row["path"], target)
            target = checkout / self.manifest["tracked_inputs"]["bootstrap"]["path"]
            target.write_bytes(target.read_bytes() + b"tamper")
            with self.assertRaises(ValueError):
                validate_tracked_repository_rows(checkout, self.manifest)

    def test_bound_identity_reaches_real_product_capture_boundary(self) -> None:
        class ForbiddenClient:
            def json(self, *_args, **_kwargs):
                raise AssertionError("product API must be the first external boundary")

            def get(self, *_args, **_kwargs):
                raise AssertionError("product asset API must not be bypassed")

        identity = {
            "repository": "Knowledge-Forge-AI/release-starport-9",
            "commit": "a" * 40,
            "tree": "b" * 40,
        }
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            output = Path(directory) / "prepared"
            with self.assertRaises(ContractError):
                acquire_public_inputs_080(
                    output,
                    repository=ROOT,
                    source_manifest=self.manifest,
                    release_client=ForbiddenClient(),
                    native_transport=PublicRelayNativeEvidenceTransport(ForbiddenClient()),
                    release_binding=self.binding,
                    source_identity=identity,
                )
            self.assertFalse(output.exists())

    def test_binding_bytes_are_canonical_and_relay_ids_are_fixed(self) -> None:
        for path in (MANIFEST_PATH, BINDING_PATH):
            value = json.loads(path.read_bytes())
            self.assertEqual(
                path.read_bytes(),
                (json.dumps(value, ensure_ascii=False, indent=2) + "\n").encode(),
            )
        relay = self.binding["native_relay"]
        self.assertEqual(
            relay,
            {
                "release_id": 438017969,
                "tag": "nebular-v0.8.0-native-evidence-run-42418673472-attempt-1",
                "archive_asset_id": 722806135,
                "inventory_asset_id": 722806134,
            },
        )

    def test_generated_workflow_uses_tracked_flags_for_080(self) -> None:
        workflow = (ROOT / ".github/workflows/rs9-tfnf-pypi-publish.yml").read_text()
        block = workflow.split("universal_prepare_public_inputs_080:", 1)[1].split(
            "  universal_build_verify_080:", 1
        )[0]
        self.assertIn("--source-manifest operators/theme-forge-current-202610/nebular080-public-input-manifest.json", block)
        self.assertIn("--release-binding operators/theme-forge-current-202610/nebular080-release-binding.json", block)
        self.assertIn('--repository "$GITHUB_WORKSPACE"', block)
        self.assertNotIn("--manifest operators/tf-pypi/theme-forge-nebular-fusion-0.8.0", block)
        self.assertNotIn("--rs9-commit", block)
        self.assertNotIn("--rs9-tree", block)
        self.assertEqual(workflow.count("node-version: '22.23.3'"), 2)
        self.assertEqual(workflow.count("node-version: '22.23.4'"), 2)


if __name__ == "__main__":
    unittest.main()
