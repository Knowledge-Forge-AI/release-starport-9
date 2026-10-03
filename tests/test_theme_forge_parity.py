"""Offline contract parity against independently extracted source facts."""

import hashlib
import json
from pathlib import Path
import unittest

from rs9.contract import load_project, normalize

ROOT = Path(__file__).resolve().parents[1]
PROJECT = ROOT / "examples/theme-forge/theme-forge-nebular-fusion"
DESTINATIONS = ROOT / "examples/destinations.example.toml"
FACTS = ROOT / "tests/fixtures/theme-forge-observed-facts.json"


class ThemeForgeParityTests(unittest.TestCase):
    def setUp(self):
        self.facts = json.loads(FACTS.read_text())
        self.product = next(p for p in self.facts["products"]
                            if p["id"] == "theme-forge-nebular-fusion")
        self.output = normalize(PROJECT, DESTINATIONS, self.product["version"])
        self.manifest = json.loads(self.output)

    def test_observed_native_asset_and_command_mappings(self):
        assets = {a["platforms"][0]: a for a in self.manifest["assets"]}
        self.assertEqual(set(assets), set(self.product["rawArchives"]))
        for platform, observed in self.product["rawArchives"].items():
            self.assertEqual(assets[platform]["name"], observed["asset"])
            self.assertEqual(assets[platform]["commands"],
                             {"tfnf": observed["executablePath"]})
        self.assertEqual([c["name"] for c in self.manifest["commands"]],
                         self.product["bins"])
        self.assertTrue(self.manifest["checks"][0]["requires-display"])

    def test_surface_names_architectures_and_provisional_packaging_license(self):
        observed = {s["destination"]: s for s in self.facts["surfaces"]
                    if s["project"] == self.product["id"]}
        targets = {t["destination"]: t for t in self.manifest["targets"]}
        self.assertEqual(set(targets), set(observed))
        for destination, target in targets.items():
            with self.subTest(destination=destination):
                surface = observed[destination]
                self.assertEqual(target["name"], surface["name"])
                self.assertEqual(set(target["ecosystem-architectures"]),
                                 set(surface["architectures"]))
                if surface["license"]:
                    # Packaging agreement is provisional, not tagged tenant authority.
                    self.assertEqual(self.manifest["license"]["expression"],
                                     surface["license"])
                self.assertEqual(len(surface["source"]["sha256"]), 64)
        self.assertEqual(targets["kfa-apt"]["destination-status"], "candidate")

    def test_public_release_metadata_matches_extracted_lock(self):
        releases = {r["repository"]: r for r in self.facts["publicReleases"]}
        for product in self.facts["products"]:
            release = releases[product["canonicalRepo"]]
            self.assertFalse(release["draft"])
            self.assertFalse(release["prerelease"])
            self.assertEqual(release["tag"], "v" + product["version"])
            if product["inputKind"] == "npm-registry":
                self.assertEqual(release["assets"][0]["sha256"], product["sha256"])
                self.assertNotEqual(release["assets"][0]["name"], product["cacheAsset"])
            else:
                public_assets = {a["name"]: a for a in release["assets"]}
                for archive in product["rawArchives"].values():
                    self.assertEqual(public_assets[archive["asset"]]["sha256"],
                                     archive["sha256"])
        self.assertEqual(self.facts["publicLock"]["sha256"],
                         self.product["source"]["sha256"])

    def test_exact_input_digests_and_golden_output(self):
        for entry in self.manifest["evidence"]["inputs"]:
            path = DESTINATIONS if entry["filename"] == "destinations.toml" else PROJECT / ".rs9" / entry["filename"]
            self.assertEqual(entry["sha256"], hashlib.sha256(path.read_bytes()).hexdigest())
        self.assertEqual(self.output, normalize(PROJECT, DESTINATIONS, "0.6.1"))
        golden = ROOT / "tests/golden/theme-forge-nebular-fusion.normalized.json"
        self.assertEqual(self.output, golden.read_bytes())

    def test_synthetic_registry_shape_preserves_mit(self):
        synthetic = ROOT / "tests/fixtures/synthetic-mit-tool"
        load_project(synthetic)
        manifest = json.loads(normalize(synthetic, DESTINATIONS, "1.0.0"))
        self.assertEqual(manifest["license"]["expression"], "MIT")
        self.assertEqual({t["adapter"] for t in manifest["targets"]}, {"npm", "pypi"})
        self.assertNotIn("AGPL", manifest["license"]["expression"])
