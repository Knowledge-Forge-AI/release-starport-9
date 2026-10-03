import json
from pathlib import Path
import shutil
import tempfile
import unittest

from rs9.compare import classify, parse_srcinfo, shadow_facts
from rs9.errors import ContractError
from rs9.scratch import canonical

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "tests/fixtures/nebular-0.6.1"
GOLDEN = ROOT / "tests/golden/shadow/nebular-0.6.1"


class ReferenceComparisonTests(unittest.TestCase):
    def test_complete_nonstale_classification_from_actual_recipe_bytes(self):
        reference = json.loads((FIXTURE / "reference-facts.json").read_bytes())["facts"]
        classifications = json.loads((FIXTURE / "comparison-classification.json").read_bytes())
        actual = classify(reference, shadow_facts(GOLDEN), classifications)
        self.assertEqual(canonical(actual), (FIXTURE / "comparison.json").read_bytes())
        for bad in (classifications[:-1], classifications + [dict(classifications[0])]):
            with self.assertRaises(ContractError):
                classify(reference, shadow_facts(GOLDEN), bad)

    def test_material_identity_and_launcher_preserved(self):
        ref = json.loads((FIXTURE / "reference-facts.json").read_bytes())["facts"]
        shadow = shadow_facts(GOLDEN)
        for adapter in ("nix", "pacman", "rpm", "aur"):
            for field in ("version", "architectures", "license"):
                self.assertEqual(ref[adapter][field], shadow[adapter][field])
            if adapter != "nix":
                self.assertEqual(ref[adapter]["name"], shadow[adapter]["name"])
        self.assertEqual(shadow["nix"]["name"]["aarch64-darwin"], "theme-forge-nebular-fusion-payload")
        self.assertEqual(shadow["nix"]["name"]["x86_64-linux"], "tfnf")
        for adapter in ("pacman", "rpm", "aur"):
            self.assertEqual(ref[adapter]["launcher"], shadow[adapter]["launcher"])
        self.assertEqual(shadow["pacman"]["architectures"], ["x86_64"])
        self.assertEqual(shadow["aur"]["architectures"], ["aarch64", "x86_64"])

    def test_recipe_name_license_and_installed_path_drift_is_observable(self):
        before = shadow_facts(GOLDEN)
        changes = [
            ("nix", "nix/theme-forge-nebular-fusion.nix", 'name = "tfnf";', 'name = "changed-launcher";', "name"),
            ("nix", "nix/theme-forge-nebular-fusion.nix", 'pname = "theme-forge-nebular-fusion-payload";', 'pname = "changed-payload";', "name"),
            ("nix", "nix/theme-forge-nebular-fusion.nix", "lib.licenses.agpl3Plus", "lib.licenses.mit", "license"),
            ("pacman", "pacman/theme-forge-nebular-fusion/PKGBUILD", "/usr/lib/theme-forge-nebular-fusion", "/usr/lib/changed-payload", "installed_paths"),
            ("aur", "aur/theme-forge-nebular-fusion-bin/PKGBUILD", "/usr/bin/tfnf", "/usr/bin/changed-launcher", "installed_paths"),
            ("rpm", "rpm/theme-forge-nebular-fusion.spec", "/usr/lib/theme-forge-nebular-fusion", "/usr/lib/changed-payload", "installed_paths"),
        ]
        for adapter, relative, old, new, field in changes:
            with self.subTest(adapter=adapter, field=field), tempfile.TemporaryDirectory() as temp:
                copy = Path(temp) / "golden"
                shutil.copytree(GOLDEN, copy)
                path = copy / relative
                text = path.read_text()
                self.assertIn(old, text)
                path.write_text(text.replace(old, new))
                self.assertNotEqual(before[adapter][field], shadow_facts(copy)[adapter][field])

    def test_unknown_nix_license_fails_closed(self):
        with tempfile.TemporaryDirectory() as temp:
            copy = Path(temp) / "golden"
            shutil.copytree(GOLDEN, copy)
            path = copy / "nix/theme-forge-nebular-fusion.nix"
            path.write_text(path.read_text().replace("lib.licenses.agpl3Plus", "lib.licenses.unknownLicense"))
            with self.assertRaises(ContractError):
                shadow_facts(copy)

    def test_rpm_install_destination_drift_cannot_hide_behind_files_section(self):
        with tempfile.TemporaryDirectory() as temp:
            copy = Path(temp) / "golden"
            shutil.copytree(GOLDEN, copy)
            path = copy / "rpm/theme-forge-nebular-fusion.spec"
            text = path.read_text()
            before, separator, files = text.partition("%files\n")
            self.assertTrue(separator)
            path.write_text(before.replace("/usr/lib/theme-forge-nebular-fusion", "/usr/lib/changed-payload") + separator + files)
            with self.assertRaises(ContractError):
                shadow_facts(copy)

    def test_desktop_behavior_differences_remain_material_and_pending(self):
        rows = json.loads((FIXTURE / "comparison.json").read_bytes())["differences"]
        for field in ("Exec", "MimeType", "StartupWMClass", "Categories"):
            row = next(r for r in rows if r["adapter"] == "desktop" and r["field"] == field)
            self.assertTrue(row["material"])
            self.assertEqual(row["class"], "reference-only behavior retained pending evidence")

    def test_srcinfo_consistent_with_recipe_facts(self):
        actual = parse_srcinfo((GOLDEN / "aur/theme-forge-nebular-fusion-bin/.SRCINFO").read_bytes())
        facts = shadow_facts(GOLDEN)["aur"]
        self.assertEqual(actual["pkgname"], [facts["name"]])
        self.assertEqual(sorted(actual["arch"]), facts["architectures"])
        for arch in actual["arch"]:
            self.assertEqual(sorted(actual["depends"] + actual.get("depends_" + arch, [])), facts["dependencies"][arch])
        self.assertEqual(actual["provides"], facts["provides"])
