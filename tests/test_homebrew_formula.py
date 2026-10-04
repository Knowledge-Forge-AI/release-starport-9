"""Unit tests for homebrew_formula module.

Tests deterministic static parsing, class name derivation, and full release identity
comparison across real tap formula fixtures and fail-closed edge cases.
"""
import hashlib
import json
from pathlib import Path
import unittest

from rs9.errors import ContractError
from rs9.homebrew_formula import compare_formula_identity, formula_class_name, parse_formula

FIXTURES = Path(__file__).resolve().parent / "fixtures" / "homebrew"


class HomebrewFormulaParserTests(unittest.TestCase):
    def setUp(self):
        with open(FIXTURES / "tap-metadata.json") as f:
            self.metadata = json.load(f)

    def test_class_name_derivation(self):
        cases = [
            ("theme-forge-stellar-burst", "ThemeForgeStellarBurst"),
            ("theme-forge-stellar-loom", "ThemeForgeStellarLoom"),
            ("theme-forge-solar-sail", "ThemeForgeSolarSail"),
            ("theme-forge-nebular-fusion", "ThemeForgeNebularFusion"),
            ("second-project", "SecondProject"),
            ("simple", "Simple"),
            ("multi_part_name", "MultiPartName"),
        ]
        for name, expected in cases:
            self.assertEqual(formula_class_name(name), expected)

    def test_class_name_invalid_fails_closed(self):
        for bad in ("", None, 123):
            with self.assertRaises(ContractError):
                formula_class_name(bad)

    def test_parse_real_fixtures(self):
        for pkg, expected in self.metadata["formulas"].items():
            path = FIXTURES / expected["path"]
            self.assertTrue(path.is_file(), f"Fixture missing: {path}")
            content = path.read_bytes()
            parsed = parse_formula(content)

            self.assertEqual(parsed["class_name"], expected["class_name"])
            self.assertEqual(parsed["url"], expected["payload_url"])
            self.assertEqual(parsed["sha256"], expected["payload_sha256"])
            self.assertEqual(parsed["license"], expected["license"])
            self.assertEqual(parsed["dependencies"], expected["dependencies"])
            if "arch_restrictions" in expected:
                self.assertEqual(parsed["arch_restrictions"], expected["arch_restrictions"])
            if "os_restrictions" in expected:
                self.assertEqual(parsed["os_restrictions"], expected["os_restrictions"])

            # Verify git blob sha matches
            actual_blob = hashlib.sha1(f"blob {len(content)}\0".encode() + content).hexdigest()
            self.assertEqual(actual_blob, expected["blob_sha"])

            # Verify formula sha256 matches
            actual_sha = hashlib.sha256(content).hexdigest()
            self.assertEqual(actual_sha, expected["formula_sha256"])

    def test_compare_identity_exact_agreement_on_fixtures(self):
        for pkg, expected in self.metadata["formulas"].items():
            content = (FIXTURES / expected["path"]).read_bytes()
            parsed = parse_formula(content)
            expect_dict = {
                "project": pkg,
                "payload_url": expected["payload_url"],
                "payload_sha256": expected["payload_sha256"],
                "license": expected["license"],
                "commands": expected["commands"],
                "data": content,
                "blob_sha": expected["blob_sha"],
                "formula_sha256": expected["formula_sha256"],
            }
            if "arch_restrictions" in expected and "arm64" in expected["arch_restrictions"]:
                expect_dict["restrictions"] = "aarch64-darwin"
            elif "node" in expected["dependencies"]:
                expect_dict["restrictions"] = "node"

            is_exact, reasons = compare_formula_identity(parsed, expect_dict)
            self.assertTrue(is_exact, f"Failed for {pkg}: {reasons}")
            self.assertEqual(reasons, [])

    def test_compare_identity_mismatches_yield_conflict(self):
        burst_bytes = (FIXTURES / "Formula/theme-forge-stellar-burst.rb").read_bytes()
        parsed = parse_formula(burst_bytes)
        base_expect = {
            "project": "theme-forge-stellar-burst",
            "payload_url": "https://registry.npmjs.org/@knowledge-forge-ai/theme-forge-stellar-burst/-/theme-forge-stellar-burst-0.6.1.tgz",
            "payload_sha256": "53ef41a3de3335e042f2c4b1d299b1155b64bfc6556a84baf6a62cb28bcca209",
            "license": "AGPL-3.0-or-later",
            "commands": ["tfsb", "tfsb-studio-service"],
            "data": burst_bytes,
            "blob_sha": "0a5cf66b85a7e88172bba72c6cbe2de65a888f48",
        }

        # 1. Class name mismatch
        bad_class = dict(base_expect, project="other-project")
        ok, reasons = compare_formula_identity(parsed, bad_class)
        self.assertFalse(ok)
        self.assertTrue(any("class name" in r for r in reasons))

        # 2. URL mismatch
        bad_url = dict(base_expect, payload_url="https://registry.npmjs.org/wrong.tgz")
        ok, reasons = compare_formula_identity(parsed, bad_url)
        self.assertFalse(ok)
        self.assertTrue(any("payload URL" in r for r in reasons))

        # 3. SHA256 mismatch
        bad_sha = dict(base_expect, payload_sha256="0" * 64)
        ok, reasons = compare_formula_identity(parsed, bad_sha)
        self.assertFalse(ok)
        self.assertTrue(any("payload SHA256" in r for r in reasons))

        # 4. License mismatch
        bad_lic = dict(base_expect, license="MIT")
        ok, reasons = compare_formula_identity(parsed, bad_lic)
        self.assertFalse(ok)
        self.assertTrue(any("license mismatch" in r for r in reasons))

        # 5. Commands mismatch
        bad_cmds = dict(base_expect, commands=["unexpected-cmd"])
        ok, reasons = compare_formula_identity(parsed, bad_cmds)
        self.assertFalse(ok)

        # 6. Blob SHA mismatch
        bad_blob = dict(base_expect, blob_sha="1" * 40)
        ok, reasons = compare_formula_identity(parsed, bad_blob)
        self.assertFalse(ok)
        self.assertTrue(any("git blob" in r for r in reasons))

        # 7. Restrictions mismatch (expecting macos-arm64 for node tool)
        bad_restr = dict(base_expect, restrictions="aarch64-darwin")
        ok, reasons = compare_formula_identity(parsed, bad_restr)
        self.assertFalse(ok)
        self.assertTrue(any("restriction" in r for r in reasons))

    def test_schema_violations_fail_closed(self):
        bad_cases = [
            ("missing-class", 'url "https://example.com/pkg.tgz"\nsha256 "' + "a" * 64 + '"\nlicense "MIT"\n'),
            ("missing-url", 'class Foo < Formula\nsha256 "' + "a" * 64 + '"\nlicense "MIT"\nend\n'),
            ("missing-sha", 'class Foo < Formula\nurl "https://example.com/pkg.tgz"\nlicense "MIT"\nend\n'),
            ("short-sha", 'class Foo < Formula\nurl "https://example.com/pkg.tgz"\nsha256 "1234"\nlicense "MIT"\nend\n'),
            ("missing-license", 'class Foo < Formula\nurl "https://example.com/pkg.tgz"\nsha256 "' + "a" * 64 + '"\nend\n'),
        ]
        for name, text in bad_cases:
            with self.subTest(name=name):
                with self.assertRaises(ContractError) as ctx:
                    parse_formula(text)
                self.assertEqual(ctx.exception.code, "HOMEBREW_FORMULA_SCHEMA")

    def test_duplicate_dynamic_unknown_and_unbounded_schema_fail_closed(self):
        from pathlib import Path
        source = (Path(__file__).parent / "fixtures/homebrew/Formula/theme-forge-stellar-burst.rb").read_bytes()
        for data in (
            source.replace(b'  depends_on "node"', b'  resource "extra" do\n  end\n  depends_on "node"'),
            source.replace(b'  depends_on "node"', b'  sha256 "' + b"a" * 64 + b'"\n  depends_on "node"'),
            source.replace(b'  license "AGPL-3.0-or-later"', b'  license "#{dynamic}"'),
            source.replace(b"\n", b"\r\n"),
            source + b"#" * (64 * 1024),
            source.replace(b"generator", b"\xff"),
        ):
            with self.subTest(sha256=__import__("hashlib").sha256(data).hexdigest()), self.assertRaises(ContractError):
                parse_formula(data)


if __name__ == "__main__":
    unittest.main()
