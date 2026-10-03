"""Adversarial inputs at the public validation boundary."""

import json
from pathlib import Path
import tempfile
import unittest

from rs9.contract import ContractError, load_destinations, load_project, normalize
from tests.test_contract import _create_destinations, _create_minimal_project


class FailClosedTests(unittest.TestCase):
    def test_malformed_types_missing_fields_and_paths(self):
        cases = [
            ("project.toml", 'interface = "cli"', 'interface = []', "INVALID_TYPE"),
            ("project.toml", 'files = ["LICENSE"]', 'files = ["a\\nfile"]', "UNSAFE_PATH"),
            ("project.toml", 'files = ["LICENSE"]', 'files = ["LICENSE", "LICENSE"]', "DUPLICATE_IDENTIFIER"),
            ("project.toml", 'repository = "example-org/my-app"', 'repository = "../.."', "INVALID_REPOSITORY"),
            ("project.toml", 'expression = "MIT"', '', "MISSING_REQUIRED_KEY"),
            ("project.toml", 'expression = "MIT"', 'expression = "(MIT OR Apache-2.0) WITH LLVM-exception"', "INVALID_SPDX_EXPRESSION"),
            ("project.toml", 'source = "tagged-repository"', 'source = "release-asset"', "INVALID_CONFIG"),
            ("project.toml", 'argv = ["my-cli", "--version"]', 'argv = "my-cli --version"', "INVALID_TYPE"),
            ("project.toml", 'schema = "rs9.project.v1alpha1"', 'schema = "rs9.project.v9"', "SCHEMA_MISMATCH"),
            ("project.toml", 'id = "my-app"', 'id = "my-app\\n"', "INVALID_SLUG"),
            ("releases.toml", 'platforms = ["x86_64-linux", "aarch64-linux"]', 'platforms = [[]]', "INVALID_TYPE"),
            ("releases.toml", 'platforms = ["x86_64-linux", "aarch64-linux"]', 'platforms = ["any", "x86_64-linux"]', "INVALID_PLATFORM"),
            ("releases.toml", 'platforms = ["x86_64-linux", "aarch64-linux"]', 'platforms = ["windows"]', "INVALID_PLATFORM"),
            ("releases.toml", 'format = "tar.gz"', 'format = []', "INVALID_TYPE"),
            ("releases.toml", 'prerelease = "reject"', 'prerelease = []', "INVALID_TYPE"),
            ("releases.toml", 'tag = "v{version}"', 'tag = "../v{version}"', "UNSAFE_PATH"),
            ("releases.toml", 'tag = "v{version}"', 'tag = "v{version}.lock"', "UNSAFE_PATH"),
            ("releases.toml", 'tag = "v{version}"', 'tag = "v}{version}{"', "MALFORMED_TEMPLATE"),
            ("releases.toml", 'my-cli = "bin/my-cli"', 'my-cli = "/bin/my-cli"', "UNSAFE_PATH"),
            ("releases.toml", 'my-cli = "bin/my-cli"', 'my-cli = "bin/../my-cli"', "UNSAFE_PATH"),
            ("releases.toml", 'schema = "rs9.releases.v1alpha1"', 'schema = "rs9.npm.v1alpha1"', "SCHEMA_MISMATCH"),
        ]
        for filename, old, new, code in cases:
            with self.subTest(filename=filename, replacement=new), tempfile.TemporaryDirectory() as temp:
                root = _create_minimal_project(Path(temp))
                path = root / ".rs9" / filename
                original = path.read_text()
                self.assertIn(old, original)
                path.write_text(original.replace(old, new))
                with self.assertRaises(ContractError) as error:
                    load_project(root)
                self.assertEqual(error.exception.code, code)

    def test_required_runtime_kind_and_decoded_credentials(self):
        additions = [("\n[runtime]\nconstraint = '>=22'\n", "MISSING_REQUIRED_KEY"),
                     ("\n[runtime]\nkind = []\n", "INVALID_TYPE")]
        escaped_token = 'ghp_' + '\\u0061' * 36
        additions.append(('\n[runtime]\nkind = "node"\nconstraint = "' + escaped_token + '"\n', "CREDENTIAL_DETECTED"))
        additions.append(('\n[runtime]\nkind = "node"\npassphrase = "fixture"\n', "CREDENTIAL_DETECTED"))
        for addition, code in additions:
            with self.subTest(code=code), tempfile.TemporaryDirectory() as temp:
                root = _create_minimal_project(Path(temp))
                path = root / ".rs9/project.toml"
                path.write_text(path.read_text() + addition)
                with self.assertRaises(ContractError) as error:
                    load_project(root)
                self.assertEqual(error.exception.code, code)

    def test_missing_required_files_and_unknown_destination(self):
        with tempfile.TemporaryDirectory() as temp:
            root = _create_minimal_project(Path(temp))
            (root / ".rs9/releases.toml").unlink()
            with self.assertRaises(ContractError) as error:
                load_project(root)
            self.assertEqual(error.exception.code, "MISSING_REQUIRED_FILE")
        with tempfile.TemporaryDirectory() as temp:
            root = _create_minimal_project(Path(temp), extra_files={"pacman.toml": '''schema = "rs9.pacman.v1alpha1"
[[packages]]
id = "main"
name = "tool"
assets = ["app-bin"]
[[publish]]
package = "main"
destination = "unknown"
'''})
            with self.assertRaises(ContractError) as error:
                normalize(root, _create_destinations(root), "1.0.0")
            self.assertEqual(error.exception.code, "UNKNOWN_REFERENCE")

    def test_destination_types_and_invalid_url(self):
        cases = [('platforms = ["x86_64-linux", "aarch64-linux"]', 'platforms = [[]]', "INVALID_TYPE"),
                 ('base-url = "https://pkg.example.com/pacman"', 'base-url = "https://pkg.example.com:bad"', "INVALID_URL"),
                 ('base-url = "https://pkg.example.com/pacman"', 'base-url = "https://pkg.example.com\\n"', "INVALID_URL")]
        for old, new, code in cases:
            with self.subTest(code=code), tempfile.TemporaryDirectory() as temp:
                path = _create_destinations(Path(temp))
                path.write_text(path.read_text().replace(old, new))
                with self.assertRaises(ContractError) as error:
                    load_destinations(path)
                self.assertEqual(error.exception.code, code)

    def test_package_ambiguity_and_restrictions(self):
        base = '''schema = "rs9.pacman.v1alpha1"
[[packages]]
id = "one"
name = "tool"
assets = ["app-bin"]
[[publish]]
package = "one"
destination = "hosted-pacman"
'''
        variants = [
            (base.replace('assets = ["app-bin"]', 'assets = [[]]'), "INVALID_TYPE"),
            (base.replace('assets = ["app-bin"]', 'assets = ["app-bin"]\nplatforms = ["x86_64-darwin"]'), "SUBSET_VIOLATION"),
            (base + '''[[packages]]
id = "two"
name = "tool"
assets = ["app-bin"]
[[publish]]
package = "two"
destination = "hosted-pacman"
''', "AMBIGUOUS_COVERAGE"),
        ]
        for content, code in variants:
            with self.subTest(code=code), tempfile.TemporaryDirectory() as temp:
                root = _create_minimal_project(Path(temp), extra_files={"pacman.toml": content})
                with self.assertRaises(ContractError) as error:
                    normalize(root, _create_destinations(root), "1.0.0")
                self.assertEqual(error.exception.code, code)
