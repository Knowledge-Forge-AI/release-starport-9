"""Contract regressions identified by the independent foundation review."""

import json
from pathlib import Path
import tempfile
import unittest

from rs9.contract import ContractError, load_destinations, load_project, main, normalize
from tests.test_contract import _create_destinations, _create_minimal_project

PACMAN = '''schema = "rs9.pacman.v1alpha1"
[[packages]]
id = "one"
name = "my-app"
assets = ["app-bin"]
[[publish]]
package = "one"
destination = "hosted-pacman"
'''


class CloseoutRegressionTests(unittest.TestCase):
    def test_native_npm_tarball_with_narrow_pacman_serving(self):
        # Synthetic command/license facts exercise Burst's observed artifact shape.
        npm = '''schema = "rs9.npm.v1alpha1"
[[packages]]
id = "registry"
name = "@example/my-app"
assets = ["app-bin"]
[[publish]]
package = "registry"
destination = "npmjs"
'''
        routing = '''schema = "rs9.destinations.v1alpha1"
[[destinations]]
id = "hosted-pacman"
adapter = "pacman"
mode = "direct"
platforms = ["x86_64-linux"]
status = "illustrative"
[[destinations]]
id = "npmjs"
adapter = "npm"
mode = "direct"
platforms = ["x86_64-linux", "aarch64-linux", "aarch64-darwin"]
status = "illustrative"
'''
        with tempfile.TemporaryDirectory() as temp:
            root = _create_minimal_project(Path(temp),
                                          asset_platforms=["x86_64-linux", "aarch64-linux", "aarch64-darwin"],
                                          extra_files={"npm.toml": npm, "pacman.toml": PACMAN})
            path = root / ".rs9/releases.toml"
            path.write_text(path.read_text().replace('format = "tar.gz"', 'format = "npm-tarball"'))
            manifest = json.loads(normalize(root, _create_destinations(root, routing), "1.0.0"))
            targets = {t["destination"]: t for t in manifest["targets"]}
            self.assertEqual(targets["hosted-pacman"]["effective-platforms"], ["x86_64-linux"])
            self.assertEqual(targets["hosted-pacman"]["ecosystem-architectures"], ["x86_64"])
            self.assertEqual(targets["npmjs"]["effective-platforms"],
                             ["aarch64-darwin", "aarch64-linux", "x86_64-linux"])
            self.assertEqual(manifest["assets"][0]["format"], "npm-tarball")
            self.assertEqual({tuple(t["assets"]) for t in targets.values()}, {("app-bin",)})

    def test_credential_substrings_in_declared_command_names(self):
        for command in ("gh-auth", "tokenizer", "credential-helper"):
            with self.subTest(command=command), tempfile.TemporaryDirectory() as temp:
                root = _create_minimal_project(Path(temp))
                for name in ("project.toml", "releases.toml"):
                    path = root / ".rs9" / name
                    path.write_text(path.read_text().replace("my-cli", command))
                manifest = json.loads(normalize(root, _create_destinations(root), "1.0.0"))
                self.assertEqual(manifest["assets"][0]["commands"],
                                 {command: "bin/" + command})

    def test_decoded_credentials_in_command_keys_and_values_still_fail(self):
        token = "ghp_" + "a" * 36
        escaped = "ghp_" + "\\u0061" * 36
        for mapping in (f'"{escaped}" = "bin/tool"', f'my-cli = "bin/{escaped}"'):
            with self.subTest(mapping_kind=mapping.startswith('"')), tempfile.TemporaryDirectory() as temp:
                root = _create_minimal_project(Path(temp))
                path = root / ".rs9/releases.toml"
                path.write_text(path.read_text().replace('my-cli = "bin/my-cli"', mapping))
                with self.assertRaises(ContractError) as error:
                    load_project(root)
                self.assertEqual(error.exception.code, "CREDENTIAL_DETECTED")
                self.assertNotIn(token, str(error.exception))

    def test_duplicate_destination_package_names_fail_without_destinations(self):
        duplicate = PACMAN + '''[[packages]]
id = "two"
name = "my-app"
assets = ["app-bin"]
[[publish]]
package = "two"
destination = "hosted-pacman"
'''
        with tempfile.TemporaryDirectory() as temp:
            root = _create_minimal_project(Path(temp), extra_files={"pacman.toml": duplicate})
            with self.assertRaises(ContractError) as error:
                load_project(root)
            self.assertEqual(error.exception.code, "AMBIGUOUS_COVERAGE")
            self.assertEqual(main(["validate", str(root)]), 1)

    def test_target_assets_follow_package_and_destination_platforms(self):
        for restrict_package in (False, True):
            with self.subTest(restrict_package=restrict_package), tempfile.TemporaryDirectory() as temp:
                package = PACMAN.replace('assets = ["app-bin"]',
                                         'assets = ["app-bin", "arm-bin"]')
                if restrict_package:
                    package = package.replace('[[publish]]',
                                              'platforms = ["aarch64-linux"]\n[[publish]]')
                root = _create_minimal_project(Path(temp), asset_platforms=["x86_64-linux"],
                                               extra_files={"pacman.toml": package})
                path = root / ".rs9/releases.toml"
                path.write_text(path.read_text() + '''
[[assets]]
id = "arm-bin"
name = "my-app-{version}-arm.tar.gz"
format = "tar.gz"
platforms = ["aarch64-linux"]
commands = {my-cli = "bin/my-cli"}
''')
                destination = _create_destinations(root)
                if not restrict_package:
                    destination.write_text(destination.read_text().replace(
                        '["x86_64-linux", "aarch64-linux"]', '["aarch64-linux"]'))
                manifest = json.loads(normalize(root, destination, "1.0.0"))
                self.assertEqual(manifest["targets"][0]["assets"], ["arm-bin"])
                self.assertEqual(manifest["targets"][0]["effective-platforms"], ["aarch64-linux"])
                self.assertEqual({a["id"] for a in manifest["assets"]}, {"app-bin", "arm-bin"})

    def test_missing_required_keys_have_one_code(self):
        cases = [
            ("project.toml", 'schema = "rs9.project.v1alpha1"'),
            ("project.toml", 'name = "My Application"'),
            ("project.toml", 'expression = "MIT"'),
            ("project.toml", 'interface = "cli"'),
            ("project.toml", 'requires-display = false'),
            ("releases.toml", 'prerelease = "reject"'),
            ("releases.toml", 'format = "tar.gz"'),
            ("pacman.toml", 'name = "my-app"'),
            ("pacman.toml", 'destination = "hosted-pacman"'),
        ]
        for name, line in cases:
            with self.subTest(name=name, line=line), tempfile.TemporaryDirectory() as temp:
                root = _create_minimal_project(Path(temp), extra_files={"pacman.toml": PACMAN})
                path = root / ".rs9" / name
                path.write_text(path.read_text().replace(line, ""))
                with self.assertRaises(ContractError) as error:
                    load_project(root)
                self.assertEqual(error.exception.code, "MISSING_REQUIRED_KEY")
        with tempfile.TemporaryDirectory() as temp:
            path = _create_destinations(Path(temp))
            path.write_text(path.read_text().replace('mode = "direct"', ""))
            with self.assertRaises(ContractError) as error:
                load_destinations(path)
            self.assertEqual(error.exception.code, "MISSING_REQUIRED_KEY")

    def test_check_text_must_be_nfc_before_normalization(self):
        for old, new in (
            ('argv = ["my-cli", "--version"]', 'argv = ["my-cli", "--cafe\u0301"]'),
            ('expect-stdout-contains = "my-cli {version}"',
             'expect-stdout-contains = "cafe\u0301 {version}"'),
        ):
            with self.subTest(field=old.split(" =")[0]), tempfile.TemporaryDirectory() as temp:
                root = _create_minimal_project(Path(temp))
                path = root / ".rs9/project.toml"
                path.write_text(path.read_text().replace(old, new))
                with self.assertRaises(ContractError) as error:
                    load_project(root)
                self.assertEqual(error.exception.code, "NON_NFC_STRING")
