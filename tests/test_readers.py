"""Hermetic unit tests for destination readers and bin normalization."""
import unittest

from rs9.errors import ContractError
from rs9.readers import _normalized_npm_bin


class NormalizedNpmBinTests(unittest.TestCase):
    def test_command_alias_paths_are_rejected(self):
        for command in ("/tool", "../tool", "dir/tool", "dir\\tool", "x:tool"):
            with self.subTest(command=command), self.assertRaises(ContractError):
                _normalized_npm_bin("pkg", {command: "./bin/tool"})

    def test_allows_one_dot_slash_prefix_and_missing_prefix_regression(self):
        """Allow one ./ prefix or missing ./ prefix, normalizing both to safe relative posix paths."""
        # String bin with scoped and unscoped package names
        self.assertEqual(_normalized_npm_bin("my-tool", "./bin/tool.js"), {"my-tool": "bin/tool.js"})
        self.assertEqual(_normalized_npm_bin("my-tool", "bin/tool.js"), {"my-tool": "bin/tool.js"})
        self.assertEqual(_normalized_npm_bin("@scope/my-tool", "./bin/tool.js"), {"my-tool": "bin/tool.js"})
        self.assertEqual(_normalized_npm_bin("@scope/my-tool", "bin/tool.js"), {"my-tool": "bin/tool.js"})

        # Dictionary bin targets with and without ./ prefix
        targets = {
            "cmd-a": "./bin/a.js",
            "cmd-b": "bin/b.js",
            "cmd-c": "./dist/cli.mjs",
            "cmd-d": "dist/cli.mjs",
        }
        expected = {
            "cmd-a": "bin/a.js",
            "cmd-b": "bin/b.js",
            "cmd-c": "dist/cli.mjs",
            "cmd-d": "dist/cli.mjs",
        }
        self.assertEqual(_normalized_npm_bin("test-pkg", targets), expected)

        # Direct ./bin and bin target regression
        self.assertEqual(_normalized_npm_bin("burst", "./bin"), {"burst": "bin"})
        self.assertEqual(_normalized_npm_bin("burst", "bin"), {"burst": "bin"})
        self.assertEqual(_normalized_npm_bin("burst", {"burst": "./bin"}), {"burst": "bin"})
        self.assertEqual(_normalized_npm_bin("burst", {"burst": "bin"}), {"burst": "bin"})

        # Missing or None bin returns empty dict
        self.assertEqual(_normalized_npm_bin("pkg", None), {})

    def test_valid_bin_array_normalized_by_basename(self):
        """Array of unique bin paths normalizes each command to its basename."""
        self.assertEqual(
            _normalized_npm_bin("my-pkg", ["./bin/tool-a", "bin/tool-b", "./dist/tool-c"]),
            {"tool-a": "bin/tool-a", "tool-b": "bin/tool-b", "tool-c": "dist/tool-c"},
        )

    def test_rejects_duplicate_array_basename_aliases(self):
        """Array with colliding basenames fails closed with duplicate array basename aliases."""
        colliding_cases = [
            ["./bin/tool", "./other/tool"],
            ["bin/tool", "other/tool"],
            ["./dir1/sub/tool.js", "./dir2/tool.js"],
        ]
        for paths in colliding_cases:
            with self.subTest(paths=paths):
                with self.assertRaises(ContractError) as caught:
                    _normalized_npm_bin("my-pkg", paths)
                self.assertEqual(caught.exception.code, "NPM_METADATA")
                self.assertIn("Duplicate array basename aliases", str(caught.exception))

    def test_rejects_multiple_dot_slash_prefixes(self):
        """Multiple ./ prefixes (e.g. ././bin) are rejected."""
        invalid_targets = ["././bin/tool.js", "./././tool.js"]
        for target in invalid_targets:
            with self.subTest(target=target):
                with self.assertRaises(ContractError):
                    _normalized_npm_bin("pkg", target)

    def test_rejects_absolute_paths(self):
        """Absolute paths starting with / are rejected."""
        absolute_targets = ["/bin/tool", "/usr/bin/tool", "/cli.js"]
        for target in absolute_targets:
            with self.subTest(target=target):
                with self.assertRaises(ContractError):
                    _normalized_npm_bin("pkg", target)

    def test_rejects_directory_traversal(self):
        """Directory traversal segments like .. or . are rejected."""
        traversal_targets = [
            "../bin/tool",
            "./../bin/tool",
            "bin/../tool",
            "bin/../../tool",
            "bin/./tool",
        ]
        for target in traversal_targets:
            with self.subTest(target=target):
                with self.assertRaises(ContractError):
                    _normalized_npm_bin("pkg", target)

    def test_rejects_backslashes(self):
        """Backslashes in targets are rejected rather than sanitized to slashes."""
        backslash_targets = ["bin\\tool", ".\\bin\\tool", "bin\\subdir\\tool.js"]
        for target in backslash_targets:
            with self.subTest(target=target):
                with self.assertRaises(ContractError):
                    _normalized_npm_bin("pkg", target)

    def test_rejects_nul_and_control_characters(self):
        """NUL bytes and ASCII control characters are rejected."""
        control_targets = ["bin/\0tool", "bin/\x1ftool", "bin/\r/tool", "bin/\n/tool"]
        for target in control_targets:
            with self.subTest(target=target):
                with self.assertRaises(ContractError):
                    _normalized_npm_bin("pkg", target)

    def test_rejects_empty_targets(self):
        """Empty string and isolated ./ target are rejected."""
        for target in ("", "./"):
            with self.subTest(target=target):
                with self.assertRaises(ContractError):
                    _normalized_npm_bin("pkg", target)

    def test_rejects_invalid_types_and_unsupported_metadata(self):
        """Non-string/dict/list/None bin structures are rejected."""
        for invalid in (123, True, [123], {"cmd": 123}, {"": "bin/tool"}):
            with self.subTest(invalid=invalid):
                with self.assertRaises(ContractError):
                    _normalized_npm_bin("pkg", invalid)


class ReadNpmAndHomebrewTests(unittest.TestCase):
    def test_read_npm_with_dot_slash_bin_reaches_exact_state(self):
        import base64
        import hashlib
        import io
        import tarfile
        from unittest.mock import patch
        from rs9.readers import read_npm
        from rs9.scratch import canonical

        package = {
            "name": "fixture-tool",
            "version": "1.0.0",
            "license": "MIT",
            "bin": {"fixture-tool": "./bin/main.js"},
        }
        metadata = canonical(package)
        buffer = io.BytesIO()
        with tarfile.open(fileobj=buffer, mode="w:gz") as archive:
            member = tarfile.TarInfo("package/package.json")
            member.size = len(metadata)
            archive.addfile(member, io.BytesIO(metadata))
        payload = buffer.getvalue()
        integrity = "sha512-" + base64.b64encode(hashlib.sha512(payload).digest()).decode()
        registry = {
            "name": "fixture-tool",
            "versions": {
                "1.0.0": {
                    **package,
                    "dist": {
                        "integrity": integrity,
                        "tarball": "https://registry.npmjs.org/fixture-tool/-/fixture-tool-1.0.0.tgz",
                    },
                }
            },
        }
        with patch("rs9.readers._get", side_effect=[canonical(registry), payload]):
            obs = read_npm(
                "fixture-tool",
                "1.0.0",
                expected_integrity=integrity,
                expected_license="MIT",
                expected_commands={"fixture-tool": "bin/main.js"},
                expected_hashes={"fixture-tool-1.0.0.tgz": hashlib.sha256(payload).hexdigest()},
            )
        self.assertEqual(obs["state"], "exact")

    def test_read_npm_with_unsafe_bin_fails_closed_to_unknown_with_diagnostic(self):
        from unittest.mock import patch
        from rs9.readers import read_npm
        from rs9.scratch import canonical

        registry = {
            "name": "unsafe-tool",
            "versions": {
                "1.0.0": {
                    "name": "unsafe-tool",
                    "version": "1.0.0",
                    "license": "MIT",
                    "bin": {"unsafe-tool": "../etc/passwd"},
                    "dist": {
                        "integrity": "sha512-" + "a" * 86 + "==",
                        "tarball": "https://registry.npmjs.org/unsafe-tool/-/unsafe-tool-1.0.0.tgz",
                    },
                }
            },
        }
        with patch("rs9.readers._get", return_value=canonical(registry)):
            obs = read_npm(
                "unsafe-tool",
                "1.0.0",
                expected_integrity="sha512-" + "a" * 86 + "==",
                expected_license="MIT",
                expected_commands={"unsafe-tool": "bin/tool.js"},
            )
        self.assertEqual(obs["state"], "unknown")
        diags = obs.get("diagnostics", [])
        self.assertTrue(any(d.get("code") == "destination-contract-error" for d in diags))

    def test_read_homebrew_requires_immutable_pinned_ref(self):
        from rs9.readers import read_homebrew

        for bad_ref in ("main", "HEAD", "not-a-sha", "1" * 39, "1" * 41):
            with self.subTest(bad_ref=bad_ref):
                with self.assertRaises(ContractError) as caught:
                    read_homebrew("test-tool", "1.0.0", pinned_ref=bad_ref)
                self.assertEqual(caught.exception.code, "HOMEBREW_PIN")

    def test_read_homebrew_requires_homebrew_adapter(self):
        from rs9.readers import read_homebrew

        with self.assertRaises(ContractError) as caught:
            read_homebrew({"id": "npm", "adapter": "npm", "mode": "projection"}, pinned_ref="a" * 40)
        self.assertEqual(caught.exception.code, "READER_DESTINATION")


if __name__ == "__main__":
    unittest.main()
