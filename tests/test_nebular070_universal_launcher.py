"""Synthetic contracts for the universal launcher's explicit runtime setup."""

import contextlib
import hashlib
import io
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from rs9 import nebular070_universal_launcher as launcher


class UniversalLauncherTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.package = self.root / "package"
        (self.package / "runtimes").mkdir(parents=True)
        self.cache = self.root / "cache"
        self.payload = b"synthetic archive, never executed"
        self.asset = {"id": 1, "name": "fixture.tar.gz", "size": len(self.payload),
                      "sha256": hashlib.sha256(self.payload).hexdigest(),
                      "url": "https://github.com/fixture"}
        manifest = {"root": "fixture", "members": [], "manifest_sha256": "a" * 64}
        raw_manifest = json.dumps(manifest).encode()
        self.spec = {"asset": self.asset, "root": "fixture", "manifest_sha256": "a" * 64,
                     "manifest_resource_sha256": hashlib.sha256(raw_manifest).hexdigest(),
                     "shell_target": "fixture/bin/tfnf", "gui_target": "fixture/bin/gui"}
        index = {"schema": "rs9.nebular070-universal-runtime-index.v1", "version": "0.7.0",
                 "targets": {key: self.spec for key in launcher.TARGETS}}
        raw_index = json.dumps(index).encode()
        (self.package / "runtime-index.json").write_bytes(raw_index)
        for key in launcher.TARGETS:
            (self.package / "runtimes" / (key + ".json")).write_bytes(raw_manifest)
        self.materialized = self.cache / "entries" / ("a" * 64) / "payload" / "fixture"
        self.helpers = SimpleNamespace(
            validate_ancestry_not_symlink=lambda path: Path(path),
            materialize_payload=Mock(return_value=self.materialized),
            resolve_launcher=Mock(side_effect=lambda root, rel: Path(root) / rel),
        )
        self.stack = contextlib.ExitStack()
        self.addCleanup(self.stack.close)
        self.stack.enter_context(patch.object(launcher, "_PACKAGE_DIR", self.package))
        self.stack.enter_context(patch.object(launcher, "INDEX_SHA256", hashlib.sha256(raw_index).hexdigest()))
        self.stack.enter_context(patch.object(launcher, "_materializer", return_value=self.helpers))
        self.stack.enter_context(patch.dict("os.environ", {"THEME_FORGE_CACHE_DIR": str(self.cache)}))

    def archive(self):
        (self.cache / "archives").mkdir(parents=True)
        path = self.cache / "archives" / (self.asset["sha256"] + ".tgz")
        path.write_bytes(self.payload)
        return path

    def test_help_and_version_do_not_require_platform_helpers_or_runtime(self):
        with patch.object(launcher, "_platform_key", side_effect=AssertionError("platform")), \
             patch.object(launcher, "_materializer", side_effect=AssertionError("helpers")), \
             contextlib.redirect_stdout(io.StringIO()) as out:
            self.assertEqual(launcher.run_launcher(["--help"]), 0)
            self.assertEqual(launcher.run_launcher(["--version"]), 0)
        self.assertIn("install-runtime", out.getvalue())
        self.assertIn("0.7.0", out.getvalue())
        self.assertFalse(self.cache.exists())

    def test_platform_selection_and_support_floors(self):
        cases = [("linux", "x86_64", "glibc 2.36", "", "linux-x64-gnu"),
                 ("linux", "arm64", "glibc 2.40", "", "linux-arm64-gnu"),
                 ("darwin", "arm64", "", "13.0", "darwin-arm64"),
                 ("linux", "x86_64", "glibc 2.35", "", None),
                 ("linux", "aarch64", "musl 1.2", "", None),
                 ("darwin", "x86_64", "", "26.0", None),
                 ("darwin", "arm64", "", "12.7", None),
                 ("win32", "AMD64", "", "", None)]
        for system, machine, libc, mac, expected in cases:
            with self.subTest(system=system, machine=machine, libc=libc, mac=mac), \
                 patch.object(launcher.sys, "platform", system), \
                 patch.object(launcher.platform, "machine", return_value=machine), \
                 patch.object(launcher.platform, "mac_ver", return_value=(mac, (), "")), \
                 patch.object(launcher.os, "confstr", return_value=libc):
                if expected:
                    self.assertEqual(launcher._platform_key(), expected)
                else:
                    with self.assertRaises(launcher.RuntimeSetupError):
                        launcher._platform_key()

    def test_missing_runtime_never_fetches_or_materializes(self):
        with patch.object(launcher, "_platform_key", return_value="linux-x64-gnu"), \
             patch.object(launcher, "_fetcher", side_effect=AssertionError("network")):
            for args in ([], ["--path"]):
                with self.assertRaisesRegex(launcher.RuntimeSetupError, "tfnf install-runtime"):
                    launcher.run_launcher(args)
        self.helpers.materialize_payload.assert_not_called()
        self.assertFalse(self.cache.exists())

    def test_installed_launch_verifies_archive_and_forwards_argv_without_fetch(self):
        self.archive()
        with patch.object(launcher, "_platform_key", return_value="linux-x64-gnu"), \
             patch.object(launcher, "_webkit_preflight") as webkit, \
             patch.object(launcher, "_fetcher", side_effect=AssertionError("network")), \
             patch.object(launcher.os, "execv") as execute:
            self.assertEqual(launcher.run_launcher(["--fixture", "value"]), 0)
        webkit.assert_called_once()
        shell = str(self.materialized / "bin/tfnf")
        execute.assert_called_once_with(shell, [shell, "--fixture", "value"])

    def test_path_uses_verified_cache_without_loading_webkit_or_network(self):
        self.archive()
        with patch.object(launcher, "_platform_key", return_value="linux-x64-gnu"), \
             patch.object(launcher, "_webkit_preflight", side_effect=AssertionError("WebKit")), \
             patch.object(launcher, "_fetcher", side_effect=AssertionError("network")), \
             contextlib.redirect_stdout(io.StringIO()) as out:
            self.assertEqual(launcher.run_launcher(["--path"]), 0)
        self.assertEqual(out.getvalue().strip(), str(self.materialized / "bin/gui"))

    def test_corrupt_or_symlink_archive_cannot_launch(self):
        path = self.archive()
        for kind in ("corrupt", "symlink"):
            with self.subTest(kind=kind):
                if kind == "corrupt":
                    path.write_bytes(b"tampered")
                else:
                    path.unlink()
                    path.symlink_to(self.root / "outside")
                with patch.object(launcher, "_platform_key", return_value="linux-x64-gnu"), \
                     patch.object(launcher.os, "execv", side_effect=AssertionError("exec")), \
                     patch.object(launcher, "_fetcher", side_effect=AssertionError("network")):
                    with self.assertRaises(launcher.RuntimeSetupError):
                        launcher.run_launcher([])
        self.helpers.materialize_payload.assert_not_called()

    def test_explicit_install_checks_webkit_before_download_and_materialization(self):
        fetch = Mock()
        with patch.object(launcher, "_platform_key", return_value="linux-x64-gnu"), \
             patch.object(launcher, "_webkit_preflight", side_effect=launcher.RuntimeSetupError("WebKitGTK 4.1")), \
             patch.object(launcher, "_fetcher", return_value=fetch):
            with self.assertRaisesRegex(launcher.RuntimeSetupError, "WebKitGTK"):
                launcher.run_launcher(["install-runtime"])
        fetch.fetch_archive.assert_not_called()
        self.helpers.materialize_payload.assert_not_called()

    def test_explicit_install_returns_only_safe_json_after_materialization(self):
        archive = self.archive()
        fetch = SimpleNamespace(fetch_archive=Mock(return_value=SimpleNamespace(
            archive=archive, downloaded=True, redirect_hosts=("release-assets.githubusercontent.com",))))
        with patch.object(launcher, "_platform_key", return_value="darwin-arm64"), \
             patch.object(launcher, "_fetcher", return_value=fetch), \
             contextlib.redirect_stdout(io.StringIO()) as out:
            self.assertEqual(launcher.run_launcher(["install-runtime", "--json"]), 0)
        doc = json.loads(out.getvalue())
        self.assertEqual(doc["target"], "darwin-arm64")
        self.assertEqual(doc["archive_sha256"], self.asset["sha256"])
        self.assertTrue(doc["downloaded"])
        self.assertNotIn(str(self.root), out.getvalue())
        self.helpers.materialize_payload.assert_called_once()

    def test_changed_index_or_manifest_is_refused_before_extraction(self):
        self.archive()
        with patch.object(launcher, "_platform_key", return_value="darwin-arm64"):
            manifest = self.package / "runtimes/darwin-arm64.json"
            manifest.write_bytes(b"{}")
            with self.assertRaises(launcher.RuntimeSetupError):
                launcher.run_launcher(["--path"])
            (self.package / "runtime-index.json").write_bytes(b"{}")
            with self.assertRaises(launcher.RuntimeSetupError):
                launcher.run_launcher(["--path"])
        self.helpers.materialize_payload.assert_not_called()

    def test_console_errors_do_not_leak_native_or_network_exception_payloads(self):
        with patch.object(launcher, "run_launcher", side_effect=OSError("/private/fixture?secret=redacted")), \
             contextlib.redirect_stderr(io.StringIO()) as out:
            with self.assertRaises(SystemExit) as caught:
                launcher.main_tfnf()
        self.assertEqual(caught.exception.code, 1)
        self.assertNotIn("/private", out.getvalue())
        self.assertNotIn("secret", out.getvalue())

    def test_setup_errors_use_only_closed_actionable_codes_without_private_context(self):
        from rs9.nebular070_universal_fetch import RuntimeDownloadError
        for code, expected in (("TFNF_RUNTIME_TLS", "certificate"),
                               ("TFNF_RUNTIME_DEADLINE", "15-minute"),
                               ("TFNF_RUNTIME_CACHE", "THEME_FORGE_CACHE_DIR"),
                               ("TFNF_RUNTIME_DIGEST", "verification")):
            fetch = SimpleNamespace(fetch_archive=Mock(side_effect=RuntimeDownloadError(code)))
            with self.subTest(code=code), patch.object(launcher, "_platform_key", return_value="darwin-arm64"), \
                 patch.object(launcher, "_fetcher", return_value=fetch):
                with self.assertRaisesRegex(launcher.RuntimeSetupError, expected) as caught:
                    launcher.run_launcher(["install-runtime"])
                self.assertIsNone(caught.exception.__context__)
                self.assertIsNone(caught.exception.__cause__)
        fetch = SimpleNamespace(fetch_archive=Mock(side_effect=OSError("PRIVATE_MARKER")))
        with patch.object(launcher, "_platform_key", return_value="darwin-arm64"), \
             patch.object(launcher, "_fetcher", return_value=fetch):
            with self.assertRaises(launcher.RuntimeSetupError) as caught:
                launcher.run_launcher(["install-runtime"])
            self.assertNotIn("PRIVATE_MARKER", str(caught.exception))
            self.assertIsNone(caught.exception.__context__)

    def test_normal_launch_rejects_foreign_owned_archive_with_fresh_cache_guidance(self):
        import os
        self.archive()
        uid = os.geteuid()
        with patch.object(launcher, "_platform_key", return_value="darwin-arm64"), \
             patch.object(launcher.os, "geteuid", return_value=uid + 1):
            with self.assertRaisesRegex(launcher.RuntimeSetupError, "THEME_FORGE_CACHE_DIR"):
                launcher.run_launcher(["--path"])
        self.helpers.materialize_payload.assert_not_called()
