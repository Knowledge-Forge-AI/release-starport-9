"""Node prerequisite, argument preservation, exit status, unsupported hosts."""
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from rs9 import tf_pypi_launcher as launcher
from rs9.tf_pypi_archive import AdmissionError
from rs9.tf_pypi_consumer import host_system, smoke
from rs9.tf_pypi_backend import build_pair
from tests.tf_pypi_fixtures import fixture


class LauncherTests(unittest.TestCase):
    def test_missing_node_and_nonexecutable_override(self):
        with patch.dict(os.environ, {}, clear=True), patch.object(launcher.shutil, "which", return_value=None):
            with self.assertRaises(RuntimeError):
                launcher.node_binary()
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "node"
            path.write_text("fixture")
            path.chmod(0o644)
            with patch.dict(os.environ, {"THEME_FORGE_NODE_BIN": str(path)}, clear=True):
                with self.assertRaises(RuntimeError):
                    launcher.node_binary()

    def test_old_malformed_and_failed_node_version(self):
        for version, code in (("v20.11.0", 0), ("node version 22", 0), ("v22.22.2", 1)):
            result = subprocess.CompletedProcess([], code, version, "")
            with patch.dict(os.environ, {"THEME_FORGE_NODE_BIN": "/bin/sh"}, clear=True), \
                    patch.object(launcher.subprocess, "run", return_value=result) as run:
                if code:
                    run.side_effect = subprocess.CalledProcessError(code, [])
                with self.assertRaises(RuntimeError):
                    launcher.node_binary()

    def test_exec_preserves_command_arguments_and_real_exit_semantics(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory).resolve() / "launcher.py"
            target = path.parent / "payload/package/bin/cli.js"
            target.parent.mkdir(parents=True)
            target.touch()
            with patch.object(launcher, "__file__", str(path)), \
                    patch.object(launcher, "TARGETS", {"fixture": "bin/cli.js"}, create=True), \
                    patch.object(launcher, "node_binary", return_value="/fixture/node"), \
                    patch.object(launcher, "check_platform"), \
                    patch.object(launcher.os, "execv") as execute, \
                    patch.object(launcher.sys, "argv", ["fixture", "space argument", "--flag"]):
                launcher.run("fixture")
            execute.assert_called_once_with("/fixture/node", ["/fixture/node", str(target), "space argument", "--flag"])

    def test_windows_launcher_and_unsupported_consumers_refuse(self):
        with patch.object(launcher.os, "name", "nt"), patch.object(launcher.sys.stderr, "write"), \
                self.assertRaises(SystemExit):
            launcher.run("fixture")
        for system, arch in (("Windows", "AMD64"), ("Darwin", "x86_64"), ("Linux", "ppc64")):
            with patch("platform.system", return_value=system), patch("platform.machine", return_value=arch), \
                    self.assertRaises(AdmissionError):
                host_system()

    def test_synthetic_wheel_and_sdist_real_node_pip_install_commands_and_uninstall(self):
        # This exercises pip and Node, but never the released Theme Forge product.
        try:
            launcher.node_binary()
            system = host_system()
        except (RuntimeError, AdmissionError):
            self.skipTest("compatible local Python/Node/POSIX host unavailable")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            for project in ("theme-forge-stellar-loom", "theme-forge-solar-sail"):
                pin, data = fixture(project)
                dist = root / project / "dist"
                build_pair(pin, data, dist)
                receipt = smoke(pin, dist, root / project / "consumer", functional=False,
                                offline_linux=system.endswith("-linux"))
                self.assertEqual(len(receipt["lifecycle"]), 2)
                self.assertTrue(receipt["offline_isolation"]["network_disabled"])
                self.assertFalse(receipt["publication_admitted"])
