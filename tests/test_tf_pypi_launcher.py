"""Node prerequisite, argument preservation, exit status, unsupported hosts."""
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from rs9 import tf_pypi_consumer as consumer
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


    def test_smoke_propagates_owned_temp_paths_to_all_subprocesses(self):
        calls = []
        wheel_name = "theme-forge-stellar-loom-py3-none-any.whl"
        sdist_name = "theme-forge-stellar-loom-0.5.0.tar.gz"

        class Builder:
            def __init__(self, **kwargs):
                self.kwargs = kwargs

            def create(self, root):
                (Path(root) / "bin").mkdir(parents=True)

        def fake_run(argv, env, *, prefix=(), input=b""):
            calls.append(dict(env))
            if "--wheel-dir" in argv:
                wheel_dir = Path(argv[argv.index("--wheel-dir") + 1])
                wheel_dir.mkdir(parents=True, exist_ok=True)
                (wheel_dir / wheel_name).write_bytes((dist / wheel_name).read_bytes())
            return subprocess.CompletedProcess(list(argv), 0, b"v22.23.3\n", b"")

        def fake_network_denial(python, node, env, prefix=()):
            calls.append(dict(env))
            return {"network_disabled": True}

        pin = {"project": "theme-forge-stellar-loom", "version": "0.5.0", "bins": {}}
        manifest = {
            "files": [{"filename": wheel_name}, {"filename": sdist_name}],
            "set_sha256": "fixture-set",
        }
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            dist = root / "dist"
            dist.mkdir()
            (dist / wheel_name).write_bytes(b"wheel")
            (dist / sdist_name).write_bytes(b"sdist")
            work = root / "consumer"
            with patch.object(consumer, "host_key", return_value="aarch64-darwin"), \
                    patch.object(consumer, "host_system", return_value="aarch64-darwin"), \
                    patch.object(consumer, "node_binary", return_value="/fixture/node"), \
                    patch.object(consumer, "verify_pair", return_value=manifest), \
                    patch.object(consumer.venv, "EnvBuilder", Builder), \
                    patch.object(consumer, "network_denial", side_effect=fake_network_denial), \
                    patch.object(consumer, "_run", side_effect=fake_run):
                result = consumer.smoke(pin, dist, work, functional=False)

            expected_temp = str(work / "tmp")
            self.assertTrue(calls)
            self.assertTrue(all(call["TMPDIR"] == expected_temp for call in calls))
            self.assertTrue(all(call["TMP"] == expected_temp for call in calls))
            self.assertTrue(all(call["TEMP"] == expected_temp for call in calls))
            self.assertEqual((work / "tmp").stat().st_mode & 0o777, 0o700)
            self.assertEqual([row["kind"] for row in result["lifecycle"]], ["wheel", "sdist"])
            self.assertFalse(result["publication_admitted"])
