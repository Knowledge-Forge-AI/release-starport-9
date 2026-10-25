"""Unit fixture tests for STUDIO_DRIVER version binding and the _burst studio seam.

This module provides unit fixture evidence only using a tiny bounded fake
JSON-RPC service in temporary directories. It is never real native, platform,
or installed-consumer qualification evidence.
"""
import json
from pathlib import Path
import shlex
import subprocess
import sys
import tempfile
import unittest

from rs9.tf_pypi_archive import AdmissionError
from rs9.tf_pypi_model import load_pin
from rs9.tf_pypi_probes import STUDIO_DRIVER, functional_probes
from tests.tf_pypi_fixtures import ROOT

PIN_DIR = ROOT / "operators/tf-pypi"

FAKE_SERVICE = """import json, pathlib, sys

declared = sys.argv[1]
log_path = pathlib.Path(sys.argv[2])
expected_nonce = "fixture-nonce"

for raw in sys.stdin:
    msg = json.loads(raw)
    method = msg.get("method", "")
    with log_path.open("a", encoding="utf-8") as log_file:
        log_file.write(method + "\\n")
        log_file.flush()
    if method == "initialize":
        reply = {
            "jsonrpc": "2.0",
            "id": msg["id"],
            "result": {
                "sessionNonce": expected_nonce,
                "selectedVersion": "1.2",
                "server": {"name": "fixture", "version": declared},
            },
        }
        sys.stdout.write(json.dumps(reply) + "\\n")
        sys.stdout.flush()
    elif method == "exit":
        sys.exit(0)
    else:
        if msg.get("params", {}).get("sessionNonce") != expected_nonce:
            sys.exit(3)
        if method == "shutdown":
            reply = {"jsonrpc": "2.0", "id": msg["id"], "result": None}
            sys.stdout.write(json.dumps(reply) + "\\n")
            sys.stdout.flush()

sys.exit(4)
"""


def _write_fake_service(directory: Path, declared_version: str, wrapper_path: Path | None = None):
    directory.mkdir(parents=True, exist_ok=True)
    script_path = directory / "fake_studio_service.py"
    log_path = directory / "studio_methods.log"
    script_path.write_text(FAKE_SERVICE, encoding="utf-8")
    log_path.write_text("", encoding="utf-8")
    target_wrapper = wrapper_path if wrapper_path is not None else (directory / "tfsb-studio-service")
    target_wrapper.parent.mkdir(parents=True, exist_ok=True)
    cmd = " ".join(
        shlex.quote(part)
        for part in (sys.executable, "-I", "-B", str(script_path), declared_version, str(log_path))
    )
    target_wrapper.write_text(f"#!/bin/sh\nexec {cmd}\n", encoding="utf-8")
    target_wrapper.chmod(0o700)
    return target_wrapper, log_path


class StudioDriverTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()

    def _run_driver(self, case_name: str, expected_version: str, declared_version: str):
        case_dir = self.root / case_name
        wrapper, log_path = _write_fake_service(case_dir, declared_version)
        env = {
            "PATH": "/usr/bin:/bin",
            "HOME": str(case_dir),
            "LANG": "C",
        }
        result = subprocess.run(
            [sys.executable, "-I", "-B", "-c", STUDIO_DRIVER, str(wrapper), expected_version],
            capture_output=True,
            timeout=60,
            cwd=str(case_dir),
            env=env,
        )
        methods = log_path.read_text(encoding="utf-8").splitlines()
        return result, methods

    def test_lifecycle_succeeds_for_historical_and_successor_versions(self):
        for idx, version in enumerate(("0.6.1", "0.7.0")):
            with self.subTest(version=version):
                result, methods = self._run_driver(f"ok-{idx}", version, version)
                self.assertEqual(result.returncode, 0, result.stderr.decode("utf-8", errors="replace"))
                self.assertEqual(
                    json.loads(result.stdout),
                    {
                        "initialize": True,
                        "shutdown": True,
                        "exit": 0,
                        "selectedVersion": "1.2",
                    },
                )
                self.assertEqual(methods, ["initialize", "initialized", "shutdown", "exit"])

    def test_rejects_mismatched_expected_and_server_versions(self):
        pairs = (
            ("0.7.0", "0.6.1"),
            ("0.6.1", "0.7.0"),
            ("0.7.0", "0.7.1"),
        )
        for idx, (expected_version, declared_version) in enumerate(pairs):
            with self.subTest(expected=expected_version, declared=declared_version):
                result, methods = self._run_driver(
                    f"mismatch-{idx}", expected_version, declared_version
                )
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(result.stdout, b"")
                self.assertIn(b"AssertionError", result.stderr)
                self.assertEqual(methods, ["initialize"])


class BurstSeamTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()

    def _prepare_case(self, case_name: str, declared_version: str):
        case_dir = self.root / case_name
        home_dir = case_dir / "home"
        home_dir.mkdir(parents=True)
        wheel_root = case_dir / "wheel"
        payload_dir = (
            wheel_root
            / "lib/python3.11/site-packages/theme_forge_stellar_burst/payload/package"
        )
        payload_dir.mkdir(parents=True)
        service_wrapper = wheel_root / "bin/tfsb-studio-service"
        _, log_path = _write_fake_service(
            case_dir / "service", declared_version, wrapper_path=service_wrapper
        )
        absent_node = str(case_dir / "absent-node")
        env = {
            "HOME": str(home_dir),
            "PATH": "/usr/bin:/bin",
            "LANG": "C",
            "THEME_FORGE_NODE_BIN": absent_node,
        }
        wheel_python = str(wheel_root / "bin/python")

        def run(argv, run_env, *, prefix=(), input=b""):
            del prefix
            str_argv = list(map(str, argv))
            if str_argv[0] == wheel_python:
                return subprocess.run(
                    [sys.executable, *str_argv[1:]],
                    env=dict(run_env),
                    input=input,
                    capture_output=True,
                    timeout=60,
                    cwd=run_env.get("HOME"),
                )
            if str_argv[0] == absent_node:
                return subprocess.CompletedProcess(
                    str_argv, 0, b'{"ok":true,"artifact":"unit-fixture","reason":null}\n', b""
                )
            return subprocess.CompletedProcess(str_argv, 0, b'{"status":"ok"}\n', b"")

        return wheel_root, env, run, log_path

    def test_selected_pin_version_reaches_real_driver(self):
        pins = (
            ("historical", load_pin("theme-forge-stellar-burst")),
            (
                "successor",
                load_pin(
                    "theme-forge-stellar-burst",
                    PIN_DIR / "theme-forge-stellar-burst-0.7.0.json",
                ),
            ),
        )
        for label, pin in pins:
            with self.subTest(release=label, version=pin["version"]):
                wheel_root, env, run, log_path = self._prepare_case(
                    f"seam-ok-{label}", pin["version"]
                )
                receipts = functional_probes(pin, wheel_root, env, (), run)
                self.assertEqual(len(receipts), 6)
                studio_receipt = receipts[-1]
                self.assertEqual(studio_receipt["command"], "tfsb-studio-service")
                self.assertEqual(studio_receipt["operation"], "initialize-shutdown-exit")
                self.assertEqual(studio_receipt["exit"], 0)
                self.assertEqual(
                    log_path.read_text(encoding="utf-8").splitlines(),
                    ["initialize", "initialized", "shutdown", "exit"],
                )

    def test_mismatched_service_version_refused_as_functional_studio(self):
        cases = (
            ("historical", load_pin("theme-forge-stellar-burst"), "0.7.0"),
            (
                "successor",
                load_pin(
                    "theme-forge-stellar-burst",
                    PIN_DIR / "theme-forge-stellar-burst-0.7.0.json",
                ),
                "0.6.1",
            ),
        )
        for label, pin, wrong_declared in cases:
            with self.subTest(release=label, pin_version=pin["version"], declared=wrong_declared):
                wheel_root, env, run, log_path = self._prepare_case(
                    f"seam-mismatch-{label}", wrong_declared
                )
                with self.assertRaises(AdmissionError) as caught:
                    functional_probes(pin, wheel_root, env, (), run)
                self.assertEqual(caught.exception.code, "TF_PYPI_FUNCTIONAL_STUDIO")
                self.assertEqual(
                    log_path.read_text(encoding="utf-8").splitlines(),
                    ["initialize"],
                )


if __name__ == "__main__":
    unittest.main()
