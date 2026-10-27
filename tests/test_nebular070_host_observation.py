"""Focused contract tests for the actual-only Nebular Linux host observer."""
from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock

import rs9.nebular070_host_observation as observer
from rs9.errors import ContractError
from rs9.nebular070_manylinux import HOST_FLOOR_SCHEMA, _digest


class ProbeRunner:
    """Bounded synthetic command results; never used by the production CLI."""

    def __init__(self, *, machine="Advanced Micro Devices X86-64", ldd="2.36", loader="2.36", loader_text=None,
                 ldd_text=None, loader_version_text=None):
        self.machine = machine
        self.ldd = ldd
        self.loader = loader
        self.loader_text = loader_text
        self.ldd_text = ldd_text
        self.loader_version_text = loader_version_text
        self.calls = []

    def __call__(self, argv):
        self.calls.append(tuple(argv))
        executable = Path(argv[0]).name
        if executable == "readelf":
            interpreter = "/lib64/ld-linux-x86-64.so.2"
            if self.machine == "AArch64":
                interpreter = "/lib/ld-linux-aarch64.so.1"
            text = f"  Machine: {self.machine}\n"
            text += f"      [Requesting program interpreter: {interpreter}]\n"
            if self.loader_text is not None:
                text = self.loader_text
            return subprocess.CompletedProcess(argv, 0, text.encode(), b"")
        if executable == "ldd":
            text = self.ldd_text if self.ldd_text is not None else f"ldd (GNU libc) {self.ldd}\n"
            return subprocess.CompletedProcess(argv, 0, text.encode(), b"")
        text = self.loader_version_text if self.loader_version_text is not None else f"GNU C Library {self.loader}\n"
        return subprocess.CompletedProcess(argv, 0, text.encode(), b"")


class Nebular070HostObservationTests(unittest.TestCase):
    def _observe(self, role="floor", *, runner=None, python="2.36", platform_version="2.36"):
        runner = runner or ProbeRunner(ldd=python, loader=python)
        self.last_runner = runner
        with mock.patch.object(observer.platform, "system", return_value="Linux"), mock.patch.object(
            observer.platform, "machine", return_value="x86_64"
        ):
            return observer.observe_host(
                role,
                command_runner=runner,
                python_libc_probe=lambda: python,
                platform_libc_probe=lambda: ("glibc", platform_version),
            )

    def test_actual_shape_and_identity_are_closed(self):
        body, extras = self._observe()
        self.assertEqual(
            set(body), {"schema", "target", "role", "status", "glibc", "loader", "identity"}
        )
        self.assertEqual(body["schema"], HOST_FLOOR_SCHEMA)
        self.assertEqual(body["target"], "x86_64-unknown-linux-gnu")
        self.assertEqual(body["role"], "floor")
        self.assertEqual(body["status"], "observed")
        self.assertEqual(body["identity"], _digest({key: value for key, value in body.items() if key != "identity"}))
        self.assertEqual(self.last_runner.calls[0][-1], f"/proc/{os.getpid()}/exe")
        self.assertEqual(extras["evidence_mode"], "synthetic")
        self.assertEqual(extras["body_identity"], body["identity"])
        self.assertEqual(len(extras["probes"]), 3)

    def test_non_linux_rejected_before_probe(self):
        runner = ProbeRunner()
        with mock.patch.object(observer.platform, "system", return_value="Darwin"), mock.patch.object(
            observer.platform, "machine", return_value="arm64"
        ), self.assertRaises(ContractError) as context:
            observer.observe_host(
                "floor", command_runner=runner, python_libc_probe=lambda: "2.36",
                platform_libc_probe=lambda: ("glibc", "2.36"),
            )
        self.assertEqual(context.exception.code, "NEBULAR_HOST_PLATFORM")
        self.assertEqual(runner.calls, [])

    def test_machine_and_elf_machine_must_agree(self):
        runner = ProbeRunner(machine="Advanced Micro Devices X86-64")
        with mock.patch.object(observer.platform, "system", return_value="Linux"), mock.patch.object(
            observer.platform, "machine", return_value="aarch64"
        ), self.assertRaises(ContractError) as context:
            observer.observe_host(
                "floor", command_runner=runner, python_libc_probe=lambda: "2.36",
                platform_libc_probe=lambda: ("glibc", "2.36"),
            )
        self.assertEqual(context.exception.code, "NEBULAR_HOST_ARCHITECTURE")

    def test_missing_or_ambiguous_loader_rejected(self):
        for readelf in (
            "  Machine: Advanced Micro Devices X86-64\n",
            "  Machine: Advanced Micro Devices X86-64\n"
            "      [Requesting program interpreter: /lib64/ld-linux-x86-64.so.2]\n"
            "      [Requesting program interpreter: /lib64/ld-linux-x86-64.so.2]\n",
        ):
            runner = ProbeRunner(loader_text=readelf)
            with self.subTest(readelf=readelf), self.assertRaises(ContractError) as context:
                self._observe(runner=runner)
            self.assertEqual(context.exception.code, "NEBULAR_HOST_LOADER")

    def test_loader_path_and_architecture_are_checked(self):
        runner = ProbeRunner(
            loader_text="  Machine: Advanced Micro Devices X86-64\n"
            "      [Requesting program interpreter: /home/operator/ld-linux-x86-64.so.2]\n"
        )
        with self.assertRaises(ContractError) as context:
            self._observe(runner=runner)
        self.assertEqual(context.exception.code, "NEBULAR_HOST_LOADER")

    def test_distribution_package_revisions_do_not_make_versions_ambiguous(self):
        for role, version, package in (
            ("floor", "2.36", "Debian GLIBC 2.36-9+deb12u13"),
            ("newer", "2.39", "Ubuntu GLIBC 2.39-0ubuntu8.4"),
        ):
            runner = ProbeRunner(
                ldd_text=f"ldd ({package}) {version}\nCopyright (C) 2024 Free Software Foundation, Inc.\n",
                loader_version_text=f"ld.so ({package}) stable release version {version}.\n",
            )
            with self.subTest(package=package):
                body, extras = self._observe(role, runner=runner, python=version, platform_version=version)
                self.assertEqual(body["glibc"], version)
                self.assertEqual(extras["cross_checks"]["ldd"], version)
                self.assertEqual(extras["cross_checks"]["loader"], version)

    def test_distinct_standalone_versions_remain_ambiguous(self):
        runner = ProbeRunner(ldd_text="ldd (GNU libc) 2.36\nldd (GNU libc) 2.39\n")
        with self.assertRaises(ContractError) as context:
            self._observe(runner=runner)
        self.assertEqual(context.exception.code, "NEBULAR_HOST_GLIBC")

    def test_banner_microversions_and_attached_words_are_not_normalized(self):
        for version in ("2.36.9000", "2.36vendor", "2.36+vendor"):
            for probe in ("ldd", "loader"):
                kwargs = {"ldd_text": f"ldd (GNU libc) {version}\n"} if probe == "ldd" else {
                    "loader_version_text": f"GNU C Library {version}\n"
                }
                with self.subTest(version=version, probe=probe):
                    with self.assertRaises(ContractError) as context:
                        self._observe(runner=ProbeRunner(**kwargs))
                    self.assertEqual(context.exception.code, "NEBULAR_HOST_GLIBC")

    def test_python_platform_ldd_and_loader_versions_must_match(self):
        runner = ProbeRunner(ldd="2.37", loader="2.36")
        with self.assertRaises(ContractError) as context:
            self._observe(runner=runner, python="2.36", platform_version="2.36")
        self.assertEqual(context.exception.code, "NEBULAR_HOST_GLIBC")

    def test_floor_and_newer_thresholds_are_fail_closed(self):
        with self.assertRaises(ContractError) as floor_context:
            self._observe("floor", python="2.37", platform_version="2.37")
        self.assertEqual(floor_context.exception.code, "NEBULAR_HOST_FLOOR")
        with self.assertRaises(ContractError) as newer_context:
            self._observe("newer", python="2.36", platform_version="2.36")
        self.assertEqual(newer_context.exception.code, "NEBULAR_HOST_FLOOR")
        body, _ = self._observe("newer", python="2.37", platform_version="2.37")
        self.assertEqual(body["role"], "newer")

    def test_synthetic_observation_cannot_be_written_as_actual(self):
        body, extras = self._observe()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            with self.assertRaises(ContractError) as context:
                observer._write_observation(root / "body.json", root / "extras.json", body, extras)
            self.assertEqual(context.exception.code, "NEBULAR_HOST_OUTPUT")
            self.assertFalse((root / "body.json").exists())
            self.assertFalse((root / "extras.json").exists())

    def test_actual_body_and_sidecar_are_exclusive_and_canonical(self):
        unsigned = {
            "schema": HOST_FLOOR_SCHEMA,
            "target": "x86_64-unknown-linux-gnu",
            "role": "floor",
            "status": "observed",
            "glibc": "2.36",
            "loader": "/lib64/ld-linux-x86-64.so.2",
        }
        body = {**unsigned, "identity": _digest(unsigned)}

        def proof(tool, args):
            stream = {"bytes": 0, "sha256": "0" * 64}
            custody = {
                "termination": "exited", "reaped": True, "cleanup": "not-needed",
                "returncode": 0, "stdout": {"bytes": 0, "complete": True},
                "stderr": {"bytes": 0, "complete": True}, "deadline_ms": 5000,
                "limit_bytes": observer.MAX_PROBE_BYTES,
            }
            return {
                "tool": tool, "args": args, "frame": "same-process-linux-host",
                "termination": "exited", "reaped": True, "cleanup": "not-needed",
                "returncode": 0, "stdout": stream, "stderr": stream, "custody": custody,
            }

        extras = {
            "schema": "rs9.nebular070-host-observation-extras.v1",
            "evidence_mode": "actual",
            "target": "linux-x64-gnu",
            "role": "floor",
            "frame": "same-process-linux-host",
            "platform": {"system": "Linux", "machine": "x86_64"},
            "cross_checks": {"python_libc": "2.36", "platform_libc": "2.36", "ldd": "2.36", "loader": "2.36"},
            "probes": [
                proof("readelf", ["-h", "-l", "--wide", f"/proc/{os.getpid()}/exe"]),
                proof("ldd", ["--version"]),
                proof("ld-linux-x86-64.so.2", ["--version"]),
            ],
            "body_identity": body["identity"],
        }
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            body_path, extras_path = root / "body.json", root / "extras.json"
            observer._write_observation(body_path, extras_path, body, extras)
            self.assertEqual(json.loads(body_path.read_text()), body)
            self.assertEqual(json.loads(extras_path.read_text()), extras)
            with self.assertRaises(ContractError) as context:
                observer._write_observation(body_path, root / "second.json", body, extras)
            self.assertEqual(context.exception.code, "NEBULAR_HOST_OUTPUT")
            self.assertFalse((root / "second.json").exists())

    def test_protected_output_components_are_refused_before_open(self):
        unsigned = {
            "schema": HOST_FLOOR_SCHEMA,
            "target": "x86_64-unknown-linux-gnu",
            "role": "floor",
            "status": "observed",
            "glibc": "2.36",
            "loader": "/lib64/ld-linux-x86-64.so.2",
        }
        body = {**unsigned, "identity": _digest(unsigned)}
        extras = {
            "schema": "rs9.nebular070-host-observation-extras.v1",
            "evidence_mode": "actual",
            "body_identity": body["identity"],
            "frame": "same-process-linux-host",
            "probes": [],
        }
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            with self.assertRaises(ContractError) as context:
                observer._write_observation(root / "RAW" / "body.json", root / "extras.json", body, extras)
            self.assertEqual(context.exception.code, "NEBULAR_HOST_OUTPUT")
            self.assertFalse((root / "RAW").exists())


class HostObservationWriteRaceTests(unittest.TestCase):
    """Serialization races must preserve paths owned or changed by another writer."""

    def test_sidecar_created_after_preflight_is_preserved(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            body_path, sidecar = root / "body.json", root / "extras.json"
            original = observer._write_exclusive

            def competing_write(path, data):
                if path == sidecar:
                    sidecar.write_bytes(b"other writer")
                return original(path, data)

            with mock.patch.object(observer, "validate_observation_body", return_value={"identity": "a" * 64}), \
                 mock.patch.object(observer, "_validate_extras"), \
                 mock.patch.object(observer, "_write_exclusive", side_effect=competing_write):
                with self.assertRaises(ContractError):
                    observer._write_observation(body_path, sidecar, {}, {})
            self.assertEqual(sidecar.read_bytes(), b"other writer")
            self.assertFalse(body_path.exists())
            self.assertEqual(sorted(path.name for path in root.iterdir()), ["extras.json"])

    def test_changed_sidecar_is_preserved_after_body_failure(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            body_path, sidecar = root / "body.json", root / "extras.json"
            original = observer._write_exclusive

            def competing_write(path, data):
                if path == body_path:
                    sidecar.write_bytes(b"changed by another writer")
                    raise ContractError("NEBULAR_HOST_OUTPUT", "fixture body failure")
                return original(path, data)

            with mock.patch.object(observer, "validate_observation_body", return_value={"identity": "a" * 64}), \
                 mock.patch.object(observer, "_validate_extras"), \
                 mock.patch.object(observer, "_write_exclusive", side_effect=competing_write):
                with self.assertRaises(ContractError):
                    observer._write_observation(body_path, sidecar, {}, {})
            self.assertEqual(sidecar.read_bytes(), b"changed by another writer")
            self.assertFalse(body_path.exists())
            self.assertEqual(sorted(path.name for path in root.iterdir()), ["extras.json"])


if __name__ == "__main__":
    unittest.main()
