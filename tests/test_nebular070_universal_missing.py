"""Synthetic floor refusal proof for the universal launcher; no native execution."""
import hashlib
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

from rs9 import nebular070_universal_missing as missing
from rs9.errors import ContractError
from rs9.nebular070_manylinux import HOST_FLOOR_SCHEMA, _digest
from rs9.scratch import canonical


TARGET = "linux-x64-gnu"
PREFIX = ("network-denial", "--")
SOURCE = {"commit": "a" * 40, "tree": "b" * 40}
LOADER = "/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2"


def sha(text):
    return hashlib.sha256(text.encode()).hexdigest()


def host(role="floor", glibc="2.36", triple="x86_64-unknown-linux-gnu"):
    unsigned = {"schema": HOST_FLOOR_SCHEMA, "target": triple, "role": role,
                "status": "observed", "glibc": glibc, "loader": LOADER}
    body = {**unsigned, "identity": _digest(unsigned)}
    probes = [{
        "tool": tool, "args": ["--version"], "frame": "same-process-linux-host",
        "termination": "exited", "reaped": True, "cleanup": "not-needed", "returncode": 0,
        "stdout": {"bytes": 1, "sha256": "c" * 64}, "stderr": {"bytes": 0, "sha256": "d" * 64},
        "custody": {"termination": "exited", "reaped": True, "cleanup": "not-needed"},
    } for tool in ("readelf", "ldd", "ld-linux-x86-64.so.2")]
    extras = {
        "schema": "rs9.nebular070-host-observation-extras.v1", "evidence_mode": "actual",
        "target": TARGET, "role": role, "frame": "same-process-linux-host",
        "platform": {"system": "Linux", "machine": "x86_64"},
        "cross_checks": {key: glibc for key in ("python_libc", "platform_libc", "ldd", "loader")},
        "probes": probes, "body_identity": body["identity"],
    }
    return body, extras


def resign(value):
    unsigned = {key: item for key, item in value.items() if key != "identity"}
    return {**unsigned, "identity": hashlib.sha256(canonical(unsigned)).hexdigest()}


class UniversalMissingRuntimeTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name).resolve()
        (self.root / "dist").mkdir()
        self.wheel = self.root / "dist" / missing.builder.FILENAME
        self.raw = b"synthetic universal wheel bytes"
        self.wheel.write_bytes(self.raw)
        self.work = self.root / "work"
        self.snapshot = {
            "wheel": {"filename": missing.builder.FILENAME, "tag": "py3-none-any",
                      "version": "0.7.0", "size": len(self.raw),
                      "sha256": hashlib.sha256(self.raw).hexdigest()},
            "runtime_inputs": {"targets": {TARGET: {}}},
            "runtime_inputs_sha256": "1" * 64, "runtime_index_sha256": "2" * 64,
            "publication_admitted": False,
        }
        self.host = host()
        self.calls = []
        self.overrides = {}

    def environment(self, **changes):
        return {"GITHUB_ACTIONS": "true", "GITHUB_REPOSITORY": "Knowledge-Forge-AI/release-starport-9",
                "GITHUB_REF": "refs/heads/main", "GITHUB_RUN_ID": "17",
                "GITHUB_RUN_ATTEMPT": "1", "GITHUB_SHA": SOURCE["commit"], **changes}

    def result(self, code=0, stdout="", stderr=""):
        return dict(exit_code=code, signal=None, stdout_token=stdout, stderr_token=stderr,
                    stdout_sha256=sha(stdout), stderr_sha256=sha(stderr),
                    cleanup_known=True, output_complete=True, forced_cleanup=False,
                    timed_out=False, output_limit_exceeded=False, duration_ms=3,
                    bounded=True, termination_reason=None)

    def label(self, argv):
        command = self.work / "venv/bin/tfnf"
        if argv[0] == sys.executable:
            return "webkit_unavailable"
        if argv[1:4] == ["-I", "-m", "pip"]:
            return argv[4]
        return {(): "cold_launch", ("--help",): "help", ("--version",): "version",
                ("install-runtime", "--json"): "explicit_setup"}[tuple(argv[1:])] \
            if argv[0] == str(command) else "unknown"

    def fake_run(self, argv, env, cwd, prefix, timeout):
        label = self.label(argv)
        self.calls.append((label, list(argv), dict(env), tuple(prefix)))
        command = self.work / "venv/bin/tfnf"
        if label in self.overrides:
            return self.overrides[label](env)
        if label == "webkit_unavailable":
            return self.result(2)
        if label == "install":
            command.write_text("#!/bin/sh\n")
            command.chmod(0o755)
            return self.result(stdout="Successfully installed theme-forge-nebular-fusion-0.7.0\n")
        if label == "help":
            return self.result(stdout="Usage: tfnf [--version|--help|--path] [application args...]\n"
                                      "       tfnf install-runtime [--json]\n")
        if label == "version":
            return self.result(stdout="theme-forge-nebular-fusion 0.7.0\n")
        if label == "cold_launch":
            return self.result(1, stderr=missing.MISSING_LINE)
        if label == "explicit_setup":
            return self.result(1, stderr=missing.WEBKIT_LINE)
        if label == "uninstall":
            command.unlink()
            return self.result(stdout="Successfully uninstalled theme-forge-nebular-fusion-0.7.0\n")
        raise AssertionError(label)

    def create_venv(self, root):
        (Path(root) / "bin").mkdir(parents=True)
        (Path(root) / "bin/python").write_text("synthetic\n")

    def check(self, *, env=None, machine="x86_64", system="Linux", target=TARGET,
              prefix=PREFIX, run_attempt="1", host_value=None):
        observed = host_value or self.host
        with patch.dict("os.environ", env or self.environment(), clear=True), \
                patch.object(missing.platform, "machine", return_value=machine), \
                patch.object(missing.platform, "system", return_value=system), \
                patch("rs9.nebular070_host_observation.observe_host",
                      return_value=observed) as observe, \
                patch("rs9.tf_pypi_consumer._nebular_run", side_effect=self.fake_run) as run, \
                patch.object(missing.venv, "EnvBuilder") as builder:
            builder.return_value.create.side_effect = self.create_venv
            self.observe, self.run, self.builder = observe, run, builder
            return missing.check_missing_runtime(
                self.wheel, self.work, target=target, source=SOURCE, run_id="17",
                run_attempt=run_attempt, prefix=prefix, snapshot=self.snapshot)

    def read(self, value, **changes):
        arguments = dict(target=TARGET, source=SOURCE, run_id="17", run_attempt="1",
                         snapshot=self.snapshot, host_identity=self.host[0]["identity"])
        arguments.update(changes)
        return missing.validate_missing_runtime(value, **arguments)

    def assertRefused(self, function, *args, **kwargs):
        with self.assertRaises(ContractError) as caught:
            function(*args, **kwargs)
        self.assertNotIn(str(self.root), str(caught.exception))
        return caught.exception.code

    def test_success_installs_offline_and_observes_both_refusals(self):
        value = self.check()
        self.assertEqual(self.read(value), value)
        self.assertEqual(value["schema"], "rs9.nebular070-universal-missing-runtime.v1")
        self.assertEqual(value["distribution"], "universal-launcher")
        self.assertEqual(value["wheel"], self.snapshot["wheel"])
        self.assertEqual(value["host_observation"]["identity"], self.host[0]["identity"])
        self.assertIs(value["payload_materialized"], False)
        self.assertIs(value["library_environment_modified"], False)
        self.assertIs(value["publication_admitted"], False)
        for process in value["processes"].values():
            self.assertEqual(set(process), missing.consumer.PROCESS_FIELDS)
            self.assertEqual(len(process), 10)
        self.observe.assert_called_once_with("floor")
        self.builder.assert_called_once_with(with_pip=True)
        labels = [call[0] for call in self.calls]
        self.assertEqual(labels, ["webkit_unavailable", "install", "help", "version",
                                  "cold_launch", "explicit_setup", "uninstall"])
        # Explicit setup keeps the original network-denial prefix.
        self.assertEqual({call[3] for call in self.calls}, {PREFIX})
        install = self.calls[1][1]
        for flag in ("--no-index", "--no-deps", "--no-compile", "--only-binary=:all:"):
            self.assertIn(flag, install)
        self.assertEqual(install[-1], str(self.wheel))
        self.assertEqual(self.calls[-1][1][-3:], ["uninstall", "--yes", "theme-forge-nebular-fusion"])
        env = self.calls[0][2]
        self.assertEqual(env["PIP_NO_INDEX"], "1")
        self.assertNotIn("THEME_FORGE_CACHE_DIR", env)
        self.assertFalse(any(key.startswith("LD_") for key in env))
        self.assertFalse((self.work / "home/.cache").exists())
        self.assertFalse((self.work / "venv/bin/tfnf").exists())
        self.assertEqual(value["processes"]["explicit_setup"]["stderr_sha256"],
                         sha(missing.WEBKIT_LINE))
        self.assertIn("sudo apt install libwebkit2gtk-4.1-0", missing.WEBKIT_LINE)

    def test_wrong_host_or_context_refuses_before_effects(self):
        cases = [
            {"env": self.environment(GITHUB_ACTIONS="false")},
            {"env": self.environment(GITHUB_REF="refs/heads/staging")},
            {"env": self.environment(GITHUB_REPOSITORY="unrelated/repository")},
            {"env": self.environment(GITHUB_RUN_ID="18")},
            {"env": self.environment(GITHUB_RUN_ATTEMPT="2"), "run_attempt": "2"},
            {"env": self.environment(GITHUB_SHA="c" * 40)},
            {"machine": "aarch64"}, {"system": "Darwin"}, {"target": "darwin-arm64"},
            {"prefix": ()}, {"prefix": ["network-denial"]}, {"prefix": ("",)},
        ]
        for case in cases:
            with self.subTest(case=sorted(case)):
                self.calls.clear()
                self.assertRefused(self.check, **case)
                self.observe.assert_not_called()
                self.run.assert_not_called()
                self.builder.assert_not_called()
                self.assertFalse(self.work.exists())

    def test_non_floor_or_foreign_host_observation_refuses_before_work(self):
        for observed in (host(role="newer", glibc="2.39"),
                         host(triple="aarch64-unknown-linux-gnu")):
            with self.subTest(target=observed[0]["target"], role=observed[0]["role"]):
                self.assertEqual(self.assertRefused(self.check, host_value=observed),
                                 "NEBULAR_UNIVERSAL_MISSING_HOST")
                self.run.assert_not_called()
                self.assertFalse(self.work.exists())

    def test_wheel_or_snapshot_tamper_refuses_before_effects(self):
        original = json.loads(json.dumps(self.snapshot))
        changes = [
            lambda: self.wheel.write_bytes(self.raw + b"!"),
            lambda: self.snapshot["wheel"].update(sha256="f" * 64),
            lambda: self.snapshot["wheel"].update(size=True),
            lambda: self.snapshot["wheel"].update(tag="py3-none-manylinux_2_36_x86_64"),
            lambda: self.snapshot["wheel"].update(filename="other.whl"),
            lambda: self.snapshot.update(publication_admitted=True),
            lambda: self.snapshot.update(runtime_index_sha256="Z" * 64),
        ]
        for index, change in enumerate(changes):
            with self.subTest(index=index):
                self.snapshot = json.loads(json.dumps(original))
                self.wheel.write_bytes(self.raw)
                change()
                self.assertRefused(self.check)
                self.run.assert_not_called()
                self.assertFalse(self.work.exists())

    def test_symlinked_wheel_or_existing_work_refuses(self):
        self.work.mkdir()
        self.assertEqual(self.assertRefused(self.check), "NEBULAR_UNIVERSAL_MISSING_WORK")
        self.work.rmdir()
        real = self.root / "real"
        real.mkdir()
        os.replace(self.wheel, real / self.wheel.name)
        (self.root / "dist").rmdir()
        (self.root / "dist").symlink_to(real)
        self.assertRefused(self.check)
        self.run.assert_not_called()
        self.assertFalse(self.work.exists())

    def test_runtime_presence_wrong_diagnostic_or_materialization_refuses(self):
        def created_cache(env):
            Path(env["XDG_CACHE_HOME"], "rs9/theme-forge-nebular-fusion").mkdir(parents=True)
            return self.result(1, stderr=missing.MISSING_LINE)

        def home_write(env):
            Path(env["HOME"], "state").write_text("x")
            return self.result(1, stderr=missing.WEBKIT_LINE)

        cases = {
            "webkit_present": ("webkit_unavailable", lambda env: self.result(0)),
            "network_first": ("explicit_setup", lambda env: self.result(1, stderr=(
                "TFNF_RUNTIME_DOWNLOAD: Runtime download failed. "
                "Check the connection and retry tfnf install-runtime.\n"))),
            "setup_succeeds": ("explicit_setup", lambda env: self.result(0, stdout="{}")),
            "webkit_on_cold": ("cold_launch", lambda env: self.result(1, stderr=missing.WEBKIT_LINE)),
            "traceback": ("cold_launch", lambda env: self.result(
                1, stderr=missing.MISSING_LINE + "Traceback (most recent call last):\n")),
            "cache_created": ("cold_launch", created_cache),
            "home_written": ("explicit_setup", home_write),
            "timed_out": ("version", lambda env: {**self.result(
                stdout="theme-forge-nebular-fusion 0.7.0\n"), "timed_out": True}),
            "uninstall_fails": ("uninstall", lambda env: self.result(1)),
            "uninstall_leaves": ("uninstall", lambda env: self.result(0)),
        }
        for name, (label, override) in cases.items():
            with self.subTest(name=name):
                temp = tempfile.TemporaryDirectory()
                self.addCleanup(temp.cleanup)
                self.work = Path(temp.name).resolve() / "work"
                self.calls.clear()
                self.overrides = {label: override}
                self.assertRefused(self.check)
                if name == "webkit_present":
                    self.assertEqual([call[0] for call in self.calls], ["webkit_unavailable"])
                    self.builder.assert_not_called()

    def test_reader_rejects_closed_shape_binding_and_identity_tamper(self):
        value = self.check()
        tampers = {
            "source": lambda v: v["source"].update(commit="c" * 40),
            "run": lambda v: v["run"].update(id="18"),
            "attempt": lambda v: v["run"].update(attempt="2"),
            "wheel_sha": lambda v: v["wheel"].update(sha256="f" * 64),
            "wheel_size_type": lambda v: v["wheel"].update(size=float(v["wheel"]["size"])),
            "distribution": lambda v: v.update(distribution="three-platform-wheel"),
            "schema": lambda v: v.update(schema="rs9.nebular070-system-webkit-missing-runtime.v1"),
            "status": lambda v: v.update(status="failed"),
            "inputs": lambda v: v.update(runtime_inputs_sha256="3" * 64),
            "payload": lambda v: v.update(payload_materialized=True),
            "library": lambda v: v.update(library_environment_modified=0),
            "publication": lambda v: v.update(publication_admitted=None),
            "sandbox": lambda v: v["sandbox"].update(network_disabled=1),
            "extra_key": lambda v: v.update(native_qualified=True),
            "missing_key": lambda v: v.pop("soname"),
            "bool_exit": lambda v: v["processes"]["cold_launch"].update(exit_code=True),
            "exit": lambda v: v["processes"]["explicit_setup"].update(exit_code=0),
            "signal": lambda v: v["processes"]["install"].update(signal=9),
            "process_extra": lambda v: v["processes"]["help"].update(stdout_token="x"),
            "process_missing": lambda v: v["processes"]["help"].pop("duration_ms"),
            "process_label": lambda v: v["processes"].pop("uninstall"),
            "hash_syntax": lambda v: v["processes"]["install"].update(stdout_sha256="A" * 64),
            "diagnostic": lambda v: v["processes"]["explicit_setup"].update(stderr_sha256="e" * 64),
            "host_role": lambda v: v["host_observation"].update(role="newer"),
            "host_extras": lambda v: v["host_extras"].update(evidence_mode="synthetic"),
        }
        for name, tamper in tampers.items():
            with self.subTest(name=name):
                changed = json.loads(json.dumps(value))
                tamper(changed)
                self.assertRefused(self.read, resign(changed))
        self.assertEqual(self.assertRefused(self.read, {**value, "identity": "0" * 64}),
                         "NEBULAR_UNIVERSAL_MISSING_IDENTITY")
        for changes in ({"host_identity": "9" * 64}, {"host_identity": None},
                        {"target": "linux-arm64-gnu"}, {"run_attempt": "2"},
                        {"source": {"commit": "a" * 40}}):
            with self.subTest(changes=sorted(changes)):
                self.assertRefused(self.read, value, **changes)
        other = json.loads(json.dumps(self.snapshot))
        other["wheel"]["sha256"] = "f" * 64
        self.assertRefused(self.read, value, snapshot=other)


if __name__ == "__main__":
    unittest.main()
