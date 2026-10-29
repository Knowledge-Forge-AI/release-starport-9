"""Pure contract tests for the explicit system-WebKit consumer branch."""
from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from rs9.errors import ContractError
from rs9.tf_pypi_archive import AdmissionError
from rs9.nebular070_installed_smoke import (
    SYSTEM_WEBKIT_NATIVE_INPUT_SCHEMA,
    SYSTEM_WEBKIT_PREFLIGHT_SCHEMA,
    SYSTEM_WEBKIT_PROFILE,
    SYSTEM_WEBKIT_PROFILE_ID,
    SYSTEM_WEBKIT_SONAME,
    _summary_system_webkit,
    produce_system_webkit_preflight,
    run_installed_smoke,
    run_system_webkit_preflight,
    validate_system_webkit_native_input,
    validate_system_webkit_preflight,
)
from rs9.tf_pypi_archive import canonical, sha256
from rs9.tf_pypi_consumer import (
    NEBULAR070_SYSTEM_WEBKIT_PROFILE,
    NEBULAR070_SYSTEM_WEBKIT_PROFILE_ID,
    _nebular_static_system_native,
    _nebular_runtime_profile,
)
from tests.nebular070_smoke_fixtures import patched_source_contract
from tests.test_nebular070_smoke_support import _support


class SystemWebKitConsumerTests(unittest.TestCase):
    def test_public_capture_projects_observed_host_and_observes_provider(self) -> None:
        import contextlib
        from rs9 import nebular070_public_consumers as public
        from rs9 import nebular070_system_webkit as runtime
        candidate = {"profile": {"profile_id": SYSTEM_WEBKIT_PROFILE_ID}}
        observed_host = {"identity": "a" * 64, "role": "floor", "schema": "host-body",
                         "target": "x86_64-unknown-linux-gnu", "glibc": "2.36"}
        provider = self._preflight()["provider"]
        with contextlib.ExitStack() as stack:
            for name, value in (
                ("physical_bytes", b"wheel"), ("_system_wheel", {}),
                ("observe_host", (observed_host, {})), ("default_sandbox_prefix", ()),
                ("make_real_user_state_snapshotter", None), ("consumer_body_from_actual", {}),
            ):
                stack.enter_context(patch.object(public, name, return_value=value))
            observe = stack.enter_context(patch.object(runtime, "observe_provider", return_value=provider))
            qualify = stack.enter_context(patch.object(public, "qualify_nebular070", return_value={}))
            args = dict(expected_artifacts={}, expected_commit="b" * 40, expected_tree="c" * 40,
                        profile_sha256="d" * 64, candidate_receipt_sha256="e" * 64,
                        target="linux-x64-gnu", kind="floor", system_webkit_native_input={})
            public.capture_public_consumer(candidate, "unused.whl", {}, "unused", **args)
            self.assertEqual(qualify.call_args.kwargs["system_webkit_host_observation"], {
                "identity": "a" * 64, "role": "floor", "class": "bookworm-floor",
            })
            self.assertEqual(qualify.call_args.kwargs["system_webkit_provider_observation"], provider)
            observe.assert_called_once_with("linux-x64-gnu")
            with self.assertRaises(ContractError):
                public.capture_public_consumer(candidate, "unused.whl", {}, "unused", **args,
                    system_webkit_provider_observation={**provider, "sha256": "f" * 64})
            qualify.assert_called_once()

    def test_live_consumer_requires_source_and_host_before_install_or_materialization(self) -> None:
        from rs9 import tf_pypi_consumer as consumer
        candidate = {"profile": {"profile_id": SYSTEM_WEBKIT_PROFILE_ID}}
        source = {"commit": "a" * 40, "tree": "b" * 40}
        host = {"identity": "c" * 64, "role": "floor", "class": "bookworm-floor"}
        contexts = (
            {}, {"system_webkit_source": source},
            {"system_webkit_host_observation": host},
            {"system_webkit_source": source, "system_webkit_host_observation": {**host, "class": "ubuntu-newer"}},
            {"system_webkit_source": {**source, "commit": "bad"}, "system_webkit_host_observation": host},
            {"system_webkit_source": source, "system_webkit_host_observation": host,
             "system_webkit_host_observation_identity": "d" * 64},
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            wheel = root / "candidate.whl"
            wheel.write_bytes(b"unused")
            for context in contexts:
                with self.subTest(context=context), patch.object(
                    consumer, "_nebular_candidate_row", return_value=({}, {}, {}),
                ), patch.object(consumer, "_nebular_identity_observed") as observe:
                    with self.assertRaisesRegex(AdmissionError, "NEBULAR_SYSTEM_WEBKIT_PREFLIGHT"):
                        consumer.consume_nebular_candidate(
                            candidate, wheel, {}, root, target="linux-x64-gnu", **context,
                        )
                    observe.assert_not_called()

    @staticmethod
    def _native_input(target: str = "linux-x64-gnu") -> dict[str, object]:
        platform_name = "linux-x64" if target == "linux-x64-gnu" else "linux-arm64"
        scenario = "C" if target == "linux-x64-gnu" else "B"
        return {
            "schema": SYSTEM_WEBKIT_NATIVE_INPUT_SCHEMA,
            "target": target,
            "profile_id": SYSTEM_WEBKIT_PROFILE_ID,
            "runtime_profile": SYSTEM_WEBKIT_PROFILE,
            "archive": {
                "payload": {"name": "payload.tar.gz", "size": 123, "sha256": "1" * 64},
                "manifest": {"path": "payload/manifest.json", "size": 456, "sha256": "2" * 64},
            },
            "members": {
                role: {"path": "theme-forge-nebular-fusion/bin/" + {
                    "gui": "theme-forge-nebular-fusion", "launcher": "tfnf", "sidecar": "tfsb-studio-service",
                }[role], "size": 10, "mode": 0o755, "sha256": str(index) * 64}
                for index, role in enumerate(("gui", "launcher", "sidecar"), 3)
            },
            "protocol": {
                "command": "tfnf", "protocol": "nebular.native-rc-smoke",
                "platform": platform_name, "scenario": scenario,
                "argv": [f"--nebular-release-smoke={scenario}"],
                "timeout_seconds": 30, "state_paths": [],
                "user_state_protocol": {
                    "schema": "nebular.native-rc-persistent-user-state-v1",
                    "method": "native-rc-smoke.persistentStateLocations+snapshotLocations",
                    "scope": "real-user-state",
                },
            },
            "preflight_contract": {
                "schema": SYSTEM_WEBKIT_PREFLIGHT_SCHEMA,
                "soname": SYSTEM_WEBKIT_SONAME,
                "launcher": "normal-installed-python", "operation": "ctypes.CDLL",
            },
            "smoke_support": _support(target=target),
        }

    @staticmethod
    def _preflight(target: str = "linux-x64-gnu") -> dict[str, object]:
        machine = "Advanced Micro Devices X86-64" if target == "linux-x64-gnu" else "AArch64"
        wheel_tag = "py3-none-linux_x86_64" if target == "linux-x64-gnu" else "py3-none-linux_aarch64"
        stream = b"NEBULAR_SYSTEM_WEBKIT_READY\n"
        provider = {
            "soname": SYSTEM_WEBKIT_SONAME,
            "classification": "system-webkitgtk-4.1",
            "requestedPath": "/usr/lib/x86_64-linux-gnu/libwebkit2gtk-4.1.so.0",
            "terminalPath": "/usr/lib/x86_64-linux-gnu/libwebkit2gtk-4.1.so.0",
            "aliasChain": [],
            "terminalFull9": ["regular", 0o644, 1, 0, 0, 0, 0, 0, 0],
            "bytes": 123,
            "sha256": "c" * 64,
            "elfMachine": machine,
            "elfClass": "ELF64",
            "versionDefinitions": ["GLIBC_2.36"],
            "readelfEvidenceSha256": "d" * 64,
        }
        unsigned = {
            "schema": SYSTEM_WEBKIT_PREFLIGHT_SCHEMA,
            "profile": SYSTEM_WEBKIT_PROFILE_ID,
            "status": "passed",
            "target": target,
            "host": {"identity": "e" * 64, "role": "floor", "class": "bookworm-floor"},
            "wheel": {"sha256": "1" * 64, "tag": wheel_tag},
            "payload": {"archive_sha256": "2" * 64, "manifest_sha256": "3" * 64},
            "source": {"commit": "a" * 40, "tree": "b" * 40},
            "run": {"id": "17", "attempt": "1"},
            "soname": SYSTEM_WEBKIT_SONAME,
            "provider": provider,
            "loader": {
                "status": "loaded", "soname": SYSTEM_WEBKIT_SONAME,
                "command": "python-ctypes-cdll", "exit_code": 0, "signal": None,
                "stdout": {"bytes": len(stream), "sha256": sha256(stream)},
                "stderr": {"bytes": 0, "sha256": sha256(b"")},
                "cleanup_known": True, "output_complete": True, "forced_cleanup": False,
            },
        }
        from rs9.nebular070_payload import _runtime_provider_row
        unsigned["provider_observation_identity"] = _runtime_provider_row(
            provider, target=target, expected_machines={machine},
            classifications=frozenset({"system-webkitgtk-4.1"}),
        )
        return {**unsigned, "identity": sha256(canonical(unsigned))}

    def test_valid_preflight_binds_all_expected_joins(self) -> None:
        value = self._preflight()
        checked = validate_system_webkit_preflight(
            value,
            target="linux-x64-gnu",
            wheel_sha256="1" * 64,
            wheel_tag="py3-none-linux_x86_64",
            payload_archive_sha256="2" * 64,
            payload_manifest_sha256="3" * 64,
            source={"commit": "a" * 40, "tree": "b" * 40},
            run_id="17",
            run_attempt="1",
            host_observation_identity="e" * 64,
        )
        self.assertEqual(checked["identity"], value["identity"])
        with self.assertRaises(AdmissionError):
            _summary_system_webkit(self._preflight("linux-arm64-gnu"), target="linux-x64-gnu")
        with self.assertRaises(AdmissionError):
            validate_system_webkit_preflight(
                value, target="linux-x64-gnu", host_observation_identity="f" * 64,
            )

    def test_private_provider_path_and_wrong_soname_fail_closed(self) -> None:
        value = self._preflight()
        value["provider"] = dict(value["provider"])
        value["provider"]["requestedPath"] = "/opt/nebular-private/libwebkit2gtk-4.1.so.0"
        unsigned = dict(value)
        unsigned.pop("identity")
        value["identity"] = sha256(canonical(unsigned))
        with self.assertRaises(AdmissionError):
            validate_system_webkit_preflight(value, target="linux-x64-gnu")

    def test_present_and_missing_loader_results_are_distinct(self) -> None:
        value = self._preflight()
        stream = b"NEBULAR_SYSTEM_WEBKIT_READY\n"
        successful = {
            "exit_code": 0, "signal": None, "stdout_sha256": sha256(stream),
            "stderr_sha256": sha256(b""), "stdout_token": "NEBULAR_SYSTEM_WEBKIT_READY\n",
            "stderr_token": "", "timed_out": False, "output_limit_exceeded": False,
            "cleanup_known": True, "output_complete": True, "forced_cleanup": False,
        }
        with tempfile.TemporaryDirectory(prefix="nebular-system-webkit-") as root:
            with patch("rs9.tf_pypi_consumer._nebular_run", return_value=successful):
                result = run_system_webkit_preflight(
                    python_launcher="/usr/bin/python3", env={"PATH": "/usr/bin:/bin"},
                    cwd=Path(root), prefix=(), runner=object(), expected=value,
                )
            self.assertEqual(result["status"], "passed")
            checked = _summary_system_webkit(result, target="linux-x64-gnu")
            self.assertEqual(checked["stdout"]["sha256"], sha256(stream))
            self.assertEqual(checked["stderr"]["sha256"], sha256(b""))
            missing = dict(successful)
            missing.update({"exit_code": 2, "stdout_token": "", "output_complete": True})
            with patch("rs9.tf_pypi_consumer._nebular_run", return_value=missing):
                with self.assertRaises(AdmissionError):
                    run_system_webkit_preflight(
                        python_launcher="/usr/bin/python3", env={"PATH": "/usr/bin:/bin"},
                        cwd=Path(root), prefix=(), runner=object(), expected=value,
                    )

    def test_static_native_input_excludes_observation_results(self) -> None:
        value = self._native_input()
        with patched_source_contract():
            self.assertEqual(validate_system_webkit_native_input(value, target="linux-x64-gnu"), value)
        for forbidden in ("qualification", "smoke", "provider_closure", "loader"):
            bad = dict(value)
            bad[forbidden] = {"status": "pass"}
            with self.subTest(forbidden=forbidden), self.assertRaises(AdmissionError):
                validate_system_webkit_native_input(bad, target="linux-x64-gnu")

    def test_static_native_input_rejects_manylinux_fields(self) -> None:
        bad = self._native_input()
        bad["manylinux_stage_a_sha256"] = "f" * 64
        with patched_source_contract(), self.assertRaises(AdmissionError):
            validate_system_webkit_native_input(bad, target="linux-x64-gnu")

    def test_static_native_input_binds_manifest_and_keeps_observations_out(self) -> None:
        value = self._native_input()
        manifest = {
            "root": "theme-forge-nebular-fusion",
            "members": [
                {**dict(value["members"][role]), "type": "file"}
                for role in ("gui", "launcher", "sidecar")
            ]
        }
        with patched_source_contract():
            native, checked = _nebular_static_system_native(
                value,
                target="linux-x64-gnu",
                manifest=manifest,
                payload_digest="1" * 64,
                manifest_digest="2" * 64,
            )
        self.assertEqual(native["system_static_input"], checked)
        self.assertEqual(native["smoke_support"], checked["smoke_support"])
        self.assertNotIn("qualification", native)
        self.assertNotIn("provider_closure", native)
        swapped = {**value, "members": {**value["members"], "gui": value["members"]["sidecar"]}}
        with patched_source_contract(), self.assertRaises(AdmissionError):
            _nebular_static_system_native(
                swapped, target="linux-x64-gnu", manifest=manifest,
                payload_digest="1" * 64, manifest_digest="2" * 64,
            )
        non_executable = dict(value)
        non_executable["members"] = dict(value["members"])
        non_executable["members"]["gui"] = dict(value["members"]["gui"], mode=0o644)
        with patched_source_contract(), self.assertRaises(AdmissionError):
            validate_system_webkit_native_input(non_executable, target="linux-x64-gnu")

    def test_preflight_is_produced_from_installed_entrypoint_without_expected(self) -> None:
        expected = self._preflight()
        process = {
            "exit_code": 0, "signal": None, "stdout_sha256": sha256(b"tfnf\n"),
            "stderr_sha256": sha256(b""), "stdout_token": "tfnf\n", "stderr_token": "",
            "timed_out": False, "output_limit_exceeded": False,
            "cleanup_known": True, "output_complete": True, "forced_cleanup": False,
        }
        context = {
            "target": "linux-x64-gnu", "wheel_sha256": "1" * 64,
            "wheel_tag": "py3-none-linux_x86_64", "payload_archive_sha256": "2" * 64,
            "payload_manifest_sha256": "3" * 64, "source": {"commit": "a" * 40, "tree": "b" * 40},
            "run_id": "17", "run_attempt": "1", "host": expected["host"],
            "provider": expected["provider"],
        }
        produced = run_system_webkit_preflight(
            python_launcher="/unused", env={}, cwd=Path("."), prefix=(), runner=object(),
            context=context, installed_process=process,
        )
        self.assertEqual(produced["loader"]["command"], "installed-tfnf")
        self.assertEqual(produced["status"], "passed")
        self.assertEqual(produced["identity"], sha256(canonical({k: v for k, v in produced.items() if k != "identity"})))
        self.assertNotIn("expected", produced)
        tampered = dict(process, stdout_sha256="0" * 64)
        with self.assertRaises(AdmissionError):
            run_system_webkit_preflight(
                python_launcher="/unused", env={}, cwd=Path("."), prefix=(), runner=object(),
                context=context, installed_process=tampered,
            )

    def test_installed_harness_routes_through_tfnf_and_refuses_failed_run(self) -> None:
        calls: list[list[str]] = []
        with tempfile.TemporaryDirectory(prefix="nebular-system-entrypoint-") as root_name:
            root = Path(root_name).resolve()
            source = root / "source"
            tools = source / "tools"
            tools.mkdir(parents=True)
            installed = root / "venv" / "bin" / "tfnf"
            installed.parent.mkdir(parents=True)
            installed.write_text("#!/bin/sh\nexit 2\n", encoding="utf-8")
            installed.chmod(0o755)
            runtime = root / "cache" / "entries" / ("3" * 64) / "payload" / "theme-forge-nebular-fusion"
            runtime.mkdir(parents=True)
            harness_source = (
                "  const launchTarget = launcherPath(launchRoot, platform);\n"
                "const result = { source: options.source ?? null, executable: {} };\n"
                'const child = spawn(launchTarget, [`--nebular-release-smoke=${scenario}`], { cwd: home, env, detached: true });\n'
                '      const timeout = options.timeoutMs ?? DEFAULT_TIMEOUT_MS;\n'
                r'(observed) => writeFileSync(join(evidenceDir, `${label}.receipt.json`), `${JSON.stringify(observed.receipt, null, 2)}\n`),'
            ).encode()
            (tools / "native-rc-smoke.mjs").write_bytes(harness_source)
            prepared = {"source": source, "tools": tools, "tool_root": "tools", "manifest_sha256": "3" * 64,
                        "records": [{"path": "tools/native-rc-smoke.mjs",
                                     "sha256": sha256(harness_source)}]}
            native = {"command": "tfnf", "scenario": "C", "timeout_seconds": 20}
            gui = {"smoke_path": "bin/theme-forge-nebular-fusion", "sha256": "1" * 64}
            expected = self._preflight()

            def missing(command, _env, _cwd, _prefix, _timeout, *, runner):
                calls.append([str(item) for item in command])
                return {
                    "exit_code": 2, "signal": None, "stdout_sha256": sha256(b""),
                    "stderr_sha256": sha256(b"missing libwebkit2gtk-4.1.so.0\n"),
                    "stdout_token": "", "stderr_token": "missing libwebkit2gtk-4.1.so.0\n",
                    "timed_out": False, "output_limit_exceeded": False,
                    "cleanup_known": True, "output_complete": True, "forced_cleanup": False,
                }

            with patch("rs9.tf_pypi_consumer._nebular_run", side_effect=missing), patch(
                "rs9.nebular070_installed_smoke.node_binary", return_value="/usr/bin/node",
            ), patch(
                "rs9.nebular070_system_webkit.observe_provider", return_value=expected["provider"],
            ):
                with self.assertRaises(AdmissionError):
                    run_installed_smoke(
                        prepared=prepared, target="linux-x64-gnu", runtime_root=runtime,
                        env={"PATH": "/usr/bin:/bin"}, prefix=(), evidence=root / "evidence",
                        native=native, gui=gui, runner=object(), timeout=20,
                        python_launcher="/usr/bin/python3", installed_command=installed,
                        system_webkit_context={
                            "target": "linux-x64-gnu", "wheel_sha256": "1" * 64,
                            "wheel_tag": "py3-none-linux_x86_64", "payload_archive_sha256": "2" * 64,
                            "payload_manifest_sha256": "3" * 64,
                            "source": {"commit": "a" * 40, "tree": "b" * 40},
                            "run_id": "17", "run_attempt": "1", "host": expected["host"],
                            "provider": expected["provider"],
                        },
                    )
            self.assertEqual(len(calls), 1)
            self.assertIn("native-rc-smoke-installed.mjs", " ".join(calls[0]))
            adapted = (tools / "native-rc-smoke-installed.mjs").read_text()
            self.assertIn("spawn(" + __import__("json").dumps(str(installed)), adapted)
            self.assertIn("installedEntrypoint:", adapted)
            self.assertIn("launcherPath(launchRoot, platform)", adapted)

    def test_profile_dispatch_is_explicit(self) -> None:
        self.assertEqual(
            _nebular_runtime_profile({"profile": {"profile_id": NEBULAR070_SYSTEM_WEBKIT_PROFILE_ID}}),
            NEBULAR070_SYSTEM_WEBKIT_PROFILE,
        )
        with self.assertRaises(AdmissionError):
            _nebular_runtime_profile({"profile": {"profile_id": "unknown"}})


if __name__ == "__main__":
    unittest.main()
