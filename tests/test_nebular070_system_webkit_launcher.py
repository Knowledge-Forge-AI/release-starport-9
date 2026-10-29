"""Focused contract tests for the opt-in system-WebKit wheel profile."""
from __future__ import annotations

import contextlib
import hashlib
import importlib.util
import io
import json
import sys
import subprocess
import tempfile
import types
import unittest
from dataclasses import replace
from pathlib import Path
from unittest import mock

from rs9.errors import ContractError
from rs9.wheel_nebular_successor import (
    GATE1_PROFILE,
    SYSTEM_WEBKIT_PROFILE,
    SYSTEM_WEBKIT_SONAME,
    canonical_candidate_profile,
    _is_system_webkit_profile,
    _render_successor_launcher,
    _run_system_webkit_probe,
    _validate_system_webkit_archive,
    gate1_profile_record,
)
from rs9.tf_pypi_nebular_successor import (
    build_gate1_candidates,
    validate_gate1_receipt,
    write_gate1_receipt,
)
from tests.test_nebular070_gate1_roundtrip import Nebular070Gate1RoundtripTests


class RetainedLauncherByteTests(unittest.TestCase):
    def test_non_system_rendering_matches_frozen_c3_bytes(self):
        # Golden digests from ee85cba's renderer, with these exact arguments.
        expected = {
            ("linux", "x86_64", "0.6.1", "0.6.1.post1"): "2509ca7ae6c9abddd47ffc91eb5641b1cb5f0cadc0459b79a62a940ce25af92a",
            ("linux", "x86_64", "0.7.0", "0.7.0"): "415de25fb3437781fdd675a6c1f81ff2fdc0d3fc920a8718b36f2407b1240a78",
            ("linux", "aarch64", "0.6.1", "0.6.1.post1"): "c9178e5af3ff27591d1512b2529f8656bcf4105e8b657c7129aec4c6fdde0f0b",
            ("linux", "aarch64", "0.7.0", "0.7.0"): "bd726f9aa88586f66231e9699e8bf78580f430fa792a55a37f5bfffbbecaba00",
            ("darwin", "aarch64", "0.6.1", "0.6.1.post1"): "2ebe69258d37fb31c50af3d9f71a406dc0fb9ba0847988d68dcbac21dc4a11fb",
            ("darwin", "aarch64", "0.7.0", "0.7.0"): "b501671633f7cc57b4c1ccc19650dbca88990ebc7ef2c7e7e03a3c10f3416c49",
        }
        for (family, arch, app, dist), digest in expected.items():
            with self.subTest(family=family, arch=arch, app=app):
                body = _render_successor_launcher(
                    "payload.tar.gz", "a" * 64, "b" * 64,
                    "payload/bin/tfnf", "payload/bin/gui", family, arch,
                    application_version=app, distribution_version=dist,
                )
                self.assertEqual(hashlib.sha256(body).hexdigest(), digest)


def _load_generated_launcher(*, system_webkit: bool = True, family: str = "linux"):
    """Load the emitted launcher with only its materializer boundary stubbed."""
    temp = tempfile.TemporaryDirectory(prefix="rs9-system-webkit-launcher-")
    package_dir = Path(temp.name)
    isolated_package = package_dir / "_isolated" / "rs9"
    isolated_package.mkdir(parents=True)
    (isolated_package / "__init__.py").write_bytes(b"")
    payload_dir = package_dir / "payload"
    payload_dir.mkdir()
    payload_name = "payload.tar.gz"
    payload_bytes = b"fixture-payload"
    (payload_dir / payload_name).write_bytes(payload_bytes)
    manifest = {"members": []}
    (payload_dir / "manifest.json").write_bytes(json.dumps(manifest).encode())
    if family == "darwin":
        shell_target = "Theme Forge Nebular Fusion.app/Contents/Resources/bin/tfnf"
        gui_target = "Theme Forge Nebular Fusion.app/Contents/MacOS/theme-forge-nebular-fusion"
        materialized_name = "Theme Forge Nebular Fusion.app"
    else:
        shell_target = "theme-forge-nebular-fusion/bin/tfnf"
        gui_target = "theme-forge-nebular-fusion/bin/theme-forge-nebular-fusion"
        materialized_name = "theme-forge-nebular-fusion"
    source = _render_successor_launcher(
        payload_name,
        hashlib.sha256(payload_bytes).hexdigest(),
        hashlib.sha256(json.dumps(manifest).encode()).hexdigest(),
        shell_target,
        gui_target,
        family,
        "x86_64" if family == "linux" else "aarch64",
        application_version="0.7.0",
        distribution_version="0.7.0",
        system_webkit=system_webkit,
    )
    module_path = package_dir / "launcher.py"
    module_path.write_bytes(source)
    fake_package = types.ModuleType("rs9")
    fake_package.__file__ = str(isolated_package / "__init__.py")
    fake_materialize = types.ModuleType("rs9.materialize")
    def materialize_payload(*args: object, **kwargs: object) -> Path:
        return Path(materialized_name)

    fake_materialize.materialize_payload = materialize_payload
    fake_materialize.resolve_launcher = lambda root, relative: Path(root) / relative
    module_name = f"_generated_nebular_launcher_{id(temp)}"
    spec = importlib.util.spec_from_file_location(module_name, module_path)
    if spec is None or spec.loader is None:
        temp.cleanup()
        raise AssertionError("generated launcher spec unavailable")
    module = importlib.util.module_from_spec(spec)
    with mock.patch.dict(
        sys.modules,
        {"rs9": fake_package, "rs9.materialize": fake_materialize},
    ):
        spec.loader.exec_module(module)
    # Keep patches local to this generated module rather than changing the
    # process-wide os.execv and subprocess.run used by other tests.
    module.os = types.SimpleNamespace(**vars(module.os))
    if hasattr(module, "subprocess"):
        module.subprocess = types.SimpleNamespace(**vars(module.subprocess))
    return temp, module


class SystemWebKitLauncherTests(unittest.TestCase):
    def test_profile_has_explicit_host_managed_policy(self) -> None:
        self.assertTrue(_is_system_webkit_profile(SYSTEM_WEBKIT_PROFILE))
        record = gate1_profile_record(SYSTEM_WEBKIT_PROFILE)
        self.assertEqual(record["profile_id"], "nebular-fusion-0.7.0-system-webkitgtk-4.1-v1")
        self.assertEqual(record["description_path"],
                         "operators/tf-pypi/descriptions/nebular-fusion-0.7.0-system-webkitgtk.md")
        self.assertEqual(
            record["linux_runtime_policy"],
            {
                "wheel_tag_policy": "generic-linux",
                "glibc_floor": "2.36",
                "glibcxx_floor": "3.4.30",
                "provider_baseline": "system-webkitgtk-4.1",
                "manylinux_claim": False,
                "dynamic_closure": "host-managed",
                "required_sonames": [SYSTEM_WEBKIT_SONAME],
            },
        )

    def test_profile_rejects_private_and_manylinux_payload_metadata(self) -> None:
        valid = {"members": [{"path": "theme-forge-nebular-fusion/bin/tfnf"}]}
        _validate_system_webkit_archive(
            valid,
            payload_name="theme-forge-nebular-fusion-v0.7.0-x86_64-unknown-linux-gnu.tar.gz",
            system="x86_64-linux",
            profile=SYSTEM_WEBKIT_PROFILE,
        )
        with self.assertRaises(ContractError):
            _validate_system_webkit_archive(
                {"members": [{"path": "theme-forge-nebular-fusion/opt/nebular-private/lib.so"}]},
                payload_name="theme-forge-nebular-fusion-v0.7.0-x86_64-unknown-linux-gnu.tar.gz",
                system="x86_64-linux",
                profile=SYSTEM_WEBKIT_PROFILE,
            )
        with self.assertRaises(ContractError):
            _validate_system_webkit_archive(
                {"manylinux": {"claim": False}, "members": []},
                payload_name="theme-forge-nebular-fusion-v0.7.0-x86_64-unknown-linux-gnu.tar.gz",
                system="x86_64-linux",
                profile=SYSTEM_WEBKIT_PROFILE,
            )
        with self.assertRaises(ContractError):
            _validate_system_webkit_archive(
                {"musllinux": {"claim": False}, "members": []},
                payload_name="theme-forge-nebular-fusion-v0.7.0-x86_64-unknown-linux-gnu.tar.gz",
                system="x86_64-linux",
                profile=SYSTEM_WEBKIT_PROFILE,
            )

    def test_profile_registry_rejects_unknown_and_mutated_profiles(self) -> None:
        self.assertIs(canonical_candidate_profile(GATE1_PROFILE), GATE1_PROFILE)
        self.assertIs(canonical_candidate_profile(SYSTEM_WEBKIT_PROFILE), SYSTEM_WEBKIT_PROFILE)
        mutated = replace(SYSTEM_WEBKIT_PROFILE, provider_baseline="other-webkit")
        unknown = replace(SYSTEM_WEBKIT_PROFILE, profile_id="unknown-profile")
        for profile in (mutated, unknown):
            with self.subTest(profile=profile.profile_id), self.assertRaises(ContractError):
                canonical_candidate_profile(profile)
            with self.subTest(profile=f"archive-{profile.profile_id}"), self.assertRaises(ContractError):
                _validate_system_webkit_archive(
                    {"members": []},
                    payload_name="theme-forge-nebular-fusion-v0.7.0-x86_64-unknown-linux-gnu.tar.gz",
                    system="x86_64-linux",
                    profile=profile,
                )

    def test_probe_accepts_present_loader_and_uses_fixed_bounded_child(self) -> None:
        calls: list[tuple[list[str], dict[str, object]]] = []

        def runner(command: list[str], **kwargs: object) -> subprocess.CompletedProcess[bytes]:
            calls.append((command, kwargs))
            return subprocess.CompletedProcess(command, 0)

        _run_system_webkit_probe(runner)
        self.assertEqual(len(calls), 1)
        command, kwargs = calls[0]
        self.assertEqual(command[1:], ["-I", "-c", f"import ctypes; ctypes.CDLL({SYSTEM_WEBKIT_SONAME!r})"])
        self.assertIs(kwargs["stdin"], subprocess.DEVNULL)
        self.assertIs(kwargs["stdout"], subprocess.DEVNULL)
        self.assertIs(kwargs["stderr"], subprocess.DEVNULL)
        self.assertEqual(kwargs["timeout"], 5.0)
        self.assertFalse(kwargs["check"])

    def test_probe_reports_missing_loader_crash_and_loader_failure(self) -> None:
        for returncode in (1, -11, 134):
            with self.subTest(returncode=returncode):
                with self.assertRaisesRegex(RuntimeError, "WebKitGTK 4.1"):
                    _run_system_webkit_probe(
                        lambda command, **kwargs: subprocess.CompletedProcess(command, returncode)
                    )

    def test_probe_contains_timeout_as_actionable_refusal(self) -> None:
        def timeout(command: list[str], **kwargs: object) -> None:
            raise subprocess.TimeoutExpired(command, kwargs["timeout"])

        with self.assertRaisesRegex(RuntimeError, "WebKitGTK 4.1"):
            _run_system_webkit_probe(timeout)

    def test_launcher_probes_only_system_linux_after_diagnostics(self) -> None:
        system_source = _render_successor_launcher(
            "payload.tar.gz", "a" * 64, "b" * 64,
            "theme-forge-nebular-fusion/bin/tfnf",
            "theme-forge-nebular-fusion/bin/theme-forge-nebular-fusion",
            "linux", "x86_64", application_version="0.7.0",
            distribution_version="0.7.0", system_webkit=True,
        ).decode()
        compile(system_source, "<system-webkit-launcher>", "exec")
        self.assertIn(SYSTEM_WEBKIT_SONAME, system_source)
        self.assertIn("timeout=5.0", system_source)
        run_source = system_source[system_source.index("def run_launcher"):]
        self.assertLess(
            run_source.index("_run_system_webkit_preflight()"),
            run_source.index("payload ="),
        )

        darwin_source = _render_successor_launcher(
            "payload.tar.gz", "a" * 64, "b" * 64,
            "Theme Forge Nebular Fusion.app/Contents/Resources/bin/tfnf",
            "Theme Forge Nebular Fusion.app/Contents/MacOS/theme-forge-nebular-fusion",
            "darwin", "aarch64", application_version="0.7.0",
            distribution_version="0.7.0",
        ).decode()
        compile(darwin_source, "<darwin-launcher>", "exec")
        portable_source = _render_successor_launcher(
            "payload.tar.gz", "a" * 64, "b" * 64,
            "theme-forge-nebular-fusion/bin/tfnf",
            "theme-forge-nebular-fusion/bin/theme-forge-nebular-fusion",
            "linux", "x86_64",
        ).decode()
        compile(portable_source, "<portable-launcher>", "exec")
        self.assertNotIn(SYSTEM_WEBKIT_SONAME, darwin_source)
        self.assertNotIn(SYSTEM_WEBKIT_SONAME, portable_source)

    def test_generated_launcher_present_failure_modes_and_diagnostics(self) -> None:
        scenarios = (
            (0, None),
            (1, "WebKitGTK 4.1"),
            (-11, "WebKitGTK 4.1"),
            (134, "WebKitGTK 4.1"),
        )
        for returncode, message in scenarios:
            with self.subTest(returncode=returncode):
                temp, module = _load_generated_launcher()
                self.addCleanup(temp.cleanup)
                original_run = module.subprocess.run
                self.addCleanup(setattr, module.subprocess, "run", original_run)
                events: list[str] = []
                module._platform_check = lambda: events.append("platform")
                module.materialize_payload = lambda *args, **kwargs: (
                    events.append("materialize") or Path("theme-forge-nebular-fusion")
                )
                module.resolve_launcher = lambda *args, **kwargs: Path("/tmp/fake-launcher")
                module.os.execv = lambda *args: events.append("exec")
                probe_calls = []
                def probe(command, **kwargs):
                    probe_calls.append((command, kwargs))
                    events.append("probe")
                    return subprocess.CompletedProcess(command, returncode)
                module.subprocess.run = probe
                if message is None:
                    self.assertEqual(module.run_launcher("tfnf", []), 0)
                    self.assertEqual(events, ["platform", "probe", "materialize", "exec"])
                else:
                    with self.assertRaisesRegex(RuntimeError, message):
                        module.run_launcher("tfnf", [])
                    self.assertEqual(events, ["platform", "probe"])
                self.assertEqual(probe_calls, [(
                    [sys.executable, "-I", "-c",
                     "import ctypes; ctypes.CDLL('libwebkit2gtk-4.1.so.0')"],
                    {"stdin": subprocess.DEVNULL, "stdout": subprocess.DEVNULL,
                     "stderr": subprocess.DEVNULL, "check": False, "timeout": 5.0},
                )])
                if returncode:
                    with self.assertRaisesRegex(RuntimeError, "sudo apt install libwebkit2gtk-4.1-0"):
                        module.run_launcher("tfnf", [])

        temp, module = _load_generated_launcher()
        self.addCleanup(temp.cleanup)
        module._platform_check = lambda: None
        module._run_system_webkit_preflight = lambda: (_ for _ in ()).throw(
            AssertionError("diagnostic probed")
        )
        for argv, expected in ((["--help"], "Usage: tfnf"), (["--version"], "0.7.0")):
            with self.subTest(argv=argv), contextlib.redirect_stdout(io.StringIO()) as stdout:
                self.assertEqual(module.run_launcher("tfnf", argv), 0)
            self.assertIn(expected, stdout.getvalue())

        events: list[str] = []
        module.materialize_payload = lambda *args, **kwargs: (
            events.append("materialize") or Path("theme-forge-nebular-fusion")
        )
        module.resolve_launcher = lambda *args, **kwargs: Path("/tmp/fake-gui")
        module.os.execv = lambda *args: events.append("exec")
        with contextlib.redirect_stdout(io.StringIO()) as stdout:
            self.assertEqual(module.run_launcher("tfnf", ["--path"]), 0)
        self.assertEqual(stdout.getvalue(), "/tmp/fake-gui\n")
        self.assertEqual(events, ["materialize"])

        darwin_temp, darwin = _load_generated_launcher(system_webkit=False, family="darwin")
        self.addCleanup(darwin_temp.cleanup)
        darwin._platform_check = lambda: None
        darwin.materialize_payload = lambda *args, **kwargs: Path("Theme Forge Nebular Fusion.app")
        darwin.resolve_launcher = lambda *args, **kwargs: Path("/tmp/fake-launcher")
        darwin.os.execv = mock.Mock()
        self.assertEqual(darwin.run_launcher("tfnf", []), 0)
        darwin.os.execv.assert_called_once()

    def test_generated_launcher_timeout_and_console_error_are_bounded(self) -> None:
        temp, module = _load_generated_launcher()
        self.addCleanup(temp.cleanup)
        original_run = module.subprocess.run
        self.addCleanup(setattr, module.subprocess, "run", original_run)
        module._platform_check = lambda: None

        def timeout(*args: object, **kwargs: object) -> None:
            raise subprocess.TimeoutExpired(args[0], kwargs["timeout"])

        module.subprocess.run = timeout
        with self.assertRaisesRegex(RuntimeError, "WebKitGTK 4.1"):
            module.run_launcher("tfnf", [])
        stderr = io.StringIO()
        with mock.patch.object(module.sys, "argv", ["launcher.py"]):
            with contextlib.redirect_stderr(stderr), self.assertRaises(SystemExit) as ctx:
                module.main_tfnf()
        self.assertEqual(ctx.exception.code, 1)
        self.assertIn("WebKitGTK 4.1", stderr.getvalue())
        self.assertNotIn("Traceback", stderr.getvalue())

    def test_system_profile_builds_and_validates_three_generic_candidates(self) -> None:
        fixture = Nebular070Gate1RoundtripTests("test_fixture_capture_build_validate_write_roundtrip_three_targets")
        fixture.setUp()
        self.addCleanup(fixture.tearDown)
        from rs9.tf_pypi_nebular_successor import authenticate_gate1_capture

        authenticated = authenticate_gate1_capture(
            fixture.repository,
            fixture.evidence,
            release_binding=fixture.binding,
            approved_bootstrap_sha256=fixture.binding["expected"]["bootstrap_sha256"],
        )
        output = Path(fixture.root) / "system-webkit-candidates"
        receipt = build_gate1_candidates(
            authenticated,
            output,
            rs9_source_commit="c" * 40,
            rs9_source_tree="d" * 40,
            candidate_profile=SYSTEM_WEBKIT_PROFILE,
            deterministic_timestamp=(2026, 10, 1, 0, 0, 0),
        )
        self.assertEqual(
            [row["wheel"]["tag"] for row in receipt["rows"]],
            ["py3-none-macosx_13_0_arm64", "py3-none-linux_aarch64", "py3-none-linux_x86_64"],
        )
        self.assertEqual(receipt["profile"]["profile_id"], SYSTEM_WEBKIT_PROFILE.profile_id)
        self.assertEqual(
            receipt["linux_runtime_policy"]["provider_baseline"], "system-webkitgtk-4.1"
        )
        self.assertFalse(any("manylinux" in key for row in receipt["rows"] for key in row))
        self.assertEqual(
            validate_gate1_receipt(
                receipt,
                authenticated,
                output_dir=output,
                candidate_profile=SYSTEM_WEBKIT_PROFILE,
            ),
            receipt,
        )
        receipt_path = Path(fixture.root) / "system-webkit-receipt.json"
        write_gate1_receipt(
            receipt_path,
            receipt,
            authenticated=authenticated,
            output_dir=output,
            candidate_profile=SYSTEM_WEBKIT_PROFILE,
        )
        self.assertEqual(json.loads(receipt_path.read_bytes()), receipt)
        mutated = replace(SYSTEM_WEBKIT_PROFILE, required_sonames=("libother.so.0",))
        with self.assertRaises(ContractError):
            build_gate1_candidates(
                authenticated,
                Path(fixture.root) / "mutated-profile-candidates",
                rs9_source_commit="c" * 40,
                rs9_source_tree="d" * 40,
                candidate_profile=mutated,
            )
        with self.assertRaises(ContractError):
            validate_gate1_receipt(
                receipt,
                authenticated,
                output_dir=output,
                candidate_profile=mutated,
            )


if __name__ == "__main__":
    unittest.main()
