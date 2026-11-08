import io
import json
import plistlib
import struct
import sys
import tarfile
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


REPOSITORY = Path(__file__).resolve().parents[1]
PACKET = REPOSITORY
FIXTURE_SOURCE = REPOSITORY / "tests/fixtures/native-rc-smoke-v0.8.0.mjs"
sys.path.insert(0, str(REPOSITORY / "src"))

from rs9 import nebular080_darwin_harness as harness_owner
from rs9 import nebular080_universal_consumer as consumer_owner
from rs9.errors import ContractError
from rs9 import nebular080_consumer_core as consumer_core
from rs9 import nebular080_installed_smoke as installed_smoke
from rs9.nebular080_consumer_core import _nebular_authenticated_darwin_payload_floor
from rs9.nebular080_darwin_harness import (
    _PGREP_SNAPSHOT,
    _PS_SNAPSHOT,
    _derive_darwin_pgrep_source,
    prepare_darwin_installed_harness,
)
from rs9.nebular080_installed_smoke import run_installed_smoke
from rs9.current_os080 import CURRENT080_VERIFIER_FILES
from rs9.nebular080_system_webkit import prepare_installed_harness
from rs9.tf_pypi_archive import AdmissionError, sha256
from rs9.wheel_native import validate_darwin_payload_floor


def _macho(minor: int) -> bytes:
    header = struct.pack("<4siiIIIII", b"\xcf\xfa\xed\xfe", 0, 0, 2, 1, 24, 0, 0)
    minimum = (13 << 16) | (minor << 8)
    command = struct.pack("<IIIIII", 0x32, 24, 1, minimum, 0, 0)
    return header + command


def _payload(*, minor: int = 3, plist_minor: int = 3) -> bytes:
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w:gz") as archive:
        files = {
            "Theme Forge Nebular Fusion.app/Contents/Info.plist": plistlib.dumps(
                {"LSMinimumSystemVersion": f"13.{plist_minor}"}, fmt=plistlib.FMT_BINARY,
            ),
            "Theme Forge Nebular Fusion.app/Contents/MacOS/theme-forge-nebular-fusion": _macho(minor),
            "Theme Forge Nebular Fusion.app/Contents/Frameworks/libnative.dylib": _macho(minor),
            "Theme Forge Nebular Fusion.app/Contents/Resources/launch.sh": b"#!/bin/sh\nexit 0\n",
        }
        for name, body in files.items():
            info = tarfile.TarInfo(name)
            info.size = len(body)
            info.mode = 0o755 if name.endswith(("theme-forge-nebular-fusion", "launch.sh")) else 0o644
            archive.addfile(info, io.BytesIO(body))
    return output.getvalue()


def _smoke_script() -> bytes:
    return (
        "  const launchTarget = launcherPath(launchRoot, platform);\n"
        "source: options.source ?? null, executable:\n"
        "const child = spawn(launchTarget, [`--nebular-release-smoke=${scenario}`]\n"
        "{ cwd: home, env, detached: true\n"
        "      const timeout = options.timeoutMs ?? DEFAULT_TIMEOUT_MS;\n"
        r"(observed) => writeFileSync(join(evidenceDir, `${label}.receipt.json`), `${JSON.stringify(observed.receipt, null, 2)}\n`),"
        "\n" + _PS_SNAPSHOT + "\n"
    ).encode("utf-8")


def _tempdir():
    # RS9 rejects symlinked ancestors; keep fixtures below this packet rather
    # than the host's /var/folders temporary alias.
    return tempfile.TemporaryDirectory(dir=Path(__file__).parents[1])


class DarwinPayloadFloorTests(unittest.TestCase):
    def test_existing_scanner_checks_every_native_member_and_declared_floor(self):
        evidence = validate_darwin_payload_floor(_payload(), required_floor=(13, 3))
        self.assertEqual(evidence["required_floor"], {"major": 13, "minor": 3})
        self.assertEqual(evidence["info_plist"], {"major": 13, "minor": 3})
        self.assertEqual(
            {row["path"] for row in evidence["macho"]},
            {
                "Theme Forge Nebular Fusion.app/Contents/MacOS/theme-forge-nebular-fusion",
                "Theme Forge Nebular Fusion.app/Contents/Frameworks/libnative.dylib",
            },
        )
        self.assertEqual(evidence["scripts"][0]["role"], "script")

    def test_existing_scanner_rejects_native_member_above_declared_floor(self):
        with self.assertRaises(ContractError):
            validate_darwin_payload_floor(_payload(minor=4), required_floor=(13, 3))

    def test_authenticated_handoff_path_and_digest_are_required(self):
        payload = _payload()
        with _tempdir() as directory:
            root = Path(directory)
            payload_dir = root / "payloads"
            payload_dir.mkdir()
            archive = payload_dir / "qualified.tar.gz"
            archive.write_bytes(payload)
            checked = _nebular_authenticated_darwin_payload_floor({
                "root": root,
                "payload_sha256": sha256(payload),
            })
            self.assertEqual(checked["required_floor"], {"major": 13, "minor": 3})
            (payload_dir / "extra.tar.gz").write_bytes(payload)
            with self.assertRaisesRegex(AdmissionError, "NEBULAR_FLOOR_BINDING"):
                _nebular_authenticated_darwin_payload_floor({
                    "root": root,
                    "payload_sha256": sha256(payload),
                })
            (payload_dir / "extra.tar.gz").unlink()
            archive.write_bytes(payload + b"tamper")
            with self.assertRaisesRegex(AdmissionError, "NEBULAR_FLOOR_BINDING"):
                _nebular_authenticated_darwin_payload_floor({
                    "root": root,
                    "payload_sha256": sha256(payload),
                })

    def test_core_rejects_payload_that_only_claims_a_higher_floor(self):
        payload = _payload(minor=4, plist_minor=4)
        with self.assertRaisesRegex(AdmissionError, "NEBULAR_FLOOR_BINDING"):
            _nebular_authenticated_darwin_payload_floor({
                "payload_bytes": payload,
                "payload_sha256": sha256(payload),
            })

    def test_darwin_pgrep_transform_is_single_use_and_fail_closed(self):
        raw = b"prefix\n" + _PS_SNAPSHOT.encode("utf-8") + b"\nsuffix\n"
        derived = _derive_darwin_pgrep_source(raw)
        self.assertIn(_PGREP_SNAPSHOT.encode("utf-8"), derived)
        self.assertNotIn(_PS_SNAPSHOT.encode("utf-8"), derived)
        with self.assertRaisesRegex(AdmissionError, "NEBULAR_DARWIN_HARNESS_SOURCE"):
            _derive_darwin_pgrep_source(raw + raw)


class ExistingInstalledAdapterTests(unittest.TestCase):
    def test_existing_installed_adapter_binds_command_and_cache_without_execution(self):
        with _tempdir() as directory:
            root = Path(directory)
            tools = root / "tools"
            tools.mkdir()
            source = _smoke_script()
            script = tools / "native-rc-smoke.mjs"
            script.write_bytes(source)
            command = root / "tfnf"
            command.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
            command.chmod(0o700)
            derived, adapter = prepare_installed_harness(
                {"tools": tools, "records": [{"path": "tools/native-rc-smoke.mjs", "sha256": sha256(source)}]},
                command,
                cache_root=root / "cache",
            )
            body = derived.read_text(encoding="utf-8")
            self.assertIn(json.dumps(str(command)), body)
            self.assertIn(json.dumps(str(root / "cache")), body)
            self.assertIn("installedEntrypoint", body)
            self.assertEqual(adapter["transform"], "authenticated-native-harness-installed-entrypoint-v1")
            self.assertGreater(adapter["entrypoint_bytes"], 0)


def _receipt_boundary_fixture(*, floor=None):
    """Build a receipt from the real 080 producer path, never fake identities."""
    payload = _payload()
    expected_floor = _nebular_authenticated_darwin_payload_floor({
        "payload_bytes": payload,
        "payload_sha256": sha256(payload),
    })
    source = FIXTURE_SOURCE.read_bytes()
    source_record = CURRENT080_VERIFIER_FILES["tools/native-rc-smoke.mjs"]
    if (len(CURRENT080_VERIFIER_FILES) != 15
            or source_record["size"] != len(source)
            or source_record["sha256"] != sha256(source)):
        raise AssertionError("authenticated 080 smoke fixture does not match its 15-member record")
    directory = _tempdir()
    try:
        root = Path(directory.name)
        tools = root / "tools"
        tools.mkdir()
        script = tools / "native-rc-smoke.mjs"
        script.write_bytes(source)
        command = root / "tfnf"
        command.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        command.chmod(0o700)
        prepared = {
            "tools": tools,
            "tool_root": "tools",
            "records": [dict(source_record, path="tools/native-rc-smoke.mjs")],
        }
        output, process_harness, adapter = prepare_darwin_installed_harness(
            prepared, command, cache_root=root / "cache",
        )
        application = {
            "native_probe": {
                "installed_entrypoint": {
                    "command": "installed-tfnf",
                    "scenarios": ["A"],
                    "argv": ["--nebular-release-smoke=A"],
                    "status": "passed",
                },
                "darwin_floor_evidence": expected_floor if floor is None else floor,
            },
            "installed_launcher_harness": adapter,
        }
        capture = {
            "payload_bytes": payload,
            "payload_sha256": sha256(payload),
            "native": {
                "smoke_support": {
                    "tool_root": "tools",
                    "files": [{"path": "tools/native-rc-smoke.mjs", "sha256": sha256(source)}],
                },
            },
        }
        # Copy the opaque receipt values before the owner tree is cleaned up.
        return application, capture, expected_floor, directory, {
            "prepared": prepared,
            "root": root,
            "tools": tools,
            "script": script,
            "command": command,
            "output": output,
            "process_harness": process_harness,
            "adapter": adapter,
        }
    except Exception:
        directory.cleanup()
        raise


def _installed_smoke_fixture():
    """Create only the owned tree needed to reach run_installed_smoke's gate."""
    source = FIXTURE_SOURCE.read_bytes()
    source_record = CURRENT080_VERIFIER_FILES["tools/native-rc-smoke.mjs"]
    directory = _tempdir()
    try:
        root = Path(directory.name)
        source_root = root / "source"
        tools = root / "tools"
        source_root.mkdir()
        tools.mkdir()
        (tools / "native-rc-smoke.mjs").write_bytes(source)
        command = root / "tfnf"
        command.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        command.chmod(0o700)
        runtime_root = root / "runtime" / "a" / "b" / "c"
        runtime_root.mkdir(parents=True)
        prepared = {
            "source": source_root,
            "tools": tools,
            "tool_root": "tools",
            "records": [dict(source_record, path="tools/native-rc-smoke.mjs")],
        }
        return directory, {
            "prepared": prepared,
            "root": root,
            "runtime_root": runtime_root,
            "command": command,
            "evidence": root / "evidence",
            "env": {"PATH": "/usr/bin:/bin", "HOME": str(root / "home")},
            "native": {"command": "tfnf", "scenario": "A"},
            "gui": {"smoke_path": "fixture.png", "sha256": "0" * 64},
        }
    except Exception:
        directory.cleanup()
        raise


class DarwinReceiptBoundaryTests(unittest.TestCase):
    def test_receipt_boundary_requires_harness_and_archive_bound_floor(self):
        application, capture, _, directory, _ = _receipt_boundary_fixture()
        self.addCleanup(directory.cleanup)
        adapter = application["installed_launcher_harness"]
        original = capture["native"]["smoke_support"]["files"][0]["sha256"]
        self.assertEqual(adapter["process_source_sha256"], original)
        self.assertNotEqual(adapter["source_sha256"], original)
        consumer_owner._require_darwin_receipt_boundary(application, capture)

    def test_071_pins_are_rejected_by_the_080_validator(self):
        with self.assertRaisesRegex(AdmissionError, "TF_PYPI_NEBULAR_DARWIN_HARNESS"):
            harness_owner.validate_darwin_harness({
                "schema": "rs9.nebular080-darwin-process-harness.v1",
                "source_sha256": "874355e36496884e55a6e4dae6986ecde817d20863bb3fe26d1b1b5a1d283e69",
                "derived_sha256": "d5c042b44be74319084d2f635e1ed97633c367e7fd1777a3c94ad99900fc9320",
                "transform": "authenticated-darwin-pgrep-snapshot-v1",
                "process_tool": "/usr/bin/pgrep",
            })

    def test_receipt_boundary_rejects_missing_or_tampered_harness(self):
        application, capture, _, directory, _ = _receipt_boundary_fixture()
        self.addCleanup(directory.cleanup)
        application.pop("installed_launcher_harness")
        with self.assertRaisesRegex(ContractError, "NEBULAR_UNIVERSAL_DARWIN_HARNESS"):
            consumer_owner._require_darwin_receipt_boundary(application, capture)

        application, capture, _, directory, _ = _receipt_boundary_fixture()
        self.addCleanup(directory.cleanup)
        application["installed_launcher_harness"]["process_source_sha256"] = "e" * 64
        with self.assertRaisesRegex(AdmissionError, "TF_PYPI_NEBULAR_DARWIN_HARNESS"):
            consumer_owner._require_darwin_receipt_boundary(application, capture)

    def test_receipt_boundary_rejects_missing_tampered_or_nonexact_floor(self):
        application, capture, expected_floor, directory, _ = _receipt_boundary_fixture()
        self.addCleanup(directory.cleanup)
        application["native_probe"].pop("darwin_floor_evidence")
        with self.assertRaisesRegex(ContractError, "NEBULAR_UNIVERSAL_DARWIN_FLOOR_BINDING"):
            consumer_owner._require_darwin_receipt_boundary(application, capture)

        application, capture, expected_floor, directory, _ = _receipt_boundary_fixture()
        self.addCleanup(directory.cleanup)
        application["native_probe"]["darwin_floor_evidence"] = dict(expected_floor)
        application["native_probe"]["darwin_floor_evidence"]["macho"] = [
            {**expected_floor["macho"][0], "path": "/private/host/path"},
            *expected_floor["macho"][1:],
        ]
        with self.assertRaisesRegex(ContractError, "NEBULAR_UNIVERSAL_DARWIN_FLOOR_BINDING"):
            consumer_owner._require_darwin_receipt_boundary(application, capture)

        high_payload = _payload(minor=3, plist_minor=4)
        high_floor = validate_darwin_payload_floor(high_payload, required_floor=(13, 3))
        application, capture, _, directory, _ = _receipt_boundary_fixture(floor=high_floor)
        self.addCleanup(directory.cleanup)
        with self.assertRaisesRegex(ContractError, "NEBULAR_UNIVERSAL_DARWIN_FLOOR_BINDING"):
            consumer_owner._require_darwin_receipt_boundary(application, capture)


class ReachedSpawn(RuntimeError):
    """Positive-control sentinel: building the spawn argv is not execution."""


class InstalledSmokeDerivedGateTests(unittest.TestCase):
    def _run(self, fixture):
        values = fixture
        return installed_smoke.run_installed_smoke(
            prepared=values["prepared"],
            target="darwin-arm64",
            runtime_root=values["runtime_root"],
            env=values["env"],
            prefix=(),
            evidence=values["evidence"],
            native=values["native"],
            gui=values["gui"],
            runner=self._forbidden_runner,
            timeout=1,
            installed_command=values["command"],
        )

    @staticmethod
    def _forbidden_runner(*_args, **_kwargs):
        raise AssertionError("process runner must not be reached")

    def test_untampered_chain_reaches_node_gate_without_native_spawn(self):
        directory, fixture = _installed_smoke_fixture()
        self.addCleanup(directory.cleanup)
        with patch.object(installed_smoke, "node_binary", side_effect=ReachedSpawn):
            with patch.object(consumer_core, "_nebular_run", side_effect=AssertionError(
                    "consumer process runner must not be reached")):
                with self.assertRaises(ReachedSpawn):
                    self._run(fixture)

    def test_tampered_derived_harness_fails_before_node_or_runner(self):
        directory, fixture = _installed_smoke_fixture()
        self.addCleanup(directory.cleanup)
        real_prepare = installed_smoke.prepare_darwin_installed_harness

        def tampered_prepare(*args, **kwargs):
            output, process_harness, adapter = real_prepare(*args, **kwargs)
            output.write_bytes(output.read_bytes() + b"tampered")
            return output, process_harness, adapter

        with patch.object(installed_smoke, "prepare_darwin_installed_harness",
                          side_effect=tampered_prepare):
            with patch.object(installed_smoke, "node_binary", side_effect=ReachedSpawn) as node:
                with patch.object(consumer_core, "_nebular_run", side_effect=AssertionError(
                        "consumer process runner must not be reached")):
                    with self.assertRaisesRegex(AdmissionError, "TF_PYPI_NEBULAR_DARWIN_HARNESS"):
                        self._run(fixture)
                node.assert_not_called()


if __name__ == "__main__":
    unittest.main()
