"""Pure contract tests for the held OS080 RPM construction seam."""

from __future__ import annotations

import copy
import io
import importlib.util
import json
from pathlib import Path
import sys
import tarfile
import tempfile
import types
import unittest
from unittest.mock import patch

from rs9.build_native import CommandReceipt
from rs9.release_core import digest


HERE = Path(__file__).resolve()
ROOT = HERE.parents[1]
SOURCE_ROOT = ROOT
FIXTURE_ROOT = ROOT / "fixtures" if (ROOT / "fixtures").is_dir() else ROOT / "tests" / "fixtures"
FIXTURE = FIXTURE_ROOT / "current080-rpm-keyfree-request.json"
ADAPTER = SOURCE_ROOT / "src" / "rs9" / "current080_rpm_keyfree.py"
BASE_SOURCE = SOURCE_ROOT / "src"
if str(BASE_SOURCE) not in sys.path:
    sys.path.insert(0, str(BASE_SOURCE))

spec = importlib.util.spec_from_file_location("current080_keyfree_candidate", ADAPTER)
assert spec is not None and spec.loader is not None
keyfree = importlib.util.module_from_spec(spec)
spec.loader.exec_module(keyfree)


def _requests() -> list[dict]:
    with FIXTURE.open(encoding="utf-8") as stream:
        return json.load(stream)


def _held_error(request: dict) -> object:
    from rs9.errors import ContractError

    error = ContractError("RPMLINT_FAILED", "held policy")
    package_sha = "a" * 64
    witness = {
        "schema": "rs9.rpm-construction-witness.v1",
        "rpmbuild_receipt": {"status": "pass"},
        "rpm_identity": {
            "name": "theme-forge-nebular-fusion",
            "version": "0.8.0",
            "release": "1",
            "arch": request["architecture"],
        },
        "rpm_payload_digest": {"digest": "b" * 64, "algorithm": "sha256"},
        "package_sha256": package_sha,
        "package_size": 128,
        "spec_sha256": "c" * 64,
    }
    inventory = {
        "schema": "rs9.rpm-preservation-inventory.v1",
        "complete": True,
        "package_sha256": package_sha,
        "asset_sha256": request["raw_asset"]["sha256"],
        "payload_manifest_sha256": request["raw_asset"]["release_payload_manifest_sha256"],
        "files": {
            "/usr/lib/theme-forge-nebular-fusion/bin": {
                "path": "/usr/lib/theme-forge-nebular-fusion/bin",
                "type": "file",
                "mode": 0o755,
                "size": 1,
                "inode": 7,
                "device": 3,
                "flags": 0,
            }
        },
        "expected": {},
        "duplicate_groups": [],
        "calculated_duplicate_waste": 0,
        "possible_duplicate_waste_bytes": [0],
        "receipts": [
            {"query": "dump", "status": "pass"},
            {"query": "algo", "status": "pass"},
            {"query": "attrs", "status": "pass"},
        ],
    }
    error.construction_witness = witness
    error.preservation_inventory = inventory
    error.rpmlint_evidence = {
        "schema": "rs9.rpmlint-evidence.v1alpha1",
        "tool_receipt": {"tool": "rpmlint", "exit_code": 64},
        "package_sha256": package_sha,
    }
    error.rpmlint_policy = {
        "schema": "rs9.rpm-lint-policy-evaluation.v1",
        "accepted": False,
        "status": "blocked",
        "blockers": ["current-generation-diagnostic-only"],
    }
    return error


class Current080KeyfreeContractTests(unittest.TestCase):
    def test_both_maintained_linux_requests_validate(self) -> None:
        for request in _requests():
            self.assertEqual(keyfree.validate_request(request), request)

    def test_closed_schema_rejects_unknown_fields_and_mode(self) -> None:
        request = _requests()[0]
        unknown = copy.deepcopy(request)
        unknown["unexpected"] = True
        with self.assertRaisesRegex(Exception, "KEYFREE_SCHEMA"):
            keyfree.validate_request(unknown)
        forbidden = copy.deepcopy(request)
        forbidden["mode"]["signing"] = True
        with self.assertRaisesRegex(Exception, "KEYFREE_MODE"):
            keyfree.validate_request(forbidden)

    def test_source_asset_container_and_policy_are_exactly_bound(self) -> None:
        for location, value in (
            (("source", "commit"), "0" * 40),
            (("raw_asset", "sha256"), "0" * 64),
            (("container", "digest"), "sha256:" + "0" * 64),
            (("policy", "sha256"), "0" * 64),
        ):
            request = copy.deepcopy(_requests()[0])
            request[location[0]][location[1]] = value
            with self.assertRaisesRegex(Exception, "KEYFREE_"):
                keyfree.validate_request(request)

    def test_native_and_release_manifest_namespaces_cannot_be_swapped(self) -> None:
        request = _requests()[0]
        for native_field, release_field in (
            ("native_package_manifest_sha256", "release_payload_manifest_sha256"),
            ("release_payload_manifest_sha256", "native_package_manifest_sha256"),
        ):
            swapped = copy.deepcopy(request)
            swapped["raw_asset"][native_field] = request["raw_asset"][release_field]
            with self.assertRaisesRegex(Exception, "KEYFREE_ASSET"):
                keyfree.validate_request(swapped)

        wrong_inventory = _held_error(request)
        wrong_inventory.preservation_inventory["payload_manifest_sha256"] = request["raw_asset"][
            "native_package_manifest_sha256"
        ]
        with self.assertRaisesRegex(Exception, "KEYFREE_READBACK"):
            keyfree.normalize_policy_held_failure(request, wrong_inventory)

    def test_policy_held_readback_requires_complete_identity_and_inventory(self) -> None:
        request = _requests()[0]
        result = keyfree.normalize_policy_held_failure(request, _held_error(request))
        self.assertFalse(result["accepted"])
        self.assertEqual(result["status"], "constructed-policy-held")
        self.assertEqual(result["source"]["asset_sha256"], request["raw_asset"]["sha256"])
        self.assertEqual(
            result["preservation_inventory"]["files"][
                "/usr/lib/theme-forge-nebular-fusion/bin"
            ]["device"],
            3,
        )

    def test_policy_held_readback_rejects_missing_or_accepted_evidence(self) -> None:
        request = _requests()[0]
        missing = _held_error(request)
        del missing.preservation_inventory
        with self.assertRaisesRegex(Exception, "KEYFREE_READBACK"):
            keyfree.normalize_policy_held_failure(request, missing)
        accepted = _held_error(request)
        accepted.rpmlint_policy["accepted"] = True
        with self.assertRaisesRegex(Exception, "KEYFREE_POLICY"):
            keyfree.normalize_policy_held_failure(request, accepted)

    def test_policy_held_readback_rejects_external_receipts_without_internal_inventory_ledger(self) -> None:
        request = _requests()[0]
        error = _held_error(request)
        del error.preservation_inventory["receipts"]
        error.preservation_inventory_receipts = [
            CommandReceipt(["rpm", "--dump"], 0, b"", b"", executed=True),
            CommandReceipt(["rpm", "--algo"], 0, b"", b"", executed=True),
            CommandReceipt(["rpm", "--attrs"], 0, b"", b"", executed=True),
        ]
        with self.assertRaisesRegex(Exception, "KEYFREE_READBACK"):
            keyfree.normalize_policy_held_failure(request, error)

    def test_adapter_never_turns_success_or_prebuild_failure_into_acceptance(self) -> None:
        request = _requests()[0]

        def success(*_args, **_kwargs):
            return {"package": "not accepted"}

        with self.assertRaisesRegex(Exception, "KEYFREE_POLICY"):
            keyfree.construct_and_readback(
                success, request, None, {}, None, runner=None, policy=request["policy"]
            )

        def prebuild(*_args, **_kwargs):
            from rs9.errors import ContractError

            raise ContractError("INPUT_CHANGED", "prebuild refused")

        with self.assertRaisesRegex(Exception, "KEYFREE_READBACK"):
            keyfree.construct_and_readback(
                prebuild, request, None, {}, None, runner=None, policy=request["policy"]
            )

        def unavailable(*_args, **_kwargs):
            raise OSError("local fixture only")

        with self.assertRaisesRegex(Exception, "KEYFREE_READBACK"):
            keyfree.construct_and_readback(
                unavailable, request, None, {}, None, runner=None, policy=request["policy"]
            )

    def test_adapter_normalizes_only_late_held_failure(self) -> None:
        request = _requests()[1]

        def held(*_args, **_kwargs):
            raise _held_error(request)

        result = keyfree.construct_and_readback(
            held, request, None, {}, None, runner=None, policy=request["policy"]
        )
        self.assertEqual(result["system"], "aarch64-linux")
        self.assertEqual(result["architecture"], "aarch64")

    def test_real_builder_late_failure_reaches_adapter_with_separate_evidence(self) -> None:
        from rs9.build_rpm import build_rpm_candidate
        from rs9.current080_rpm_keyfree_job import _load_policy

        request = _requests()[0]
        raw_policy, summary_policy = _load_policy(SOURCE_ROOT, request)
        build_context = {
            "project_id": keyfree.PROJECT,
            "version": keyfree.VERSION,
            "is_native": False,
            "arch": "x86_64",
            "is_native_desktop": False,
            "is_native_node_cli": False,
            "is_pure_js_cli": True,
            "payload_root": "/payload",
            "payload": {"commands": {"tfnf": {"path": "/payload/bin/tfnf"}}},
            "summary": "bounded fixture",
            "license": "MIT",
            "asset_name": "source.tar.gz",
            "asset_sha": request["raw_asset"]["sha256"],
            "asset_bytes": b"bounded source asset",
        }
        observed_evidence: dict[str, object] = {}

        class FakeRunner:
            def __init__(self, root: Path) -> None:
                self.root = root
                self.calls: list[list[str]] = []

            def which(self, _name: str) -> str:
                return "/usr/bin/tool"

            def run(self, argv, **_kwargs):
                self.calls.append(list(argv))
                if argv and argv[0] == "rpmbuild":
                    rpm_dir = self.root / "rpmbuild" / "RPMS" / "x86_64"
                    rpm_dir.mkdir(parents=True, exist_ok=True)
                    (rpm_dir / "theme-forge-nebular-fusion-0.8.0-1.x86_64.rpm").write_bytes(
                        b"fake-rpm"
                    )
                if "--requires" in argv:
                    return CommandReceipt(argv, 0, b"nodejs >= 22\n", b"", executed=True)
                if "--provides" in argv:
                    return CommandReceipt(
                        argv, 0, b"theme-forge-nebular-fusion = 0.8.0-1\n", b"", executed=True
                    )
                return CommandReceipt(argv, 0, b"", b"", executed=True)

        def fake_bundle(_source: Path, destination: Path) -> str:
            destination.write_bytes(b"bounded npm closure")
            return "d" * 64

        def fake_lint(*, spec_path: Path, rpm_path: Path, **_kwargs):
            return (
                {
                    "schema": "rs9.rpmlint-evidence.v1alpha1",
                    "tool_receipt": {"tool": "rpmlint", "exit_code": 64},
                    "package_sha256": digest(rpm_path.read_bytes()),
                    "spec_sha256": digest(spec_path.read_bytes()),
                    "findings": [],
                },
                [CommandReceipt(["rpmlint"], 64, b"", b"", executed=True)],
            )

        def fake_inventory(**kwargs):
            observed_evidence.update(
                client_runtime=kwargs["client_runtime"],
                caller_evidence=kwargs["caller_evidence"],
            )
            package_sha = digest(Path(kwargs["rpm_file"]).read_bytes())
            inventory = {
                "schema": "rs9.rpm-preservation-inventory.v1",
                "complete": True,
                "package_sha256": package_sha,
                "asset_sha256": request["raw_asset"]["sha256"],
                "payload_manifest_sha256": request["raw_asset"]["release_payload_manifest_sha256"],
                "files": {
                    "/usr/lib/theme-forge-nebular-fusion/bin": {
                        "path": "/usr/lib/theme-forge-nebular-fusion/bin",
                        "type": "file",
                        "mode": 0o755,
                        "size": 1,
                        "inode": 7,
                        "device": 3,
                        "flags": 0,
                    }
                },
                "expected": {},
                "duplicate_groups": [],
                "calculated_duplicate_waste": 0,
                "possible_duplicate_waste_bytes": [0],
                "receipts": [
                    {"query": "dump", "status": "pass"},
                    {"query": "algo", "status": "pass"},
                    {"query": "attrs", "status": "pass"},
                ],
            }
            receipts = [
                CommandReceipt(["rpm", "--dump"], 0, b"", b"", executed=True),
                CommandReceipt(["rpm", "--algo"], 0, b"", b"", executed=True),
                CommandReceipt(["rpm", "--attrs"], 0, b"", b"", executed=True),
            ]
            return inventory, receipts

        def blocked_policy(*_args, **_kwargs):
            return {
                "schema": "rs9.rpm-lint-policy-evaluation.v1",
                "accepted": False,
                "status": "blocked",
                "blockers": ["current-generation-diagnostic-only"],
                "raw_lint_status": "fail",
                "raw_exit_code": 64,
            }

        runtime = {"status": "pass", "schema": "runtime-fixture.v1"}
        caller = {"status": "pass", "files": {"bin/tfnf": {"sha256": "e" * 64}}}
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            scratch = Path(directory) / "build"
            scratch.mkdir()
            runner = FakeRunner(scratch)
            with (
                patch("rs9.rpm_lint_policy.assert_policy_capture"),
                patch("rs9.build_rpm.validate_build_inputs", return_value=build_context),
                patch("rs9.build_rpm.stage_offline_npm_closure"),
                patch("rs9.build_native.npm_bundle", side_effect=fake_bundle),
                patch("rs9.build_rpm._render_rpm_spec", return_value=b"bounded spec"),
                patch("rs9.build_rpm._format_rpm_changelog", return_value="bounded changelog"),
                patch("rs9.build_rpm.query_rpm_package", return_value=(
                    {"name": keyfree.PROJECT, "version": keyfree.VERSION, "release": "1", "arch": "x86_64"},
                    {"algorithm": "sha256", "digest": "b" * 64},
                    [],
                )),
                patch("rs9.build_rpm.execute_rpmlint", side_effect=fake_lint),
                patch("rs9.build_rpm.collect_preservation_inventory", side_effect=fake_inventory),
                patch("rs9.build_rpm.evaluate_policy", side_effect=blocked_policy),
            ):
                result = keyfree.construct_and_readback(
                    build_rpm_candidate,
                    request,
                    None,
                    {},
                    scratch,
                    runner=runner,
                    policy=summary_policy,
                    builder_policy=raw_policy,
                    client_runtime=runtime,
                    caller_evidence=caller,
                )
        self.assertEqual(result["status"], "constructed-policy-held")
        self.assertFalse(result["accepted"])
        self.assertEqual(observed_evidence, {"client_runtime": runtime, "caller_evidence": caller})
        self.assertTrue(any(command and command[0] == "rpmbuild" for command in runner.calls))

    def test_real_native_desktop_builder_reaches_blocked_policy_without_runtime_or_caller_evidence(self) -> None:
        from rs9.build_rpm import build_rpm_candidate
        from rs9.current080_rpm_keyfree_job import _load_policy
        from tests.elf_builder import build_elf

        request = _requests()[0]
        raw_policy, summary_policy = _load_policy(SOURCE_ROOT, request)
        observed_evidence: dict[str, object] = {}
        build_context: dict[str, object] = {
            "project_id": keyfree.PROJECT,
            "version": keyfree.VERSION,
            "is_native": True,
            "arch": "x86_64",
            "is_native_desktop": True,
            "is_native_node_cli": False,
            "is_pure_js_cli": False,
            "payload_root": "/payload",
            "payload": {
                "payload_manifest_sha256": request["raw_asset"]["release_payload_manifest_sha256"],
                "launchers": {"tfnf": {"path": "/payload/usr/bin/tfnf"}},
            },
            "summary": "bounded native desktop fixture",
            "license": "AGPL-3.0-or-later",
            "asset_name": "nebular-native-0.8.0.tar.gz",
            "asset_sha": request["raw_asset"]["sha256"],
        }

        class FakeRunner:
            def __init__(self, root: Path) -> None:
                self.root = root
                self.calls: list[list[str]] = []

            def which(self, name: str) -> str:
                return "/usr/bin/" + name

            def run(self, argv, **_kwargs):
                self.calls.append(list(argv))
                if argv and argv[0] == "rpmbuild":
                    spec_path = Path(argv[2])
                    sources = spec_path.parent.parent / "SOURCES"
                    self.assert_staged = (
                        (sources / f"{keyfree.PROJECT}.desktop").is_file()
                        and (sources / "icon.png").is_file()
                        and "usr/bin/tfnf" in spec_path.read_text(encoding="utf-8")
                    )
                    rpm_dir = self.root / "rpmbuild" / "RPMS" / "x86_64"
                    rpm_dir.mkdir(parents=True, exist_ok=True)
                    (rpm_dir / f"{keyfree.PROJECT}-0.8.0-1.x86_64.rpm").write_bytes(b"native-fake-rpm")
                if argv and argv[0] == "rpm" and "--requires" in argv:
                    return CommandReceipt(argv, 0, b"libc.so.6()(64bit)\n", b"", executed=True)
                if argv and argv[0] == "rpm" and "--provides" in argv:
                    return CommandReceipt(argv, 0, b"libc.so.6()(64bit)\n", b"", executed=True)
                return CommandReceipt(argv, 0, b"", b"", executed=True)

        def fake_inventory(**kwargs):
            observed_evidence.update(
                client_runtime=kwargs["client_runtime"],
                caller_evidence=kwargs["caller_evidence"],
            )
            package_sha = digest(Path(kwargs["rpm_file"]).read_bytes())
            inventory = {
                "schema": "rs9.rpm-preservation-inventory.v1",
                "complete": True,
                "package_sha256": package_sha,
                "asset_sha256": request["raw_asset"]["sha256"],
                "payload_manifest_sha256": request["raw_asset"]["release_payload_manifest_sha256"],
                "files": {
                    "/usr/bin/tfnf": {
                        "path": "/usr/bin/tfnf",
                        "type": "file",
                        "mode": 0o755,
                        "size": 1,
                        "inode": 7,
                        "device": 3,
                        "flags": 0,
                    }
                },
                "expected": {},
                "wrappers": {},
                "permitted_directories": [],
                "duplicate_groups": [],
                "calculated_duplicate_waste": 0,
                "possible_duplicate_waste_bytes": [0],
                "receipts": [
                    {"query": "dump", "status": "pass"},
                    {"query": "algo", "status": "pass"},
                    {"query": "attrs", "status": "pass"},
                ],
            }
            receipts = [
                CommandReceipt(["rpm", "--dump"], 0, b"", b"", executed=True),
                CommandReceipt(["rpm", "--algo"], 0, b"", b"", executed=True),
                CommandReceipt(["rpm", "--attrs"], 0, b"", b"", executed=True),
            ]
            return inventory, receipts

        def fake_lint(*, spec_path: Path, rpm_path: Path, product: str, **_kwargs):
            package_sha = digest(rpm_path.read_bytes())
            evidence = {
                "schema": "rs9.rpmlint-evidence.v1alpha1",
                "product": product,
                "package_sha256": package_sha,
                "spec_sha256": digest(spec_path.read_bytes()),
                "status": "fail",
                "clean": False,
                "reason_token": "lint-errors",
                "parse_complete": True,
                "error_overflow": False,
                "unparsed_count": 0,
                "findings_summary": {
                    "errors": 1,
                    "warnings": 0,
                    "information": 0,
                    "filtered": raw_policy["tool_constraints"]["filtered_count"],
                    "packages": 1,
                    "specfiles": 1,
                },
                "error_records": [
                    {
                        "target": product + ".x86_64",
                        "code": "fixture-diagnostic",
                        "level": "E",
                        "message": "bounded fixture finding",
                        "arguments_complete": True,
                        "path": "/usr/bin/tfnf",
                    }
                ],
                "tool_receipt": {
                    "tool": "rpmlint",
                    "executed": True,
                    "exit_code": 64,
                    "stderr_bytes": 0,
                },
                "tool_version": {
                    "version": "2.8.0",
                    "exit_code": 0,
                    "package_query": {
                        "version": "rpmlint|2.8.0|2.fc43|noarch",
                        "exit_code": 0,
                    },
                },
            }
            return evidence, [CommandReceipt(["rpmlint"], 64, b"", b"", executed=True)]

        with tempfile.TemporaryDirectory(dir=SOURCE_ROOT) as directory:
            root = Path(directory)
            asset_file = root / build_context["asset_name"]
            elf = build_elf(
                machine="x86_64",
                needed=["libc.so.6"],
                interpreter="/lib64/ld-linux-x86-64.so.2",
            )
            with tarfile.open(asset_file, "w:gz") as archive:
                member = tarfile.TarInfo("payload/usr/bin/tfnf")
                member.mode = 0o755
                member.size = len(elf)
                archive.addfile(member, io.BytesIO(elf))
            build_context["asset_file"] = asset_file
            build_context["asset_bytes"] = asset_file.read_bytes()
            capture = types.SimpleNamespace(source={"icon.png": b"native-icon"}, record={})
            intent = {
                "project": {"id": keyfree.PROJECT},
                "version": keyfree.VERSION,
                "desktop": {"icon": {"path": "icon.png"}, "categories": ["Development"]},
            }
            scratch = root / "build"
            scratch.mkdir()
            runner = FakeRunner(scratch)
            with (
                patch("rs9.rpm_lint_policy.assert_policy_capture"),
                patch("rs9.build_rpm.validate_build_inputs", return_value=build_context),
                patch("rs9.build_rpm.png_size"),
                patch("rs9.build_rpm._format_rpm_changelog", return_value="bounded changelog"),
                patch(
                    "rs9.build_rpm.query_rpm_package",
                    return_value=(
                        {
                            "name": keyfree.PROJECT,
                            "version": keyfree.VERSION,
                            "release": "1",
                            "arch": "x86_64",
                        },
                        {"algorithm": "sha256", "digest": "b" * 64},
                        [],
                    ),
                ),
                patch("rs9.build_rpm.execute_rpmlint", side_effect=fake_lint),
                patch("rs9.build_rpm.collect_preservation_inventory", side_effect=fake_inventory),
            ):
                result = keyfree.construct_and_readback(
                    build_rpm_candidate,
                    request,
                    capture,
                    intent,
                    scratch,
                    runner=runner,
                    policy=summary_policy,
                    builder_policy=raw_policy,
                    client_runtime=None,
                    caller_evidence=None,
                )
        self.assertEqual(result["status"], "constructed-policy-held")
        self.assertFalse(result["accepted"])
        self.assertIn("current-generation-diagnostic-only", result["rpmlint_policy"]["blockers"])
        self.assertEqual(observed_evidence, {"client_runtime": None, "caller_evidence": None})
        self.assertTrue(any(command and command[0] == "rpmbuild" for command in runner.calls))
        self.assertTrue(runner.assert_staged)


if __name__ == "__main__":
    unittest.main()
