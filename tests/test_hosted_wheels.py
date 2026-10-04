"""Hosted wheel contracts preserve truthful tags and actual native runtime qualification."""
from __future__ import annotations

import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import MagicMock, patch

from rs9.errors import ContractError
from rs9.hosted_platforms import (
    PLATFORM_TABLE,
    SUPPORTED_WHEEL_SYSTEMS,
    platform_contract,
    select_payload,
)
from rs9.hosted_wheels import (
    _get_target_platform,
    execute,
)
from rs9.wheel_native import WheelWithheldError, resolve_native_linux_candidate_tag

ROOT = Path(__file__).resolve().parents[1]


class HostedWheelContracts(unittest.TestCase):
    def test_platforms_and_candidate_tags_are_honest(self):
        self.assertEqual(_get_target_platform("aarch64-darwin"), "aarch64-apple-darwin")
        self.assertEqual(_get_target_platform("x86_64-linux"), "x86_64-unknown-linux-gnu")
        self.assertEqual(_get_target_platform("aarch64-linux"), "aarch64-unknown-linux-gnu")

        self.assertEqual(resolve_native_linux_candidate_tag("aarch64-unknown-linux-gnu"), "py3-none-linux_aarch64")
        self.assertEqual(resolve_native_linux_candidate_tag("x86_64-unknown-linux-gnu"), "py3-none-linux_x86_64")
        with self.assertRaises(WheelWithheldError):
            resolve_native_linux_candidate_tag("x86_64-unknown-linux-gnu", "manylinux_2_34_x86_64")

    def test_all_systems_in_platform_contract(self):
        """Verify all three systems have explicit one-way contracts in hosted_platforms."""
        for sys_name in ("aarch64-darwin", "x86_64-linux", "aarch64-linux"):
            self.assertIn(sys_name, SUPPORTED_WHEEL_SYSTEMS)
            row = platform_contract(sys_name)
            self.assertEqual(row.system, sys_name)
            self.assertEqual(_get_target_platform(sys_name), row.target_triple)
            self.assertTrue(len(row.asset_platform) > 0)
            self.assertTrue(len(row.wheel_tag) > 0)

    def test_lifecycle_native_verifier_runs_before_uninstall(self):
        source = (ROOT / "src/rs9/hosted_wheels.py").read_text()
        self.assertIn("commands_to_test=commands", source)
        self.assertIn('glob("entries/*/payload/*")', source)
        self.assertIn("verify_nebular_runtime(roots[0]", source)
        self.assertNotIn('commands[name] = {"argv": ["--version"]}', source)

    def test_linux_clients_are_pinned_and_network_disconnected(self):
        source = (ROOT / "src/rs9/hosted_wheel_clients.py").read_text()
        self.assertIn('context["pins"][family]["container_digests"]', source)
        self.assertIn('("deb", "rpm")', source)
        self.assertIn("verify_offline_venv_lifecycle", source)


class HostedWheelIsolationTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name).resolve()
        self.scratch = self.root / "scratch"
        self.scratch.mkdir()
        self.repo = self.root / "repo"
        self.repo.mkdir()

    def _create_mock_wheel(self, filename: str, tag: str = "py3-none-any"):
        wheel = MagicMock()
        wheel.filename = filename
        wheel.wheel_path = self.scratch / filename
        wheel.wheel_path.write_bytes(b"PK\x05\x06" + b"\x00" * 18)
        wheel.wheel_bytes = wheel.wheel_path.read_bytes()
        wheel.sha256 = "0" * 64
        wheel.size = len(wheel.wheel_bytes)
        wheel.tag = tag
        wheel.can_publish = False
        wheel.record = {"candidate_only": True, "promotability": "candidate", "manylinux_proven": False}
        return wheel

    def test_installed_burst_callback_binds_target_gate_to_real_load_probe(self):
        wheel = self._create_mock_wheel("theme_forge_stellar_burst-0.6.1-py3-none-macosx_13_0_arm64.whl", "py3-none-macosx_13_0_arm64")
        wheel.record.update(platform_specific=True, target_system="aarch64-darwin", target_native_addon={"path": "target", "sha256": "a" * 64})
        capture = MagicMock()
        capture.source = {"package.json": b"{}"}
        context = {"repository": self.repo, "scratch": self.scratch, "system": "aarch64-darwin",
                   "captures": [(capture, {"project": {"id": "theme-forge-stellar-burst"}}, {})]}
        def lifecycle(*a, **kw):
            verifier = kw["commands_to_test"]["tfsb"]["verifier"]
            verifier(self.root / "venv/bin/tfsb", [], {})
            return {"installed": True}
        with patch("rs9.hosted_wheels.closure_for_capture", return_value=[]), \
             patch("rs9.hosted_wheels.verify_double_build", return_value=(wheel, wheel)) as build, \
             patch("rs9.hosted_wheels.verify_wheel_record_bidirectional", return_value={"record_valid": True, "member_count": 5}), \
             patch("rs9.hosted_wheels.verify_offline_venv_lifecycle", side_effect=lifecycle), \
             patch("rs9.hosted_commands.run_probes", return_value=[{"name": "tfsb", "status": "pass"}]), \
             patch("rs9.hosted_wheels.verify_installed_burst", autospec=True, return_value={"status": "pass", "node_abi": "127"}) as load:
            result = execute(context)
        self.assertEqual(build.call_args.kwargs["system"], "aarch64-darwin")
        self.assertEqual(load.call_args.args[2], "aarch64-darwin")
        gates = {g["name"]: g["status"] for g in result["gates"]}
        self.assertEqual(gates["burst-native-addon-load"], "pass")

    @patch("rs9.hosted_wheels.closure_for_capture", return_value=[])
    @patch("rs9.hosted_wheels.verify_wheel_record_bidirectional")
    @patch("rs9.hosted_wheels.verify_double_build")
    @patch("rs9.hosted_wheels.verify_offline_venv_lifecycle")
    def test_product_isolation_and_skipped_second_loop_darwin(
        self,
        mock_lifecycle,
        mock_double_build,
        mock_record_inv,
        mock_closure,
    ):
        """When Nebular fails build with ContractError, other products build, second loop skips safely."""
        mock_record_inv.return_value = {"record_valid": True, "member_count": 5}
        mock_lifecycle.return_value = {"installed": True}

        # Stellar burst succeeds, Nebular fails
        burst_wheel = self._create_mock_wheel("theme_forge_stellar_burst-0.6.1-py3-none-macosx_13_0_arm64.whl", "py3-none-macosx_13_0_arm64")
        burst_wheel.record.update(platform_specific=True, target_system="aarch64-darwin", target_native_addon={"path": "target", "sha256": "a" * 64})

        def side_effect_double_build(builder, product_id, *args, **kwargs):
            if product_id == "theme-forge-nebular-fusion":
                raise ContractError(
                    "UNQUALIFIED_PLATFORM",
                    "Native CLI dependency wheels require platform qualification",
                    details={"origin": "node_modules/native-addon/binding.node"},
                )
            return burst_wheel, burst_wheel

        mock_double_build.side_effect = side_effect_double_build

        capture_burst = MagicMock()
        capture_burst.source = {"package.json": "{}"}
        capture_neb = MagicMock()
        capture_neb.source = {"package.json": "{}"}
        captures = [
            (capture_burst, {"project": {"id": "theme-forge-stellar-burst"}}, {}),
            (capture_neb, {"project": {"id": "theme-forge-nebular-fusion"}}, {}),
        ]

        context = {
            "repository": self.repo,
            "scratch": self.scratch,
            "system": "aarch64-darwin",
            "captures": captures,
        }

        # execute must NOT crash
        result = execute(context)

        # Check gates
        gate_names = {g["name"]: g for g in result["gates"]}

        # Stellar burst build passed
        self.assertEqual(gate_names["build.theme-forge-stellar-burst"]["status"], "pass")
        self.assertEqual(gate_names["record.theme-forge-stellar-burst"]["status"], "pass")

        self.assertEqual(gate_names["burst-native-addon-target"]["status"], "pass")
        self.assertEqual(gate_names["burst-native-addon-load"]["status"], "fail")

        # Nebular build failed
        self.assertEqual(gate_names["build.theme-forge-nebular-fusion"]["status"], "fail")
        self.assertEqual(gate_names["build.theme-forge-nebular-fusion"]["reason"], "UNQUALIFIED_PLATFORM")
        self.assertEqual(gate_names["record.theme-forge-nebular-fusion"]["status"], "fail")

        # Deterministic build gate failed because not all products built
        self.assertEqual(gate_names["wheel-deterministic-build"]["status"], "fail")

        # Second loop: Stellar burst lifecycle passed
        self.assertEqual(gate_names["lifecycle.theme-forge-stellar-burst"]["status"], "pass")

        # Second loop: Nebular skipped safely (guarded against missing product_records)
        self.assertEqual(gate_names["lifecycle.theme-forge-nebular-fusion"]["status"], "fail")
        self.assertEqual(gate_names["lifecycle.theme-forge-nebular-fusion"]["reason"], "product-not-built")

        # Native verifier failed because Nebular was unbuilt
        self.assertEqual(gate_names["wheel-native-verifier"]["status"], "fail")
        self.assertEqual(gate_names["wheel-native-verifier"]["reason"], "nebular-unbuilt")

        # Diagnostic file was written under scratch/diagnostics
        diag_file = self.scratch / "diagnostics" / "theme-forge-nebular-fusion-build-diagnostic.json"
        self.assertTrue(diag_file.is_file())
        diag_data = json.loads(diag_file.read_bytes())
        self.assertEqual(diag_data["product"], "theme-forge-nebular-fusion")
        self.assertEqual(diag_data["substage"], "build")
        self.assertEqual(diag_data["error_code"], "UNQUALIFIED_PLATFORM")
        self.assertNotIn("error_message", diag_data)

        # Verify safe error context fields
        details = diag_data["details"]
        self.assertEqual(details["product"], "theme-forge-nebular-fusion")
        self.assertEqual(details["substage"], "build")
        self.assertEqual(details["origin"], "node_modules/native-addon/binding.node")
        self.assertEqual(details["system"], "aarch64-darwin")
        self.assertEqual(details["target_triple"], "aarch64-apple-darwin")
        self.assertEqual(details["asset_platform"], "aarch64-darwin")
        self.assertEqual(details["wheel_tag"], "pending")

        # Retained artifact contains the successful wheel
        self.assertTrue((self.scratch / "retained" / burst_wheel.filename).is_file())

        # Manifest generated and valid
        self.assertTrue((self.scratch / "hosted-wheels-manifest.json").is_file())
        self.assertIn("theme-forge-stellar-burst", result["details"]["products"])
        self.assertNotIn("theme-forge-nebular-fusion", result["details"]["products"])

    @patch("rs9.hosted_wheels.closure_for_capture", return_value=[])
    @patch("rs9.hosted_wheels.linux_runtime_prefix", return_value=[])
    @patch("subprocess.run")
    @patch("rs9.hosted_wheels.verify_wheel_record_bidirectional")
    @patch("rs9.hosted_wheels.verify_double_build")
    @patch("rs9.hosted_wheels.verify_offline_venv_lifecycle")
    def test_product_isolation_and_guarded_client_qualification_linux(
        self,
        mock_lifecycle,
        mock_double_build,
        mock_record_inv,
        mock_subproc,
        mock_prefix,
        mock_closure,
    ):
        """On Linux, unbuilt Nebular cleanly fails client qualification gates without crashing."""
        mock_record_inv.return_value = {"record_valid": True, "member_count": 5}
        mock_lifecycle.return_value = {"installed": True}
        mock_subproc.return_value = MagicMock(returncode=0)

        burst_wheel = self._create_mock_wheel("theme_forge_stellar_burst-0.6.1-py3-none-linux_x86_64.whl", "py3-none-linux_x86_64")
        burst_wheel.record.update(platform_specific=True, target_system="x86_64-linux", target_native_addon={"path": "target", "sha256": "a" * 64})

        def side_effect_double_build(builder, product_id, *args, **kwargs):
            if product_id == "theme-forge-nebular-fusion":
                raise ContractError(
                    "MISSING_ASSET",
                    "No Linux x86_64 payload asset found",
                    details={"origin": "release_capture"},
                )
            return burst_wheel, burst_wheel

        mock_double_build.side_effect = side_effect_double_build

        capture_burst = MagicMock()
        capture_burst.source = {"package.json": "{}"}
        capture_neb = MagicMock()
        capture_neb.source = {"package.json": "{}"}
        captures = [
            (capture_burst, {"project": {"id": "theme-forge-stellar-burst"}}, {}),
            (capture_neb, {"project": {"id": "theme-forge-nebular-fusion"}}, {}),
        ]

        context = {
            "repository": self.repo,
            "scratch": self.scratch,
            "system": "x86_64-linux",
            "captures": captures,
        }

        result = execute(context)
        gate_names = {g["name"]: g for g in result["gates"]}

        # Linux client qualification gates exist and report clean failure
        self.assertEqual(gate_names["wheel-client-deb"]["status"], "fail")
        self.assertEqual(gate_names["wheel-client-deb"]["reason"], "nebular-unbuilt-or-unprepared")
        self.assertEqual(gate_names["wheel-client-rpm"]["status"], "fail")
        self.assertEqual(gate_names["wheel-client-rpm"]["reason"], "nebular-unbuilt-or-unprepared")

    @patch("rs9.hosted_wheels.closure_for_capture", return_value=[])
    @patch("rs9.hosted_smoke.prepare_smoke")
    @patch("rs9.hosted_wheels.verify_wheel_record_bidirectional")
    @patch("rs9.hosted_wheels.verify_double_build")
    @patch("rs9.hosted_wheels.verify_offline_venv_lifecycle")
    def test_nebular_built_diagnostics_bind_actual_computed_tag(
        self,
        mock_lifecycle,
        mock_double_build,
        mock_record_inv,
        mock_prepare_smoke,
        mock_closure,
    ):
        """When Nebular builds with computed tag and subsequent substage fails, diagnostic binds actual first.tag."""
        mock_record_inv.return_value = {"record_valid": True, "member_count": 5}
        neb_wheel = self._create_mock_wheel("theme_forge_nebular_fusion-0.6.1-py3-none-macosx_13_0_arm64.whl", tag="py3-none-macosx_13_0_arm64")
        mock_double_build.return_value = (neb_wheel, neb_wheel)
        mock_prepare_smoke.side_effect = ContractError("SMOKE_FAILED", "Simulated smoke prepare error", details={"origin": "prepare_smoke"})
        mock_lifecycle.side_effect = ContractError("LIFECYCLE_FAILED", "Simulated lifecycle error", details={"origin": "verify_offline_venv_lifecycle"})

        capture_neb = MagicMock()
        capture_neb.source = {"package.json": "{}"}
        captures = [
            (capture_neb, {"project": {"id": "theme-forge-nebular-fusion"}}, {}),
        ]

        context = {
            "repository": self.repo,
            "scratch": self.scratch,
            "system": "aarch64-darwin",
            "captures": captures,
        }

        result = execute(context)

        # 1. Check prepare_smoke diagnostic
        smoke_diag_file = self.scratch / "diagnostics" / "nebular-smoke-prepare-diagnostic.json"
        self.assertTrue(smoke_diag_file.is_file())
        smoke_diag = json.loads(smoke_diag_file.read_bytes())
        self.assertEqual(smoke_diag["details"]["wheel_tag"], "py3-none-macosx_13_0_arm64")
        self.assertNotIn("error_message", smoke_diag)

        # 2. Check lifecycle diagnostic
        life_diag_file = self.scratch / "diagnostics" / "theme-forge-nebular-fusion-lifecycle-diagnostic.json"
        self.assertTrue(life_diag_file.is_file())
        life_diag = json.loads(life_diag_file.read_bytes())
        self.assertEqual(life_diag["details"]["wheel_tag"], "py3-none-macosx_13_0_arm64")
        self.assertNotIn("error_message", life_diag)


if __name__ == "__main__":
    unittest.main()
