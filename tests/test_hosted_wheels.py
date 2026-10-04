"""Hosted wheel contracts preserve truthful tags and actual native runtime qualification."""
from pathlib import Path
import unittest
from rs9.errors import ContractError
from rs9.hosted_wheels import _get_target_platform, SUPPORTED_WHEEL_SYSTEMS
from rs9.wheel_native import resolve_native_linux_candidate_tag, WheelWithheldError
ROOT=Path(__file__).resolve().parents[1]

class HostedWheelContracts(unittest.TestCase):
    def test_platforms_and_candidate_tags_are_honest(self):
        self.assertEqual(_get_target_platform("aarch64-darwin"),"aarch64-apple-darwin")
        self.assertEqual(resolve_native_linux_candidate_tag("aarch64-unknown-linux-gnu"),"py3-none-linux_aarch64")
        with self.assertRaises(WheelWithheldError):
            resolve_native_linux_candidate_tag("x86_64-unknown-linux-gnu","manylinux_2_34_x86_64")

    def test_lifecycle_native_verifier_runs_before_uninstall(self):
        source=(ROOT / "src/rs9/hosted_wheels.py").read_text()
        self.assertIn("commands_to_test=commands",source)
        self.assertIn('glob("entries/*/payload/*")',source)
        self.assertIn("verify_nebular_runtime(roots[0]",source)
        self.assertNotIn('commands[name] = {"argv": ["--version"]}',source)

    def test_linux_clients_are_pinned_and_network_disconnected(self):
        source=(ROOT / "src/rs9/hosted_wheel_clients.py").read_text()
        self.assertIn('context["pins"][family]["container_digests"]',source)
        self.assertIn('("deb", "rpm")',source)
        self.assertIn("verify_offline_venv_lifecycle",source)
