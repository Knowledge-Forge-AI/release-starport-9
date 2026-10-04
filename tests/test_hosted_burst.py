"""Installed native selection must be observed, platform-bound and byte-identical."""
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from rs9.burst_native import BURST_CLOSED_PREBUILDS
from rs9.errors import ContractError
from rs9.hosted_burst import validate_load_receipt, verify_burst_payload, verify_installed_burst
from rs9.release_core import digest
from tests.elf_builder import build_elf
from tests.test_burst_platform_wheel import make_synthetic_macho


class InstalledBurstTests(unittest.TestCase):
    def receipt(self, system="x86_64-linux"):
        key = {"x86_64-linux": "linux-x64-gnu", "aarch64-linux": "linux-arm64-gnu", "aarch64-darwin": "darwin-arm64"}[system]
        expected = {"path": BURST_CLOSED_PREBUILDS[key], "sha256": digest(self.addon_bytes(system))}
        receipt = {"loaded": True, "artifact": key, "loads": [expected["path"]], "sha256": expected["sha256"],
                   "node_version": "v22.20.0", "node_abi": "127", "platform": "darwin" if system.endswith("darwin") else "linux",
                   "architecture": "x64" if system == "x86_64-linux" else "arm64"}
        return expected, receipt

    def addon_bytes(self, system="x86_64-linux"):
        return make_synthetic_macho() if system.endswith("darwin") else build_elf(machine="aarch64" if system.startswith("aarch64") else "x86_64")

    def test_each_qualified_host_binds_one_observed_load_and_node_abi(self):
        """[SYNTHETIC] Verify each qualified host binds one load and node ABI."""
        for system in ("x86_64-linux", "aarch64-linux", "aarch64-darwin"):
            expected, receipt = self.receipt(system)
            self.assertEqual(validate_load_receipt(receipt, expected, system)["status"], "pass")

    def test_no_load_foreign_load_double_load_bytes_and_host_fail_closed(self):
        """[SYNTHETIC] Verify failure conditions fail closed."""
        expected, receipt = self.receipt()
        for field, value, code in (
            ("loaded", False, "BURST_NATIVE_LOAD"),
            ("loads", [], "BURST_NATIVE_LOAD_COUNT"),
            ("loads", [expected["path"], expected["path"]], "BURST_NATIVE_LOAD_COUNT"),
            ("loads", [BURST_CLOSED_PREBUILDS["linux-arm64-gnu"]], "BURST_NATIVE_LOAD_TARGET"),
            ("loads", ["outside-installed-payload"], "BURST_NATIVE_LOAD_TARGET"),
            ("sha256", "0" * 64, "BURST_NATIVE_LOAD_BYTES"),
            ("architecture", "arm64", "BURST_NATIVE_LOAD_TARGET"),
            ("node_version", "v20.0.0", "BURST_NATIVE_NODE"),
            ("node_abi", None, "BURST_NATIVE_NODE"),
        ):
            with self.subTest(field=field, value=value), self.assertRaises(ContractError) as caught:
                validate_load_receipt({**receipt, field: value}, expected, "x86_64-linux")
            self.assertEqual(caught.exception.code, code)

    def test_installed_loader_bytes_and_target_are_checked_before_probe(self):
        """[SYNTHETIC] Installed loader bytes and target are checked before probe."""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            console = root / "venv/bin/tfsb"
            console.parent.mkdir(parents=True)
            console.write_bytes(b"console")
            payload = root / "venv/lib/python3.13/site-packages/theme_forge_stellar_burst/payload"
            expected, receipt = self.receipt()
            addon = payload / expected["path"]
            addon.parent.mkdir(parents=True)
            addon.write_bytes(self.addon_bytes())
            loader = payload / "package/dist/directory-snapshot-native.js"
            loader.parent.mkdir()
            loader.write_bytes(b"authenticated-released-lazy-loader")
            record = {"platform_specific": True, "target_system": "x86_64-linux", "target_native_addon": expected,
                      "native_loader": {"path": "package/dist/directory-snapshot-native.js", "sha256": digest(loader.read_bytes())}}
            with patch("rs9.hosted_burst.subprocess.run", return_value=subprocess.CompletedProcess([], 0, json.dumps(receipt).encode(), b"")) as run:
                result = verify_installed_burst(console, record, "x86_64-linux", root / "probe", prefix=["network-denied"], env={"FIXTURE": "1"})
            self.assertEqual(result["status"], "pass")
            self.assertEqual(run.call_args.args[0][:4], ["network-denied", "node", "--require", str(root / "probe/observe-load.cjs")])
            self.assertEqual(run.call_args.kwargs["env"], {"FIXTURE": "1"})
            self.assertIn("loadDirectorySnapshotNative()", (root / "probe/exercise-loader.mjs").read_text())
            for mutation in ("missing", "changed", "symlink", "loader"):
                with self.subTest(mutation=mutation):
                    addon.unlink()
                    if mutation == "changed": addon.write_bytes(b"changed")
                    elif mutation == "symlink": addon.symlink_to(loader)
                    elif mutation == "loader":
                        addon.write_bytes(self.addon_bytes())
                        loader.write_bytes(b"changed")
                    with patch("rs9.hosted_burst.subprocess.run") as run, self.assertRaises(ContractError):
                        verify_installed_burst(console, record, "x86_64-linux", root / "unused-probe")
                    run.assert_not_called()
                    if not addon.exists() and not addon.is_symlink(): addon.write_bytes(self.addon_bytes())

    def test_universal_or_wrong_system_record_never_runs_node(self):
        """[SYNTHETIC] Universal or wrong system record never runs node."""
        expected, _ = self.receipt()
        for record in ({"platform_specific": False}, {"platform_specific": True, "target_system": "aarch64-linux", "target_native_addon": expected}):
            with patch("rs9.hosted_burst.subprocess.run") as run, self.assertRaises(ContractError):
                verify_installed_burst(Path("venv/bin/tfsb"), record, "x86_64-linux", Path("unused"))
            run.assert_not_called()

    def test_payload_root_verifier_with_injectable_runner(self):
        """[SYNTHETIC] Verify payload-root verifier with custom layout prefix and injectable runner."""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            payload = root / "nix_payload"
            expected, receipt = self.receipt("aarch64-darwin")
            addon_path = payload / expected["path"]
            addon_path.parent.mkdir(parents=True)
            addon_path.write_bytes(self.addon_bytes("aarch64-darwin"))

            loader_path = payload / "package/dist/directory-snapshot-native.js"
            loader_path.parent.mkdir(parents=True)
            loader_path.write_bytes(b"authenticated-loader")

            record = {
                "platform_specific": True,
                "target_system": "aarch64-darwin",
                "target_native_addon": expected,
                "native_loader": {"path": "package/dist/directory-snapshot-native.js", "sha256": digest(loader_path.read_bytes())},
            }

            executed_commands = []
            def custom_runner(cmd, env=None):
                executed_commands.append(cmd)
                return subprocess.CompletedProcess(cmd, 0, json.dumps(receipt).encode("utf-8"), b"")

            res = verify_burst_payload(
                payload,
                record,
                "aarch64-darwin",
                root / "probe",
                layout_prefix="package",
                runner=custom_runner,
            )
            self.assertEqual(res["status"], "pass")
            self.assertEqual(len(executed_commands), 1)
            self.assertIn("node", executed_commands[0])
