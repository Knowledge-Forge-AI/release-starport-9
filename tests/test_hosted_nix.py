"""Nix candidate source binds real outputs and fails before a build without capture."""
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from rs9.errors import ContractError
from rs9.hosted_nix import command, execute, SYSTEMS
ROOT = Path(__file__).resolve().parents[1]

class NixHostedTests(unittest.TestCase):
    def test_real_tool_failure_is_not_an_output_digest(self):
        from subprocess import CompletedProcess
        with patch("rs9.hosted_nix.subprocess.run",return_value=CompletedProcess(["nix","build"],1,b"",b"error")):
            with self.assertRaises(ContractError):
                command(["nix","build"])

    def test_unsupported_system_refused(self):
        with self.assertRaises(ContractError):
            execute({"system":"windows","repository":ROOT,"scratch":ROOT})

    def test_source_has_real_build_and_path_info_contract(self):
        source=(ROOT / "src/rs9/hosted_nix.py").read_text()
        self.assertIn('"nix", "build"',source)
        self.assertIn('"nix", "path-info"',source)
        self.assertNotIn("compute_bounded_out_hash",source)
        self.assertEqual(SYSTEMS,{"aarch64-darwin","x86_64-linux","aarch64-linux"})

    def test_nix_uses_store_materializer_and_full_fhs_runtime(self):
        source=(ROOT / "nix/nebular.nix").read_text()
        self.assertIn("buildFHSEnv",source)
        self.assertIn("webkitgtk_4_1",source)
        self.assertIn("dontFixup = true",source)
        self.assertIn("runtime/launch.py",source)
