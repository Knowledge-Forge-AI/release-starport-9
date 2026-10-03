import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from tests.shadow_fixtures import ROOT, fixture_evidence


class ShadowCliTests(unittest.TestCase):
    def test_offline_operations_from_foreign_directory_and_fail_closed_fetch(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            evidence = root / "evidence"
            evidence.mkdir()
            fixture_evidence(evidence)
            environment = {"PATH": os.defpath, "PYTHONPATH": str(ROOT / "src"), "PYTHONDONTWRITEBYTECODE": "1"}
            base = [sys.executable, "-m", "rs9.shadow"]
            parameters = [str(ROOT / "examples/theme-forge/theme-forge-nebular-fusion"), "--destinations", str(ROOT / "examples/destinations.example.toml"), "--version", "0.6.1", "--evidence", str(evidence)]
            for operation in ("authenticate", "dependencies", "render"):
                output = root / operation
                output.mkdir()
                result = subprocess.run(base + [operation] + parameters + ["--output", str(output)], cwd=root,
                                        env=environment, capture_output=True, text=True, timeout=30)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertTrue(list(output.iterdir()))
            output = root / "bad"
            output.mkdir()
            (evidence / "api/release.json").write_text("not-json")
            result = subprocess.run(base + ["authenticate"] + parameters + ["--output", str(output)], cwd=root,
                                    env=environment, capture_output=True, text=True, timeout=30)
            self.assertEqual(result.returncode, 2)
            self.assertIn("INVALID_EVIDENCE", result.stderr)
            self.assertEqual(list(output.iterdir()), [])
