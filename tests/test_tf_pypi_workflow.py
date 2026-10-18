"""Publication remains withheld; APGR and deferred Nebular stay untouched."""
import hashlib
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import unittest
from unittest.mock import patch

from rs9.tf_pypi_model import PRODUCTS, load_pin
from rs9.tf_pypi_workflow import main, parser
from tests.tf_pypi_fixtures import ROOT


class Output:
    def __init__(self):
        self.buffer = io.BytesIO()


class WorkflowTests(unittest.TestCase):
    def test_no_unqualified_first_wave_or_nebular_publisher(self):
        workflows = ROOT / ".github/workflows"
        for product in PRODUCTS:
            pin = load_pin(product)
            self.assertEqual((workflows / pin["workflow"]).exists(), pin["source_status"] == "READY")
        self.assertFalse((workflows / "rs9-tfnf-pypi-publish.yml").exists())
        self.assertEqual(hashlib.sha256((workflows / "rs9-pypi-publish.yml").read_bytes()).hexdigest(),
                         "d248edcab45a912f76ca04289d46a4fdd8de91f53d86780a6f2539a667004e3a")

    def test_status_never_equates_absence_or_publication_with_source_ready(self):
        for remote in ("absent", "published-exact", "unknown", "conflict", "present-unverified"):
            output = Output()
            with patch("rs9.tf_pypi_workflow.project_state", return_value=remote), patch("sys.stdout", output):
                result = main(["status", "--project", "theme-forge-solar-sail", "--remote"])
            receipt = json.loads(output.buffer.getvalue())
            self.assertEqual(receipt["source"], load_pin("theme-forge-solar-sail")["source_status"])
            self.assertFalse(receipt["publication_admitted"])
            self.assertEqual(result, 1 if remote in {"unknown", "conflict", "present-unverified"} else 0)

    def test_cli_has_no_upload_select_missing_dispatch_or_credential_operation(self):
        for operation in ("publish", "upload", "select-missing", "dispatch", "pin"):
            with patch("sys.stderr", io.StringIO()), self.assertRaises(SystemExit):
                parser().parse_args([operation])

    def test_module_import_has_no_io_and_cli_output_has_no_local_paths(self):
        for product in PRODUCTS:
            result = subprocess.run([sys.executable, "-B", "-m", "rs9.tf_pypi_workflow", "status",
                                     "--project", product], cwd=ROOT, capture_output=True, timeout=10,
                                    env={**os.environ, "PYTHONPATH": str(ROOT / "src")})
            self.assertEqual(result.returncode, 0, result.stderr)
            receipt = json.loads(result.stdout)
            self.assertEqual(receipt["remote"], "not-read")
            self.assertNotIn(str(ROOT).encode(), result.stdout + result.stderr)

    def test_backend_helpers_are_stdlib_only(self):
        import ast
        from rs9.tf_pypi_backend import HELPERS
        for filename in HELPERS:
            path = ROOT / "src/rs9" / filename
            tree = ast.parse(path.read_text(), feature_version=(3, 9))
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    for item in node.names:
                        self.assertIn(item.name.split(".")[0], sys.stdlib_module_names)
                elif isinstance(node, ast.ImportFrom) and not node.level:
                    if node.module.startswith("rs9."):
                        self.assertIn(node.module.split(".")[1] + ".py", HELPERS)
                    else:
                        self.assertIn(node.module.split(".")[0], sys.stdlib_module_names)
