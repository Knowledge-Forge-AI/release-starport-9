"""Publication remains withheld; APGR and deferred Nebular stay untouched."""
import ast
import hashlib
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from rs9.tf_pypi_backend import HELPERS
from rs9.tf_pypi_model import PRODUCTS, load_pin
from rs9.tf_pypi_publish import workflow_text
from rs9.tf_pypi_verify import verify_pair
from rs9.tf_pypi_workflow import main, parser
from tests.tf_pypi_fixtures import ROOT, aggregate, fixture


class Output:
    def __init__(self):
        self.buffer = io.BytesIO()


class WorkflowTests(unittest.TestCase):
    def test_no_unqualified_first_wave_or_nebular_publisher(self):
        from rs9.tf_pypi_nebular import workflow_text as nebular_workflow_text
        workflows = ROOT / ".github/workflows"
        for product in PRODUCTS:
            pin = load_pin(product)
            self.assertEqual((workflows / pin["workflow"]).exists(), pin["source_status"] == "READY")
        self.assertEqual((workflows / "rs9-tfnf-pypi-publish.yml").read_text(), nebular_workflow_text())
        self.assertEqual(hashlib.sha256((workflows / "rs9-pypi-publish.yml").read_bytes()).hexdigest(),
                         "d248edcab45a912f76ca04289d46a4fdd8de91f53d86780a6f2539a667004e3a")

    def test_registered_first_wave_workflows_are_byte_identical_to_generator(self):
        workflows = ROOT / ".github/workflows"
        for product in sorted(PRODUCTS):
            pin = load_pin(product)
            raw = (workflows / pin["workflow"]).read_bytes()
            self.assertEqual(raw, workflow_text(pin).encode("utf-8"))
            self.assertNotIn(b"--output dist --target", raw)
            self.assertNotIn(b"native_consumer:", raw)
            self.assertNotIn(f"name: native-consumer-{product}\n".encode("utf-8"), raw)

    def test_status_never_equates_absence_or_publication_with_source_ready(self):
        pin = load_pin("theme-forge-solar-sail")
        for remote in ("absent", "version-absent", "published-exact", "unknown", "conflict", "present-unverified"):
            output = Output()
            with patch("rs9.tf_pypi_workflow.project_state", return_value=remote), patch("sys.stdout", output):
                result = main(["status", "--project", "theme-forge-solar-sail", "--remote"])
            receipt = json.loads(output.buffer.getvalue())
            self.assertEqual(receipt["version"], pin["distribution_version"])
            self.assertEqual(receipt["upstream_version"], pin["version"])
            self.assertEqual(receipt["source"], pin["source_status"])
            self.assertFalse(receipt["publication_admitted"])
            self.assertEqual(result, 1 if remote in {"unknown", "conflict", "present-unverified"} else 0)

    def test_build_verify_and_consumer_operate_on_aggregate_and_host_view(self):
        pin, data = fixture("theme-forge-solar-sail")
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            inputs = root / "inputs"
            inputs.mkdir()
            (inputs / pin["asset"]).write_bytes(data)
            dist = root / "dist"

            build_out = Output()
            with patch("rs9.tf_pypi_workflow.load_pin", return_value=pin), patch("sys.stdout", build_out):
                rc = main(["build", "--project", pin["project"], "--inputs", str(inputs), "--output", str(dist)])
            self.assertEqual(rc, 0)
            built = json.loads(build_out.buffer.getvalue())
            self.assertEqual(built["schema"], "rs9.tf-pypi-candidate-aggregate.v1")
            self.assertEqual(built["version"], pin["distribution_version"])
            self.assertEqual(built["upstream_version"], pin["version"])
            self.assertEqual(len(built["files"]), 4)

            verify_out = Output()
            with patch("rs9.tf_pypi_workflow.load_pin", return_value=pin), patch("sys.stdout", verify_out):
                rc = main(["verify", "--project", pin["project"], "--dist", str(dist)])
            self.assertEqual(rc, 0)
            self.assertEqual(json.loads(verify_out.buffer.getvalue()), built)

            observed_views = []
            def fake_smoke(smoke_pin, view_dir, consumer_work, *, offline_linux=False, functional=True):
                pair = verify_pair(smoke_pin, view_dir, target="linux-x64-gnu")
                observed_views.append((pair, Path(consumer_work), offline_linux))
                return {"project": smoke_pin["project"], "target": "linux-x64-gnu", "publication_admitted": False}

            consumer_out = Output()
            work_dir = root / "work"
            with patch("rs9.tf_pypi_workflow.load_pin", return_value=pin), \
                    patch("rs9.tf_pypi_workflow.host_key", return_value="linux-x64-gnu"), \
                    patch("rs9.tf_pypi_workflow.smoke", side_effect=fake_smoke), \
                    patch("sys.stdout", consumer_out):
                rc = main([
                    "consumer", "--project", pin["project"],
                    "--dist", str(dist), "--work", str(work_dir), "--offline-linux",
                ])
            self.assertEqual(rc, 0)
            self.assertEqual(len(observed_views), 1)
            pair_manifest, consumer_work, offline_flag = observed_views[0]
            self.assertEqual(len(pair_manifest["files"]), 2)
            self.assertTrue(any("manylinux_2_28_x86_64" in f["filename"] for f in pair_manifest["files"]))
            self.assertEqual(consumer_work, work_dir / "consumer")
            self.assertTrue(offline_flag)

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
            self.assertEqual(receipt["version"], load_pin(product)["distribution_version"])
            self.assertEqual(receipt["upstream_version"], load_pin(product)["version"])
            self.assertEqual(receipt["remote"], "not-read")
            self.assertNotIn(str(ROOT).encode(), result.stdout + result.stderr)

    def test_backend_helpers_are_stdlib_only(self):
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


if __name__ == "__main__":
    unittest.main()
