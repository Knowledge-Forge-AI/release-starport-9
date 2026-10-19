"""Tests for the source-owned future publication contract."""
import ast
import copy
import hashlib
import io
import os
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import MagicMock, patch
import yaml

from rs9.tf_pypi_archive import AdmissionError, canonical, fail, sha256
from rs9.tf_pypi_backend import build_pair
from rs9.tf_pypi_closure import DEPENDENCIES
from rs9.tf_pypi_model import PRODUCTS, load_pin
from rs9.tf_pypi_publish import (
    DEFAULT_TARGET,
    approval_path,
    build,
    dependency_url,
    fetch_dependency,
    load_approval,
    main,
    parser,
    readback,
    select_missing,
    verify_approved,
    workflow_text,
)
from rs9.tf_pypi_verify import verify_pair
from tests.tf_pypi_fixtures import ROOT, fixture

ALLOWED_ACTIONS = {
    "actions/setup-python@ece7cb06caefa5fff74198d8649806c4678c61a1",
    "actions/setup-node@249970729cb0ef3589644e2896645e5dc5ba9c38",
    "actions/checkout@fbc6f3992d24b796d5a048ff273f7fcc4a7b6c09",
    "actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02",
    "actions/download-artifact@d3f86a106a0bac45b974a628896c90dbdf5c8093",
    "pypa/gh-action-pypi-publish@ed0c53931b1dc9bd32cbe73a98c7f6766f8a527e",
}


class StaticContractTests(unittest.TestCase):
    def test_backend_and_publish_helpers_are_stdlib_only(self):
        path = ROOT / "src/rs9/tf_pypi_publish.py"
        tree = ast.parse(path.read_text(), feature_version=(3, 12))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for item in node.names:
                    self.assertIn(item.name.split(".")[0], sys.stdlib_module_names)
            elif isinstance(node, ast.ImportFrom) and not node.level:
                if node.module.startswith("rs9."):
                    helper = node.module.split(".")[1] + ".py"
                    self.assertTrue((ROOT / "src/rs9" / helper).is_file())
                else:
                    self.assertIn(node.module.split(".")[0], sys.stdlib_module_names)

    def test_workflow_source_parses_for_python312_and_does_not_use_tar_extraction_defaults(self):
        for path in (ROOT / "src/rs9").glob("tf_pypi_*.py"):
            with self.subTest(module=path.name):
                tree = ast.parse(path.read_text(), feature_version=(3, 12))
                for node in ast.walk(tree):
                    if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
                        self.assertNotIn(node.func.attr, ("extract", "extractall"))

    def test_no_unmaterialized_workflows_or_apgr_mutations(self):
        from rs9.tf_pypi_nebular import workflow_text as nebular_workflow_text
        workflows = ROOT / ".github/workflows"
        for product in PRODUCTS:
            pin = load_pin(product)
            self.assertEqual((workflows / pin["workflow"]).exists(), pin["source_status"] == "READY")
        self.assertEqual((workflows / "rs9-tfnf-pypi-publish.yml").read_text(), nebular_workflow_text())
        apgr = workflows / "rs9-pypi-publish.yml"
        self.assertEqual(
            hashlib.sha256(apgr.read_bytes()).hexdigest(),
            "d248edcab45a912f76ca04289d46a4fdd8de91f53d86780a6f2539a667004e3a",
        )

    def test_cli_has_no_direct_upload_publish_or_dispatch_command(self):
        for operation in ("publish", "upload", "dispatch", "pin", "deploy", "setup-node", "npm"):
            with patch("sys.stderr", io.StringIO()), self.assertRaises(SystemExit):
                parser().parse_args([operation])

    def test_dependencies_list_matches_agreed_schema(self):
        self.assertEqual(len(DEPENDENCIES), 3)
        for dep in DEPENDENCIES:
            self.assertEqual(set(dep.keys()), {"name", "version", "asset", "size", "sha256", "license"})
            self.assertTrue(dep["asset"].endswith(".tgz"))
            self.assertEqual(len(dep["sha256"]), 64)
            self.assertEqual(dependency_url(dep), f"https://registry.npmjs.org/{dep['name']}/-/{dep['asset']}")
        self.assertEqual(
            dependency_url(DEPENDENCIES[0]),
            "https://registry.npmjs.org/@xmldom/xmldom/-/xmldom-0.9.12.tgz",
        )

    def test_deterministic_cross_target_builder_default(self):
        self.assertEqual(DEFAULT_TARGET, "darwin-arm64")

    def test_module_import_and_cli_no_local_path_leak(self):
        for product in PRODUCTS:
            result = subprocess.run(
                [sys.executable, "-B", "-m", "rs9.tf_pypi_publish", "workflow", "--project", product],
                cwd=ROOT,
                env={**os.environ, "PYTHONPATH": str(ROOT / "src")},
                capture_output=True,
                timeout=10,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertNotIn(str(ROOT).encode(), result.stdout + result.stderr)


class WorkflowGeneratorTests(unittest.TestCase):
    def test_workflow_text_structure_for_all_products(self):
        for product in sorted(PRODUCTS):
            pin = load_pin(product)
            text = workflow_text(pin)
            if pin["source_status"] == "READY":
                self.assertEqual((ROOT / ".github/workflows" / pin["workflow"]).read_text(), text)
            doc = yaml.safe_load(text)

            self.assertEqual(doc["name"], f"RS9 {product} PyPI Publish")
            self.assertIn("${{ inputs.mode }}", doc["run-name"])
            self.assertIn("${{ inputs.dispatch_id }}", doc["run-name"])

            # Branch qualification plus explicit main publication
            on_trigger = doc.get("on") or doc.get(True)
            self.assertIsNotNone(on_trigger)
            self.assertEqual(set(on_trigger.keys()), {"workflow_dispatch", "push"})
            self.assertEqual(on_trigger["push"], {"branches": ["rs9-tf-pypi-hostqual1"]})
            inputs = on_trigger["workflow_dispatch"]["inputs"]
            self.assertEqual(set(inputs.keys()), {"mode", "dispatch_id"})
            self.assertEqual(inputs["mode"]["type"], "choice")
            self.assertEqual(inputs["mode"]["options"], ["qualify", "publish"])
            self.assertEqual(inputs["mode"]["default"], "qualify")

            # top-level permissions
            self.assertEqual(doc["permissions"], {"contents": "read"})

            # per-product concurrency
            concurrency_group = pin["workflow"][:-4]
            self.assertEqual(doc["concurrency"]["group"], concurrency_group + "-${{ github.ref }}")
            self.assertFalse(doc["concurrency"]["cancel-in-progress"])

            # Native same-artifact consumer is mandatory before publishing
            self.assertEqual(set(doc["jobs"].keys()), {"build_verify", "native_consumer", "publish"})

            bv = doc["jobs"]["build_verify"]
            self.assertEqual(bv["if"], "github.ref == 'refs/heads/main' || github.ref == 'refs/heads/rs9-tf-pypi-hostqual1'")
            self.assertEqual(bv["runs-on"], "ubuntu-24.04")
            self.assertEqual(bv["timeout-minutes"], 15)

            # verify checkout step in build_verify
            bv_checkout = bv["steps"][0]
            self.assertEqual(bv_checkout["uses"], "actions/checkout@fbc6f3992d24b796d5a048ff273f7fcc4a7b6c09")
            self.assertEqual(bv_checkout["with"]["ref"], "${{ github.sha }}")
            self.assertFalse(bv_checkout["with"]["persist-credentials"])

            # verify build step in build_verify
            bv_build = bv["steps"][1]
            self.assertIn(f"--project {product}", bv_build["run"])
            self.assertIn("--target darwin-arm64", bv_build["run"])

            # verify upload artifact step in build_verify
            bv_upload = bv["steps"][2]
            self.assertEqual(bv_upload["uses"], "actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02")
            self.assertEqual(bv_upload["with"]["name"], "pypi-artifacts")
            self.assertEqual(bv_upload["with"]["path"], "dist/")

            pub = doc["jobs"]["publish"]
            self.assertEqual(pub["if"], "github.ref == 'refs/heads/main' && github.event_name == 'workflow_dispatch' && inputs.mode == 'publish'")
            self.assertEqual(pub["needs"], ["build_verify", "native_consumer"])
            self.assertEqual(pub["runs-on"], "ubuntu-24.04")
            self.assertEqual(pub["timeout-minutes"], 15)
            self.assertEqual(pub["environment"]["name"], "pypi")
            self.assertEqual(pub["environment"]["url"], f"https://pypi.org/p/{product}")
            self.assertEqual(pub["permissions"], {"id-token": "write", "contents": "read"})

            # verify checkout in publish
            pub_checkout = pub["steps"][0]
            self.assertEqual(pub_checkout["uses"], "actions/checkout@fbc6f3992d24b796d5a048ff273f7fcc4a7b6c09")
            self.assertEqual(pub_checkout["with"]["ref"], "${{ github.sha }}")
            self.assertFalse(pub_checkout["with"]["persist-credentials"])

            # verify download artifact in publish
            pub_download = pub["steps"][1]
            self.assertEqual(pub_download["uses"], "actions/download-artifact@d3f86a106a0bac45b974a628896c90dbdf5c8093")
            self.assertEqual(pub_download["with"]["name"], "pypi-artifacts")
            self.assertEqual(pub_download["with"]["path"], "dist/")

            # verify select-missing in publish
            pub_select = pub["steps"][2]
            self.assertEqual(pub_select["id"], "missing")
            self.assertIn("select-missing", pub_select["run"])
            self.assertIn(f"--project {product}", pub_select["run"])
            self.assertIn('>> "$GITHUB_OUTPUT"', pub_select["run"])

            # verify conditional upload in publish
            pub_publish = pub["steps"][3]
            self.assertEqual(pub_publish["if"], "steps.missing.outputs.upload == 'true'")
            self.assertEqual(pub_publish["uses"], "pypa/gh-action-pypi-publish@ed0c53931b1dc9bd32cbe73a98c7f6766f8a527e")
            self.assertEqual(pub_publish["with"]["packages-dir"], "upload/")

            # verify readback in publish
            pub_readback = pub["steps"][4]
            self.assertIn("readback", pub_readback["run"])
            self.assertIn(f"--project {product}", pub_readback["run"])

    def test_workflow_text_actions_use_only_apgr_shas(self):
        for product in PRODUCTS:
            doc = yaml.safe_load(workflow_text(product))
            for job in doc["jobs"].values():
                for step in job["steps"]:
                    if "uses" in step:
                        self.assertIn(step["uses"], ALLOWED_ACTIONS)

    def test_workflow_text_rejects_invalid_pin(self):
        with self.assertRaises(AdmissionError):
            workflow_text({"project": "invalid"})
        with self.assertRaises(AdmissionError):
            workflow_text("invalid-project")


class ApprovalAndVerificationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.pin, self.data = fixture("theme-forge-stellar-loom")

    def test_blocked_pin_source_status_refuses_approval(self):
        # A BLOCKED status must refuse approval even when committed pins are READY.
        for product in PRODUCTS:
            pin = load_pin(product)
            pin["source_status"] = "BLOCKED"
            with self.assertRaises(AdmissionError) as cm:
                verify_approved(pin, self.root / "dist")
            self.assertEqual(cm.exception.code, "TF_PYPI_SOURCE_NOT_READY")

    def test_missing_approval_file_refuses_approval(self):
        ready_pin = copy.deepcopy(self.pin)
        ready_pin["source_status"] = "READY"
        with patch("rs9.tf_pypi_publish.approval_path", return_value=self.root / "absent.json"), self.assertRaises(AdmissionError) as cm:
            verify_approved(ready_pin, self.root / "dist")
        self.assertEqual(cm.exception.code, "TF_PYPI_APPROVAL_ABSENT")

    def test_approval_mismatch_refuses_approval(self):
        ready_pin = copy.deepcopy(self.pin)
        ready_pin["source_status"] = "READY"
        dist = self.root / "dist"
        build_pair(ready_pin, self.data, dist, target=DEFAULT_TARGET)
        actual = verify_pair(ready_pin, dist, target=DEFAULT_TARGET)

        tampered = copy.deepcopy(actual)
        tampered["set_sha256"] = "0" * 64

        with patch("rs9.tf_pypi_publish.load_approval", return_value=tampered):
            with self.assertRaises(AdmissionError) as cm:
                verify_approved(ready_pin, dist, target=DEFAULT_TARGET)
            self.assertEqual(cm.exception.code, "TF_PYPI_APPROVAL_MISMATCH")

    def test_approval_match_succeeds(self):
        ready_pin = copy.deepcopy(self.pin)
        ready_pin["source_status"] = "READY"
        dist = self.root / "dist"
        build_pair(ready_pin, self.data, dist, target=DEFAULT_TARGET)
        actual = verify_pair(ready_pin, dist, target=DEFAULT_TARGET)

        with patch("rs9.tf_pypi_publish.load_approval", return_value=actual):
            approved = verify_approved(ready_pin, dist, target=DEFAULT_TARGET)
            self.assertEqual(approved, actual)


class SelectMissingStateTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.pin, self.data = fixture("theme-forge-stellar-loom")
        self.pin["source_status"] = "READY"
        self.dist = self.root / "dist"
        build_pair(self.pin, self.data, self.dist, target=DEFAULT_TARGET)
        self.approved = verify_pair(self.pin, self.dist, target=DEFAULT_TARGET)
        self.local = {r["filename"]: (self.dist / r["filename"]).read_bytes() for r in self.approved["files"]}
        self.url = f"https://pypi.org/pypi/{self.pin['project']}/json"
        self.version_url = f"https://pypi.org/pypi/{self.pin['project']}/{self.pin['version']}/json"

    def rows(self):
        return [
            {
                "filename": name,
                "size": len(body),
                "digests": {"sha256": sha256(body)},
                "yanked": False,
                "url": f"https://files.pythonhosted.org/{name}",
            }
            for name, body in sorted(self.local.items())
        ]

    def mock_get(self, rows=None, *, project=None, wrong_bytes=False, absent=False):
        if absent:
            def get_absent(url):
                fail("REMOTE_ABSENT")
            return get_absent

        values = {
            self.url: canonical(
                project
                if project is not None
                else {"info": {"name": self.pin["project"]}, "releases": {self.pin["version"]: []}}
            ),
            self.version_url: canonical(
                {"info": {"name": self.pin["project"], "version": self.pin["version"]}, "urls": rows or []}
            ),
        }
        for name, body in self.local.items():
            values[f"https://files.pythonhosted.org/{name}"] = b"tampered" if wrong_bytes else body

        return lambda url: values[url]

    def test_select_missing_when_remote_absent(self):
        upload = self.root / "upload"
        with patch("rs9.tf_pypi_publish.load_approval", return_value=self.approved):
            res = select_missing(self.pin, dist=self.dist, upload_dir=upload, get=self.mock_get(absent=True))
        self.assertTrue(res["upload"])
        self.assertEqual(res["state"], "absent")
        self.assertEqual(set(res["missing"]), set(self.local.keys()))
        self.assertTrue(upload.is_dir())
        self.assertEqual(
            {p.name: p.read_bytes() for p in upload.iterdir()},
            self.local,
        )

    def test_missing_extra_or_changed_artifact_refuses_before_remote_read(self):
        for mutation in ("missing", "extra", "changed"):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as directory:
                dist = Path(directory).resolve() / "dist"
                dist.mkdir()
                for name, body in self.local.items():
                    (dist / name).write_bytes(body)
                first = dist / next(iter(self.local))
                if mutation == "missing":
                    first.unlink()
                elif mutation == "extra":
                    (dist / "unexpected.txt").write_text("extra")
                else:
                    first.write_bytes(b"changed")
                upload = dist.parent / "upload"
                with patch("rs9.tf_pypi_publish.load_approval", return_value=self.approved), \
                        patch("rs9.tf_pypi_publish.exact_state") as remote:
                    with self.assertRaises(AdmissionError):
                        verify_approved(self.pin, dist)
                    with self.assertRaises(AdmissionError):
                        select_missing(self.pin, dist=dist, upload_dir=upload)
                remote.assert_not_called()
                self.assertFalse(upload.exists())

    def test_select_missing_when_remote_incomplete_subset(self):
        upload = self.root / "upload"
        rows = self.rows()
        # Remote already has the first file (e.g. sdist), but not the wheel
        existing_file = rows[0]["filename"]
        missing_file = rows[1]["filename"]
        subset_rows = [rows[0]]

        with patch("rs9.tf_pypi_publish.load_approval", return_value=self.approved):
            res = select_missing(self.pin, dist=self.dist, upload_dir=upload, get=self.mock_get(subset_rows))
        self.assertTrue(res["upload"])
        self.assertEqual(res["state"], "incomplete")
        self.assertEqual(res["missing"], [missing_file])
        self.assertTrue(upload.is_dir())
        # ONLY the missing file is copied, not the existing file
        self.assertEqual({p.name for p in upload.iterdir()}, {missing_file})
        self.assertEqual((upload / missing_file).read_bytes(), self.local[missing_file])

    def test_select_missing_when_published_exact(self):
        upload = self.root / "upload"
        with patch("rs9.tf_pypi_publish.load_approval", return_value=self.approved):
            res = select_missing(self.pin, dist=self.dist, upload_dir=upload, get=self.mock_get(self.rows()))
        self.assertFalse(res["upload"])
        self.assertEqual(res["state"], "published-exact")
        self.assertEqual(res["missing"], [])
        self.assertFalse(upload.exists())

    def test_select_missing_refuses_conflict_state(self):
        upload = self.root / "upload"
        with patch("rs9.tf_pypi_publish.load_approval", return_value=self.approved):
            with self.assertRaises(AdmissionError) as cm:
                select_missing(
                    self.pin,
                    dist=self.dist,
                    upload_dir=upload,
                    get=self.mock_get(self.rows(), wrong_bytes=True),
                )
            self.assertEqual(cm.exception.code, "TF_PYPI_REMOTE_CONFLICT")
        self.assertFalse(upload.exists())

    def test_select_missing_refuses_unknown_state(self):
        upload = self.root / "upload"
        with patch("rs9.tf_pypi_publish.load_approval", return_value=self.approved):
            with self.assertRaises(AdmissionError) as cm:
                select_missing(self.pin, dist=self.dist, upload_dir=upload, get=lambda _: fail("REMOTE_UNKNOWN"))
            self.assertEqual(cm.exception.code, "TF_PYPI_REMOTE_UNKNOWN")
        self.assertFalse(upload.exists())

    def test_select_missing_refuses_initially_non_empty_upload_dir(self):
        upload = self.root / "upload"
        upload.mkdir()
        (upload / "leftover.txt").write_bytes(b"taint")
        with patch("rs9.tf_pypi_publish.load_approval", return_value=self.approved):
            with self.assertRaises(AdmissionError) as cm:
                select_missing(self.pin, dist=self.dist, upload_dir=upload, get=self.mock_get(absent=True))
            self.assertEqual(cm.exception.code, "TF_PYPI_UPLOAD_DIR")

    def test_select_missing_refuses_symlink_upload_dir(self):
        target = self.root / "real_upload"
        target.mkdir()
        upload = self.root / "symlink_upload"
        upload.symlink_to(target)
        with patch("rs9.tf_pypi_publish.load_approval", return_value=self.approved):
            with self.assertRaises(AdmissionError) as cm:
                select_missing(self.pin, dist=self.dist, upload_dir=upload, get=self.mock_get(absent=True))
            self.assertEqual(cm.exception.code, "TF_PYPI_UPLOAD_DIR")


class ReadbackStateTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.pin, self.data = fixture("theme-forge-stellar-loom")
        self.pin["source_status"] = "READY"
        self.dist = self.root / "dist"
        build_pair(self.pin, self.data, self.dist, target=DEFAULT_TARGET)
        self.approved = verify_pair(self.pin, self.dist, target=DEFAULT_TARGET)
        self.local = {r["filename"]: (self.dist / r["filename"]).read_bytes() for r in self.approved["files"]}
        self.url = f"https://pypi.org/pypi/{self.pin['project']}/json"
        self.version_url = f"https://pypi.org/pypi/{self.pin['project']}/{self.pin['version']}/json"

    def rows(self):
        return [
            {
                "filename": name,
                "size": len(body),
                "digests": {"sha256": sha256(body)},
                "yanked": False,
                "url": f"https://files.pythonhosted.org/{name}",
            }
            for name, body in sorted(self.local.items())
        ]

    def mock_get(self, rows=None, *, project=None, wrong_bytes=False, absent=False):
        if absent:
            def get_absent(url):
                fail("REMOTE_ABSENT")
            return get_absent

        values = {
            self.url: canonical(
                project
                if project is not None
                else {"info": {"name": self.pin["project"]}, "releases": {self.pin["version"]: []}}
            ),
            self.version_url: canonical(
                {"info": {"name": self.pin["project"], "version": self.pin["version"]}, "urls": rows or []}
            ),
        }
        for name, body in self.local.items():
            values[f"https://files.pythonhosted.org/{name}"] = b"tampered" if wrong_bytes else body

        return lambda url: values[url]

    def test_readback_succeeds_when_published_exact(self):
        with patch("rs9.tf_pypi_publish.load_approval", return_value=self.approved):
            res = readback(self.pin, dist=self.dist, get=self.mock_get(self.rows()))
            self.assertEqual(res["state"], "published-exact")

    def test_readback_fails_when_incomplete(self):
        with patch("rs9.tf_pypi_publish.load_approval", return_value=self.approved):
            with self.assertRaises(AdmissionError) as cm:
                readback(self.pin, dist=self.dist, get=self.mock_get(self.rows()[:1]))
            self.assertEqual(cm.exception.code, "TF_PYPI_READBACK_INCOMPLETE")

    def test_readback_fails_when_absent(self):
        with patch("rs9.tf_pypi_publish.load_approval", return_value=self.approved):
            with self.assertRaises(AdmissionError) as cm:
                readback(self.pin, dist=self.dist, get=self.mock_get(absent=True))
            self.assertEqual(cm.exception.code, "TF_PYPI_READBACK_ABSENT")

    def test_readback_fails_when_conflict(self):
        with patch("rs9.tf_pypi_publish.load_approval", return_value=self.approved):
            with self.assertRaises(AdmissionError) as cm:
                readback(self.pin, dist=self.dist, get=self.mock_get(self.rows(), wrong_bytes=True))
            self.assertEqual(cm.exception.code, "TF_PYPI_READBACK_CONFLICT")

    def test_readback_fails_when_unknown(self):
        with patch("rs9.tf_pypi_publish.load_approval", return_value=self.approved):
            with self.assertRaises(AdmissionError) as cm:
                readback(self.pin, dist=self.dist, get=lambda _: fail("REMOTE_UNKNOWN"))
            self.assertEqual(cm.exception.code, "TF_PYPI_READBACK_UNKNOWN")


class BuildCommandTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.pin, self.data = fixture("theme-forge-stellar-loom")

    def test_build_with_inputs_offline(self):
        inputs = self.root / "inputs"
        inputs.mkdir()
        (inputs / self.pin["asset"]).write_bytes(self.data)
        out = self.root / "dist"

        self.pin["source_status"] = "READY"
        control = self.root / "control"
        build_pair(self.pin, self.data, control, target=DEFAULT_TARGET)
        approved = verify_pair(self.pin, control, target=DEFAULT_TARGET)
        with patch("socket.socket", side_effect=AssertionError("network attempted")), \
                patch("rs9.tf_pypi_publish.load_approval", return_value=approved):
            res = build(self.pin, output=out, inputs=inputs, target=DEFAULT_TARGET)

        self.assertFalse(res["publication_admitted"])
        self.assertEqual(res["project"], self.pin["project"])
        self.assertEqual(len(res["files"]), 2)
        wheel = [f for f in res["files"] if f["filename"].endswith(".whl")][0]
        self.assertIn("macosx_11_0_arm64", wheel["filename"])

    def test_build_rejects_unsupported_target(self):
        inputs = self.root / "inputs"
        inputs.mkdir()
        (inputs / self.pin["asset"]).write_bytes(self.data)
        out = self.root / "dist"

        with self.assertRaises(AdmissionError) as cm:
            build(self.pin, output=out, inputs=inputs, target="linux-unsupported")
        self.assertEqual(cm.exception.code, "TF_PYPI_UNSUPPORTED_PLATFORM")

    def test_fetch_dependency_validates_url(self):
        dep = copy.deepcopy(DEPENDENCIES[0])
        dep["name"] = "../unsafe"
        with self.assertRaises(AdmissionError) as cm:
            fetch_dependency(dep)
        self.assertEqual(cm.exception.code, "TF_PYPI_DEPENDENCY_URL")


class CLIMainTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.pin, self.data = fixture("theme-forge-stellar-loom")
        self.pin["source_status"] = "READY"
        self.dist = self.root / "dist"
        build_pair(self.pin, self.data, self.dist, target=DEFAULT_TARGET)
        self.approved = verify_pair(self.pin, self.dist, target=DEFAULT_TARGET)

    def test_cli_workflow_prints_yaml(self):
        buf = io.StringIO()
        with patch("sys.stdout", buf):
            code = main(["workflow", "--project", "theme-forge-stellar-loom"])
        self.assertEqual(code, 0)
        self.assertIn("name: RS9 theme-forge-stellar-loom PyPI Publish", buf.getvalue())

    def test_cli_select_missing_outputs_github_output_format(self):
        upload = self.root / "upload"
        buf = io.StringIO()
        with patch("rs9.tf_pypi_publish.load_pin", return_value=self.pin), \
             patch("rs9.tf_pypi_publish.load_approval", return_value=self.approved), \
             patch("sys.stdout", buf):
            code = main(
                ["select-missing", "--project", "theme-forge-stellar-loom",
                 "--dist", str(self.dist), "--upload-dir", str(upload)],
                get=lambda _: fail("REMOTE_ABSENT"),
            )
        self.assertEqual(code, 0)
        self.assertEqual(buf.getvalue(), "upload=true\nstate=absent\n")

    def test_cli_readback_exact_returns_zero(self):
        local = {r["filename"]: (self.dist / r["filename"]).read_bytes() for r in self.approved["files"]}
        url = f"https://pypi.org/pypi/{self.pin['project']}/json"
        version_url = f"https://pypi.org/pypi/{self.pin['project']}/{self.pin['version']}/json"
        rows = [
            {
                "filename": name,
                "size": len(body),
                "digests": {"sha256": sha256(body)},
                "yanked": False,
                "url": f"https://files.pythonhosted.org/{name}",
            }
            for name, body in sorted(local.items())
        ]
        values = {
            url: canonical({"info": {"name": self.pin["project"]}, "releases": {self.pin["version"]: []}}),
            version_url: canonical({"info": {"name": self.pin["project"], "version": self.pin["version"]}, "urls": rows}),
        }
        for name, body in local.items():
            values[f"https://files.pythonhosted.org/{name}"] = body

        buf = io.StringIO()
        with patch("rs9.tf_pypi_publish.load_pin", return_value=self.pin), \
             patch("rs9.tf_pypi_publish.load_approval", return_value=self.approved), \
             patch("sys.stdout", buf):
            code = main(
                ["readback", "--project", "theme-forge-stellar-loom", "--dist", str(self.dist)],
                get=lambda u: values[u],
            )
        self.assertEqual(code, 0)
        self.assertEqual(buf.getvalue(), "state=published-exact\n")

    def test_cli_readback_conflict_returns_nonzero(self):
        err = io.StringIO()
        with patch("rs9.tf_pypi_publish.load_pin", return_value=self.pin), \
             patch("rs9.tf_pypi_publish.load_approval", return_value=self.approved), \
             patch("sys.stderr", err):
            code = main(
                ["readback", "--project", "theme-forge-stellar-loom", "--dist", str(self.dist)],
                get=lambda _: fail("REMOTE_UNKNOWN"),
            )
        self.assertEqual(code, 1)
        self.assertIn("TF_PYPI_READBACK_UNKNOWN", err.getvalue())


if __name__ == "__main__":
    unittest.main()
