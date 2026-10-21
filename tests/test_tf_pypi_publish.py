"""Tests for the source-owned future publication contract."""
import ast
import copy
import hashlib
import io
import json
import os
from pathlib import Path
import shlex
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
import yaml

from rs9.tf_pypi_archive import AdmissionError, canonical, fail, physical_bytes, sha256
from rs9.tf_pypi_closure import DEPENDENCIES
from rs9 import tf_pypi_hosted as h
from rs9.tf_pypi_hosted import TARGET_SYSTEMS
from rs9.tf_pypi_model import PRODUCTS, TARGETS, load_pin, strict_json
from rs9.tf_pypi_publish import (
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
from rs9.tf_pypi_verify import host_view, verify_aggregate, verify_pair
from tests.tf_pypi_fixtures import ROOT, aggregate, fixture, qualified

ALLOWED_ACTIONS = {
    "actions/setup-python@ece7cb06caefa5fff74198d8649806c4678c61a1",
    "actions/setup-node@249970729cb0ef3589644e2896645e5dc5ba9c38",
    "actions/checkout@fbc6f3992d24b796d5a048ff273f7fcc4a7b6c09",
    "actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02",
    "actions/download-artifact@d3f86a106a0bac45b974a628896c90dbdf5c8093",
    "pypa/gh-action-pypi-publish@ed0c53931b1dc9bd32cbe73a98c7f6766f8a527e",
}
COMMIT = "a" * 40
RUN_ID = "12345"
COMMITTED_POST1_APPROVALS = {
    "theme-forge-solar-sail": {
        "file_sha256": "e7d6b00e1f55652ef7aafe1117fcf3d5a4ad479585935a8de06fcee4f22046f4",
        "file_size": 1662,
        "set_sha256": "c50b64cb0251df129a8075155ee47b845490c14c82a12ed67165969dbe5adddf",
        "filenames": [
            "theme_forge_solar_sail-0.2.1.post1-py3-none-macosx_11_0_arm64.whl",
            "theme_forge_solar_sail-0.2.1.post1-py3-none-manylinux_2_28_aarch64.whl",
            "theme_forge_solar_sail-0.2.1.post1-py3-none-manylinux_2_28_x86_64.whl",
            "theme_forge_solar_sail-0.2.1.post1.tar.gz",
        ],
    },
    "theme-forge-stellar-burst": {
        "file_sha256": "414dbee9423c193992106b661f43effe235a6c0ba1f7a01efdc57234748faff9",
        "file_size": 1681,
        "set_sha256": "816c5c230c4b413aa5f8d4dd41a0d02fcf755a1d4fb28d27d8bdef29c44a97c0",
        "filenames": [
            "theme_forge_stellar_burst-0.6.1.post1-py3-none-macosx_13_0_arm64.whl",
            "theme_forge_stellar_burst-0.6.1.post1-py3-none-manylinux_2_33_aarch64.whl",
            "theme_forge_stellar_burst-0.6.1.post1-py3-none-manylinux_2_33_x86_64.whl",
            "theme_forge_stellar_burst-0.6.1.post1.tar.gz",
        ],
    },
    "theme-forge-stellar-loom": {
        "file_sha256": "a52d332b1257d48a73ebc8b9c552d82cc032fd3777f9dbd21137b104dfe596e4",
        "file_size": 1675,
        "set_sha256": "05e1f8dc651e813f2f78d3b8cdc1effb6dea52a6a12d80d6e5b9649b247b52d0",
        "filenames": [
            "theme_forge_stellar_loom-0.4.0.post1-py3-none-macosx_11_0_arm64.whl",
            "theme_forge_stellar_loom-0.4.0.post1-py3-none-manylinux_2_28_aarch64.whl",
            "theme_forge_stellar_loom-0.4.0.post1-py3-none-manylinux_2_28_x86_64.whl",
            "theme_forge_stellar_loom-0.4.0.post1.tar.gz",
        ],
    },
}


def _write_matrix_receipts(pin, dist_dir, aggregate_manifest, receipts_dir, *, commit=COMMIT, run_id=RUN_ID, run_attempt="1"):
    receipts_dir = Path(receipts_dir)
    receipts_dir.mkdir(parents=True, exist_ok=True)
    sdist_record = next(row for row in aggregate_manifest["files"] if row["target"] is None)
    for idx, target in enumerate(TARGETS):
        wheel_record = next(row for row in aggregate_manifest["files"] if row["target"] == target)
        view_dir = receipts_dir.parent / f"_view_{idx}_{target}"
        pair = host_view(pin, dist_dir, target, view_dir)
        consumer = {
            "project": pin["project"],
            "target": target,
            "system": TARGET_SYSTEMS[target],
            "set_sha256": pair["set_sha256"],
            "functional": True,
            "offline_isolation": {"network_disabled": True},
            "publication_admitted": False,
            "lifecycle": [
                {"kind": "wheel", "install_exit": 0, "probes": [{"command": "tfsl"}]},
                {"kind": "sdist", "install_exit": 0, "probes": [{"command": "tfsl"}]},
            ],
        }
        rec = {
            "schema": "rs9.tf-pypi-hosted-consumer.v2",
            "status": "native-consumer-passed",
            "project": pin["project"],
            "version": pin["distribution_version"],
            "upstream_version": pin["version"],
            "target": target,
            "commit": commit,
            "run_id": run_id,
            "run_attempt": run_attempt,
            "wheel": wheel_record,
            "sdist": sdist_record,
            "artifacts": pair["files"],
            "set_sha256": pair["set_sha256"],
            "aggregate_set_sha256": aggregate_manifest["set_sha256"],
            "consumer": consumer,
            "network_mechanism": "linux-unshare-net" if target.startswith("linux") else "macOS-seatbelt-deny-network",
            "qualification_scope": f"native-{target}",
            "public_writes": 0,
            "publication_admitted": False,
        }
        target_dir = receipts_dir / target
        target_dir.mkdir(parents=True, exist_ok=True)
        (target_dir / "result.json").write_bytes(canonical(rec))


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

    def test_versioned_approval_path_and_committed_false_post1_records(self):
        for product in sorted(PRODUCTS):
            pin = load_pin(product)
            expected = COMMITTED_POST1_APPROVALS[product]
            path = approval_path(pin)
            self.assertEqual(path.name, f"{product}-{pin['distribution_version']}-artifacts.json")
            self.assertNotEqual(path.name, f"{product}-artifacts.json")
            self.assertTrue(path.is_file())

            raw = physical_bytes(path)
            self.assertEqual(len(raw), expected["file_size"])
            self.assertEqual(sha256(raw), expected["file_sha256"])

            record = load_approval(pin)
            self.assertEqual(record, strict_json(raw))
            self.assertEqual(
                set(record.keys()),
                {"files", "project", "publication_admitted", "schema", "set_sha256", "targets", "upstream_version", "version"},
            )
            self.assertEqual(record["schema"], "rs9.tf-pypi-candidate-aggregate.v1")
            self.assertEqual(record["project"], product)
            self.assertEqual(record["version"], pin["distribution_version"])
            self.assertEqual(record["upstream_version"], pin["version"])
            self.assertEqual(record["targets"], pin["candidate_platforms"])
            self.assertEqual(record["targets"], list(TARGETS))
            self.assertIs(record["publication_admitted"], True)

            files = record["files"]
            self.assertEqual(len(files), 4)
            self.assertEqual([f["filename"] for f in files], sorted(f["filename"] for f in files))
            self.assertEqual([f["filename"] for f in files], expected["filenames"])
            self.assertEqual([f["target"] for f in files], [*pin["candidate_platforms"], None])
            self.assertTrue(files[-1]["filename"].endswith(".tar.gz"))
            for item in files:
                self.assertEqual(set(item.keys()), {"filename", "logical_sha256", "sha256", "size", "target"})
                self.assertIs(type(item["size"]), int)
                self.assertGreater(item["size"], 0)
                self.assertRegex(item["sha256"], r"^[0-9a-f]{64}$")
                self.assertRegex(item["logical_sha256"], r"^[0-9a-f]{64}$")

            self.assertEqual(record["set_sha256"], sha256(canonical(files)))
            self.assertEqual(record["set_sha256"], expected["set_sha256"])
            self.assertEqual(
                raw.decode("utf-8"),
                json.dumps(record, indent=2, sort_keys=True, ensure_ascii=False) + "\n",
            )

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
        expected_jobs = {
            "build_verify",
            "native_darwin_arm64",
            "native_linux_arm64",
            "native_linux_x64",
            "qualification_gate",
            "publish",
        }
        for product in sorted(PRODUCTS):
            pin = load_pin(product)
            text = workflow_text(pin)
            doc = yaml.safe_load(text)

            self.assertEqual(doc["name"], f"RS9 {product} PyPI Publish")
            self.assertIn("${{ inputs.mode }}", doc["run-name"])
            self.assertIn("${{ inputs.dispatch_id }}", doc["run-name"])

            on_trigger = doc.get("on") or doc.get(True)
            self.assertIsNotNone(on_trigger)
            self.assertEqual(set(on_trigger.keys()), {"workflow_dispatch", "push"})
            self.assertEqual(on_trigger["push"], {"branches": ["rs9-tf-pypi-hostqual1"]})
            inputs = on_trigger["workflow_dispatch"]["inputs"]
            self.assertEqual(set(inputs.keys()), {"mode", "dispatch_id"})
            self.assertEqual(inputs["mode"]["type"], "choice")
            self.assertEqual(inputs["mode"]["options"], ["qualify", "publish"])
            self.assertEqual(inputs["mode"]["default"], "qualify")

            self.assertEqual(doc["permissions"], {"contents": "read"})

            concurrency_group = pin["workflow"][:-4]
            self.assertEqual(doc["concurrency"]["group"], concurrency_group + "-${{ github.ref }}")
            self.assertFalse(doc["concurrency"]["cancel-in-progress"])

            self.assertEqual(set(doc["jobs"].keys()), expected_jobs)

            bv = doc["jobs"]["build_verify"]
            self.assertEqual(bv["if"], "github.ref == 'refs/heads/main' || github.ref == 'refs/heads/rs9-tf-pypi-hostqual1'")
            self.assertEqual(bv["runs-on"], "ubuntu-24.04")
            self.assertEqual(bv["timeout-minutes"], 15)
            bv_build = bv["steps"][1]
            self.assertIn(f"rs9.tf_pypi_publish build --project {product} --output dist", bv_build["run"])
            self.assertNotIn("--target", bv_build["run"])

            native_specs = (
                ("native_darwin_arm64", "macos-15", "darwin-arm64", True),
                ("native_linux_arm64", "ubuntu-24.04-arm", "linux-arm64-gnu", False),
                ("native_linux_x64", "ubuntu-24.04", "linux-x64-gnu", False),
            )
            for job_id, runner, target, uses_sandbox in native_specs:
                job = doc["jobs"][job_id]
                self.assertEqual(job["runs-on"], runner)
                self.assertEqual(job["needs"], ["build_verify"])
                self.assertEqual(job["permissions"], {"contents": "read"})
                self.assertNotIn("environment", job)
                run_step = job["steps"][4]
                self.assertIn(f"--project {product}", run_step["run"])
                self.assertIn(f"--target {target}", run_step["run"])
                self.assertIn('--run-id "$QUALIFY_RUN_ID"', run_step["run"])
                self.assertIn('--run-attempt "$QUALIFY_RUN_ATTEMPT"', run_step["run"])
                if uses_sandbox:
                    self.assertIn("/usr/bin/sandbox-exec", run_step["run"])
                upload_step = job["steps"][5]
                self.assertEqual(upload_step["if"], "always()")
                self.assertEqual(upload_step["with"]["name"], f"native-consumer-{product}-{target}")
                self.assertEqual(upload_step["with"]["if-no-files-found"], "error")

            gate = doc["jobs"]["qualification_gate"]
            self.assertEqual(gate["runs-on"], "ubuntu-24.04")
            self.assertEqual(
                gate["needs"],
                ["build_verify", "native_darwin_arm64", "native_linux_arm64", "native_linux_x64"],
            )
            self.assertNotIn("environment", gate)
            self.assertEqual(gate["permissions"], {"contents": "read"})
            self.assertIn("rs9.tf_pypi_hosted admit", gate["steps"][-1]["run"])

            pub = doc["jobs"]["publish"]
            self.assertEqual(pub["if"], "github.ref == 'refs/heads/main' && github.event_name == 'workflow_dispatch' && inputs.mode == 'publish'")
            self.assertEqual(
                pub["needs"],
                ["build_verify", "native_darwin_arm64", "native_linux_arm64", "native_linux_x64", "qualification_gate"],
            )
            self.assertEqual(pub["runs-on"], "ubuntu-24.04")
            self.assertEqual(pub["timeout-minutes"], 15)
            self.assertEqual(pub["environment"]["name"], "pypi")
            self.assertEqual(pub["environment"]["url"], f"https://pypi.org/p/{product}")
            self.assertEqual(pub["permissions"], {"id-token": "write", "contents": "read"})

            pub_select = [s for s in pub["steps"] if s.get("id") == "missing"][0]
            self.assertIn("select-missing", pub_select["run"])
            self.assertIn(f"--project {product}", pub_select["run"])
            self.assertIn("--receipts receipts", pub_select["run"])
            self.assertIn('--expected-commit "$QUALIFY_COMMIT"', pub_select["run"])
            self.assertIn('--run-id "$QUALIFY_RUN_ID"', pub_select["run"])
            self.assertIn('--run-attempt "$QUALIFY_RUN_ATTEMPT"', pub_select["run"])
            self.assertIn('>> "$GITHUB_OUTPUT"', pub_select["run"])

            pub_publish = [s for s in pub["steps"] if s.get("uses", "").startswith("pypa/gh-action-pypi-publish@")][0]
            self.assertEqual(pub_publish["if"], "steps.missing.outputs.upload == 'true'")
            self.assertEqual(pub_publish["with"]["packages-dir"], "upload/")

            pub_readback = pub["steps"][-1]
            self.assertIn("readback", pub_readback["run"])
            self.assertIn(f"--project {product}", pub_readback["run"])

    def test_workflow_text_actions_use_only_apgr_shas(self):
        for product in PRODUCTS:
            doc = yaml.safe_load(workflow_text(product))
            for name, job in doc["jobs"].items():
                if name != "publish":
                    for step in job["steps"]:
                        self.assertFalse(step.get("uses", "").startswith("pypa/gh-action-pypi-publish@"))
                for step in job["steps"]:
                    if "uses" in step:
                        self.assertIn(step["uses"], ALLOWED_ACTIONS)

    def test_workflow_text_rejects_invalid_pin(self):
        with self.assertRaises(AdmissionError):
            workflow_text({"project": "invalid"})
        with self.assertRaises(AdmissionError):
            workflow_text("invalid-project")

    def _extract_module_invocations(self, doc):
        invocations = []
        for job_id, job in doc["jobs"].items():
            for step in job["steps"]:
                run_text = step.get("run")
                if not run_text:
                    continue
                joined = run_text.replace("\\\n", " ")
                for line in joined.splitlines():
                    for module in ("rs9.tf_pypi_publish", "rs9.tf_pypi_hosted"):
                        if f"-m {module}" in line:
                            tokens = shlex.split(line)
                            if ">>" in tokens:
                                tokens = tokens[:tokens.index(">>")]
                            idx = tokens.index(module)
                            invocations.append((job_id, module, tokens[idx + 1:]))
        return invocations

    def test_registered_and_generated_commands_parse_with_current_clis(self):
        workflows = ROOT / ".github/workflows"
        for product in sorted(PRODUCTS):
            pin = load_pin(product)
            sources = (
                ("registered", (workflows / pin["workflow"]).read_text(encoding="utf-8")),
                ("generated", workflow_text(pin)),
            )
            for label, text in sources:
                with self.subTest(product=product, source=label):
                    doc = yaml.safe_load(text)
                    invocations = self._extract_module_invocations(doc)
                    publish_ops = []
                    hosted_qualify_targets = []
                    hosted_admit_calls = []

                    for job_id, module, argv in invocations:
                        self.assertIn("--project", argv)
                        if module == "rs9.tf_pypi_publish":
                            self.assertNotIn("--target", argv)
                            try:
                                with patch("sys.stderr", io.StringIO()):
                                    args = parser().parse_args(argv)
                            except SystemExit as exc:
                                self.fail(f"{label} {job_id} publish CLI exited with {exc.code}: {argv!r}")
                            self.assertEqual(args.project, product)
                            publish_ops.append(args.operation)
                            if args.operation == "build":
                                self.assertEqual(args.output, Path("dist"))
                            elif args.operation == "select-missing":
                                self.assertEqual(args.dist, Path("dist"))
                                self.assertEqual(args.upload_dir, Path("upload"))
                                self.assertEqual(args.receipts, Path("receipts"))
                                self.assertEqual(args.expected_commit, "$QUALIFY_COMMIT")
                                self.assertEqual(args.run_id, "$QUALIFY_RUN_ID")
                                self.assertEqual(args.run_attempt, "$QUALIFY_RUN_ATTEMPT")
                            elif args.operation == "readback":
                                self.assertEqual(args.dist, Path("dist"))
                        else:
                            out_stream = io.TextIOWrapper(io.BytesIO(), encoding="utf-8")
                            err_stream = io.StringIO()
                            with patch.object(h, "qualify", return_value={"status": "native-consumer-passed"}) as q_mock, \
                                    patch.object(h, "admit_matrix", return_value={"status": "native-matrix-passed"}) as a_mock, \
                                    patch.object(h, "write_report") as w_mock, \
                                    patch("sys.stdout", out_stream), \
                                    patch("sys.stderr", err_stream):
                                try:
                                    rc = h.main(argv)
                                except SystemExit as exc:
                                    self.fail(f"{label} {job_id} hosted CLI exited with {exc.code}: {argv!r}")
                            self.assertEqual(rc, 0, err_stream.getvalue())
                            if argv[0] == "qualify":
                                q_mock.assert_called_once()
                                w_mock.assert_called_once()
                                c_args, c_kwargs = q_mock.call_args
                                self.assertEqual(
                                    c_args,
                                    (
                                        product,
                                        "$GITHUB_WORKSPACE/dist",
                                        "$PHYSICAL_RUNNER_TEMP/tf-consumer",
                                        "$QUALIFY_COMMIT",
                                    ),
                                )
                                self.assertEqual(c_kwargs["run_id"], "$QUALIFY_RUN_ID")
                                self.assertEqual(c_kwargs["run_attempt"], "$QUALIFY_RUN_ATTEMPT")
                                hosted_qualify_targets.append(c_kwargs["target"])
                            elif argv[0] == "admit":
                                a_mock.assert_called_once_with(
                                    product,
                                    "dist",
                                    "receipts",
                                    "$QUALIFY_COMMIT",
                                    "$QUALIFY_RUN_ID",
                                    "$QUALIFY_RUN_ATTEMPT",
                                )
                                hosted_admit_calls.append(job_id)

                    self.assertEqual(publish_ops, ["build", "select-missing", "readback"])
                    self.assertEqual(hosted_qualify_targets, list(TARGETS))
                    self.assertEqual(hosted_admit_calls, ["qualification_gate"])

    def test_registered_workflows_matrix_wiring_and_oidc_boundary(self):
        workflows = ROOT / ".github/workflows"
        expected_jobs = [
            "build_verify",
            "native_darwin_arm64",
            "native_linux_arm64",
            "native_linux_x64",
            "qualification_gate",
            "publish",
        ]
        expected_qualify_env = {
            "QUALIFY_COMMIT": "${{ github.sha }}",
            "QUALIFY_RUN_ID": "${{ github.run_id }}",
            "QUALIFY_RUN_ATTEMPT": "${{ github.run_attempt }}",
        }
        native_specs = (
            ("native_darwin_arm64", "macos-15", "darwin-arm64"),
            ("native_linux_arm64", "ubuntu-24.04-arm", "linux-arm64-gnu"),
            ("native_linux_x64", "ubuntu-24.04", "linux-x64-gnu"),
        )
        for product in sorted(PRODUCTS):
            pin = load_pin(product)
            doc = yaml.safe_load((workflows / pin["workflow"]).read_text(encoding="utf-8"))
            jobs = doc["jobs"]
            self.assertEqual(list(jobs.keys()), expected_jobs)
            self.assertEqual(doc["permissions"], {"contents": "read"})

            uploaded_receipts = []
            for job_id, runner, target in native_specs:
                job = jobs[job_id]
                self.assertEqual(job["runs-on"], runner)
                self.assertEqual(job["needs"], ["build_verify"])
                self.assertEqual(job["permissions"], {"contents": "read"})
                self.assertNotIn("environment", job)
                qualify_step = job["steps"][4]
                for key, val in expected_qualify_env.items():
                    self.assertEqual(qualify_step["env"][key], val)
                upload_step = job["steps"][5]
                artifact_name = upload_step["with"]["name"]
                self.assertEqual(artifact_name, f"native-consumer-{product}-{target}")
                uploaded_receipts.append(artifact_name)
            self.assertEqual(len(set(uploaded_receipts)), 3)

            expected_receipt_downloads = [
                {"name": f"native-consumer-{product}-{t}", "path": f"receipts/{t}/"}
                for t in TARGETS
            ]
            gate = jobs["qualification_gate"]
            self.assertEqual(gate["runs-on"], "ubuntu-24.04")
            self.assertEqual(
                gate["needs"],
                ["build_verify", "native_darwin_arm64", "native_linux_arm64", "native_linux_x64"],
            )
            self.assertEqual(gate["permissions"], {"contents": "read"})
            self.assertNotIn("environment", gate)
            gate_downloads = [
                s["with"] for s in gate["steps"]
                if s.get("uses", "").startswith("actions/download-artifact@")
            ]
            self.assertEqual(
                gate_downloads,
                [{"name": "pypi-artifacts", "path": "dist/"}, *expected_receipt_downloads],
            )
            gate_admit = gate["steps"][-1]
            for key, val in expected_qualify_env.items():
                self.assertEqual(gate_admit["env"][key], val)

            pub = jobs["publish"]
            self.assertEqual(pub["runs-on"], "ubuntu-24.04")
            self.assertEqual(
                pub["needs"],
                ["build_verify", "native_darwin_arm64", "native_linux_arm64", "native_linux_x64", "qualification_gate"],
            )
            self.assertEqual(
                pub["if"],
                "github.ref == 'refs/heads/main' && github.event_name == 'workflow_dispatch' && inputs.mode == 'publish'",
            )
            self.assertEqual(pub["environment"], {"name": "pypi", "url": f"https://pypi.org/p/{product}"})
            self.assertEqual(pub["permissions"], {"id-token": "write", "contents": "read"})
            pub_downloads = [
                s["with"] for s in pub["steps"]
                if s.get("uses", "").startswith("actions/download-artifact@")
            ]
            self.assertEqual(
                pub_downloads,
                [{"name": "pypi-artifacts", "path": "dist/"}, *expected_receipt_downloads],
            )
            missing_step = [s for s in pub["steps"] if s.get("id") == "missing"][0]
            for key, val in expected_qualify_env.items():
                self.assertEqual(missing_step["env"][key], val)

            for job_id, job in jobs.items():
                if job_id != "publish":
                    self.assertNotIn("id-token", job.get("permissions", {}))
                    self.assertNotIn("environment", job)
                for step in job["steps"]:
                    if "uses" in step:
                        self.assertIn(step["uses"], ALLOWED_ACTIONS)
                    if step.get("uses", "").startswith("actions/download-artifact@"):
                        self.assertNotIn("run-id", step["with"])
                        self.assertNotIn("github-token", step["with"])


class ApprovalAndVerificationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.pin, self.data = fixture("theme-forge-stellar-loom")

    def test_blocked_pin_source_status_refuses_approval(self):
        for product in PRODUCTS:
            pin = load_pin(product)
            pin["source_status"] = "BLOCKED"
            with self.assertRaises(AdmissionError) as cm:
                verify_approved(pin, self.root / "dist")
            self.assertEqual(cm.exception.code, "TF_PYPI_SOURCE_NOT_READY")

    def test_missing_approval_file_refuses_approval(self):
        ready_pin = copy.deepcopy(self.pin)
        ready_pin["source_status"] = "READY"
        with patch("rs9.tf_pypi_publish.approval_path", return_value=self.root / "absent.json"), \
                self.assertRaises(AdmissionError) as cm:
            verify_approved(ready_pin, self.root / "dist")
        self.assertEqual(cm.exception.code, "TF_PYPI_APPROVAL_ABSENT")

    def test_unversioned_approval_is_not_a_substitute(self):
        ready_pin = copy.deepcopy(self.pin)
        ready_pin["source_status"] = "READY"
        dist = self.root / "dist"
        aggregate(ready_pin, self.data, dist)

        for product in sorted(PRODUCTS):
            pin = load_pin(product)
            legacy_path = ROOT / "operators/tf-pypi" / f"{product}-artifacts.json"
            self.assertTrue(legacy_path.is_file())
            with patch("rs9.tf_pypi_publish.approval_path", return_value=self.root / f"{product}-absent.json"), \
                    self.assertRaises(AdmissionError) as cm:
                load_approval(pin)
            self.assertEqual(cm.exception.code, "TF_PYPI_APPROVAL_ABSENT")

            legacy_record = strict_json(physical_bytes(legacy_path))
            with patch("rs9.tf_pypi_publish.load_approval", return_value=legacy_record), \
                    self.assertRaises(AdmissionError) as cm:
                verify_approved(ready_pin, dist)
            self.assertEqual(cm.exception.code, "TF_PYPI_APPROVAL_MISMATCH")

    def test_false_unqualified_candidates_still_build_and_qualify(self):
        for product in sorted(PRODUCTS):
            committed_pin = load_pin(product)
            self.assertEqual(committed_pin["qualified_platforms"], list(TARGETS))
            candidate_pin = copy.deepcopy(committed_pin)
            candidate_pin["qualified_platforms"] = []
            committed_approval = load_approval(committed_pin)
            candidate_approval = copy.deepcopy(committed_approval)
            candidate_approval["publication_admitted"] = False
            self.assertEqual({**candidate_approval, "publication_admitted": True}, committed_approval)
            # Platform veto (tf_pypi_publish.py:163) fires before approval read; loader patch is an ordering guard.
            with patch("rs9.tf_pypi_publish.exact_state", side_effect=AssertionError("remote called")) as remote, \
                    patch("rs9.tf_pypi_publish.load_approval", return_value=candidate_approval) as loader, \
                    self.assertRaises(AdmissionError) as cm:
                select_missing(
                    candidate_pin,
                    dist=self.root / "unused-dist",
                    upload_dir=self.root / "unused-upload",
                    receipts=self.root / "unused-receipts",
                    expected_commit=COMMIT,
                    run_id=RUN_ID,
                    run_attempt="1",
                )
            self.assertEqual(cm.exception.code, "TF_PYPI_PLATFORM_UNQUALIFIED")
            remote.assert_not_called()
            loader.assert_not_called()
            self.assertFalse((self.root / "unused-upload").exists())

        self.pin["qualified_platforms"] = []
        self.assertEqual(self.pin["qualified_platforms"], [])
        inputs = self.root / "inputs"
        inputs.mkdir()
        (inputs / self.pin["asset"]).write_bytes(self.data)
        dist = self.root / "dist-unqualified"

        with patch("rs9.tf_pypi_publish.approval_path", return_value=self.root / "absent-approval.json"):
            built = build(self.pin, output=dist, inputs=inputs)
            verified = verify_aggregate(self.pin, dist)
            self.assertEqual(built, verified)
            self.assertIs(built["publication_admitted"], False)

            receipts_dir = self.root / "receipts-unqualified"
            for target in TARGETS:
                work_dir = self.root / f"work-{target}"

                def fake_smoke(s_pin, view_dir, consumer_dir, *, offline_linux=False, functional=True, _target=target):
                    pair = verify_pair(s_pin, view_dir, target=_target)
                    return {
                        "project": s_pin["project"],
                        "target": _target,
                        "system": TARGET_SYSTEMS[_target],
                        "set_sha256": pair["set_sha256"],
                        "functional": True,
                        "offline_isolation": {"network_disabled": True},
                        "publication_admitted": False,
                        "lifecycle": [
                            {"kind": "wheel", "install_exit": 0, "probes": [{"command": "tfsl"}]},
                            {"kind": "sdist", "install_exit": 0, "probes": [{"command": "tfsl"}]},
                        ],
                    }

                with patch.object(h, "load_pin", return_value=self.pin), \
                        patch.object(h, "host_key", return_value=target), \
                        patch.object(h, "source_commit", return_value=COMMIT), \
                        patch.object(h, "smoke", side_effect=fake_smoke):
                    rec = h.qualify(
                        self.pin["project"], dist, work_dir, COMMIT,
                        target=target, run_id=RUN_ID, run_attempt="1",
                    )
                self.assertEqual(rec["status"], "native-consumer-passed")
                self.assertIs(rec["publication_admitted"], False)
                target_dir = receipts_dir / target
                target_dir.mkdir(parents=True, exist_ok=True)
                (target_dir / "result.json").write_bytes(canonical(rec))

            with patch.object(h, "source_commit", return_value=COMMIT):
                matrix = h.admit_matrix(self.pin, dist, receipts_dir, COMMIT, RUN_ID, "1")
            self.assertEqual(matrix["status"], "native-matrix-passed")
            self.assertIs(matrix["publication_admitted"], False)

    def test_legacy_pair_approval_and_tampered_approval_refused(self):
        ready_pin = copy.deepcopy(self.pin)
        ready_pin["source_status"] = "READY"
        dist = self.root / "dist"
        actual = aggregate(ready_pin, self.data, dist)

        legacy_approval = strict_json(
            physical_bytes(ROOT / "operators/tf-pypi/theme-forge-stellar-loom-artifacts.json")
        )
        with patch("rs9.tf_pypi_publish.load_approval", return_value=legacy_approval), \
                self.assertRaises(AdmissionError) as cm:
            verify_approved(ready_pin, dist)
        self.assertEqual(cm.exception.code, "TF_PYPI_APPROVAL_MISMATCH")

        tampered = copy.deepcopy(actual)
        tampered["set_sha256"] = "0" * 64
        with patch("rs9.tf_pypi_publish.load_approval", return_value=tampered), \
                self.assertRaises(AdmissionError) as cm:
            verify_approved(ready_pin, dist)
        self.assertEqual(cm.exception.code, "TF_PYPI_APPROVAL_MISMATCH")

    def test_approval_match_succeeds(self):
        ready_pin = copy.deepcopy(self.pin)
        ready_pin["source_status"] = "READY"
        dist = self.root / "dist"
        actual = aggregate(ready_pin, self.data, dist)

        with patch("rs9.tf_pypi_publish.load_approval", return_value=actual):
            approved = verify_approved(ready_pin, dist)
            self.assertEqual(approved, actual)


class SelectMissingStateTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        raw_pin, self.data = fixture("theme-forge-stellar-loom")
        self.pin = qualified(raw_pin)
        self.pin["source_status"] = "READY"
        self.dist = self.root / "dist"
        self.approved = aggregate(self.pin, self.data, self.dist)
        self.admitted = {**self.approved, "publication_admitted": True}
        self.receipts = self.root / "receipts"
        _write_matrix_receipts(self.pin, self.dist, self.approved, self.receipts)
        self.local = {r["filename"]: (self.dist / r["filename"]).read_bytes() for r in self.approved["files"]}
        self.dv = self.pin["distribution_version"]
        self.url = f"https://pypi.org/pypi/{self.pin['project']}/json"
        self.version_url = f"https://pypi.org/pypi/{self.pin['project']}/{self.dv}/json"

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

    def mock_get(self, rows=None, *, project=None, wrong_bytes=False, absent=False, version_absent=False):
        if absent:
            def get_absent(url):
                fail("REMOTE_ABSENT")
            return get_absent

        values = {
            self.url: canonical(
                project
                if project is not None
                else {
                    "info": {"name": self.pin["project"]},
                    "releases": (
                        {self.pin["version"]: [{}]}
                        if version_absent
                        else {self.pin["version"]: [{}], self.dv: []}
                    ),
                }
            ),
            self.version_url: canonical(
                {"info": {"name": self.pin["project"], "version": self.dv}, "urls": rows or []}
            ),
        }
        for name, body in self.local.items():
            values[f"https://files.pythonhosted.org/{name}"] = b"tampered" if wrong_bytes else body

        def reader(url):
            if version_absent and url == self.version_url:
                fail("REMOTE_ABSENT")
            return values[url]

        return reader

    def _select(
        self,
        *,
        pin=None,
        dist=None,
        upload_dir=None,
        receipts=None,
        expected_commit=COMMIT,
        run_id=RUN_ID,
        run_attempt="1",
        get=None,
        approval=None,
    ):
        chosen_approval = self.admitted if approval is None else approval
        with patch("rs9.tf_pypi_publish.load_approval", return_value=chosen_approval), \
                patch("rs9.tf_pypi_hosted.source_commit", return_value=COMMIT):
            return select_missing(
                pin or self.pin,
                dist=dist or self.dist,
                upload_dir=upload_dir or (self.root / "upload"),
                receipts=self.receipts if receipts is None else receipts,
                expected_commit=expected_commit,
                run_id=run_id,
                run_attempt=run_attempt,
                get=get,
            )

    def test_publication_admission_veto_precedes_registry_and_upload(self):
        # Old-behavior reds: False, 0, 1, and 1.0 pass verify_approved equality on the old tree
        # and must be refused by the explicit publication_admitted is True check before remote or upload.
        for idx, flag in enumerate((False, 0, 1, 1.0)):
            upload = self.root / f"upload-veto-{idx}"
            candidate = {**self.approved, "publication_admitted": flag}
            with self.subTest(flag=repr(flag)), \
                    patch("rs9.tf_pypi_publish.exact_state", side_effect=AssertionError("remote called")) as remote:
                with self.assertRaises(AdmissionError) as cm:
                    self._select(
                        approval=candidate,
                        upload_dir=upload,
                        get=self.mock_get(absent=True),
                    )
                self.assertEqual(cm.exception.code, "TF_PYPI_PUBLICATION_NOT_ADMITTED")
                remote.assert_not_called()
                self.assertFalse(upload.exists())

        # CLI variant with false approval record: exit 1, TF_PYPI_PUBLICATION_NOT_ADMITTED, no upload dir.
        cli_upload = self.root / "upload-cli-veto"
        out_buf = io.StringIO()
        err_buf = io.StringIO()
        with patch("rs9.tf_pypi_publish.load_pin", return_value=self.pin), \
                patch("rs9.tf_pypi_publish.load_approval", return_value=self.approved), \
                patch("rs9.tf_pypi_hosted.source_commit", return_value=COMMIT), \
                patch("rs9.tf_pypi_publish.exact_state", side_effect=AssertionError("remote called")) as remote, \
                patch("sys.stdout", out_buf), \
                patch("sys.stderr", err_buf):
            code = main(
                [
                    "select-missing", "--project", "theme-forge-stellar-loom",
                    "--dist", str(self.dist), "--upload-dir", str(cli_upload),
                    "--receipts", str(self.receipts), "--expected-commit", COMMIT,
                    "--run-id", RUN_ID, "--run-attempt", "1",
                ],
                get=self.mock_get(absent=True),
            )
        self.assertEqual(code, 1)
        self.assertEqual(err_buf.getvalue(), "TF_PYPI_PUBLICATION_NOT_ADMITTED\n")
        self.assertEqual(out_buf.getvalue(), "")
        remote.assert_not_called()
        self.assertFalse(cli_upload.exists())

        # Missing key, null, string, list, dict: refused by verify_approved (APPROVAL_MISMATCH)
        # and also refused by the publication_admitted is True check if verify_approved is bypassed.
        missing_key = {k: v for k, v in self.approved.items() if k != "publication_admitted"}
        non_bool_records = [
            ("missing", missing_key),
            ("null", {**self.approved, "publication_admitted": None}),
            ("str_true", {**self.approved, "publication_admitted": "true"}),
            ("str_True", {**self.approved, "publication_admitted": "True"}),
            ("str_1", {**self.approved, "publication_admitted": "1"}),
            ("list", {**self.approved, "publication_admitted": [True]}),
            ("dict", {**self.approved, "publication_admitted": {"admitted": True}}),
        ]
        for label, record in non_bool_records:
            upload = self.root / f"upload-nonbool-{label}"
            with self.subTest(label=label), \
                    patch("rs9.tf_pypi_publish.exact_state", side_effect=AssertionError("remote called")) as remote:
                with self.assertRaises(AdmissionError) as cm:
                    self._select(approval=record, upload_dir=upload, get=self.mock_get(absent=True))
                self.assertEqual(cm.exception.code, "TF_PYPI_APPROVAL_MISMATCH")

                with patch("rs9.tf_pypi_publish.verify_approved", return_value=record), \
                        patch("rs9.tf_pypi_hosted.source_commit", return_value=COMMIT), \
                        self.assertRaises(AdmissionError) as cm2:
                    select_missing(
                        self.pin,
                        dist=self.dist,
                        upload_dir=upload,
                        receipts=self.receipts,
                        expected_commit=COMMIT,
                        run_id=RUN_ID,
                        run_attempt="1",
                        get=self.mock_get(absent=True),
                    )
                self.assertEqual(cm2.exception.code, "TF_PYPI_PUBLICATION_NOT_ADMITTED")
                remote.assert_not_called()
                self.assertFalse(upload.exists())

        # Exact boolean True with all other gates valid selects only the exact missing file.
        rows = self.rows()
        missing_file = rows[-1]["filename"]
        subset_rows = rows[:-1]
        admitted_upload = self.root / "upload-admitted"
        res = self._select(
            approval=self.admitted,
            upload_dir=admitted_upload,
            get=self.mock_get(subset_rows),
        )
        self.assertTrue(res["upload"])
        self.assertEqual(res["state"], "incomplete")
        self.assertEqual(res["missing"], [missing_file])
        self.assertEqual({p.name for p in admitted_upload.iterdir()}, {missing_file})

    def test_mutated_post1_approval_records_refuse_before_remote(self):
        base = copy.deepcopy(self.admitted)

        def _flip_hex(digest):
            return ("0" if digest[0] != "0" else "1") + digest[1:]

        mutations = []

        m_no_post1 = copy.deepcopy(base)
        m_no_post1["files"][0]["filename"] = m_no_post1["files"][0]["filename"].replace(".post1", "")
        mutations.append(("filename_no_post1", m_no_post1))

        m_schema = copy.deepcopy(base)
        m_schema["schema"] = "rs9.tf-pypi-candidate-set.v1"
        mutations.append(("schema", m_schema))

        m_project = copy.deepcopy(base)
        m_project["project"] = "theme-forge-solar-sail"
        mutations.append(("project", m_project))

        m_version = copy.deepcopy(base)
        m_version["version"] = self.pin["version"]
        mutations.append(("version_upstream", m_version))

        m_upstream = copy.deepcopy(base)
        m_upstream["upstream_version"] = self.pin["distribution_version"]
        mutations.append(("upstream_post1", m_upstream))

        m_drop_target = copy.deepcopy(base)
        m_drop_target["targets"] = list(TARGETS[:-1])
        mutations.append(("dropped_target", m_drop_target))

        m_reorder_target = copy.deepcopy(base)
        m_reorder_target["targets"] = list(reversed(TARGETS))
        mutations.append(("reordered_targets", m_reorder_target))

        m_swap_wheel_target = copy.deepcopy(base)
        m_swap_wheel_target["files"][0]["target"], m_swap_wheel_target["files"][1]["target"] = (
            m_swap_wheel_target["files"][1]["target"],
            m_swap_wheel_target["files"][0]["target"],
        )
        mutations.append(("swapped_wheel_target", m_swap_wheel_target))

        m_size = copy.deepcopy(base)
        m_size["files"][0]["size"] += 1
        mutations.append(("file_size", m_size))

        m_sha = copy.deepcopy(base)
        m_sha["files"][0]["sha256"] = _flip_hex(m_sha["files"][0]["sha256"])
        mutations.append(("file_sha256", m_sha))

        m_logical = copy.deepcopy(base)
        m_logical["files"][0]["logical_sha256"] = _flip_hex(m_logical["files"][0]["logical_sha256"])
        mutations.append(("logical_sha256", m_logical))

        m_set_sha = copy.deepcopy(base)
        m_set_sha["set_sha256"] = _flip_hex(m_set_sha["set_sha256"])
        mutations.append(("set_sha256", m_set_sha))

        m_extra_rec = copy.deepcopy(base)
        extra_entry = copy.deepcopy(m_extra_rec["files"][0])
        extra_entry["filename"] = "extra-" + extra_entry["filename"]
        m_extra_rec["files"].append(extra_entry)
        mutations.append(("extra_record", m_extra_rec))

        m_missing_rec = copy.deepcopy(base)
        m_missing_rec["files"] = m_missing_rec["files"][:-1]
        mutations.append(("missing_record", m_missing_rec))

        m_dup_rec = copy.deepcopy(base)
        m_dup_rec["files"].append(copy.deepcopy(m_dup_rec["files"][0]))
        mutations.append(("duplicate_record", m_dup_rec))

        m_extra_key = copy.deepcopy(base)
        m_extra_key["extra"] = True
        mutations.append(("extra_top_key", m_extra_key))

        for name, mutated in mutations:
            upload = self.root / f"upload-mut-{name}"
            with self.subTest(mutation=name), \
                    patch("rs9.tf_pypi_publish.load_approval", return_value=mutated), \
                    patch("rs9.tf_pypi_publish.exact_state", side_effect=AssertionError("remote called")) as remote:
                with self.assertRaises(AdmissionError) as cm1:
                    verify_approved(self.pin, self.dist)
                self.assertEqual(cm1.exception.code, "TF_PYPI_APPROVAL_MISMATCH")
                with self.assertRaises(AdmissionError) as cm2:
                    self._select(approval=mutated, upload_dir=upload, get=self.mock_get(absent=True))
                self.assertEqual(cm2.exception.code, "TF_PYPI_APPROVAL_MISMATCH")
                remote.assert_not_called()
                self.assertFalse(upload.exists())

    def test_unqualified_platforms_and_invalid_matrix_refuse_before_remote_read(self):
        unqualified_pin = copy.deepcopy(self.pin)
        unqualified_pin["qualified_platforms"] = []
        with patch("rs9.tf_pypi_publish.exact_state") as remote:
            with self.assertRaises(AdmissionError) as cm:
                self._select(pin=unqualified_pin)
            self.assertEqual(cm.exception.code, "TF_PYPI_PLATFORM_UNQUALIFIED")

            with self.assertRaises(AdmissionError) as cm:
                self._select(run_attempt="2")
            self.assertEqual(cm.exception.code, "TF_PYPI_HOSTED_RUN_ATTEMPT")

            with self.assertRaises(AdmissionError) as cm:
                self._select(run_id="99999")
            self.assertEqual(cm.exception.code, "TF_PYPI_HOSTED_MATRIX_RECEIPT")

            remote.assert_not_called()

    def test_select_missing_when_remote_absent_or_version_absent(self):
        for idx, (absent, version_absent, expected_state) in enumerate((
            (True, False, "absent"),
            (False, True, "version-absent"),
        )):
            upload = self.root / f"upload-{idx}"
            res = self._select(
                upload_dir=upload,
                get=self.mock_get(absent=absent, version_absent=version_absent),
            )
            self.assertTrue(res["upload"])
            self.assertEqual(res["state"], expected_state)
            self.assertEqual(set(res["missing"]), set(self.local.keys()))
            self.assertEqual(len(res["missing"]), 4)
            self.assertEqual({p.name: p.read_bytes() for p in upload.iterdir()}, self.local)

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
                        self._select(dist=dist, upload_dir=upload)
                remote.assert_not_called()
                self.assertFalse(upload.exists())

    def test_select_missing_when_remote_incomplete_subset(self):
        upload = self.root / "upload"
        rows = self.rows()
        missing_file = rows[-1]["filename"]
        subset_rows = rows[:-1]

        res = self._select(upload_dir=upload, get=self.mock_get(subset_rows))
        self.assertTrue(res["upload"])
        self.assertEqual(res["state"], "incomplete")
        self.assertEqual(res["missing"], [missing_file])
        self.assertEqual({p.name for p in upload.iterdir()}, {missing_file})
        self.assertEqual((upload / missing_file).read_bytes(), self.local[missing_file])

    def test_select_missing_when_published_exact(self):
        upload = self.root / "upload"
        res = self._select(upload_dir=upload, get=self.mock_get(self.rows()))
        self.assertFalse(res["upload"])
        self.assertEqual(res["state"], "published-exact")
        self.assertEqual(res["missing"], [])
        self.assertFalse(upload.exists())

    def test_select_missing_refuses_conflict_and_unknown_states(self):
        upload = self.root / "upload"
        with self.assertRaises(AdmissionError) as cm:
            self._select(upload_dir=upload, get=self.mock_get(self.rows(), wrong_bytes=True))
        self.assertEqual(cm.exception.code, "TF_PYPI_REMOTE_CONFLICT")
        self.assertFalse(upload.exists())

        with self.assertRaises(AdmissionError) as cm:
            self._select(upload_dir=upload, get=lambda _: fail("REMOTE_UNKNOWN"))
        self.assertEqual(cm.exception.code, "TF_PYPI_REMOTE_UNKNOWN")
        self.assertFalse(upload.exists())

    def test_select_missing_refuses_initially_non_empty_or_symlink_upload_dir(self):
        upload = self.root / "upload"
        upload.mkdir()
        (upload / "leftover.txt").write_bytes(b"taint")
        with self.assertRaises(AdmissionError) as cm:
            self._select(upload_dir=upload, get=self.mock_get(absent=True))
        self.assertEqual(cm.exception.code, "TF_PYPI_UPLOAD_DIR")

        target = self.root / "real_upload"
        target.mkdir()
        symlink_upload = self.root / "symlink_upload"
        symlink_upload.symlink_to(target)
        with self.assertRaises(AdmissionError) as cm:
            self._select(upload_dir=symlink_upload, get=self.mock_get(absent=True))
        self.assertEqual(cm.exception.code, "TF_PYPI_UPLOAD_DIR")


class ReadbackStateTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.pin, self.data = fixture("theme-forge-stellar-loom")
        self.pin["source_status"] = "READY"
        self.dist = self.root / "dist"
        self.approved = aggregate(self.pin, self.data, self.dist)
        self.local = {r["filename"]: (self.dist / r["filename"]).read_bytes() for r in self.approved["files"]}
        self.dv = self.pin["distribution_version"]
        self.url = f"https://pypi.org/pypi/{self.pin['project']}/json"
        self.version_url = f"https://pypi.org/pypi/{self.pin['project']}/{self.dv}/json"

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

    def mock_get(self, rows=None, *, project=None, wrong_bytes=False, absent=False, version_absent=False):
        if absent:
            def get_absent(url):
                fail("REMOTE_ABSENT")
            return get_absent

        values = {
            self.url: canonical(
                project
                if project is not None
                else {
                    "info": {"name": self.pin["project"]},
                    "releases": (
                        {self.pin["version"]: [{}]}
                        if version_absent
                        else {self.pin["version"]: [{}], self.dv: []}
                    ),
                }
            ),
            self.version_url: canonical(
                {"info": {"name": self.pin["project"], "version": self.dv}, "urls": rows or []}
            ),
        }
        for name, body in self.local.items():
            values[f"https://files.pythonhosted.org/{name}"] = b"tampered" if wrong_bytes else body

        def reader(url):
            if version_absent and url == self.version_url:
                fail("REMOTE_ABSENT")
            return values[url]

        return reader

    def test_readback_states(self):
        with patch("rs9.tf_pypi_publish.load_approval", return_value=self.approved):
            res = readback(self.pin, dist=self.dist, get=self.mock_get(self.rows()))
            self.assertEqual(res["state"], "published-exact")
            self.assertEqual(res["version"], self.dv)
            self.assertEqual(res["upstream_version"], self.pin["version"])

            for kwargs, code in (
                ({"rows": self.rows()[:1]}, "TF_PYPI_READBACK_INCOMPLETE"),
                ({"absent": True}, "TF_PYPI_READBACK_ABSENT"),
                ({"version_absent": True}, "TF_PYPI_READBACK_VERSION_ABSENT"),
                ({"rows": self.rows(), "wrong_bytes": True}, "TF_PYPI_READBACK_CONFLICT"),
            ):
                with self.subTest(code=code), self.assertRaises(AdmissionError) as cm:
                    readback(self.pin, dist=self.dist, get=self.mock_get(**kwargs))
                self.assertEqual(cm.exception.code, code)

            with self.assertRaises(AdmissionError) as cm:
                readback(self.pin, dist=self.dist, get=lambda _: fail("REMOTE_UNKNOWN"))
            self.assertEqual(cm.exception.code, "TF_PYPI_READBACK_UNKNOWN")


class BuildCommandTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.pin, self.data = fixture("theme-forge-stellar-loom")

    def test_build_with_inputs_offline_produces_four_file_aggregate_without_approval(self):
        inputs = self.root / "inputs"
        inputs.mkdir()
        (inputs / self.pin["asset"]).write_bytes(self.data)
        out = self.root / "dist"

        with patch("socket.socket", side_effect=AssertionError("network attempted")):
            res = build(self.pin, output=out, inputs=inputs)

        self.assertEqual(res["schema"], "rs9.tf-pypi-candidate-aggregate.v1")
        self.assertFalse(res["publication_admitted"])
        self.assertEqual(res["project"], self.pin["project"])
        self.assertEqual(res["version"], self.pin["distribution_version"])
        self.assertEqual(res["upstream_version"], self.pin["version"])
        self.assertEqual(len(res["files"]), 4)
        wheel_names = [f["filename"] for f in res["files"] if f["filename"].endswith(".whl")]
        self.assertEqual(len(wheel_names), 3)
        self.assertTrue(any("macosx_11_0_arm64" in w for w in wheel_names))
        self.assertTrue(any("manylinux_2_28_aarch64" in w for w in wheel_names))
        self.assertTrue(any("manylinux_2_28_x86_64" in w for w in wheel_names))

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
        raw_pin, self.data = fixture("theme-forge-stellar-loom")
        self.pin = qualified(raw_pin)
        self.pin["source_status"] = "READY"
        self.dist = self.root / "dist"
        self.approved = aggregate(self.pin, self.data, self.dist)
        self.admitted = {**self.approved, "publication_admitted": True}
        self.receipts = self.root / "receipts"
        _write_matrix_receipts(self.pin, self.dist, self.approved, self.receipts)

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
             patch("rs9.tf_pypi_publish.load_approval", return_value=self.admitted), \
             patch("rs9.tf_pypi_hosted.source_commit", return_value=COMMIT), \
             patch("sys.stdout", buf):
            code = main(
                [
                    "select-missing", "--project", "theme-forge-stellar-loom",
                    "--dist", str(self.dist), "--upload-dir", str(upload),
                    "--receipts", str(self.receipts), "--expected-commit", COMMIT,
                    "--run-id", RUN_ID, "--run-attempt", "1",
                ],
                get=lambda _: fail("REMOTE_ABSENT"),
            )
        self.assertEqual(code, 0)
        self.assertEqual(buf.getvalue(), "upload=true\nstate=absent\n")

    def test_cli_readback_exact_returns_zero_and_conflict_nonzero(self):
        local = {r["filename"]: (self.dist / r["filename"]).read_bytes() for r in self.approved["files"]}
        dv = self.pin["distribution_version"]
        url = f"https://pypi.org/pypi/{self.pin['project']}/json"
        version_url = f"https://pypi.org/pypi/{self.pin['project']}/{dv}/json"
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
            url: canonical({"info": {"name": self.pin["project"]}, "releases": {dv: []}}),
            version_url: canonical({"info": {"name": self.pin["project"], "version": dv}, "urls": rows}),
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
