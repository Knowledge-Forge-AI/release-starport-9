"""Prepare-only policy boundaries; no native builds, Git mutation or network."""
import copy
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from rs9.current_generation import (CURRENT_GENERATION, HISTORICAL_GENERATION, DISTRIBUTION_JOBS,
    DISTRIBUTION_SCOPE, distribution_paths, configuration_paths, configuration_identity, rpm_policy_path)
from rs9.errors import ContractError
from tests.test_current_rpm_preservation_policy import blocked_policy
from rs9.hosted_contract import load_hosted_lanes, generate_matrix_outputs, REQUIRED_RECEIPTS
from rs9.hosted_custody import builder_identity, provenance, source_tree_identity, verify_set
from rs9.hosted_pipeline import _inputs, main, run_lane
from rs9.hosted_summary import contract, required, gate_blockers, summarize, validate_summary_binding, validate_summary, validate_rpm_policy_source
from rs9.collect_candidate import _run_identity, collect, packet_classification, WORKFLOW

ROOT = Path(__file__).resolve().parents[1]
COMMIT = "1" * 40
TREE = "2" * 40


class CurrentDistributionQualificationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        env = patch.dict(os.environ, {"GITHUB_SHA": COMMIT, "GITHUB_REF": "refs/heads/main",
            "GITHUB_EVENT_NAME": "push", "GITHUB_RUN_ATTEMPT": "1", "GITHUB_RUN_ID": "7",
            "GITHUB_REPOSITORY": "Knowledge-Forge-AI/release-starport-9"})
        env.start()
        self.addCleanup(env.stop)

    def admitted_context(self):
        from rs9.collect_candidate import admit_original_run
        document = {"id": 7, "head_sha": COMMIT, "event": "push", "head_branch": "main",
            "path": distribution_paths(CURRENT_GENERATION)[0], "run_attempt": 1, "status": "completed",
            "repository": {"full_name": "Knowledge-Forge-AI/release-starport-9"}, "created_at": "2026-10-29T00:00:01Z"}
        return admit_original_run(ROOT, commit=COMMIT, run_id=7, started_at=datetime(2026, 10, 29, tzinfo=timezone.utc),
            generation=CURRENT_GENERATION, runner=lambda root, argv: json.dumps(document))[1]

    def test_closed_paths_preserve_historical_constants(self):
        self.assertEqual(distribution_paths(), (".github/workflows/rs9-candidate-tests.yml", "operators/live1/hosted-lanes.json", "full-live1"))
        self.assertEqual(WORKFLOW, "rs9-candidate-tests.yml")
        self.assertIn(("wheels", "aarch64-darwin"), REQUIRED_RECEIPTS)
        self.assertEqual(hashlib.sha256((ROOT / "operators/live1/hosted-lanes.json").read_bytes()).hexdigest(), "56f972f168717ccac7b378d62db11895d1b143908c81817f3d3339c08046e13f")
        self.assertEqual(hashlib.sha256((ROOT / distribution_paths()[0]).read_bytes()).hexdigest(), "0c37ba64fbce0eec188c4c2d2c0e119d9dcf6f2b2833b450c559e341fe128f2a")
        for generation in (None, "latest", "../current", {}):
            with self.subTest(generation=generation), self.assertRaises(ContractError) as error:
                distribution_paths(generation)
            self.assertEqual(error.exception.code, "GENERATION_SELECTION")
            with self.assertRaises(ContractError) as error:
                collect("missing", "missing", commit=COMMIT, started_at=None, generation=generation)
            self.assertEqual(error.exception.code, "GENERATION_SELECTION")

    def test_current_contract_preserves_every_selected_lane_row(self):
        old = load_hosted_lanes(ROOT)
        current = load_hosted_lanes(ROOT, generation=CURRENT_GENERATION)
        self.assertEqual(current["required_jobs"], list(DISTRIBUTION_JOBS))
        selected = {"unit", "pins", "authenticate", "nix", "pacman", "rpm", "deb", "pages", "summary"}
        self.assertEqual(current["lanes"], [row for row in old["lanes"] if row["lane"] in selected])
        keys = {(row["lane"], row["system"]) for row in required(ROOT, generation=CURRENT_GENERATION)}
        self.assertEqual(keys, {("authenticate", "generation"), ("pins", "generation"), ("pages", "generation"),
            ("nix", "aarch64-darwin"), ("nix", "x86_64-linux"), ("nix", "aarch64-linux"),
            ("deb", "amd64"), ("deb", "arm64"), ("rpm", "x86_64-linux"), ("rpm", "aarch64-linux"), ("pacman", "x86_64-linux")})
        self.assertEqual(current["experiments"], [])
        matrix = generate_matrix_outputs(current)
        self.assertEqual(len(json.loads(matrix["matrix_nix"])["include"]), 3)
        self.assertEqual(len(json.loads(matrix["matrix_native"])["include"]), 5)
        self.assertEqual(json.loads(matrix["matrix_wheels"])["include"], [])

    def test_current_gate_weakening_is_rejected(self):
        for relative in (distribution_paths()[1], distribution_paths(CURRENT_GENERATION)[1]):
            target = self.root / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / relative, target)
        path = self.root / distribution_paths(CURRENT_GENERATION)[1]
        doc = json.loads(path.read_bytes())
        row = next(row for row in doc["lanes"] if row["lane"] == "rpm")
        row["required_gates"].remove("rpm-policy-custody")
        path.write_text(json.dumps(doc))
        with self.assertRaises(ContractError) as error:
            load_hosted_lanes(self.root, generation=CURRENT_GENERATION)
        self.assertEqual(error.exception.code, "LANES_POLICY")

    def test_workflow_has_exact_jobs_selectors_and_existing_guard(self):
        text = (ROOT / distribution_paths(CURRENT_GENERATION)[0]).read_text()
        jobs_text = text.split("jobs:\n", 1)[1]
        self.assertEqual(set(re.findall(r"^  ([a-z-]+):$", jobs_text, re.M)), set(DISTRIBUTION_JOBS))
        for line in text.splitlines():
            if "python3 -m rs9.hosted_pipeline " in line:
                self.assertIn("--generation " + CURRENT_GENERATION, line)
        self.assertIn("./.github/scripts/rs9-linux-userns-apparmor-guard.sh --", text)
        self.assertEqual(hashlib.sha256((ROOT / ".github/scripts/rs9-linux-userns-apparmor-guard.sh").read_bytes()).hexdigest(), "875855d2ad584ab04202e3bb30984429688750eb056a5206d9ed580215af3aea")
        self.assertIn("permissions:\n  contents: read", text)
        self.assertNotIn("id-token:", text)
        self.assertNotIn("WEBKIT_DISABLE_SANDBOX", text)

    def test_selected_inputs_change_both_configuration_and_builder_identity(self):
        for relative in configuration_paths(ROOT, generation=CURRENT_GENERATION):
            source = ROOT / relative
            if source.is_file():
                target = self.root / relative
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(source, target)
        for relative in ("operators/theme-forge-current-202610/command-contracts.json",
                         "operators/theme-forge-current-202610/nebular-callers.json",
                         "nix/theme-forge-current-202610-products.json", rpm_policy_path(CURRENT_GENERATION)):
            before = builder_identity(self.root, generation=CURRENT_GENERATION)
            config_before = configuration_identity(self.root, generation=CURRENT_GENERATION)
            target = self.root / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(target.read_bytes() + b" " if target.exists() else b"{}")
            self.assertNotEqual(config_before, configuration_identity(self.root, generation=CURRENT_GENERATION))
            self.assertNotEqual(before, builder_identity(self.root, generation=CURRENT_GENERATION))

    def test_snapshot_never_claims_git_tree_authentication(self):
        with patch("rs9.hosted_custody.subprocess.run") as run, self.assertRaises(ContractError) as error:
            source_tree_identity(self.root, COMMIT)
        self.assertEqual(error.exception.code, "HOSTED_SOURCE_TREE")
        run.assert_not_called()

    def test_provenance_binds_generation_scope_run_tree_and_configuration(self):
        with patch("rs9.hosted_custody.source_tree_identity", return_value=TREE):
            current = provenance(ROOT, "a" * 64, generation=CURRENT_GENERATION)
        self.assertEqual(current["generation"], CURRENT_GENERATION)
        self.assertEqual(current["qualification_scope"], DISTRIBUTION_SCOPE)
        self.assertEqual(current["run_id"], 7)
        self.assertEqual(current["source_tree"], TREE)
        self.assertEqual(current["configuration_sha256"], configuration_identity(ROOT, generation=CURRENT_GENERATION))
        self.assertNotEqual(current["workflow_sha256"], provenance(ROOT, "a" * 64)["workflow_sha256"])
        with patch.dict(os.environ, {"GITHUB_REPOSITORY": "other/repository"}), self.assertRaises(ContractError):
            provenance(ROOT, "a" * 64, generation=CURRENT_GENERATION)

    def test_summary_binding_refuses_each_mixed_identity(self):
        with patch("rs9.hosted_custody.source_tree_identity", return_value=TREE):
            receipt = {"schema": "rs9.hosted-candidate-summary.v1alpha2", **provenance(ROOT, "a" * 64, generation=CURRENT_GENERATION),
                       "production_enabled": False, "publication_authority": False, "adoptable": True}
            validate_summary_binding(receipt, ROOT, COMMIT, generation=CURRENT_GENERATION, run_id=7, original_run=self.admitted_context())
            for field in ("generation", "qualification_scope", "workflow_path", "configuration_sha256", "source_tree", "repository", "run_id", "attempt", "ref", "event"):
                with self.subTest(field=field), self.assertRaises(ContractError):
                    validate_summary_binding({**receipt, field: "mixed"}, ROOT, COMMIT, generation=CURRENT_GENERATION, run_id=7, original_run=self.admitted_context())
            with self.assertRaises(ContractError):
                validate_summary_binding(receipt, ROOT, COMMIT)

    def test_upstream_custody_cannot_mix_generation(self):
        (self.root / "artifact-manifest.json").write_text("{}")
        with patch("rs9.hosted_custody.source_tree_identity", return_value=TREE):
            historical = provenance(ROOT, "a" * 64)
            with patch("rs9.hosted_pipeline.verify_set", return_value={**historical, "lane": "authenticate", "system": "generation"}), self.assertRaises(ContractError) as error:
                _inputs(self.root, ROOT, COMMIT, generation=CURRENT_GENERATION)
        self.assertEqual(error.exception.code, "CUSTODY_SOURCE")

    def test_current_nix_requires_all_four_outputs_and_all_old_gates(self):
        row = next(row for row in required(ROOT, generation=CURRENT_GENERATION) if row["lane"] == "nix")
        from rs9.hosted_nix import PRODUCTS
        receipt = {"gates": [{"name": gate, "status": "pass"} for gate in row["required_gates"]],
                   "details": {"outputs": {product: {} for product in PRODUCTS}}}
        self.assertEqual(gate_blockers(row, receipt, generation=CURRENT_GENERATION), [])
        del receipt["details"]["outputs"]["theme-forge-nebular-fusion"]
        self.assertIn("missing-current-nix-products", gate_blockers(row, receipt, generation=CURRENT_GENERATION))
        receipt["gates"].pop()
        self.assertTrue(any(item.startswith("missing-or-duplicate-gate:") for item in gate_blockers(row, receipt, generation=CURRENT_GENERATION)))

    def test_current_rpm_policy_is_held_without_fallback(self):
        self.assertFalse((self.root / rpm_policy_path(CURRENT_GENERATION)).exists())
        with self.assertRaises(ContractError) as error:
            validate_rpm_policy_source(self.root, {"lane": "rpm", "details": {}}, generation=CURRENT_GENERATION)
        self.assertEqual(error.exception.code, "CURRENT_RPM_POLICY_HELD")

    def test_config_and_summary_cli_forward_explicit_generation(self):
        with patch("rs9.hosted_pipeline.generate_matrix_outputs", return_value={}) as matrix, patch("rs9.hosted_pipeline.contract", return_value={}) as selected:
            self.assertEqual(main(["config", "--repository", str(ROOT), "--generation", CURRENT_GENERATION]), 0)
        self.assertEqual(selected.call_args.kwargs["generation"], CURRENT_GENERATION)
        with patch("rs9.hosted_pipeline.summarize", return_value=2) as summary:
            self.assertEqual(main(["summary", "--repository", str(ROOT), "--generation", CURRENT_GENERATION,
                "--inputs", str(self.root), "--receipts", str(self.root / "output")]), 2)
        self.assertEqual(summary.call_args.kwargs["generation"], CURRENT_GENERATION)

    def test_collector_admits_only_selected_workflow_push_main_attempt_one(self):
        started = datetime(2026, 10, 29, tzinfo=timezone.utc)
        doc = {"head_sha": COMMIT, "event": "push", "head_branch": "main", "path": distribution_paths(CURRENT_GENERATION)[0],
               "run_attempt": 1, "repository": {"full_name": "Knowledge-Forge-AI/release-starport-9"}, "created_at": "2026-10-29T00:00:01Z"}
        _run_identity(doc, COMMIT, started, generation=CURRENT_GENERATION)
        for field, value in (("path", distribution_paths()[0]), ("event", "workflow_dispatch"), ("head_branch", "topic"), ("run_attempt", 2)):
            with self.subTest(field=field), self.assertRaises(ContractError):
                _run_identity({**doc, field: value}, COMMIT, started, generation=CURRENT_GENERATION)
        self.assertEqual(packet_classification({"generation": CURRENT_GENERATION, "validation": {"status": "pass"}}), "qualified-current-distribution-candidate")

    @patch("rs9.rpm_lint_policy.load_policy", side_effect=lambda *args, **kwargs: blocked_policy())
    def test_complete_synthetic_distribution_evidence_stays_held_for_explicit_blocked_policy(self, selected_policy):
        from tests.test_hosted_summary import HostedSummaryTests
        from rs9.scratch import canonical
        from rs9.hosted_nix import PRODUCTS
        fixture = HostedSummaryTests()
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        lanes = required(ROOT, generation=CURRENT_GENERATION)
        names = {row["artifact_name"] for row in lanes}
        for directory in fixture.inputs.iterdir():
            if directory.name not in names:
                shutil.rmtree(directory)
        jobs = {job: {"result": "success"} for job in DISTRIBUTION_JOBS if job != "summary"}
        with patch.dict(os.environ, {"RS9_JOB_CONCLUSIONS": json.dumps(jobs)}), patch("rs9.hosted_custody.source_tree_identity", return_value=TREE):
            selected = provenance(ROOT, "a" * 64, generation=CURRENT_GENERATION)
            for lane in lanes:
                directory = fixture.inputs / lane["artifact_name"]
                name = lane["lane"] + "-" + lane["system"] + ".json"
                receipt = json.loads((directory / name).read_bytes())
                receipt["provenance"] = selected
                if lane["lane"] == "nix":
                    receipt["details"] = {"outputs": {product: {} for product in PRODUCTS}}
                raw = canonical(receipt)
                (directory / name).write_bytes(raw)
                manifest_path = directory / "artifact-manifest.json"
                manifest = json.loads(manifest_path.read_bytes())
                manifest.update(selected)
                manifest["qualification_receipt_hashes"] = {name: hashlib.sha256(raw).hexdigest()}
                manifest_path.write_bytes(canonical(manifest))
            self.assertEqual(summarize(ROOT, fixture.inputs, fixture.output, generation=CURRENT_GENERATION), 2)
            summary = json.loads((fixture.output / "hosted-summary.json").read_bytes())
            self.assertEqual(summary["qualification_scope"], DISTRIBUTION_SCOPE)
            self.assertEqual(summary["qualification_verdict"], "not-qualified")
            self.assertEqual(summary["blocking_reasons"], ["candidate-rpm-aarch64-linux:CURRENT_RPM_POLICY_HELD", "candidate-rpm-x86_64-linux:CURRENT_RPM_POLICY_HELD"])
            with self.assertRaises(ContractError) as error:
                validate_summary(summary, ROOT, COMMIT, generation=CURRENT_GENERATION, run_id=7, original_run=self.admitted_context())
            self.assertEqual(error.exception.code, "CURRENT_RPM_POLICY_HELD")
            with patch.dict(os.environ, {"GITHUB_EVENT_NAME": "workflow_dispatch"}):
                self.assertEqual(summarize(ROOT, fixture.inputs, fixture.output, generation=CURRENT_GENERATION), 2)
            dispatched = json.loads((fixture.output / "hosted-summary.json").read_bytes())
            self.assertIn("current-distribution-push-main-attempt-one-required", dispatched["blocking_reasons"])

    def test_current_policy_loader_receives_explicit_generation_without_fallback(self):
        policy = self.root / rpm_policy_path(CURRENT_GENERATION)
        policy.parent.mkdir(parents=True)
        policy.write_text("{}")
        selected = {"status": "blocked", "blocking": True, "exceptions": []}
        from rs9.scratch import canonical
        receipt = {"lane": "rpm", "details": {"rpm_lint_policy": {"product": {"policy_sha256": hashlib.sha256(canonical(selected)).hexdigest()}}}}
        with patch("rs9.rpm_lint_policy.load_policy", return_value=selected) as load, self.assertRaises(ContractError) as error:
            validate_rpm_policy_source(self.root, receipt, generation=CURRENT_GENERATION)
        self.assertEqual(error.exception.code, "CURRENT_RPM_POLICY_HELD")
        self.assertEqual(load.call_args.args, (policy,))
        self.assertEqual(load.call_args.kwargs, {"generation": CURRENT_GENERATION})

    def test_source_becoming_dirty_after_execution_retains_failure(self):
        from types import SimpleNamespace
        from rs9.scratch import canonical
        for final in (ContractError("HOSTED_SOURCE_TREE", "Synthetic dirty source"), "3" * 40):
            with self.subTest(final=type(final).__name__):
                base = self.root / ("dirty" if isinstance(final, Exception) else "changed-tree")
                base.mkdir()
                work, receipts = base / "work", base / "receipts"
                work.mkdir()
                def capture(repository, output, **kwargs):
                    (output / "summary").mkdir()
                    (output / "summary/authentication.json").write_bytes(canonical({"projects": []}))
                    return []
                with patch("rs9.hosted_custody.source_tree_identity", side_effect=[TREE, final]) as identity, \
                     patch("rs9.hosted_pipeline.capture_generation", side_effect=capture) as captured, \
                     patch("rs9.hosted_pipeline.runner_facts", return_value={}), \
                     patch("rs9.hosted_pipeline.report_generation", return_value={}):
                    self.assertEqual(run_lane(ROOT, work, receipts, "authenticate", "generation", client=SimpleNamespace(receipts=[]), generation=CURRENT_GENERATION), 2)
                self.assertEqual(identity.call_count, 2)
                captured.assert_called_once()
                record = json.loads((receipts / "authenticate-generation.json").read_bytes())
                manifest = json.loads((receipts / "artifact-manifest.json").read_bytes())
                self.assertEqual(record["execution_error"], "HOSTED_SOURCE_TREE")
                self.assertIsNone(record["provenance"]["source_tree"])
                self.assertIsNone(manifest["source_tree"])
                self.assertEqual(manifest["execution_error"], "HOSTED_SOURCE_TREE")
                self.assertEqual(record["provenance"]["source_identity_error"], "HOSTED_SOURCE_TREE")
                with self.assertRaises(ContractError):
                    verify_set(receipts)
                with patch("rs9.hosted_custody.source_tree_identity", return_value=TREE), self.assertRaises(ContractError):
                    _inputs(base, ROOT, COMMIT, generation=CURRENT_GENERATION)

    def test_summary_identity_failures_preserve_not_qualified_record(self):
        for invalid_run in (False, True):
            with self.subTest(invalid_run=invalid_run):
                inputs = self.root / ("inputs-invalid" if invalid_run else "inputs-no-git")
                inputs.mkdir()
                output = inputs / "output"
                env = {"GITHUB_RUN_ID": "invalid"} if invalid_run else {}
                with patch.dict(os.environ, env):
                    self.assertEqual(summarize(ROOT, inputs, output, generation=CURRENT_GENERATION), 2)
                record = json.loads((output / "hosted-summary.json").read_bytes())
                self.assertEqual(record["qualification_verdict"], "not-qualified")
                self.assertIs(record["adoptable"], False)
                self.assertIsNone(record["source_tree"])
                self.assertIn("source-tree-unauthenticated", record["blocking_reasons"])
                self.assertIn("HOSTED_PROVENANCE" if invalid_run else "HOSTED_SOURCE_TREE", record["blocking_reasons"])
                with patch("rs9.hosted_custody.source_tree_identity", return_value=TREE), self.assertRaises(ContractError):
                    validate_summary_binding(record, ROOT, COMMIT, generation=CURRENT_GENERATION, run_id=7, original_run=self.admitted_context())

    def test_missing_runtime_coordinates_retain_failing_lane(self):
        work = self.root / "bad-run-work"
        work.mkdir()
        receipts = self.root / "bad-run-receipts"
        with patch.dict(os.environ, {"GITHUB_RUN_ID": "invalid"}), patch("rs9.hosted_pipeline.runner_facts", return_value={}):
            self.assertEqual(run_lane(ROOT, work, receipts, "authenticate", "generation", generation=CURRENT_GENERATION), 2)
        record = json.loads((receipts / "authenticate-generation.json").read_bytes())
        self.assertEqual(record["execution_error"], "HOSTED_PROVENANCE")
        self.assertIsNone(record["provenance"]["source_tree"])
        self.assertIsNone(record["provenance"]["run_id"])
        with self.assertRaises(ContractError):
            verify_set(receipts)

    def test_rpm_lane_refuses_symlink_policy_before_capture(self):
        for relative in (distribution_paths()[1], distribution_paths(CURRENT_GENERATION)[1]):
            target = self.root / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / relative, target)
        for relative in (distribution_paths()[0], distribution_paths(CURRENT_GENERATION)[0]):
            target = self.root / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / relative, target)
        target = self.root / "synthetic-policy.json"
        target.write_text("{}")
        policy = self.root / rpm_policy_path(CURRENT_GENERATION)
        policy.symlink_to(target)
        work = self.root / "rpm-work"
        work.mkdir()
        receipts = self.root / "rpm-receipts"
        with patch("rs9.hosted_custody.source_tree_identity", return_value=TREE), \
             patch("rs9.hosted_pipeline.capture_generation") as capture, \
             patch("rs9.hosted_pipeline.validate_host"), \
             patch("rs9.hosted_pipeline.runner_facts", return_value={}):
            self.assertEqual(run_lane(self.root, work, receipts, "rpm", "x86_64-linux", generation=CURRENT_GENERATION), 2)
        capture.assert_not_called()
        record = json.loads((receipts / "rpm-x86_64-linux.json").read_bytes())
        self.assertEqual(record["execution_error"], "CURRENT_RPM_POLICY_HELD")

    def test_current_collector_omits_historical_diagnostic_classes(self):
        with patch("rs9.collect_candidate.output_directory", return_value=self.root), \
             patch("rs9.collect_candidate.gh_read", side_effect=ContractError("HOSTED_RUN", "Synthetic unavailable run")):
            packet = collect(ROOT, self.root, commit=COMMIT, started_at=datetime(2026, 10, 29, tzinfo=timezone.utc), run_id=7,
                             timeout=30, generation=CURRENT_GENERATION)
        self.assertNotIn("known_unqualified_lanes", packet["diagnostic_scope"])
        self.assertEqual(packet["classification"], "current-distribution-collection-failure")
        self.assertIs(packet["diagnostic_scope"]["full_live1_qualification"], False)

    def test_source_clean_check_does_not_reject_ignored_caches(self):
        replies = [subprocess.CompletedProcess([], 0, COMMIT.encode() + b"\n", b""),
                   subprocess.CompletedProcess([], 0, TREE.encode() + b"\n", b""),
                   subprocess.CompletedProcess([], 0, b"", b"")]
        with patch("rs9.hosted_custody.Path.exists", return_value=True), patch("rs9.hosted_custody.subprocess.run", side_effect=replies) as run:
            self.assertEqual(source_tree_identity(self.root, COMMIT), TREE)
        status = run.call_args_list[-1].args[0]
        self.assertEqual(status, ["git", "status", "--porcelain", "--untracked-files=all"])
        self.assertNotIn("--ignored", status)

    def test_collector_cannot_authenticate_null_tree_diagnostic_artifact(self):
        import io
        import zipfile
        from rs9.hosted_custody import diagnostic_provenance, retain
        work, receipt_dir = self.root / "artifact-work", self.root / "artifact"
        work.mkdir()
        record = {"lane": "authenticate", "system": "generation", "runner": {}, "execution_error": "HOSTED_SOURCE_TREE",
                  "provenance": diagnostic_provenance(ROOT, None, "HOSTED_SOURCE_TREE", generation=CURRENT_GENERATION)}
        retain(work, receipt_dir, [], record)
        archive = io.BytesIO()
        with zipfile.ZipFile(archive, "w") as zipper:
            for path in receipt_dir.iterdir():
                zipper.writestr(path.name, path.read_bytes())
        data = archive.getvalue()
        def read(root, argv):
            endpoint = argv[-1]
            if "/artifacts/9/zip" in endpoint:
                return data
            if "/jobs?" in endpoint:
                return json.dumps({"total_count": 0, "jobs": []})
            if "/artifacts?" in endpoint:
                return json.dumps({"total_count": 1, "artifacts": [{"id": 9, "name": "candidate-authenticate-generation",
                    "digest": "sha256:" + hashlib.sha256(data).hexdigest(), "expired": False}]})
            return json.dumps({"id": 7, "head_sha": COMMIT, "event": "push", "head_branch": "main", "path": distribution_paths(CURRENT_GENERATION)[0],
                "run_attempt": 1, "status": "completed", "conclusion": "failure", "repository": {"full_name": "Knowledge-Forge-AI/release-starport-9"},
                "created_at": "2026-10-29T00:00:01Z"})
        output = self.root / "packet"
        output.mkdir()
        with patch("rs9.collect_candidate.output_directory", return_value=output), patch("rs9.hosted_custody.source_tree_identity", return_value=TREE):
            packet = collect(ROOT, output, commit=COMMIT, started_at=datetime(2026, 10, 29, tzinfo=timezone.utc),
                             run_id=7, timeout=30, runner=read, generation=CURRENT_GENERATION)
        self.assertEqual(packet["validation"]["status"], "fail")
        self.assertEqual(packet["artifacts"][0]["collection"], "failed")
        self.assertEqual(packet["artifacts"][0]["reason"], "HOSTED_PROVENANCE")
        self.assertNotIn("known_unqualified_lanes", packet["diagnostic_scope"])
        self.assertEqual(json.loads((output / "manager-packet.json").read_bytes()), packet)

    def test_capture_failure_with_authenticated_source_preserves_generation_report(self):
        work, receipts = self.root / "capture-work", self.root / "capture-receipts"
        work.mkdir()
        with patch("rs9.hosted_custody.source_tree_identity", return_value=TREE), \
             patch("rs9.hosted_pipeline.capture_generation", side_effect=ContractError("FETCH_FAILED", "Synthetic capture failure")) as capture, \
             patch("rs9.hosted_pipeline.report_generation", return_value={}) as report, \
             patch("rs9.hosted_pipeline.runner_facts", return_value={}):
            self.assertEqual(run_lane(ROOT, work, receipts, "authenticate", "generation", client=object(), generation=CURRENT_GENERATION), 2)
        self.assertEqual(capture.call_args.kwargs["generation"], CURRENT_GENERATION)
        self.assertEqual(report.call_args.kwargs["generation"], CURRENT_GENERATION)
        record = json.loads((receipts / "authenticate-generation.json").read_bytes())
        self.assertEqual(record["execution_error"], "FETCH_FAILED")
        self.assertEqual(record["provenance"]["source_tree"], TREE)
