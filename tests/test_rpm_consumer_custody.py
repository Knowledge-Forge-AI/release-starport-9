"""Consumer raw custody verification, current marker contracts, and adversarial tests."""
import copy
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch


from rs9.build_rpm import build_rpm_candidate
from rs9.collect_candidate import diagnostic_scope
from rs9.errors import ContractError
from rs9.hosted_custody import retain, verify_set, diagnostic_bytes, provenance
from rs9.hosted_foundation3 import execute as execute_foundation3
from rs9.hosted_summary import (
    validate_rpm_policy_custody,
    validate_rpm_custody,
    validate_rpm_policy_source,
    validate_summary,
    rpm_lint_results,
    RPM_POLICY_PROMOTION_BLOCKER,
)
from rs9.records import canonical, snapshot
from rs9.release_core import digest
from rs9.rpm_evidence import (
    CURRENT_RPM_EVIDENCE_CONTRACT,
    is_current_rpm_evidence_contract,
    durable_lint_projection,
    validate_durable_lint,
    write_policy_evidence,
    verify_policy_custody,
    verify_raw_custody,
    verify_rpm_custody,
)
from tests import test_build_rpm as build_helpers
from tests.test_build_native import create_cli_fixture


ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "tests/fixtures/run10/rpm"


from rs9.build_native import CommandReceipt
from tests.rpm_fixtures import fixture_policy


class RpmConsumerCustodyTests(unittest.TestCase):
    def setUp(self):
        env = patch.dict("os.environ", {
            "GITHUB_SHA": "0" * 40,
            "GITHUB_REF": "refs/heads/main",
            "GITHUB_EVENT_NAME": "push",
            "GITHUB_RUN_ATTEMPT": "1",
        })
        env.start()
        self.addCleanup(env.stop)

    def fixture(self, product="theme-forge-stellar-burst"):
        helper = build_helpers.BuildRpmTests()
        helper.setUp()
        self.addCleanup(helper.doCleanups)
        if product.endswith("burst"):
            capture, intent, npm = helper._make_burst_fixture("durable")
            arch = "x86_64"
        else:
            capture, intent, npm = create_cli_fixture(helper.root / "input", product=product)
            arch = "noarch"
        runner = helper._setup_runner(arch=arch, name=product, version=intent["version"])
        original = runner.handlers["rpm"]
        requires = (["rpmlib(CompressedFileNames) <= 3.0.4-1"] * 2500 + ["nodejs >= 22"])
        receipts = []
        def query(argv, **kwargs):
            if "--requires" in argv:
                return CommandReceipt(argv, 0, ("\n".join(requires) + "\n").encode(), b"", executed=True)
            return original(argv, **kwargs)
        runner.handlers["rpm"] = query
        raw = ((product + ".spec: W: no-%check-section\n" + product + "." + arch + ": W: no-documentation\n")
               + "".join(product + "." + arch + ": W: fixture-warning detail " + "x" * 64 + "\n" for _ in range(900))
               + product + "." + arch + ": E: env-script-interpreter /usr/lib/" + product + "/bin/run.js /usr/bin/env node\n"
               + "1 packages and 1 specfiles checked; 1 errors, 902 warnings, 0 filtered.\n").encode()
        def lint(argv, **kwargs):
            receipt = CommandReceipt(argv, 0 if "--version" in argv else 64,
                                     b"2.8.0\n" if "--version" in argv else raw, b"", executed=True)
            if "--version" not in argv:
                receipts.append(receipt)
            return receipt
        runner.handlers["rpmlint"] = lint
        def policy(*args, **kwargs):
            value = fixture_policy(helper.root)
            launcher = "tfsb" if product.endswith("burst") else "tfsl" if product.endswith("loom") else "tfss"
            value["projects"][product]["exceptions"] = {"env-script-interpreter": {
                "/usr/lib/" + product + "/bin/run.js": {"launcher": "/usr/bin/" + launcher}}}
            return value
        return helper, capture, intent, npm, arch, runner, policy, receipts

    def _build_accepted_pipeline(self, helper, capture, intent, npm, arch, runner, policy, product):
        with patch("rs9.rpm_lint_policy.load_policy", side_effect=policy):
            result = build_rpm_candidate(
                capture, intent, arch, helper.scratch,
                offline_npm_archives=npm, runner=runner, builder_system="x86_64-linux"
            )
        raw = result["manifest"]["rpmlint"]
        derivation = result["derivation_record"]
        manifest_obj = result["manifest"]
        policy_eval = result["policy_evaluation"]

        manifest_path = helper.scratch / "build" / product / "rpm-manifest.json"
        manifest_path.parent.mkdir(parents=True, exist_ok=True)
        manifest_path.write_bytes((helper.scratch / "rpm-manifest.json").read_bytes())
        summary, policy_files = write_policy_evidence(helper.scratch, policy_eval)
        raw_path = helper.scratch / "diagnostics" / ("rpmlint-" + product + ".json")
        raw_path.parent.mkdir(parents=True, exist_ok=True)
        raw_path.write_bytes(canonical(raw))

        pkg_path = helper.scratch / "unsigned" / Path(manifest_obj["package_file"]).name
        pkg_path.parent.mkdir(exist_ok=True)
        pkg_path.write_bytes((helper.scratch / manifest_obj["package_file"]).read_bytes())

        record = {
            "schema": "rs9.hosted-candidate-diagnostic.v1alpha2",
            "lane": "rpm",
            "system": "x86_64-linux",
            "runner": {},
            "provenance": provenance(ROOT, "0" * 40),
            "production_enabled": False,
            "publication_authority": False,
            "execution_error": None,
            "policy_blockers": [],
            "production_promotion_blockers": [RPM_POLICY_PROMOTION_BLOCKER],
            "gates": [
                {"name": "rpm-lint-policy-accepted", "status": "pass"},
                {"name": "rpm-client-qualification", "status": "pass"},
            ],
            "details": {
                "rpm_evidence_contract": CURRENT_RPM_EVIDENCE_CONTRACT,
                "rpm_lint_raw": {product: raw},
                "rpm_lint_policy": {product: summary},
            },
        }

        retained = helper.root / "custody"
        retained_manifest = retain(
            helper.scratch, retained,
            [manifest_path, raw_path, pkg_path, *policy_files],
            record
        )
        return {
            "retained": retained,
            "manifest": retained_manifest,
            "record": record,
            "raw": raw,
            "derivation": derivation,
            "manifest_obj": manifest_obj,
            "summary": summary,
            "policy_files": policy_files,
            "policy_eval": policy_eval,
            "product": product,
        }

    def test_accepted_policy_pipeline_to_all_consumers(self):
        """Full pipeline: accepted policy -> derivation -> manifest -> retain -> verify_set -> all consumers."""
        product = "theme-forge-stellar-burst"
        helper, capture, intent, npm, arch, runner, policy, _ = self.fixture(product)
        pipeline = self._build_accepted_pipeline(helper, capture, intent, npm, arch, runner, policy, product)

        retained = pipeline["retained"]
        manifest = pipeline["manifest"]
        record = pipeline["record"]
        raw = pipeline["raw"]
        derivation = pipeline["derivation"]
        manifest_obj = pipeline["manifest_obj"]
        summary = pipeline["summary"]
        policy_eval = pipeline["policy_eval"]

        # 1. Manifest verification
        self.assertEqual(verify_set(retained), manifest)

        # 2. Consumer: verify_raw_custody returns matching derivation projection
        projection = verify_raw_custody(
            retained, manifest, raw,
            product=product, receipt=record, derivation=derivation, rpm_manifest=manifest_obj
        )
        self.assertEqual(projection, derivation["evidence"]["rpmlint"])
        validate_durable_lint(projection, raw)

        # 3. Consumer: verify_policy_custody returns original evaluation
        assembled = verify_policy_custody(retained, manifest, summary)
        self.assertEqual(assembled, policy_eval)

        # 4. Consumer: validate_rpm_policy_custody and validate_rpm_custody succeed
        res = validate_rpm_custody(retained, manifest, record)
        self.assertIn(product, res)
        self.assertEqual(res[product], projection)
        validate_rpm_policy_custody(retained, manifest, record)

        # 5. Consumer: validate_rpm_policy_source succeeds
        with patch("rs9.rpm_lint_policy.load_policy", side_effect=policy):
            validate_rpm_policy_source(ROOT, record)

        # 6. Consumer: Collector diagnostic_scope accepts lane
        lanes = [{
            "lane": "rpm",
            "system": "x86_64-linux",
            "module": "rs9.hosted_packaging",
            "artifact_name": "candidate-rpm-x86_64-linux",
            "required_gates": ["rpm-lint-policy-accepted", "rpm-client-qualification"],
        }]
        packet_dir = helper.root / "packet"
        packet_dir.mkdir(parents=True, exist_ok=True)
        lane_packet_dir = packet_dir / "candidate-rpm-x86_64-linux"
        retain(helper.scratch, lane_packet_dir, [
            helper.scratch / "build" / product / "rpm-manifest.json",
            helper.scratch / "diagnostics" / ("rpmlint-" + product + ".json"),
            helper.scratch / "unsigned" / Path(manifest_obj["package_file"]).name,
            *pipeline["policy_files"],
        ], record)
        packet = {
            "source_commit": "0" * 40,
            "artifacts": [{"name": "candidate-rpm-x86_64-linux", "collection": "verified"}],
            "jobs": [{"name": "rpm-x86_64-linux", "status": "completed", "conclusion": "success", "steps": []}],
        }
        scope = diagnostic_scope(ROOT, packet_dir, packet, {"lanes": lanes})
        for lane_res in scope["required_lanes"]:
            self.assertEqual(lane_res["integrity"], "verified")
            for reason in lane_res.get("reasons", []):
                self.assertNotIn("rpm-policy-custody-invalid", reason)

        # 7. Consumer: Foundation3 execute succeeds without custody_error
        f3_scratch = helper.root / "f3_scratch"
        f3_scratch.mkdir()
        from rs9.profiles import evaluate_profile, PACKAGE_PROFILE
        profile = evaluate_profile(capture, PACKAGE_PROFILE, intent)
        context = {
            "inputs": str(helper.root),
            "scratch": f3_scratch,
            "captures": [(capture, intent, profile)],
        }
        f3_res = execute_foundation3(context)
        self.assertNotIn("custody_error", f3_res["details"])
        for missing_item in f3_res["details"]["missing_inputs"]:
            self.assertNotIn("rpm-custody-invalid", missing_item)

        # 8. Consumer: Pages (hosted_deb.execute_pages) processes without custody-invalid
        from rs9.hosted_deb import execute_pages
        pages_scratch = helper.root / "pages_scratch"
        pages_scratch.mkdir()
        pages_context = {
            "repository": ROOT,
            "inputs": packet_dir,
            "scratch": pages_scratch,
            "system": "generation",
            "family": "pages",
            "authentication_sha256": "0" * 64,
            "captures": [(capture, intent, profile)],
        }
        pages_res = execute_pages(pages_context)
        self.assertNotIn("custody_error", pages_res["details"])
        for gate in pages_res["gates"]:
            if gate.get("reason"):
                self.assertNotIn("custody-invalid", gate["reason"])

    def test_mandatory_chunk_summaries_for_current_marker_rejects_inline_bypass(self):
        """Current marker 'rs9.rpm-evidence-contract.v2' forbids inline bypass (requires chunk summaries)."""
        product = "theme-forge-stellar-burst"
        helper, capture, intent, npm, arch, runner, policy, _ = self.fixture(product)
        pipeline = self._build_accepted_pipeline(helper, capture, intent, npm, arch, runner, policy, product)

        retained = pipeline["retained"]
        manifest = pipeline["manifest"]
        record = copy.deepcopy(pipeline["record"])
        # Replace chunk summary with raw unchunked evaluation (inline bypass attempt)
        record["details"]["rpm_lint_policy"][product] = pipeline["policy_eval"]

        with self.assertRaises(ContractError) as caught:
            validate_rpm_policy_custody(retained, manifest, record)
        self.assertEqual(caught.exception.code, "RPM_POLICY_CUSTODY")
        self.assertIn("inline bypass not permitted", str(caught.exception))

    def test_missing_raw_architecture_cannot_satisfy_consumer_system_binding(self):
        product = "theme-forge-stellar-burst"
        helper, capture, intent, npm, arch, runner, policy, _ = self.fixture(product)
        pipeline = self._build_accepted_pipeline(helper, capture, intent, npm, arch, runner, policy, product)
        raw = copy.deepcopy(pipeline['raw'])
        raw['architecture'] = None
        record = copy.deepcopy(pipeline['record'])
        record['details']['rpm_lint_raw'][product] = raw
        manifest = copy.deepcopy(pipeline['manifest'])
        row = next(r for r in manifest['files'] if r['path'].endswith('/rpmlint-' + product + '.json'))
        data = canonical(raw)
        (pipeline['retained'] / row['path']).write_bytes(data)
        row.update(sha256=digest(data), size=len(data))
        with self.assertRaises(ContractError) as caught:
            verify_raw_custody(pipeline['retained'], manifest, raw, product=product, receipt=record)
        self.assertEqual(caught.exception.code, 'RPM_RAW_EVIDENCE_SYSTEM')

    def test_past_64kib_chunk_boundaries_rejected(self):
        """Chunk summaries and individual chunk files must not exceed 64 KiB."""
        product = "theme-forge-stellar-burst"
        helper, capture, intent, npm, arch, runner, policy, _ = self.fixture(product)
        pipeline = self._build_accepted_pipeline(helper, capture, intent, npm, arch, runner, policy, product)

        retained = pipeline["retained"]
        manifest = pipeline["manifest"]
        record = pipeline["record"]

        # An oversized chunk file on disk must fail custody verification
        chunk_file = next(p for p in retained.rglob("*.part-*.json"))
        # Tamper by appending padding beyond 64 KiB
        oversized_data = chunk_file.read_bytes() + (b" " * (65 * 1024))
        chunk_file.write_bytes(oversized_data)

        with self.assertRaises(ContractError) as caught:
            validate_rpm_policy_custody(retained, manifest, record)
        self.assertEqual(caught.exception.code, "RPM_POLICY_CUSTODY")

    def test_crossproduct_wrong_lane_or_system_rejected(self):
        """Custody verification strictly rejects product, lane, and system mismatches."""
        product = "theme-forge-stellar-burst"
        helper, capture, intent, npm, arch, runner, policy, _ = self.fixture(product)
        pipeline = self._build_accepted_pipeline(helper, capture, intent, npm, arch, runner, policy, product)

        retained = pipeline["retained"]
        manifest = pipeline["manifest"]
        record = pipeline["record"]
        raw = pipeline["raw"]

        # Product mismatch
        with self.assertRaises(ContractError) as caught:
            verify_raw_custody(retained, manifest, raw, product="theme-forge-stellar-loom", receipt=record)
        self.assertEqual(caught.exception.code, "RPM_RAW_EVIDENCE_PRODUCT")

        # System mismatch in receipt
        rec_wrong_sys = copy.deepcopy(record)
        rec_wrong_sys["system"] = "aarch64-linux"
        with self.assertRaises(ContractError) as caught:
            verify_raw_custody(retained, manifest, raw, product=product, receipt=rec_wrong_sys)
        self.assertEqual(caught.exception.code, "RPM_RAW_EVIDENCE_SYSTEM")

        # Lane mismatch in receipt
        rec_wrong_lane = copy.deepcopy(record)
        rec_wrong_lane["lane"] = "deb"
        with self.assertRaises(ContractError) as caught:
            verify_raw_custody(retained, manifest, raw, product=product, receipt=rec_wrong_lane)
        self.assertEqual(caught.exception.code, "RPM_RAW_EVIDENCE_SOURCE")

    def test_wrong_source_and_tampered_hashes_rejected(self):
        """Tampered package, spec, or raw lint hashes trigger RPM_RAW_CUSTODY."""
        product = "theme-forge-stellar-burst"
        helper, capture, intent, npm, arch, runner, policy, _ = self.fixture(product)
        pipeline = self._build_accepted_pipeline(helper, capture, intent, npm, arch, runner, policy, product)

        retained = pipeline["retained"]
        manifest = pipeline["manifest"]
        record = pipeline["record"]
        raw = pipeline["raw"]
        derivation = pipeline["derivation"]
        manifest_obj = pipeline["manifest_obj"]

        # 1. Tampered package_sha256 in raw
        tampered_raw = copy.deepcopy(raw)
        tampered_raw["package_sha256"] = "f" * 64
        with self.assertRaises(ContractError) as caught:
            verify_raw_custody(retained, manifest, tampered_raw, product=product, receipt=record,
                               derivation=derivation, rpm_manifest=manifest_obj)
        self.assertEqual(caught.exception.code, "RPM_RAW_EVIDENCE_HASH")

        # 2. Tampered spec_sha256 in rpm_manifest
        tampered_manifest = copy.deepcopy(manifest_obj)
        tampered_manifest["spec_sha256"] = "e" * 64
        with self.assertRaises(ContractError) as caught:
            verify_raw_custody(retained, manifest, raw, product=product, receipt=record,
                               derivation=derivation, rpm_manifest=tampered_manifest)
        self.assertEqual(caught.exception.code, "RPM_RAW_EVIDENCE_HASH")

        # 3. Tampered receipt details rpm_lint_raw
        tampered_rec = copy.deepcopy(record)
        tampered_rec["details"]["rpm_lint_raw"][product]["clean"] = True
        with self.assertRaises(ContractError) as caught:
            verify_raw_custody(retained, manifest, raw, product=product, receipt=tampered_rec,
                               derivation=derivation, rpm_manifest=manifest_obj)
        self.assertEqual(caught.exception.code, "RPM_RAW_EVIDENCE_HASH")

    def test_wrong_schema_and_unknown_contract_marker_rejected(self):
        """Invalid evidence schemas or unrecognized contract markers are rejected."""
        product = "theme-forge-stellar-burst"
        helper, capture, intent, npm, arch, runner, policy, _ = self.fixture(product)
        pipeline = self._build_accepted_pipeline(helper, capture, intent, npm, arch, runner, policy, product)

        retained = pipeline["retained"]
        manifest = pipeline["manifest"]
        record = pipeline["record"]
        raw = pipeline["raw"]

        # Invalid raw schema
        bad_raw = copy.deepcopy(raw)
        bad_raw["schema"] = "rs9.rpmlint-evidence.unknown"
        with self.assertRaises(ContractError) as caught:
            verify_raw_custody(retained, manifest, bad_raw, product=product, receipt=record)
        self.assertEqual(caught.exception.code, "RPM_RAW_EVIDENCE_SCHEMA")

        # Unknown contract marker
        bad_marker_rec = copy.deepcopy(record)
        bad_marker_rec["details"]["rpm_evidence_contract"] = "rs9.rpm-evidence-contract.v999"
        with self.assertRaises(ContractError) as caught:
            validate_rpm_policy_custody(retained, manifest, bad_marker_rec)
        self.assertEqual(caught.exception.code, "RPM_POLICY_CUSTODY")

    def test_unselected_and_surplus_files_rejected(self):
        """Unselected files or surplus raw lint files on disk or in manifest are rejected."""
        product = "theme-forge-stellar-burst"
        helper, capture, intent, npm, arch, runner, policy, _ = self.fixture(product)
        pipeline = self._build_accepted_pipeline(helper, capture, intent, npm, arch, runner, policy, product)

        retained = pipeline["retained"]
        manifest = pipeline["manifest"]
        record = pipeline["record"]
        raw = pipeline["raw"]

        # 1. Surplus file on disk
        surplus_file = retained / "objects/diagnostics" / f"rpmlint-{product}.extra.json"
        surplus_file.write_bytes(b"{}")
        with self.assertRaises(ContractError) as caught:
            verify_raw_custody(retained, manifest, raw, product=product, receipt=record)
        self.assertEqual(caught.exception.code, "RPM_RAW_EVIDENCE_UNSELECTED")
        surplus_file.unlink()

        # 2. Surplus file in manifest
        bad_manifest = copy.deepcopy(manifest)
        bad_manifest["files"].append({
            "path": f"objects/diagnostics/rpmlint-{product}.extra.json",
            "sha256": "0" * 64,
            "size": 2,
        })
        with self.assertRaises(ContractError) as caught:
            verify_raw_custody(retained, bad_manifest, raw, product=product, receipt=record)
        self.assertEqual(caught.exception.code, "RPM_RAW_EVIDENCE_UNSELECTED")

    def test_altered_projection_rejected(self):
        """Altered projection in derivation record triggers RPM_EVIDENCE_PROJECTION."""
        product = "theme-forge-stellar-burst"
        helper, capture, intent, npm, arch, runner, policy, _ = self.fixture(product)
        pipeline = self._build_accepted_pipeline(helper, capture, intent, npm, arch, runner, policy, product)

        retained = pipeline["retained"]
        manifest = pipeline["manifest"]
        record = pipeline["record"]
        raw = pipeline["raw"]
        derivation = copy.deepcopy(pipeline["derivation"])
        manifest_obj = pipeline["manifest_obj"]

        # Flip clean bit in derivation projection
        derivation["evidence"]["rpmlint"]["clean"] = True
        with self.assertRaises(ContractError) as caught:
            verify_raw_custody(retained, manifest, raw, product=product, receipt=record,
                               derivation=derivation, rpm_manifest=manifest_obj)
        self.assertEqual(caught.exception.code, "RPM_EVIDENCE_PROJECTION")

        # Tamper raw_evidence object in derivation
        derivation2 = copy.deepcopy(pipeline["derivation"])
        derivation2["evidence"]["rpmlint"]["raw_evidence"]["object"] = "diagnostics/tampered.json"
        with self.assertRaises(ContractError) as caught:
            verify_raw_custody(retained, manifest, raw, product=product, receipt=record,
                               derivation=derivation2, rpm_manifest=manifest_obj)
        self.assertEqual(caught.exception.code, "RPM_EVIDENCE_PROJECTION")

    def test_marker_free_historical_handling(self):
        """Historical marker-free receipts cannot acquire qualification and require explicit false authority."""
        product = "theme-forge-stellar-burst"
        helper, capture, intent, npm, arch, runner, policy, _ = self.fixture(product)
        pipeline = self._build_accepted_pipeline(helper, capture, intent, npm, arch, runner, policy, product)

        retained = pipeline["retained"]
        manifest = pipeline["manifest"]
        record = copy.deepcopy(pipeline["record"])
        del record["details"]["rpm_evidence_contract"]

        self.assertFalse(is_current_rpm_evidence_contract(record))
        summary_record = copy.deepcopy(record)
        summary_record["provenance"] = {"source_commit": "0" * 40}
        mock_summary = {
            "source_commit": "0" * 40,
            "release_record_sha256": "0" * 40,
            "receipts": [summary_record],
            "artifact_manifests": [{"lane": "rpm", "system": "x86_64-linux"}],
        }
        with patch("rs9.hosted_summary.validate_summary_binding", return_value=mock_summary), \
             patch("rs9.hosted_summary.required", return_value=[{"lane": "rpm", "system": "x86_64-linux"}]), \
             patch("rs9.hosted_summary.provenance", return_value={"source_commit": "0" * 40}), \
             patch("rs9.hosted_summary.gate_blockers", return_value=[]):
            with self.assertRaises(ContractError) as caught:
                validate_summary({"receipts": [summary_record]}, ROOT, "0" * 40)
            self.assertEqual(caught.exception.code, "HOSTED_NOT_QUALIFIED")

        # Historical receipt with production_enabled=True is rejected by custody
        bad_auth = copy.deepcopy(record)
        bad_auth["production_enabled"] = True
        with self.assertRaises(ContractError) as caught:
            validate_rpm_policy_custody(retained, manifest, bad_auth)
        self.assertEqual(caught.exception.code, "RPM_POLICY_CUSTODY")

        # Historical receipt with publication_authority=True is rejected by custody
        bad_pub = copy.deepcopy(record)
        bad_pub["publication_authority"] = True
        with self.assertRaises(ContractError) as caught:
            validate_rpm_policy_custody(retained, manifest, bad_pub)
        self.assertEqual(caught.exception.code, "RPM_POLICY_CUSTODY")

    def test_diagnostic_failure_retention_across_consumers(self):
        """Specific custody failure code is preserved across Collector, Foundation3, and Pages."""
        product = "theme-forge-stellar-burst"
        helper, capture, intent, npm, arch, runner, policy, _ = self.fixture(product)
        pipeline = self._build_accepted_pipeline(helper, capture, intent, npm, arch, runner, policy, product)

        retained = pipeline["retained"]
        manifest = pipeline["manifest"]
        record = copy.deepcopy(pipeline["record"])

        # Intentionally tamper raw lint in details before retain to cause RPM_RAW_CUSTODY failure
        record["details"]["rpm_lint_raw"][product]["clean"] = True

        # 1. Collector diagnostic_scope
        lanes = [{
            "lane": "rpm",
            "system": "x86_64-linux",
            "module": "rs9.hosted_packaging",
            "artifact_name": "candidate-rpm-x86_64-linux",
            "required_gates": ["rpm-lint-policy-accepted", "rpm-client-qualification"],
        }]
        packet_dir = helper.root / "packet2"
        packet_dir.mkdir(parents=True, exist_ok=True)
        lane_packet_dir = packet_dir / "candidate-rpm-x86_64-linux"
        raw_path = helper.scratch / "diagnostics" / ("rpmlint-" + product + ".json")
        pkg_path = helper.scratch / "unsigned" / Path(pipeline["manifest_obj"]["package_file"]).name
        manifest_path = helper.scratch / "build" / product / "rpm-manifest.json"
        manifest_path.parent.mkdir(parents=True, exist_ok=True)
        manifest_path.write_bytes((helper.scratch / "rpm-manifest.json").read_bytes())
        retain(
            helper.scratch, lane_packet_dir,
            [manifest_path, raw_path, pkg_path, *pipeline["policy_files"]],
            record
        )
        packet = {
            "source_commit": "0" * 40,
            "artifacts": [{"name": "candidate-rpm-x86_64-linux", "collection": "verified"}],
            "jobs": [{"name": "rpm-x86_64-linux", "status": "completed", "conclusion": "success", "steps": []}],
        }
        scope = diagnostic_scope(ROOT, packet_dir, packet, {"lanes": lanes})
        reasons = scope["required_lanes"][0]["reasons"]
        self.assertIn("rpm-policy-custody-invalid:RPM_RAW_EVIDENCE_HASH", reasons)

        # 2. Foundation3 execute preserves custody_error
        f3_scratch = helper.root / "f3_scratch2"
        f3_scratch.mkdir()
        from rs9.profiles import evaluate_profile, PACKAGE_PROFILE
        profile = evaluate_profile(capture, PACKAGE_PROFILE, intent)
        context = {
            "inputs": str(packet_dir),
            "scratch": f3_scratch,
            "captures": [(capture, intent, profile)],
        }
        f3_res = execute_foundation3(context)
        self.assertEqual(f3_res["details"]["custody_error"], "RPM_RAW_EVIDENCE_HASH")
        self.assertIn("rpm-custody-invalid:RPM_RAW_EVIDENCE_HASH", f3_res["details"]["missing_inputs"])

        # 3. Pages (_gather_custody block in hosted_deb)
        from rs9.hosted_deb import execute_pages
        pages_scratch = helper.root / "pages_scratch"
        pages_scratch.mkdir()
        pages_context = {
            "repository": ROOT,
            "inputs": packet_dir,
            "scratch": pages_scratch,
            "system": "generation",
            "family": "pages",
            "authentication_sha256": "0" * 64,
            "captures": [(capture, intent, profile)],
        }
        pages_res = execute_pages(pages_context)
        self.assertEqual(pages_res["details"]["custody_error"], "RPM_RAW_EVIDENCE_HASH")
        failed_gates = [g for g in pages_res["gates"] if "custody-invalid:RPM_RAW_EVIDENCE_HASH" in g.get("reason", "")]
        self.assertTrue(len(failed_gates) > 0)
