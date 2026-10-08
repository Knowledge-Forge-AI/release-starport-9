"""Actual accepted builder paths, full receipts and durable custody boundaries."""
import json
from pathlib import Path
import sys
import types
import unittest
from unittest.mock import patch


from rs9.build_rpm import build_rpm_candidate
from rs9.build_native import CommandReceipt
from rs9.errors import ContractError
from rs9.hosted_custody import retain, verify_set, provenance
from rs9.records import snapshot
from rs9.release_core import digest
from rs9.rpm_evidence import write_policy_evidence, verify_policy_custody, verify_raw_custody
from rs9.hosted_summary import validate_rpm_policy_custody
from rs9.scratch import canonical
from tests.rpm_fixtures import fixture_policy
from tests.test_build_native import create_cli_fixture
from tests import test_build_rpm as build_helpers


class RpmDerivationCustodyTests(unittest.TestCase):
    def fixture(self, product):
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
        self.assertGreater(len(raw), 64 * 1024)
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

    def test_three_accepted_raw_fail_shapes_complete_derivation_manifest_and_custody(self):
        for product in ("theme-forge-stellar-burst", "theme-forge-stellar-loom", "theme-forge-solar-sail"):
            with self.subTest(product=product):
                helper, capture, intent, npm, arch, runner, policy, receipts = self.fixture(product)
                # Replay the former raw embedding at the actual accepted-policy
                # boundary, using the real derivation constructor and receipts.
                former = helper.root / "former-record-boundary"; former.mkdir()
                with patch("rs9.rpm_lint_policy.load_policy", side_effect=policy), \
                     patch("rs9.rpm_evidence.durable_lint_projection", side_effect=lambda raw: raw):
                    with self.assertRaises(ContractError) as rejected:
                        build_rpm_candidate(capture, intent, arch, former,
                            offline_npm_archives=npm, runner=runner, builder_system="x86_64-linux")
                self.assertEqual(rejected.exception.code, "RPM_DERIVATION_RECORD")
                self.assertEqual(rejected.exception.details["underlying_code"], "INVALID_STRING")
                self.assertEqual(rejected.exception.details["field_path"],
                                 "$.evidence.rpmlint.findings[1].message")
                self.assertEqual(rejected.exception.details["rule"], "INVALID_STRING")
                self.assertTrue(rejected.exception.rpmlint_policy["accepted"])
                self.assertFalse(rejected.exception.rpmlint_evidence["clean"])
                with patch("rs9.rpm_lint_policy.load_policy", side_effect=policy):
                    result = build_rpm_candidate(capture, intent, arch, helper.scratch,
                        offline_npm_archives=npm, runner=runner, builder_system="x86_64-linux")
                raw = result["manifest"]["rpmlint"]
                self.assertFalse(raw["clean"])
                self.assertEqual(raw["tool_receipt"]["exit_code"], 64)
                self.assertEqual(raw["tool_receipt"]["stdout_sha256"], receipts[0].stdout_sha256)
                self.assertEqual(len(raw["error_records"]), 1)
                self.assertTrue(result["policy_evaluation"]["accepted"])
                derivation = result["derivation_record"]
                self.assertGreater(len(canonical(derivation)), 64 * 1024)
                snapshot(derivation)
                with self.assertRaises(ContractError) as rejected:
                    snapshot({"evidence": {"rpmlint": raw}})
                self.assertEqual(rejected.exception.code, "INVALID_STRING")
                self.assertTrue(rejected.exception.details["field_path"].endswith(".message"))
                manifest_path = helper.scratch / "rpm-manifest.json"
                self.assertEqual(json.loads(manifest_path.read_bytes()), result["manifest"])
                selected_manifest = helper.scratch / "build" / product / "rpm-manifest.json"
                selected_manifest.parent.mkdir(parents=True, exist_ok=True)
                selected_manifest.write_bytes(manifest_path.read_bytes())
                selected_package = helper.scratch / "unsigned" / Path(result["rpm_path"]).name
                selected_package.parent.mkdir(exist_ok=True)
                selected_package.write_bytes(Path(result["rpm_path"]).read_bytes())
                summary, files = write_policy_evidence(helper.scratch, result["policy_evaluation"])
                raw_path = helper.scratch / "diagnostics" / ("rpmlint-" + product + ".json")
                raw_path.write_bytes(canonical(raw))
                self.assertEqual(derivation["evidence"]["rpmlint"]["raw_evidence"]["sha256"], digest(raw_path.read_bytes()))
                record = {"lane": "rpm", "system": "x86_64-linux", "runner": {}, "provenance": provenance(Path(__file__).resolve().parents[1], "1" * 64),
                          "production_enabled": False, "publication_authority": False,
                          "details": {"rpm_evidence_contract": "rs9.rpm-evidence-contract.v2",
                                      "rpm_lint_raw": {product: raw},
                                      "rpm_lint_policy": {product: summary}}}
                retained = helper.root / "custody"
                manifest = retain(helper.scratch, retained, [selected_manifest, selected_package, raw_path, *files], record)
                self.assertEqual(verify_set(retained), manifest)
                self.assertEqual(verify_policy_custody(retained, manifest, summary), result["policy_evaluation"])
                projection = verify_raw_custody(retained, manifest, raw, product=product, receipt=record, derivation=derivation)
                self.assertEqual(projection, derivation["evidence"]["rpmlint"])
                validate_rpm_policy_custody(retained, manifest, record)

    def test_actual_manifest_write_failure_keeps_stage_and_evidence_without_tool_blame(self):
        product = "theme-forge-stellar-loom"
        helper, capture, intent, npm, arch, runner, policy, _ = self.fixture(product)
        original = Path.write_bytes
        def write(path, data):
            if path == helper.scratch / "rpm-manifest.json":
                raise OSError("controlled-manifest-write")
            return original(path, data)
        with patch("rs9.rpm_lint_policy.load_policy", side_effect=policy), patch.object(Path, "write_bytes", write):
            with self.assertRaises(ContractError) as caught:
                build_rpm_candidate(capture, intent, arch, helper.scratch, offline_npm_archives=npm, runner=runner)
        error = caught.exception
        self.assertEqual(error.code, "RPM_MANIFEST_RECORD")
        self.assertEqual(error.details["substage"], "rpm-manifest-write")
        self.assertEqual(error.details["field_path"], "$")
        self.assertIsNone(error.causal_receipt)
        self.assertFalse(error.rpmlint_evidence["clean"])
        self.assertTrue(Path(error.package_path).is_file())
        from tests.test_rpm_failure_integration import RpmFailureIntegrationTests, PRODUCTS, ERROR
        root = helper.root / "hosted"; root.mkdir()
        with patch("rs9.rpm_lint_policy.load_policy", side_effect=policy):
            result, _, _ = RpmFailureIntegrationTests().run_lane(root, {p: (1, ERROR) for p in PRODUCTS},
                                                               injected_errors={product: error})
        failure = result["details"]["product_failures"][product]
        self.assertEqual(failure["substage"], "rpm-manifest-write")
        self.assertEqual(failure["field_path"], "$")
        self.assertNotIn("tool", failure)

    def test_later_policy_retention_failure_keeps_actual_raw_and_construction_identity(self):
        product = "theme-forge-stellar-loom"
        helper, capture, intent, npm, arch, runner, policy, _ = self.fixture(product)
        with patch("rs9.rpm_lint_policy.load_policy", side_effect=policy):
            built = build_rpm_candidate(capture, intent, arch, helper.scratch,
                offline_npm_archives=npm, runner=runner)
        from tests.test_rpm_failure_integration import RpmFailureIntegrationTests, PRODUCTS, ERROR
        root = helper.root / "hosted"; root.mkdir()
        cause = ContractError("RECORD_LIMIT", "Controlled retention rejection",
                              details={"field_path": "$.member_proofs", "rule": "RECORD_LIMIT"})
        cause.field_path, cause.rule = "$.member_proofs", "RECORD_LIMIT"
        with patch("rs9.rpm_lint_policy.load_policy", side_effect=policy), \
             patch("rs9.rpm_evidence.write_policy_evidence", side_effect=cause):
            result, _, _ = RpmFailureIntegrationTests().run_lane(root, {p: (1, ERROR) for p in PRODUCTS},
                injected_results={product: built})
        failure = result["details"]["product_failures"][product]
        self.assertEqual(failure["substage"], "rpm-policy-custody")
        self.assertEqual(failure["field_path"], "$.member_proofs")
        self.assertEqual(failure["rule"], "RECORD_LIMIT")
        self.assertNotIn("tool", failure)
        self.assertEqual(failure["identities"]["package_sha256"], built["manifest"]["package_sha256"])
        self.assertEqual(result["details"]["rpm_lint_raw"][product], built["manifest"]["rpmlint"])
