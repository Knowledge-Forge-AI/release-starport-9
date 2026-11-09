"""Pure facade-routing checks for the isolated 0.8 admission path."""
import copy
from datetime import datetime, timezone
import hashlib
import inspect
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from rs9 import own_repository_admission as own071
from rs9 import own_repository_admission080 as own080
from rs9 import qualified_distribution_inputs as facade
from rs9.current_generation import CURRENT_GENERATION
from rs9.errors import ContractError
from rs9.hosted_summary import required, summarize
from rs9.rpm_evidence import durable_lint_projection, verify_policy_custody, write_policy_evidence
from rs9.rpm_lint_policy import load_policy
from rs9.scratch import canonical

from tests.test_own_repository_admission import (
    QualifiedFixture,
    PTREE,
)


ROOT = Path(__file__).resolve().parents[1]
FIXTURE_080 = Path(__file__).resolve().parent / "fixtures/own-repository-admission080/consumer"


class Qualified080Fixture(QualifiedFixture):
    """Controlled custody fixture for the real current080 admission loop.

    The inherited fixture supplies the maintained collector/custody machinery.
    Its historical native observations are converted to a deliberately synthetic
    current080 pass shape; this never claims native or hosted qualification.
    """

    def setUp(self):
        super().setUp()
        # Bind the exact proposed 080 consumer bodies, not the inherited 071
        # bodies.  The descriptor/run context remains the controlled fixture.
        for name in own080.CONSUMER_FILE_HASHES_080:
            target = self.p / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes((FIXTURE_080 / name).read_bytes())
        self.rebuild_tree()

    @staticmethod
    def _routing_versions():
        from tests.test_own_repository_admission import routing
        return routing.VERSIONS

    def make_artifacts(self):
        # Use the existing producer fixture to build all custody objects and
        # constructor witnesses, changing only its controlled package version
        # table so the Nebular RPM filename is 0.8.0.
        with patch.dict(own071.VERSIONS, own080.VERSIONS_080), \
                patch.dict(self._routing_versions(), own080.VERSIONS_080):
            super().make_artifacts()
        self._convert_rpm_observations_to_080()

    def _convert_rpm_observations_to_080(self):
        """Rebuild retained controlled RPM objects with current080 scalars."""
        self.policy = load_policy(
            self.rs / "operators/theme-forge-current-202610/rpm-lint-policy-nebular080.json",
            generation=CURRENT_GENERATION,
            policy_variant="current080",
        )
        policy_hash = own080.digest(self.policy)
        for lane in required(self.rs, generation=CURRENT_GENERATION):
            if lane["lane"] != "rpm":
                continue
            directory = self.inputs / lane["artifact_name"]
            receipt_path = directory / (lane["lane"] + "-" + lane["system"] + ".json")
            receipt = json.loads(receipt_path.read_text())
            manifest_path = directory / "artifact-manifest.json"
            manifest = json.loads(manifest_path.read_text())
            details = receipt["details"]
            for product, old_summary in list(details["rpm_lint_policy"].items()):
                evaluation = verify_policy_custody(directory, manifest, old_summary)
                raw = copy.deepcopy(details["rpm_lint_raw"][product])
                entry = self.policy["projects"][product]
                version = entry["version"]
                inputs = evaluation["inputs"]
                inputs.update(version=version)
                binding = entry["inventory_bindings"][lane["system"]]
                inputs["payload_manifest_sha256"] = binding["payload_manifest_sha256"]
                auth = entry["authenticated_inputs"]
                if "assets" in auth:
                    suffix = "-" + lane["system"].removesuffix("-linux") + "-unknown-linux-gnu.tar.gz"
                    asset = next(row["sha256"] for row in auth["assets"] if row["name"].endswith(suffix))
                else:
                    asset = auth["asset_sha256"]
                inputs["asset_sha256"] = asset
                inputs["closure_sha256"] = auth.get("closure_sha256")

                # Do not relabel historical 071 native errors as 080 findings.
                # A closed zero-error result keeps this fixture synthetic while
                # exercising all downstream custody and policy checks.
                raw["error_records"] = []
                raw["findings"] = []
                raw["groups"] = []
                raw["counts"] = {**raw.get("counts", {}), "E": 0}
                raw["findings_summary"] = {**raw["findings_summary"], "errors": 0}
                raw["clean"] = True
                raw["status"] = "pass"
                raw["tool_receipt"] = {**raw["tool_receipt"], "exit_code": 0}
                raw["rpm_identity"] = {**raw.get("rpm_identity", {}), "version": version}
                raw["arguments"] = [raw.get("arguments", [product, raw["package_file"]])[0], raw["package_file"]]
                evaluation.update(
                    accepted=True,
                    status="accepted-no-exceptions",
                    blockers=[],
                    rule_blockers=[],
                    rule_blocker_causes=[],
                    accepted_findings=[],
                    member_proofs=[],
                    duplicate_groups=[],
                    observed_error_members=[],
                    calculated_duplicate_waste=None,
                    policy_sha256=policy_hash,
                    inventory_sha256=binding["source_inventory_sha256"],
                    raw_lint_status="pass",
                    raw_exit_code=0,
                )

                raw_path = next(directory / row["path"] for row in manifest["files"]
                                 if row["path"].endswith("objects/diagnostics/rpmlint-" + product + ".json"))
                raw_path.write_bytes(canonical(raw))
                rpm_manifest_path = next(directory / row["path"] for row in manifest["files"]
                                         if row["path"].endswith("build/" + product + "/rpm-manifest.json"))
                rpm_manifest = json.loads(rpm_manifest_path.read_text())
                rpm_manifest["rpmlint"] = raw
                rpm_manifest["derivation"]["evidence"]["rpmlint"] = durable_lint_projection(raw)
                rpm_manifest_path.write_bytes(canonical(rpm_manifest))
                summary, _ = write_policy_evidence(directory / "objects", evaluation)
                stem = "rpm-lint-policy-" + product
                expected_policy_names = {stem + ".json"} | {
                    Path(ref["object"]).name for ref in summary["chunks"]
                }
                for row in list(manifest["files"]):
                    name = Path(row["path"]).name
                    if (name == stem + ".json" or name.startswith(stem + ".part-")) \
                            and name not in expected_policy_names:
                        stale = directory / row["path"]
                        if stale.is_file():
                            stale.unlink()
                        manifest["files"].remove(row)
                details["rpm_lint_raw"][product] = raw
                details["rpm_lint_policy"][product] = summary

            # The synthetic zero-error result has no retained exception token.
            receipt["production_promotion_blockers"] = []
            receipt_path.write_bytes(canonical(receipt))
            for row in manifest["files"]:
                path = directory / row["path"]
                if path.is_file():
                    row["sha256"] = hashlib.sha256(path.read_bytes()).hexdigest()
                    row["size"] = path.stat().st_size
            manifest["qualification_receipt_hashes"] = {
                receipt_path.name: hashlib.sha256(receipt_path.read_bytes()).hexdigest()
            }
            manifest_path.write_bytes(canonical(manifest))

        jobs = {name: {"result": "success"} for name in self.contract_jobs() if name != "summary"}
        with patch.dict("os.environ", {"RS9_JOB_CONCLUSIONS": json.dumps(jobs)}):
            result = summarize(self.rs, self.inputs, self.summaryroot, generation=CURRENT_GENERATION)
        self.assertEqual(result, 0)
        self.summary = json.loads((self.summaryroot / "hosted-summary.json").read_text())
        self.repack()

    def contract_jobs(self):
        from tests.test_own_repository_admission import contract
        return contract(self.rs, generation=CURRENT_GENERATION)["required_jobs"]

    def _consumer_api(self, root, argv):
        endpoint = argv[-1]
        if endpoint.endswith("git/ref/heads/main"):
            return json.dumps({"object": {"type": "commit", "sha": "f" * 40}})
        if "/git/commits/" in endpoint:
            return json.dumps({"sha": "f" * 40, "tree": {"sha": "e" * 40}})
        rows = []
        for name in sorted(set(own080.CONSUMER_FILE_HASHES_080) | {own080.DESCRIPTOR}):
            data = (self.p / name).read_bytes()
            rows.append({"path": name, "type": "blob", "mode": "100644",
                         "sha": hashlib.sha1(b"blob " + str(len(data)).encode() + b"\0" + data).hexdigest()})
        return json.dumps({"sha": "e" * 40, "truncated": False, "tree": rows})

    def consumer_080(self):
        with patch.object(own080, "source_tree_identity", return_value=PTREE), \
                patch.object(own080, "gh_read", side_effect=self._consumer_api):
            return own080.consumer_source_080(self.config, self.p, "f" * 40, "e" * 40)

    def admit_080(self):
        consumer = self.consumer_080()
        self.addCleanup(own080.release_consumer_080, consumer)
        return consumer, own080.admit_080(self.rs, self.inputs, self.summary, self.expected, consumer)

    def mutate_physical_raw_error_set(self, *, accepted_synthetic=False):
        """Change one retained raw object while preserving its typed custody."""
        lane = next(row for row in required(self.rs, generation=CURRENT_GENERATION)
                    if row["lane"] == "rpm" and row["system"] == "x86_64-linux")
        directory = self.inputs / lane["artifact_name"]
        receipt_path = directory / "rpm-x86_64-linux.json"
        receipt = json.loads(receipt_path.read_text())
        manifest_path = directory / "artifact-manifest.json"
        manifest = json.loads(manifest_path.read_text())
        product = "theme-forge-nebular-fusion"
        raw_path = next(directory / row["path"] for row in manifest["files"]
                        if row["path"].endswith("objects/diagnostics/rpmlint-" + product + ".json"))
        raw = json.loads(raw_path.read_text())
        raw["error_records"] = [{
            "arguments_complete": True,
            "arguments_sha256": hashlib.sha256(b"").hexdigest(),
            "code": "files-duplicated-waste" if accepted_synthetic else "synthetic-mutated-error",
            "level": "E",
            "message": "",
            "target": product,
        }]
        raw["counts"] = {**raw["counts"], "E": 1}
        raw["findings_summary"] = {**raw["findings_summary"], "errors": 1}
        raw["clean"] = False
        raw["status"] = "fail"
        raw["tool_receipt"] = {**raw["tool_receipt"], "exit_code": 64}
        raw_path.write_bytes(canonical(raw))
        rpm_manifest_path = next(directory / row["path"] for row in manifest["files"]
                                 if row["path"].endswith("build/" + product + "/rpm-manifest.json"))
        rpm_manifest = json.loads(rpm_manifest_path.read_text())
        rpm_manifest["rpmlint"] = raw
        rpm_manifest["derivation"]["evidence"]["rpmlint"] = durable_lint_projection(raw)
        rpm_manifest_path.write_bytes(canonical(rpm_manifest))
        receipt["details"]["rpm_lint_raw"][product] = raw
        evaluation = verify_policy_custody(
            directory, manifest, receipt["details"]["rpm_lint_policy"][product]
        )
        evaluation["raw_lint_status"] = "fail"
        evaluation["raw_exit_code"] = 64
        if accepted_synthetic:
            # Fresh synthetic finding for the admission boundary, not an
            # assertion that a native producer proved this preservation rule.
            evaluation["accepted_findings"] = copy.deepcopy(raw["error_records"])
            evaluation["status"] = "accepted"
        summary, _ = write_policy_evidence(directory / "objects", evaluation)
        receipt["details"]["rpm_lint_policy"][product] = summary
        if accepted_synthetic:
            from rs9.hosted_summary import RPM_POLICY_PROMOTION_BLOCKER
            receipt["production_promotion_blockers"] = [RPM_POLICY_PROMOTION_BLOCKER]
        receipt_path.write_bytes(canonical(receipt))
        for row in manifest["files"]:
            path = directory / row["path"]
            if path.is_file():
                row["sha256"] = hashlib.sha256(path.read_bytes()).hexdigest()
                row["size"] = path.stat().st_size
        manifest["qualification_receipt_hashes"] = {
            receipt_path.name: hashlib.sha256(receipt_path.read_bytes()).hexdigest()
        }
        manifest_path.write_bytes(canonical(manifest))
        jobs = {name: {"result": "success"} for name in self.contract_jobs() if name != "summary"}
        with patch.dict("os.environ", {"RS9_JOB_CONCLUSIONS": json.dumps(jobs)}):
            result = summarize(self.rs, self.inputs, self.summaryroot, generation=CURRENT_GENERATION)
        self.assertEqual(result, 0)
        self.summary = json.loads((self.summaryroot / "hosted-summary.json").read_text())
        self.repack()

    def mutate_physical_evaluation_input(self, field):
        """Isolate an admit080 input join using consistent controlled custody.

        Only the direct admission precondition is supplied here. This is not a
        claim that the mutated data passes the original collector or summary.
        """
        self.assertIn(field, {"asset_sha256", "payload_manifest_sha256"})
        lane = next(row for row in required(self.rs, generation=CURRENT_GENERATION)
                    if row["lane"] == "rpm" and row["system"] == "x86_64-linux")
        directory = self.inputs / lane["artifact_name"]
        receipt_path = directory / "rpm-x86_64-linux.json"
        manifest_path = directory / "artifact-manifest.json"
        receipt = json.loads(receipt_path.read_text())
        manifest = json.loads(manifest_path.read_text())
        product = "theme-forge-nebular-fusion"
        evaluation = verify_policy_custody(directory, manifest, receipt["details"]["rpm_lint_policy"][product])
        self.assertNotEqual(evaluation["inputs"][field], "0" * 64)
        evaluation["inputs"][field] = "0" * 64
        summary, paths = write_policy_evidence(directory / "objects", evaluation)
        actual_paths = {p.relative_to(directory).as_posix() for p in paths}
        stem = "rpm-lint-policy-" + product
        prior_paths = {row["path"] for row in manifest["files"]
                       if Path(row["path"]).name == stem + ".json"
                       or Path(row["path"]).name.startswith(stem + ".part-")}
        self.assertEqual(actual_paths, prior_paths)
        receipt["details"]["rpm_lint_policy"][product] = summary
        receipt_path.write_bytes(canonical(receipt))
        for row in manifest["files"]:
            path = directory / row["path"]
            row["sha256"] = hashlib.sha256(path.read_bytes()).hexdigest()
            row["size"] = path.stat().st_size
        manifest["qualification_receipt_hashes"] = {
            receipt_path.name: hashlib.sha256(receipt_path.read_bytes()).hexdigest()}
        manifest_path.write_bytes(canonical(manifest))
        for key, updated in (("receipts", receipt), ("artifact_manifests", manifest)):
            # These are direct-admission unit doubles, not a saved qualified
            # summary that could be supplied to the production facade.
            position, = [i for i, row in enumerate(self.summary[key])
                         if row["lane"] == lane["lane"] and row["system"] == lane["system"]]
            self.summary[key][position] = updated


class Qualified080FacadeTests(unittest.TestCase):
    """Synthetic context only; no collection, native receipt, or publication claim."""

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.output = Path(self.temp.name).resolve()
        self.config = facade.SourceBoundConfiguration(
            ROOT, "1" * 40, "2" * 40, 7, datetime(2026, 10, 29, tzinfo=timezone.utc), *(["a" * 64] * 5))
        self.expected = self.config.expected()
        self.consumer = own080._Consumer(
            {"repository": own080.TARGET, "admission_profile": "current080"},
            own080.digest(self.expected), own080._PROOF_080)
        self.admission = own080._Admission(
            (), {"admission_profile": "current080"}, own080._PROOF_080)

    def test_080_facade_routes_typed_proof_and_preserves_authority_flags(self):
        with patch.object(own071, "verify_execution_source"), \
                patch.object(facade, "_verified_context", return_value=(ROOT, self.output, {}, self.expected)), \
                patch.object(own080, "consumer_source_080", return_value=self.consumer) as source, \
                patch.object(own080, "admit_080", return_value=self.admission) as admit, \
                patch.object(facade, "_binary_inputs", return_value=([], {})) as binaries:
            result = facade.qualified_theme_forge_packages_inputs_080(
                self.config, self.output, consumer_repository=self.output,
                consumer_commit="f" * 40, consumer_tree="e" * 40)
        self.assertEqual(source.call_count, 3)
        admit.assert_called_once_with(ROOT, self.output, {}, self.expected, self.consumer)
        binaries.assert_called_once_with(ROOT, self.output, {}, self.expected, _admission_080=self.admission)
        for field in ("production_enabled", "publication_authority", "attended_gates_satisfied", "signing_authority",
                      "full_live1_qualification", "published_linux_nix_ready"):
            self.assertIs(result[field], False)
        self.assertEqual(result["own_repository_admission"]["admission_profile"], "current080")

    def test_both_profile_proofs_are_rejected_before_custody_work(self):
        with self.assertRaises(ContractError) as error:
            facade._binary_inputs(self.output, self.output, {}, {}, _admission=object(), _admission_080=object())
        self.assertEqual(error.exception.code, "OWN_REPOSITORY_ADMISSION")

    def test_default_facade_has_no_public_080_selector(self):
        self.assertIsNot(facade.qualified_theme_forge_packages_inputs,
                         facade.qualified_theme_forge_packages_inputs_080)
        self.assertNotIn("policy_variant", inspect.signature(facade.qualified_theme_forge_packages_inputs).parameters)
        self.assertEqual(CURRENT_GENERATION, "theme-forge-current-202610")


class Qualified080ConnectedTests(Qualified080Fixture):
    """Connected synthetic 080 path; no native/publication acceptance claim."""

    def _binary_with_proof(self, proof):
        rpm_lane = next(row for row in required(self.rs, generation=CURRENT_GENERATION)
                        if row["lane"] == "rpm" and row["system"] == "x86_64-linux")
        with patch.object(facade, "required", return_value=[rpm_lane]):
            return facade._binary_inputs(
                self.rs, self.inputs, self.summary, self.expected, _admission_080=proof)

    def test_real_080_admit_check_lane_and_binary_selection(self):
        consumer, proof = self.admit_080()
        self.addCleanup(own080.release_080, proof)
        binaries, _ = self._binary_with_proof(proof)
        self.assertEqual(proof.record["admission_profile"], "current080")
        self.assertEqual(proof.record["policy_sha256"], own080.digest(self.policy))
        self.assertEqual({row["product"]: row["version"] for row in binaries}, own080.VERSIONS_080)
        self.assertTrue(all(row["admission_profile"] == "current080" for row in [proof.record]))

        # The branch above calls check_lane_080 against physical receipt and
        # manifest custody.  A released or foreign proof cannot be reused.
        foreign = own080._Admission(proof.ledger, proof.record, object())
        with self.assertRaises(ContractError):
            self._binary_with_proof(foreign)
        own080.release_080(proof)
        with self.assertRaises(ContractError):
            self._binary_with_proof(proof)
        own080.release_consumer_080(consumer)

    def test_connected_admission_rejects_policy_digest_and_changed_raw_set(self):
        consumer = self.consumer_080()
        self.addCleanup(own080.release_consumer_080, consumer)
        wrong_policy = copy.deepcopy(self.policy)
        wrong_policy["test_only_digest_mutation"] = True
        with patch.object(own080, "load_policy", return_value=wrong_policy), \
                self.assertRaises(ContractError):
            own080.admit_080(self.rs, self.inputs, self.summary, self.expected, consumer)

        # Mutate the retained raw object, receipt and manifest consistently so
        # direct admission must reject the changed error set. This case does
        # not isolate which inner raw/error predicate fires first.
        self.mutate_physical_raw_error_set()
        with self.assertRaises(ContractError):
            own080.admit_080(self.rs, self.inputs, self.summary, self.expected, consumer)

    def test_connected_admission_rejects_changed_asset_and_payload_bindings(self):
        consumer = self.consumer_080()
        self.addCleanup(own080.release_consumer_080, consumer)
        for field in ("asset", "payload"):
            with self.subTest(field=field):
                wrong_policy = copy.deepcopy(self.policy)
                entry = wrong_policy["projects"]["theme-forge-nebular-fusion"]
                if field == "asset":
                    entry["authenticated_inputs"]["assets"][0]["sha256"] = "0" * 64
                else:
                    entry["inventory_bindings"]["x86_64-linux"]["payload_manifest_sha256"] = "0" * 64
                with patch.object(own080, "load_policy", return_value=wrong_policy), \
                        self.assertRaises(ContractError):
                    own080.admit_080(self.rs, self.inputs, self.summary, self.expected, consumer)

    def test_policy_change_after_admit_cannot_cross_binary_join(self):
        consumer, proof = self.admit_080()
        self.addCleanup(own080.release_080, proof)
        policy_path = self.rs / "operators/theme-forge-current-202610/rpm-lint-policy-nebular080.json"
        original = policy_path.read_bytes()
        changed = json.loads(original)
        changed["projects"]["theme-forge-nebular-fusion"]["exceptions"]["files-duplicated-waste"]["justification"] += " (changed)"
        policy_path.write_bytes(canonical(changed))
        try:
            with self.assertRaises(ContractError):
                self._binary_with_proof(proof)
        finally:
            policy_path.write_bytes(original)

    def test_physical_asset_input_refuses_at_admission_asset_join(self):
        consumer = self.consumer_080()
        self.addCleanup(own080.release_consumer_080, consumer)
        self.mutate_physical_evaluation_input("asset_sha256")
        with self.assertRaises(ContractError) as error:
            own080.admit_080(self.rs, self.inputs, self.summary, self.expected, consumer)
        self.assertIn("Policy/capture asset or closure differs", str(error.exception))

    def test_physical_payload_input_refuses_at_admission_payload_join(self):
        consumer = self.consumer_080()
        self.addCleanup(own080.release_consumer_080, consumer)
        self.mutate_physical_evaluation_input("payload_manifest_sha256")
        with self.assertRaises(ContractError) as error:
            own080.admit_080(self.rs, self.inputs, self.summary, self.expected, consumer)
        self.assertIn("Incomplete current080 preservation/native evaluation", str(error.exception))

    def test_synthetic_exception_scope_admits_080_and_default_refuses(self):
        from rs9.hosted_summary import RPM_POLICY_PROMOTION_BLOCKER
        self.mutate_physical_raw_error_set(accepted_synthetic=True)
        consumer, proof = self.admit_080()
        self.addCleanup(own080.release_080, proof)
        self.assertEqual(proof.record["original_restrictions"], [RPM_POLICY_PROMOTION_BLOCKER])
        self.assertIs(proof.record["original_production_promotion_blocked"], True)
        self.assertIs(proof.record["raw_clean_claim"], False)
        observations = [r for r in proof.record["raw_policy_evidence"]
                        if r["product"] == "theme-forge-nebular-fusion" and r["system"] == "x86_64-linux"]
        self.assertEqual(len(observations), 1)
        self.assertIs(observations[0]["raw_clean"], False)
        binaries, _ = self._binary_with_proof(proof)
        self.assertEqual({r["product"]: r["version"] for r in binaries}, own080.VERSIONS_080)
        with self.assertRaises(ContractError) as error:
            self.run_facade(False)
        self.assertEqual(error.exception.code, "DISTRIBUTION_PROMOTION_HELD")
        own080.release_consumer_080(consumer)

    def test_connected_admission_rejects_consumer_mutation_and_cleans_proof(self):
        consumer = self.consumer_080()
        self.assertIn(consumer, own080._CONSUMERS_080)
        consumer.record["tree"] = "0" * 40
        with self.assertRaises(ContractError):
            own080.admit_080(self.rs, self.inputs, self.summary, self.expected, consumer)
        own080.release_consumer_080(consumer)
        self.assertNotIn(consumer, own080._CONSUMERS_080)


def load_tests(loader, tests, pattern):
    """Exclude inherited 071 fixture tests from this focused 080 module."""
    suite = unittest.TestSuite()
    suite.addTests(loader.loadTestsFromTestCase(Qualified080FacadeTests))
    for name in (
        "test_real_080_admit_check_lane_and_binary_selection",
        "test_connected_admission_rejects_policy_digest_and_changed_raw_set",
        "test_connected_admission_rejects_changed_asset_and_payload_bindings",
        "test_policy_change_after_admit_cannot_cross_binary_join",
        "test_physical_asset_input_refuses_at_admission_asset_join",
        "test_physical_payload_input_refuses_at_admission_payload_join",
        "test_synthetic_exception_scope_admits_080_and_default_refuses",
        "test_connected_admission_rejects_consumer_mutation_and_cleans_proof",
    ):
        suite.addTest(Qualified080ConnectedTests(name))
    return suite

