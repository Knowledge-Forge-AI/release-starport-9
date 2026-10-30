"""Strict verifier boundaries and real byte-role checks on synthetic archives."""
import copy
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest.mock import patch

from rs9.current_generation import CURRENT_GENERATION, DISTRIBUTION_SCOPE, DISTRIBUTION_JOBS
from rs9.errors import ContractError
from tests.test_current_rpm_preservation_policy import blocked_policy
from rs9.hosted_custody import provenance, retain
from rs9.hosted_summary import required, summarize
from rs9.qualified_distribution_inputs import SourceBoundConfiguration, qualified_distribution_inputs, _binary_inputs
from rs9.scratch import canonical
from tests.test_hosted_summary_roles import _make_synthetic_rpm

ROOT = Path(__file__).resolve().parents[1]
COMMIT, TREE = "1" * 40, "2" * 40
LOOM = "theme-forge-stellar-loom"


class QualifiedDistributionInputTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        env = patch.dict(os.environ, {"GITHUB_SHA": COMMIT, "GITHUB_REF": "refs/heads/main", "GITHUB_EVENT_NAME": "push",
            "GITHUB_RUN_ATTEMPT": "1", "GITHUB_RUN_ID": "7", "GITHUB_REPOSITORY": "Knowledge-Forge-AI/release-starport-9"})
        env.start(); self.addCleanup(env.stop)
        tree = patch("rs9.hosted_custody.source_tree_identity", return_value=TREE)
        tree.start(); self.addCleanup(tree.stop)
        self.expected = provenance(ROOT, "a" * 64, generation=CURRENT_GENERATION)
        self.config = SourceBoundConfiguration(ROOT, COMMIT, TREE, 7, datetime(2026, 10, 29, tzinfo=timezone.utc),
            *[self.expected[field] for field in ("workflow_sha256", "contract_sha256", "builder_source_sha256", "configuration_sha256", "release_ingestion_sha256")])
        from rs9.collect_candidate import admit_original_run
        from rs9.current_generation import distribution_paths
        document = {"id": 7, "head_sha": COMMIT, "event": "push", "head_branch": "main", "path": distribution_paths(CURRENT_GENERATION)[0],
                    "run_attempt": 1, "status": "completed", "repository": {"full_name": "Knowledge-Forge-AI/release-starport-9"}, "created_at": "2026-10-29T00:00:01Z"}
        _, self.original_run = admit_original_run(ROOT, commit=COMMIT, run_id=7, started_at=self.config.not_before,
            generation=CURRENT_GENERATION, runner=lambda root, argv: json.dumps(document))
        admitted = patch("rs9.qualified_distribution_inputs.admit_original_run", return_value=(document, self.original_run))
        admitted.start(); self.addCleanup(admitted.stop)
        self.packet = {"validation": {"status": "pass", "reasons": []}, "classification": "qualified-current-distribution-candidate",
            "generation": CURRENT_GENERATION, "qualification_scope": DISTRIBUTION_SCOPE, "source_commit": COMMIT, "run_id": 7,
            "production_enabled": False, "publication_authority": False, "diagnostic_scope": {
                "current_distribution_qualification": True, "full_live1_qualification": False, "published_linux_nix_ready": False}}
        self.summary = {"schema": "rs9.hosted-candidate-summary.v1alpha2", **self.expected, "qualification_verdict": "qualified",
            "adoptable": True, "blocking_reasons": [], "production_promotion_blockers": [], "production_promotion_blocked": False,
            "production_enabled": False, "publication_authority": False, "attended_gates_satisfied": False, "receipts": [], "artifact_manifests": []}
        (self.root / "hosted-summary").mkdir()
        (self.root / "hosted-summary/hosted-summary.json").write_bytes(canonical(self.summary))

    def test_saved_flags_are_not_an_input_and_source_is_recomputed_before_collection(self):
        with patch("rs9.qualified_distribution_inputs.collect") as collect:
            with self.assertRaises(ContractError):
                qualified_distribution_inputs(self.packet, self.root)
            with patch("rs9.qualified_distribution_inputs.source_identity", return_value={**self.expected, "source_tree": "3" * 40}), self.assertRaises(ContractError) as error:
                qualified_distribution_inputs(self.config, self.root)
        self.assertEqual(error.exception.code, "DISTRIBUTION_SOURCE")
        collect.assert_not_called()

    def test_recomputed_packet_conditions_are_all_required(self):
        mutations = [{"validation": {"status": "pass", "reasons": ["unresolved"]}}, {"classification": "fully-qualified-candidate"},
                     {"source_commit": "3" * 40}, {"run_id": 8}, {"production_enabled": True}, {"publication_authority": True},
                     {"diagnostic_scope": {**self.packet["diagnostic_scope"], "current_distribution_qualification": False}},
                     {"diagnostic_scope": {**self.packet["diagnostic_scope"], "full_live1_qualification": True}},
                     {"diagnostic_scope": {**self.packet["diagnostic_scope"], "published_linux_nix_ready": True}}]
        for mutation in mutations:
            with self.subTest(mutation=mutation), patch("rs9.qualified_distribution_inputs.source_identity", return_value=self.expected), \
                 patch("rs9.qualified_distribution_inputs.collect", return_value={**self.packet, **mutation}) as collect, \
                 patch("rs9.qualified_distribution_inputs.validate_hosted_summary") as validate, self.assertRaises(ContractError):
                qualified_distribution_inputs(self.config, self.root, zip_transport="public-release-relay")
            self.assertEqual(collect.call_args.kwargs["zip_transport"], "public-release-relay")
            validate.assert_not_called()

    def test_summary_is_revalidated_and_actual_promotion_and_authority_flags_refuse(self):
        mutations = [{"production_promotion_blockers": ["preserved-rpm-finding"]}, {"production_promotion_blocked": True},
                     {"production_promotion_blockers": None}, {"attended_gates_satisfied": True}, {"production_enabled": True},
                     {"publication_authority": True}, {"qualification_verdict": "not-qualified"}, {"adoptable": False}, {"blocking_reasons": ["held"]}]
        for mutation in mutations:
            (self.root / "hosted-summary/hosted-summary.json").write_bytes(canonical({**self.summary, **mutation}))
            with self.subTest(mutation=mutation), patch("rs9.qualified_distribution_inputs.source_identity", return_value=self.expected), \
                 patch("rs9.qualified_distribution_inputs.collect", return_value=self.packet), \
                 patch("rs9.qualified_distribution_inputs.validate_hosted_summary", return_value={**self.summary, **mutation}) as validate, \
                 patch("rs9.qualified_distribution_inputs._binary_inputs") as binaries, self.assertRaises(ContractError):
                qualified_distribution_inputs(self.config, self.root)
            self.assertEqual(validate.call_args.kwargs, {"generation": CURRENT_GENERATION, "run_id": 7, "original_run": self.original_run})
            binaries.assert_not_called()

    def test_no_signing_or_publication_authority_is_granted_by_result_constructor(self):
        # Isolated control-flow fixture, not an end-to-end qualification claim.
        with patch("rs9.qualified_distribution_inputs.source_identity", return_value=self.expected), \
             patch("rs9.qualified_distribution_inputs.collect", return_value=self.packet), \
             patch("rs9.qualified_distribution_inputs.validate_hosted_summary", return_value=self.summary), \
             patch("rs9.qualified_distribution_inputs._binary_inputs", return_value=([], {})):
            result = qualified_distribution_inputs(self.config, self.root)
        for field in ("production_enabled", "publication_authority", "attended_gates_satisfied", "signing_authority", "full_live1_qualification", "published_linux_nix_ready"):
            self.assertIs(result[field], False)

    @patch("rs9.rpm_lint_policy.load_policy", side_effect=lambda *args, **kwargs: blocked_policy())
    def test_forged_green_packet_cannot_override_explicit_current_rpm_policy_hold(self, selected_policy):
        from tests.test_hosted_summary import HostedSummaryTests
        from rs9.hosted_nix import PRODUCTS
        fixture = HostedSummaryTests(); fixture.setUp(); self.addCleanup(fixture.doCleanups)
        lanes = required(ROOT, generation=CURRENT_GENERATION)
        names = {lane["artifact_name"] for lane in lanes}
        for directory in fixture.inputs.iterdir():
            if directory.name not in names:
                shutil.rmtree(directory)
        with patch("rs9.hosted_custody.source_tree_identity", return_value=TREE):
            for lane in lanes:
                directory = fixture.inputs / lane["artifact_name"]
                name = lane["lane"] + "-" + lane["system"] + ".json"
                receipt = json.loads((directory / name).read_bytes()); receipt["provenance"] = self.expected
                if lane["lane"] == "nix":
                    receipt["details"] = {"outputs": {product: {} for product in PRODUCTS}}
                (directory / name).write_bytes(canonical(receipt))
                manifest_path = directory / "artifact-manifest.json"; manifest = json.loads(manifest_path.read_bytes()); manifest.update(self.expected)
                manifest["qualification_receipt_hashes"] = {name: hashlib.sha256(canonical(receipt)).hexdigest()}; manifest_path.write_bytes(canonical(manifest))
            jobs = {job: {"result": "success"} for job in DISTRIBUTION_JOBS if job != "summary"}
            with patch.dict(os.environ, {"RS9_JOB_CONCLUSIONS": json.dumps(jobs)}):
                self.assertEqual(summarize(ROOT, fixture.inputs, fixture.output, generation=CURRENT_GENERATION), 2)
            destination = fixture.inputs / "hosted-summary"; fixture.output.rename(destination)
            with patch("rs9.qualified_distribution_inputs.collect", return_value=self.packet), self.assertRaises(ContractError) as error:
                qualified_distribution_inputs(self.config, fixture.inputs)
        self.assertEqual(error.exception.code, "CURRENT_RPM_POLICY_HELD")

    def bundle(self, family, system, *, payload=b"fixture", include_binary=True, disguise_source=False, header_arch=None):
        work = self.root / (family + "-" + system + "-work"); work.mkdir()
        artifact = "candidate-" + family + "-" + system
        directory = self.root / artifact
        files = []
        if family == "rpm":
            name = LOOM + "-0.5.0-1.noarch.rpm"
            binary = _make_synthetic_rpm(LOOM, version="0.5.0", arch=header_arch or "noarch", payload=payload, is_source=disguise_source)
            source = work / "lane-work/unsigned-source" / (LOOM + "-0.5.0-1.src.rpm")
            source.parent.mkdir(parents=True); source.write_bytes(_make_synthetic_rpm(LOOM, version="0.5.0", is_source=True))
            build = work / "lane-work/build" / LOOM / "rpm-manifest.json"; build.parent.mkdir(parents=True)
            build.write_bytes(canonical({"project": LOOM, "reproducibility": {"source_rpm": {"name": source.name,
                "sha256": hashlib.sha256(source.read_bytes()).hexdigest(), "size": source.stat().st_size}}}))
            files.extend([source, build])
            fixture = work / "lane-work/repository" / name; fixture.parent.mkdir(parents=True); fixture.write_bytes(_make_synthetic_rpm(LOOM, version="0.5.0")); files.append(fixture)
        else:
            name = LOOM + "_0.5.0-1_all.deb"; binary = b"!<arch>\n" + payload
        if include_binary:
            package = work / "lane-work/unsigned" / name; package.parent.mkdir(parents=True, exist_ok=True); package.write_bytes(binary); files.append(package)
        receipt = {"lane": family, "system": system, "provenance": self.expected, "runner": {}, "production_enabled": False,
                   "publication_authority": False, "attended_gates_satisfied": False, "production_promotion_blockers": [], "details": {}}
        manifest = retain(work, directory, files, receipt)
        lane = {"lane": family, "system": system, "artifact_name": artifact, "required_products": [LOOM]}
        return lane, receipt, manifest

    def select(self, rows):
        summary = {"receipts": [row[1] for row in rows], "artifact_manifests": [row[2] for row in rows]}
        # Isolate byte-role/architecture selection from the separately held policy layer.
        with patch("rs9.qualified_distribution_inputs.required", return_value=[row[0] for row in rows]), \
             patch("rs9.qualified_distribution_inputs.validate_rpm_policy_source"):
            return _binary_inputs(ROOT, self.root, summary, self.expected)

    def test_real_byte_roles_exclude_source_and_fixture_copies(self):
        rows = [self.bundle("rpm", system) for system in ("x86_64-linux", "aarch64-linux")]
        binaries, nix = self.select(rows)
        self.assertEqual(len(binaries), 1)
        self.assertEqual(binaries[0]["name"], LOOM + "-0.5.0-1.noarch.rpm")
        self.assertEqual(len(binaries[0]["origins"]), 2)
        self.assertTrue(all("/unsigned/" in origin["path"] for origin in binaries[0]["origins"]))
        self.assertFalse(nix)

    def test_source_or_fixture_only_does_not_satisfy_installable_presence(self):
        rows = [self.bundle("rpm", "x86_64-linux", include_binary=False)]
        with self.assertRaises(ContractError) as error:
            self.select(rows)
        self.assertEqual(error.exception.code, "DISTRIBUTION_BINARY_SCOPE")

    def test_actual_source_bytes_disguised_as_binary_and_header_architecture_refuse(self):
        for system, change in (("x86_64-linux", {"disguise_source": True}), ("aarch64-linux", {"header_arch": "aarch64"})):
            row = self.bundle("rpm", system, **change)
            with self.assertRaises(ContractError) as error:
                self.select([row])
            self.assertIn(error.exception.code, {"CUSTODY_ROLE", "CUSTODY_ARCHITECTURE"})

    def test_noarch_and_all_require_identical_complete_bytes_between_lanes(self):
        for family, systems in (("rpm", ("x86_64-linux", "aarch64-linux")), ("deb", ("amd64", "arm64"))):
            rows = [self.bundle(family, systems[0], payload=b"one"), self.bundle(family, systems[1], payload=b"two")]
            with self.subTest(family=family), self.assertRaises(ContractError) as error:
                self.select(rows)
            self.assertEqual(error.exception.code, "CUSTODY_CONFLICT")

    def test_lane_restrictions_are_recomputed_even_when_summary_aggregate_is_clear(self):
        lane, receipt, manifest = self.bundle("rpm", "x86_64-linux")
        receipt["details"] = {"rpm_lint_policy": {LOOM: {"accepted_findings": [{"rule": "preserved"}]}}}
        directory = self.root / lane["artifact_name"]; name = "rpm-x86_64-linux.json"; raw = canonical(receipt)
        (directory / name).write_bytes(raw); manifest["qualification_receipt_hashes"] = {name: hashlib.sha256(raw).hexdigest()}
        (directory / "artifact-manifest.json").write_bytes(canonical(manifest))
        with self.assertRaises(ContractError) as error:
            self.select([(lane, receipt, manifest)])
        self.assertEqual(error.exception.code, "DISTRIBUTION_PROMOTION_HELD")

    def test_unknown_mode_refuses_before_source_or_collection(self):
        with patch("rs9.qualified_distribution_inputs.source_identity") as source, patch("rs9.qualified_distribution_inputs.collect") as collect, self.assertRaises(ContractError) as error:
            qualified_distribution_inputs(self.config, self.root, zip_transport="unknown")
        self.assertEqual(error.exception.code, "PUBLIC_RELAY_MODE")
        source.assert_not_called(); collect.assert_not_called()

    def test_summary_symlink_and_changed_revalidation_refuse(self):
        target = self.root / "hosted-summary/hosted-summary.json"
        original = self.root / "original.json"; original.write_bytes(target.read_bytes()); target.unlink(); target.symlink_to(original)
        with patch("rs9.qualified_distribution_inputs.source_identity", return_value=self.expected), patch("rs9.qualified_distribution_inputs.collect", return_value=self.packet), self.assertRaises(ContractError):
            qualified_distribution_inputs(self.config, self.root)
        target.unlink(); target.write_bytes(original.read_bytes())
        with patch("rs9.qualified_distribution_inputs.source_identity", return_value=self.expected), patch("rs9.qualified_distribution_inputs.collect", return_value=self.packet), \
             patch("rs9.qualified_distribution_inputs.validate_hosted_summary", return_value={**self.summary, "changed": True}), self.assertRaises(ContractError) as error:
            qualified_distribution_inputs(self.config, self.root)
        self.assertEqual(error.exception.code, "DISTRIBUTION_CUSTODY")
