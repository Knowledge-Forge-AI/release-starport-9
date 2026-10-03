"""Tests for qualification trust roots and diagnostic record boundaries."""
import copy
import hashlib
from pathlib import Path
import tempfile
import unittest

from rs9.errors import ContractError
from rs9.gates import check_gates, gate
from rs9.planner import destination_policy
from rs9.qualification import Qualification, artifact_inventory, bound_qualifications, execute_qualification
from rs9.records import record_sha256
from rs9.release_core import digest
from tests.publication_fixtures import fixture, observation, T0


def dummy_verifier(candidate):
    return [{"id": "dummy-verifier", "exit_code": 0,
             "stdout_sha256": digest(b""), "stderr_sha256": digest(b"")}]


class QualificationTrustTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name).resolve()
        self.bundle = fixture(self.root)
        self.intent, self.capture, self.profile, self.output, self.gates, self.policy = self.bundle
        self.this_file_sha = digest(Path(__file__).read_bytes())

    def run_qual(self, gate_id="package.render", trust_root=None, verifier=None):
        v = verifier or dummy_verifier
        kwargs = {
            "verifier_id": "dummy-verifier",
            "verifier_source_sha256": self.this_file_sha,
            "environment": {"purpose": "synthetic-fixture"},
        }
        if trust_root is not None:
            kwargs["trust_root"] = trust_root
        return execute_qualification(self.capture, self.output, gate_id, self.root, v, **kwargs)

    def test_default_trust_root_is_provider_local_unattested(self):
        record = self.run_qual()
        self.assertEqual(record["trust_root"], "provider-local-unattested")

    def test_closed_trust_roots_accepted(self):
        for tr in ("attended-local-rerun", "provider-local-unattested", "hosted-candidate-unattested"):
            record = self.run_qual(trust_root=tr)
            self.assertEqual(record["trust_root"], tr)

    def test_unknown_trust_root_rejected(self):
        for bad in ("arbitrary", "ci-attestation", "untrusted", "", "attended", "hosted"):
            with self.assertRaises(ContractError) as ctx:
                self.run_qual(trust_root=bad)
            self.assertEqual(ctx.exception.code, "QUALIFICATION_TRUST_ROOT")

    def test_bound_qualifications_accepts_only_attended_local_rerun(self):
        self.capture._qualification_records = []
        
        # 1. provider-local-unattested -> ignored by bound_qualifications
        self.run_qual("package.render", trust_root="provider-local-unattested")
        self.assertEqual(bound_qualifications(self.capture, self.output, "package.render"), [])

        # 2. hosted-candidate-unattested -> ignored by bound_qualifications
        self.run_qual("package.render", trust_root="hosted-candidate-unattested")
        self.assertEqual(bound_qualifications(self.capture, self.output, "package.render"), [])

        # 3. attended-local-rerun -> accepted by bound_qualifications
        row = self.run_qual("package.render", trust_root="attended-local-rerun")
        h = record_sha256(row)
        bound = bound_qualifications(self.capture, self.output, "package.render")
        self.assertEqual(bound, [h])

    def test_provider_and_hosted_diagnostic_records_cannot_mint_mandatory_gates(self):
        self.capture._qualification_records = []
        
        r1 = self.run_qual("license.authority", trust_root="provider-local-unattested")
        r2 = self.run_qual("package.render", trust_root="provider-local-unattested")
        
        policy = destination_policy(external_evidence={
            "license.authority": [record_sha256(r1)],
            "package.render": [record_sha256(r2)],
        })
        gates = copy.deepcopy(self.gates)
        gates[1] = gate("license.authority", "pass", "tenant", [
            {"kind": "profile-result", "sha256": record_sha256(self.profile)},
            {"kind": "qualification-record", "sha256": record_sha256(r1)}
        ], reason="attempt-diagnostic-gate")
        gates[2] = gate("package.render", "pass", self.output["destination"]["adapter"], [
            {"kind": "source-manifest", "sha256": self.output["source_manifest_sha256"]},
            {"kind": "qualification-record", "sha256": record_sha256(r2)}
        ], reason="attempt-diagnostic-gate")

        _, reasons = check_gates(self.intent, self.capture, self.profile, self.output, gates, policy)
        self.assertIn("execution-evidence-unbound:license.authority", reasons)
        self.assertIn("execution-evidence-unbound:package.render", reasons)

    def test_hosted_candidate_diagnostic_records_cannot_mint_mandatory_gates(self):
        self.capture._qualification_records = []
        r1 = self.run_qual("license.authority", trust_root="hosted-candidate-unattested")
        r2 = self.run_qual("package.render", trust_root="hosted-candidate-unattested")
        
        policy = destination_policy(external_evidence={
            "license.authority": [record_sha256(r1)],
            "package.render": [record_sha256(r2)],
        })
        gates = copy.deepcopy(self.gates)
        gates[1] = gate("license.authority", "pass", "tenant", [
            {"kind": "profile-result", "sha256": record_sha256(self.profile)},
            {"kind": "qualification-record", "sha256": record_sha256(r1)}
        ], reason="attempt-hosted-gate")
        gates[2] = gate("package.render", "pass", self.output["destination"]["adapter"], [
            {"kind": "source-manifest", "sha256": self.output["source_manifest_sha256"]},
            {"kind": "qualification-record", "sha256": record_sha256(r2)}
        ], reason="attempt-hosted-gate")

        _, reasons = check_gates(self.intent, self.capture, self.profile, self.output, gates, policy)
        self.assertIn("execution-evidence-unbound:license.authority", reasons)
        self.assertIn("execution-evidence-unbound:package.render", reasons)

    def test_attended_local_rerun_satisfies_mandatory_gates(self):
        self.capture._qualification_records = []
        r1 = self.run_qual("license.authority", trust_root="attended-local-rerun")
        r2 = self.run_qual("package.render", trust_root="attended-local-rerun")
        
        policy = destination_policy(external_evidence={
            "license.authority": [record_sha256(r1)],
            "package.render": [record_sha256(r2)],
        })
        gates = copy.deepcopy(self.gates)
        gates[1] = gate("license.authority", "pass", "tenant", [
            {"kind": "profile-result", "sha256": record_sha256(self.profile)},
            {"kind": "qualification-record", "sha256": record_sha256(r1)}
        ], reason="attended-local-gate")
        gates[2] = gate("package.render", "pass", self.output["destination"]["adapter"], [
            {"kind": "source-manifest", "sha256": self.output["source_manifest_sha256"]},
            {"kind": "qualification-record", "sha256": record_sha256(r2)}
        ], reason="attended-local-gate")

        _, reasons = check_gates(self.intent, self.capture, self.profile, self.output, gates, policy)
        self.assertNotIn("execution-evidence-unbound:license.authority", reasons)
        self.assertNotIn("execution-evidence-unbound:package.render", reasons)

    def test_tampered_qualification_record_rejected_in_bound_qualifications(self):
        self.capture._qualification_records = []
        self.run_qual("package.render", trust_root="attended-local-rerun")
        self.capture._qualification_records[0].record["gate"] = "tampered"
        with self.assertRaises(ContractError) as ctx:
            bound_qualifications(self.capture, self.output, "package.render")
        self.assertEqual(ctx.exception.code, "QUALIFICATION_CHANGED")

    def test_forged_proof_ignored(self):
        self.capture._qualification_records = [
            Qualification({"gate": "package.render", "trust_root": "attended-local-rerun"})
        ]
        self.assertEqual(bound_qualifications(self.capture, self.output, "package.render"), [])
