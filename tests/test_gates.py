from pathlib import Path
import tempfile
import unittest

from rs9.errors import ContractError
from rs9.gates import gate, derive_gates
from rs9.planner import plan
from rs9.release_core import authenticated_record_hash
from tests.publication_fixtures import fixture, observation, T0


class GateTests(unittest.TestCase):
    def test_statuses_and_evidence(self):
        for status in ("fail", "not-run", "not-applicable", "deferred"):
            self.assertEqual(gate("platform.install", status, "linux", reason="fixture")["status"], status)
        with self.assertRaises(ContractError): gate("release.authenticated", "pass", "release", reason="fixture")
        with self.assertRaises(ContractError): gate("release.authenticated", "PASS", "release", reason="fixture")

    def test_json_and_modified_capture_cannot_authorize(self):
        with tempfile.TemporaryDirectory() as tmp:
            intent, capture, profile, output, gates, policy = fixture(Path(tmp).resolve())
            with self.assertRaises(ContractError): authenticated_record_hash(capture.record)
            capture.record["release"]["id"] = 900
            with self.assertRaises(ContractError): authenticated_record_hash(capture)

    def test_unbound_missing_not_run_and_deferred_gates_block(self):
        with tempfile.TemporaryDirectory() as tmp:
            intent, capture, profile, output, gates, policy = fixture(Path(tmp).resolve())
            for values in ([], [gate("release.authenticated", "pass", "release", [{"kind": "release-record", "sha256": "a" * 64}], reason="fixture"), *gates[1:]],
                           [*gates[:2], gate("package.render", "not-run", "registry", reason="fixture")],
                           [*gates[:2], gate("package.render", "deferred", "registry", reason="fixture")]):
                result = plan(intent, capture, profile, output, values, policy, observation(output), evaluated_at=T0)
                self.assertEqual(result["outcome"], "block-gate")

    def test_required_external_trust_gate_binds_operator_evidence(self):
        from rs9.planner import destination_policy
        with tempfile.TemporaryDirectory() as tmp:
            intent, capture, profile, output, gates, policy = fixture(Path(tmp).resolve())
            trust = gate("trust.signature", "pass", "registry", [{"kind": "signature-receipt", "sha256": "c" * 64}], reason="operator-bound")
            for external, outcome in (({}, "block-gate"), ({"trust.signature": ["c" * 64]}, "block-gate")):
                authority = policy["external_evidence"]["license.authority"]
                policy = destination_policy(required_gates=["trust.signature"], external_evidence={**policy["external_evidence"], **external})
                result = plan(intent, capture, profile, output, [*gates, trust], policy, observation(output), evaluated_at=T0)
                self.assertEqual(result["outcome"], outcome)

    def test_license_agreement_alone_does_not_authorize(self):
        from rs9.planner import destination_policy
        with tempfile.TemporaryDirectory() as tmp:
            intent,capture,profile,output,gates,policy=fixture(Path(tmp).resolve())
            derived=derive_gates(intent,capture,profile,output)
            self.assertEqual(derived[1]["status"],"not-run")
            result=plan(intent,capture,profile,output,gates,destination_policy(),observation(output),evaluated_at=T0)
            self.assertEqual(result["outcome"],"block-gate")
