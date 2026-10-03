import copy
from pathlib import Path
import tempfile
import unittest

from rs9.errors import ContractError
from rs9.gates import derive_gates
from rs9.ingestion import authenticate
from rs9.planner import plan, destination_policy, allocate_revision, adapter_outputs_from_shadow, safe_repair_contract
from rs9.records import record_sha256
from rs9.records import semantic_identity_sha256
from rs9.render import render
from rs9.scratch import canonical
from tests.publication_fixtures import fixture, observation, make_plan, T0, T1
from tests.shadow_fixtures import fixture_evidence


class PlannerTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name).resolve()
        self.bundle = fixture(self.root)

    def test_outcomes_and_gate_precedence(self):
        for state, outcome in (("absent", "publish-intent"), ("exact", "noop"), ("conflict", "block-conflict"),
                               ("unknown", "defer-readback"), ("unreachable", "defer-readback"), ("incomplete", "block")):
            self.assertEqual(make_plan(self.bundle, state)["outcome"], outcome)
        n, cap, profile, output, gates, policy = self.bundle
        self.assertEqual(plan(n, cap, profile, output, [], policy, observation(output,"exact"), evaluated_at=T0)["outcome"], "noop")
        self.assertEqual(plan(n, cap, profile, output, gates, destination_policy(enabled=False), observation(output), evaluated_at=T0)["outcome"], "block")

    def test_stale_and_future_exact_are_deferred(self):
        for state in ("exact", "absent", "conflict"):
            self.assertEqual(make_plan(self.bundle, state, evaluation="2026-10-03T12:10:00Z")["outcome"], "defer-readback")
            self.assertEqual(make_plan(self.bundle, state, at=T1, evaluation=T0)["outcome"], "defer-readback")

    def test_determinism_under_gate_and_artifact_permutation(self):
        n, cap, profile, output, gates, policy = self.bundle
        first = make_plan(self.bundle)
        second = plan(n,cap,profile,output,list(reversed(gates)),policy,observation(output),evaluated_at=T0)
        self.assertEqual(canonical(first),canonical(second))
        self.assertNotIn("success", first)
        self.assertEqual(first["inputs"]["observation_sha256"],record_sha256(first["observation"]))

    def test_repair_requires_same_named_adapter_and_policy_contract(self):
        n, cap, profile, output, gates, policy = self.bundle
        output["repair_contract"] = safe_repair_contract("repository-index-repair.v1", output["destination"]["adapter"], [row["path"] for row in output["artifacts"]])
        for contract, outcome in ((None,"block"),("different.v1","block"),("repository-index-repair.v1","repair-intent")):
            result = plan(n,cap,profile,output,gates,destination_policy(repair_contract=contract,external_evidence=policy["external_evidence"]),observation(output,"incomplete"),evaluated_at=T0)
            self.assertEqual(result["outcome"],outcome)

    def test_unbound_output_profile_and_subject_rejected(self):
        n, cap, profile, output, gates, policy = self.bundle
        changed = copy.deepcopy(profile);changed["sections"]["license"]["status"] = "conflict"
        with self.assertRaises(ContractError): plan(n,cap,changed,output,gates,policy,observation(output),evaluated_at=T0)
        changed=copy.deepcopy(output);changed["content_identity_sha256"]="a"*64
        with self.assertRaises(ContractError): plan(n,cap,profile,changed,gates,policy,observation(output),evaluated_at=T0)
        changed=observation(output);changed["subject"]["version"]="2.0"
        with self.assertRaises(ContractError): plan(n,cap,profile,output,gates,policy,changed,evaluated_at=T0)
        changed=observation(output);changed["state"]="exact"
        with self.assertRaises(ContractError): plan(n,cap,profile,output,gates,policy,changed,evaluated_at=T0)
        changed=copy.deepcopy(output["semantic_identity"])
        changed["artifact_payload_hashes"][next(iter(changed["artifact_payload_hashes"]))]="c"*64
        self.assertNotEqual(semantic_identity_sha256(changed),output["content_identity_sha256"])
        altered=copy.deepcopy(n);altered["version"]="0.6.2"
        with self.assertRaises(ContractError): plan(altered,cap,profile,output,gates,policy,observation(output),evaluated_at=T0)

    def test_multi_destination_partial_fanout(self):
        n,cap,profile,output,gates,policy=self.bundle
        other=copy.deepcopy(output);other["destination"]["id"]="second"
        plans=[plan(n,cap,profile,output,gates,policy,observation(output,"exact"),evaluated_at=T0),
               plan(n,cap,profile,other,gates,policy,observation(other),evaluated_at=T0)]
        self.assertEqual([row["outcome"] for row in plans],["noop","publish-intent"])

    def test_revision_allocation_conflict_reuse_and_rerender(self):
        identity="a"*64
        row={"revision":1,"content_identity_sha256":identity,"complete":True}
        self.assertEqual(allocate_revision("pkgrel",[],identity)["output"],{"revision":1,"basis":"first"})
        self.assertEqual(allocate_revision("pkgrel",[row],identity)["output"]["basis"],"reuse-exact")
        row["content_identity_sha256"]="b"*64
        self.assertEqual(allocate_revision("pkgrel",[row],identity,immutable=False)["output"]["revision"],2)
        self.assertEqual(allocate_revision("pkgrel",[row],identity,pinned=1,immutable=False)["output"]["basis"],"pinned-conflict")
        self.assertEqual(allocate_revision("none",[row],identity)["output"]["basis"],"immutable-conflict")
        with self.assertRaises(ContractError): allocate_revision("pkgrel",[row,row],identity)
        n,cap,profile,output,gates,policy=self.bundle
        output["revision_scheme"]="pkgrel";output["subject"]["revision"]=1
        obs=observation(output,revisions=[row])
        result=plan(n,cap,profile,output,gates,destination_policy(immutable_versions=False,external_evidence=policy["external_evidence"]),obs,evaluated_at=T0)
        self.assertEqual(result["outcome"],"block")
        self.assertEqual(result["revision_allocation"]["output"]["revision"],2)

    def test_projection_base_and_allowed_path_components(self):
        n,cap,profile,output,gates,policy=self.bundle
        output["destination"]["mode"]="projection"
        obs=observation(output,remote={"commit":"a"*40})
        for paths,outcome in ((["packages"],"publish-intent"),(["package"],"block"),([],"block")):
            policy=destination_policy(base_commit="a"*40,allowed_paths=paths,external_evidence=policy["external_evidence"])
            self.assertEqual(plan(n,cap,profile,output,gates,policy,obs,evaluated_at=T0)["outcome"],outcome)
        policy=destination_policy(base_commit="b"*40,allowed_paths=["packages"],external_evidence=policy["external_evidence"])
        self.assertEqual(plan(n,cap,profile,output,gates,policy,obs,evaluated_at=T0)["outcome"],"defer-readback")

    def test_contribution_pr_state_is_separate(self):
        n,cap,profile,output,gates,policy=self.bundle
        output["destination"]["mode"]="contribution"
        obs=observation(output,contribution={"pr_id":"42","state":"open"})
        res=plan(n,cap,profile,output,gates,policy,obs,evaluated_at=T0)
        self.assertEqual(res["outcome"],"block");self.assertEqual(res["observation"]["state"],"absent")
        self.assertEqual(res["contribution"]["state"],"open")

    def test_nebular_shadow_binding_license_block_and_revision_independent_identity(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp).resolve();evidence=root/"evidence";evidence.mkdir()
            intent=fixture_evidence(evidence);auth=authenticate(intent,evidence)
            first=root/"first";second=root/"second";first.mkdir();second.mkdir()
            one=adapter_outputs_from_shadow(auth,render(auth,first,revision=1))
            two=adapter_outputs_from_shadow(auth,render(auth,second,revision=2))
            self.assertEqual([r["content_identity_sha256"] for r in one],[r["content_identity_sha256"] for r in two])
            self.assertNotEqual(one[0]["artifacts"],two[0]["artifacts"])
            output=next(row for row in one if row["destination"]["mode"]=="direct")
            gates=derive_gates(intent,auth.release_capture,auth.profile_result,output)
            res=plan(intent,auth.release_capture,auth.profile_result,output,gates,destination_policy(),observation(output),evaluated_at=T0,ingestion_record=auth.record)
            self.assertEqual(res["outcome"],"block-gate")
            self.assertIn("tenant-license-unresolved",res["reasons"])
