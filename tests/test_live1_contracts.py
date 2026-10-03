"""LIVE1 authority regressions; synthetic execution never qualifies live lanes."""
import copy
import json
from pathlib import Path
import tempfile
import unittest

from rs9.adapter_gates import mandatory_gates
from rs9.bootstrap import configuration_inventory, load_bootstrap, require_release_configuration
from rs9.errors import ContractError
from rs9.gates import derive_gates, gate
from rs9.npm_deps import runtime_closure
from rs9.planner import destination_policy, plan
from rs9.profiles import selection_for_intent
from rs9.publication import mutation_attempt, publication_receipt
from rs9.qualification import Qualification, artifact_inventory
from rs9.records import record_sha256
from rs9.release_core import digest
from rs9.scratch import canonical
from tests.publication_fixtures import fixture, make_plan, observation, T0, T1, T2, T3


class LiveContracts(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name).resolve()
        self.bundle = fixture(self.root)

    def test_renderer_verdict_and_hash_only_cannot_authorize(self):
        n,c,p,o,g,policy = self.bundle
        self.assertEqual(derive_gates(n,c,p,o)[2]["status"], "not-run")
        c._qualification_records = []
        self.assertEqual(make_plan(self.bundle)["outcome"], "block-gate")
        c._qualification_records = [Qualification({"gate": "package.render"})]
        self.assertEqual(make_plan(self.bundle)["outcome"], "block-gate")

    def test_execution_record_mutation_rejected(self):
        n,c,p,o,g,policy = self.bundle
        c._qualification_records[0].record["host"]["os"] = "forged"
        with self.assertRaises(ContractError): make_plan(self.bundle)

    def test_source_and_tree_change_after_authentication_are_rejected(self):
        from rs9.release_core import authenticated_record_hash, authenticated_tree
        capture=self.bundle[1]
        tree_path=capture.root/"api/tree.json"
        tree=json.loads(tree_path.read_bytes());tree["tree"].append({"path":"changed","type":"blob"})
        tree_path.write_bytes(canonical(tree))
        with self.assertRaises(ContractError):authenticated_tree(capture)
        source_path=next(iter(capture.source));capture.source[source_path]=b"changed"
        with self.assertRaises(ContractError):authenticated_record_hash(capture)

    def test_independent_inventory_rejects_tamper(self):
        output = self.bundle[3]
        (self.root / output["artifacts"][0]["path"]).write_bytes(b"tampered")
        with self.assertRaises(ContractError): artifact_inventory(self.root, output["artifacts"])

    def test_adapter_gate_cannot_be_waived(self):
        n,c,p,o,g,policy = self.bundle
        o = copy.deepcopy(o)
        o["destination"]["adapter"] = o["semantic_identity"]["adapter"] = "pypi"
        o["content_identity_sha256"] = record_sha256(o["semantic_identity"])
        policy = destination_policy(allow_not_applicable=mandatory_gates(n,"pypi"))
        values = [gate(k,"not-applicable","pypi",reason="fixture") for k in mandatory_gates(n,"pypi")]
        result = plan(n,c,p,o,values,policy,observation(o),evaluated_at=T0)
        self.assertEqual(result["outcome"], "block-gate")
        self.assertIn("status:pypi.trusted-publisher:not-applicable", result["reasons"])

    def test_observe_only_exact_noop_absent_block_conflict_preserved(self):
        n,c,p,o,g,policy = self.bundle
        policy = destination_policy(mode="observe-only")
        for state, expected in (("exact","noop"),("absent","block"),("conflict","block-conflict"),("unknown","defer-readback")):
            self.assertEqual(plan(n,c,p,o,g,policy,observation(o,state),evaluated_at=T0)["outcome"], expected)

    def test_synthetic_or_asserted_live_json_never_published(self):
        result = make_plan(self.bundle)
        attempt = mutation_attempt(result,executor_role="operator",started_at=T1,finished_at=T2,transport_outcome="confirmed")
        post = observation(self.bundle[3],"exact",at=T3)
        for source in ("synthetic-fixture", "live-read"):
            post["source"] = source
            post["reader"] = {"id":"pypi-json-files","version":"v1alpha1"}
            self.assertNotEqual(publication_receipt(result,[attempt],post)["final_state"], "published")

    def make_bootstrap(self):
        n,c,*_ = self.bundle
        config = self.root / "bootstrap" / "project"
        config.mkdir(parents=True)
        (config / "intent.json").write_bytes(canonical(n))
        row = {"repository":c.record["repository"]["full_name"],"repository_id":c.record["repository"]["id"],
               "release_id":c.record["release"]["id"],"tag":n["tag"],"version":n["version"],
               "tag_commit":c.record["tag"]["commit"],"tag_tree":c.record["tag"]["tree"],
               "configuration":"project","config_sha256":record_sha256(configuration_inventory(config))}
        manifest = {"schema":"rs9.bootstrap-tenant-manifest.v1alpha1","bootstrap-pre-rs9":True,
                    "release-contains-rs9":False,"scope":"exact-generation","future-releases":"forbidden","projects":[row]}
        path = config.parent / "manifest.json"
        path.write_bytes(canonical(manifest))
        return path,c,manifest

    def test_bootstrap_exact_and_allowlist_required(self):
        path,c,_ = self.make_bootstrap()
        sha = digest(path.read_bytes())
        self.assertEqual(load_bootstrap(path,c,approved_manifests=[sha]),self.bundle[0])
        with self.assertRaises(ContractError): load_bootstrap(path,c,approved_manifests=[])
        (path.parent / "project/intent.json").write_bytes(b"{}")
        with self.assertRaises(ContractError): load_bootstrap(path,c,approved_manifests=[sha])

    def test_bootstrap_wrong_generation_and_release_owned_configuration(self):
        path,c,manifest = self.make_bootstrap()
        for key in ("tag", "version", "release_id", "tag_commit", "tag_tree"):
            changed=copy.deepcopy(manifest)
            changed["projects"][0][key] = "changed"
            path.write_bytes(canonical(changed))
            with self.assertRaises(ContractError): load_bootstrap(path,c,approved_manifests=[digest(path.read_bytes())])
        path.write_bytes(canonical(manifest))
        tree_path=c.root / "api/tree.json"
        tree=json.loads(tree_path.read_bytes());tree["tree"].append({"path":".rs9/project.toml","type":"blob"})
        tree_path.write_bytes(canonical(tree))
        with self.assertRaises(ContractError): load_bootstrap(path,c,approved_manifests=[digest(path.read_bytes())])

    def test_future_release_configuration_required(self):
        with self.assertRaises(ContractError): require_release_configuration(self.bundle[1])

    def test_tagged_runtime_lock_closure_exact_and_transitive(self):
        package={"dependencies":{"one":"1.2.3"}}
        row=lambda v:{"version":v,"resolved":"https://registry.npmjs.org/one/-/one.tgz","integrity":"sha512-YQ=="}
        lock={"lockfileVersion":3,"packages":{"":{"dependencies":package["dependencies"]},"node_modules/one":row("1.2.3"),"node_modules/two":row("2.0.0")}}
        lock["packages"]["node_modules/one"]["dependencies"]={"two":"^2"}
        self.assertEqual([r["path"] for r in runtime_closure(package,lock)],["node_modules/one","node_modules/two"])
        lock["packages"][""]["dependencies"]={"one":"1.2.4"}
        with self.assertRaises(ContractError): runtime_closure(package,lock)

    def test_bootstrap_inventory_hashes_match_checked_in_manifest(self):
        root=Path(__file__).resolve().parents[1]/"bootstrap/pre-rs9/theme-forge-live1"
        manifest=json.loads((root/"manifest.json").read_bytes())
        for row in manifest["projects"]:
            self.assertEqual(record_sha256(configuration_inventory(root/row["configuration"])),row["config_sha256"])

    def test_repository_license_authority_retains_npm_conflict(self):
        from tests.shadow_fixtures import fixture_evidence
        from rs9.profiles import TAURI_AUTHORITY_PROFILE, evaluate_profile
        from rs9.release_core import authenticate_release
        evidence=self.root/"nebular"
        evidence.mkdir()
        intent=fixture_evidence(evidence)
        npm_path=evidence/"npm/metadata.json"
        npm=json.loads(npm_path.read_bytes());npm["license"]="AGPL-3.0-or-later OR Commercial"
        npm_path.write_bytes(canonical(npm))
        intent["release"]["evidence"]["profile"] = TAURI_AUTHORITY_PROFILE
        capture=authenticate_release(selection_for_intent(intent),evidence)
        profile=evaluate_profile(capture,TAURI_AUTHORITY_PROFILE,intent)
        license=profile["sections"]["legacy_ingestion"]["license"]
        self.assertEqual(license["status"],"consistent")
        self.assertEqual(license["authority"],"tagged-repository")
        self.assertTrue(any(r["expression"]=="AGPL-3.0-or-later OR Commercial" for r in license["downstream_metadata_conflicts"]))
