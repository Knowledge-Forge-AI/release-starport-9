"""071 OS joins using real core capture mechanisms and explicit synthetic bytes.

Fixture captures and source-only guest proofs never qualify released products.
Actual private byte readback is separately retained by the preparation packet.
"""
import copy
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from rs9 import current_os071 as pins
from rs9 import hosted_smoke as smoke
from rs9 import nebular_callers as callers
from rs9 import smoke_source_envelope as envelope
from rs9.bootstrap import checked_bootstrap_configurations, require_configuration_authority
from rs9.current_generation import CURRENT_GENERATION, HISTORICAL_GENERATION, generation_paths
from rs9.errors import ContractError
from rs9.profiles import evaluate_profile, PACKAGE_PROFILE
from rs9.release_core import authenticated_record_hash, digest
from rs9.scratch import canonical
from tests.test_sidecar_harness_closure import current_import_fixture
from tests.test_nebular_callers import current_caller_fixture
import tests.test_nebular_callers as caller_fixtures
import tests.test_current_replay_progress as replay_fixtures
from rs9 import application_smoke_diagnostic as diagnostic

ROOT = Path(__file__).resolve().parents[1]


class Current071OsTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()

    def fixture(self):
        capture, captures, client, contract, sources, fixtures = current_import_fixture(self.root, "0.7.1")
        for target, value in (("rs9.nebular_callers._load_current071_contract", contract),
                              ("rs9.hosted_smoke.CURRENT071_VERIFIER_FILES", sources),
                              ("rs9.hosted_smoke.CURRENT070_FIXTURE_FILES", fixtures)):
            patcher = patch(target, return_value=value) if target.endswith("_load_current071_contract") else patch(target, value)
            patcher.start(); self.addCleanup(patcher.stop)
        prepared = smoke.prepare_smoke(capture, captures, client, self.root / "prepared")
        return capture, prepared

    def test_actual_source_metadata_and_unchanged_cli_coordinates(self):
        self.assertEqual(pins.CURRENT071_COMMIT, "f2c527ee6f3cbd53fd44e095d5355ca7f5c7519a")
        self.assertEqual(pins.CURRENT071_TREE, "6e3561855f6ee0093fb709488ad976b69bf501d2")
        self.assertEqual(set(pins.CURRENT071_VERIFIER_IMPORTS), set(pins.CURRENT071_VERIFIER_FILES)-{"package.json"})
        self.assertTrue(all(set(edges) <= set(pins.CURRENT071_VERIFIER_IMPORTS)
                            for edges in pins.CURRENT071_VERIFIER_IMPORTS.values()))
        self.assertEqual(len(pins.CURRENT071_REPLAY_PROGRESS_PROFILE["modules"]), 7)
        self.assertEqual(pins.CURRENT071_REPLAY_PROGRESS_PROFILE["support"], pins.CURRENT071_VERIFIER_FILES["package.json"])
        wrapper=Path(diagnostic.__file__).with_name("replay_progress_wrapper.mjs").read_text()
        marker="const CURRENT071_PROFILE = Object.freeze("
        start=wrapper.index(marker)+len(marker);end=wrapper.index(");\n",start)
        self.assertEqual(json.loads(wrapper[start:end]),pins.CURRENT071_REPLAY_PROGRESS_PROFILE)
        manifest, _ = generation_paths(CURRENT_GENERATION)
        configs = checked_bootstrap_configurations(ROOT/manifest,
            approved_manifests=[digest((ROOT/manifest).read_bytes())])
        versions = {intent["project"]["id"]:intent["version"] for _,intent in configs}
        self.assertEqual(versions, {"theme-forge-stellar-burst":"0.7.0","theme-forge-stellar-loom":"0.5.0",
            "theme-forge-solar-sail":"0.3.0","theme-forge-nebular-fusion":"0.7.1"})
        self.assertEqual(generation_paths(HISTORICAL_GENERATION)[0], "bootstrap/pre-rs9/theme-forge-live1/manifest-author-aligned.json")
        with self.assertRaises(ContractError): generation_paths("0.7.1")

    def test_real_core_capture071_and_source_only_guest_roundtrip(self):
        capture, prepared = self.fixture()
        self.assertEqual(prepared["capture"], capture)
        data = smoke.export_current_source_readback(prepared)
        self.assertEqual(data["producers"]["nebular"]["tag"], "v0.7.1")
        self.assertEqual(data["producers"]["nebular"]["commit"], pins.CURRENT071_COMMIT)
        serialized = json.loads(canonical(data))
        proof = envelope.mint_guest_readback(serialized, prepared["source"], prepared["tools"])
        guest = {"source_readback": serialized, "records": serialized["records"], "source_generation":envelope.GENERATION,
                 "source":prepared["source"],"tools":prepared["tools"],"container_client":True,"_source_readback_proof":proof}
        self.assertEqual(envelope.verify_guest_prepared(guest), digest(canonical(data)))
        for operation in (lambda: authenticated_record_hash(proof),lambda: require_configuration_authority(proof, {}),
                          lambda: evaluate_profile(proof, PACKAGE_PROFILE, {}),lambda: smoke.export_current_source_readback(guest)):
            with self.assertRaises(ContractError): operation()

    def test_mixed_generation_or_changed_source_refuses_before_import(self):
        _, prepared = self.fixture()
        data = smoke.export_current_source_readback(prepared)
        for change in ("producer", "record", "extra", "unknown", "malformed"):
            value = copy.deepcopy(data)
            if change == "producer": value["producers"]["nebular"]["commit"] = smoke.CURRENT070_COMMIT
            elif change == "record": value["records"][0]["tag_commit"] = smoke.CURRENT070_COMMIT
            elif change == "extra": value["records"].append(copy.deepcopy(value["records"][0]))
            elif change == "unknown":
                for row in value["records"]:
                    if row["role"] != "fixture": row["tag_commit"] = "0"*40
            else: value["records"][0]["tag_commit"] = []
            with self.subTest(change=change), self.assertRaises(ContractError): envelope.checked_envelope(value)
        (prepared["source"]/"package.json").write_bytes(b'{"version":"0.7.0"}')
        with patch.object(smoke,"_run_verifier") as imported, self.assertRaises(ContractError):
            smoke.verifier_import_preflight(prepared,"x86_64-linux")
        imported.assert_not_called()

    def test_actual071_contract_and_frozen070_remain_distinct(self):
        old = callers._load_current_contract(); new = callers._load_current071_contract()
        self.assertEqual(old["identity"]["tag"],"v0.7.0")
        self.assertEqual(new["identity"]["tag"],"v0.7.1")
        self.assertEqual(new["identity"]["commit"],pins.CURRENT071_COMMIT)
        for platform in new["platforms"].values():
            self.assertEqual(platform["runtime"]["version"],"22.23.4")
            self.assertGreater(platform["asset"]["github_asset_id"],0)
        shared=set(new["source_files"]) & set(pins.CURRENT071_VERIFIER_FILES)
        self.assertTrue(shared)
        for name in shared:self.assertEqual(new["source_files"][name],pins.CURRENT071_VERIFIER_FILES[name])
        for system,platform in new["platforms"].items():
            for member,source in ((callers.PAYLOAD+"/loom-adapter/theme-adapter.mjs","src-tauri/loom-adapter/theme-adapter.mjs"),
                                  (callers.PAYLOAD+"/solar-sail-adapter/solar-sail-adapter.mjs","src-tauri/solar-sail-adapter/solar-sail-adapter.mjs")):
                self.assertEqual(platform["members"][member]["sha256"],new["source_files"][source]["sha256"])

    def test071_caller_requires_live_core_capture_and_exact_version(self):
        capture, contract, client, inventory, inputs = current_caller_fixture(self.root,tag="v0.7.1",
            tag_commit=pins.CURRENT071_COMMIT,tag_tree=pins.CURRENT071_TREE,version="0.7.1",release_id=429782340)
        with patch.object(callers,"_load_current071_contract",return_value=contract):
            evidence=callers.collect_caller_sources(capture,client,self.root/"caller-source")
            self.assertEqual(evidence["status"],"available",evidence.get("reason"))
            inventory["caller_evidence"]=evidence
            helper=caller_fixtures.CurrentNebularCallerTests()
            proof,reason=helper.proof(contract,inventory,inputs)
            self.assertIsNone(reason);self.assertEqual(proof["tag_commit"],pins.CURRENT071_COMMIT)
            for key,value in (("version","0.7.0"),("asset_sha256","0"*64)):
                with self.subTest(key=key):self.assertIsNone(helper.proof(contract,inventory,{**inputs,key:value})[0])
            inventory["caller_evidence"]=json.loads(canonical(evidence))
            self.assertIsNone(helper.proof(contract,inventory,inputs)[0])

    def test_old_rpm_disposition_does_not_authorize071(self):
        from rs9.rpm_lint_policy import load_policy, evaluate_policy
        from tests.test_current_rpm_preservation_policy import actual_case
        policy = load_policy(generation=CURRENT_GENERATION)
        self.assertEqual(policy["projects"]["theme-forge-nebular-fusion"]["version"], "0.7.0")
        case = actual_case("theme-forge-nebular-fusion", "x86_64-linux")
        inputs = {**case["inputs"], "version": "0.7.1"}
        result = evaluate_policy(case["raw"], case["inventory"], inputs, policy, generation=CURRENT_GENERATION)
        self.assertFalse(result["accepted"])
        self.assertIn("project-version-platform-mismatch", result["blockers"])
        self.assertNotIn("malformed-or-unavailable-policy-evidence", result["blockers"])

    def test071_replay_profile_requires_real_capture_and_exact_closed_bytes(self):
        _, prepared = self.fixture()
        profile = copy.deepcopy(pins.CURRENT071_REPLAY_PROGRESS_PROFILE)
        source = prepared["source"]
        profile["modules"] = {name: replay_fixtures.pin((source/"tools"/name).read_bytes()) for name in profile["modules"]}
        profile["support"] = replay_fixtures.pin((source/"package.json").read_bytes())
        with patch.object(diagnostic,"CURRENT071_REPLAY_PROGRESS_PROFILE",profile):
            self.assertEqual(diagnostic._current_replay_progress_profile(prepared),profile)
            plain={k:v for k,v in prepared.items() if k not in {"capture","fixture_capture"}}
            self.assertIsNone(diagnostic._current_replay_progress_profile(plain))
            changed=copy.deepcopy(profile);changed["modules"]["native-rc-smoke.mjs"]["blob"]="0"*40
            with patch.object(diagnostic,"CURRENT071_REPLAY_PROGRESS_PROFILE",changed):
                self.assertIsNone(diagnostic._current_replay_progress_profile(prepared))

    def test071_inert_node_observer_preserves_hooks_streams_and_failed_status(self):
        fixture=replay_fixtures.CurrentReplayWrapperTests()
        fixture.setUp();self.addCleanup(fixture.doCleanups)
        for path in fixture.source.rglob("*"):
            if path.is_file():path.write_bytes(path.read_bytes().replace(b"0.7.0",b"0.7.1"))
        fixture.profile=copy.deepcopy(pins.CURRENT071_REPLAY_PROGRESS_PROFILE)
        fixture.profile["modules"]={name:replay_fixtures.pin((fixture.tools/name).read_bytes()) for name in fixture.profile["modules"]}
        fixture.profile["support"]=replay_fixtures.pin((fixture.source/"package.json").read_bytes())
        source=Path(diagnostic.__file__).with_name("replay_progress_wrapper.mjs").read_text()
        start=source.index("const CURRENT071_PROFILE = Object.freeze(");end=source.index(");\n",start)+3
        fixture.wrapper.write_text(source[:start]+"const CURRENT071_PROFILE = Object.freeze("+json.dumps(fixture.profile)+");\n"+source[end:])
        fixture.test_current_spawn_write_and_marker_hooks_preserve_streams_and_fail_status()
        # Exact source selection refuses before the import hook gets a chance.
        command=fixture.command();at=command.index("--rs9-replay-progress-source-tree")+1;command[at]="0"*40
        result=fixture.run_wrapper(command)
        self.assertEqual(result.returncode,1);self.assertEqual(result.stdout,b"")

    def test071_contract_tamper_and_wrong_source_coordinates_refuse(self):
        changed=self.root/"changed-caller.json"
        changed.write_bytes(callers.CURRENT071_CONTRACT_PATH.read_bytes()+b" ")
        with patch.object(callers,"CURRENT071_CONTRACT_PATH",changed),self.assertRaises(ContractError):
            callers._load_current071_contract()
        for label,arguments in (("tag",{"tag":"v0.7.0"}),
                                 ("commit",{"tag_commit":"0"*40}),
                                 ("tree",{"tag_tree":"0"*40}),
                                 ("release",{"release_id":426333162})):
            root=self.root/label;root.mkdir()
            values=dict(tag="v0.7.1",tag_commit=pins.CURRENT071_COMMIT,
                        tag_tree=pins.CURRENT071_TREE,version="0.7.1",release_id=429782340)
            values.update(arguments)
            capture,contract,client,_,_=current_caller_fixture(root,**values)
            with self.subTest(label=label),patch.object(callers,"_load_current071_contract",return_value=contract),self.assertRaises(ContractError):
                callers.current_contract_for_capture(capture)
