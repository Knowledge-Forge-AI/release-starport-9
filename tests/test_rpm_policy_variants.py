"""Private proposal semantics; synthetic core captures never qualify products."""
import copy
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from rs9 import rpm_lint_policy as policy
from rs9 import nebular_callers as callers
from rs9.current_generation import CURRENT_GENERATION, HISTORICAL_GENERATION, configuration_paths, rpm_policy_path
from rs9.errors import ContractError
from rs9.hosted_summary import validate_rpm_policy_source
from rs9.release_core import authenticate_release, authenticated_record_hash, digest
from rs9.profiles import selection_for_intent
from rs9.scratch import canonical
from tests.release_fixtures import package_evidence
from tests.test_nebular_callers import current_caller_fixture
from tests.test_current_rpm_preservation_policy import actual_case

ROOT = Path(__file__).resolve().parents[1]
NEBULAR = 'theme-forge-nebular-fusion'


def receipt(selected, system='x86_64-linux'):
    """Source/digest test envelope only: no raw/native/custody/pass claims."""
    rows = {}
    for product, entry in selected['projects'].items():
        auth = entry['authenticated_inputs']
        asset = auth.get('asset_sha256') or next(x['sha256'] for x in auth['assets']
            if system.removesuffix('-linux')+'-unknown-linux-gnu' in x['name'])
        rows[product] = {'product':product, 'policy_sha256':digest(canonical(selected)),
            'inputs':{'project_id':product,'version':entry['version'],'system':system,
                'arch':system.removesuffix('-linux') if product in (NEBULAR,'theme-forge-stellar-burst') else 'noarch',
                'asset_sha256':asset,'closure_sha256':auth.get('closure_sha256'),
                'payload_manifest_sha256':entry['inventory_bindings'][system]['payload_manifest_sha256']}}
    return {'lane':'rpm','system':system,'details':{'rpm_lint_policy':rows}}


class PolicyVariantTests(unittest.TestCase):
    def test_default070_and_historical_and_cli_entries_unchanged(self):
        old=policy.load_policy(generation=CURRENT_GENERATION)
        new=policy.load_policy(generation=CURRENT_GENERATION,policy_variant='current071')
        self.assertEqual(old['projects'][NEBULAR]['version'],'0.7.0')
        self.assertEqual(new['projects'][NEBULAR]['version'],'0.7.1')
        for name in old['projects'].keys()-{NEBULAR}:
            self.assertEqual(old['projects'][name],new['projects'][name])
        self.assertEqual(policy.CURRENT_POLICY_VERSIONS[NEBULAR],'0.7.0')
        self.assertTrue(rpm_policy_path().startswith('operators/live1/'))
        self.assertEqual(policy.load_policy()['projects'][NEBULAR]['version'],'0.6.1')

    def test_071_inventory_source_pins_are_exact_data_only(self):
        n=policy.load_policy(generation=CURRENT_GENERATION,policy_variant='current071')['projects'][NEBULAR]
        self.assertEqual(n['inventory_bindings']['aarch64-linux']['source_inventory_sha256'],
            'afca36d1ed49f3b8d13587c1598e9b4748fa566f18ff26de9f38be16bf0fc0f6')
        self.assertEqual(n['inventory_bindings']['x86_64-linux']['source_inventory_sha256'],
            '4d57208f5e8a3a7fe915b3dc5e9d0b95197bdecec941a4e47535406876765b61')
        self.assertEqual(len(policy.CURRENT_SOURCE_INVENTORY_FIELDS),9)

    def test_closed_selection_and_cross_generation(self):
        for generation,variant in ((HISTORICAL_GENERATION,'current071'),(CURRENT_GENERATION,'0.7.1'),(CURRENT_GENERATION,'')):
            with self.subTest(generation=generation,variant=variant),self.assertRaises(ContractError):
                policy.load_policy(generation=generation,policy_variant=variant)

    def test_source_policy_mutation_and_relabel_refuse(self):
        new=policy.load_policy(generation=CURRENT_GENERATION,policy_variant='current071')
        for change in ('version','pin','flag'):
            bad=copy.deepcopy(new)
            if change=='version':bad['projects'][NEBULAR]['version']='0.7.0'
            if change=='pin':bad['projects'][NEBULAR]['inventory_bindings']['x86_64-linux']['source_inventory_sha256']='0'*64
            if change=='flag':bad['publication_authority']=True
            with self.subTest(change=change),self.assertRaises(ContractError):
                policy._validate_policy(bad,generation=CURRENT_GENERATION,policy_variant='current071')
        with self.assertRaises(ContractError):policy._validate_policy(new,generation=CURRENT_GENERATION)

    def test_default071_refusal_and_explicit071_missing_inventory_refusal(self):
        old=actual_case(NEBULAR)
        inp={**old['inputs'],'version':'0.7.1'}
        result=policy.evaluate_policy(old['raw'],old['inventory'],inp,generation=CURRENT_GENERATION)
        self.assertIn('project-version-platform-mismatch',result['blockers'])
        selected=policy.load_policy(generation=CURRENT_GENERATION,policy_variant='current071')
        inp=receipt(selected)['details']['rpm_lint_policy'][NEBULAR]['inputs']
        result=policy.evaluate_policy(old['raw'],None,inp,selected,generation=CURRENT_GENERATION,policy_variant='current071')
        self.assertFalse(result['accepted'])
        self.assertIn('incomplete-preservation-inventory',result['blockers'])
        self.assertEqual(result['accepted_findings'],[])

    def test_explicit071_source_validation_default_refuses_and070_replay_remains(self):
        new=receipt(policy.load_policy(generation=CURRENT_GENERATION,policy_variant='current071'))
        validate_rpm_policy_source(ROOT,new,generation=CURRENT_GENERATION,policy_variant='current071')
        with self.assertRaises(ContractError):validate_rpm_policy_source(ROOT,new,generation=CURRENT_GENERATION)
        self.assertEqual(policy.policy_variant_for_evaluations(ROOT,new),'current071')
        from rs9.hosted_summary import _validate_hosted_rpm_policy_source
        _validate_hosted_rpm_policy_source(ROOT,new,generation=CURRENT_GENERATION)
        old=receipt(policy.load_policy(generation=CURRENT_GENERATION))
        self.assertIsNone(policy.policy_variant_for_evaluations(ROOT,old))
        validate_rpm_policy_source(ROOT,old,generation=CURRENT_GENERATION)

    def test_consumer_mixed_missing_changed_tuple_refusals(self):
        original=receipt(policy.load_policy(generation=CURRENT_GENERATION,policy_variant='current071'))
        for key,value in (('version','0.7.0'),('asset_sha256','0'*64),('payload_manifest_sha256','0'*64),('arch','noarch'),('arch','aarch64'),('system','aarch64-linux')):
            bad=copy.deepcopy(original);bad['details']['rpm_lint_policy'][NEBULAR]['inputs'][key]=value
            with self.subTest(key=key),self.assertRaises(ContractError):policy.policy_variant_for_evaluations(ROOT,bad)
        bad=copy.deepcopy(original);del bad['details']['rpm_lint_policy'][NEBULAR]
        with self.assertRaises(ContractError):policy.policy_variant_for_evaluations(ROOT,bad)
        bad=copy.deepcopy(original);bad['details']['rpm_lint_policy'][NEBULAR]['policy_sha256']='0'*64
        with self.assertRaises(ContractError):policy.policy_variant_for_evaluations(ROOT,bad)

    def test_configuration_closure_has_both_variants_and_callers(self):
        paths=configuration_paths(ROOT,generation=CURRENT_GENERATION)
        for path in ('rpm-lint-policy.json','rpm-lint-policy-nebular071.json','nebular-callers.json','nebular-callers-070.json'):
            self.assertIn('operators/theme-forge-current-202610/'+path,paths)

    def test_explicit071_client_floor_uses_same_real_source_policy(self):
        from tests.test_rpm_client_runtime import ClientRuntimeTests
        from rs9.rpm_client_runtime import bind_engine_floors
        _,evidence=ClientRuntimeTests().prepare()
        capture=object();intent={'project':{'id':NEBULAR},'version':'0.7.1'}
        selected=callers._load_current071_contract()
        with patch('rs9.rpm_client_runtime.bind_native_build_generation'), \
             patch('rs9.build_native.validate_build_inputs',return_value={'asset_file':Path('synthetic.tar.gz')}), \
             patch.object(policy,'assert_policy_capture') as auth, \
             patch.object(policy,'load_policy',wraps=policy.load_policy) as loader, \
             patch.object(callers,'current_contract_for_capture',return_value=selected), \
             patch.object(callers,'release_runtime_floor',return_value='>=22') as floor:
            result=bind_engine_floors(evidence,[(capture,intent,{})],generation=CURRENT_GENERATION,policy_variant='current071')
        self.assertEqual(result['status'],'pass')
        auth.assert_called_once_with(capture,intent,'current071')
        loader.assert_called_once_with(generation=CURRENT_GENERATION,policy_variant='current071')
        self.assertEqual(floor.call_args.args[1]['version'],'0.7.1')
        self.assertIs(floor.call_args.kwargs['capture'],capture)

    def test_builder_refuses_supplied070_policy_before_any_command(self):
        from rs9.build_rpm import build_rpm_candidate
        from unittest.mock import Mock
        runner=Mock()
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);cap,contract,_,_,_=current_caller_fixture(root,version='0.7.1',tag='v0.7.1',
                tag_commit=callers.CURRENT071_COMMIT,tag_tree=callers.CURRENT071_TREE,release_id=callers.CURRENT071_RELEASE_ID)
            intent={'project':{'id':NEBULAR},'version':'0.7.1'}
            with patch.object(callers,'_load_current071_contract',return_value=contract),self.assertRaises(ContractError):
                build_rpm_candidate(cap,intent,'x86_64',root/'build',runner=runner,generation=CURRENT_GENERATION,
                    policy_variant='current071',policy=policy.load_policy(generation=CURRENT_GENERATION))
        self.assertEqual(runner.mock_calls,[])

    def test_malformed_and_forged_batch_refusals(self):
        for batch in (None,{},[None]*4,[(None,{},None)]*4):
            with self.subTest(batch=batch),self.assertRaises(ContractError):policy.select_current_rpm_variant(batch)

    def test_real_core_nebular_selection_wrong_tuple_and_serialization_refuse(self):
        with tempfile.TemporaryDirectory() as tmp:
            cap,contract,_,_,_=current_caller_fixture(Path(tmp),version='0.7.1',tag='v0.7.1',
                tag_commit=callers.CURRENT071_COMMIT,tag_tree=callers.CURRENT071_TREE,release_id=callers.CURRENT071_RELEASE_ID)
            intent={'project':{'id':NEBULAR},'version':'0.7.1'}
            with patch.object(callers,'_load_current071_contract',return_value=contract):
                policy.assert_policy_capture(cap,intent,'current071')
                for value in (cap.record,copy.deepcopy(cap)):
                    if not isinstance(value,dict):value.record['tag']['tree']='0'*40
                    with self.assertRaises(ContractError):policy.assert_policy_capture(value,intent,'current071')
                with self.assertRaises(ContractError):policy.assert_policy_capture(cap,intent,'current070')

    def test_authenticated_wrong_tag_commit_tree_release_and_asset_refuse(self):
        cases=({'tag':'v0.7.2'},{'tag_commit':'0'*40},{'tag_tree':'0'*40},{'release_id':999})
        for changes in cases:
            with self.subTest(changes=changes),tempfile.TemporaryDirectory() as tmp:
                kwargs=dict(version='0.7.1',tag='v0.7.1',tag_commit=callers.CURRENT071_COMMIT,
                    tag_tree=callers.CURRENT071_TREE,release_id=callers.CURRENT071_RELEASE_ID)
                kwargs.update(changes)
                cap,contract,_,_,_=current_caller_fixture(Path(tmp),**kwargs)
                authenticated_record_hash(cap)
                with patch.object(callers,'_load_current071_contract',return_value=contract),self.assertRaises(ContractError):
                    policy.assert_policy_capture(cap,{'project':{'id':NEBULAR},'version':'0.7.1'},'current071')
        with tempfile.TemporaryDirectory() as tmp:
            cap,contract,_,_,_=current_caller_fixture(Path(tmp),version='0.7.1',tag='v0.7.1',
                tag_commit=callers.CURRENT071_COMMIT,tag_tree=callers.CURRENT071_TREE,release_id=callers.CURRENT071_RELEASE_ID)
            wrong=copy.deepcopy(contract);wrong['platforms']['x86_64-linux']['asset']['sha256']='0'*64
            with patch.object(callers,'_load_current071_contract',return_value=wrong),self.assertRaises(ContractError):
                policy.assert_policy_capture(cap,{'project':{'id':NEBULAR},'version':'0.7.1'},'current071')

    def test_real_core_four_capture_batch_uses_exact_synthetic_expectations(self):
        # All bytes/API inputs here are synthetic; authentication APIs stay real.
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);cap,contract,_,_,_=current_caller_fixture(root,version='0.7.1',tag='v0.7.1',
                tag_commit=callers.CURRENT071_COMMIT,tag_tree=callers.CURRENT071_TREE,release_id=callers.CURRENT071_RELEASE_ID)
            captures=[(cap,{'project':{'id':NEBULAR},'version':'0.7.1'}, {})];expectations=[]
            for i,(product,version) in enumerate(policy.CURRENT_POLICY_VERSIONS.items()):
                if product==NEBULAR:continue
                directory=root/product;directory.mkdir();intent=package_evidence(directory)
                selection=selection_for_intent(intent)
                intent['project']['id']=product;intent['version']=version
                rel=json.loads((directory/'api/release.json').read_bytes());rel.update(immutable=False,published_at='2026-10-01T00:00:00Z')
                (directory/'api/release.json').write_bytes(canonical(rel))
                capture=authenticate_release(selection,directory)
                record=capture.record
                expectations.append(dict(project=product,repository=record['repository']['full_name'],repository_id=record['repository']['id'],
                    release_id=record['release']['id'],tag=record['release']['tag'],commit=record['tag']['commit'],tree=record['tag']['tree'],
                    immutable=False,published_at=record['source_times']['published_at'],contains_rs9=False,truncated=False,
                    assets=[dict(name=x['name'],id=x['github_asset_id'],sha256=x['sha256'],size=x['size']) for x in record['assets']]))
                captures.append((capture,intent,{}))
            with patch.object(callers,'_load_current071_contract',return_value=contract),patch.object(policy,'_current_policy_expectations',return_value=expectations):
                self.assertEqual(policy.select_current_rpm_variant(captures),'current071')
                with self.assertRaises(ContractError):policy.select_current_rpm_variant(captures[:-1])
                wrong=copy.deepcopy(captures);wrong[1][0].record['release']['id']=999
                with self.assertRaises(ContractError):policy.select_current_rpm_variant(wrong)


if __name__=='__main__':unittest.main()
