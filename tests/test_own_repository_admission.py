"""Controlled API/source fixtures. No native, Git, signing or adoption authority."""
import base64
import copy
from dataclasses import replace, asdict
from datetime import datetime, timezone
import gzip
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest.mock import patch
import zipfile
import sys

# Standalone RS9 tests use the exact paired P body as an explicit test fixture.
# An externally supplied P test module must have those same reviewed bytes.

from rs9 import own_repository_admission as own
from rs9.collect_candidate import collect
from rs9.current_generation import CURRENT_GENERATION, distribution_paths
from rs9.errors import ContractError
from rs9.hosted_custody import provenance, retain
from rs9.hosted_summary import required, contract, summarize, RPM_POLICY_PROMOTION_BLOCKER as TOKEN
from rs9.qualified_distribution_inputs import SourceBoundConfiguration, qualified_distribution_inputs, qualified_theme_forge_packages_inputs
from rs9.rpm_evidence import write_policy_evidence, durable_lint_projection
from rs9.scratch import canonical
from tests.test_hosted_summary_roles import _make_synthetic_rpm
from tests.test_repo_apt import build_minimal_deb

FIXTURES=Path(__file__).resolve().parent/'fixtures/own-repository-admission'
ROOT=Path(__file__).resolve().parents[1]
COMMIT,TREE,PCOMMIT,PTREE='1'*40,'2'*40,'f'*40,'e'*40
START=datetime(2026,10,29,tzinfo=timezone.utc)
_importer=FIXTURES/'paired-importer.py'
if 'current_import_routing' not in sys.modules:
    _spec=importlib.util.spec_from_file_location('current_import_routing',_importer)
    _module=importlib.util.module_from_spec(_spec);sys.modules['current_import_routing']=_module;_spec.loader.exec_module(_module)
else:
    assert Path(sys.modules['current_import_routing'].__file__).read_bytes()==_importer.read_bytes()

PRODUCER=dict(GITHUB_REPOSITORY='Knowledge-Forge-AI/release-starport-9',GITHUB_SHA=COMMIT,GITHUB_RUN_ID='7',
              GITHUB_REF='refs/heads/main',GITHUB_EVENT_NAME='push',GITHUB_RUN_ATTEMPT='1')


def future_policy_module():
    path=FIXTURES/'preservation-source/src/rs9/rpm_lint_policy.py'
    spec=importlib.util.spec_from_file_location('rs9._controlled_preservation_policy',path)
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    return module


class SourceFixtures(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup);self.root=Path(self.tmp.name)
        self.config=SourceBoundConfiguration(ROOT,COMMIT,TREE,7,START,*(['a'*64]*5))
        self.p=self.root/'p';shutil.copytree(FIXTURES/'p-source',self.p)
        (self.p/own.IMPORTER).write_bytes((FIXTURES/'paired-importer.py').read_bytes())
        self.descriptor={'schema':'theme-forge.current-rs9-input-source.v1','generation':CURRENT_GENERATION,
            'status':'qualified-original-run-inputs','production_enabled':False,'publication_authority':False,
            'rs9':{**self.config.expected(),'not_before':START.isoformat()}}
        self.write_descriptor();self.rebuild_tree()
    def write_descriptor(self):
        (self.p/own.DESCRIPTOR).write_bytes(canonical(self.descriptor))
    def rebuild_tree(self):
        self.rows=[]
        for name in sorted(set(own.CONSUMER_FILE_HASHES)|{own.DESCRIPTOR}):
            data=(self.p/name).read_bytes()
            self.rows.append(dict(path=name,type='blob',mode='100644',sha=hashlib.sha1(b'blob '+str(len(data)).encode()+b'\0'+data).hexdigest()))
    def api(self,root,argv):
        endpoint=argv[-1];self.assertTrue(endpoint.startswith('repos/'+own.TARGET+'/'))
        if endpoint.endswith('git/ref/heads/main'):return json.dumps({'object':{'type':'commit','sha':PCOMMIT}})
        if '/git/commits/' in endpoint:return json.dumps({'sha':PCOMMIT,'tree':{'sha':PTREE}})
        return json.dumps({'sha':PTREE,'truncated':False,'tree':self.rows})
    def verify(self):
        with patch.object(own,'source_tree_identity',return_value=PTREE),patch.object(own,'gh_read',side_effect=self.api):
            return own.consumer_source(self.config,self.p,PCOMMIT,PTREE)
    def test_real_paired_body_and_tracked_descriptor_are_source_bound(self):
        proof=self.verify();self.addCleanup(own.release_consumer,proof)
        self.assertEqual(proof.record['repository'],own.TARGET)
        self.assertEqual(proof.record['files'][own.IMPORTER],own.CONSUMER_FILE_HASHES[own.IMPORTER])
    def test_held_real_descriptor_never_admits_a_run(self):
        self.descriptor=json.loads((FIXTURES/'unadmitted-descriptor.json').read_text());self.write_descriptor();self.rebuild_tree()
        with self.assertRaises(ContractError) as error:self.verify()
        self.assertEqual(error.exception.code,'OWN_REPOSITORY_UNADMITTED')
    def test_body_descriptor_ignored_blob_and_main_mismatch_refuse(self):
        original=(self.p/own.IMPORTER).read_bytes();(self.p/own.IMPORTER).write_bytes(original+b'\n');self.rebuild_tree()
        with self.assertRaises(ContractError):self.verify()
        (self.p/own.IMPORTER).write_bytes(original);self.rebuild_tree();self.rows=[row for row in self.rows if row['path']!=own.IMPORTER]
        with self.assertRaises(ContractError):self.verify() # physical bytes do not prove trackedness
        self.rebuild_tree();self.descriptor['rs9']['run_id']=8;self.write_descriptor();self.rebuild_tree()
        with self.assertRaises(ContractError):self.verify()
    def test_unknown_descriptor_keys_authority_and_synthetic_capability_refuse(self):
        self.descriptor['waiver']=True;self.write_descriptor();self.rebuild_tree()
        with self.assertRaises(ContractError):self.verify()
        with self.assertRaises(ContractError):own.admit(ROOT,self.root,{},self.config.expected(),{'repository':own.TARGET})
        with self.assertRaises(ContractError):own.check_lane({'accepted':True},{'lane':'rpm','system':'x86_64-linux'},{},{})
    def test_missing_or_changed_tracked_blob_is_not_ignored_source_authority(self):
        self.rows[0]['sha']='0'*40
        with self.assertRaises(ContractError):self.verify()
        self.rebuild_tree();self.rows[0]['mode']='120000'
        with self.assertRaises(ContractError):self.verify()
    def test_wrong_main_or_truncated_api_tree_refuses(self):
        original=self.api
        def wrong(root,argv):
            value=json.loads(original(root,argv))
            if argv[-1].endswith('git/ref/heads/main'):value['object']['sha']='0'*40
            return json.dumps(value)
        with patch.object(self,'api',side_effect=wrong),self.assertRaises(ContractError):self.verify()
        def truncated(root,argv):
            value=json.loads(original(root,argv))
            if '/git/trees/' in argv[-1]:value['truncated']=True
            return json.dumps(value)
        with patch.object(self,'api',side_effect=truncated),self.assertRaises(ContractError):self.verify()
    def test_caller_extra_ignored_inventory_is_not_authority(self):
        import current_import_routing as routing
        files={name:hashlib.sha256((self.p/name).read_bytes()).hexdigest() for name in routing.SOURCE_FILES}
        (self.p/'ignored.json').write_bytes(b'{}');files['ignored.json']=hashlib.sha256(b'{}').hexdigest()
        source=routing.ProductionSource(self.p,PCOMMIT,PTREE,files)
        with patch.object(routing,'source_tree_identity',return_value=PTREE),self.assertRaises(ContractError):source.verify()
    def test_restriction_semantics_not_token_filter(self):
        rpm=dict(lane='rpm',system='x86_64-linux');deb=dict(lane='deb',system='amd64')
        good={'production_promotion_blockers':[TOKEN],'details':{'rpm_lint_policy':{'p':{'accepted_findings':[{}]}}}}
        self.assertEqual(own._restriction(rpm,good),[TOKEN])
        for lane,row in [(rpm,{**good,'production_promotion_blockers':[]}),(rpm,{**good,'production_promotion_blockers':[TOKEN,'unknown-token']}),
                         (deb,good),(rpm,{'production_promotion_blockers':[TOKEN]}),(rpm,{**good,'production_promotion_blockers':'bad'})]:
            with self.assertRaises(ContractError):own._restriction(lane,row)


class QualifiedFixture(SourceFixtures):
    """Simulated original producer/run/caller gates; not native caller capability.

    Uses actual sealed proposed policy loader at one disclosed integration seam,
    actual collector/summary/raw+chunk/role/facade validators and synthetic package
    bodies/API metadata. GUI accepted evaluation is a simulated producer statement,
    never a claim serialized GUI fixtures mint live caller authority.
    """
    def setUp(self):
        super().setUp()
        self.rs=self.root/'rs9';self.rs.mkdir()
        for name in ['src','operators','bootstrap','nix','.github']:
            shutil.copytree(ROOT/name,self.rs/name)
        shutil.copyfile(ROOT/'flake.nix',self.rs/'flake.nix')
        self.policy_module=future_policy_module();self.policy=self.policy_module.load_policy(generation=CURRENT_GENERATION)
        (self.rs/'operators/theme-forge-current-202610/rpm-lint-policy.json').write_bytes(canonical(self.policy))
        self.env=patch.dict(os.environ,PRODUCER);self.env.start();self.addCleanup(self.env.stop)
        self.treepatch=patch('rs9.hosted_custody.source_tree_identity',return_value=TREE);self.treepatch.start();self.addCleanup(self.treepatch.stop)
        self.loader=patch('rs9.rpm_lint_policy.load_policy',side_effect=self.policy_module.load_policy);self.loader.start();self.addCleanup(self.loader.stop)
        self.ownloader=patch.object(own,'load_policy',side_effect=self.policy_module.load_policy);self.ownloader.start();self.addCleanup(self.ownloader.stop)
        # Non-admitting copied-tree fixture seam only. Production requires the
        # package to execute in the exact selected physical checkout. All module
        # inventory/byte/origin checks remain real in this controlled transport.
        self.execution_root_join=patch.object(own,'_require_selected_execution_root')
        self.execution_root_join.start();self.addCleanup(self.execution_root_join.stop)
        self.expected=provenance(self.rs,'a'*64,generation=CURRENT_GENERATION)
        self.config=SourceBoundConfiguration(self.rs,COMMIT,TREE,7,START,*[self.expected[k] for k in
            ('workflow_sha256','contract_sha256','builder_source_sha256','configuration_sha256','release_ingestion_sha256')])
        self.descriptor['rs9']={**self.config.expected(),'not_before':START.isoformat()};self.write_descriptor();self.rebuild_tree()
        self.inputs=self.root/'inputs';self.inputs.mkdir();self.summaryroot=self.root/'summary'
        self.make_artifacts()
    def make_artifacts(self):
        for lane in required(self.rs,generation=CURRENT_GENERATION):
            scratch=self.root/('scratch-'+lane['artifact_name']);scratch.mkdir();files=[]
            receipt=dict(schema='rs9.hosted-candidate-diagnostic.v1alpha2',lane=lane['lane'],system=lane['system'],
                production_enabled=False,publication_authority=False,attended_gates_satisfied=False,
                execution_error=None,policy_blockers=[],runner={},provenance=self.expected,production_promotion_blockers=[],
                gates=[dict(name=name,status='pass') for name in lane['required_gates']])
            details={}
            if lane['lane']=='nix':
                from rs9.hosted_nix import PRODUCTS
                details={'outputs':{p:{} for p in PRODUCTS}}
            for product in lane.get('required_products',[]):
                version=own.VERSIONS[product];pure=product in {'theme-forge-stellar-loom','theme-forge-solar-sail'}
                if lane['lane']=='rpm':
                    f=json.loads((FIXTURES/'preservation-cases'/f'{product}-{lane["system"]}.json').read_text())
                    case=json.loads(gzip.decompress(base64.b64decode(f['data'])));raw=copy.deepcopy(case['raw'])
                    arch=case['inputs']['arch'];name=f'{product}-{version}-1.fc43.{arch}.rpm'
                    data=_make_synthetic_rpm(product,version=version,arch=arch)
                elif lane['lane']=='deb':
                    arch='all' if pure else lane['system'];name=f'{product}_{version}-1_{arch}.deb';data=build_minimal_deb(product,version+'-1',arch)
                elif lane['lane']=='pacman':
                    arch='any' if pure else 'x86_64';name=f'{product}-{version}-1-{arch}.pkg.tar.zst';data=('CONTROLLED-ROUTING:'+name).encode()
                else:continue
                package=scratch/'unsigned'/name;package.parent.mkdir(exist_ok=True);package.write_bytes(data);files.append(package)
                if lane['lane']!='rpm':continue
                raw['package_sha256']=hashlib.sha256(data).hexdigest();raw['package_file']=name
                rawpath=scratch/'diagnostics'/('rpmlint-'+product+'.json');rawpath.parent.mkdir(exist_ok=True);rawpath.write_bytes(canonical(raw));files.append(rawpath)
                evaluation=self.policy_module.evaluate_policy(case['raw'],case['inventory'],case['inputs'],self.policy,generation=CURRENT_GENERATION)
                if product=='theme-forge-nebular-fusion':
                    # A simulated original source-run producer statement. Native
                    # GUI caller validation is NOT executed or bypassed here.
                    evaluation.update(accepted=True,status='accepted',blockers=[],rule_blockers=[],accepted_findings=raw['error_records'])
                self.assertTrue(evaluation['accepted'],evaluation['blockers'])
                summary,chunks=write_policy_evidence(scratch,evaluation);files.extend(chunks)
                derivation=dict(project=product,adapter='rpm',artifact={'sha256':raw['package_sha256']},evidence={'rpmlint':durable_lint_projection(raw)})
                manifest=dict(schema='rs9.rpm-candidate.v1alpha2',project=product,architecture=arch,package_file='unsigned/'+name,
                    package_sha256=raw['package_sha256'],package_size=len(data),rpmlint=raw,derivation=derivation)
                mp=scratch/'build'/product/'rpm-manifest.json';mp.parent.mkdir(parents=True);mp.write_bytes(canonical(manifest));files.append(mp)
                details.setdefault('rpm_lint_raw',{})[product]=raw;details.setdefault('rpm_lint_policy',{})[product]=summary
            if lane['lane']=='rpm':
                details['rpm_evidence_contract']='rs9.rpm-evidence-contract.v2';receipt['production_promotion_blockers']=[TOKEN]
            if not files:
                f=scratch/'fixture-evidence.json';f.write_bytes(b'{}');files.append(f)
            receipt['details']=details;retain(scratch,self.inputs/lane['artifact_name'],files,receipt)
        jobs={name:{'result':'success'} for name in contract(self.rs,generation=CURRENT_GENERATION)['required_jobs'] if name!='summary'}
        with patch.dict(os.environ,{'RS9_JOB_CONCLUSIONS':json.dumps(jobs)}):
            self.assertEqual(summarize(self.rs,self.inputs,self.summaryroot,generation=CURRENT_GENERATION),0)
        self.summary=json.loads((self.summaryroot/'hosted-summary.json').read_text())
        self.repack()
    def repack(self):
        self.artifacts=[];self.zips={}
        directories=[(lane['artifact_name'],self.inputs/lane['artifact_name']) for lane in required(self.rs,generation=CURRENT_GENERATION)]+[('hosted-summary',self.summaryroot)]
        for identity,(name,directory) in enumerate(directories,10):
            stream=io.BytesIO()
            with zipfile.ZipFile(stream,'w') as z:
                for path in sorted(directory.rglob('*')):
                    if path.is_file():z.writestr(path.relative_to(directory).as_posix(),path.read_bytes())
            body=stream.getvalue();self.zips[identity]=body
            self.artifacts.append(dict(id=identity,name=name,digest='sha256:'+hashlib.sha256(body).hexdigest(),expired=False,size_in_bytes=len(body)))
        names={lane['lane']+'-'+lane['system'] if lane['lane'] in {'nix','rpm','deb','pacman'} else lane['lane'] for lane in required(self.rs,generation=CURRENT_GENERATION)}|{'config','unit','summary'}
        self.jobs=[dict(id=i,name=name,status='completed',conclusion='success',steps=[dict(name='controlled fixture',conclusion='success')]) for i,name in enumerate(sorted(names),1)]
    def mutate_receipt(self,lane,system,change):
        directory=self.inputs/('candidate-'+lane+'-'+system);path=directory/(lane+'-'+system+'.json')
        receipt=json.loads(path.read_text());change(receipt);path.write_bytes(canonical(receipt))
        mp=directory/'artifact-manifest.json';manifest=json.loads(mp.read_text());manifest['qualification_receipt_hashes']={path.name:hashlib.sha256(path.read_bytes()).hexdigest()};mp.write_bytes(canonical(manifest))
        jobs={name:{'result':'success'} for name in contract(self.rs,generation=CURRENT_GENERATION)['required_jobs'] if name!='summary'}
        with patch.dict(os.environ,{'RS9_JOB_CONCLUSIONS':json.dumps(jobs)}):summarize(self.rs,self.inputs,self.summaryroot,generation=CURRENT_GENERATION)
        self.summary=json.loads((self.summaryroot/'hosted-summary.json').read_text());self.repack()
    def original_api(self,root,argv):
        endpoint=argv[-1]
        if endpoint.endswith('/zip'):return self.zips[int(endpoint.split('/')[-2])]
        if '/jobs?' in endpoint:return json.dumps({'total_count':len(self.jobs),'jobs':self.jobs})
        if '/artifacts?' in endpoint:return json.dumps({'total_count':len(self.artifacts),'artifacts':self.artifacts})
        return json.dumps(dict(id=7,head_sha=COMMIT,event='push',head_branch='main',path=distribution_paths(CURRENT_GENERATION)[0],run_attempt=1,
             status='completed',conclusion='success',repository={'full_name':'Knowledge-Forge-AI/release-starport-9'},created_at='2026-10-29T00:00:01Z'))
    def run_facade(self,scoped):
        output=self.root/('collection-'+str(len(list(self.root.glob('collection-*')))));output.mkdir()
        with patch.object(own,'source_tree_identity',return_value=PTREE),patch.object(own,'gh_read',side_effect=self.api), \
             patch('rs9.collect_candidate.output_directory',return_value=output), \
             patch('rs9.collect_candidate.gh_read',side_effect=lambda root,argv,runner=None:self.original_api(root,['gh',*argv])), \
             patch('rs9.qualified_distribution_inputs.collect',side_effect=lambda *a,**kw:collect(*a,runner=self.original_api,**kw)):
            if scoped:return qualified_theme_forge_packages_inputs(self.config,output,consumer_repository=self.p,consumer_commit=PCOMMIT,consumer_tree=PTREE,timeout=30)
            return qualified_distribution_inputs(self.config,output,timeout=30)
    def test_complete_controlled_transport_can_reach_only_scoped_unsigned_inventory(self):
        inventory=self.run_facade(True);record=inventory['own_repository_admission']
        self.assertEqual(record['original_restrictions'],[TOKEN]);self.assertTrue(record['original_production_promotion_blocked'])
        self.assertEqual(len(record['raw_policy_evidence']),8)
        self.assertFalse(inventory['production_enabled']);self.assertFalse(record['publication_authority']);self.assertFalse(record['signing_authority'])
        self.assertTrue(all(row['raw_clean'] is False for row in record['raw_policy_evidence']))
    def test_generic_entry_still_refuses_same_complete_current_candidate(self):
        with self.assertRaises(ContractError) as error:self.run_facade(False)
        self.assertEqual(error.exception.code,'DISTRIBUTION_PROMOTION_HELD')
    def test_live_proof_cannot_be_copied_or_replayed_after_release(self):
        consumer=self.verify();self.addCleanup(own.release_consumer,consumer)
        proof=own.admit(self.rs,self.inputs,self.summary,self.expected,consumer)
        lane=required(self.rs,generation=CURRENT_GENERATION)[0];directory=self.inputs/lane['artifact_name']
        receipt=json.loads((directory/(lane['lane']+'-'+lane['system']+'.json')).read_text());manifest=json.loads((directory/'artifact-manifest.json').read_text())
        own.check_lane(proof,lane,receipt,manifest)
        for fake in [asdict(proof),replace(proof),replace(proof,ledger=())]:
            with self.assertRaises(ContractError):own.check_lane(fake,lane,receipt,manifest)
        own.release(proof)
        with self.assertRaises(ContractError):own.check_lane(proof,lane,receipt,manifest)
    def test_unknown_or_misplaced_token_fails_real_scoped_facade(self):
        self.mutate_receipt('rpm','x86_64-linux',lambda row:row['production_promotion_blockers'].append('unknown-restriction'))
        with self.assertRaises(ContractError) as error:self.run_facade(True)
        self.assertEqual(error.exception.code,'OWN_REPOSITORY_ADMISSION')
        self.mutate_receipt('rpm','x86_64-linux',lambda row:row.update(production_promotion_blockers=[TOKEN]))
        self.mutate_receipt('deb','amd64',lambda row:row.update(production_promotion_blockers=[TOKEN]))
        with self.assertRaises(ContractError) as error:self.run_facade(True)
        self.assertEqual(error.exception.code,'OWN_REPOSITORY_ADMISSION')
    def test_required_native_gate_remains_mandatory(self):
        def fail_native(row):next(g for g in row['gates'] if g['name']=='rpm-client-qualification').update(status='fail')
        self.mutate_receipt('rpm','aarch64-linux',fail_native)
        with self.assertRaises(ContractError) as error:self.run_facade(True)
        self.assertEqual(error.exception.code,'DISTRIBUTION_NOT_QUALIFIED')
    def test_changed_raw_custody_is_not_admitted(self):
        path=next((self.inputs/'candidate-rpm-x86_64-linux').rglob('rpmlint-*.json'));path.write_bytes(path.read_bytes()+b' ');self.repack()
        with self.assertRaises(ContractError) as error:self.run_facade(True)
        self.assertEqual(error.exception.code,'DISTRIBUTION_NOT_QUALIFIED')
    def test_executing_rs9_body_must_match_descriptor_checkout(self):
        path=self.rs/'src/rs9/own_repository_admission.py';path.write_bytes(path.read_bytes()+b'\n')
        with self.assertRaises(ContractError) as error:self.run_facade(True)
        self.assertEqual(error.exception.code,'OWN_REPOSITORY_SOURCE')
    def test_changed_selected_helper_refuses_before_collection(self):
        path=self.rs/'src/rs9/hosted_summary.py';path.write_bytes(path.read_bytes()+b'\n# different helper\n')
        with patch('rs9.qualified_distribution_inputs.collect') as collector:
            with self.assertRaises(ContractError) as error:self.run_facade(True)
            self.assertEqual(error.exception.code,'OWN_REPOSITORY_SOURCE');collector.assert_not_called()
    def test_mixed_helper_file_and_spec_origins_refuse(self):
        import rs9.hosted_summary as helper
        with patch.object(helper,'__file__',str(self.root/'hosted_summary.py')):
            with self.assertRaises(ContractError):own.verify_execution_source(self.rs)
        with patch.object(helper.__spec__,'origin',str(self.root/'hosted_summary.py')):
            with self.assertRaises(ContractError):own.verify_execution_source(self.rs)
    def test_mixed_package_search_path_refuses(self):
        import rs9
        with patch.object(rs9,'__path__',[str(ROOT/'src/rs9'),str(self.root)]):
            with self.assertRaises(ContractError):own.verify_execution_source(self.rs)
    def test_mixed_imported_helper_function_refuses(self):
        import rs9.hosted_summary as helper
        namespace={'__name__':'rs9.hosted_summary'}
        exec(compile('def required(*a,**kw): return []',str(self.root/'hosted_summary.py'),'exec'),namespace)
        with patch.object(helper,'required',namespace['required']):
            with self.assertRaises(ContractError):own.verify_execution_source(self.rs)
    def test_helper_mutation_during_collection_refuses(self):
        original=self.original_api;mutated=False
        def changing(root,argv):
            nonlocal mutated
            if not mutated:
                path=self.rs/'src/rs9/hosted_summary.py';path.write_bytes(path.read_bytes()+b'\n');mutated=True
            return original(root,argv)
        with patch.object(self,'original_api',side_effect=changing),self.assertRaises(ContractError) as error:self.run_facade(True)
        self.assertEqual(error.exception.code,'OWN_REPOSITORY_SOURCE')
    def test_exact_physical_root_required_even_with_identical_module_bytes(self):
        self.execution_root_join.stop()
        for name in ['nix/theme-forge-current-202610-products.json',
                     'operators/theme-forge-current-202610/nebular-callers.json']:
            path=self.rs/name;path.write_bytes(path.read_bytes()+b'\n')
        with self.assertRaises(ContractError) as error:own.verify_execution_source(self.rs)
        self.assertEqual(error.exception.code,'OWN_REPOSITORY_SOURCE')
    def test_owned_contextmanager_helper_remains_in_selected_source(self):
        # contextlib preserves __module__ but its wrapper code belongs to stdlib.
        import inspect
        from rs9 import verify_wheel
        self.execution_root_join.stop()
        wrapped = verify_wheel._lifecycle_phase
        self.assertNotEqual(Path(wrapped.__code__.co_filename).parent, ROOT / "src/rs9")
        self.assertEqual(Path(inspect.unwrap(wrapped).__code__.co_filename).parent, ROOT / "src/rs9")
        own.verify_execution_source(ROOT)

    def test_wrapped_helper_cycle_is_a_coded_source_refusal(self):
        self.execution_root_join.stop()
        with patch.object(own.digest, "__wrapped__", own.digest, create=True):
            with self.assertRaises(ContractError) as error:
                own.verify_execution_source(ROOT)
        self.assertEqual(error.exception.code, "OWN_REPOSITORY_SOURCE")

    def test_actual_selected_execution_root_passes_without_fixture_seam(self):
        self.execution_root_join.stop()
        own.verify_execution_source(ROOT)
    def test_consumer_mutation_during_collection_refuses_before_selection(self):
        original=self.original_api;mutated=False
        def changing(root,argv):
            nonlocal mutated
            if not mutated:
                path=self.p/own.IMPORTER;path.write_bytes(path.read_bytes()+b'\n');mutated=True
            return original(root,argv)
        with patch.object(self,'original_api',side_effect=changing),self.assertRaises(ContractError) as error:self.run_facade(True)
        self.assertEqual(error.exception.code,'OWN_REPOSITORY_SOURCE')
    def test_failed_selection_invalidates_internal_scope_object(self):
        with patch('rs9.qualified_distribution_inputs._binary_inputs',side_effect=ContractError('CONTROLLED_SELECTION_FAILURE','fixture')):
            with self.assertRaises(ContractError):self.run_facade(True)
        self.assertEqual(len(own._ACTIVE),0)
    def test_complete_paired_import_keeps_unsigned_bytes_and_limits(self):
        import current_import_routing as routing
        collection=self.root/'p-collection';collection.mkdir();stage=self.root/'p-stage';stage.mkdir()
        production=routing.ProductionSource(self.p,PCOMMIT,PTREE,{name:hashlib.sha256((self.p/name).read_bytes()).hexdigest() for name in routing.SOURCE_FILES})
        with patch.object(routing,'source_tree_identity',return_value=PTREE), \
             patch.object(own,'source_tree_identity',return_value=PTREE),patch.object(own,'gh_read',side_effect=self.api), \
             patch('rs9.collect_candidate.output_directory',return_value=collection), \
             patch('rs9.collect_candidate.gh_read',side_effect=lambda root,argv,runner=None:self.original_api(root,['gh',*argv])), \
             patch('rs9.qualified_distribution_inputs.collect',side_effect=lambda *a,**kw:collect(*a,runner=self.original_api,**kw)):
            result=routing.prepare_unsigned(self.config,production,collection,stage,release_date='Thu, 29 Oct 2026 00:00:00 +0000',timeout=30)
        self.assertFalse(result['signed']);self.assertFalse(result['assembly_ready']);self.assertFalse(result['publication_authority'])
        self.assertEqual(result['own_repository_admission']['original_restrictions'],[TOKEN])
        self.assertTrue(result['own_repository_admission']['original_production_promotion_blocked'])
        for row in result['objects']:
            for path in row['destinations']:self.assertEqual(hashlib.sha256((stage/path).read_bytes()).hexdigest(),row['sha256'])
        self.assertEqual({row['product'] for row in result['objects']},set(own.VERSIONS))


if __name__=='__main__':unittest.main()
