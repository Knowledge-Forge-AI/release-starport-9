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
from rs9 import current_pacman_any as any_mod
from rs9.collect_candidate import collect
from rs9.current_generation import CURRENT_GENERATION, distribution_paths, rpm_policy_path
from rs9.current_pacman_reuse import ARM_ARTIFACT, CANONICAL_ARTIFACT, WITNESS_PATH, candidate_reuse
from rs9.errors import ContractError
from rs9.hosted_custody import builder_identity, provenance, retain
from rs9.package_roles import RAW_REUSE_REPLICA, is_installable_binary
from rs9.hosted_summary import (
    required,
    contract,
    summarize,
    validate_rpm_policy_source,
    RPM_POLICY_PROMOTION_BLOCKER as TOKEN,
)
from rs9.qualified_distribution_inputs import (
    SourceBoundConfiguration,
    qualified_distribution_inputs,
    qualified_theme_forge_packages_inputs,
)
from rs9.rpm_evidence import write_policy_evidence, durable_lint_projection
from rs9.rpm_lint_policy import load_policy
from rs9.scratch import canonical
from tests.test_hosted_summary_roles import _make_synthetic_rpm
from tests.test_repo_apt import build_minimal_deb
from tests import current_archarm_own_fixtures as arm

OLD_FIXTURES=Path(__file__).resolve().parent/'fixtures/own-repository-admission'
FIXTURES=Path(__file__).resolve().parent/'fixtures/own-repository-admission071'
ROOT=Path(__file__).resolve().parents[1]
COMMIT,TREE,PCOMMIT,PTREE='1'*40,'2'*40,'f'*40,'e'*40
START=datetime(2026,10,29,tzinfo=timezone.utc)
_importer=FIXTURES/'paired-importer.py'
if 'current_import_routing' not in sys.modules:
    _spec=importlib.util.spec_from_file_location('current_import_routing',_importer)
    _module=importlib.util.module_from_spec(_spec);sys.modules['current_import_routing']=_module;_spec.loader.exec_module(_module)
else:
    assert Path(sys.modules['current_import_routing'].__file__).read_bytes()==_importer.read_bytes()
import current_import_routing as routing

PRODUCER=dict(GITHUB_REPOSITORY='Knowledge-Forge-AI/release-starport-9',GITHUB_SHA=COMMIT,GITHUB_RUN_ID='7',
              GITHUB_REF='refs/heads/main',GITHUB_EVENT_NAME='push',GITHUB_RUN_ATTEMPT='1')


class SourceFixtures(unittest.TestCase):
    def setUp(self):
        # Physical (symlink-free) root: custody/importer helpers refuse linked ancestry.
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup);self.root=Path(self.tmp.name).resolve()
        self.config=SourceBoundConfiguration(ROOT,COMMIT,TREE,7,START,*(['a'*64]*5))
        # Overlay every exact current P consumer source body; retain the legacy
        # fixture unchanged for historical-source refusal checks.
        self.p=self.root/'p';shutil.copytree(OLD_FIXTURES/'p-source',self.p)
        for name in sorted(set(own.CONSUMER_FILE_HASHES) - {own.IMPORTER}):
            (self.p/name).parent.mkdir(parents=True,exist_ok=True)
            (self.p/name).write_bytes((FIXTURES/'p-source'/name).read_bytes())
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
        expected_hashes={name:hashlib.sha256((self.p/name).read_bytes()).hexdigest() for name in own.CONSUMER_FILE_HASHES}
        self.assertEqual(own.VERSIONS,routing.VERSIONS)
        self.assertEqual(own.VERSIONS['theme-forge-nebular-fusion'],'0.7.1')
        self.assertEqual(own.CONSUMER_FILE_HASHES,expected_hashes)
        proof=self.verify();self.addCleanup(own.release_consumer,proof)
        self.assertEqual(proof.record['repository'],own.TARGET)
        self.assertEqual(proof.record['files'][own.IMPORTER],own.CONSUMER_FILE_HASHES[own.IMPORTER])
    def test_old070_consumer_source_and_importer_files_refuse_under_071_profile(self):
        pairs=[
            ('package-matrix.json',OLD_FIXTURES/'p-source/package-matrix.json'),
            ('release-lock.json',OLD_FIXTURES/'p-source/release-lock.json'),
            (own.IMPORTER,OLD_FIXTURES/'paired-importer.py'),
        ]
        saved={rel:(self.p/rel).read_bytes() for rel,_ in pairs}
        try:
            for rel,old_src in pairs:
                (self.p/rel).write_bytes(old_src.read_bytes())
            self.rebuild_tree()
            with self.assertRaises(ContractError) as error:self.verify()
            self.assertEqual(error.exception.code,'OWN_REPOSITORY_SOURCE')
        finally:
            for rel,data in saved.items():
                (self.p/rel).write_bytes(data)
            self.rebuild_tree()
        for rel,old_src in pairs:
            with self.subTest(path=rel):
                current_bytes=(self.p/rel).read_bytes()
                (self.p/rel).write_bytes(old_src.read_bytes());self.rebuild_tree()
                try:
                    with self.assertRaises(ContractError) as error:self.verify()
                    self.assertEqual(error.exception.code,'OWN_REPOSITORY_SOURCE')
                finally:
                    (self.p/rel).write_bytes(current_bytes);self.rebuild_tree()
        old_lock=(OLD_FIXTURES/'p-source/release-lock.json').read_bytes()
        current_lock=(self.p/'release-lock.json').read_bytes()
        (self.p/'release-lock.json').write_bytes(old_lock)
        try:
            files={name:hashlib.sha256((self.p/name).read_bytes()).hexdigest() for name in routing.SOURCE_FILES}
            source=routing.ProductionSource(self.p,PCOMMIT,PTREE,files)
            with patch.object(routing,'source_tree_identity',return_value=PTREE),self.assertRaises(ContractError) as error:
                source.verify()
            self.assertEqual(error.exception.code,'CURRENT_IMPORT_ROUTING')
        finally:
            (self.p/'release-lock.json').write_bytes(current_lock)
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
        del self.descriptor['waiver']
        for flag in ('production_enabled','publication_authority'):
            self.descriptor[flag]=True;self.write_descriptor();self.rebuild_tree()
            with self.assertRaises(ContractError):self.verify()
            self.descriptor[flag]=False
        self.descriptor['rs9']['repository']='Knowledge-Forge-AI/other';self.write_descriptor();self.rebuild_tree()
        with self.assertRaises(ContractError):self.verify()
        self.descriptor['rs9']['repository']='Knowledge-Forge-AI/release-starport-9';self.write_descriptor();self.rebuild_tree()
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
    """Controlled original producer/run/caller transport; not native acceptance.

    Uses the real source-owned current071 RPM policy and loader, genuine captured
    current-native raw/policy evaluations from run 41368171900, real collector/
    summary/raw+chunk/role/facade validators, and explicit synthetic package
    bodies/API metadata doubles.

    Current pacman: the canonical x86_64 constructor artifact is retained by the
    real producer code; the current-only ARM lane holds native Burst/Nebular
    aarch64 custody plus the two raw reuse replicas and witness minted by the
    REAL canonical-any importer against an import-time view of the same
    controlled original run. candidate_reuse/original_reuse/role/summary
    validators all run unpatched. Unit-only; no native qualification claim.
    """
    def setUp(self):
        super().setUp()
        any_mod._ACQUIRED.clear();self.addCleanup(any_mod._ACQUIRED.clear)
        self.rs=self.root/'rs9';self.rs.mkdir()
        for name in ['src','operators','bootstrap','nix','.github']:
            shutil.copytree(ROOT/name,self.rs/name)
        shutil.copyfile(ROOT/'flake.nix',self.rs/'flake.nix')
        self.policy=load_policy(self.rs/rpm_policy_path(CURRENT_GENERATION,policy_variant='current071'),
                                generation=CURRENT_GENERATION,policy_variant='current071')
        self.env=patch.dict(os.environ,PRODUCER);self.env.start();self.addCleanup(self.env.stop)
        self.treepatch=patch('rs9.hosted_custody.source_tree_identity',return_value=TREE);self.treepatch.start();self.addCleanup(self.treepatch.stop)
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
        self.run_document=arm.run_document(COMMIT,status='completed',conclusion='success')
        self.collection=None
        self.make_artifacts()
    @staticmethod
    def job_name(lane):
        return lane['lane']+'-'+lane['system'] if lane['lane'] in {'nix','rpm','deb','pacman'} else lane['lane']
    def job_names(self):
        return {self.job_name(lane) for lane in required(self.rs,generation=CURRENT_GENERATION)}|{'config','unit','summary'}
    def artifact_directories(self):
        return [(lane['artifact_name'],self.inputs/lane['artifact_name'],self.job_name(lane))
                for lane in required(self.rs,generation=CURRENT_GENERATION)]+[('hosted-summary',self.summaryroot,'summary')]
    def api_artifacts(self,names=None):
        rows,zips=[],{}
        for identity,(name,directory,job) in enumerate(self.artifact_directories(),10):
            if names is not None and name not in names:continue
            body=arm.zip_directory(directory);zips[identity]=body
            rows.append(arm.artifact_row(identity,name,body,arm.artifact_created(job),COMMIT))
        return rows,zips
    def make_arm_lane(self,lane):
        # The ARM importer reads the in-progress original run: same ids, steps,
        # timestamps and constructor ZIP bytes the final collector later reads.
        final_jobs=arm.jobs(self.job_names(),COMMIT,arm.job_runners(self.rs))
        earlier=[name for name,_,job in self.artifact_directories() if arm.artifact_created(job)<arm.importer_started()]
        rows,zips=self.api_artifacts(set(earlier))
        self.import_api=arm.ImportTimeApi(arm.run_document(COMMIT,status='in_progress',conclusion=None),
                                          arm.import_time_jobs(final_jobs),arm.import_time_artifacts(rows),zips)
        scratch=self.root/('scratch-'+lane['artifact_name'])
        _,self.witness=arm.produce_arm_lane(self.rs,scratch,self.inputs/lane['artifact_name'],source=self.expected,
                                            versions=own.VERSIONS,gates=lane['required_gates'],api=self.import_api)
    def make_artifacts(self):
        arm_lane=None
        for lane in required(self.rs,generation=CURRENT_GENERATION):
            if (lane['lane'],lane['system'])==('pacman','x86_64-linux'):
                arm.retain_constructor(self.root/'constructor-x86_64',self.inputs/lane['artifact_name'],self.expected,own.VERSIONS)
                continue
            if (lane['lane'],lane['system'])==('pacman','aarch64-linux'):
                arm_lane=lane;continue
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
                version=routing.VERSIONS[product];pure=product in {'theme-forge-stellar-loom','theme-forge-solar-sail'}
                if lane['lane']=='rpm':
                    obs=json.loads((FIXTURES/'native-observations'/f'{product}-{lane["system"]}.json').read_text())
                    raw=copy.deepcopy(obs['raw']);evaluation=copy.deepcopy(obs['policy_evaluation'])
                    arch=evaluation['inputs']['arch'];name=f'{product}-{version}-1.fc43.{arch}.rpm'
                    data=_make_synthetic_rpm(product,version=version,arch=arch)
                elif lane['lane']=='deb':
                    arch='all' if pure else lane['system'];name=f'{product}_{version}-1_{arch}.deb';data=build_minimal_deb(product,version+'-1',arch)
                else:continue
                package=scratch/'unsigned'/name;package.parent.mkdir(exist_ok=True);package.write_bytes(data);files.append(package)
                if lane['lane']!='rpm':continue
                # Explicit unit package double mutation: rebind only raw package_sha256
                # and package_file to the synthetic RPM header; policy_evaluation is untouched.
                raw['package_sha256']=hashlib.sha256(data).hexdigest();raw['package_file']=name
                rawpath=scratch/'diagnostics'/('rpmlint-'+product+'.json');rawpath.parent.mkdir(exist_ok=True);rawpath.write_bytes(canonical(raw));files.append(rawpath)
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
        self.make_arm_lane(arm_lane)
        jobs={name:{'result':'success'} for name in contract(self.rs,generation=CURRENT_GENERATION)['required_jobs'] if name!='summary'}
        with patch.dict(os.environ,{'RS9_JOB_CONCLUSIONS':json.dumps(jobs)}):
            self.assertEqual(summarize(self.rs,self.inputs,self.summaryroot,generation=CURRENT_GENERATION),0)
        self.summary=json.loads((self.summaryroot/'hosted-summary.json').read_text())
        self.repack()
    def repack(self):
        # Deterministic ZIP bytes: unchanged lanes keep their provider digest,
        # so the importer witness keeps joining the same constructor artifact.
        self.artifacts,self.zips=self.api_artifacts()
        self.jobs=arm.jobs(self.job_names(),COMMIT,arm.job_runners(self.rs))
    def api_row(self,name):
        return next(row for row in self.artifacts if row['name']==name)
    def api_job(self,name):
        return next(row for row in self.jobs if row['name']==name)
    def collection_reasons(self):
        return json.loads((self.collection/'manager-packet.json').read_text())['validation']['reasons']
    def derived_binary_rows(self):
        """Inventory expectations measured from the retained original manifests."""
        rows=[]
        for lane in required(self.rs,generation=CURRENT_GENERATION):
            if lane['lane'] not in {'deb','rpm','pacman'}:continue
            manifest=json.loads((self.inputs/lane['artifact_name']/'artifact-manifest.json').read_text())
            rows.extend((lane['lane'],lane['artifact_name'],lane['system'],row['path']) for row in manifest['files']
                        if is_installable_binary(row) or row.get('role')==RAW_REUSE_REPLICA)
        return rows
    def assert_current_inventory(self,binaries):
        rows=self.derived_binary_rows()
        self.assertEqual(sorted((b['family'],b['name']) for b in binaries),sorted({(r[0],Path(r[3]).name) for r in rows}))
        self.assertEqual(len(binaries),18)
        self.assertEqual(sorted((b['family'],o['artifact'],o['system'],o['path']) for b in binaries for o in b['origins']),sorted(rows))
        pacman={b['name']:b for b in binaries if b['family']=='pacman'}
        natives=own.VERSIONS.keys()-arm.ANY_PRODUCTS
        self.assertEqual({(b['product'],b['architecture']) for b in pacman.values()},
                         {(p,'any') for p in arm.ANY_PRODUCTS}|{(p,a) for p in natives for a in ('x86_64','aarch64')})
        for product in arm.ANY_PRODUCTS:
            name=arm.package_name(product,own.VERSIONS)
            # Two canonical x86_64 construction-custody origins, then exactly one ARM reuse replica.
            self.assertEqual(pacman[name]['origins'],[
                {'artifact':CANONICAL_ARTIFACT,'system':'x86_64-linux','path':'objects/lane-work/unsigned-custody/files/'+name},
                {'artifact':CANONICAL_ARTIFACT,'system':'x86_64-linux','path':'objects/lane-work/unsigned/'+name},
                {'artifact':ARM_ARTIFACT,'system':'aarch64-linux','path':'objects/lane-work/canonical-any/files/'+name}])
            body=(self.inputs/CANONICAL_ARTIFACT/'objects/lane-work/unsigned-custody/files'/name).read_bytes()
            self.assertEqual((pacman[name]['sha256'],pacman[name]['size']),(hashlib.sha256(body).hexdigest(),len(body)))
        for product in natives:
            for arch,artifact in (('x86_64',CANONICAL_ARTIFACT),('aarch64',ARM_ARTIFACT)):
                name=f'{product}-{own.VERSIONS[product]}-1-{arch}.pkg.tar.zst'
                self.assertEqual(sorted((o['artifact'],o['path']) for o in pacman[name]['origins']),
                                 [(artifact,'objects/lane-work/unsigned-custody/files/'+name),(artifact,'objects/lane-work/unsigned/'+name)])
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
        if endpoint!=f'repos/{own.RS9_REPOSITORY}/actions/runs/7':raise AssertionError('unexpected original endpoint')
        return json.dumps(self.run_document)
    def run_facade(self,scoped):
        output=self.root/('collection-'+str(len(list(self.root.glob('collection-*')))));output.mkdir();self.collection=output
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
        self.assertFalse(record['raw_clean_claim']);self.assertFalse(record['official_fedora_qualification_claim'])
        self.assertTrue(all(row['raw_clean'] is False for row in record['raw_policy_evidence']))
        self.assertEqual({row['product']:row['version'] for row in inventory['binaries']},own.VERSIONS)
        self.assert_current_inventory(inventory['binaries'])
        # The live collector re-admitted the original API rows, constructor ZIP
        # bytes and witness; its public packet retains identities only.
        packet=json.loads((self.collection/'manager-packet.json').read_text())
        self.assertEqual(packet['canonical_any']['construction_authority'],'pacman/x86_64-linux')
        self.assertEqual(packet['canonical_any']['provider'],{'lane':'pacman','system':'x86_64-linux','run_id':7,
            'job_id':self.api_job(arm.CONSTRUCTOR_JOB)['id'],'artifact_id':self.api_row(CANONICAL_ARTIFACT)['id'],
            'artifact_digest':self.api_row(CANONICAL_ARTIFACT)['digest']})
        self.assertNotIn('custody_paths',packet['canonical_any'])
        from rs9.candidate import configuration_rows
        active={intent['project']['id']:intent['version'] for _,intent in configuration_rows(self.rs,generation=CURRENT_GENERATION)}
        self.assertEqual(active['theme-forge-nebular-fusion'],'0.7.1')
        self.assertEqual(own.VERSIONS['theme-forge-nebular-fusion'],'0.7.1')
        self.assertEqual(active,own.VERSIONS)
        default_policy=load_policy(self.rs/rpm_policy_path(CURRENT_GENERATION),generation=CURRENT_GENERATION)
        self.assertEqual(record['policy_sha256'],own.digest(self.policy))
        self.assertNotEqual(record['policy_sha256'],own.digest(default_policy))
    def test_generic_binary_scope_keeps_active071_versions_without_paired_proof(self):
        from rs9 import qualified_distribution_inputs as facade
        rpm_lane=next(row for row in required(self.rs,generation=CURRENT_GENERATION)
                      if row['lane']=='rpm' and row['system']=='x86_64-linux')
        with patch.object(facade,'required',return_value=[rpm_lane]),self.assertRaises(ContractError) as error:
            facade._binary_inputs(self.rs,self.inputs,self.summary,self.expected)
        self.assertEqual(error.exception.code,'DISTRIBUTION_PROMOTION_HELD')
        with patch.object(facade,'required',return_value=[rpm_lane]),self.assertRaises(ContractError) as error:
            facade._binary_inputs(self.rs,self.inputs,self.summary,self.expected,_admission={'accepted':True})
        self.assertEqual(error.exception.code,'OWN_REPOSITORY_ADMISSION')
        # Even if promotion restrictions were absent, generic _binary_inputs without
        # an authentic _admission proof keeps default 0.7.0 RPM policy validation.
        with patch.object(facade,'required',return_value=[rpm_lane]), \
             patch.object(facade,'promotion_restrictions',return_value=([],[])):
            rpm_dir=self.inputs/'candidate-rpm-x86_64-linux';rpm_rec_path=rpm_dir/'rpm-x86_64-linux.json'
            orig_rec=rpm_rec_path.read_bytes();orig_man=(rpm_dir/'artifact-manifest.json').read_bytes()
            rec=json.loads(orig_rec);rec['production_promotion_blockers']=[]
            rpm_rec_path.write_bytes(canonical(rec))
            man=json.loads(orig_man);man['qualification_receipt_hashes']={rpm_rec_path.name:hashlib.sha256(rpm_rec_path.read_bytes()).hexdigest()}
            (rpm_dir/'artifact-manifest.json').write_bytes(canonical(man))
            summary_copy=copy.deepcopy(self.summary)
            for r in summary_copy['receipts']:
                if (r['lane'],r['system'])==('rpm','x86_64-linux'):r['production_promotion_blockers']=[]
            for m in summary_copy['artifact_manifests']:
                if (m['lane'],m['system'])==('rpm','x86_64-linux'):m.update(man)
            try:
                with self.assertRaises(ContractError) as error:
                    facade._binary_inputs(self.rs,self.inputs,summary_copy,self.expected)
                self.assertEqual(error.exception.code,'HOSTED_POLICY')
            finally:
                rpm_rec_path.write_bytes(orig_rec);(rpm_dir/'artifact-manifest.json').write_bytes(orig_man)
        # With an authentic live _Admission proof, _binary_inputs selects current071 policy and versions.
        receipts_by_key={(r['lane'],r['system']):r for r in self.summary['receipts']}
        manifests_by_key={(m['lane'],m['system']):m for m in self.summary['artifact_manifests']}
        ledger=tuple((k[0],k[1],own.digest(receipts_by_key[k]),own.digest(manifests_by_key[k])) for k in receipts_by_key)
        live_proof=own._Admission(ledger,{'scope':'unsigned-current-four-inputs'},own._PROOF)
        own._ACTIVE[live_proof]=own.digest(live_proof.record)
        self.addCleanup(own.release,live_proof)
        with patch.object(facade,'required',return_value=[rpm_lane]),patch.dict(own.VERSIONS,routing.VERSIONS):
            rpm_binaries,_=facade._binary_inputs(self.rs,self.inputs,self.summary,self.expected,_admission=live_proof)
        self.assertEqual({row['product']:row['version'] for row in rpm_binaries},routing.VERSIONS)
        admitted_binaries,_=facade._binary_inputs(self.rs,self.inputs,self.summary,self.expected,_admission=live_proof)
        self.assertEqual({row['product']:row['version'] for row in admitted_binaries},routing.VERSIONS)
        own.release(live_proof)
        lane=next(row for row in required(self.rs,generation=CURRENT_GENERATION)
                  if row['lane']=='deb' and row['system']=='amd64')
        # Component-only check with existing valid custody and no admission.
        # Old070 filenames must not become valid generic current071 inputs.
        directory=self.inputs/'candidate-deb-amd64';manifest_path=directory/'artifact-manifest.json'
        manifest=json.loads(manifest_path.read_text())
        row=next(row for row in manifest['files'] if 'theme-forge-nebular-fusion_0.7.1-' in row['path'])
        old=directory/row['path'];new_path=row['path'].replace('theme-forge-nebular-fusion_0.7.1-','theme-forge-nebular-fusion_0.7.0-',1)
        old.rename(directory/new_path);row['path']=new_path
        manifest_path.write_bytes(canonical(manifest))
        self.mutate_receipt('deb','amd64',lambda value:None)
        with patch.object(facade,'required',return_value=[lane]),self.assertRaises(ContractError) as error:
            facade._binary_inputs(self.rs,self.inputs,self.summary,self.expected)
        self.assertEqual(error.exception.code,'DISTRIBUTION_BINARY_SCOPE')

    def test070_binary_filename_cannot_pass_live071_paired_proof(self):
        # Rebind only synthetic fixture custody for a hostile 0.7.0 filename. Original
        # receipt bytes and the fixed proof's version/preservation scope stay 0.7.1.
        directory=self.inputs/'candidate-deb-amd64'
        manifest_path=directory/'artifact-manifest.json'
        manifest=json.loads(manifest_path.read_text())
        row=next(row for row in manifest['files'] if 'theme-forge-nebular-fusion_0.7.1-' in row['path'])
        old=directory/row['path'];new_path=row['path'].replace('theme-forge-nebular-fusion_0.7.1-','theme-forge-nebular-fusion_0.7.0-',1)
        old.rename(directory/new_path);row['path']=new_path
        manifest_path.write_bytes(canonical(manifest))
        receipt=directory/'deb-amd64.json';before=receipt.read_bytes()
        self.mutate_receipt('deb','amd64',lambda value:None)
        self.assertEqual(receipt.read_bytes(),before)
        with self.assertRaises(ContractError) as error:self.run_facade(True)
        self.assertEqual(error.exception.code,'DISTRIBUTION_BINARY_SCOPE')
        self.assertEqual(len(own._ACTIVE),0)

    def test_old070_proof_and_captured_version_crossover_refuse(self):
        default070=load_policy(self.rs/rpm_policy_path(CURRENT_GENERATION),generation=CURRENT_GENERATION)
        historical=load_policy()
        self.assertEqual(default070['projects']['theme-forge-nebular-fusion']['version'],'0.7.0')
        self.assertEqual(historical['projects']['theme-forge-nebular-fusion']['version'],'0.6.1')
        rpm_receipt=json.loads((self.inputs/'candidate-rpm-x86_64-linux/rpm-x86_64-linux.json').read_text())
        with self.assertRaises(ContractError) as error:
            validate_rpm_policy_source(self.rs,rpm_receipt,generation=CURRENT_GENERATION)
        self.assertEqual(error.exception.code,'HOSTED_POLICY')
        validate_rpm_policy_source(self.rs,rpm_receipt,generation=CURRENT_GENERATION,policy_variant='current071')
        with patch.dict(own.CONSUMER_FILE_HASHES,{name:hashlib.sha256((self.p/name).read_bytes()).hexdigest() for name in own.CONSUMER_FILE_HASHES}):
            consumer=self.verify()
        self.addCleanup(own.release_consumer,consumer)
        proof071=own.admit(self.rs,self.inputs,self.summary,self.expected,consumer)
        self.addCleanup(own.release,proof071)
        self.assertEqual(proof071.record['policy_sha256'],own.digest(self.policy))
        own.release(proof071)
        old_envelope=json.loads((OLD_FIXTURES/'preservation-cases/theme-forge-nebular-fusion-x86_64-linux.json').read_text())
        old_case=json.loads(gzip.decompress(base64.b64decode(old_envelope['data'])))
        obs071=json.loads((FIXTURES/'native-observations/theme-forge-nebular-fusion-x86_64-linux.json').read_text())
        def rebuild_rpm_x64(nebular_eval,nebular_raw,nebular_version):
            scratch=self.root/('crossover-'+str(len(list(self.root.glob('crossover-*')))));scratch.mkdir();files=[]
            receipt=dict(schema='rs9.hosted-candidate-diagnostic.v1alpha2',lane='rpm',system='x86_64-linux',
                production_enabled=False,publication_authority=False,attended_gates_satisfied=False,
                execution_error=None,policy_blockers=[],runner={},provenance=self.expected,
                production_promotion_blockers=[TOKEN],
                gates=[dict(name=name,status='pass') for name in next(
                    r['required_gates'] for r in required(self.rs,generation=CURRENT_GENERATION)
                    if (r['lane'],r['system'])==('rpm','x86_64-linux'))])
            details={'rpm_evidence_contract':'rs9.rpm-evidence-contract.v2'}
            for product in routing.VERSIONS:
                if product=='theme-forge-nebular-fusion':
                    raw=copy.deepcopy(nebular_raw);evaluation=copy.deepcopy(nebular_eval);version=nebular_version
                else:
                    obs=json.loads((FIXTURES/'native-observations'/f'{product}-x86_64-linux.json').read_text())
                    raw=copy.deepcopy(obs['raw']);evaluation=copy.deepcopy(obs['policy_evaluation']);version=routing.VERSIONS[product]
                arch=evaluation['inputs']['arch'];name=f'{product}-{version}-1.fc43.{arch}.rpm'
                data=_make_synthetic_rpm(product,version=version,arch=arch)
                package=scratch/'unsigned'/name;package.parent.mkdir(exist_ok=True);package.write_bytes(data);files.append(package)
                raw['package_sha256']=hashlib.sha256(data).hexdigest();raw['package_file']=name
                rawpath=scratch/'diagnostics'/('rpmlint-'+product+'.json');rawpath.parent.mkdir(exist_ok=True);rawpath.write_bytes(canonical(raw));files.append(rawpath)
                summary,chunks=write_policy_evidence(scratch,evaluation);files.extend(chunks)
                derivation=dict(project=product,adapter='rpm',artifact={'sha256':raw['package_sha256']},evidence={'rpmlint':durable_lint_projection(raw)})
                manifest=dict(schema='rs9.rpm-candidate.v1alpha2',project=product,architecture=arch,package_file='unsigned/'+name,
                    package_sha256=raw['package_sha256'],package_size=len(data),rpmlint=raw,derivation=derivation)
                mp=scratch/'build'/product/'rpm-manifest.json';mp.parent.mkdir(parents=True);mp.write_bytes(canonical(manifest));files.append(mp)
                details.setdefault('rpm_lint_raw',{})[product]=raw;details.setdefault('rpm_lint_policy',{})[product]=summary
            receipt['details']=details
            target=self.inputs/'candidate-rpm-x86_64-linux';shutil.rmtree(target)
            manifest=retain(scratch,target,files,receipt)
            summary_copy=copy.deepcopy(self.summary)
            summary_copy['receipts']=[receipt if (r['lane'],r['system'])==('rpm','x86_64-linux') else r for r in summary_copy['receipts']]
            summary_copy['artifact_manifests']=[manifest if (m['lane'],m['system'])==('rpm','x86_64-linux') else m for m in summary_copy['artifact_manifests']]
            return summary_copy
        # 1. Old 0.7.0 Nebular policy digest and 0.7.0 inputs refused by 0.7.1 admit
        eval_old070=copy.deepcopy(obs071['policy_evaluation'])
        eval_old070.update(policy_sha256=own.digest(default070),inputs=copy.deepcopy(old_case['inputs']),
                           accepted_findings=copy.deepcopy(old_case['raw']['error_records']))
        summary_old070=rebuild_rpm_x64(eval_old070,old_case['raw'],'0.7.0')
        with self.assertRaises(ContractError) as error:
            own.admit(self.rs,self.inputs,summary_old070,self.expected,consumer)
        self.assertEqual(error.exception.code,'HOSTED_POLICY')
        # 2. Crossover: 0.7.1 policy_sha256 paired with captured 0.7.0 version/inputs refused
        eval_crossover_ver=copy.deepcopy(obs071['policy_evaluation'])
        eval_crossover_ver['inputs']=copy.deepcopy(old_case['inputs'])
        eval_crossover_ver['accepted_findings']=copy.deepcopy(old_case['raw']['error_records'])
        summary_crossover_ver=rebuild_rpm_x64(eval_crossover_ver,old_case['raw'],'0.7.0')
        with self.assertRaises(ContractError) as error:
            own.admit(self.rs,self.inputs,summary_crossover_ver,self.expected,consumer)
        self.assertEqual(error.exception.code,'OWN_REPOSITORY_ADMISSION')
        self.assertEqual(error.exception.message,'Incomplete current preservation/native evaluation')
        # 3. Crossover: 0.7.1 version and 0.7.1 policy_sha256 paired with old 0.7.0 asset_sha256 refused
        eval_crossover_asset=copy.deepcopy(obs071['policy_evaluation'])
        eval_crossover_asset['inputs']['asset_sha256']=old_case['inputs']['asset_sha256']
        summary_crossover_asset=rebuild_rpm_x64(eval_crossover_asset,obs071['raw'],'0.7.1')
        with self.assertRaises(ContractError) as error:
            own.admit(self.rs,self.inputs,summary_crossover_asset,self.expected,consumer)
        self.assertEqual(error.exception.code,'OWN_REPOSITORY_ADMISSION')
        self.assertEqual(error.exception.message,'Policy/capture asset or closure differs')
        self.assertEqual(len(own._ACTIVE),0)

    def test_package_role_custody_mismatch_and_unavailable_policy_refusals(self):
        consumer=self.verify();self.addCleanup(own.release_consumer,consumer)
        # Unavailable/missing current071 policy file refuses with INVALID_POLICY / CURRENT_RPM_POLICY_HELD
        policy_file=self.rs/rpm_policy_path(CURRENT_GENERATION,policy_variant='current071')
        policy_bytes=policy_file.read_bytes();policy_file.unlink()
        try:
            with self.assertRaises(ContractError) as error:
                own.admit(self.rs,self.inputs,self.summary,self.expected,consumer)
            self.assertIn(error.exception.code,{'INVALID_POLICY','CURRENT_RPM_POLICY_HELD'})
        finally:
            policy_file.write_bytes(policy_bytes)
        # Receipt / manifest mismatch against validated summary refuses
        bad_summary=copy.deepcopy(self.summary)
        bad_summary['receipts'][0]['runner']={'tampered':True}
        with self.assertRaises(ContractError) as error:
            own.admit(self.rs,self.inputs,bad_summary,self.expected,consumer)
        self.assertEqual(error.exception.code,'OWN_REPOSITORY_ADMISSION')
        self.assertEqual(error.exception.message,'Scoped custody differs from validated original')
        bad_manifest_summary=copy.deepcopy(self.summary)
        bad_manifest_summary['artifact_manifests'][0]['qualification_receipt_hashes']={'tampered':'0'*64}
        with self.assertRaises(ContractError) as error:
            own.admit(self.rs,self.inputs,bad_manifest_summary,self.expected,consumer)
        self.assertEqual(error.exception.code,'OWN_REPOSITORY_ADMISSION')
        self.assertEqual(error.exception.message,'Scoped custody differs from validated original')
        # Disguised source RPM in unsigned binary slot refuses package-role verification under live proof
        from rs9 import qualified_distribution_inputs as facade
        rpm_dir=self.inputs/'candidate-rpm-x86_64-linux'
        pkg_rel='objects/unsigned/theme-forge-nebular-fusion-0.7.1-1.fc43.x86_64.rpm'
        pkg_path=rpm_dir/pkg_rel
        disguised=_make_synthetic_rpm('theme-forge-nebular-fusion',version='0.7.1',arch='x86_64',is_source=True)
        pkg_path.write_bytes(disguised);new_sha=hashlib.sha256(disguised).hexdigest()
        raw_path=rpm_dir/'objects/diagnostics/rpmlint-theme-forge-nebular-fusion.json'
        raw=json.loads(raw_path.read_text());raw['package_sha256']=new_sha;raw_path.write_bytes(canonical(raw))
        mp_path=rpm_dir/'objects/build/theme-forge-nebular-fusion/rpm-manifest.json'
        mp=json.loads(mp_path.read_text());mp['package_sha256']=new_sha;mp['package_size']=len(disguised)
        mp['rpmlint']=raw;mp['derivation']['artifact']['sha256']=new_sha
        mp['derivation']['evidence']['rpmlint']=durable_lint_projection(raw)
        mp_path.write_bytes(canonical(mp))
        rec_path=rpm_dir/'rpm-x86_64-linux.json';rec=json.loads(rec_path.read_text())
        rec['details']['rpm_lint_raw']['theme-forge-nebular-fusion']=raw;rec_path.write_bytes(canonical(rec))
        man_path=rpm_dir/'artifact-manifest.json';man=json.loads(man_path.read_text())
        for row in man['files']:
            if row['path'] in {pkg_rel,'objects/diagnostics/rpmlint-theme-forge-nebular-fusion.json','objects/build/theme-forge-nebular-fusion/rpm-manifest.json'}:
                p=rpm_dir/row['path'];row['sha256']=hashlib.sha256(p.read_bytes()).hexdigest();row['size']=p.stat().st_size
        man['qualification_receipt_hashes']={rec_path.name:hashlib.sha256(rec_path.read_bytes()).hexdigest()}
        man_path.write_bytes(canonical(man))
        role_summary=copy.deepcopy(self.summary)
        role_summary['receipts']=[rec if (r['lane'],r['system'])==('rpm','x86_64-linux') else r for r in role_summary['receipts']]
        role_summary['artifact_manifests']=[man if (m['lane'],m['system'])==('rpm','x86_64-linux') else m for m in role_summary['artifact_manifests']]
        proof=own.admit(self.rs,self.inputs,role_summary,self.expected,consumer)
        self.addCleanup(own.release,proof)
        with self.assertRaises(ContractError) as error:
            facade._binary_inputs(self.rs,self.inputs,role_summary,self.expected,_admission=proof)
        self.assertEqual(error.exception.code,'CUSTODY_ROLE')
        own.release(proof)
        self.mutate_receipt('rpm','x86_64-linux',lambda r:r['details']['rpm_lint_raw'].update({'theme-forge-nebular-fusion':raw}))
        with self.assertRaises(ContractError) as error:self.run_facade(True)
        self.assertEqual(error.exception.code,'DISTRIBUTION_NOT_QUALIFIED')
        self.assertEqual(len(own._ACTIVE),0)

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
        # run_facade installs its own collect wrapper, so observe the original API
        # transport itself: any collection would read it.
        calls=[];original=self.original_api
        def recording(root,argv):
            calls.append(argv);return original(root,argv)
        with patch.object(self,'original_api',side_effect=recording):
            with self.assertRaises(ContractError) as error:self.run_facade(True)
            self.assertEqual(error.exception.code,'OWN_REPOSITORY_SOURCE');self.assertEqual(calls,[])
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
        self.assert_current_inventory(result['objects'])
        for product in arm.ANY_PRODUCTS:
            name=arm.package_name(product,own.VERSIONS)
            row=next(r for r in result['objects'] if r['family']=='pacman' and r['name']==name)
            # P stages the canonical x86_64 construction bytes once; the ARM replica only witnesses them.
            self.assertEqual(row['destinations'],['unsigned/pacman/'+name])
            self.assertEqual((stage/row['destinations'][0]).read_bytes(),
                             (collection/CANONICAL_ARTIFACT/'objects/lane-work/unsigned-custody/files'/name).read_bytes())

    # ---- current ARM pacman reuse: real importer, collector and validators ----
    def test_current_arm_lane_is_reuse_witness_with_native_only_custody(self):
        directory=self.inputs/ARM_ARTIFACT
        manifest=json.loads((directory/'artifact-manifest.json').read_text())
        receipt=json.loads((directory/'pacman-aarch64-linux.json').read_text())
        any_names={arm.package_name(p,own.VERSIONS) for p in arm.ANY_PRODUCTS}
        natives=own.VERSIONS.keys()-arm.ANY_PRODUCTS
        native_names={arm.native_arm_name(p,own.VERSIONS) for p in natives}
        self.assertEqual({row['path'] for row in manifest['files'] if row.get('role')==RAW_REUSE_REPLICA},
                         {'objects/lane-work/canonical-any/files/'+n for n in any_names})
        self.assertEqual({row['path'] for row in manifest['files'] if is_installable_binary(row)},
                         {prefix+n for n in native_names for prefix in ('objects/lane-work/unsigned/','objects/lane-work/unsigned-custody/files/')})
        # No ARM any construction: no any build manifest, custody row or fixture-signed construction.
        self.assertFalse([row for row in manifest['files'] if row['path'].endswith('-any.pkg.tar.zst') and row.get('role')!=RAW_REUSE_REPLICA])
        self.assertEqual({row['path'] for row in manifest['files'] if row['path'].endswith('/pacman-manifest.json')},
                         {'objects/lane-work/build/'+p+'/pacman-manifest.json' for p in natives})
        from rs9.pages_candidate import CUSTODY_MANIFEST
        custody=json.loads((directory/'objects/lane-work/unsigned-custody'/CUSTODY_MANIFEST).read_text())
        self.assertEqual((custody['family'],custody['system'],set(custody['files'])),('pacman','aarch64-linux',native_names))
        witness=(directory/WITNESS_PATH).read_bytes();self.assertEqual(witness,self.witness)
        doc=json.loads(witness);row=self.api_row(CANONICAL_ARTIFACT)
        self.assertEqual(doc['source'],self.expected)
        self.assertEqual((doc['constructor']['job_id'],doc['importer']['job_id']),
                         (self.api_job(arm.CONSTRUCTOR_JOB)['id'],self.api_job(arm.IMPORTER_JOB)['id']))
        self.assertEqual((doc['constructor']['artifact_id'],doc['constructor']['artifact_digest'],doc['constructor']['artifact_size']),
                         (row['id'],row['digest'],row['size_in_bytes']))
        self.assertEqual(doc['constructor']['artifact_manifest_sha256'],
                         hashlib.sha256((self.inputs/CANONICAL_ARTIFACT/'artifact-manifest.json').read_bytes()).hexdigest())
        declared=receipt['details']['canonical_any_reuse']
        self.assertIs(declared['construction_on_this_lane'],False)
        self.assertEqual(declared['witness_sha256'],hashlib.sha256(witness).hexdigest())
        prefix=f'repos/{own.RS9_REPOSITORY}/actions/'
        self.assertEqual([call[4] for call in self.import_api.calls],[prefix+'runs/7',prefix+'runs/7/attempts/1/jobs?per_page=100&page=1',
                         prefix+'runs/7/artifacts?per_page=100&page=1',prefix+f'artifacts/{row["id"]}/zip'])
        self.assertEqual(self.import_api.zips[row['id']],self.zips[row['id']])
        self.assertNotIn(ARM_ARTIFACT,{a['name'] for a in self.import_api.artifacts})
        self.assertEqual(set(candidate_reuse(self.rs,self.inputs,self.expected)['replicas']),set(arm.ANY_PRODUCTS))
        self.assertEqual(self.summary['qualification_verdict'],'qualified')
    def test_arm_reuse_declaration_is_enforced_by_real_summary_and_collector(self):
        path=self.inputs/ARM_ARTIFACT/'pacman-aarch64-linux.json';saved=json.loads(path.read_text())
        first=sorted(arm.ANY_PRODUCTS)[0]
        mutations={'arm-construction':lambda r:r['details']['canonical_any_reuse'].update(construction_on_this_lane=True),
                   'other-replica-digest':lambda r:r['details']['canonical_any_reuse']['replicas'][first].update(sha256='0'*64),
                   'other-witness-digest':lambda r:r['details']['canonical_any_reuse'].update(witness_sha256='0'*64),
                   'missing-declaration':lambda r:r['details'].pop('canonical_any_reuse')}
        for label,change in mutations.items():
            with self.subTest(case=label):
                self.mutate_receipt('pacman','aarch64-linux',change)
                try:
                    self.assertEqual(self.summary['qualification_verdict'],'not-qualified')
                    self.assertIn(ARM_ARTIFACT+':CANONICAL_ANY_REUSE',self.summary['blocking_reasons'])
                    for product in arm.ANY_PRODUCTS:
                        self.assertIn(ARM_ARTIFACT+':missing-product:'+product,self.summary['blocking_reasons'])
                    with self.assertRaises(ContractError) as error:self.run_facade(True)
                    self.assertEqual(error.exception.code,'DISTRIBUTION_NOT_QUALIFIED')
                finally:
                    self.mutate_receipt('pacman','aarch64-linux',lambda r:(r.clear(),r.update(copy.deepcopy(saved))))
        self.assertEqual(self.summary['qualification_verdict'],'qualified')
        self.assertEqual(len(own._ACTIVE),0)
    def test_api_metadata_cannot_replace_original_constructor_zip_byte_join(self):
        row=self.api_row(CANONICAL_ARTIFACT);original=self.zips[row['id']]
        # Metadata-only substitution: the served bytes no longer match the API digest.
        row['digest']='sha256:'+hashlib.sha256(original+b'other').hexdigest()
        with self.assertRaises(ContractError) as error:self.run_facade(True)
        self.assertEqual(error.exception.code,'DISTRIBUTION_NOT_QUALIFIED')
        self.assertEqual(self.collection_reasons(),['HOSTED_ARTIFACTS'])
        # Same extracted custody in a different ZIP with self-consistent API metadata:
        # the importer witness still binds the original artifact bytes.
        other=arm.zip_directory(self.inputs/CANONICAL_ARTIFACT,date_time=(2026,10,29,0,39,0))
        self.assertNotEqual(other,original)
        self.zips[row['id']]=other;row.update(digest='sha256:'+hashlib.sha256(other).hexdigest(),size_in_bytes=len(other))
        with self.assertRaises(ContractError) as error:self.run_facade(True)
        self.assertEqual(error.exception.code,'DISTRIBUTION_NOT_QUALIFIED')
        self.assertEqual(self.collection_reasons(),['CANONICAL_ANY_WITNESS'])
        self.assertEqual(len(own._ACTIVE),0)
    def test_final_original_jobs_must_join_importer_witness(self):
        def strip_upload():
            job=self.api_job(arm.CONSTRUCTOR_JOB)
            job['steps']=[s for s in job['steps'] if not s['name'].startswith(any_mod.UPLOAD_STEP_PREFIX)]
        cases=[('importer-id',lambda:self.api_job(arm.IMPORTER_JOB).update(id=99),'CANONICAL_ANY_WITNESS'),
               ('constructor-id',lambda:self.api_job(arm.CONSTRUCTOR_JOB).update(id=98),'CANONICAL_ANY_WITNESS'),
               ('constructor-upload-step-missing',strip_upload,'CANONICAL_ANY_JOB')]
        for label,mutate,code in cases:
            with self.subTest(case=label):
                self.repack();mutate()
                with self.assertRaises(ContractError) as error:self.run_facade(True)
                self.assertEqual(error.exception.code,'DISTRIBUTION_NOT_QUALIFIED')
                self.assertEqual(self.collection_reasons(),[code])
        self.assertEqual(len(own._ACTIVE),0)
    def test_original_run_must_remain_main_push_attempt_one(self):
        for label,change in (('attempt',{'run_attempt':2}),('event',{'event':'workflow_dispatch'}),('branch',{'head_branch':'topic'})):
            with self.subTest(case=label):
                saved=copy.deepcopy(self.run_document);self.run_document.update(change)
                try:
                    with self.assertRaises(ContractError) as error:self.run_facade(True)
                    self.assertEqual(error.exception.code,'DISTRIBUTION_NOT_QUALIFIED')
                    self.assertEqual(self.collection_reasons(),['HOSTED_BINDING'])
                finally:
                    self.run_document=saved
        self.assertEqual(len(own._ACTIVE),0)

    # ---- nested SDK source hygiene ----
    def test_nested_sdk_modules_join_selected_checkout(self):
        import rs9.archarm_sdk  # loads the nested rs9._archarm_support package
        self.assertTrue(any(name.startswith('rs9._archarm_support.') for name in sys.modules))
        own.verify_execution_source(self.rs)
        self.execution_root_join.stop()
        own.verify_execution_source(ROOT)
    def test_nested_sdk_body_inventory_and_origin_mismatches_refuse(self):
        import rs9.archarm_sdk
        from rs9._archarm_support import refusal as nested
        support=self.rs/'src/rs9/_archarm_support'
        def changed(name):
            path=support/name;original=path.read_bytes();path.write_bytes(original+b'\n# changed\n')
            return lambda:path.write_bytes(original)
        def extra():
            path=support/'unselected_helper.py';path.write_bytes(b'');return path.unlink
        def missing():
            path=support/'refusal.py';original=path.read_bytes();path.unlink()
            return lambda:path.write_bytes(original)
        for label,mutate in (('changed-nested-body',lambda:changed('origin.py')),('changed-nested-init',lambda:changed('__init__.py')),
                             ('extra-nested-module',extra),('missing-nested-module',missing)):
            with self.subTest(case=label):
                restore=mutate()
                try:
                    with self.assertRaises(ContractError) as error:own.verify_execution_source(self.rs)
                    self.assertEqual(error.exception.code,'OWN_REPOSITORY_SOURCE')
                finally:
                    restore()
        own.verify_execution_source(self.rs)
        foreign=str(self.root/'refusal.py')
        with patch.object(nested,'__file__',foreign),self.assertRaises(ContractError) as error:own.verify_execution_source(self.rs)
        self.assertEqual(error.exception.code,'OWN_REPOSITORY_SOURCE')
        with patch.object(nested.__spec__,'origin',foreign),self.assertRaises(ContractError) as error:own.verify_execution_source(self.rs)
        self.assertEqual(error.exception.code,'OWN_REPOSITORY_SOURCE')
        namespace={'__name__':'rs9._archarm_support.refusal'}
        exec(compile('def require(*a,**kw): return None',foreign,'exec'),namespace)
        with patch.object(nested,'require',namespace['require']),self.assertRaises(ContractError) as error:own.verify_execution_source(self.rs)
        self.assertEqual(error.exception.code,'OWN_REPOSITORY_SOURCE')
    def test_current_builder_identity_covers_nested_sdk_pin_data(self):
        self.assertEqual(builder_identity(self.rs,generation=CURRENT_GENERATION),self.expected['builder_source_sha256'])
        pins=self.rs/'src/rs9/_archarm_support/pins'
        for name in ('ROOTFS-PIN.json','PACKAGE-PINS.json','archlinuxarm-builder-public.gpg'):
            with self.subTest(pin=name):
                path=pins/name;original=path.read_bytes();path.write_bytes(original+b'\n')
                try:
                    self.assertNotEqual(builder_identity(self.rs,generation=CURRENT_GENERATION),self.expected['builder_source_sha256'])
                finally:
                    path.write_bytes(original)
        path=pins/'PACKAGE-PINS.json';path.write_bytes(path.read_bytes()+b'\n')
        calls=[];original=self.original_api
        def recording(root,argv):
            calls.append(argv);return original(root,argv)
        with patch.object(self,'original_api',side_effect=recording),self.assertRaises(ContractError) as error:self.run_facade(True)
        self.assertEqual(error.exception.code,'DISTRIBUTION_SOURCE')
        self.assertEqual(calls,[])
        self.assertEqual(len(own._ACTIVE),0)


if __name__=='__main__':unittest.main()
