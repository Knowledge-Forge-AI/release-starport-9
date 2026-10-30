"""Pure current-generation policy/wiring tests; native tools are explicit doubles."""
import copy
import io
import json
from pathlib import Path
import tarfile
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch
from contextlib import ExitStack

from rs9.current_generation import HISTORICAL_GENERATION, CURRENT_GENERATION
from rs9.errors import ContractError
from rs9.release_core import digest
from rs9.rpm_lint_policy import load_policy, _validate_policy, evaluate_policy, CURRENT_VERSIONS
from rs9.rpm_preservation import INVENTORY_SCHEMA
from rs9.build_rpm import build_rpm_candidate
from rs9.build_native import CommandReceipt, validate_build_inputs
from tests.test_rpm_lint_policy import raw_from_records
from tests import test_build_rpm as build_fixtures
from tests.test_build_native import create_cli_fixture


def current_case():
    policy = load_policy(generation=CURRENT_GENERATION)
    name = 'theme-forge-stellar-loom'
    entry = policy['projects'][name]
    inputs = dict(project_id=name, version='0.5.0', arch='noarch', system='x86_64-linux',
                  asset_sha256=entry['authenticated_inputs']['asset_sha256'],
                  payload_manifest_sha256='c'*64, closure_sha256=None)
    inventory = dict(schema=INVENTORY_SCHEMA, complete=True, package_sha256='f'*64,
                     files={}, expected={}, wrappers={}, permitted_directories=[],
                     engine_node='>=22', requires=['nodejs >= 22'],
                     **{k:inputs[k] for k in ('asset_sha256','payload_manifest_sha256','closure_sha256')})
    for rule in entry['launchers'].values():
        path, target = rule['path'], rule['target']
        body = ('#!/bin/sh\nexec node "'+target+'" "$@"\n').encode()
        row = dict(type='file', mode=0o755, size=len(body), sha256=digest(body))
        inventory['expected'][path] = row
        inventory['files'][path] = dict(row, owner='root', group='root', flags=0)
        inventory['wrappers'][path] = dict(target=target, sha256=digest(body), mode=0o755, type='file')
    return raw_from_records([]), inventory, inputs, policy


class CurrentRpmDiagnosticPolicyTests(unittest.TestCase):
    def test_generation_is_explicit_and_cross_generation_policies_reject(self):
        historical = load_policy()
        current = load_policy(generation=CURRENT_GENERATION)
        self.assertEqual(CURRENT_VERSIONS['theme-forge-stellar-loom'], '0.4.0')
        for policy, generation in [(historical,CURRENT_GENERATION),(current,HISTORICAL_GENERATION)]:
            with self.subTest(generation=generation), self.assertRaises(ContractError):
                _validate_policy(policy,generation=generation)
        with self.assertRaises(ContractError):
            load_policy(Path('operators/live1/rpm-lint-policy.json'),generation=CURRENT_GENERATION)
        with self.assertRaises(ContractError):
            load_policy(Path('operators/theme-forge-current-202610/rpm-lint-policy.json'))
        for generation in ('unknown','../live1'):
            with self.assertRaises(ContractError):load_policy(generation=generation)
        with tempfile.TemporaryDirectory() as tmp:
            path=Path(tmp)/'arbitrary.json'; path.write_text(json.dumps(current))
            current['projects']['theme-forge-stellar-loom']['version']='9.0.0'
            path.write_text(json.dumps(current))
            with self.assertRaises(ContractError):load_policy(path,generation=CURRENT_GENERATION)

    def test_current_policy_cannot_authorize_or_change_exact_contract(self):
        original=load_policy(generation=CURRENT_GENERATION)
        mutations = [lambda p:p.update(status='authorized'), lambda p:p.update(blocking=False),
            lambda p:p.update(production_enabled=True), lambda p:p.update(publication_authority=True),
            lambda p:p['tool_constraints'].update(filtered_count=0),
            lambda p:p['projects']['theme-forge-stellar-loom'].update(status='authorized'),
            lambda p:p['projects']['theme-forge-stellar-loom'].update(exceptions={'env-script-interpreter':{}}),
            lambda p:p['projects']['theme-forge-stellar-loom'].update(allowed_architectures=['x86_64']),
            lambda p:p['projects']['theme-forge-stellar-loom']['authenticated_inputs'].update(asset_sha256='0'*64),
            lambda p:p['projects']['theme-forge-stellar-loom']['launchers']['tfsl'].update(target='/usr/bin/other'),
            lambda p:p['projects']['theme-forge-nebular-fusion']['public_symlinks']['tfnf'].update(target='/usr/bin/other'),
            lambda p:p['projects']['theme-forge-nebular-fusion']['runtime_requires_contract'].update(sha256='0'*64)]
        for mutate in mutations:
            policy=copy.deepcopy(original); mutate(policy)
            with self.assertRaises(ContractError):_validate_policy(policy,generation=CURRENT_GENERATION)

    def test_clean_raw_lint_never_accepts_blocked_empty_exception_policy(self):
        raw,inventory,inputs,policy=current_case()
        result=evaluate_policy(raw,inventory,inputs,policy,generation=CURRENT_GENERATION)
        self.assertFalse(result['accepted'])
        self.assertEqual(result['status'],'blocked')
        self.assertEqual(result['accepted_findings'],[])
        self.assertEqual(set(result['blockers']),{'current-generation-diagnostic-only','incomplete-project-policy'})
        self.assertEqual(result['raw_lint_status'],'pass')
        for code in ('no-changelogname-tag','explicit-lib-dependency','env-script-interpreter'):
            result=evaluate_policy(raw_from_records([dict(code=code,target=inputs['project_id']+'.noarch')]),
                                   inventory,inputs,policy,generation=CURRENT_GENERATION)
            self.assertFalse(result['accepted']);self.assertEqual(result['accepted_findings'],[])
            self.assertIn('unapproved-error-code:'+code,result['blockers'])

    def test_unavailable_current_source_contract_is_blocked_without_historical_fallback(self):
        raw,inventory,inputs,policy=current_case()
        with patch('rs9.rpm_lint_policy.Path.read_bytes',side_effect=OSError('missing selected source')):
            result=evaluate_policy(raw,inventory,inputs,policy,generation=CURRENT_GENERATION)
        self.assertFalse(result['accepted'])
        self.assertEqual(result['blockers'],['malformed-or-unavailable-policy-evidence'])

    def test_current_builder_raw_lint_precedes_policy_and_retains_failure_objects(self):
        from rs9 import rpm_lint_policy
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);capture,intent,npm=create_cli_fixture(root/'capture')
            work=root/'work';work.mkdir()
            runner=build_fixtures.BuildRpmTests()._setup_runner()
            raw_handler=runner.handlers['rpmlint'];order=[]
            def lint(argv,**kwargs):
                if '--version' not in argv:order.append('raw-lint')
                return raw_handler(argv,**kwargs)
            runner.handlers['rpmlint']=lint
            def evaluation(*args,**kwargs):
                order.append('policy');self.assertEqual(kwargs['generation'],CURRENT_GENERATION)
                return rpm_lint_policy.evaluate_policy(*args,**kwargs)
            with patch('rs9.build_rpm.evaluate_policy',side_effect=evaluation):
                with self.assertRaises(ContractError) as caught:
                    build_rpm_candidate(capture,intent,'noarch',work,offline_npm_archives=npm,
                        runner=runner,policy=load_policy(generation=CURRENT_GENERATION),generation=CURRENT_GENERATION)
            error=caught.exception
            self.assertEqual(order,['raw-lint','policy'])
            self.assertEqual(error.code,'RPMLINT_FAILED')
            self.assertFalse(error.rpmlint_policy['accepted'])
            self.assertIn('current-generation-diagnostic-only',error.rpmlint_policy['blockers'])
            for path,key in [(error.package_path,'package_sha256'),(error.spec_path,'spec_sha256')]:
                self.assertEqual(digest(Path(path).read_bytes()),getattr(error,key))
            self.assertEqual(error.construction_witness['package_sha256'],error.package_sha256)
            self.assertEqual(error.rpmlint_evidence['status'],'pass')
            self.assertFalse(any('createrepo_c' in command['argv'][0] for command in runner.calls))
            self.assertFalse((work/'rpm-manifest.json').exists())

    def test_current_policy_load_failure_does_not_reload_historical_default(self):
        from rs9 import rpm_lint_policy
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);capture,intent,npm=create_cli_fixture(root/'capture');work=root/'work';work.mkdir()
            with patch.object(rpm_lint_policy,'load_policy',side_effect=ContractError('INVALID_POLICY','missing current')) as loader:
                with self.assertRaises(ContractError) as caught:
                    build_rpm_candidate(capture,intent,'noarch',work,offline_npm_archives=npm,
                        runner=build_fixtures.BuildRpmTests()._setup_runner(),generation=CURRENT_GENERATION)
            self.assertEqual(loader.call_count,1)
            loader.assert_called_once_with(generation=CURRENT_GENERATION)
            self.assertEqual(caught.exception.code,'RPMLINT_FAILED')
            self.assertFalse(caught.exception.rpmlint_policy['accepted'])

    def test_builder_floor_uses_real_capture_only_for_current_generation(self):
        from rs9.build_native import MockCommandRunner
        for generation in (HISTORICAL_GENERATION,CURRENT_GENERATION):
            with tempfile.TemporaryDirectory() as tmp:
                root=Path(tmp);archive=root/'native.tar.gz'
                with tarfile.open(archive,'w:gz') as tar:
                    for name,data in [('theme-forge-nebular-fusion/bin/gui',b'\x7fELFfixture'),
                                      ('theme-forge-nebular-fusion/bin/script',b'#!/usr/bin/env node\n')]:
                        member=tarfile.TarInfo(name);member.size=len(data);member.mode=0o755;tar.addfile(member,io.BytesIO(data))
                capture=SimpleNamespace(source={'icon.png':b'fixture'},record={})
                name='theme-forge-nebular-fusion'
                ctx=dict(project_id=name,version='0.7.0',is_native=True,arch='x86_64',asset_name=archive.name,
                    asset_bytes=archive.read_bytes(),asset_file=archive,is_native_desktop=True,payload_root=name,
                    payload={'launchers':{'tfnf':{'path':name+'/bin/tfnf'}}},summary='fixture')
                policy={'projects':{name:{'runtime_requires_contract':{'fixture':'caller contract'}}}}
                runner=MockCommandRunner(available_tools={t:'/fixture/'+t for t in ['rpmbuild','rpm','rpmlint','createrepo_c']})
                work=root/'work';work.mkdir()
                with patch('rs9.build_rpm.validate_build_inputs',return_value=ctx),patch('rs9.build_rpm.png_size'), \
                     patch('rs9.elf.parse_elf',return_value={'needed':[]}), \
                     patch('rs9.nebular_callers.release_runtime_floor',side_effect=ContractError('FLOOR_REACHED','sentinel')) as floor:
                    with self.assertRaises(ContractError) as caught:
                        build_rpm_candidate(capture,{'desktop':{'icon':{'path':'icon.png'}}},'x86_64',work,
                            runner=runner,policy=policy,generation=generation)
                self.assertEqual(caught.exception.code,'FLOOR_REACHED')
                self.assertEqual(floor.call_args.args,(archive,policy['projects'][name]))
                self.assertEqual(floor.call_args.kwargs,{} if generation==HISTORICAL_GENERATION else {'capture':capture})

    def test_hosted_current_rejection_retains_evidence_and_never_reaches_signer_or_repository(self):
        from rs9 import hosted_packaging as hosted
        from rs9.build_native import MockCommandRunner
        from tests.rpm_summary_fixtures import witnessed_build_double
        policy=load_policy(generation=CURRENT_GENERATION)
        for missing_policy in (False,True):
            with self.subTest(missing_policy=missing_policy),tempfile.TemporaryDirectory() as tmp:
                root=Path(tmp);scratch=root/'work';scratch.mkdir()
                context=dict(family='rpm',system='x86_64-linux',repository=Path('.').resolve(),
                    scratch=scratch,pins={},client=None,generation=CURRENT_GENERATION,
                    captures=[(SimpleNamespace(),{'project':{'id':pid}}, {}) for pid in policy['projects']],
                    binding={'source_commit':'0'*40},authentication_sha256='1'*64,
                    runner=MockCommandRunner(available_tools={'docker':'fixture-docker'}))
                environment=dict(platform='linux/amd64',image_ref='fixture@sha256:'+'a'*64,preprovisioned_packages=[],tools={})
                seen=[]
                def build(capture,intent,arch,work,**kwargs):
                    pid=intent['project']['id'];seen.append(pid)
                    self.assertEqual(kwargs['generation'],CURRENT_GENERATION)
                    self.assertEqual(kwargs['policy'],{} if missing_policy else policy)
                    rpm=work/(pid+'.rpm');spec=work/(pid+'.spec')
                    rpm.write_bytes(b'fixture-unsigned-rpm');spec.write_bytes(b'Name: fixture\n')
                    raw=raw_from_records([]);raw.update(package_sha256=digest(rpm.read_bytes()),spec_sha256=digest(spec.read_bytes()))
                    raw['tool_receipt'].update(stdout_sha256=digest(b'clean'),stderr_sha256=digest(b''))
                    evaluation=evaluate_policy(raw,{},dict(project_id=pid,version=policy['projects'][pid]['version'],arch=arch,
                        system='x86_64-linux'),kwargs['policy'],generation=kwargs['generation'])
                    error=ContractError('RPMLINT_FAILED','blocked current diagnostic policy',details={'substage':'rpmlint'})
                    error.rpmlint_evidence=raw;error.rpmlint_policy=evaluation
                    error.package_path=str(rpm);error.spec_path=str(spec)
                    error.package_sha256=raw['package_sha256'];error.spec_sha256=raw['spec_sha256']
                    raise error
                with ExitStack() as stack:
                    for target,value in [('rs9.hosted_packaging.provision',environment),
                        ('rs9.hosted_packaging.container_tool_facts',{}),
                        ('rs9.hosted_packaging._resolve_offline_npm_archives',None),
                        ('rs9.hosted_packaging.prepare_client',{'status':'unavailable'}),
                        ('rs9.rpm_client_runtime.bind_engine_floors',{'status':'unavailable'})]:
                        stack.enter_context(patch(target,return_value=value))
                    for target in ['rs9.hosted_deb.provision_image','rs9.hosted_packaging.checked']:
                        stack.enter_context(patch(target))
                    stack.enter_context(patch('rs9.nebular_callers.collect_caller_sources',side_effect=ContractError('CALLER_SOURCE_UNAVAILABLE','fixture')))
                    stack.enter_context(patch.object(hosted,'build_rpm_candidate',side_effect=witnessed_build_double(build)))
                    for target in ['rs9.hosted_packaging.SigningFixture','rs9.rpm_repository.metadata_command','rs9.hosted_deb.client_cycle']:
                        stack.enter_context(patch(target,side_effect=AssertionError('rejection must stop downstream action')))
                    loader=stack.enter_context(patch('rs9.rpm_lint_policy.load_policy',
                        side_effect=ContractError('INVALID_POLICY','missing selected current') if missing_policy else None,
                        return_value=policy))
                    result=hosted.execute(context)
                loader.assert_called_once_with(context['repository']/'operators/theme-forge-current-202610/rpm-lint-policy.json',generation=CURRENT_GENERATION)
                self.assertEqual(set(seen),set(policy['projects']))
                gates={row['name']:row for row in result['gates']}
                self.assertEqual(gates['rpm-lint-policy-accepted']['status'],'fail')
                self.assertEqual(gates['rpm-repository-indexing']['status'],'not-run')
                self.assertEqual(gates['rpm-client-qualification']['status'],'not-run')
                self.assertFalse((scratch/'unsigned-custody').exists())
                for pid in seen:
                    failure=result['details']['product_failures'][pid]
                    self.assertEqual(failure['code'],'RPMLINT_FAILED')
                    self.assertIn(scratch/'quarantine'/(pid+'.rpm'),result['artifacts'])
                    self.assertTrue((scratch/'diagnostics'/('rpmlint-'+pid+'.json')).is_file())
                    self.assertTrue(any('spec' in path.name for path in result['artifacts']))
                    self.assertIn(pid,result['details']['construction_witnesses'])
