"""Actual-record regressions and controlled complete preservation proofs.

Historical records are immutable evidence. Synthetic inventories prove source
contracts only, with native signing, payload and client authority kept separate.
"""
import copy
import json
from pathlib import Path
import stat
import tempfile
import unittest

from rs9.build_native import CommandReceipt, MockCommandRunner, validate_build_inputs, stage_offline_npm_closure, npm_bundle
from rs9.errors import ContractError
from rs9.release_core import digest
from rs9.rpm_lint import parse_rpmlint_output
from rs9.rpm_lint_policy import evaluate_policy, load_policy
from rs9.rpm_preservation import INVENTORY_SCHEMA, parse_dump, duplicate_groups, duplicate_waste_totals, collect_preservation_inventory
from tests.rpm_fixtures import inventory_response
from tests.test_build_native import create_cli_fixture

FIXTURES = Path(__file__).parent/'fixtures/run9/rpm'


def raw_from_records(records, warnings=0, filtered=8):
    records=[dict(level='E',arguments_complete=True,**r) if 'level' not in r else r for r in records]
    return dict(error_records=records,parse_complete=True,unparsed_count=0,error_overflow=False,
                clean=not records,status='fail' if records else 'pass',package_sha256='f'*64,
                findings_summary=dict(errors=len(records),warnings=warnings,filtered=filtered,packages=1,specfiles=1),
                tool_receipt=dict(exit_code=64 if records else 0,stderr_bytes=0,executed=True),
                tool_version=dict(exit_code=0,version='2.8.0',package_query=dict(exit_code=0,version='rpmlint|2.8.0|2.fc43|noarch')))


def complete_case(name='theme-forge-stellar-loom', arch='noarch', system='x86_64-linux'):
    policy = load_policy()
    entry = policy['projects'][name]
    auth = entry['authenticated_inputs']
    asset = auth.get('asset_sha256') or next(r['sha256'] for r in auth['assets'] if arch in r['name'])
    inputs = dict(project_id=name,version=entry['version'],arch=arch,system=system,asset_sha256=asset,
                  payload_manifest_sha256='c'*64,closure_sha256=auth.get('closure_sha256'))
    inventory = dict(schema=INVENTORY_SCHEMA,complete=True,package_sha256='f'*64,files={},expected={},wrappers={},
                     permitted_directories=[],engine_node='>=22.0.0',requires=['nodejs >= 22'],**{k:inputs[k] for k in ('asset_sha256','payload_manifest_sha256','closure_sha256')})
    records=[]
    def add_file(path,body,mode=0o644,origin='release'):
        inventory['expected'][path]=dict(path=path,type='file',size=len(body),mode=mode,sha256=digest(body),
                                       input_member='package/'+path.split('/'+name+'/',1)[-1],
                                       input_archive_sha256=asset,origin=origin,shebang=body.split(b'\n')[0].decode() if body.startswith(b'#!') else None)
    for code,rules in entry['exceptions'].items():
        if code=='files-duplicated-waste':
            body=b'x'*rules['expected_waste_bytes']
            for suffix in ('a.dat','b.dat'): add_file('/usr/lib/'+name+'/duplicates/'+suffix,body)
            records.append(dict(code=code,target=name+'.'+arch,waste_bytes=len(body)))
            continue
        for path,rule in rules.items():
            mode=int(rule.get('mode','0755'),8)
            add_file(path,b'#!/usr/bin/env node\n'+path.encode()+b'\n',mode)
            record=dict(code=code,target=name+'.'+arch,path=path,interpreter='/usr/bin/env node')
            if code=='non-executable-script': record['mode']=format(mode,'o')
            records.append(record)
            if rule.get('launcher'):
                launcher=rule['launcher']
                body=('#!/bin/sh\nexec node "'+path+'" "$@"\n').encode()
                add_file(launcher,body,0o755,'maintained-launcher')
                inventory['wrappers'][launcher]=dict(target=path,sha256=digest(body),mode=0o755,type='file')
    for inode,(path,row) in enumerate(inventory['expected'].items(),1):
        inventory['files'][path]=dict(row,owner='root',group='root',inode=inode,device=1,flags=0)
    return raw_from_records(records),inventory,inputs,policy


class CandidatePolicyTests(unittest.TestCase):
    def test_authorized_script_and_duplicate_proofs_keep_raw_failure(self):
        for name,arch in (('theme-forge-stellar-burst','x86_64'),('theme-forge-stellar-loom','noarch'),('theme-forge-solar-sail','noarch')):
            for system in ('x86_64-linux','aarch64-linux'):
                raw,inventory,inputs,policy=complete_case(name,'aarch64' if arch!='noarch' and system=='aarch64-linux' else arch,system)
                original=copy.deepcopy(raw)
                result=evaluate_policy(raw,inventory,inputs,policy)
                self.assertTrue(result['accepted'],result['blockers'])
                self.assertEqual(result['status'],'accepted')
                self.assertEqual(result['raw_exit_code'],64)
                self.assertEqual(result['raw_lint_status'],'fail')
                self.assertEqual(len(result['accepted_findings']),len(raw['error_records']))
                self.assertEqual(raw,original)

    def test_table_driven_wrong_identity_member_mode_target_and_environment(self):
        mutations = {
            'version':lambda r,i,x,p:x.update(version='0.4.1'),
            'project':lambda r,i,x,p:x.update(project_id='unknown'),
            'platform':lambda r,i,x,p:x.update(system='x86_64-darwin'),
            'arch':lambda r,i,x,p:x.update(arch='x86_64'),
            'asset-hash':lambda r,i,x,p:x.update(asset_sha256='0'*64),
            'closure-hash':lambda r,i,x,p:x.update(closure_sha256='0'*64),
            'manifest-hash':lambda r,i,x,p:x.update(payload_manifest_sha256='0'*64),
            'package-hash':lambda r,i,x,p:r.update(package_sha256='0'*64),
            'mode':lambda r,i,x,p:i['files'][r['error_records'][0]['path']].update(mode=0o644),
            'bytes':lambda r,i,x,p:i['files'][r['error_records'][0]['path']].update(sha256='0'*64),
            'shebang':lambda r,i,x,p:i['expected'][r['error_records'][0]['path']].update(shebang='#!/bin/bash'),
            'owner':lambda r,i,x,p:i['files'][r['error_records'][0]['path']].update(owner='other'),
            'link':lambda r,i,x,p:i['files'][r['error_records'][0]['path']].update(type='symlink',target='different'),
            'path':lambda r,i,x,p:r['error_records'][0].update(path='/usr/bin/unexpected'),
            'repeated-path':lambda r,i,x,p:r['error_records'][0].update(path=r['error_records'][1]['path']),
            'target':lambda r,i,x,p:r['error_records'][0].update(target='different.noarch'),
            'unknown-code':lambda r,i,x,p:r['error_records'][0].update(code='unknown-error'),
            'changelog':lambda r,i,x,p:r['error_records'][0].update(code='no-changelogname-tag'),
            'library':lambda r,i,x,p:r['error_records'][0].update(code='explicit-lib-dependency'),
            'missing-node':lambda r,i,x,p:i.update(requires=[]),
            'wrong-node-version':lambda r,i,x,p:i.update(requires=['nodejs >= 20']),
            'source-engine':lambda r,i,x,p:i.update(engine_node='>=24'),
            'wrapper':lambda r,i,x,p:i['files']['/usr/bin/tfsl-batch'].update(sha256='0'*64),
            'wrapper-target':lambda r,i,x,p:i['wrappers']['/usr/bin/tfsl-batch'].update(target='/different'),
            'extra-public-launcher':lambda r,i,x,p:i['files'].update({'/usr/bin/unexpected':dict(type='file',mode=0o755)}),
        }
        for name,mutate in mutations.items():
            with self.subTest(name=name):
                raw,inventory,inputs,policy=complete_case()
                mutate(raw,inventory,inputs,policy)
                result=evaluate_policy(raw,inventory,inputs,policy)
                self.assertFalse(result['accepted'])
                self.assertEqual(result['accepted_findings'],[])

    def test_tool_execution_incomplete_unknown_and_count_mismatch_are_blocking(self):
        mutations = [lambda r:r['tool_receipt'].update(executed=False),lambda r:r['tool_receipt'].update(exit_code=0),lambda r:r['tool_receipt'].update(exit_code=1),
                     lambda r:r['tool_receipt'].update(stderr_bytes=1),lambda r:r.update(parse_complete=False),
                     lambda r:r['error_records'][0].update(arguments_complete=False),lambda r:r.update(error_overflow=True),lambda r:r.update(unparsed_count=1),
                     lambda r:r.update(error_records=r['error_records'][:-1]),lambda r:r.update(clean=True),
                     lambda r:r['findings_summary'].update(errors=True),lambda r:r['findings_summary'].update(filtered=9),
                     lambda r:r['findings_summary'].update(packages=2),lambda r:r['findings_summary'].update(specfiles=0),
                     lambda r:r['tool_version'].update(version='2.9.0'),lambda r:r['tool_version']['package_query'].update(exit_code=1)]
        for mutate in mutations:
            raw,inventory,inputs,policy=complete_case();mutate(raw)
            self.assertFalse(evaluate_policy(raw,inventory,inputs,policy)['accepted'])
        for inventory in (None,{},dict(schema=INVENTORY_SCHEMA,complete=False)):
            raw,_,inputs,policy=complete_case()
            self.assertFalse(evaluate_policy(raw,inventory,inputs,policy)['accepted'])

    def test_malformed_raw_typed_data_cannot_raise_or_accept(self):
        raw,inventory,inputs,policy=complete_case()
        for wrong in (None,[],"wrong",1,True):
            self.assertFalse(evaluate_policy(wrong,inventory,inputs,policy)['accepted'])
        self.assertFalse(evaluate_policy(raw,inventory,None,policy)['accepted'])

    def test_malformed_observation_members_and_serialization_are_blocked(self):
        mutations = (
            lambda r,i: r.update(error_records=[None]),
            lambda r,i: r.update(error_records=['wrong']),
            lambda r,i: r['error_records'][0].update(path=[]),
            lambda r,i: i.update(expected=[]),
            lambda r,i: i['expected'][r['error_records'][0]['path']].pop('input_archive_sha256'),
            lambda r,i: i['expected'][r['error_records'][0]['path']].pop('mode'),
            lambda r,i: r.update(tool_receipt=None),
            lambda r,i: i.update(duplicate_groups=[object()]),
        )
        for mutate in mutations:
            raw,inventory,inputs,policy=complete_case()
            mutate(raw,inventory)
            self.assertFalse(evaluate_policy(raw,inventory,inputs,policy)['accepted'])

    def test_declared_policy_launchers_and_shebangs_are_enforced(self):
        mutations = (
            lambda p: p['launchers']['tfsl'].update(target='/usr/lib/theme-forge-stellar-loom/other.js'),
            lambda p: p['launchers']['tfsl'].update(path='/usr/bin/other'),
            lambda p: p['launchers']['tfsl'].update(mode='0644'),
            lambda p: p['launchers']['tfsl'].update(type='symlink'),
            lambda p: p['launchers'].pop('tfsl'),
            lambda p: next(iter(p['exceptions']['env-script-interpreter'].values())).update(shebang='/bin/bash'),
        )
        for mutate in mutations:
            raw,inventory,inputs,policy=complete_case()
            mutate(policy['projects'][inputs['project_id']])
            self.assertFalse(evaluate_policy(raw,inventory,inputs,policy)['accepted'])

    def test_mixed_prefix_duplicates_accept_only_declared_possible_total(self):
        raw,inventory,inputs,policy=complete_case('theme-forge-stellar-burst','x86_64')
        source='/usr/lib/'+inputs['project_id']+'/duplicates/a.dat'
        target='/usr/share/licenses/'+inputs['project_id']+'/LICENSE'
        inventory['expected'][target]=dict(inventory['expected'][source],path=target,origin='license-projection')
        inventory['files'][target]=dict(inventory['files'][source],path=target,inode=999)
        groups,waste=duplicate_groups(inventory['files'])
        self.assertIsNone(waste)
        self.assertEqual(duplicate_waste_totals(groups),[0,214129])
        self.assertTrue(evaluate_policy(raw,inventory,inputs,policy)['accepted'])
        raw['error_records'][-1]['waste_bytes']=0
        self.assertFalse(evaluate_policy(raw,inventory,inputs,policy)['accepted'])

    def test_policy_missing_malformed_wildcard_and_future_scope_fail_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            path=Path(tmp)/'policy.json'
            for content in (None,'not json','{}'):
                if content is not None:path.write_text(content)
                with self.assertRaises(ContractError):load_policy(path)
        for mutation in (lambda p:p.update(schema='old'),lambda p:p.update(production_enabled=True),
                         lambda p:p['projects']['theme-forge-stellar-loom'].update(version='0.4.1'),
                         lambda p:p['projects']['theme-forge-stellar-loom']['exceptions'].update({'explicit-lib-dependency':{}}),
                         lambda p:p['projects']['theme-forge-stellar-loom']['exceptions'].update({'env-script-interpreter':{'/usr/lib/theme-forge-stellar-loom/*':{}}})):
            raw,inventory,inputs,policy=complete_case();mutation(policy)
            self.assertFalse(evaluate_policy(raw,inventory,inputs,policy)['accepted'])

    def test_excess_duplicate_waste_arbitrary_duplicates_and_hardlinks_block(self):
        for mutation in ('waste','extra','hardlink','license-copy'):
            raw,inventory,inputs,policy=complete_case('theme-forge-stellar-burst','x86_64')
            if mutation=='waste':raw['error_records'][-1]['waste_bytes']+=1
            elif mutation=='extra':
                inventory['files']['/usr/lib/'+inputs['project_id']+'/unexpected.dat']=dict(next(iter(inventory['files'].values())))
            elif mutation=='hardlink':
                rows=list(inventory['files'].values());rows[-1]['inode']=rows[-2]['inode']
            else:
                inventory['files']['/usr/share/licenses/unreviewed/LICENSE']=dict(next(iter(inventory['files'].values())))
            self.assertFalse(evaluate_policy(raw,inventory,inputs,policy)['accepted'])

    def test_no_exceptions_raw_clean_and_nebular_incomplete_are_distinct(self):
        raw,inventory,inputs,policy=complete_case()
        raw=raw_from_records([])
        result=evaluate_policy(raw,inventory,inputs,policy)
        self.assertTrue(result['accepted']);self.assertEqual(result['status'],'accepted-no-exceptions')
        raw,inventory,inputs,policy=complete_case('theme-forge-nebular-fusion','x86_64')
        self.assertIn('incomplete-project-policy',evaluate_policy(raw,inventory,inputs,policy)['blockers'])


class RealRun9EvidenceTests(unittest.TestCase):
    def test_all_selected_fixture_hashes_match_upload_provenance(self):
        provenance=json.loads((FIXTURES/'provenance.json').read_bytes())
        for path,row in provenance['files'].items():
            data=(FIXTURES/path).read_bytes()
            self.assertEqual(len(data),row['bytes']);self.assertEqual(digest(data),row['sha256'])

    def test_all_eight_actual_records_parse_without_inventing_missing_errors(self):
        records=list(FIXTURES.glob('*-linux/rpmlint-*.json'))
        self.assertEqual(len(records),8)
        for path in records:
            old=json.loads(path.read_bytes());before=digest(path.read_bytes())
            summary=old['findings_summary']
            # Retained safe messages are replay inputs, not original raw streams.
            lines=[f"{r['target']}: {r['level']}: {r['check']} {r.get('message','')}" for r in old['findings']]
            lines.append(f"1 packages and 1 specfiles checked; {summary['errors']} errors, {summary['warnings']} warnings, {summary['filtered']} filtered.")
            parsed=parse_rpmlint_output('\n'.join(lines),exit_code=64,strict=False)
            raw=raw_from_records(parsed['error_records'],summary['warnings'])
            raw['findings_summary']=summary
            raw['parse_complete']=parsed['parse_complete']
            raw['error_overflow']=parsed['error_overflow']
            result=evaluate_policy(raw,None,{'project_id':old['product'],'version':old['rpm_identity']['version'],'arch':old['architecture'],'system':path.parent.name})
            self.assertFalse(result['accepted'])
            if 'nebular' in path.name:
                self.assertEqual(len(old['findings']),100);self.assertEqual(summary['errors'],15)
                self.assertEqual(len(parsed['error_records']),8);self.assertFalse(parsed['parse_complete'])
            else:
                self.assertTrue(parsed['parse_complete']);self.assertEqual(len(parsed['error_records']),summary['errors'])
                self.assertTrue(all(len(r['message'])<128 for r in old['findings'] if r['level']=='E'))
                self.assertIn('no-changelogname-tag',[r['code'] for r in parsed['error_records']])
            self.assertEqual(result['raw_exit_code'],64);self.assertEqual(result['raw_lint_status'],'fail')
            self.assertEqual(digest(path.read_bytes()),before)

    def test_errors_after_first_hundred_rows_remain_complete(self):
        rows=[f'pkg.x86_64: W: warning-code detail-{i}' for i in range(139)]
        rows += [f'pkg.x86_64: E: unknown-{i} detail' for i in range(15)]
        rows += ['1 packages and 1 specfiles checked; 15 errors, 139 warnings, 8 filtered.']
        parsed=parse_rpmlint_output('\n'.join(rows),exit_code=64)
        self.assertEqual(len(parsed['findings']),100);self.assertEqual(len(parsed['error_records']),15)
        self.assertEqual(sum(g['count'] for g in parsed['groups'] if g['severity']=='E'),15)


class InventoryTests(unittest.TestCase):
    def test_dump_requires_complete_exact_sha256_modes_and_metadata(self):
        path='/usr/lib/pkg/a.js'
        line=f'{path} 3 1 '+digest(b'abc')+' 0100644 root root 0 0 0 X\n'
        attributes={path:dict(inode=1,device=1,flags=0)}
        self.assertEqual(parse_dump(line,attributes)[path]['mode'],0o644)
        for text,attrs in ((line+"\n"+line,attributes),(line,{}),(line.replace('0100644','0020644'),attributes),
                           (line.replace(digest(b'abc'),'abc'),attributes),(line.replace('/usr/lib/pkg','/private/pkg'),attributes)):
            with self.assertRaises(ContractError):parse_dump(text,attrs)

    def test_complete_real_backend_inventory_from_authenticated_controlled_archives(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp).resolve();capture,intent,npm=create_cli_fixture(root/'input')
            ctx=validate_build_inputs(capture,intent,'noarch',adapter='rpm',distro='fedora-43')
            scratch=root/'scratch';sources=scratch/'rpmbuild/SOURCES';specs=scratch/'rpmbuild/SPECS';sources.mkdir(parents=True);specs.mkdir()
            name=ctx['project_id'];(sources/ctx['asset_name']).write_bytes(ctx['asset_bytes'])
            staged=scratch/'rpmbuild/staged_node_modules';stage_offline_npm_closure(capture,name,npm,staged);npm_bundle(staged,sources/'npm-closure.tar.gz')
            from rs9.build_rpm import _render_rpm_spec
            cmds=[{'name':'tfsl','path':'bin/run.js'},{'name':'tfsl-batch','path':'bin/batch.js'}]
            (specs/(name+'.spec')).write_bytes(_render_rpm_spec(name,ctx['version'],1,'Fixture','MIT',ctx['asset_name'],ctx['asset_sha'],'noarch',['nodejs >= 22'],cmds,False,'package',published_at='2026-09-30T12:00:00Z'))
            rpm=scratch/'fixture.rpm';rpm.write_bytes(b'controlled-rpm')
            runner=MockCommandRunner(available_tools={'rpm':'/usr/bin/rpm'},handlers={'rpm':lambda argv,cwd=None,env=None:inventory_response(argv,cwd)})
            inventory,receipts=collect_preservation_inventory(runner,rpm,capture,ctx,staged,cmds,['nodejs >= 22'],scratch,scratch/'db',scratch/'keys')
            self.assertTrue(inventory['complete']);self.assertEqual(len(receipts),3)
            self.assertEqual(inventory['payload_manifest_sha256'],ctx['payload']['payload_manifest_sha256'])
            self.assertEqual(inventory['engine_node'],'>=22')
            self.assertIn('/usr/share/licenses/'+name+'/LICENSE',inventory['license_projections'])
            self.assertTrue(all('--dbpath' in call['argv'] and '--define' in call['argv'] for call in runner.calls))
            # rpmlint 2.8 PkgFiles uses FILERDEVS, not source-filesystem FILEDEVICES.
            attributes = runner.calls[-1]['argv']
            query = attributes[attributes.index('--queryformat')+1]
            self.assertIn('%{FILERDEVS}',query)
            self.assertNotIn('%{FILEDEVICES}',query)

    def test_duplicate_algorithm_prefix_ghost_and_hardlink_accounting(self):
        def row(path,inode,flags=0):return dict(path=path,type='file',size=100,sha256='a'*64,device=1,inode=inode,flags=flags)
        files={p:row(p,n) for n,p in enumerate(['/usr/lib/pkg/a','/usr/lib/pkg/b','/usr/share/licenses/pkg/a'],1)}
        groups,waste=duplicate_groups(files);self.assertIsNone(waste);self.assertEqual(len(groups[0]['members']),3)
        self.assertEqual(duplicate_waste_totals(groups),[0,100])
        self.assertEqual(duplicate_groups(dict(reversed(list(files.items())))),(groups,waste))
        files['/usr/lib/pkg/b']['inode']=1
        self.assertEqual(duplicate_groups(files)[1],0)
        files['/usr/lib/pkg/a']['flags']=64
        self.assertEqual(len(duplicate_groups(files)[0][0]['members']),2)
