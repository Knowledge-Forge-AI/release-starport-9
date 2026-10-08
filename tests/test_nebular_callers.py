"""Real tagged sources; controlled release/tool fixtures do not claim native results."""
import copy
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from rs9 import nebular_callers as callers
from rs9.rpm_lint_policy import load_policy, evaluate_policy
from rs9.release_core import digest
from rs9.scratch import canonical

SOURCES = Path(__file__).parent / 'fixtures/nebular-0.6.1/caller-sources.json'


def attach_caller_fixture(inventory, inputs):
    """Actual source bytes plus explicit external package/manifest test doubles."""
    inventory['caller_evidence'] = dict(schema='rs9.nebular-caller-sources.v1', status='available',
        tag_commit=callers.TAG_COMMIT, tag_tree=callers.TAG_TREE, files=json.loads(SOURCES.read_bytes()))
    def add(path, sha, size, mode):
        row=dict(path=path,type='file',sha256=sha,size=size,mode=mode,device=1,inode=90000+len(inventory['files']),owner='root',group='root',flags=0)
        inventory['files'][path]=row
        inventory['expected'][path]=dict(row,origin='release',input_archive_sha256=inputs['asset_sha256'],
            input_member=path.removeprefix('/usr/lib/'))
    binding=json.loads(inventory['caller_evidence']['files']['protocol/theme-lab-v2/payload-binding.json']['content'])
    for row in binding['files']:
        path=callers.PAYLOAD+'/loom-payload/'+row['path']
        if path in inventory['files']:
            inventory['files'][path]['size']=row['bytes']
            inventory['expected'][path]['size']=row['bytes']
    rt=callers.RUNTIME_PINS[inputs['system']]
    add(callers.RUNTIME,rt['sha256'],rt['size'],0o755)
    add(callers.ROOT+'/bin/'+callers.NEBULAR_PROJECT_ID,digest(b'external-main-binary-double'),37,0o755)
    members=[dict(path=p.removeprefix(callers.PAYLOAD+'/sidecar-payload/'), **{k:r[k] for k in ('sha256','size','mode')})
        for p,r in inventory['files'].items() if '/sidecar-payload/' in p and p!=callers.MANIFEST]
    manifest=dict(schema='tfsb.studio-sidecar-distribution',runtimeKind='node-runtime-payload-v1',target=rt['target'],
        entrypoint='dist/service-protocol/server-cli.js',runtime=dict(rt,mode=0o755,version='22.23.3'),files=members)
    data=canonical(manifest)
    add(callers.MANIFEST,digest(data),len(data),0o644)
    inventory.setdefault('contract_members',{})[callers.MANIFEST]=data.decode()
    metadata=json.loads(SOURCES.with_name('caller-payload-members.json').read_bytes())['loom:package/package.json']
    add(callers.FLOOR_MEMBER,metadata['sha256'],metadata['size'],metadata['mode'])
    inventory['contract_members'][callers.FLOOR_MEMBER]=metadata['content']


class NebularCallerTests(unittest.TestCase):
    def test_policy_intent_matches_authenticated_role(self):
        from rs9.errors import ContractError
        policy = load_policy()
        for rules in policy['projects'][callers.NEBULAR_PROJECT_ID]['exceptions'].values():
            for path, rule in rules.items():
                if not isinstance(rule, dict) or 'role' not in rule:
                    continue
                expected = ('internal-interpreter-mediated' if rule['role'] == 'embedded-runtime-invocation'
                            else 'typescript-declaration-data' if rule['role'] == 'typescript-declaration-data'
                            else 'internal-retained-source')
                self.assertEqual(rule['intent'], expected, path)
                changed = copy.deepcopy(rule)
                changed['intent'] = 'internal-module-data'
                with self.assertRaises(ContractError):
                    callers.validate_rule(path, changed)

    def test_hypothetical_json_caller_contract_is_rejected_for_other_products(self):
        from rs9.errors import ContractError
        from rs9.rpm_lint_policy import _validate_policy
        policy = load_policy()
        rule = copy.deepcopy(policy['projects'][callers.NEBULAR_PROJECT_ID]['exceptions']['env-script-interpreter'][
            callers.PAYLOAD + '/loom-payload/bin/tfsl.js'])
        for key in ('role', 'caller_structure'):
            rule.pop(key)
        rule.update(intent='internal-interpreter-mediated', reference_contract={
            'kind': 'json-pointer', 'pointer': '/script', 'value': {'interpreter': 'node', 'script': 'private.js'},
            'role': 'invocation'})
        entry = policy['projects']['theme-forge-stellar-burst']
        entry['exceptions']['env-script-interpreter'] = {'/usr/lib/theme-forge-stellar-burst/private.js': rule}
        with self.assertRaises(ContractError):
            _validate_policy(policy)

    def test_actual_engine_bytes_drive_versioned_requires(self):
        import io, tarfile
        payload=json.loads(SOURCES.with_name('caller-payload-members.json').read_bytes())
        metadata=payload['loom:package/package.json']
        self.assertEqual(digest(metadata['content'].encode()),callers.FLOOR_SHA256)
        with tempfile.TemporaryDirectory() as tmp:
            archive=Path(tmp)/'candidate.tar.gz'
            with tarfile.open(archive,'w:gz') as output:
                data=metadata['content'].encode()
                row=tarfile.TarInfo(callers.FLOOR_MEMBER.removeprefix('/usr/lib/'));row.size=len(data)
                output.addfile(row,io.BytesIO(data))
            entry=load_policy()['projects'][callers.NEBULAR_PROJECT_ID]
            self.assertEqual(callers.release_runtime_floor(archive,entry),'>= 22')
            changed=copy.deepcopy(entry);changed['runtime_requires_contract']['sha256']='0'*64
            from rs9.errors import ContractError
            with self.assertRaises(ContractError):callers.release_runtime_floor(archive,changed)

    def test_tagged_blob_bytes_and_all_roles_are_authenticated(self):
        sources=json.loads(SOURCES.read_bytes())
        self.assertEqual(set(sources),set(callers.REVIEWED_CALLER_FILES))
        for path,row in sources.items():
            self.assertTrue(callers._source_valid(path,row),path)
        self.assertEqual(len(callers.NEBULAR_MEMBER_DEFINITIONS),8)
        self.assertEqual(sum(d['role']=='embedded-runtime-invocation' for d in callers.NEBULAR_MEMBER_DEFINITIONS.values()),4)

    def test_two_architectures_real_source_relations_need_no_system_node(self):
        from tests.test_rpm_lint_policy import run10_fixture_case
        for system in callers.RUNTIME_PINS:
            raw,inventory,inputs,_,_=run10_fixture_case(system)
            attach_caller_fixture(inventory,inputs)
            value=evaluate_policy(raw,inventory,inputs,load_policy())
            self.assertTrue(value['accepted'],value['blockers'])
            self.assertFalse(raw['clean'])
            self.assertEqual(len(value['duplicate_groups']),128)
            for proof in value['member_proofs']:
                if proof.get('role')!='typescript-declaration-data':
                    self.assertFalse(proof['system_node_required'])
                    self.assertFalse(proof['native_execution_claimed'])

    def test_forged_source_tag_runtime_manifest_and_mixed_rules_fail(self):
        from tests.test_rpm_lint_policy import run10_fixture_case
        raw,inventory,inputs,_,_=run10_fixture_case('x86_64-linux')
        attach_caller_fixture(inventory,inputs)
        variants=[]
        v=copy.deepcopy(inventory);v['caller_evidence']['tag_tree']='0'*40;variants.append(v)
        v=copy.deepcopy(inventory);v['caller_evidence']['files']['src-tauri/src/platform.rs']['content']+='\n';variants.append(v)
        v=copy.deepcopy(inventory);v['files'][callers.RUNTIME]['sha256']='0'*64;variants.append(v)
        v=copy.deepcopy(inventory);v['contract_members'][callers.MANIFEST]='{}';variants.append(v)
        v=copy.deepcopy(inventory);v['files'].pop(callers.RUNTIME);variants.append(v)
        v=copy.deepcopy(inventory);v['requires']=['nodejs'];variants.append(v)
        for v in variants:
            result=evaluate_policy(raw,v,inputs,load_policy())
            self.assertFalse(result['accepted'])
            if result['rule_blocker_causes']:
                self.assertEqual(result['rule_blocker_causes'][0]['cause'],'identity-mismatch')
        absent=copy.deepcopy(inventory);absent['caller_evidence']=None
        result=evaluate_policy(raw,absent,inputs,load_policy())
        self.assertEqual(result['rule_blocker_causes'][0]['cause'],'content-absent')
        policy=load_policy();rule=next(iter(policy['projects'][callers.NEBULAR_PROJECT_ID]['exceptions']['env-script-interpreter'].values()))
        rule['status']='blocked';rule['missing_predicate']='caller-content-or-identity-unproven'
        self.assertFalse(evaluate_policy(raw,inventory,inputs,policy)['accepted'])
        rule.pop('status');rule.pop('missing_predicate')
        rule['caller_structure']['floor']='>=22'
        self.assertFalse(evaluate_policy(raw,inventory,inputs,policy)['accepted'])

    def test_collector_authenticates_bytes_not_claimed_hashes_and_names_missing_items(self):
        sources=json.loads(SOURCES.read_bytes())
        class Capture:
            record={'tag':{'commit':callers.TAG_COMMIT,'tree':callers.TAG_TREE}}
        with tempfile.TemporaryDirectory() as tmp:
            output=Path(tmp)
            records=[]
            for path,row in sources.items():
                target=output/path;target.parent.mkdir(parents=True,exist_ok=True);target.write_text(row['content'])
                records.append({k:v for k,v in row.items() if k!='content'})
            with patch('rs9.hosted_smoke.tagged_files',return_value=records):
                self.assertEqual(callers.collect_caller_sources(Capture(),object(),output)['status'],'available')
                (output/'src-tauri/src/platform.rs').write_text('forged')
                result=callers.collect_caller_sources(Capture(),object(),output)
                self.assertEqual(result['reason'],'CALLER_SOURCE_IDENTITY')
                self.assertIn('src-tauri/src/platform.rs',result['missing_items'])
            absent=callers.collect_caller_sources(Capture(),None,output)
            self.assertEqual(absent['status'],'unavailable')
            self.assertEqual(set(absent['missing_items']),set(callers.REVIEWED_CALLER_FILES))
