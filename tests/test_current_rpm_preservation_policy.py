"""Actual retained raw findings and reconstructed source/header observations; no native tools."""
import base64
import copy
import gzip
import hashlib
import io
import json
from pathlib import Path
import unittest
from unittest.mock import patch

from rs9.current_generation import CURRENT_GENERATION
from rs9.errors import ContractError
from rs9.rpm_lint_policy import load_policy, _validate_policy, evaluate_policy
from rs9.hosted_summary import validate_rpm_policy_source, promotion_restrictions, RPM_POLICY_PROMOTION_BLOCKER
from rs9.scratch import canonical

ROOT = Path(__file__).resolve().parents[1]
PRODUCTS = ('theme-forge-stellar-burst','theme-forge-stellar-loom','theme-forge-solar-sail','theme-forge-nebular-fusion')
SYSTEMS = ('x86_64-linux','aarch64-linux')


def blocked_policy():
    return json.loads((ROOT/'tests/fixtures/current-rpm-diagnostic-policy.json').read_bytes())


def actual_case(product='theme-forge-stellar-burst',system='x86_64-linux'):
    path=ROOT/'tests/fixtures/current-rpm-preservation'/(product+'-'+system+'.json')
    envelope=json.loads(path.read_bytes())
    compressed=base64.b64decode(envelope['data'],validate=True)
    with gzip.GzipFile(fileobj=io.BytesIO(compressed)) as stream: raw=stream.read(4*1024**2+1)
    if len(raw)>4*1024**2 or len(raw)!=envelope['decoded_bytes'] or hashlib.sha256(raw).hexdigest()!=envelope['data_sha256']:
        raise AssertionError('Actual fixture identity differs')
    return json.loads(raw)


class CurrentRpmPreservationPolicyTests(unittest.TestCase):
    def evaluate(self,case,policy=None):
        return evaluate_policy(case['raw'],case['inventory'],case['inputs'],
            load_policy(generation=CURRENT_GENERATION) if policy is None else policy,generation=CURRENT_GENERATION)

    def test_actual_non_gui_findings_remain_raw_fail_and_all_six_cases_are_exactly_preserved(self):
        for product in PRODUCTS[:-1]:
            for system in SYSTEMS:
                with self.subTest(product=product,system=system):
                    case=actual_case(product,system);result=self.evaluate(case)
                    self.assertTrue(result['accepted'],result['blockers'])
                    self.assertEqual(result['accepted_findings'],case['raw']['error_records'])
                    self.assertEqual(result['raw_lint_status'],'fail')
                    self.assertEqual(case['raw']['findings_summary']['errors'],len(result['accepted_findings']))

    def test_serialized_nebular_observations_never_mint_live_caller_capability(self):
        for system in SYSTEMS:
            case=actual_case(PRODUCTS[-1],system)
            for counterfeit in (None,{'schema':'rs9.nebular-caller-sources.v1','status':'available','files':{},'tag_name':'v0.7.0'}):
                with self.subTest(system=system,counterfeit=bool(counterfeit)):
                    case['inventory']['caller_evidence']=counterfeit
                    result=self.evaluate(case)
                    self.assertFalse(result['accepted'])
                    self.assertTrue(any('caller-content-or-identity-unproven' in reason for reason in result['blockers']))

    def test_blocked_empty_current_fixture_remains_held_and_cannot_be_flag_promoted(self):
        policy=blocked_policy();self.assertEqual(_validate_policy(policy,generation=CURRENT_GENERATION)['status'],'blocked')
        result=self.evaluate(actual_case(),policy)
        self.assertFalse(result['accepted']);self.assertIn('current-generation-diagnostic-only',result['blockers'])
        policy.update(status='authorized',blocking=False)
        with self.assertRaises(ContractError):_validate_policy(policy,generation=CURRENT_GENERATION)

    def test_authorized_policy_is_complete_source_owned_and_rejects_flags_partial_unknown_or_forged_data(self):
        original=load_policy(generation=CURRENT_GENERATION)
        mutations=[lambda p:p.update(status='unknown'),lambda p:p.update(status=None),lambda p:p.update(blocking=True),
            lambda p:p.update(production_enabled=True),lambda p:p.update(publication_authority=True),
            lambda p:p['projects'].pop(PRODUCTS[-1]),
            lambda p:p['projects'][PRODUCTS[0]].update(version='0.6.1'),
            lambda p:p['projects'][PRODUCTS[0]].update(allowed_architectures=['noarch']),
            lambda p:p['projects'][PRODUCTS[0]]['inventory_bindings'].pop('aarch64-linux'),
            lambda p:p['projects'][PRODUCTS[0]]['exceptions'].update({'explicit-lib-dependency':{}}),
            lambda p:p['projects'][PRODUCTS[0]]['exceptions']['files-duplicated-waste']['systems']['x86_64-linux'].update(group_count=1),
            lambda p:p['projects'][PRODUCTS[0]]['inventory_bindings']['x86_64-linux'].update(source_inventory_sha256='0'*64)]
        for index,mutate in enumerate(mutations):
            with self.subTest(mutation=index):
                policy=copy.deepcopy(original);mutate(policy)
                self.assertFalse(self.evaluate(actual_case(),policy)['accepted'])

    def test_version_asset_payload_inventory_path_class_and_architecture_mismatches_refuse(self):
        changes=[('version',lambda c:c['inputs'].update(version='0.6.1')),
            ('asset',lambda c:(c['inputs'].update(asset_sha256='0'*64),c['inventory'].update(asset_sha256='0'*64))),
            ('manifest',lambda c:(c['inputs'].update(payload_manifest_sha256='0'*64),c['inventory'].update(payload_manifest_sha256='0'*64))),
            ('closure',lambda c:(c['inputs'].update(closure_sha256='0'*64),c['inventory'].update(closure_sha256='0'*64))),
            ('inventory',lambda c:c['inventory']['expected'].pop(next(iter(c['inventory']['expected'])))),
            ('path',lambda c:c['raw']['error_records'][0].update(path='/usr/lib/'+PRODUCTS[0]+'/unknown.js')),
            ('class',lambda c:c['raw']['error_records'][0].update(code='no-changelogname-tag')),
            ('arch',lambda c:c['inputs'].update(arch='noarch')),
            ('system',lambda c:c['inputs'].update(system='aarch64-linux'))]
        for name,mutate in changes:
            with self.subTest(change=name):
                case=actual_case();mutate(case);self.assertFalse(self.evaluate(case)['accepted'])
        nebular=actual_case(PRODUCTS[-1]);nebular['inputs'].update(system='aarch64-linux',arch='aarch64')
        result=self.evaluate(nebular)
        self.assertFalse(result['accepted']);self.assertIn('asset-identity-mismatch',result['blockers'])

    def test_source_inventory_cannot_be_rewritten_even_if_observed_file_is_changed_to_match(self):
        case=actual_case();path=case['raw']['error_records'][0]['path']
        case['inventory']['expected'][path]['sha256']='0'*64;case['inventory']['files'][path]['sha256']='0'*64
        self.assertIn('current-source-inventory-mismatch',self.evaluate(case)['blockers'])

    def test_duplicate_inode_preservation_stays_runtime_strict_while_device_identity_is_not_frozen(self):
        case=actual_case();files=[row for row in case['inventory']['files'].values() if row['type']=='file']
        for row in files:row['device']=987654321
        self.assertTrue(self.evaluate(case)['accepted'])
        files[1]['inode']=files[0]['inode']
        result=self.evaluate(case)
        self.assertFalse(result['accepted']);self.assertIn('current-runtime-inode-alias',result['blockers'])

    def test_noarch_runtime_inode_alias_is_not_hidden_by_nonblocking_duplicate_waste(self):
        case=actual_case('theme-forge-stellar-loom')
        rows=[row for row in case['inventory']['files'].values() if row['type']=='file']
        rows[1]['device']=rows[0]['device'];rows[1]['inode']=rows[0]['inode']
        self.assertIn('current-runtime-inode-alias',self.evaluate(case)['blockers'])

    def test_duplicate_group_and_observed_waste_mismatches_refuse(self):
        case=actual_case();case['inventory']['duplicate_groups'].pop()
        self.assertIn('current-duplicate-inventory-mismatch',self.evaluate(case)['blockers'])
        case=actual_case()
        finding=next(row for row in case['raw']['error_records'] if row['code']=='files-duplicated-waste')
        finding['waste_bytes']+=1
        self.assertIn('duplicate-preservation-unproven',self.evaluate(case)['blockers'])

    def test_raw_count_and_path_sets_cannot_be_collapsed_or_duplicated(self):
        for operation in ('zero','remove','duplicate'):
            with self.subTest(operation=operation):
                case=actual_case();raw=case['raw']
                if operation=='zero':
                    raw.update(error_records=[],status='pass',clean=True);raw['findings_summary']['errors']=0;raw['tool_receipt']['exit_code']=0
                elif operation=='remove':raw['error_records'].pop();raw['findings_summary']['errors']-=1
                else:raw['error_records'].append(copy.deepcopy(raw['error_records'][0]));raw['findings_summary']['errors']+=1
                self.assertFalse(self.evaluate(case)['accepted'])

    def test_valid_selected_policy_reaches_summary_source_binding_but_preserves_production_blocker(self):
        policy=load_policy(generation=CURRENT_GENERATION)
        evaluation=self.evaluate(actual_case())
        receipt={'lane':'rpm','system':'x86_64-linux','details':{'rpm_lint_policy':{PRODUCTS[0]:evaluation}},
                 'production_promotion_blockers':[RPM_POLICY_PROMOTION_BLOCKER]}
        validate_rpm_policy_source(ROOT,receipt,generation=CURRENT_GENERATION)
        tokens,errors=promotion_restrictions({'lane':'rpm'},receipt)
        self.assertEqual(tokens,[RPM_POLICY_PROMOTION_BLOCKER]);self.assertEqual(errors,[])
        with patch('rs9.rpm_lint_policy.load_policy',return_value=blocked_policy()),self.assertRaises(ContractError) as error:
            validate_rpm_policy_source(ROOT,receipt,generation=CURRENT_GENERATION)
        self.assertEqual(error.exception.code,'CURRENT_RPM_POLICY_HELD')
