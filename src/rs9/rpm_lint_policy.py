"""Fail-closed current-generation candidate lint policy, distinct from raw lint."""
from collections import Counter
import json
from pathlib import Path
import re

from rs9.errors import ContractError
from rs9.release_core import digest
from rs9.scratch import canonical
from rs9.rpm_preservation import duplicate_groups, duplicate_waste_totals, INVENTORY_SCHEMA

DEFAULT_POLICY_PATH = Path(__file__).resolve().parents[2]/'operators/live1/rpm-lint-policy.json'
RPM_LINT_POLICY_SCHEMA = 'rs9.rpm-lint-policy.v1'
RPM_POLICY_EVALUATION_SCHEMA = 'rs9.rpm-lint-policy-evaluation.v1'
PERMITTED_EXCEPTION_CLASSES = frozenset({'env-script-interpreter','non-executable-script','files-duplicated-waste'})
CURRENT_VERSIONS = {'theme-forge-stellar-burst':'0.6.1','theme-forge-stellar-loom':'0.4.0','theme-forge-solar-sail':'0.2.1','theme-forge-nebular-fusion':'0.6.1'}
UNWAIVABLE_ERROR_CLASSES = frozenset({'no-changelogname-tag','explicit-lib-dependency'})


def _validate_policy(policy):
    json.dumps(policy,allow_nan=False)
    if not isinstance(policy,dict) or policy.get('schema')!=RPM_LINT_POLICY_SCHEMA:
        raise ContractError('INVALID_POLICY','Invalid candidate lint policy schema')
    if policy.get('production_enabled') is not False or policy.get('publication_authority') is not False:
        raise ContractError('INVALID_POLICY','Nonproduction lint policy required')
    codes = policy.get('permitted_preservation_exception_classes')
    projects = policy.get('projects')
    constraints = policy.get('tool_constraints')
    if not isinstance(constraints,dict) or type(constraints.get('filtered_count')) is not int or constraints['filtered_count']<0:
        raise ContractError('INVALID_POLICY','Explicit existing tool filter count required')
    if not isinstance(codes,list) or set(codes)!=PERMITTED_EXCEPTION_CLASSES or not isinstance(projects,dict) or not projects:
        raise ContractError('INVALID_POLICY','Malformed candidate lint policy')
    for name, entry in projects.items():
        if not isinstance(entry,dict) or entry.get('package_name')!=name or entry.get('version') != CURRENT_VERSIONS.get(name):
            raise ContractError('INVALID_POLICY','Malformed exact project identity')
        architectures = entry.get('allowed_architectures')
        systems = entry.get('allowed_systems')
        if (not isinstance(architectures,list) or not architectures or set(architectures)-{'noarch','x86_64','aarch64'}
                or not isinstance(systems,list) or not systems or set(systems)-{'x86_64-linux','aarch64-linux'}):
            raise ContractError('INVALID_POLICY','Malformed exact platform scope')
        exceptions = entry.get('exceptions')
        if not isinstance(exceptions,dict) or set(exceptions)-PERMITTED_EXCEPTION_CLASSES:
            raise ContractError('INVALID_POLICY','Unauthorized exception class')
        for code, rules in exceptions.items():
            if not isinstance(rules,dict): raise ContractError('INVALID_POLICY','Malformed exception rules')
            if code == 'files-duplicated-waste':
                if type(rules.get('expected_waste_bytes')) is not int or rules['expected_waste_bytes'] < 0:
                    raise ContractError('INVALID_POLICY','Exact duplicate waste required')
            elif not rules or any(not isinstance(path,str) or not path.startswith('/usr/lib/'+name+'/')
                                  or any(c in path for c in '*?[') or not isinstance(rule,dict)
                                  for path,rule in rules.items()):
                raise ContractError('INVALID_POLICY','Exact private script paths required')
    return policy


def load_policy(path=None):
    try:
        return _validate_policy(json.loads((Path(path) if path is not None else DEFAULT_POLICY_PATH).read_bytes()))
    except (OSError,ValueError,TypeError) as exc:
        raise ContractError('INVALID_POLICY','Candidate lint policy unavailable or malformed') from exc


def _raw_blockers(raw, policy):
    summary, tool = raw.get('findings_summary'), raw.get('tool_receipt',{})
    if not isinstance(summary,dict): return ['missing-findings-summary']
    fields = ('errors','warnings','filtered','packages','specfiles')
    if any(type(summary.get(k)) is not int or summary[k]<0 for k in fields): return ['malformed-counts']
    if summary['filtered'] != policy['tool_constraints']['filtered_count']: return ['configuration-filtered-count-mismatch']
    errors = raw.get('error_records')
    if not isinstance(errors,list) or len(errors)!=summary['errors']: return ['incomplete-error-records']
    if any(not isinstance(r,dict) or r.get('arguments_complete') is not True or r.get('level')!='E'
           or not isinstance(r.get('code'),str) or not isinstance(r.get('target'),str) for r in errors):
        return ['malformed-error-records']
    if raw.get('parse_complete') is not True or raw.get('unparsed_count')!=0 or raw.get('error_overflow'):
        return ['incomplete-raw-result']
    if (summary['packages'],summary['specfiles'])!=(1,1): return ['input-count-mismatch']
    expected_exit = 64 if summary['errors'] else 0
    if tool.get('executed') is not True or tool.get('exit_code')!=expected_exit or tool.get('stderr_bytes')!=0: return ['tool-execution-failure']
    if raw.get('clean') is not (summary['errors']==0) or raw.get('status')!=('fail' if summary['errors'] else 'pass'):
        return ['contradictory-raw-result']
    version = raw.get('tool_version',{})
    package = version.get('package_query',{})
    if (version.get('exit_code')!=0 or version.get('version') not in ('2.8.0','rpmlint 2.8.0')
            or package.get('exit_code')!=0 or package.get('version')!='rpmlint|2.8.0|2.fc43|noarch'):
        return ['tool-identity-mismatch']
    return []


def _input_blockers(entry, inputs, inventory, raw):
    if not isinstance(inventory,dict) or inventory.get('schema')!=INVENTORY_SCHEMA or inventory.get('complete') is not True:
        return ['incomplete-preservation-inventory']
    for key in ('asset_sha256','payload_manifest_sha256','closure_sha256'):
        if inputs.get(key)!=inventory.get(key): return ['input-inventory-mismatch:'+key]
    if inventory.get('package_sha256')!=raw.get('package_sha256') or not re.fullmatch('[0-9a-f]{64}',raw.get('package_sha256','')):
        return ['package-identity-mismatch']
    auth = entry.get('authenticated_inputs',{})
    asset = auth.get('asset_sha256')
    if asset is None:
        platform = {'x86_64':'x86_64-unknown-linux-gnu','aarch64':'aarch64-unknown-linux-gnu'}.get(inputs.get('arch'))
        asset = next((r['sha256'] for r in auth.get('assets',[]) if platform and platform in r['name']),None)
    if inputs.get('asset_sha256')!=asset: return ['asset-identity-mismatch']
    if inputs.get('closure_sha256')!=auth.get('closure_sha256'): return ['closure-identity-mismatch']
    if not re.fullmatch('[0-9a-f]{64}',inputs.get('payload_manifest_sha256','')): return ['payload-manifest-unbound']
    return []


def _preserved(path, inventory):
    actual = inventory['files'].get(path)
    expected = inventory['expected'].get(path)
    if not actual or not expected: return False
    if actual.get('owner')!='root' or actual.get('group')!='root' or actual.get('flags',0)&64: return False
    keys = ('type','mode','size','sha256') if expected['type']=='file' else ('type','mode','target') if expected['type']=='symlink' else ('type','mode')
    return all(actual.get(k)==expected.get(k) for k in keys)


def _node_available(inventory):
    engine = inventory.get('engine_node')
    if not isinstance(engine,str) or not re.fullmatch(r'>=\s*22(?:\.0(?:\.0)?)?',engine): return False
    return 'nodejs >= 22' in inventory.get('requires',[])


def _script_proof(record, rule, inventory):
    path = record.get('path')
    if not _preserved(path,inventory): return None
    expected, actual = inventory['expected'][path], inventory['files'][path]
    shebang = expected.get('shebang')
    if shebang!='#!/usr/bin/env node' or record.get('interpreter')!='/usr/bin/env node': return None
    if rule.get('shebang', '/usr/bin/env node') != shebang.removeprefix('#!'): return None
    if rule.get('interpreter', 'node') != 'node': return None
    if not expected.get('input_member') or not re.fullmatch('[0-9a-f]{64}', expected.get('input_archive_sha256','')): return None
    if 'mode' in rule and actual['mode']!=int(rule['mode'],8): return None
    if record['code']=='non-executable-script' and int(record.get('mode','0'),8)!=actual['mode']: return None
    intent = rule.get('intent')
    if intent=='typescript-declaration-data':
        if not path.endswith('.d.ts') or record['code']!='non-executable-script': return None
    else:
        launcher = rule.get('launcher')
        wrapper = inventory['wrappers'].get(launcher)
        installed = inventory['files'].get(launcher)
        if not wrapper or not installed or wrapper['target']!=path or any(installed.get(k)!=wrapper[k] for k in ('sha256','mode','type')):
            return None
        if not _node_available(inventory): return None
    return {'path':path,'input_member':expected['input_member'],'input_archive_sha256':expected['input_archive_sha256'],
            'sha256':actual['sha256'],'mode':actual['mode'],'shebang':shebang,'intent':intent or 'maintained-node-wrapper',
            'launcher':rule.get('launcher')}


def _duplicate_proof(record, rule, inventory):
    groups, waste = duplicate_groups(inventory['files'])
    observed_waste = record.get('waste_bytes')
    if (type(observed_waste) is not int or observed_waste not in duplicate_waste_totals(groups)
            or observed_waste != rule.get('expected_waste_bytes')):
        return None
    if any(not _preserved(path,inventory) or inventory['expected'][path].get('origin') not in {'release','offline-npm','license-projection'}
           for g in groups for path in g['members']): return None
    # Authenticated archives forbid hardlinks; reject any changed inode grouping.
    keys = [(r['device'],r['inode']) for r in inventory['files'].values() if r['type']=='file']
    if len(set(keys))!=len(keys): return None
    expected_files = {p:dict(r,device=0,inode=i,flags=0) for i,(p,r) in enumerate(sorted(inventory['expected'].items()))}
    expected_groups, expected_waste = duplicate_groups(expected_files)
    if groups!=expected_groups or waste!=expected_waste: return None
    return groups


def _launcher_blockers(entry, inventory):
    declared = entry.get('launchers', {})
    wrappers = inventory['wrappers']
    if not isinstance(declared, dict) or set(wrappers) != {r['path'] for r in declared.values()}:
        return ['policy-launcher-set-mismatch']
    for rule in declared.values():
        path, target = rule['path'], rule['target']
        body = ('#!/bin/sh\nexec node "'+target+'" "$@"\n').encode()
        expected = dict(target=target,sha256=digest(body),mode=int(rule['mode'],8),type='file')
        if (rule['type']!='node_wrapper' or expected['mode']!=0o755 or wrappers[path]!=expected
                or not _preserved(path,inventory)):
            return ['policy-launcher-mismatch']
    return []


def _evaluate_errors(raw, entry, inventory, inputs):
    blockers, accepted, proofs, duplicates = [], [], [], []
    exceptions = entry['exceptions']
    counts = Counter(r.get('code') for r in raw['error_records'])
    expected_counts = {code:len(rules) if code!='files-duplicated-waste' else 1 for code,rules in exceptions.items()}
    if dict(counts)!=expected_counts: blockers.append('exception-count-mismatch')
    for code, rules in exceptions.items():
        if code != 'files-duplicated-waste' and Counter(r.get('path') for r in raw['error_records'] if r.get('code') == code) != Counter(rules.keys()):
            blockers.append('exception-path-set-mismatch')
    for record in raw['error_records']:
        code = record.get('code')
        if record.get('target')!=inputs['project_id']+'.'+inputs['arch']:
            blockers.append('wrong-finding-target'); continue
        if code not in exceptions or code not in PERMITTED_EXCEPTION_CLASSES:
            blockers.append('unapproved-error-code:'+str(code)); continue
        if code=='files-duplicated-waste':
            groups = _duplicate_proof(record,exceptions[code],inventory)
            if groups is None: blockers.append('duplicate-preservation-unproven')
            else: duplicates=groups; accepted.append(record)
        else:
            rule = exceptions[code].get(record.get('path'))
            proof = _script_proof(record,rule,inventory) if rule else None
            if proof is None: blockers.append('script-preservation-unproven')
            else: proofs.append(proof); accepted.append(record)
    return blockers,accepted,proofs,duplicates


def _evaluate_policy(raw_evidence, inventory, inputs, policy=None):
    """Only complete raw results and exact member proofs can accept exceptions."""
    if not isinstance(raw_evidence,dict):
        return {'schema':RPM_POLICY_EVALUATION_SCHEMA,'accepted':False,'status':'blocked',
                'blockers':['malformed-raw-evidence'],'accepted_findings':[]}
    if not isinstance(inputs,dict): inputs = {}
    accepted, proofs, duplicates = [], [], []
    try:
        policy = _validate_policy(policy) if policy is not None else load_policy()
        entry = policy['projects'].get(inputs.get('project_id'))
        blockers = _raw_blockers(raw_evidence,policy)
        if not isinstance(entry,dict): blockers.append('unauthorized-project')
        elif (inputs.get('version')!=entry['version'] or inputs.get('arch') not in entry.get('allowed_architectures',[])
                or inputs.get('system') not in entry.get('allowed_systems',[])
                or (inputs.get('arch')!='noarch' and inputs.get('system')!=inputs.get('arch','')+'-linux')):
            blockers.append('project-version-platform-mismatch')
        else:
            blockers += _input_blockers(entry,inputs,inventory,raw_evidence)
            if not blockers:
                if entry.get('status')!='authorized' or entry.get('blocking') is not False:
                    blockers.append('incomplete-project-policy')
                blockers += _launcher_blockers(entry,inventory)
                if any(not _preserved(p,inventory) for p in inventory['expected']):
                    blockers.append('authenticated-payload-changed')
                if any(p not in inventory['expected'] and not (
                        r['type']=='directory' and p in inventory.get('permitted_directories',[])
                        and r['mode']==0o755) for p,r in inventory['files'].items()):
                    blockers.append('unexpected-payload-member')
                if not blockers and raw_evidence['findings_summary']['errors']:
                    extra,accepted,proofs,duplicates = _evaluate_errors(raw_evidence,entry,inventory,inputs)
                    blockers += extra
    except (ContractError,ValueError,TypeError,KeyError,AttributeError) as exc:
        blockers = ['malformed-or-unavailable-policy-evidence']
    observations = []
    if isinstance(inventory,dict) and isinstance(raw_evidence.get('error_records'),list):
        for record in raw_evidence['error_records']:
            path = record.get('path')
            member = inventory.get('expected',{}).get(path)
            if member and member.get('input_member'):
                observations.append({'code':record.get('code'),'path':path,
                                     'input_member':member['input_member'],
                                     'input_archive_sha256':member['input_archive_sha256'],
                                     'sha256':member.get('sha256'),'mode':member['mode'],
                                     'shebang':member.get('shebang'),'preserved':_preserved(path,inventory)})
    result = {'schema':RPM_POLICY_EVALUATION_SCHEMA,'accepted':not blockers,
              'status':('accepted' if accepted else 'accepted-no-exceptions') if not blockers else 'blocked',
              'blockers':sorted(set(blockers)),'accepted_findings':accepted if not blockers else [],
              'member_proofs':proofs,'duplicate_groups':duplicates,
              'observed_error_members':observations,
              'observed_duplicate_groups':inventory.get('duplicate_groups',[]) if isinstance(inventory,dict) else [],
              'calculated_duplicate_waste':inventory.get('calculated_duplicate_waste') if isinstance(inventory,dict) else None,'policy_sha256':digest(canonical(policy)) if isinstance(policy,dict) else None,
              'raw_lint_status':raw_evidence.get('status'),'raw_exit_code':raw_evidence.get('tool_receipt',{}).get('exit_code'),
              'inputs':inputs,'inventory_sha256':digest(canonical(inventory)) if isinstance(inventory,dict) else None}
    if len(canonical(result))>512*1024:
        return {'schema':RPM_POLICY_EVALUATION_SCHEMA,'accepted':False,'status':'blocked',
                'blockers':['policy-evidence-exceeds-bound'],'accepted_findings':[]}
    return result


def evaluate_policy(raw_evidence, inventory, inputs, policy=None):
    """Malformed observations and serialization must also produce a blocked result."""
    try:
        return _evaluate_policy(raw_evidence, inventory, inputs, policy)
    except (ContractError, ValueError, TypeError, KeyError, AttributeError, OverflowError, RecursionError):
        return {'schema':RPM_POLICY_EVALUATION_SCHEMA,'accepted':False,'status':'blocked',
                'blockers':['malformed-or-unavailable-policy-evidence'],'accepted_findings':[]}
