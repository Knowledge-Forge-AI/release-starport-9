"""Fail-closed current-generation candidate lint policy, distinct from raw lint."""
from collections import Counter
import json
from pathlib import Path
import re

from rs9.errors import ContractError
from rs9.records import closed
from rs9.security import validate_safe_relative_posix_path
import posixpath
from rs9.release_core import digest
from rs9.scratch import canonical
from rs9.rpm_preservation import duplicate_groups, duplicate_waste_totals, INVENTORY_SCHEMA

DEFAULT_POLICY_PATH = Path(__file__).resolve().parents[2]/'operators/live1/rpm-lint-policy.json'
RPM_LINT_POLICY_SCHEMA = 'rs9.rpm-lint-policy.v1'
RPM_POLICY_EVALUATION_SCHEMA = 'rs9.rpm-lint-policy-evaluation.v1'
PERMITTED_EXCEPTION_CLASSES = frozenset({'env-script-interpreter','non-executable-script','files-duplicated-waste'})
CURRENT_VERSIONS = {'theme-forge-stellar-burst':'0.6.1','theme-forge-stellar-loom':'0.4.0','theme-forge-solar-sail':'0.2.1','theme-forge-nebular-fusion':'0.6.1'}
UNWAIVABLE_ERROR_CLASSES = frozenset({'no-changelogname-tag','explicit-lib-dependency'})
MISSING_EVIDENCE_PREDICATES = frozenset({'caller-contract-unproven', 'caller-member-missing',
    'caller-reference-unresolved', 'engine-floor-unproven', 'engine-floor-unmet',
    'node-runtime-floor-unobserved', 'caller-content-or-identity-unproven'})


def _validate_policy(policy):
    json.dumps(policy, allow_nan=False)
    if not isinstance(policy, dict) or policy.get('schema') != RPM_LINT_POLICY_SCHEMA:
        raise ContractError('INVALID_POLICY', 'Invalid candidate lint policy schema')
    if policy.get('production_enabled') is not False or policy.get('publication_authority') is not False:
        raise ContractError('INVALID_POLICY', 'Nonproduction lint policy required')
    codes = policy.get('permitted_preservation_exception_classes')
    projects = policy.get('projects')
    constraints = policy.get('tool_constraints')
    if not isinstance(constraints, dict) or type(constraints.get('filtered_count')) is not int or constraints['filtered_count'] < 0:
        raise ContractError('INVALID_POLICY', 'Explicit existing tool filter count required')
    if not isinstance(codes, list) or set(codes) != PERMITTED_EXCEPTION_CLASSES or not isinstance(projects, dict) or not projects:
        raise ContractError('INVALID_POLICY', 'Malformed candidate lint policy')
    for name, entry in projects.items():
        if not isinstance(entry, dict) or entry.get('package_name') != name or entry.get('version') != CURRENT_VERSIONS.get(name):
            raise ContractError('INVALID_POLICY', 'Malformed exact project identity')
        architectures = entry.get('allowed_architectures')
        systems = entry.get('allowed_systems')
        if (not isinstance(architectures, list) or not architectures or set(architectures) - {'noarch', 'x86_64', 'aarch64'}
                or not isinstance(systems, list) or not systems or set(systems) - {'x86_64-linux', 'aarch64-linux'}):
            raise ContractError('INVALID_POLICY', 'Malformed exact platform scope')
        exceptions = entry.get('exceptions')
        if not isinstance(exceptions, dict) or set(exceptions) - PERMITTED_EXCEPTION_CLASSES:
            raise ContractError('INVALID_POLICY', 'Unauthorized exception class')
        for code, rules in exceptions.items():
            if not isinstance(rules, dict):
                raise ContractError('INVALID_POLICY', 'Malformed exception rules')
            if code == 'files-duplicated-waste':
                if rules.get('discriminator') == 'exact-duplicate-set':
                    closed(rules, {'discriminator', 'systems', 'justification', 'group_authority'}, required={'discriminator', 'systems'})
                    if 'noarch' in architectures or set(rules['systems']) != set(systems):
                        raise ContractError('INVALID_POLICY', 'Exact native duplicate system scope required')
                    for system, pin in rules['systems'].items():
                        closed(pin, {'schema', 'asset_sha256', 'group_count', 'group_set_sha256', 'possible_waste_totals'})
                        if (pin['schema'] != 'fixed-group-set' or type(pin['group_count']) is not int or pin['group_count'] < 1
                                or not re.fullmatch('[0-9a-f]{64}', pin['asset_sha256'])
                                or not re.fullmatch('[0-9a-f]{64}', pin['group_set_sha256'])
                                or not isinstance(pin['possible_waste_totals'], list) or not pin['possible_waste_totals']
                                or any(type(t) is not int or t < 0 for t in pin['possible_waste_totals'])
                                or sorted(set(pin['possible_waste_totals'])) != pin['possible_waste_totals']):
                            raise ContractError('INVALID_POLICY', 'Exact duplicate-group contract required')
                elif rules.get('discriminator') is not None or 'systems' in rules or 'possible_waste_totals' in rules or 'schema' in rules:
                    raise ContractError('INVALID_POLICY', 'Mixed or unknown duplicate rule forms forbidden')
                elif type(rules.get('expected_waste_bytes')) is not int or rules['expected_waste_bytes'] < 0:
                    raise ContractError('INVALID_POLICY', 'Exact duplicate waste required')
            elif not rules or any(not isinstance(path, str) or not path.startswith('/usr/lib/' + name + '/')
                                  or any(c in path for c in '*?[') or not isinstance(rule, dict)
                                  for path, rule in rules.items()):
                raise ContractError('INVALID_POLICY', 'Exact private script paths required')
            else:
                for path, rule in rules.items():
                    discriminator = rule.get('discriminator')
                    if discriminator == 'per-system-script':
                        closed(rule, {'discriminator', 'intent', 'public_launcher', 'status', 'missing_predicate', 'systems', 'caller_member', 'reference_contract', 'floor_source', 'role', 'caller_structure'}, required={'discriminator', 'intent', 'public_launcher', 'systems'})
                        if (any(k in rule for k in ('caller_member', 'reference_contract', 'floor_source'))
                                or (rule.get('intent') != 'typescript-declaration-data' and 'role' not in rule)):
                            raise ContractError('INVALID_POLICY', 'Authenticated typed caller role required')
                        if 'role' in rule:
                            from rs9.nebular_callers import NEBULAR_REAL_ROLES, validate_rule
                            if name != 'theme-forge-nebular-fusion' or rule['role'] not in NEBULAR_REAL_ROLES:
                                raise ContractError('INVALID_POLICY', 'Unauthorized script role')
                            validate_rule(path, rule)
                        if 'caller_structure' in rule:
                            if not isinstance(rule['caller_structure'], dict):
                                raise ContractError('INVALID_POLICY', 'Malformed caller structure')
                        if rule['public_launcher'] is not False:
                            raise ContractError('INVALID_POLICY', 'Private member rules cannot expose launchers')
                        if 'missing_predicate' in rule and rule['missing_predicate'] not in MISSING_EVIDENCE_PREDICATES:
                            raise ContractError('INVALID_POLICY', 'Unknown caller missing-evidence predicate')
                        if 'noarch' in entry.get('allowed_architectures', []):
                            raise ContractError('INVALID_POLICY', 'Reject noarch form for native platform')
                        sys_map = rule.get('systems')
                        if not isinstance(sys_map, dict) or not sys_map or set(sys_map) != set(entry['allowed_systems']):
                            raise ContractError('INVALID_POLICY', 'Malformed exact platform scope')
                        if 'noarch' in sys_map:
                            raise ContractError('INVALID_POLICY', 'Reject noarch form for native platform')
                        for s_name, spin in sys_map.items():
                            closed(spin, {'asset_sha256', 'input_member', 'sha256', 'mode', 'shebang', 'caller_sha256', 'floor_sha256', 'client_image'}, required={'asset_sha256', 'input_member', 'sha256', 'mode', 'shebang'})
                            if not re.fullmatch(r'[0-9a-f]{64}', str(spin.get('asset_sha256', ''))):
                                raise ContractError('INVALID_POLICY', 'Exact system asset sha256 required')
                            inp_mem = spin.get('input_member')
                            if not isinstance(inp_mem, str) or any(c in inp_mem for c in '*?['):
                                raise ContractError('INVALID_POLICY', 'Exact input member required')
                            validate_safe_relative_posix_path(inp_mem)
                            if not re.fullmatch(r'[0-9a-f]{64}', str(spin.get('sha256', ''))):
                                raise ContractError('INVALID_POLICY', 'Exact member sha256 required')
                            mode_val = spin.get('mode')
                            if not isinstance(mode_val, str) or not re.fullmatch(r'[0-7]{3,4}', mode_val):
                                raise ContractError('INVALID_POLICY', 'Exact octal mode required')
                            if not isinstance(spin.get('shebang'), str):
                                raise ContractError('INVALID_POLICY', 'Exact shebang required')
                        intent = rule.get('intent')
                        if intent == 'typescript-declaration-data':
                            if not path.endswith('.d.ts') or rule.get('public_launcher') is not False:
                                raise ContractError('INVALID_POLICY', 'TypeScript declaration nonexecute not public required')
                        elif intent in ('internal-interpreter-mediated', 'internal-retained-source'):
                            if rule.get('launcher'):
                                raise ContractError('INVALID_POLICY', 'Public wrappers forbidden for internal scripts')
                        else:
                            raise ContractError('INVALID_POLICY', 'Unauthorized script intent')
                    elif discriminator is not None or 'systems' in rule:
                        raise ContractError('INVALID_POLICY', 'Unknown or ambiguous discriminator')
    return policy


def load_policy(path=None):
    try:
        return _validate_policy(json.loads((Path(path) if path is not None else DEFAULT_POLICY_PATH).read_bytes()))
    except (OSError, ValueError, TypeError) as exc:
        raise ContractError('INVALID_POLICY', 'Candidate lint policy unavailable or malformed') from exc


def _raw_blockers(raw, policy):
    summary, tool = raw.get('findings_summary'), raw.get('tool_receipt', {})
    if not isinstance(summary, dict):
        return ['missing-findings-summary']
    fields = ('errors', 'warnings', 'filtered', 'packages', 'specfiles')
    if any(type(summary.get(k)) is not int or summary[k] < 0 for k in fields):
        return ['malformed-counts']
    if summary['filtered'] != policy['tool_constraints']['filtered_count']:
        return ['configuration-filtered-count-mismatch']
    errors = raw.get('error_records')
    if not isinstance(errors, list) or len(errors) != summary['errors']:
        return ['incomplete-error-records']
    if any(not isinstance(r, dict) or r.get('arguments_complete') is not True or r.get('level') != 'E'
           or not isinstance(r.get('code'), str) or not isinstance(r.get('target'), str) for r in errors):
        return ['malformed-error-records']
    if raw.get('parse_complete') is not True or raw.get('unparsed_count') != 0 or raw.get('error_overflow'):
        return ['incomplete-raw-result']
    if (summary['packages'], summary['specfiles']) != (1, 1):
        return ['input-count-mismatch']
    expected_exit = 64 if summary['errors'] else 0
    if tool.get('executed') is not True or tool.get('exit_code') != expected_exit or tool.get('stderr_bytes') != 0:
        return ['tool-execution-failure']
    if raw.get('clean') is not (summary['errors'] == 0) or raw.get('status') != ('fail' if summary['errors'] else 'pass'):
        return ['contradictory-raw-result']
    version = raw.get('tool_version', {})
    package = version.get('package_query', {})
    if (version.get('exit_code') != 0 or version.get('version') not in ('2.8.0', 'rpmlint 2.8.0')
            or package.get('exit_code') != 0 or package.get('version') != 'rpmlint|2.8.0|2.fc43|noarch'):
        return ['tool-identity-mismatch']
    return []


def _input_blockers(entry, inputs, inventory, raw):
    if not isinstance(inventory, dict) or inventory.get('schema') != INVENTORY_SCHEMA or inventory.get('complete') is not True:
        return ['incomplete-preservation-inventory']
    for key in ('asset_sha256', 'payload_manifest_sha256', 'closure_sha256'):
        if inputs.get(key) != inventory.get(key):
            return ['input-inventory-mismatch:' + key]
    if inventory.get('package_sha256') != raw.get('package_sha256') or not re.fullmatch('[0-9a-f]{64}', raw.get('package_sha256', '')):
        return ['package-identity-mismatch']
    auth = entry.get('authenticated_inputs', {})
    asset = auth.get('asset_sha256')
    if asset is None:
        platform = {'x86_64': 'x86_64-unknown-linux-gnu', 'aarch64': 'aarch64-unknown-linux-gnu'}.get(inputs.get('arch'))
        asset = next((r['sha256'] for r in auth.get('assets', []) if platform and platform in r['name']), None)
    if inputs.get('asset_sha256') != asset:
        return ['asset-identity-mismatch']
    if inputs.get('closure_sha256') != auth.get('closure_sha256'):
        return ['closure-identity-mismatch']
    if not re.fullmatch('[0-9a-f]{64}', inputs.get('payload_manifest_sha256', '')):
        return ['payload-manifest-unbound']
    return []


def _preserved(path, inventory):
    actual = inventory.get('files', {}).get(path)
    expected = inventory.get('expected', {}).get(path)
    if not actual or not expected:
        return False
    if actual.get('owner') != 'root' or actual.get('group') != 'root' or actual.get('flags', 0) & 64:
        return False
    keys = ('type', 'mode', 'size', 'sha256') if expected['type'] == 'file' else ('type', 'mode', 'target') if expected['type'] == 'symlink' else ('type', 'mode')
    return all(actual.get(k) == expected.get(k) for k in keys)


def _node_available(inventory):
    engine = inventory.get('engine_node')
    if not isinstance(engine, str) or not re.fullmatch(r'>=\s*22(?:\.0(?:\.0)?)?', engine):
        return False
    return 'nodejs >= 22' in inventory.get('requires', [])


NODE_QUERY_COMMAND = ['rpm', '-q', '--queryformat', '%{NAME}|%{VERSION}|%{RELEASE}|%{ARCH}\n', 'nodejs']


def _publicly_exposed(path, inventory):
    if any(w.get('target') == path for name, w in inventory.get('wrappers', {}).items() if name.startswith('/usr/bin/')):
        return True
    return any(name.startswith('/usr/bin/') and row.get('type') == 'symlink'
               and posixpath.normpath(posixpath.join(posixpath.dirname(name), row.get('target', ''))) == path
               for name, row in inventory['files'].items())


def _script_proof(record, rule, inventory, inputs=None):
    path = record.get('path')
    if not _preserved(path, inventory):
        return None, 'script-preservation-unproven'
    expected, actual = inventory['expected'][path], inventory['files'][path]
    shebang = expected.get('shebang')
    if shebang != '#!/usr/bin/env node' or record.get('interpreter') != '/usr/bin/env node':
        return None, 'script-interpreter-mismatch'

    discriminator = rule.get('discriminator')
    if discriminator == 'per-system-script':
        system = inputs.get('system') if inputs else None
        if not system or system not in rule.get('systems', {}):
            return None, 'system-pin-missing'
        pin = rule['systems'][system]
        if pin.get('asset_sha256') != expected.get('input_archive_sha256') or pin.get('asset_sha256') != (inputs.get('asset_sha256') if inputs else None):
            return None, 'asset-sha-mismatch'
        if pin.get('input_member') != expected.get('input_member'):
            return None, 'input-member-mismatch'
        if pin.get('sha256') != actual.get('sha256'):
            return None, 'member-sha-mismatch'
        expected_mode = int(pin['mode'], 8) if isinstance(pin.get('mode'), str) else pin.get('mode')
        if actual.get('mode') != expected_mode:
            return None, 'member-mode-mismatch'
        if record.get('code') == 'non-executable-script' and int(record.get('mode', '0'), 8) != actual['mode']:
            return None, 'record-mode-mismatch'
        expected_shebang = pin.get('shebang', '/usr/bin/env node')
        if shebang.removeprefix('#!') != expected_shebang.removeprefix('#!'):
            return None, 'shebang-mismatch'

        if actual['type'] != 'file' or expected.get('origin') != 'release' or _publicly_exposed(path, inventory):
            return None, 'private-member-exposure-or-type'
        intent = rule.get('intent')
        if intent == 'typescript-declaration-data':
            if not path.endswith('.d.ts') or record.get('code') != 'non-executable-script' or actual['mode'] & 0o111:
                return None, 'declaration-predicate-failed'
            if rule.get('public_launcher') is not False:
                return None, 'public-launcher-forbidden'
            proof = {
                'path': path,
                'input_member': expected['input_member'],
                'input_archive_sha256': expected['input_archive_sha256'],
                'sha256': actual['sha256'],
                'mode': actual['mode'],
                'shebang': shebang,
                'intent': intent,
            }
            if 'role' in rule:
                proof['role'] = rule['role']
            return proof, None
        elif intent in ('internal-interpreter-mediated', 'internal-retained-source'):
            if inputs and inputs.get('project_id') == 'theme-forge-nebular-fusion':
                from rs9.nebular_callers import verify_nebular_caller
                return verify_nebular_caller(
                    path,
                    rule,
                    pin,
                    inventory,
                    inputs,
                    caller_evidence=inventory.get('caller_evidence'),
                    client_runtime=inventory.get('client_runtime_evidence'),
                )
            return None, 'caller-contract-unproven'
        else:
            return None, 'unapproved-intent'
    else:
        # Legacy form
        if rule.get('shebang', '/usr/bin/env node') != shebang.removeprefix('#!'):
            return None, 'shebang-mismatch'
        if rule.get('interpreter', 'node') != 'node':
            return None, 'interpreter-mismatch'
        if not expected.get('input_member') or not re.fullmatch('[0-9a-f]{64}', expected.get('input_archive_sha256', '')):
            return None, 'member-identity-missing'
        if 'mode' in rule and actual['mode'] != int(rule['mode'], 8):
            return None, 'member-mode-mismatch'
        if record['code'] == 'non-executable-script' and int(record.get('mode', '0'), 8) != actual['mode']:
            return None, 'record-mode-mismatch'
        intent = rule.get('intent')
        if intent == 'typescript-declaration-data':
            if not path.endswith('.d.ts') or record['code'] != 'non-executable-script':
                return None, 'declaration-predicate-failed'
        else:
            launcher = rule.get('launcher')
            wrapper = inventory.get('wrappers', {}).get(launcher)
            installed = inventory.get('files', {}).get(launcher)
            if not wrapper or not installed or wrapper['target'] != path or any(installed.get(k) != wrapper[k] for k in ('sha256', 'mode', 'type')):
                return None, 'launcher-mismatch'
            if not _node_available(inventory):
                return None, 'node-unavailable'
        return {
            'path': path,
            'input_member': expected['input_member'],
            'input_archive_sha256': expected['input_archive_sha256'],
            'sha256': actual['sha256'],
            'mode': actual['mode'],
            'shebang': shebang,
            'intent': intent or 'maintained-node-wrapper',
            'launcher': rule.get('launcher'),
        }, None


def _duplicate_proof(record, rule, inventory, inputs=None):
    groups, waste = duplicate_groups(inventory['files'])
    observed_waste = record.get('waste_bytes')
    if type(observed_waste) is not int:
        return None
    is_fixed = (
        rule.get('discriminator') == 'exact-duplicate-set'
    )
    if is_fixed:
        system = inputs.get('system') if inputs else None
        sys_rule = rule.get('systems', {}).get(system) if system and 'systems' in rule else rule
        if not isinstance(sys_rule, dict) or sys_rule.get('asset_sha256') != inputs.get('asset_sha256'):
            return None
        expected_count = sys_rule.get('group_count')
        expected_set_sha = sys_rule.get('group_set_sha256')
        declared_totals = sys_rule.get('possible_waste_totals')
        if len(groups) != expected_count:
            return None
        if digest(canonical(groups)) != expected_set_sha:
            return None
        recomputed_totals = duplicate_waste_totals(groups)
        if declared_totals != recomputed_totals:
            return None
        if observed_waste not in recomputed_totals:
            return None
    else:
        if observed_waste not in duplicate_waste_totals(groups) or observed_waste != rule.get('expected_waste_bytes'):
            return None

    if any(not _preserved(path, inventory) or inventory['expected'][path].get('origin') not in {'release', 'offline-npm', 'license-projection'}
           for g in groups for path in g['members']):
        return None
    # Authenticated archives forbid hardlinks; reject any changed inode grouping.
    keys = [(r['device'], r['inode']) for r in inventory['files'].values() if r['type'] == 'file']
    if len(set(keys)) != len(keys):
        return None
    expected_files = {p: dict(r, device=0, inode=i, flags=0) for i, (p, r) in enumerate(sorted(inventory['expected'].items()))}
    expected_groups, expected_waste = duplicate_groups(expected_files)
    if groups != expected_groups or waste != expected_waste:
        return None
    return groups


def _launcher_blockers(entry, inventory):
    declared = entry.get('launchers', {})
    wrappers = inventory.get('wrappers', {})
    if not isinstance(declared, dict) or set(wrappers) != {r['path'] for r in declared.values()}:
        return ['policy-launcher-set-mismatch']
    for rule in declared.values():
        path, target = rule['path'], rule['target']
        body = ('#!/bin/sh\nexec node "' + target + '" "$@"\n').encode()
        expected = dict(target=target, sha256=digest(body), mode=int(rule['mode'], 8), type='file')
        if (rule['type'] != 'node_wrapper' or expected['mode'] != 0o755 or wrappers.get(path) != expected
                or not _preserved(path, inventory)):
            return ['policy-launcher-mismatch']
    return []


def _evaluate_errors(raw, entry, inventory, inputs):
    blockers, rule_blockers, accepted, proofs, duplicates = [], [], [], [], []
    exceptions = entry['exceptions']
    counts = Counter(r.get('code') for r in raw['error_records'])
    expected_counts = {code: len(rules) if code != 'files-duplicated-waste' else 1 for code, rules in exceptions.items()}
    if dict(counts) != expected_counts:
        blockers.append('exception-count-mismatch')
    for code, rules in exceptions.items():
        if code != 'files-duplicated-waste' and Counter(r.get('path') for r in raw['error_records'] if r.get('code') == code) != Counter(rules.keys()):
            blockers.append('exception-path-set-mismatch')
    for record in raw['error_records']:
        code = record.get('code')
        path = record.get('path')
        if record.get('target') != inputs['project_id'] + '.' + inputs['arch']:
            blockers.append('wrong-finding-target')
            continue
        if code not in exceptions or code not in PERMITTED_EXCEPTION_CLASSES:
            blockers.append('unapproved-error-code:' + str(code))
            continue
        if code == 'files-duplicated-waste':
            groups = _duplicate_proof(record, exceptions[code], inventory, inputs)
            if groups is None:
                rule_blockers.append(f"{code}:duplicate-preservation-unproven")
                blockers.append('duplicate-preservation-unproven')
            else:
                duplicates = groups
                accepted.append(record)
        else:
            rule = exceptions[code].get(path)
            proof, pred = _script_proof(record, rule, inventory, inputs) if rule else (None, 'script-preservation-unproven')
            if proof is None:
                rule_blockers.append(f"{code}:{path}:{pred}")
                blockers.append(f"{code}:{path}:{pred}")
            else:
                proofs.append(proof)
                accepted.append(record)
    return blockers, rule_blockers, accepted, proofs, duplicates


def _blocked_evaluation(reason, raw, inputs):
    """Retain source identity even when policy evaluation itself is unavailable."""
    raw = raw if isinstance(raw, dict) else {}
    receipt = raw.get('tool_receipt')
    return {'schema': RPM_POLICY_EVALUATION_SCHEMA, 'accepted': False,
            'status': 'blocked', 'blockers': [reason], 'rule_blockers': [],
            'accepted_findings': [], 'member_proofs': [], 'duplicate_groups': [],
            'inputs': inputs if isinstance(inputs, dict) else {},
            'raw_lint_status': raw.get('status'),
            'raw_exit_code': receipt.get('exit_code') if isinstance(receipt, dict) else None}


def _evaluate_policy(raw_evidence, inventory, inputs, policy=None):
    """Only complete raw results and exact member proofs can accept exceptions."""
    if not isinstance(raw_evidence, dict):
        return _blocked_evaluation('malformed-raw-evidence', raw_evidence, inputs)
    if not isinstance(inputs, dict):
        inputs = {}
    accepted, proofs, duplicates, rule_blockers = [], [], [], []
    payload_compromised = False
    try:
        policy = _validate_policy(policy) if policy is not None else load_policy()
        entry = policy['projects'].get(inputs.get('project_id'))
        blockers = _raw_blockers(raw_evidence, policy)
        if not isinstance(entry, dict):
            blockers.append('unauthorized-project')
            payload_compromised = True
        elif (inputs.get('version') != entry['version'] or inputs.get('arch') not in entry.get('allowed_architectures', [])
                or inputs.get('system') not in entry.get('allowed_systems', [])
                or (inputs.get('arch') != 'noarch' and inputs.get('system') != inputs.get('arch', '') + '-linux')):
            blockers.append('project-version-platform-mismatch')
            payload_compromised = True
        else:
            inp_bl = _input_blockers(entry, inputs, inventory, raw_evidence)
            if inp_bl:
                blockers += inp_bl
                payload_compromised = True
            else:
                if entry.get('status') != 'authorized' or entry.get('blocking') is not False:
                    blockers.append('incomplete-project-policy')
                lnch_bl = _launcher_blockers(entry, inventory)
                if lnch_bl:
                    blockers += lnch_bl
                    payload_compromised = True
                if any(not _preserved(p, inventory) for p in inventory.get('expected', {})):
                    blockers.append('authenticated-payload-changed')
                    payload_compromised = True
                if any(p not in inventory.get('expected', {}) and not (
                        r['type'] == 'directory' and p in inventory.get('permitted_directories', [])
                        and r['mode'] == 0o755) for p, r in inventory.get('files', {}).items()):
                    blockers.append('unexpected-payload-member')
                    payload_compromised = True

                # Evaluate errors without blanket short circuit for incomplete-project-policy
                if raw_evidence.get('findings_summary', {}).get('errors'):
                    extra, r_blockers, acc, prfs, dups = _evaluate_errors(raw_evidence, entry, inventory, inputs)
                    blockers += extra
                    rule_blockers += r_blockers
                    accepted = acc
                    proofs = prfs
                    duplicates = dups
    except (ContractError, ValueError, TypeError, KeyError, AttributeError) as exc:
        blockers = ['malformed-or-unavailable-policy-evidence']
        payload_compromised = True

    # Partial proofs are useful only for exact Nebular rules awaiting caller or
    # client evidence. A changed identity, error set or legacy rule stays wholly
    # rejected, as before.
    partial = (inputs.get('project_id') == 'theme-forge-nebular-fusion'
               and blockers and set(blockers) == set(rule_blockers)
               and all(b.rsplit(':', 1)[-1] in MISSING_EVIDENCE_PREDICATES for b in blockers))
    if (not blockers or partial) and not payload_compromised and not _raw_blockers(raw_evidence, policy):
        accepted_findings = accepted
        member_proofs = proofs
        duplicate_groups_res = duplicates
    else:
        accepted_findings = []
        member_proofs = []
        duplicate_groups_res = []

    observations = []
    if isinstance(inventory, dict) and isinstance(raw_evidence.get('error_records'), list):
        for record in raw_evidence['error_records']:
            path = record.get('path')
            member = inventory.get('expected', {}).get(path)
            if member and member.get('input_member'):
                observations.append({
                    'code': record.get('code'),
                    'path': path,
                    'input_member': member['input_member'],
                    'input_archive_sha256': member['input_archive_sha256'],
                    'sha256': member.get('sha256'),
                    'mode': member['mode'],
                    'shebang': member.get('shebang'),
                    'preserved': _preserved(path, inventory),
                })

    result = {
        'schema': RPM_POLICY_EVALUATION_SCHEMA,
        'accepted': not blockers,
        'status': ('accepted' if accepted_findings else 'accepted-no-exceptions') if not blockers else 'blocked',
        'blockers': sorted(set(blockers)),
        'rule_blockers': sorted(set(rule_blockers)),
        'rule_blocker_causes': [dict(predicate='caller-content-or-identity-unproven', path=b.split(':')[1],
             cause='content-absent' if not (inventory.get('caller_evidence') or {}).get('files') else 'identity-mismatch')
             for b in sorted(set(rule_blockers)) if b.endswith(':caller-content-or-identity-unproven')],
        'accepted_findings': accepted_findings,
        'member_proofs': member_proofs,
        'duplicate_groups': duplicate_groups_res,
        'observed_error_members': observations,
        'observed_duplicate_groups': inventory.get('duplicate_groups', []) if isinstance(inventory, dict) else [],
        'calculated_duplicate_waste': inventory.get('calculated_duplicate_waste') if isinstance(inventory, dict) else None,
        'policy_sha256': digest(canonical(policy)) if isinstance(policy, dict) else None,
        'raw_lint_status': raw_evidence.get('status'),
        'raw_exit_code': raw_evidence.get('tool_receipt', {}).get('exit_code'),
        'inputs': inputs,
        'inventory_sha256': digest(canonical(inventory)) if isinstance(inventory, dict) else None,
    }
    if len(canonical(result)) > 512 * 1024:
        return _blocked_evaluation('policy-evidence-exceeds-bound', raw_evidence, inputs)
    return result


def evaluate_policy(raw_evidence, inventory, inputs, policy=None):
    """Malformed observations and serialization must also produce a blocked result."""
    try:
        return _evaluate_policy(raw_evidence, inventory, inputs, policy)
    except (ContractError, ValueError, TypeError, KeyError, AttributeError, OverflowError, RecursionError):
        return _blocked_evaluation('malformed-or-unavailable-policy-evidence', raw_evidence, inputs)
