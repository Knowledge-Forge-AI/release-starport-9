"""Authenticated input projections and isolated RPM inventory for lint policy.

No payload extraction or transformation. RPM SHA256 header digests, modes,
links and inode groups are compared with complete authenticated input members.
"""
from collections import Counter, defaultdict
import json
from pathlib import Path
import posixpath
import re
import stat
from typing import Any

from rs9.archives import inspect_archive
from rs9.errors import ContractError, safe_details
from rs9.machine_stream import machine_records, machine_text, raise_stream_error
from rs9.profiles import png_size
from rs9.release_core import digest
from rs9.rpm_query import rpm_isolation_args
from rs9.scratch import canonical
from rs9.security import validate_safe_relative_posix_path

INVENTORY_SCHEMA = "rs9.rpm-preservation-inventory.v1"
DIAGNOSTIC_SCHEMA = "rs9.rpm-preservation-diagnostic.v1"
MAX_FILES = 20000
RPM_QUERY_MAX_BYTES = 16 * 1024 * 1024
RPM_ALGO_MAX_BYTES = 64


def package_path(value):
    if (
        not isinstance(value, str)
        or len(value) > 1024
        or not value.startswith('/usr/')
        or any(c.isspace() or c in '|:' for c in value)
    ):
        raise ContractError('RPM_INVENTORY_FAILED', 'Package member cannot be represented exactly')
    validate_safe_relative_posix_path(value[1:])
    return value


def _build_inventory_diagnostic(queries_ledger: list[dict[str, Any]], overall_status: str) -> dict[str, Any]:
    """Construct bounded inventory diagnostic (<= 16KiB) without raw lines or private paths."""
    diagnostic = {
        "schema": DIAGNOSTIC_SCHEMA,
        "status": overall_status,
        "substage": "rpm-preservation-inventory",
        "queries": queries_ledger,
    }
    from rs9.security import scan_for_credentials
    raw = canonical(diagnostic)
    scan_for_credentials(raw.decode('utf-8'))
    if len(raw) > 16 * 1024:
        raise ContractError('RPM_INVENTORY_FAILED', 'Inventory diagnostic exceeds 16KiB bound')
    return diagnostic


def _query(runner, rpm_file, scratch, isolation, args, query_name):
    cmd = ['rpm', *isolation, '-qp', *args, str(rpm_file)]
    try:
        receipt = runner.run(cmd, cwd=scratch)
    except ContractError as exc:
        exc.details = safe_details({**exc.details,
            'substage': 'rpm-preservation-inventory', 'tool': 'rpm',
            'reason_token': 'query-execution-failed', 'diagnostic_token': query_name,
            'underlying_code': exc.code})
        raise
    if receipt.exit_code != 0 or bool(receipt.stderr_bytes):
        reason = "process-nonzero" if receipt.exit_code != 0 else "stderr-not-empty"
        msg = (
            f"Isolated RPM query {query_name} failed"
            if receipt.exit_code != 0
            else f"Isolated RPM query {query_name} returned stderr"
        )
        raise_stream_error(
            code='RPM_INVENTORY_FAILED',
            message=msg,
            reason_token=reason,
            receipt=receipt,
            stream='stdout' if receipt.exit_code != 0 else 'stderr',
            substage='rpm-preservation-inventory',
        )
    return receipt


def parse_dump(text_or_records, attributes):
    """Require the complete 11-field RPM dump and matching inode/flag inventory."""
    if isinstance(text_or_records, str):
        if not text_or_records or not text_or_records.endswith('\n'):
            raise ContractError('RPM_INVENTORY_FAILED', 'Incomplete RPM member inventory')
        lines = text_or_records[:-1].split('\n')
    elif isinstance(text_or_records, (list, tuple)):
        lines = text_or_records
    else:
        raise ContractError('RPM_INVENTORY_FAILED', 'Invalid dump records type')

    files = {}
    for line in lines:
        if not line or not line.strip():
            raise ContractError('RPM_INVENTORY_FAILED', 'Malformed or excessive RPM dump')
        parts = line.split(' ')
        if len(parts) != 11 or any(not part for part in parts) or len(files) >= MAX_FILES:
            raise ContractError('RPM_INVENTORY_FAILED', 'Malformed or excessive RPM dump')
        path = package_path(parts[0])
        if path in files or path not in attributes:
            raise ContractError('RPM_INVENTORY_FAILED', 'Duplicate or unmatched RPM member')

        # Strict canonical ASCII decimal checks
        if not re.fullmatch(r'[0-9]{1,20}', parts[1], re.ASCII) or not re.fullmatch(r'[0-9]{1,20}', parts[2], re.ASCII):
            raise ContractError('RPM_INVENTORY_FAILED', 'Malformed RPM member metadata')
        size, mtime = int(parts[1]), int(parts[2])

        # Strict canonical ASCII octal mode check
        if not re.fullmatch(r'[0-7]{1,7}', parts[4], re.ASCII):
            raise ContractError('RPM_INVENTORY_FAILED', 'Malformed RPM member metadata')
        mode = int(parts[4], 8)

        if size < 0 or parts[7] not in ('0', '1') or parts[8] not in ('0', '1'):
            raise ContractError('RPM_INVENTORY_FAILED', 'Malformed RPM member metadata')

        # Strict canonical rdev check
        if not re.fullmatch(r'[0-9]{1,20}', parts[9], re.ASCII):
            raise ContractError('RPM_INVENTORY_FAILED', 'Malformed RPM member metadata')

        # Owner and group non-empty ASCII tokens
        if not re.fullmatch(r'[A-Za-z0-9_.-]+', parts[5], re.ASCII) or not re.fullmatch(r'[A-Za-z0-9_.-]+', parts[6], re.ASCII):
            raise ContractError('RPM_INVENTORY_FAILED', 'Malformed RPM member metadata')

        kind = 'file' if stat.S_ISREG(mode) else 'directory' if stat.S_ISDIR(mode) else 'symlink' if stat.S_ISLNK(mode) else 'special'
        if kind == 'special':
            raise ContractError('RPM_INVENTORY_FAILED', 'Unsupported RPM member kind or digest')

        # SHA256 or zero non-file digest
        if kind == 'file':
            if not re.fullmatch(r'[0-9a-f]{64}', parts[3], re.ASCII) or parts[3] == '0' * 64:
                raise ContractError('RPM_INVENTORY_FAILED', 'Unsupported RPM member kind or digest')
        else:
            if parts[3] != '0' * 64:
                raise ContractError('RPM_INVENTORY_FAILED', 'Unsupported RPM member kind or digest')

        # Symlink target check
        if kind == 'symlink':
            target = parts[10]
            if not target:
                raise ContractError('RPM_INVENTORY_FAILED', 'Malformed RPM member metadata')
        else:
            if parts[10] != 'X':
                raise ContractError('RPM_INVENTORY_FAILED', 'Malformed RPM member metadata')

        row = dict(
            path=path,
            type=kind,
            mode=stat.S_IMODE(mode),
            size=size,
            owner=parts[5],
            group=parts[6],
            **attributes[path],
        )
        if kind == 'file':
            row['sha256'] = parts[3]
        if kind == 'symlink':
            row['target'] = parts[10]
        files[path] = row

    if set(files) != set(attributes) or not files:
        raise ContractError('RPM_INVENTORY_FAILED', 'Incomplete RPM member inventory')
    return files


def duplicate_groups(files, minimum_size=0):
    """Retain complete groups and every possible rpmlint 2.8 representative.

    Upstream set.pop() can choose any member. A mixed-prefix group can therefore
    have several waste values; never substitute a sorted member for that choice.
    Uses full inode/rdev/ghost metadata and retains all duplicate member paths.
    """
    eligible = [r for r in files.values() if r['type'] == 'file' and not r.get('flags',0) & 64 and r['size'] > minimum_size]
    links = Counter((r['device'],r['inode']) for r in eligible)
    hashes = defaultdict(list)
    for row in eligible: hashes[row['sha256']].append(row)
    groups = []
    def prefix(path):
        parts = path.split('/')
        return '/'.join(parts[:2] if len(parts) == 3 else parts[:3])
    for sha, rows in sorted(hashes.items()):
        if len(rows) < 2: continue
        rows.sort(key=lambda r:r['path'])
        if len({r['size'] for r in rows}) != 1:
            raise ContractError('RPM_INVENTORY_FAILED', 'Equal digest with inconsistent sizes')
        values = set()
        for index, representative in enumerate(rows):
            copies = len(rows) - links[(representative['device'],representative['inode'])]
            other_prefixes = sum(prefix(r['path']) != prefix(representative['path'])
                                 for i,r in enumerate(rows) if i != index)
            values.add(0 if copies <= 0 else representative['size'] * (copies - other_prefixes))
        groups.append({'sha256':sha,'size':rows[0]['size'],'members':[r['path'] for r in rows],
                       'possible_waste_bytes':sorted(values),
                       'waste':next(iter(values)) if len(values)==1 else None})
    totals = duplicate_waste_totals(groups)
    return groups, totals[0] if len(totals)==1 else None


def duplicate_waste_totals(groups):
    """Bound the exact sums; excessive ambiguity blocks rather than approximates."""
    totals = {0}
    for group in groups:
        next_totals = set()
        for a in totals:
            for b in group['possible_waste_bytes']:
                next_totals.add(a+b)
                if len(next_totals) > MAX_FILES:
                    raise ContractError('RPM_INVENTORY_FAILED', 'Duplicate waste ambiguity exceeds bound')
        totals = next_totals
    return sorted(totals)


def _archive_projection(path, expected_sha, install_root, origin, contract_members=None):
    if digest(Path(path).read_bytes()) != expected_sha:
        raise ContractError('INPUT_CHANGED', 'Authenticated inventory archive identity changed')
    scripts, package = {}, {}
    contract_contents = {}
    known_members = set(contract_members) if contract_members else set()
    def visit(name, data, mode):
        if data.startswith(b'#!'):
            line = data.split(b'\n',1)[0]
            if len(line)>512 or any(c < 32 or c > 126 for c in line):
                raise ContractError('RPM_INVENTORY_FAILED','Unbounded input shebang')
            scripts[name] = line.decode('ascii')
        if name.endswith('/package.json') and name.count('/')==1:
            package.update(json.loads(data))
        destination = install_root + '/' + name.split('/', 1)[-1]
        if destination in known_members:
            if len(data) > 256 * 1024:
                raise ContractError('RPM_INVENTORY_FAILED', 'Authenticated contract member exceeds bound')
            try:
                text = data.decode('utf-8')
            except UnicodeDecodeError:
                return  # Binary members cannot satisfy the text contract.
            from rs9.security import scan_for_credentials
            scan_for_credentials(text)
            contract_contents[name] = text
    manifest = inspect_archive(path, {}, on_file=visit)
    root = manifest['root']
    expected = {}
    for row in manifest['members']:
        suffix = row['path'].removeprefix(root)
        destination = package_path(install_root + suffix)
        value = {k:v for k,v in row.items() if k not in ('path',)}
        value.update(path=destination, input_member=row['path'], input_archive_sha256=expected_sha, origin=origin)
        if row['path'] in scripts: value['shebang']=scripts[row['path']]
        if row['path'] in contract_contents: value['content']=contract_contents[row['path']]
        expected[destination] = value
    return expected, manifest['manifest_sha256'], package


def collect_preservation_inventory(
    runner,
    rpm_file,
    capture,
    ctx,
    staged_nm,
    cmds,
    requires,
    scratch,
    dbpath,
    keyringpath,
    *,
    policy=None,
    client_runtime=None,
    caller_evidence=None,
):
    isolation = rpm_isolation_args(dbpath=dbpath, keyring='rpmdb', keyringpath=keyringpath)
    substage = "rpm-preservation-inventory"
    queries_ledger = []

    # 1. Query: dump
    dump = None
    dump_records = None
    try:
        dump = _query(runner, rpm_file, scratch, isolation, ['--dump'], 'dump')
        dump_records = machine_records(
            dump,
            limit=RPM_QUERY_MAX_BYTES,
            code='RPM_INVENTORY_FAILED',
            substage=substage,
            encoding='utf-8',
        )
        queries_ledger.append({
            'query': 'dump',
            'tool': 'rpm', 'substage': 'rpm-dump',
            'executed': dump.executed if dump is not None else False,
            'limit': RPM_QUERY_MAX_BYTES,
            'exit_code': dump.exit_code,
            'stdout_sha256': dump.stdout_sha256,
            'stderr_sha256': dump.stderr_sha256,
            'stdout_length': len(dump.stdout_bytes),
            'stderr_length': len(dump.stderr_bytes),
            'count': len(dump_records),
            'status': 'pass',
        })
    except Exception as exc:
        dump = getattr(exc, 'receipt', None) or dump
        queries_ledger.append({
            'query': 'dump',
            'tool': 'rpm', 'substage': 'rpm-dump',
            'executed': dump.executed if dump is not None else False,
            'limit': RPM_QUERY_MAX_BYTES,
            'exit_code': getattr(dump, "exit_code", None) if dump else None,
            'stdout_sha256': getattr(dump, "stdout_sha256", None) if dump else None,
            'stderr_sha256': getattr(dump, "stderr_sha256", None) if dump else None,
            'stdout_length': len(dump.stdout_bytes) if dump else 0,
            'stderr_length': len(dump.stderr_bytes) if dump else 0,
            'count': 0,
            'status': 'fail',
        })
        queries_ledger.extend([
            {'query': 'algo', 'exit_code': None, 'stdout_sha256': None, 'stderr_sha256': None, 'stdout_length': 0, 'stderr_length': 0, 'count': 0, 'status': 'not-run'},
            {'query': 'attrs', 'exit_code': None, 'stdout_sha256': None, 'stderr_sha256': None, 'stdout_length': 0, 'stderr_length': 0, 'count': 0, 'status': 'not-run'},
        ])
        diag = _build_inventory_diagnostic(queries_ledger, "fail")
        exc.inventory_diagnostic = diag
        if getattr(exc, 'receipt', None) is None:
            exc.receipt = dump
        raise exc

    # 2. Query: algo
    algo = None
    try:
        algo = _query(runner, rpm_file, scratch, isolation, ['--queryformat', '%{FILEDIGESTALGO}\\n'], 'algo')
        algo_text = machine_text(
            algo,
            limit=RPM_ALGO_MAX_BYTES,
            code='RPM_INVENTORY_FAILED',
            substage=substage,
            encoding='utf-8',
        )
        if algo_text != "8\n":
            raise_stream_error(
                code='RPM_INVENTORY_FAILED',
                message='SHA256 RPM file digests required',
                reason_token='algo-mismatch',
                receipt=algo,
                stream='stdout',
                substage=substage,
            )
        queries_ledger.append({
            'query': 'algo',
            'tool': 'rpm', 'substage': 'rpm-algo',
            'executed': algo.executed if algo is not None else False,
            'limit': RPM_ALGO_MAX_BYTES,
            'exit_code': algo.exit_code,
            'stdout_sha256': algo.stdout_sha256,
            'stderr_sha256': algo.stderr_sha256,
            'stdout_length': len(algo.stdout_bytes),
            'stderr_length': len(algo.stderr_bytes),
            'count': 1,
            'status': 'pass',
        })
    except Exception as exc:
        algo = getattr(exc, 'receipt', None) or algo
        queries_ledger.append({
            'query': 'algo',
            'tool': 'rpm', 'substage': 'rpm-algo',
            'executed': algo.executed if algo is not None else False,
            'limit': RPM_ALGO_MAX_BYTES,
            'exit_code': getattr(algo, "exit_code", None) if algo else None,
            'stdout_sha256': getattr(algo, "stdout_sha256", None) if algo else None,
            'stderr_sha256': getattr(algo, "stderr_sha256", None) if algo else None,
            'stdout_length': len(algo.stdout_bytes) if algo else 0,
            'stderr_length': len(algo.stderr_bytes) if algo else 0,
            'count': 0,
            'status': 'fail',
        })
        queries_ledger.append({
            'query': 'attrs', 'exit_code': None, 'stdout_sha256': None, 'stderr_sha256': None, 'stdout_length': 0, 'stderr_length': 0, 'count': 0, 'status': 'not-run',
        })
        diag = _build_inventory_diagnostic(queries_ledger, "fail")
        exc.inventory_diagnostic = diag
        if getattr(exc, 'receipt', None) is None:
            exc.receipt = algo
        raise exc

    # 3. Query: attrs
    attrs = None
    attributes = {}
    try:
        attrs = _query(
            runner,
            rpm_file,
            scratch,
            isolation,
            ['--queryformat', '[%{FILENAMES}|%{FILEINODES}|%{FILERDEVS}|%{FILEFLAGS}\\n]'],
            'attrs',
        )
        attr_records = machine_records(
            attrs,
            limit=RPM_QUERY_MAX_BYTES,
            code='RPM_INVENTORY_FAILED',
            substage=substage,
            encoding='utf-8',
        )
        if len(attr_records) > MAX_FILES:
            raise_stream_error(
                code='RPM_INVENTORY_FAILED',
                message='Malformed or excessive RPM dump',
                reason_token='attrs-count-exceeded',
                receipt=attrs,
                stream='stdout',
                substage=substage,
            )
        for line in attr_records:
            parts = line.split('|')
            if len(parts) != 4 or len(attributes) >= MAX_FILES:
                raise_stream_error(
                    code='RPM_INVENTORY_FAILED',
                    message='Malformed RPM inode metadata',
                    reason_token='malformed-attrs',
                    receipt=attrs,
                    stream='stdout',
                    substage=substage,
                )
            raw_path, inode_s, rdev_s, flags_s = parts
            try:
                path = package_path(raw_path)
            except ContractError:
                raise_stream_error(
                    code='RPM_INVENTORY_FAILED',
                    message='Malformed RPM inode member path',
                    reason_token='malformed-attrs-path',
                    receipt=attrs,
                    stream='stdout',
                    substage=substage,
                )
            if path in attributes:
                raise_stream_error(
                    code='RPM_INVENTORY_FAILED',
                    message='Malformed RPM inode metadata',
                    reason_token='duplicate-member',
                    receipt=attrs,
                    stream='stdout',
                    substage=substage,
                )
            if (
                not re.fullmatch(r'[0-9]{1,20}', inode_s, re.ASCII)
                or not re.fullmatch(r'[0-9]{1,20}', rdev_s, re.ASCII)
                or not re.fullmatch(r'[0-9]{1,20}', flags_s, re.ASCII)
            ):
                raise_stream_error(
                    code='RPM_INVENTORY_FAILED',
                    message='Malformed RPM inode metadata',
                    reason_token='malformed-attrs-number',
                    receipt=attrs,
                    stream='stdout',
                    substage=substage,
                )
            attributes[path] = dict(inode=int(inode_s), device=int(rdev_s), flags=int(flags_s))

        queries_ledger.append({
            'query': 'attrs',
            'tool': 'rpm', 'substage': 'rpm-attrs',
            'executed': attrs.executed if attrs is not None else False,
            'limit': RPM_QUERY_MAX_BYTES,
            'exit_code': attrs.exit_code,
            'stdout_sha256': attrs.stdout_sha256,
            'stderr_sha256': attrs.stderr_sha256,
            'stdout_length': len(attrs.stdout_bytes),
            'stderr_length': len(attrs.stderr_bytes),
            'count': len(attributes),
            'status': 'pass',
        })
    except Exception as exc:
        attrs = getattr(exc, 'receipt', None) or attrs
        queries_ledger.append({
            'query': 'attrs',
            'tool': 'rpm', 'substage': 'rpm-attrs',
            'executed': attrs.executed if attrs is not None else False,
            'limit': RPM_QUERY_MAX_BYTES,
            'exit_code': getattr(attrs, "exit_code", None) if attrs else None,
            'stdout_sha256': getattr(attrs, "stdout_sha256", None) if attrs else None,
            'stderr_sha256': getattr(attrs, "stderr_sha256", None) if attrs else None,
            'stdout_length': len(attrs.stdout_bytes) if attrs else 0,
            'stderr_length': len(attrs.stderr_bytes) if attrs else 0,
            'count': len(attributes),
            'status': 'fail',
        })
        diag = _build_inventory_diagnostic(queries_ledger, "fail")
        exc.inventory_diagnostic = diag
        if getattr(exc, 'receipt', None) is None:
            exc.receipt = attrs
        raise exc

    # Parse dump against attributes
    try:
        files = parse_dump(dump_records, attributes)
    except Exception as exc:
        diag = _build_inventory_diagnostic(queries_ledger, "fail")
        exc.inventory_diagnostic = diag
        exc.receipt = dump
        if isinstance(exc, ContractError):
            exc.details = safe_details({**exc.details,
                'reason_token': 'malformed-dump', 'tool': 'rpm',
                'exit_code': dump.exit_code, 'stdout_sha256': dump.stdout_sha256,
                'stderr_sha256': dump.stderr_sha256, 'diagnostic_token': 'dump',
                'size': len(dump.stdout_bytes)})
        raise exc

    # Diagnostic ledger for completed queries
    success_diag = _build_inventory_diagnostic(queries_ledger, "pass")

    # Non-query projection stage
    try:
        name = ctx['project_id']
        named_contracts = set()
        entry = (policy.get('projects', {}) if isinstance(policy, dict) else {}).get(name, {})
        named_contracts.update(entry.get('archive_contract_members', []))
        for code, rules in entry.get('exceptions', {}).items():
            if code != 'files-duplicated-waste' and isinstance(rules, dict):
                for rule in rules.values():
                    if isinstance(rule, dict):
                        if rule.get('caller_member'):
                            named_contracts.add(rule['caller_member'])
                        if rule.get('floor_source', {}).get('member'):
                            named_contracts.add(rule['floor_source']['member'])
        expected, manifest_sha, package = _archive_projection(
            ctx['asset_file'], ctx['asset_sha'], '/usr/lib/' + name, 'release', named_contracts
        )
        if manifest_sha != ctx['payload']['payload_manifest_sha256']:
            raise ContractError('INPUT_CHANGED', 'Authenticated payload member manifest mismatch')
        closure_sha = None
        if staged_nm is not None:
            closure = Path(staged_nm).parent / 'SOURCES/npm-closure.tar.gz'
            closure_sha = digest(closure.read_bytes())
            closure_expected, _, _ = _archive_projection(
                closure, closure_sha, '/usr/lib/' + name + '/node_modules', 'offline-npm'
            )
            if set(expected) & set(closure_expected) - {'/usr/lib/' + name + '/node_modules'}:
                raise ContractError('RPM_INVENTORY_FAILED', 'Conflicting authenticated input projections')
            expected.update(closure_expected)
        projections = {}
        for license_name in ('LICENSE', 'NOTICE'):
            source = '/usr/lib/' + name + '/' + license_name
            if source not in expected:
                raise ContractError('RPM_INVENTORY_FAILED', 'Required license input missing')
            target = '/usr/share/licenses/' + name + '/' + license_name
            expected[target] = dict(expected[source], path=target, mode=0o644, origin='license-projection')
            projections[target] = source
        wrappers = {}
        for cmd in cmds:
            path = '/usr/bin/' + cmd['name']
            target = '/usr/lib/' + name + '/' + cmd['path']
            if ctx.get('is_native_desktop'):
                expected[path] = {
                    'path': path,
                    'type': 'symlink',
                    'mode': 0o777,
                    'size': len(target),
                    'target': target,
                    'origin': 'maintained-launcher',
                }
            else:
                body = ('#!/bin/sh\nexec node "' + target + '" "$@"\n').encode()
                wrappers[path] = {'target': target, 'sha256': digest(body), 'mode': 0o755, 'type': 'file'}
                expected[path] = dict(wrappers[path], path=path, size=len(body), origin='maintained-launcher')
        if ctx.get('is_native_desktop'):
            sources = Path(scratch) / 'rpmbuild/SOURCES'
            for source, target in (
                (sources / (name + '.desktop'), '/usr/share/applications/' + name + '.desktop'),
                (sources / 'icon.png', '/usr/share/icons/hicolor/256x256/apps/' + name + '.png'),
            ):
                body = source.read_bytes()
                expected[target] = dict(
                    path=target,
                    type='file',
                    mode=0o644,
                    size=len(body),
                    sha256=digest(body),
                    origin='reviewed-desktop-projection',
                )
        permitted_directories = set()
        for path in expected:
            parent = posixpath.dirname(path)
            while parent.startswith('/usr'):
                permitted_directories.add(parent)
                parent = posixpath.dirname(parent)
        groups, waste = duplicate_groups(files)
    except Exception as exc:
        exc.receipt = None
        exc.inventory_diagnostic = success_diag
        raise exc

    return {
        'schema': INVENTORY_SCHEMA,
        'complete': True,
        'package_sha256': digest(Path(rpm_file).read_bytes()),
        'asset_sha256': ctx['asset_sha'],
        'payload_manifest_sha256': manifest_sha,
        'closure_sha256': closure_sha,
        'files': files,
        'expected': expected,
        'permitted_directories': sorted(permitted_directories),
        'license_projections': projections,
        'wrappers': wrappers,
        'contract_members': {p: r['content'] for p, r in expected.items() if 'content' in r},
        'engine_node': package.get('engines', {}).get('node'),
        'requires': list(requires),
        'duplicate_groups': groups,
        'calculated_duplicate_waste': waste,
        'possible_duplicate_waste_bytes': duplicate_waste_totals(groups),
        'inventory_diagnostic': success_diag,
        'receipts': queries_ledger,
        'client_runtime_evidence': client_runtime,
        'caller_evidence': caller_evidence,
    }, [dump, algo, attrs]
