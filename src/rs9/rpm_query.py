"""Closed capability-bound RPM identity and compressed payload SHA256 readback.

PAYLOADSHA256 is compressed payload; ALT is uncompressed and never selected.
RPM 4.x called it PAYLOADDIGEST. See rpm.org 6.0 signatures_digests manual.
PGPHASHALGO_SHA256 = 8 is verified against upstream include/rpm/rpmpgp.h.
Whole-package SHA256 remains separate from these payload values.
"""
from pathlib import Path
import re

from rs9.errors import ContractError
from rs9.release_core import digest

RPM_EXPECTED_ARCHITECTURES = frozenset({'noarch', 'x86_64', 'aarch64'})
PGPHASHALGO_SHA256 = 8
RPM_CLOSED_QUERYTAGS = {
    'rpm6': {'digest_tag': 'PAYLOADSHA256', 'algo_tag': 'PAYLOADSHA256ALGO'},
    'legacy': {'digest_tag': 'PAYLOADDIGEST', 'algo_tag': 'PAYLOADDIGESTALGO'},
}
IDENTITY_QUERYFORMAT = '%{NAME}|%{VERSION}|%{RELEASE}|%{ARCH}\n'
UPLOADED_PAYLOADDIGEST_ERROR_STDERR = 'error: incorrect format: unknown tag: "PAYLOADDIGEST"\n'
UPLOADED_PAYLOADDIGEST_ERROR_SHA256 = '7d9d1aa567137d6c38111fd189312572c041a32da954bfa55fa8bf8b3f36ddd8'


def rpm_isolation_args(*, dbpath=None, keyring=None, keyringpath=None):
    """Build isolated RPM 6 keyring and dbpath CLI arguments."""
    args = []
    if dbpath is not None:
        args.extend(['--dbpath', str(dbpath), '--define', f'_dbpath {dbpath}'])
    if keyring is not None:
        args.extend(['--define', f'_keyring {keyring}', '--define', '_pkgverify_flags 0', '--define', '_vsflags_query 0'])
    if keyringpath is not None:
        args.extend(['--define', f'_keyringpath {keyringpath}'])
    return args


def _safe_observed_token(value):
    if not value or not isinstance(value, str):
        return ''
    return value if value not in {'.', '..'} and len(value) <= 64 and re.fullmatch(r'[A-Za-z0-9_.+-]+', value) else digest(value.encode('utf-8', errors='replace'))


def _details(receipt, substage='rpm-query', product=None):
    result = {'substage': substage, 'tool': 'rpm', 'exit_code': receipt.exit_code,
              'stdout_sha256': receipt.stdout_sha256, 'stderr_sha256': receipt.stderr_sha256}
    if product is not None:
        result['product'] = product
    return result


def check_query_receipt(receipt, substage='rpm-query', tool='rpm', product=None, limit=4096):
    details = {**_details(receipt, substage, product), 'tool': tool}
    if (receipt.exit_code != 0 or not receipt.stdout_bytes
            or len(receipt.stdout_bytes) > limit or bool(receipt.stderr_bytes)):
        raise ContractError('RPM_QUERY_FAILED', 'RPM query failed or returned invalid streams', details=details)


def _fields(receipt, count, product=None):
    raw = receipt.stdout_text
    line = raw.removesuffix('\n')
    fields = line.split('|', count)
    details = {**_details(receipt, product=product), 'observed_field_count': line.count('|') + 1,
               'observed_field_tokens': [_safe_observed_token(v) for v in fields[:count]],
               'observed_fields_truncated': len(fields) > count}
    if count == 4:
        details['observed_architecture'] = _safe_observed_token(fields[3]) if len(fields) >= 4 else ''
    try:
        check_query_receipt(receipt, product=product)
    except ContractError as error:
        raise ContractError(error.code, error.message, details=details) from None
    if (not raw.endswith('\n') or len(fields) != count or any(not v or v == '(none)' or '\n' in v or '\r' in v for v in fields)):
        raise ContractError('RPM_QUERY_FAILED', 'Expected one bounded RPM query record', details=details)
    return fields, details


def read_rpm_identity(receipt, product=None, version=None, architecture=None, revision=None, dist='fc43', expected_release=None):
    fields, details = _fields(receipt, 4, product)
    name, observed_version, release, arch = fields
    details['observed_architecture'] = _safe_observed_token(arch)
    for code, observed, expected in (('INVALID_NAME', name, product), ('INVALID_VERSION', observed_version, version),
                                     ('INVALID_ARCHITECTURE', arch, architecture)):
        if expected is not None and observed != expected:
            raise ContractError(code, 'RPM identity differs from intended package', details={**details, 'diagnostic_token': _safe_observed_token(observed)})
    if any(re.fullmatch(r'[A-Za-z0-9_.+-]+', v) is None for v in fields):
        raise ContractError('RPM_QUERY_FAILED', 'Malformed identity token', details=details)
    if arch not in RPM_EXPECTED_ARCHITECTURES:
        raise ContractError('INVALID_ARCHITECTURE', 'Unsupported RPM architecture', details={**details, 'diagnostic_token': arch})
    if re.fullmatch(r'[0-9]+(?:\.[A-Za-z0-9_]+)*', release) is None:
        raise ContractError('INVALID_RELEASE', 'Malformed RPM release', details=details)
    if expected_release is not None:
        release_ok = release == expected_release
    else:
        # Parser-only fixtures may exercise plain and distro releases. Actual
        # builds supply the exact macro expansion below.
        base = str(revision) if revision is not None else release.split('.', 1)[0]
        release_ok = release in {base, base + '.' + dist.lstrip('.')}
    if not release_ok:
        raise ContractError('INVALID_RELEASE', 'RPM release differs from builder expansion', details={**details, 'diagnostic_token': _safe_observed_token(release)})
    return dict(zip(('name', 'version', 'release', 'arch'), fields))


def select_payload_capability(runner, cwd=None, *, dbpath=None, keyring=None, keyringpath=None):
    cmd = ['rpm'] + rpm_isolation_args(dbpath=dbpath, keyring=keyring, keyringpath=keyringpath) + ['--querytags']
    receipt = runner.run(cmd, cwd=cwd)
    check_query_receipt(receipt, substage='rpm-query-capability', limit=64 * 1024)
    try:
        lines = receipt.stdout_bytes.decode('ascii').splitlines()
    except UnicodeError:
        raise ContractError('RPM_PAYLOAD_DIGEST_UNSUPPORTED', 'Malformed tag capability output') from None
    if not lines or any(re.fullmatch(r'[A-Z][A-Z0-9_]*', v) is None for v in lines) or len(lines) != len(set(lines)):
        raise ContractError('RPM_PAYLOAD_DIGEST_UNSUPPORTED', 'Malformed tag capability output')
    for name, row in RPM_CLOSED_QUERYTAGS.items():
        if {row['digest_tag'], row['algo_tag']} <= set(lines):
            return name, receipt
    raise ContractError('RPM_PAYLOAD_DIGEST_UNSUPPORTED', 'No supported compressed SHA256 payload capability',
                        details=_details(receipt, 'rpm-query-capability'))


def read_rpm_payload_digest(receipt, capability='rpm6', product=None):
    fields, details = _fields(receipt, 2, product)
    if capability not in RPM_CLOSED_QUERYTAGS:
        raise ContractError('UNSUPPORTED_CAPABILITY', 'Digest source is outside the closed table', details=details)
    value, algorithm = fields
    if re.fullmatch(r'[0-9a-f]{64}', value) is None:
        raise ContractError('INVALID_DIGEST', 'Expected exactly one lowercase SHA256 payload digest', details=details)
    if algorithm != '8':
        raise ContractError('INVALID_ALGORITHM', 'Payload algorithm differs from SHA256 numeric identifier', details=details)
    row = RPM_CLOSED_QUERYTAGS[capability]
    return {'tag': row['digest_tag'], 'algo_tag': row['algo_tag'], 'scope': 'compressed-payload',
            'digest': value, 'payload_digest': value, 'algorithm': 'sha256', 'payload_digest_algo': 'sha256',
            'algorithm_numeric': 8, 'capability': capability}


def query_rpm_identity(
    runner,
    rpm_path,
    product=None,
    version=None,
    architecture=None,
    revision=None,
    dist='fc43',
    cwd=None,
    expected_release=None,
    *,
    dbpath=None,
    keyring=None,
    keyringpath=None,
):
    cmd = ['rpm'] + rpm_isolation_args(dbpath=dbpath, keyring=keyring, keyringpath=keyringpath) + ['-qp', '--queryformat', IDENTITY_QUERYFORMAT, str(rpm_path)]
    receipt = runner.run(cmd, cwd=cwd)
    return read_rpm_identity(receipt, product, version, architecture, revision, dist, expected_release), receipt


def query_rpm_payload_digest(runner, rpm_path, capability=None, product=None, cwd=None, *, dbpath=None, keyring=None, keyringpath=None):
    selected, discovery = select_payload_capability(runner, cwd, dbpath=dbpath, keyring=keyring, keyringpath=keyringpath)
    if capability is not None and capability != selected:
        raise ContractError('RPM_PAYLOAD_DIGEST_UNSUPPORTED', 'Requested digest source differs from observed capabilities')
    return _query_payload(runner, rpm_path, selected, discovery, product, cwd, dbpath=dbpath, keyring=keyring, keyringpath=keyringpath)


def _query_payload(runner, rpm_path, selected, discovery, product, cwd, *, dbpath=None, keyring=None, keyringpath=None):
    row = RPM_CLOSED_QUERYTAGS[selected]
    fmt = '%{' + row['digest_tag'] + '}|%{' + row['algo_tag'] + '}\n'
    cmd = ['rpm'] + rpm_isolation_args(dbpath=dbpath, keyring=keyring, keyringpath=keyringpath) + ['-qp', '--queryformat', fmt, str(rpm_path)]
    receipt = runner.run(cmd, cwd=cwd)
    payload = read_rpm_payload_digest(receipt, selected, product)
    payload['querytags_sha256'] = discovery.stdout_sha256
    return payload, receipt


def query_rpm_package(
    runner,
    rpm_path,
    product=None,
    version=None,
    architecture=None,
    revision=None,
    dist='fc43',
    capability=None,
    cwd=None,
    *,
    dbpath=None,
    keyring=None,
    keyringpath=None,
):
    expected_release = None
    release_receipt = None
    if revision is not None:
        cmd = ['rpm'] + rpm_isolation_args(dbpath=dbpath, keyring=keyring, keyringpath=keyringpath) + ['--eval', str(revision) + '%{?dist}']
        release_receipt = runner.run(cmd, cwd=cwd)
        check_query_receipt(release_receipt, substage='rpm-query-release', limit=128)
        expected_release = release_receipt.stdout_text.removesuffix('\n')
        if not release_receipt.stdout_text.endswith('\n') or re.fullmatch(re.escape(str(revision)) + r'(?:\.[A-Za-z0-9_]+)*', expected_release) is None:
            raise ContractError('INVALID_RELEASE', 'Malformed builder release expansion')
    identity, ident_receipt = query_rpm_identity(
        runner, rpm_path, product, version, architecture, revision, dist, cwd, expected_release,
        dbpath=dbpath, keyring=keyring, keyringpath=keyringpath
    )
    selected, discovery = select_payload_capability(runner, cwd, dbpath=dbpath, keyring=keyring, keyringpath=keyringpath)
    if capability is not None and capability != selected:
        raise ContractError('RPM_PAYLOAD_DIGEST_UNSUPPORTED', 'Requested digest source differs from observed capabilities')
    payload, payload_receipt = _query_payload(
        runner, rpm_path, selected, discovery, product, cwd,
        dbpath=dbpath, keyring=keyring, keyringpath=keyringpath
    )
    return identity, payload, [r for r in (release_receipt, ident_receipt, discovery, payload_receipt) if r is not None]


def verify_primary_rpm_source_algorithm(source_path=None):
    """Explicit bounded source-fixture check; runtime needs no development headers."""
    if source_path is None or not Path(source_path).is_file():
        return False
    raw = Path(source_path).read_bytes()
    if len(raw) > 512 * 1024 or re.search(rb'PGPHASHALGO_SHA256\s*(?:=\s*|\s+)(8)\b', raw) is None:
        raise ContractError('ALGORITHM_MISMATCH', 'Explicit RPM source does not confirm SHA256 identifier')
    return True
