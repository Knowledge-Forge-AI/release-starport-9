"""Structured rpmlint evidence, output parser, sanitizer, and cleanliness verification.

WP-RPM structured rpmlint evidence:
- Parses bounded safe findings (E, W, I) and summary from rpmlint output.
- Captures session headers, tool/package version/identity receipts.
- Preserves 4-field RPM identity (name, version, release, arch) and payload hash.
- Captures spec file SHA-256 and candidate RPM SHA-256.
- Fails closed on empty, malformed, or count-mismatched output.
- Never assumes exit-code meanings alone or green exit 64.
- Sanitizes paths, credentials, and control bytes; excludes raw command/private logs.
- Tool version query failure never replaces blamed lint receipt.
"""

from __future__ import annotations

from pathlib import Path
import re
from typing import Any, Mapping, Sequence

from rs9.build_native import CommandReceipt, CommandRunner
from rs9.errors import ContractError
from rs9.release_core import digest
from rs9.scratch import canonical
from rs9.security import scan_for_credentials, TOKEN_PATTERNS
from rs9.rpm_query import _safe_observed_token, RPM_EXPECTED_ARCHITECTURES

RPMLINT_EVIDENCE_SCHEMA = "rs9.rpmlint-evidence.v1alpha1"
MAX_FINDINGS = 100
MAX_MESSAGE_CHARS = 512
MAX_HEADER_CHARS = 256
MAX_HEADERS = 16
MAX_STREAM_BYTES = 512 * 1024

SUMMARY_REGEX = re.compile(
    r"^(?P<packages>\d+) packages? and (?P<specfiles>\d+) specfiles? checked; "
    r"(?P<errors>\d+) errors?, (?P<warnings>\d+) warnings?"
    r"(?:, (?P<filtered>\d+) filtered)?(?:, (?P<badness>\d+) badness)?"
    r"(?:; has taken [0-9.]+ s)?\.?$"
)
FINDING_REGEX = re.compile(
    r"^(?P<target>[^\s:]+?)(?::(?P<line>\d+))?:\s*(?:\[(?P<bracket_level>[EWI])\]|(?P<plain_level>[EWI]|ERROR|WARNING|INFO))\s*:\s*(?P<check>[A-Za-z0-9_.%+-]+)(?:\s+(?P<message>.*))?$"
)
MAX_GROUPS = 128


def sanitize_text(text, max_chars=MAX_MESSAGE_CHARS):
    """Public package paths only; withhold credentials/control streams before capping."""
    text = re.sub(r"\x1b\[[0-9;]*[a-zA-Z]", "", str(text))
    if any(c not in "\n\r\t" and not 32 <= ord(c) < 127 for c in text):
        return "[NONPRINTABLE]"
    for pattern in TOKEN_PATTERNS:
        text = pattern.sub("[REDACTED_CREDENTIAL]", text)
    text = re.sub(r"(?i)(?:bearer\s+|(?:password|token|secret|credential)\s*[:=]\s*)\S+", "[REDACTED_CREDENTIAL]", text)
    try:
        scan_for_credentials(text)
    except ContractError:
        return "[REDACTED_CREDENTIAL]"
    text = re.sub(r"(?:https?://|[A-Za-z]:\\|~/)[^\s]+", "[PATH]", text)
    def path(m):
        token = m.group()
        if token.startswith(('/usr/lib/theme-forge-', '/usr/bin/', '/usr/share/')):
            return 'package:' + token.lstrip('/')
        return '[PATH]'
    text = re.sub(r"(?<![A-Za-z0-9])/(?:[^\s:;,\"']+)", path, text)
    return re.sub(r"[\r\n\t]+", " ", text).strip()[:max_chars]


def _sanitize_target(raw_target: str) -> str:
    """Sanitize finding target (package name, spec file, or (none))."""
    raw_target = raw_target.strip()
    if raw_target == "(none)":
        return "(none)"
    # Strip any directory path prefix (e.g. /tmp/xyz/SPECS/foo.spec -> foo.spec)
    name = Path(raw_target).name
    if re.fullmatch(r"[A-Za-z0-9_.+-]+", name) and len(name) <= 128:
        return name
    return _safe_observed_token(name)


def parse_rpmlint_output(stdout_text, exit_code=0, *, strict=True):
    """rpmlint 2.x headers/findings/summary, with partial evidence on malformed output.

    Upstream Lint._print_header/_run defines the decorated session and summary;
    unknown nonempty lines are hashed and fail closed rather than hiding findings.
    """
    findings, headers, groups, unparsed, unparsed_samples = [], [], {}, [], []
    try:
        scan_for_credentials(stdout_text)
        sample_stream_safe = True
    except ContractError:
        sample_stream_safe = False
    counts = {'E':0,'W':0,'I':0}
    summary, summary_count, config = None, 0, False
    truncated = len(stdout_text.encode('utf-8',errors='replace')) > MAX_STREAM_BYTES
    for raw in stdout_text[:MAX_STREAM_BYTES].splitlines():
        line = re.sub(r"\x1b\[[0-9;]*[a-zA-Z]", "", raw).strip()
        if not line: continue
        decorated = line.strip('= ').strip()
        match=SUMMARY_REGEX.fullmatch(decorated)
        if match:
            summary_count+=1
            summary={k:int(v or 0) for k,v in match.groupdict().items()}
            config=False
            continue
        match=FINDING_REGEX.fullmatch(line)
        if match:
            config=False
            values=match.groupdict()
            level=values['bracket_level'] or values['plain_level']
            level={'ERROR':'E','WARNING':'W','INFO':'I'}.get(level,level)
            counts[level]+=1
            code=values['check']
            code=code if len(code)<=64 and sanitize_text(code)==code else digest(code.encode())
            target=_sanitize_target(values['target'])
            if sanitize_text(target)!=target: target=digest(target.encode())
            finding={'target':target,'level':level,'check':code,'message':sanitize_text(values['message'] or '',128)}
            if values['line']: finding['line']=min(int(values['line']),2**31-1)
            if len(findings)<MAX_FINDINGS:findings.append(finding)
            key=(level,code)
            if key not in groups and len(groups)<MAX_GROUPS:
                groups[key]={'severity':level,'code':code,'count':0,'samples':[]}
            if key in groups:
                groups[key]['count']+=1
                if len(groups[key]['samples'])<3:groups[key]['samples'].append(finding)
            else:truncated=True
            continue
        if (decorated == 'rpmlint session starts'
                or re.fullmatch(r'rpmlint(?::| version)? [0-9]+(?:\.[0-9]+)+(?:[-+][A-Za-z0-9.]+)?', decorated)
                or re.fullmatch(r'rpmlint \([A-Za-z0-9 ._-]{1,64}\)', decorated)
                or line.startswith(('Loaded configuration','Loading configuration','Checking:', 'checks:', 'rpmlintrc:'))
                or line=='configuration:' or re.fullmatch(r'Badness [0-9]+ exceeds threshold [0-9]+, aborting\.',line.strip('- '))):
            config=line=='configuration:'
            if len(headers)<MAX_HEADERS:headers.append(sanitize_text(line,MAX_HEADER_CHARS))
            continue
        if config and raw.startswith((' ','\t')) and line.startswith('/'):
            if len(headers)<MAX_HEADERS:headers.append('[CONFIG_PATH]')
            continue
        unparsed.append(digest(raw.encode()))
        if len(unparsed_samples) < 8:
            unparsed_samples.append({
                'sha256': unparsed[-1],
                'sample': sanitize_text(raw, 128) if sample_stream_safe else '[CREDENTIAL_STREAM_WITHHELD]',
            })
    reason=('empty-output' if not stdout_text.strip() else 'malformed-output' if not summary or summary_count!=1 or unparsed or truncated
            else 'count-mismatch' if counts['E']!=summary['errors'] or counts['W']!=summary['warnings'] else None)
    parsed={'findings':findings,'groups':[groups[k] for k in sorted(groups)],
            'findings_truncated':sum(counts.values())>len(findings),'summary':summary,
            'session_headers':headers,'counts':counts,'parse_complete':reason is None,
            'unparsed_count':len(unparsed),'unparsed_sha256':digest(canonical(unparsed)),
            'unparsed_samples':unparsed_samples,
            'reason_token':reason}
    if strict and reason:
        error=ContractError('RPMLINT_FAILED','rpmlint output incomplete or malformed',details={'reason_token':reason})
        error.parsed=parsed
        raise error
    return parsed


def evaluate_rpmlint_cleanliness(
    summary: dict[str, int],
    exit_code: int,
    *,
    allow_warnings: bool = True,
) -> tuple[bool, str]:
    """Evaluate cleanliness without assuming exit code alone or green exit 64.

    Returns (is_clean, reason_token).
    """
    if summary["errors"] > 0:
        return False, "lint-errors"

    if exit_code != 0:
        if exit_code == 64:
            return False, "lint-exit64"
        return False, "exit-nonzero"

    if summary["warnings"] > 0 and not allow_warnings:
        return False, "lint-warnings"

    return True, "clean"


def build_rpmlint_evidence(
    receipt: CommandReceipt,
    spec_path: str | Path,
    rpm_path: str | Path,
    product: str,
    *,
    rpm_identity: Mapping[str, str] | None = None,
    rpm_payload_digest: Mapping[str, Any] | None = None,
    tool_version_info: dict[str, Any] | None = None,
    allow_warnings: bool = True,
) -> dict[str, Any]:
    """Construct structured rpmlint evidence record preserving identities and hashes."""
    spec_path = Path(spec_path)
    rpm_path = Path(rpm_path)

    spec_sha256 = digest(spec_path.read_bytes()) if spec_path.is_file() else ""
    package_sha256 = digest(rpm_path.read_bytes()) if rpm_path.is_file() else ""

    parsed = parse_rpmlint_output(receipt.stdout_text, exit_code=receipt.exit_code, strict=False)
    if parsed["parse_complete"] and (parsed["summary"]["packages"] != 1 or parsed["summary"]["specfiles"] != 1):
        parsed.update(parse_complete=False, reason_token="input-count-mismatch")
    summary = parsed["summary"] or {
        "packages": 0, "specfiles": 0, "filtered": 0,
        "errors": parsed["counts"]["E"], "warnings": parsed["counts"]["W"],
    }
    findings = parsed["findings"]
    session_headers = parsed["session_headers"]
    findings_truncated = parsed["findings_truncated"]

    is_clean, reason_token = evaluate_rpmlint_cleanliness(
        summary, receipt.exit_code, allow_warnings=allow_warnings
    )

    if not parsed["parse_complete"]:
        is_clean, reason_token = False, parsed["reason_token"]

    # Preserve supported 4-field identity: name, version, release, arch
    identity_record = None
    if rpm_identity is not None:
        identity_record = {
            "name": rpm_identity.get("name", product),
            "version": rpm_identity.get("version", ""),
            "release": rpm_identity.get("release", ""),
            "arch": rpm_identity.get("arch", ""),
        }

    # Preserve payload hash
    payload_record = dict(rpm_payload_digest) if rpm_payload_digest is not None else None

    evidence: dict[str, Any] = {
        "schema": RPMLINT_EVIDENCE_SCHEMA,
        "product": product,
        "package_file": rpm_path.name,
        "package_sha256": package_sha256,
        "spec_file": spec_path.name,
        "spec_sha256": spec_sha256,
        "clean": is_clean,
        "status": "pass" if is_clean else "fail",
        "reason_token": reason_token,
        "tool_receipt": {
            "tool": "rpmlint",
            "exit_code": receipt.exit_code,
            "stdout_sha256": receipt.stdout_sha256,
            "stderr_sha256": receipt.stderr_sha256,
            "stdout_bytes": len(receipt.stdout_bytes),
            "stderr_bytes": len(receipt.stderr_bytes),
        },
        "session_headers": session_headers,
        "findings": findings,
        "findings_truncated": findings_truncated,
        "groups": parsed["groups"], "parse_complete": parsed["parse_complete"],
        "unparsed_count": parsed["unparsed_count"], "unparsed_sha256": parsed["unparsed_sha256"],
        "unparsed_samples": parsed["unparsed_samples"],
        "architecture": (rpm_identity or {}).get("arch"),
        "arguments": [spec_path.name, rpm_path.name],
        "findings_summary": {
            "packages": summary["packages"],
            "specfiles": summary["specfiles"],
            "errors": summary["errors"],
            "warnings": summary["warnings"],
            "information": parsed["counts"]["I"],
            "filtered": summary["filtered"],
        },
    }

    if identity_record is not None:
        evidence["rpm_identity"] = identity_record
    if payload_record is not None:
        evidence["rpm_payload_digest"] = payload_record
    if tool_version_info is not None:
        evidence["tool_version"] = tool_version_info

    # Preserve all severity/code counts while bounding samples and headers.
    if len(canonical(evidence)) > 60 * 1024:
        evidence['findings']=[{k:v for k,v in f.items() if k!='message'} for f in evidence['findings']]
        for g in evidence['groups']:g['samples']=[]
        evidence['diagnostic_truncated']=True
    if len(canonical(evidence)) > 60 * 1024:
        raise ContractError('RPMLINT_FAILED','Lint evidence exceeded bound')
    scan_for_credentials(canonical(evidence).decode())
    return evidence


def execute_rpmlint(
    runner: CommandRunner,
    spec_path: str | Path,
    rpm_path: str | Path,
    product: str,
    *,
    rpm_identity: Mapping[str, str] | None = None,
    rpm_payload_digest: Mapping[str, Any] | None = None,
    cwd: str | Path | None = None,
    allow_warnings: bool = True,
) -> tuple[dict[str, Any], list[CommandReceipt]]:
    """Execute real rpmlint against spec and candidate package, building structured evidence.

    Fails closed with ContractError('RPMLINT_FAILED', ...) on errors, non-zero exit,
    count mismatch, empty output, or malformed streams.
    Tool version query failure is recorded without replacing blamed lint receipt.
    """
    spec_path = Path(spec_path)
    rpm_path = Path(rpm_path)

    # 1. Query tool version if available, but version query failure must NOT replace blamed lint receipt
    version_info: dict[str, Any] | None = None
    try:
        v_receipt = runner.run(["rpmlint", "--version"], cwd=cwd)
        if v_receipt.exit_code == 0:
            version_info = {
                "version": sanitize_text(v_receipt.stdout_text.strip(), 128),
                "stdout_sha256": v_receipt.stdout_sha256,
                "exit_code": 0,
            }
        else:
            version_info = {
                "version": "query-failed",
                "exit_code": v_receipt.exit_code,
                "stdout_sha256": v_receipt.stdout_sha256,
            }
    except Exception:
        version_info = {"version": "query-unavailable"}

    try:
        package_version = runner.run(['rpm','-q','--qf','%{NAME}|%{VERSION}|%{RELEASE}|%{ARCH}\\n','rpmlint'],cwd=cwd)
        version_info['package_query']={'exit_code':package_version.exit_code,
            'stdout_sha256':package_version.stdout_sha256,'stderr_sha256':package_version.stderr_sha256,
            'version':sanitize_text(package_version.stdout_text,128) if package_version.exit_code==0 else 'query-failed'}
    except (ContractError,OSError):
        version_info['package_query']={'status':'unavailable'}

    # 2. Execute rpmlint
    rpmlint_cmd = ["rpmlint", str(spec_path), str(rpm_path)]
    receipt = runner.run(rpmlint_cmd, cwd=cwd)

    version_info['tool_identity_sha256']=digest((receipt.tool_path or receipt.tool_name or 'rpmlint').encode())
    version_info['tool']='rpmlint'

    # 3. Build evidence (handles parsing, sanitization, count validation)
    try:
        evidence = build_rpmlint_evidence(receipt,spec_path,rpm_path,product,rpm_identity=rpm_identity,
            rpm_payload_digest=rpm_payload_digest,tool_version_info=version_info,allow_warnings=allow_warnings)
    except ContractError as error:
        # Collection failure is still a lint failure with quarantinable bytes.
        err = ContractError("RPMLINT_FAILED", "Candidate RPM lint evidence collection failed", details={
            **error.details, "substage": "rpmlint", "tool": "rpmlint", "product": product,
            "exit_code": receipt.exit_code, "stdout_sha256": receipt.stdout_sha256,
            "stderr_sha256": receipt.stderr_sha256})
        err.package_path, err.spec_path = str(rpm_path), str(spec_path)
        for name, path in (("package", rpm_path), ("spec", spec_path)):
            try:
                value = digest(path.read_bytes())
            except OSError:
                value = ""
            setattr(err, name + "_sha256", value)
        raise err from None
    (Path(cwd) if cwd else spec_path.parent).joinpath('rpmlint-findings.json').write_bytes(canonical(evidence))

    # 4. Check cleanliness
    if not evidence["clean"]:
        findings = evidence["findings"]
        primary_check = findings[0]["check"] if findings else evidence["reason_token"]
        details = {
            "substage": "rpmlint",
            "tool": "rpmlint",
            "exit_code": receipt.exit_code,
            "stdout_sha256": receipt.stdout_sha256,
            "stderr_sha256": receipt.stderr_sha256,
            "product": product,
            "sha256": evidence["package_sha256"],
            "observed_field_count": len(findings),
            "observed_field_tokens": [_safe_observed_token(f["check"]) for f in findings[:6]],
            "diagnostic_token": _safe_observed_token(primary_check),
            "reason_token": evidence["reason_token"],
        }
        err = ContractError(
            "RPMLINT_FAILED",
            f"Candidate RPM did not pass rpmlint: {primary_check}",
            details=details,
        )
        err.evidence = evidence
        err.package_path = str(rpm_path)
        err.spec_path = str(spec_path)
        err.spec_sha256 = evidence["spec_sha256"]
        err.package_sha256 = evidence["package_sha256"]
        raise err

    return evidence, [receipt]
