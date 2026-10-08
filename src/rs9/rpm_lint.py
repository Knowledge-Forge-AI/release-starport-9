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

import json
from pathlib import Path
import re
from typing import Any, Mapping, Sequence

from rs9.build_native import CommandReceipt, CommandRunner
from rs9.errors import ContractError
from rs9.release_core import digest
from rs9.scratch import canonical
from rs9.security import scan_for_credentials, TOKEN_PATTERNS
from rs9.rpm_query import _safe_observed_token, RPM_EXPECTED_ARCHITECTURES

from rs9.machine_stream import machine_records, machine_text, raise_stream_error

RPMLINT_EVIDENCE_SCHEMA = "rs9.rpmlint-evidence.v1alpha1"
MAX_FINDINGS = 100
MAX_MESSAGE_CHARS = 512
MAX_HEADER_CHARS = 256
MAX_HEADERS = 16
MAX_STREAM_BYTES = 512 * 1024
RPMLINT_IDENTITY_MAX_BYTES = 1024


def _tool_identity_record(receipt, *, package=False):
    """Read one ASCII identity record; diagnostic previews never supply identity."""
    if receipt.stderr_bytes:
        raise_stream_error(code='RPMLINT_FAILED', message='Tool identity query returned stderr',
            reason_token='stderr-not-empty', receipt=receipt, stream='stderr',
            substage='rpmlint-tool-identity')
    records = machine_records(receipt, limit=RPMLINT_IDENTITY_MAX_BYTES,
        code='RPMLINT_FAILED', substage='rpmlint-tool-identity', encoding='ascii')
    pattern = (r'rpmlint\|[A-Za-z0-9._+~-]{1,64}\|[A-Za-z0-9._+~-]{1,64}\|[A-Za-z0-9_]{1,32}'
               if package else r'(?:rpmlint )?[0-9]+(?:\.[0-9]+)+(?:[-+][A-Za-z0-9._-]+)?')
    if len(records) != 1 or not re.fullmatch(pattern, records[0], re.ASCII):
        raise_stream_error(code='RPMLINT_FAILED', message='Malformed tool identity record',
            reason_token='malformed-identity', receipt=receipt, stream='stdout',
            substage='rpmlint-tool-identity')
    scan_for_credentials(records[0])
    return records[0]


def _tool_identity_evidence(receipt, *, package=False):
    identity = {'exit_code': receipt.exit_code,
                'stdout_sha256': receipt.stdout_sha256, 'stderr_sha256': receipt.stderr_sha256,
                'stdout_length': len(receipt.stdout_bytes), 'stderr_length': len(receipt.stderr_bytes)}
    if receipt.exit_code != 0:
        identity.update(version='query-failed', reason_token='process-nonzero')
        return identity
    try:
        identity['version'] = _tool_identity_record(receipt, package=package)
    except ContractError as error:
        identity.update(version='query-invalid', reason_token=error.details.get('reason_token', 'unsafe-identity'))
    return identity

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
MAX_ERROR_RECORDS = 256


def _parse_error_record(
    target: str,
    code: str,
    raw_message: str,
    line_no: int | None = None,
) -> dict[str, Any]:
    """Parse complete structured error record before 128-char message truncation."""
    raw = raw_message or ""
    tokens = raw.split()
    complete = (len(raw) <= 4096 and len(target) <= 128 and len(code) <= 64
                and all(32 <= ord(c) < 127 for c in raw))
    record = {"target": target, "code": code, "level": "E",
              "message": sanitize_text(raw, 512), "arguments_sha256": digest(raw.encode()),
              "arguments_complete": complete}
    if line_no is not None: record["line"] = line_no
    if code in {"non-executable-script", "env-script-interpreter"}:
        path = tokens[0] if tokens else ""
        if path.startswith("package:usr/"): path = "/" + path[len("package:"):]
        from rs9.rpm_preservation import package_path
        try: record["path"] = package_path(path)
        except ContractError: record["arguments_complete"] = False
        offset = 1
        if code == "non-executable-script":
            if len(tokens)>1 and re.fullmatch("[0-7]{3,4}",tokens[1]): record["mode"] = tokens[1]
            else: record["arguments_complete"] = False
            offset = 2
        interpreter = " ".join(tokens[offset:]).replace("package:usr/", "/usr/")
        if len(interpreter) <= 256 and re.fullmatch(r"/(?:usr/)?bin/[A-Za-z0-9_./+-]+(?: [A-Za-z0-9_./+-]+)*",interpreter):
            record["interpreter"] = interpreter
        else: record["arguments_complete"] = False
    elif code == "files-duplicated-waste":
        if len(tokens)==1 and tokens[0].isdigit() and len(tokens[0])<=20: record["waste_bytes"] = int(tokens[0])
        else: record["arguments_complete"] = False
    elif code == "explicit-lib-dependency":
        if len(tokens)==1 and re.fullmatch(r"[A-Za-z0-9_.+-]{1,128}",tokens[0]): record["dependency"] = tokens[0]
        else: record["arguments_complete"] = False
    return record


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
    name = Path(raw_target).name
    if re.fullmatch(r"[A-Za-z0-9_.+-]+", name) and len(name) <= 128:
        return name
    return _safe_observed_token(name)


def parse_rpmlint_output(stdout_text, exit_code=0, *, strict=True):
    """rpmlint 2.x headers/findings/summary, with partial evidence on malformed output.

    Upstream Lint._print_header/_run defines the decorated session and summary;
    unknown nonempty lines are hashed and fail closed rather than hiding findings.
    Parses complete structured error_records from raw lines before capping.
    Warnings are dropped first when bounding findings; missing/overflow errors never hidden.
    """
    error_findings, warning_findings, info_findings = [], [], []
    error_records = []
    error_overflow = False
    headers, groups, unparsed, unparsed_samples = [], {}, [], []
    try:
        scan_for_credentials(stdout_text)
        sample_stream_safe = True
    except ContractError:
        sample_stream_safe = False
    counts = {"E": 0, "W": 0, "I": 0}
    summary, summary_count, config = None, 0, False
    truncated = len(stdout_text.encode('utf-8')) > MAX_STREAM_BYTES
    replacement_detected = '\ufffd' in stdout_text
    lines = stdout_text[:MAX_STREAM_BYTES].split('\n')

    for raw in lines:
        line = re.sub(r"\x1b\[[0-9;]*[a-zA-Z]", "", raw).strip()
        if not line:
            continue
        if summary_count > 0:
            unparsed.append(digest(raw.encode("utf-8", errors="replace")))
            if len(unparsed_samples) < 8:
                unparsed_samples.append({
                    "sha256": unparsed[-1],
                    "sample": sanitize_text(raw, 128) if sample_stream_safe else "[CREDENTIAL_STREAM_WITHHELD]",
                })
            continue

        decorated = line.strip("= ").strip()
        match = SUMMARY_REGEX.fullmatch(decorated)
        if match:
            summary_count += 1
            summary = {k: int(v or 0) for k, v in match.groupdict().items()}
            config = False
            continue
        match = FINDING_REGEX.fullmatch(line)
        if match:
            config = False
            values = match.groupdict()
            level = values["bracket_level"] or values["plain_level"]
            level = {"ERROR": "E", "WARNING": "W", "INFO": "I"}.get(level, level)
            counts[level] += 1
            code = values["check"]
            code = code if len(code) <= 64 and sanitize_text(code) == code else digest(code.encode())
            target = _sanitize_target(values["target"])
            if sanitize_text(target) != target:
                target = digest(target.encode())
            finding = {"target": target, "level": level, "check": code, "message": sanitize_text(values["message"] or "", 128)}
            line_no = None
            if values["line"]:
                line_no = min(int(values["line"]), 2**31 - 1)
                finding["line"] = line_no

            if level == "E":
                if len(error_records) < MAX_ERROR_RECORDS:
                    rec = _parse_error_record(target, code, values["message"] or "", line_no)
                    error_records.append(rec)
                    if not rec["arguments_complete"]:
                        error_overflow = True
                else:
                    error_overflow = True
                error_findings.append(finding)
            elif level == "W":
                warning_findings.append(finding)
            else:
                info_findings.append(finding)

            key = (level, code)
            if key not in groups and len(groups) < MAX_GROUPS:
                groups[key] = {"severity": level, "code": code, "count": 0, "samples": []}
            if key in groups:
                groups[key]["count"] += 1
                if len(groups[key]["samples"]) < 3:
                    groups[key]["samples"].append(finding)
            else:
                truncated = True
            continue
        if (decorated == "rpmlint session starts"
                or re.fullmatch(r"rpmlint(?::| version)? [0-9]+(?:\.[0-9]+)+(?:[-+][A-Za-z0-9.]+)?", decorated)
                or re.fullmatch(r"rpmlint \([A-Za-z0-9 ._-]{1,64}\)", decorated)
                or line.startswith(("Loaded configuration", "Loading configuration", "Checking:", "checks:", "rpmlintrc:"))
                or line == "configuration:" or re.fullmatch(r"Badness [0-9]+ exceeds threshold [0-9]+, aborting\.", line.strip("- "))):
            config = line == "configuration:"
            if len(headers) < MAX_HEADERS:
                headers.append(sanitize_text(line, MAX_HEADER_CHARS))
            continue
        if config and raw.startswith((" ", "\t")) and line.startswith("/"):
            if len(headers) < MAX_HEADERS:
                headers.append("[CONFIG_PATH]")
            continue
        unparsed.append(digest(raw.encode("utf-8", errors="replace")))
        if len(unparsed_samples) < 8:
            unparsed_samples.append({
                "sha256": unparsed[-1],
                "sample": sanitize_text(raw, 128) if sample_stream_safe else "[CREDENTIAL_STREAM_WITHHELD]",
            })

    if replacement_detected and len(unparsed_samples) < 8:
        rep_hash = digest(b"[REPLACEMENT_CHARACTER]")
        unparsed.append(rep_hash)
        unparsed_samples.append({
            "sha256": rep_hash,
            "sample": "[REPLACEMENT_CHARACTER_DETECTED]",
        })

    # Prioritize errors into findings; warnings are dropped first when bounding
    findings = list(error_findings[:MAX_FINDINGS])
    remaining_slots = MAX_FINDINGS - len(findings)
    if remaining_slots > 0:
        findings.extend(warning_findings[:remaining_slots])
        remaining_slots = MAX_FINDINGS - len(findings)
        if remaining_slots > 0:
            findings.extend(info_findings[:remaining_slots])

    reason = (
        "empty-output" if not stdout_text.strip()
        else "error-overflow" if error_overflow
        else "malformed-output" if (
            not summary
            or summary_count != 1
            or unparsed
            or truncated
            or replacement_detected
        )
        else "count-mismatch" if counts["E"] != summary["errors"] or counts["W"] != summary["warnings"]
        else None
    )
    parsed = {
        "findings": findings,
        "groups": [groups[k] for k in sorted(groups)],
        "findings_truncated": sum(counts.values()) > len(findings),
        "summary": summary,
        "session_headers": headers,
        "counts": counts,
        "parse_complete": reason is None,
        "unparsed_count": len(unparsed),
        "unparsed_sha256": digest(canonical(unparsed)),
        "unparsed_samples": unparsed_samples,
        "reason_token": reason,
        "error_records": error_records,
        "error_overflow": error_overflow,
    }
    if strict and reason:
        error = ContractError("RPMLINT_FAILED", "rpmlint output incomplete or malformed", details={"reason_token": reason})
        error.parsed = parsed
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

    spec_sha256 = ""
    try:
        if spec_path.is_file():
            spec_sha256 = digest(spec_path.read_bytes())
    except OSError:
        pass

    package_sha256 = ""
    try:
        if rpm_path.is_file():
            package_sha256 = digest(rpm_path.read_bytes())
    except OSError:
        pass

    stdout_raw = getattr(receipt, "stdout_bytes", b"")
    stderr_raw = getattr(receipt, "stderr_bytes", b"")
    stdout_hash = getattr(receipt, "stdout_sha256", digest(stdout_raw))
    stderr_hash = getattr(receipt, "stderr_sha256", digest(stderr_raw))

    reader_error = None
    reason_token = None
    try:
        stdout_text = machine_text(
            receipt,
            stream="stdout",
            limit=MAX_STREAM_BYTES,
            code="RPMLINT_FAILED",
            substage="rpmlint",
            encoding="utf-8",
        )
    except ContractError as err:
        reader_error = err
        reason_token = err.details.get("reason_token", "malformed-output")
        stdout_text = None

    if reader_error is None and stdout_raw and not stdout_raw.endswith(b"\n"):
        reason_token = "malformed-output"
        reader_error = ContractError(
            "RPMLINT_FAILED",
            "rpmlint stream missing newline framing",
            details={"reason_token": reason_token},
        )

    if reader_error is not None:
        unparsed_samples = [{
            "sha256": stdout_hash,
            "sample": f"[NON_ACCEPTANCE_STREAM_ERROR:{reason_token}]",
        }]
        evidence: dict[str, Any] = {
            "schema": RPMLINT_EVIDENCE_SCHEMA,
            "product": product,
            "package_file": rpm_path.name,
            "package_sha256": package_sha256,
            "spec_file": spec_path.name,
            "spec_sha256": spec_sha256,
            "clean": False,
            "status": "fail",
            "reason_token": reason_token,
            "tool_receipt": {
                "tool": "rpmlint",
                "executed": getattr(receipt, "executed", False),
                "command": ["rpmlint", spec_path.name, rpm_path.name],
                "command_sha256": digest(canonical(list(getattr(receipt, "command", [])))),
                "exit_code": getattr(receipt, "exit_code", -1),
                "stdout_sha256": stdout_hash,
                "stderr_sha256": stderr_hash,
                "stdout_bytes": len(stdout_raw),
                "stderr_bytes": len(stderr_raw),
            },
            "session_headers": [],
            "effective_configuration": {
                "listing_sha256": digest(canonical([])),
                "session_header_sha256": digest(canonical([])),
                "filtered_count": 0,
                "invocation": "default-tool-config-no-added-filters",
            },
            "findings": [],
            "findings_truncated": False,
            "groups": [],
            "parse_complete": False,
            "unparsed_count": 1,
            "unparsed_sha256": digest(canonical([stdout_hash])),
            "unparsed_samples": unparsed_samples,
            "error_records": [],
            "error_overflow": False,
            "architecture": (rpm_identity or {}).get("arch"),
            "arguments": [spec_path.name, rpm_path.name],
            "counts": {"E": 0, "W": 0, "I": 0},
            "findings_summary": None,
            "diagnostic_samples": [f"[NON_ACCEPTANCE_STREAM_ERROR:{reason_token}]"],
        }
        if rpm_identity is not None:
            evidence["rpm_identity"] = {
                "name": rpm_identity.get("name", product),
                "version": rpm_identity.get("version", ""),
                "release": rpm_identity.get("release", ""),
                "arch": rpm_identity.get("arch", ""),
            }
        if rpm_payload_digest is not None:
            evidence["rpm_payload_digest"] = dict(rpm_payload_digest)
        if tool_version_info is not None:
            evidence["tool_version"] = tool_version_info
        return evidence

    parsed = parse_rpmlint_output(stdout_text, exit_code=receipt.exit_code, strict=False)
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

    if receipt.stderr_bytes:
        is_clean, reason_token = False, "unexpected-stderr"

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

    config_listing = [
        line.strip()
        for line in stdout_text.splitlines()
        if line.startswith((" ", "\t")) and line.strip().startswith("/")
    ]

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
            "executed": receipt.executed,
            "command": ["rpmlint", spec_path.name, rpm_path.name],
            "command_sha256": digest(canonical(list(receipt.command))),
            "exit_code": receipt.exit_code,
            "stdout_sha256": receipt.stdout_sha256,
            "stderr_sha256": receipt.stderr_sha256,
            "stdout_bytes": len(receipt.stdout_bytes),
            "stderr_bytes": len(receipt.stderr_bytes),
        },
        "session_headers": session_headers,
        "effective_configuration": {
            "listing_sha256": digest(canonical(config_listing)),
            "session_header_sha256": digest(canonical(session_headers)),
            "filtered_count": summary["filtered"],
            "invocation": "default-tool-config-no-added-filters",
        },
        "findings": findings,
        "findings_truncated": findings_truncated,
        "groups": parsed["groups"],
        "parse_complete": parsed["parse_complete"],
        "unparsed_count": parsed["unparsed_count"],
        "unparsed_sha256": parsed["unparsed_sha256"],
        "unparsed_samples": parsed["unparsed_samples"],
        "error_records": parsed.get("error_records", []),
        "error_overflow": parsed.get("error_overflow", False),
        "architecture": (rpm_identity or {}).get("arch"),
        "arguments": [spec_path.name, rpm_path.name],
        "counts": parsed["counts"],
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

    def _evidence_exceeds_cap(ev: dict[str, Any]) -> bool:
        if len(canonical(ev)) > 60 * 1024:
            return True
        if len(json.dumps(ev, indent=2).encode("utf-8")) > 64 * 1024:
            return True
        return False

    # Preserve all severity/code counts while bounding samples and headers.
    # Warnings are dropped first, never hiding error records.
    if _evidence_exceeds_cap(evidence):
        evidence["findings"] = [
            f if f.get("level") == "E" else {k: v for k, v in f.items() if k != "message"}
            for f in evidence["findings"]
        ]
        for g in evidence["groups"]:
            if g.get("severity") != "E":
                g["samples"] = []
        evidence["diagnostic_truncated"] = True

    if _evidence_exceeds_cap(evidence):
        evidence["findings"] = [f for f in evidence["findings"] if f.get("level") == "E"]
        for g in evidence["groups"]:
            g["samples"] = []
        evidence["diagnostic_truncated"] = True

    if _evidence_exceeds_cap(evidence):
        evidence["error_overflow"] = True
        evidence["parse_complete"] = False
        evidence["reason_token"] = "evidence-size-exceeded"
        error = ContractError("RPMLINT_FAILED", "Lint evidence exceeded bound", details={"reason_token": "evidence-size-exceeded"})
        error.evidence = {k: v for k, v in evidence.items() if k not in ("findings", "groups", "error_records")}
        error.evidence["error_records_sha256"] = digest(canonical(evidence["error_records"]))
        error.evidence["error_record_count"] = len(evidence["error_records"])
        raise error
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
    allow_policy: bool = False,
) -> tuple[dict[str, Any], list[CommandReceipt]]:
    """Execute real rpmlint against spec and candidate package, building structured evidence.

    Fails closed with ContractError('RPMLINT_FAILED', ...) on errors, non-zero exit,
    count mismatch, empty output, or malformed streams.
    Tool version query failure is recorded without replacing blamed lint receipt.
    """
    spec_path = Path(spec_path)
    rpm_path = Path(rpm_path)

    # 1. Retain package and spec hashes before version/rpm probes or secondary fs operations
    spec_sha256 = ""
    try:
        if spec_path.is_file():
            spec_sha256 = digest(spec_path.read_bytes())
    except OSError:
        pass

    package_sha256 = ""
    try:
        if rpm_path.is_file():
            package_sha256 = digest(rpm_path.read_bytes())
    except OSError:
        pass

    # 2. Execute causal rpmlint command FIRST
    rpmlint_cmd = ["rpmlint", str(spec_path), str(rpm_path)]
    receipt = runner.run(rpmlint_cmd, cwd=cwd)

    # 4. Build structured evidence (handles parsing, sanitization, count validation)
    try:
        evidence = build_rpmlint_evidence(
            receipt,
            spec_path,
            rpm_path,
            product,
            rpm_identity=rpm_identity,
            rpm_payload_digest=rpm_payload_digest,
            tool_version_info=None,
            allow_warnings=allow_warnings,
        )
    except ContractError as error:
        # Collection failure is still a lint failure with quarantinable bytes.
        err = ContractError("RPMLINT_FAILED", "Candidate RPM lint evidence collection failed", details={
            **error.details, "substage": "rpmlint", "tool": "rpmlint", "product": product,
            "exit_code": receipt.exit_code, "stdout_sha256": receipt.stdout_sha256,
            "stderr_sha256": receipt.stderr_sha256,
        })
        err.receipt = receipt
        err.package_path, err.spec_path = str(rpm_path), str(spec_path)
        for name, path in (("package", rpm_path), ("spec", spec_path)):
            try:
                value = digest(path.read_bytes()) if path.is_file() else ""
            except OSError:
                value = ""
            setattr(err, name + "_sha256", value)

        ev = getattr(error, "evidence", None)
        if ev is None:
            ev = {
                "schema": RPMLINT_EVIDENCE_SCHEMA,
                "product": product,
                "package_file": rpm_path.name,
                "package_sha256": package_sha256,
                "spec_file": spec_path.name,
                "spec_sha256": spec_sha256,
                "clean": False,
                "status": "fail",
                "reason_token": error.details.get("reason_token", "collection-failed"),
                "tool_receipt": {
                    "tool": "rpmlint",
                    "exit_code": receipt.exit_code,
                    "stdout_sha256": receipt.stdout_sha256,
                    "stderr_sha256": receipt.stderr_sha256,
                    "stdout_bytes": len(receipt.stdout_bytes),
                    "stderr_bytes": len(receipt.stderr_bytes),
                },
                "session_headers": getattr(error, "parsed", {}).get("session_headers", []) if hasattr(error, "parsed") else [],
                "findings": getattr(error, "parsed", {}).get("findings", []) if hasattr(error, "parsed") else [],
                "groups": getattr(error, "parsed", {}).get("groups", []) if hasattr(error, "parsed") else [],
                "findings_truncated": False,
                "parse_complete": False,
                "evidence_status": "collection-failed",
                "findings_summary": None,
                "collection_error": error.code,
            }
        err.evidence = ev

        # Secondary fs operations cannot replace original lint error
        try:
            findings_dir = Path(cwd) if cwd else spec_path.parent
            findings_dir.mkdir(parents=True, exist_ok=True)
            (findings_dir / "rpmlint-findings.json").write_bytes(canonical(ev))
        except OSError:
            ev["local_findings_write"] = "failed"

        raise err from None

    # Freeze the identities observed before diagnostic probes.
    evidence["spec_sha256"] = spec_sha256
    evidence["package_sha256"] = package_sha256
    evidence["identity_status"] = {"spec": "available" if spec_sha256 else "unavailable",
                                   "package": "available" if package_sha256 else "unavailable"}
    if evidence["clean"] and (not spec_sha256 or not package_sha256):
        evidence.update(clean=False, status="fail", reason_token="input-identity-unavailable")

    # 3. Query tool/package versions; failures must NOT replace causal lint receipt
    version_info: dict[str, Any] = {
        "tool": "rpmlint",
        "tool_identity_sha256": digest((receipt.tool_path or receipt.tool_name or "rpmlint").encode()),
    }
    try:
        v_receipt = runner.run(["rpmlint", "--version"], cwd=cwd)
        version_info.update(_tool_identity_evidence(v_receipt))
    except Exception:
        version_info["version"] = "query-unavailable"

    try:
        package_version = runner.run(["rpm", "-q", "--qf", "%{NAME}|%{VERSION}|%{RELEASE}|%{ARCH}\\n", "rpmlint"], cwd=cwd)
        version_info["package_query"] = _tool_identity_evidence(package_version, package=True)
    except Exception:
        version_info["package_query"] = {"status": "unavailable"}

    evidence["tool_version"] = version_info

    # Secondary fs operations cannot replace original lint error
    try:
        findings_dir = Path(cwd) if cwd else spec_path.parent
        findings_dir.mkdir(parents=True, exist_ok=True)
        (findings_dir / "rpmlint-findings.json").write_bytes(canonical(evidence))
    except OSError:
        evidence["local_findings_write"] = "failed"

    # 5. Check cleanliness
    if not evidence["clean"]:
        if allow_policy:
            is_recognized_lint_result = (
                evidence.get("parse_complete", False)
                and evidence.get("unparsed_count", -1) == 0
                and not evidence.get("error_overflow", False)
                and evidence.get("reason_token") in ("lint-errors", "lint-exit64", "lint-warnings")
                and evidence.get("findings_summary") is not None
                and receipt.exit_code == (64 if evidence["findings_summary"].get("errors") else 0)
                and not receipt.stderr_bytes
                and bool(evidence.get("spec_sha256"))
                and bool(evidence.get("package_sha256"))
                and evidence["findings_summary"].get("packages") == 1
                and evidence["findings_summary"].get("specfiles") == 1
                and evidence["findings_summary"].get("errors") == len(evidence.get("error_records", []))
            )
            if is_recognized_lint_result:
                return evidence, [receipt]

        findings = evidence["findings"]
        primary_check = (
            evidence.get("error_records", [{}])[0].get("code")
            if evidence.get("error_records")
            else (findings[0]["check"] if findings else evidence["reason_token"])
        )
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
        err.receipt = receipt
        err.evidence = evidence
        err.rpmlint_evidence = evidence
        err.package_path = str(rpm_path)
        err.spec_path = str(spec_path)
        err.spec_sha256 = evidence["spec_sha256"]
        err.package_sha256 = evidence["package_sha256"]
        raise err

    return evidence, [receipt]
