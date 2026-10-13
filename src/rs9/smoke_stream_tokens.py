"""Bounded observations after the original smoke outcome; no raw text or authority."""
import os
from pathlib import Path
import re
import stat

from rs9.errors import ContractError
from rs9.release_core import digest
from rs9.security import scan_for_credentials

MAX_BYTES = 64 * 1024
MAX_ENTRIES = 32
MAX_TOKENS = 8
STAGE = "original-smoke-process-stderr"
INVENTORY_STAGE = "after-original-smoke-before-client-cleanup"
WITHHELD = frozenset({"empty", "oversize", "invalid-utf8", "private", "incomplete",
                      "truncated", "unterminated", "control-bytes", "invalid-observation", "binding-mismatch"})
# Fixed forms from the bound release's native-rc-smoke.mjs and fs-snapshot.mjs.
# Their authenticated identities and the offline message comparison live in CONT22 evidence.
FIXED = {
    "candidate executable is not executable": "release-executable-not-executable",
    "maintained core fixture project name changed": "release-fixture-project-changed",
    "maintained core fixture brand changed": "release-fixture-brand-changed",
}
PATTERNS = {
    "node-type-error": r"^TypeError(?:\s*\[[A-Z_]+\])?:",
    "node-reference-error": r"^ReferenceError:",
    "node-syntax-error": r"^SyntaxError:",
    "node-module-not-found": r"^(?:Error \[ERR_MODULE_NOT_FOUND\]:|Error: Cannot find module )",
    "node-warning": r"^\(node:[0-9]+\) (?:Warning|ExperimentalWarning):",
    "display-unavailable": r"^(?:.*Gtk-WARNING.*:|.*Gdk-WARNING.*:)\s*cannot open display:",
    "xlib-auth-denied": r"^(?:Authorization required, but no authorization protocol specified|No protocol specified)$",
    "bwrap-namespace-denied": r"^bwrap: (?:Creating new namespace failed|No permissions to create new namespace).*",
    "loader-library-missing": r"^[^\n]+: error while loading shared libraries:",
    "release-executable-snapshot-error": r"^Candidate executable (?:is missing|must not be a symbolic link|must be a regular file|changed while it was read|was truncated while it was read|grew while it was read): ",
}
ERRNOS = ("EACCES", "EPERM", "ENOENT", "ELOOP", "ENOSPC", "EROFS")
SYSCALLS = ("open", "mkdir", "scandir", "lstat", "stat", "unlink", "rmdir", "realpath")
TOKENS = frozenset((*FIXED.values(), *PATTERNS,
                    *("node-errno-" + x.lower() for x in ERRNOS),
                    *("node-syscall-" + x for x in SYSCALLS)))
PRIVATE = re.compile(r"/(?:Users|home|private|var/folders)/|(?:https?|postgres(?:ql)?|mysql)://|"
                     r"(?i:password|passwd|api[_-]?key|access[_-]?token|cookie)\s*[:=]|"
                     r"[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}")
KINDS = ("run.json", "receipt.json", "stdout.log", "stderr.log")


def _withheld_stream(raw, complete):
    if complete is not True:
        return "incomplete", None
    if not raw:
        return "empty", ""
    if len(raw) > MAX_BYTES:
        return "oversize", None
    try:
        text = raw.decode("utf-8")
    except UnicodeError:
        return "invalid-utf8", None
    try:
        scan_for_credentials(text)
        if PRIVATE.search(text):
            return "private", None
    except ContractError:
        return "private", None
    if any(ord(c) < 32 and c not in "\n\r\t" or ord(c) == 127 for c in text):
        return "control-bytes", None
    if not text.endswith("\n"):
        return "unterminated", None
    return None, text


def stream_tokens(raw, *, complete):
    """Classify captured bytes only; messages, paths and dynamic values never leave."""
    reason, text = _withheld_stream(raw, complete)
    utf8_valid = None if reason in {"incomplete", "oversize"} else reason != "invalid-utf8"
    line_count = None if reason in {"incomplete", "oversize"} else len(raw.splitlines())
    result = {"stage": STAGE, "bytes": len(raw), "sha256": digest(raw),
              "line_count": line_count, "utf8_valid": utf8_valid,
              "tokens": [], "tokens_omitted": 0, "withheld_reason": reason}
    if reason:
        return result
    tokens = {token for message, token in FIXED.items() if message in text.splitlines()}
    tokens.update(token for token, pattern in PATTERNS.items() if re.search(pattern, text, re.M))
    for line in text.splitlines():
        match = re.match(r"^(?:Error: )?(" + "|".join(ERRNOS) + r"): [^\n,]+, (" +
                         "|".join(SYSCALLS) + r") '", line)
        if match:
            tokens.update(("node-errno-" + match[1].lower(), "node-syscall-" + match[2]))
    result["tokens"] = sorted(tokens)[:MAX_TOKENS]
    result["tokens_omitted"] = max(0, len(tokens) - MAX_TOKENS)
    return result


def validate_stream_tokens(raw, *, sha256, byte_count, complete, mismatch=False):
    """Idempotent closed projection of guest observations bound to original stderr."""
    if not isinstance(raw, dict):
        return None
    tokens, reason = raw.get("tokens"), raw.get("withheld_reason")
    omitted = raw.get("tokens_omitted", 0)
    valid = (raw.get("stage") == STAGE and raw.get("sha256") == sha256 and
             type(raw.get("bytes")) is int and raw["bytes"] == byte_count and
             (type(raw.get("line_count")) is int and 0 <= raw["line_count"] <= MAX_BYTES or
              raw.get("line_count") is None and reason in ("incomplete", "oversize")) and
             (type(raw.get("utf8_valid")) is bool or raw.get("utf8_valid") is None and reason in ("incomplete", "oversize")) and
             isinstance(tokens, list) and len(tokens) <= MAX_TOKENS and
             all(isinstance(t, str) and t in TOKENS for t in tokens) and
             type(omitted) is int and 0 <= omitted <= len(TOKENS) - MAX_TOKENS and
             (omitted == 0 or reason is None and len(set(tokens)) == MAX_TOKENS) and
             (reason is None or isinstance(reason, str) and reason in WITHHELD))
    if not valid:
        reason = "invalid-observation"
    elif reason is None and (raw["utf8_valid"] is not True or not byte_count or byte_count > MAX_BYTES):
        reason = "invalid-observation"
    if mismatch:
        reason = "binding-mismatch"
    elif not complete:
        reason = "incomplete"
    return {"stage": STAGE, "bytes": byte_count, "sha256": sha256,
            "line_count": raw["line_count"] if valid else None,
            "utf8_valid": raw["utf8_valid"] if valid else False,
            "tokens": sorted(set(tokens)) if valid and reason is None else [],
            "tokens_omitted": omitted if valid and reason is None else 0,
            "withheld_reason": reason}


def evidence_inventory(directory, platform, scenario):
    """No-follow, at most 32 entries; only four released artifact kinds, no content."""
    result = {"stage": INVENTORY_STAGE, "status": "unavailable", "artifacts": [],
              "entries_observed": 0, "unlisted": 0}
    directory = Path(directory)
    if any(p.is_symlink() for p in (directory, *directory.parents)):
        return result
    names = {platform + "-" + scenario + "." + kind: kind for kind in KINDS}
    fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        with os.scandir(fd) as entries:
            for entry in entries:
                if result["entries_observed"] == MAX_ENTRIES:
                    result["status"] = "limit-exceeded"
                    break
                result["entries_observed"] += 1
                if entry.name not in names:
                    result["unlisted"] += 1
                    continue
                info = entry.stat(follow_symlinks=False)
                result["artifacts"].append({"kind": names[entry.name], "bytes": info.st_size,
                    "regular": stat.S_ISREG(info.st_mode), "symlink": stat.S_ISLNK(info.st_mode)})
            else:
                result["status"] = "observed"
    finally:
        os.close(fd)
    result["artifacts"].sort(key=lambda x: x["kind"])
    return result


def validate_inventory(raw, *, mismatch=False):
    if not isinstance(raw, dict):
        return None
    fallback = {"stage": INVENTORY_STAGE, "status": "unavailable", "artifacts": [],
                "entries_observed": 0, "unlisted": 0}
    artifacts = raw.get("artifacts")
    if (mismatch or raw.get("stage") != INVENTORY_STAGE or
            not isinstance(raw.get("status"), str) or raw["status"] not in {"observed", "unavailable", "limit-exceeded"} or
            not isinstance(artifacts, list) or len(artifacts) > len(KINDS) or
            any(type(raw.get(k)) is not int or not 0 <= raw[k] <= MAX_ENTRIES
                for k in ("entries_observed", "unlisted"))):
        return fallback
    rows = []
    if (raw["status"] == "unavailable" and (artifacts or raw["entries_observed"] or raw["unlisted"]) or
            raw["status"] == "limit-exceeded" and raw["entries_observed"] != MAX_ENTRIES):
        return fallback
    for item in artifacts:
        if (not isinstance(item, dict) or item.get("kind") not in KINDS or
                type(item.get("bytes")) is not int or not 0 <= item["bytes"] <= 2**63 - 1 or
                any(type(item.get(k)) is not bool for k in ("regular", "symlink")) or
                item["regular"] and item["symlink"]):
            return fallback
        rows.append({k: item[k] for k in ("kind", "bytes", "regular", "symlink")})
    if len({r["kind"] for r in rows}) != len(rows) or raw["unlisted"] + len(rows) != raw["entries_observed"]:
        return fallback
    return {"stage": INVENTORY_STAGE, "status": raw["status"], "artifacts": sorted(rows, key=lambda x: x["kind"]),
            "entries_observed": raw["entries_observed"], "unlisted": raw["unlisted"]}


def collect_failure_diagnostics(stderr, fields, evidence, platform, scenario):
    """Each optional observation fails independently after the gate outcome is fixed."""
    result = {}
    try:
        result["stderr_diagnostic"] = stream_tokens(stderr, complete=fields["stream_capture_complete"])
    except Exception:
        pass
    try:
        result["evidence_inventory"] = evidence_inventory(evidence, platform, scenario)
    except Exception:
        pass
    return result
