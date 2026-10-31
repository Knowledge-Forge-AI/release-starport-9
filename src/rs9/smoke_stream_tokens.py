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
INNER_STAGE = "original-inner-application-stderr"
RUN_STAGE = "original-harness-run-record"
INVENTORY_STAGE = "after-original-smoke-before-client-cleanup"
MAX_STEP_ENTRIES = 64
MAX_PROBLEMS = 64
SCENARIO_A_STEPS = (
    "app-shell",
    "host-start",
    "host-status",
    "project-open",
    "brand-read",
    "theme-lab-compile",
    "app-theme-status",
    "app-theme-compile",
    "brand-system-view",
    "host-status-final",
)
STEP_STATES = frozenset({"pass", "fail", "unknown", "missing", "duplicate"})
RUN_WITHHELD = frozenset({
    "receipt-missing",
    "receipt-invalid",
    "receipt-oversize",
    "receipt-corrupt",
    "receipt-malformed",
    "invalid-observation",
    "binding-mismatch",
})
INNER_READ_ERRORS = frozenset({"missing", "symlink", "nonregular", "oversize", "read-error"})
# Closed problem inventory from the root-authenticated harness (runSmoke / judgeReceipt).
PROBLEM_CATEGORIES = {
    "no receipt was written": "receipt-not-written",
    "receipt mode ": "receipt-mode-mismatch",
    "receipt schema": "receipt-schema",
    "receipt scenario ": "receipt-scenario-mismatch",
    "receipt status ": "receipt-status",
    "receipt pid ": "receipt-pid-mismatch",
    "receipt target ": "receipt-target-mismatch",
    "the running executable is not the candidate executable": "running-executable-mismatch",
    "required step ": "required-step",
    "receipt signal expectation": "receipt-signal-expectation",
    "the application did not exit within its bound and was killed": "application-bound-killed",
    "orphan candidate processes remained: ": "orphan-candidate-processes",
    "the signal scenario never reached its signal point": "signal-point-not-reached",
    "no sidecar was running when the application was terminated": "signal-sidecar-not-running",
    "application ended by ": "signal-termination-mismatch",
    "application exit code ": "application-exit-nonzero",
    "the derived asset was not written to the case-exact project": "derived-asset-not-written",
    "the case-distinct sibling project was modified": "sibling-project-modified",
    "read-only fixture ": "read-only-fixture-modified",
    "persistent user state changed: ": "persistent-user-state-changed",
    "the candidate executable changed during the smoke run": "candidate-executable-changed",
    "harness cleanup of the owned scratch directory failed": "harness-cleanup-failed",
    "harness error: ": "harness-error",
}
_EXACT_PROBLEM_FORMS = frozenset({
    "no receipt was written",
    "receipt schema",
    "the running executable is not the candidate executable",
    "receipt signal expectation",
    "the application did not exit within its bound and was killed",
    "the signal scenario never reached its signal point",
    "no sidecar was running when the application was terminated",
    "the derived asset was not written to the case-exact project",
    "the case-distinct sibling project was modified",
    "the candidate executable changed during the smoke run",
    "harness cleanup of the owned scratch directory failed",
})
_PROBLEM_SUFFIXES = {
    "application ended by ": " instead of SIGTERM",
    "read-only fixture ": " was modified",
}
_ORDERED_PROBLEM_PREFIXES = tuple(
    sorted(PROBLEM_CATEGORIES.items(), key=lambda kv: len(kv[0]), reverse=True)
)
_PROBLEM_CATEGORY_SET = frozenset(PROBLEM_CATEGORIES.values())
# Separately versioned Linux B/C category-only envelope; distinct from Darwin harness_run_record.
CATEGORY_SCHEMA = "rs9.original-smoke-problem-categories.v1alpha1"
CATEGORY_STAGE = "original-harness-problem-categories"
CATEGORY_WITHHELD = frozenset({"invalid-observation", "binding-mismatch"})
_CATEGORY_BINDINGS = frozenset({
    ("x86_64-linux", "linux-x64", "C"),
    ("x86_64-linux", "linux-x64", "C-signal"),
    ("aarch64-linux", "linux-arm64", "B"),
})
_CATEGORY_SCENARIOS = {"x86_64-linux": frozenset({"C", "C-signal"}), "aarch64-linux": frozenset({"B"})}
_CATEGORY_KEYS = frozenset({"schema", "stage", "system", "scenario", "receipt", "problems"})
_CATEGORY_PROBLEM_KEYS = frozenset({"total", "scanned", "categories", "unrecognized", "non_string",
                                    "omitted", "unavailable"})
FINALIZATION_SCHEMA = "nebular.native-rc-finalization-v1"
FINALIZATION_STATUSES = frozenset({"complete", "failed"})
FINALIZATION_PHASES = frozenset({
    "complete", "pre-spawn", "post-exit", "receipt-copy", "cleanup", "report-write",
})
FINALIZATION_EXCEPTION_FAMILIES = frozenset({
    "state", "parse", "timeout", "process", "filesystem", "unknown",
})
FINALIZATION_RECEIPT_OBSERVATIONS = frozenset({
    "not-attempted", "read-failed", "present-at-read", "absent-at-read",
})
FINALIZATION_RECEIPT_COPIES = frozenset({"not-attempted", "copy-failed", "written"})
_FINALIZATION_KEYS = frozenset({
    "status", "phase", "exceptionFamily", "spawned", "exitObserved",
    "applicationReceiptObservation", "applicationReceiptCopy",
})
_RECEIPT_SUMMARY_KEYS = frozenset({"present", "bytes", "sha256", "status", "problem_codes",
                                   "problem_count", "executable_sha256"})
_CATEGORY_RECEIPT_ERRORS = frozenset({"receipt-missing", "receipt-invalid", "receipt-oversize", "receipt-corrupt"})
WITHHELD = frozenset({"empty", "oversize", "invalid-utf8", "private", "incomplete",
                      "truncated", "unterminated", "control-bytes", "invalid-observation", "binding-mismatch"})
# Outer process stderr Error.message lines frozen from CONT22 ("candidate executable is not
# executable" is thrown before runSmoke's try block to outer stderr; in the authenticated
# harness, copyProject/prepareFixtures run inside runSmoke's try block so the two fixture
# throws surface in result.problems under "harness error: ", while their FIXED entries remain
# inherited CONT22 outer-stderr mappings).
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


def _classify_stream(raw, *, stage, complete):
    reason, text = _withheld_stream(raw, complete)
    utf8_valid = None if reason in {"incomplete", "oversize"} else reason != "invalid-utf8"
    line_count = None if reason in {"incomplete", "oversize"} else len(raw.splitlines())
    result = {"stage": stage, "bytes": len(raw), "sha256": digest(raw),
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


def stream_tokens(raw, *, complete):
    """Classify captured bytes only; messages, paths and dynamic values never leave."""
    return _classify_stream(raw, stage=STAGE, complete=complete)


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


def _unavailable_run(reason, byte_count=None, sha256=None):
    return {
        "stage": RUN_STAGE,
        "status": "unavailable",
        "withheld_reason": reason,
        "bytes": byte_count,
        "sha256": sha256,
        "steps": [{"id": s, "state": "unknown"} for s in SCENARIO_A_STEPS],
        "steps_entries_observed": 0,
        "steps_unlisted": 0,
        "steps_omitted": 0,
        "problems": {
            "total": None,
            "scanned": 0,
            "categories": [],
            "unrecognized": 0,
            "non_string": 0,
            "unavailable": 1,
        },
    }


def project_run_record(record, identity=None, *, receipt_error=None):
    """Project already-read Scenario A .run.json into closed step states and problem counts."""
    meta = identity if isinstance(identity, dict) else {}
    raw_bytes = meta.get("bytes")
    byte_count = raw_bytes if type(raw_bytes) is int and 0 <= raw_bytes <= 2**63 - 1 else None
    raw_sha = meta.get("sha256")
    sha256 = raw_sha if isinstance(raw_sha, str) and re.fullmatch(r"[0-9a-f]{64}", raw_sha) else None
    if not isinstance(record, dict):
        reason = receipt_error if isinstance(receipt_error, str) and receipt_error in RUN_WITHHELD else "receipt-malformed"
        if reason in {"receipt-missing", "receipt-invalid"}:
            return _unavailable_run(reason)
        if reason == "receipt-oversize":
            return _unavailable_run(reason, byte_count=byte_count)
        return _unavailable_run(reason, byte_count=byte_count, sha256=sha256)
    if byte_count is None or not 0 < byte_count <= 1024 * 1024 or sha256 is None:
        return _unavailable_run("invalid-observation")
    inner_receipt = record.get("receipt")
    raw_steps = inner_receipt.get("steps") if isinstance(inner_receipt, dict) else None
    if isinstance(raw_steps, list):
        window = raw_steps[:MAX_STEP_ENTRIES]
        steps_entries_observed = len(window)
        steps_omitted = max(0, len(raw_steps) - MAX_STEP_ENTRIES)
        steps_unlisted = 0
        seen = {}
        for item in window:
            if not isinstance(item, dict) or not isinstance(item.get("id"), str) or item["id"] not in SCENARIO_A_STEPS:
                steps_unlisted += 1
                continue
            sid = item["id"]
            ok = item.get("ok")
            state = ("pass" if ok else "fail") if type(ok) is bool else "unknown"
            seen[sid] = "duplicate" if sid in seen else state
        default_state = "unknown" if steps_omitted > 0 else "missing"
        steps = [{"id": s, "state": seen.get(s, default_state)} for s in SCENARIO_A_STEPS]
    else:
        steps_entries_observed = 0
        steps_unlisted = 0
        steps_omitted = 0
        steps = [{"id": s, "state": "unknown"} for s in SCENARIO_A_STEPS]
    return {
        "stage": RUN_STAGE,
        "status": "observed",
        "withheld_reason": None,
        "bytes": byte_count,
        "sha256": sha256,
        "steps": steps,
        "steps_entries_observed": steps_entries_observed,
        "steps_unlisted": steps_unlisted,
        "steps_omitted": steps_omitted,
        "problems": _classify_problems(record.get("problems")),
    }


def _classify_problems(raw_problems, *, current071=False):
    """Closed category counts over the bounded prefix; no problem text leaves."""
    if not isinstance(raw_problems, list):
        return {"total": None, "scanned": 0, "categories": [], "unrecognized": 0,
                "non_string": 0, "unavailable": 1}
    prob_window = raw_problems[:MAX_PROBLEMS]
    counts = {}
    unrecognized = 0
    non_string = 0
    for item in prob_window:
        if not isinstance(item, str):
            non_string += 1
            continue
        for prefix, category in _ORDERED_PROBLEM_PREFIXES:
            if category == "harness-cleanup-failed" and current071 is not True:
                continue
            if prefix in _EXACT_PROBLEM_FORMS:
                matched = item == prefix
            elif prefix in _PROBLEM_SUFFIXES:
                suffix = _PROBLEM_SUFFIXES[prefix]
                matched = (
                    item.startswith(prefix)
                    and item.endswith(suffix)
                    and len(item) > len(prefix) + len(suffix)
                )
            else:
                matched = item.startswith(prefix)
            if matched:
                counts[category] = counts.get(category, 0) + 1
                break
        else:
            unrecognized += 1
    return {
        "total": len(raw_problems),
        "scanned": len(prob_window),
        "categories": [{"category": c, "count": counts[c]} for c in sorted(counts)],
        "unrecognized": unrecognized,
        "non_string": non_string,
        "unavailable": 0,
    }


def validate_run_record(raw, *, inventory=None, mismatch=False):
    """Idempotent closed validator for Scenario A harness_run_record bound to evidence_inventory."""
    if not isinstance(raw, dict):
        return None
    fallback_reason = "binding-mismatch" if mismatch else "invalid-observation"
    expected_keys = {
        "stage", "status", "withheld_reason", "bytes", "sha256",
        "steps", "steps_entries_observed", "steps_unlisted", "steps_omitted", "problems",
    }
    if set(raw.keys()) != expected_keys or raw.get("stage") != RUN_STAGE:
        return _unavailable_run(fallback_reason)
    status = raw.get("status")
    reason = raw.get("withheld_reason")
    byte_count = raw.get("bytes")
    sha256 = raw.get("sha256")
    steps = raw.get("steps")
    obs_cnt = raw.get("steps_entries_observed")
    unl_cnt = raw.get("steps_unlisted")
    omi_cnt = raw.get("steps_omitted")
    probs = raw.get("problems")
    if (not (byte_count is None or type(byte_count) is int and 0 <= byte_count <= 2**63 - 1) or
            not (sha256 is None or isinstance(sha256, str) and bool(re.fullmatch(r"[0-9a-f]{64}", sha256))) or
            not isinstance(steps, list) or len(steps) != len(SCENARIO_A_STEPS) or
            any(not isinstance(s, dict) or set(s.keys()) != {"id", "state"} or
                s.get("id") != SCENARIO_A_STEPS[i] or not isinstance(s.get("state"), str) or s["state"] not in STEP_STATES
                for i, s in enumerate(steps)) or
            any(type(v) is not int for v in (obs_cnt, unl_cnt, omi_cnt)) or
            not (0 <= obs_cnt <= MAX_STEP_ENTRIES and 0 <= unl_cnt <= obs_cnt and 0 <= omi_cnt <= 1024 * 1024) or
            (omi_cnt > 0 and (obs_cnt != MAX_STEP_ENTRIES or any(s["state"] == "missing" for s in steps))) or
            not isinstance(probs, dict) or
            set(probs.keys()) != {"total", "scanned", "categories", "unrecognized", "non_string", "unavailable"}):
        return _unavailable_run(fallback_reason)
    recognized_entries = obs_cnt - unl_cnt
    min_required_entries = sum(1 if s["state"] in {"pass", "fail"} else 2 if s["state"] == "duplicate" else 0 for s in steps)
    if min_required_entries > recognized_entries:
        return _unavailable_run(fallback_reason)
    total = probs.get("total")
    scanned = probs.get("scanned")
    cats = probs.get("categories")
    unrec = probs.get("unrecognized")
    nonstr = probs.get("non_string")
    unavail = probs.get("unavailable")
    if (any(type(v) is not int for v in (scanned, unrec, nonstr, unavail)) or
            unavail not in (0, 1) or
            (unavail == 0 and (type(total) is not int or not (0 <= total <= 1024 * 1024 and 0 <= scanned <= MAX_PROBLEMS and scanned == min(total, MAX_PROBLEMS)))) or
            (unavail == 1 and (total is not None or scanned != 0)) or
            not (0 <= unrec <= scanned and 0 <= nonstr <= scanned) or
            not isinstance(cats, list) or len(cats) > len(_PROBLEM_CATEGORY_SET) or
            any(not isinstance(c, dict) or set(c.keys()) != {"category", "count"} or
                not isinstance(c.get("category"), str) or c["category"] not in _PROBLEM_CATEGORY_SET or
                type(c.get("count")) is not int or not 1 <= c["count"] <= scanned
                for c in cats) or
            [c["category"] for c in cats] != sorted({c["category"] for c in cats}) or
            sum(c["count"] for c in cats) + unrec + nonstr != scanned):
        return _unavailable_run(fallback_reason)
    if status == "observed":
        if reason is not None or type(byte_count) is not int or not 0 < byte_count <= 1024 * 1024 or sha256 is None:
            return _unavailable_run(fallback_reason)
    elif status == "unavailable":
        if (not isinstance(reason, str) or reason not in RUN_WITHHELD or
                obs_cnt != 0 or unl_cnt != 0 or omi_cnt != 0 or
                any(s["state"] != "unknown" for s in steps) or
                unavail != 1 or
                (reason in {"invalid-observation", "binding-mismatch", "receipt-missing", "receipt-invalid"} and
                 (byte_count is not None or sha256 is not None)) or
                (reason == "receipt-oversize" and sha256 is not None)):
            return _unavailable_run(fallback_reason)
    else:
        return _unavailable_run(fallback_reason)
    if mismatch:
        return _unavailable_run("binding-mismatch")
    if isinstance(inventory, dict) and inventory.get("status") == "observed":
        run_art = next((a for a in inventory.get("artifacts", ()) if isinstance(a, dict) and a.get("kind") == "run.json"), None)
        if status == "observed":
            if (run_art is None or run_art.get("regular") is not True or
                    run_art.get("symlink") is not False or run_art.get("bytes") != byte_count):
                return _unavailable_run("binding-mismatch")
        elif reason == "receipt-missing":
            if run_art is not None:
                return _unavailable_run("binding-mismatch")
        elif reason == "receipt-oversize":
            if (run_art is None or run_art.get("regular") is not True or run_art.get("symlink") is not False or
                    (byte_count is not None and run_art.get("bytes") != byte_count)):
                return _unavailable_run("binding-mismatch")
        elif reason in {"receipt-corrupt", "receipt-malformed"} and byte_count is not None:
            if (run_art is None or run_art.get("regular") is not True or
                    run_art.get("symlink") is not False or run_art.get("bytes") != byte_count):
                return _unavailable_run("binding-mismatch")
    return {
        "stage": RUN_STAGE,
        "status": status,
        "withheld_reason": reason,
        "bytes": byte_count,
        "sha256": sha256,
        "steps": [{"id": s["id"], "state": s["state"]} for s in steps],
        "steps_entries_observed": obs_cnt,
        "steps_unlisted": unl_cnt,
        "steps_omitted": omi_cnt,
        "problems": {
            "total": total,
            "scanned": scanned,
            "categories": [{"category": c["category"], "count": c["count"]} for c in cats],
            "unrecognized": unrec,
            "non_string": nonstr,
            "unavailable": unavail,
        },
    }


def _receipt_identity(raw):
    """Exact same-read {bytes, sha256}, or None; never a guessed or partial identity."""
    if not isinstance(raw, dict):
        return None
    byte_count, sha256 = raw.get("bytes"), raw.get("sha256")
    if (type(byte_count) is not int or not 0 < byte_count <= 1024 * 1024 or
            not isinstance(sha256, str) or not re.fullmatch(r"[0-9a-f]{64}", sha256)):
        return None
    return {"bytes": byte_count, "sha256": sha256}


def _withheld_categories(reason):
    # The single failure representation: no system, receipt, counts or exception text.
    return {"schema": CATEGORY_SCHEMA, "stage": CATEGORY_STAGE, "withheld_reason": reason}


def _closed_finalization(raw, *, allow_schema=False):
    """Exact closed projection of run.json.finalization; no error message, path, or PID."""
    if not isinstance(raw, dict):
        return None
    keys = set(raw)
    if allow_schema:
        if keys != _FINALIZATION_KEYS | {"schema"} or raw.get("schema") != FINALIZATION_SCHEMA:
            return None
    elif keys != _FINALIZATION_KEYS:
        return None
    status = raw.get("status")
    phase = raw.get("phase")
    family = raw.get("exceptionFamily")
    spawned = raw.get("spawned")
    exited = raw.get("exitObserved")
    obs = raw.get("applicationReceiptObservation")
    copy = raw.get("applicationReceiptCopy")
    if (not isinstance(status, str) or status not in FINALIZATION_STATUSES or
            not isinstance(phase, str) or phase not in FINALIZATION_PHASES or
            not (family is None or isinstance(family, str) and family in FINALIZATION_EXCEPTION_FAMILIES) or
            type(spawned) is not bool or type(exited) is not bool or
            not isinstance(obs, str) or obs not in FINALIZATION_RECEIPT_OBSERVATIONS or
            not isinstance(copy, str) or copy not in FINALIZATION_RECEIPT_COPIES):
        return None
    if status == "complete" and (phase != "complete" or family is not None):
        return None
    if status == "failed" and (phase == "complete" or family is None):
        return None
    return {
        "status": status,
        "phase": phase,
        "exceptionFamily": family,
        "spawned": spawned,
        "exitObserved": exited,
        "applicationReceiptObservation": obs,
        "applicationReceiptCopy": copy,
    }


def project_problem_categories(record, identity, *, system, platform, scenario, current071=False):
    """Category-only Linux B/C projection of the already-read original .run.json; no reread."""
    if (not all(isinstance(v, str) for v in (system, platform, scenario)) or
            (system, platform, scenario) not in _CATEGORY_BINDINGS or not isinstance(record, dict)):
        return None
    if not isinstance(identity, dict) or identity.get("present") is not True:
        return None
    receipt = _receipt_identity(identity)
    if receipt is None:
        return None
    problems = _classify_problems(record.get("problems"), current071=current071)
    total = problems["total"]
    finalization = (_closed_finalization(record.get("finalization"), allow_schema=True)
                    if current071 is True else None)
    result = {
        "schema": CATEGORY_SCHEMA,
        "stage": CATEGORY_STAGE,
        "system": system,
        "scenario": scenario,
        "receipt": receipt,
        "problems": {
            "total": total,
            "scanned": problems["scanned"],
            "categories": problems["categories"],
            "unrecognized": problems["unrecognized"],
            "non_string": problems["non_string"],
            "omitted": 0 if total is None else total - problems["scanned"],
            "unavailable": problems["unavailable"],
        },
    }
    if finalization is not None:
        result["finalization"] = finalization
    return result


def _closed_categories(raw):
    """Exact positive envelope structure and count closure, or None; binding is separate."""
    if not isinstance(raw, dict) or set(raw) not in (_CATEGORY_KEYS, _CATEGORY_KEYS | {"finalization"}):
        return None
    system, scenario, receipt, probs = raw["system"], raw["scenario"], raw["receipt"], raw["problems"]
    if (raw["schema"] != CATEGORY_SCHEMA or raw["stage"] != CATEGORY_STAGE or
            not isinstance(system, str) or system not in _CATEGORY_SCENARIOS or
            not isinstance(scenario, str) or scenario not in _CATEGORY_SCENARIOS[system] or
            not isinstance(receipt, dict) or set(receipt) != {"bytes", "sha256"} or
            _receipt_identity(receipt) is None or
            not isinstance(probs, dict) or set(probs) != _CATEGORY_PROBLEM_KEYS):
        return None
    finalization = None
    if "finalization" in raw:
        finalization = _closed_finalization(raw["finalization"])
        if finalization is None:
            return None
    total, scanned, cats = probs["total"], probs["scanned"], probs["categories"]
    unrec, nonstr, omitted, unavail = (probs[k] for k in ("unrecognized", "non_string", "omitted", "unavailable"))
    if any(type(v) is not int for v in (scanned, unrec, nonstr, omitted, unavail)) or not isinstance(cats, list):
        return None
    if unavail == 1:
        if total is not None or scanned or unrec or nonstr or omitted or cats:
            return None
    elif unavail == 0:
        if (type(total) is not int or not 0 <= total <= 1024 * 1024 or
                scanned != min(total, MAX_PROBLEMS) or omitted != total - scanned):
            return None
    else:
        return None
    if (not (0 <= unrec <= scanned and 0 <= nonstr <= scanned) or len(cats) > len(_PROBLEM_CATEGORY_SET) or
            any(not isinstance(c, dict) or set(c) != {"category", "count"} or
                not isinstance(c["category"], str) or c["category"] not in _PROBLEM_CATEGORY_SET or
                type(c["count"]) is not int or not 1 <= c["count"] <= scanned
                for c in cats)):
        return None
    names = [c["category"] for c in cats]
    if names != sorted(set(names)) or sum(c["count"] for c in cats) + unrec + nonstr != scanned:
        return None
    result = {
        "schema": CATEGORY_SCHEMA,
        "stage": CATEGORY_STAGE,
        "system": system,
        "scenario": scenario,
        "receipt": {"bytes": receipt["bytes"], "sha256": receipt["sha256"]},
        "problems": {
            "total": total,
            "scanned": scanned,
            "categories": [{"category": c["category"], "count": c["count"]} for c in cats],
            "unrecognized": unrec,
            "non_string": nonstr,
            "omitted": omitted,
            "unavailable": unavail,
        },
    }
    if finalization is not None:
        result["finalization"] = finalization
    return result


def _observation_receipt(raw):
    """First-pass descriptor summary (present: True) or a prior positive {bytes, sha256} only."""
    if not isinstance(raw, dict):
        return None
    keys = set(raw)
    if keys == {"bytes", "sha256"} or ("present" in keys and raw["present"] is True and keys <= _RECEIPT_SUMMARY_KEYS):
        return _receipt_identity(raw)
    return None


def _inventory_binds(inventory, raw_inventory, byte_count):
    """Length/type corroboration only; the inventory schema carries no digest."""
    if not isinstance(raw_inventory, dict) or not isinstance(inventory, dict):
        return False
    if inventory.get("status") not in {"observed", "limit-exceeded"}:
        return False
    rows = [a for a in inventory.get("artifacts", ()) if a.get("kind") == "run.json"]
    # Missing or outside the bounded window is uncorroborated, never a positive binding.
    return (len(rows) == 1 and rows[0]["regular"] is True and rows[0]["symlink"] is False and
            rows[0]["bytes"] == byte_count)


def validate_problem_categories(raw, *, system, scenario, receipt, receipt_error=None,
                                inventory=None, raw_inventory=None, mismatch=False):
    """Idempotent closed Linux B/C category envelope bound to the observation's same-read receipt."""
    if raw is None:
        return None
    if (isinstance(raw, dict) and set(raw) == {"schema", "stage", "withheld_reason"} and
            raw["schema"] == CATEGORY_SCHEMA and raw["stage"] == CATEGORY_STAGE and
            isinstance(raw["withheld_reason"], str) and raw["withheld_reason"] in CATEGORY_WITHHELD):
        return _withheld_categories("binding-mismatch" if mismatch else raw["withheld_reason"])
    closed = _closed_categories(raw)
    if closed is None:
        return _withheld_categories("binding-mismatch" if mismatch else "invalid-observation")
    observed = _observation_receipt(receipt)
    if (mismatch or closed["system"] != system or closed["scenario"] != scenario or
            observed is None or observed != closed["receipt"] or
            isinstance(receipt_error, str) and receipt_error in _CATEGORY_RECEIPT_ERRORS or
            not _inventory_binds(inventory, raw_inventory, closed["receipt"]["bytes"])):
        return _withheld_categories("binding-mismatch")
    return closed


def _unavailable_inner(read_error, withheld_reason, byte_count=None):
    return {
        "stage": INNER_STAGE,
        "bytes": byte_count,
        "sha256": None,
        "complete": False,
        "read_error": read_error,
        "line_count": None,
        "utf8_valid": None,
        "tokens": [],
        "tokens_omitted": 0,
        "withheld_reason": withheld_reason,
    }


def read_inner_stderr(directory, platform, scenario):
    """Physical no-follow descriptor read of original inner application stderr.

    `complete` means only that this bounded regular-file read finished; the released
    harness writes `<platform>-<scenario>.stderr.log` after the child exit wait without
    proving child-pipe EOF.
    """
    directory = Path(directory)
    try:
        if any(p.is_symlink() for p in (directory, *directory.parents)):
            return _unavailable_inner("symlink", "symlink")
        dir_fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    except FileNotFoundError:
        return _unavailable_inner("missing", "missing")
    except OSError:
        return _unavailable_inner("read-error", "read-error")
    try:
        name = f"{platform}-{scenario}.stderr.log"
        try:
            linfo = os.lstat(name, dir_fd=dir_fd)
        except FileNotFoundError:
            return _unavailable_inner("missing", "missing")
        except OSError:
            return _unavailable_inner("read-error", "read-error")
        if stat.S_ISLNK(linfo.st_mode):
            return _unavailable_inner("symlink", "symlink")
        if not stat.S_ISREG(linfo.st_mode):
            return _unavailable_inner("nonregular", "nonregular")
        try:
            fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=dir_fd)
            with os.fdopen(fd, "rb") as stream:
                info = os.fstat(stream.fileno())
                if not stat.S_ISREG(info.st_mode):
                    return _unavailable_inner("nonregular", "nonregular")
                if info.st_size > MAX_BYTES:
                    return _unavailable_inner("oversize", "oversize", byte_count=info.st_size)
                raw = stream.read(MAX_BYTES + 1)
        except OSError:
            return _unavailable_inner("read-error", "read-error")
        if len(raw) > MAX_BYTES:
            return _unavailable_inner("oversize", "oversize", byte_count=len(raw))
    finally:
        os.close(dir_fd)
    classified = _classify_stream(raw, stage=INNER_STAGE, complete=True)
    return {
        "stage": INNER_STAGE,
        "bytes": classified["bytes"],
        "sha256": classified["sha256"],
        "complete": True,
        "read_error": None,
        "line_count": classified["line_count"],
        "utf8_valid": classified["utf8_valid"],
        "tokens": classified["tokens"],
        "tokens_omitted": classified["tokens_omitted"],
        "withheld_reason": classified["withheld_reason"],
    }


def validate_inner_stream_tokens(raw, *, inventory=None, mismatch=False, require_inventory=False):
    """Idempotent closed validator for original inner application stderr bound to evidence_inventory."""
    if not isinstance(raw, dict):
        return None
    fallback_reason = "binding-mismatch" if mismatch else "invalid-observation"
    expected_keys = {
        "stage", "bytes", "sha256", "complete", "read_error",
        "line_count", "utf8_valid", "tokens", "tokens_omitted", "withheld_reason",
    }
    if set(raw.keys()) != expected_keys or raw.get("stage") != INNER_STAGE:
        return _unavailable_inner(None, fallback_reason)
    byte_count = raw.get("bytes")
    sha256 = raw.get("sha256")
    complete = raw.get("complete")
    read_error = raw.get("read_error")
    line_count = raw.get("line_count")
    utf8_valid = raw.get("utf8_valid")
    tokens = raw.get("tokens")
    omitted = raw.get("tokens_omitted")
    reason = raw.get("withheld_reason")
    if type(complete) is not bool:
        return _unavailable_inner(None, fallback_reason)
    if complete:
        valid_complete = (
            read_error is None and
            type(byte_count) is int and 0 <= byte_count <= MAX_BYTES and
            isinstance(sha256, str) and bool(re.fullmatch(r"[0-9a-f]{64}", sha256)) and
            type(line_count) is int and 0 <= line_count <= MAX_BYTES and
            type(utf8_valid) is bool and
            isinstance(tokens, list) and len(tokens) <= MAX_TOKENS and
            all(isinstance(t, str) and t in TOKENS for t in tokens) and
            tokens == sorted(set(tokens)) and
            type(omitted) is int and 0 <= omitted <= len(TOKENS) - MAX_TOKENS and
            (omitted == 0 or reason is None and len(tokens) == MAX_TOKENS) and
            (reason is None or isinstance(reason, str) and reason in {"empty", "invalid-utf8", "private", "control-bytes", "unterminated"})
        )
        if not valid_complete:
            return _unavailable_inner(None, fallback_reason)
        if reason is None and (utf8_valid is not True or byte_count == 0):
            return _unavailable_inner(None, fallback_reason)
        if reason is not None:
            if tokens or omitted != 0:
                return _unavailable_inner(None, fallback_reason)
            if reason == "empty" and (byte_count != 0 or sha256 != digest(b"") or line_count != 0 or utf8_valid is not True):
                return _unavailable_inner(None, fallback_reason)
            if reason == "invalid-utf8" and (byte_count == 0 or utf8_valid is not False):
                return _unavailable_inner(None, fallback_reason)
            if reason in {"private", "control-bytes", "unterminated"} and (byte_count == 0 or utf8_valid is not True):
                return _unavailable_inner(None, fallback_reason)
    else:
        if (sha256 is not None or line_count is not None or utf8_valid is not None or
                tokens != [] or omitted != 0):
            return _unavailable_inner(None, fallback_reason)
        if isinstance(read_error, str) and read_error in INNER_READ_ERRORS and reason == read_error:
            if read_error == "oversize":
                if type(byte_count) is not int or not MAX_BYTES < byte_count <= 2**63 - 1:
                    return _unavailable_inner(None, fallback_reason)
            elif byte_count is not None:
                return _unavailable_inner(None, fallback_reason)
        elif read_error is None and isinstance(reason, str) and reason in {"invalid-observation", "binding-mismatch", "incomplete"} and byte_count is None:
            pass
        else:
            return _unavailable_inner(None, fallback_reason)
    if mismatch:
        return _unavailable_inner(None, "binding-mismatch")
    if require_inventory:
        inventory = validate_inventory(inventory)
    observed = isinstance(inventory, dict) and inventory.get("status") == "observed"
    if require_inventory and byte_count is not None and not observed:
        return _unavailable_inner(None, "binding-mismatch")
    if observed:
        err_art = next((a for a in inventory.get("artifacts", ()) if isinstance(a, dict) and a.get("kind") == "stderr.log"), None)
        if complete:
            if (err_art is None or err_art.get("regular") is not True or
                    err_art.get("symlink") is not False or err_art.get("bytes") != byte_count):
                return _unavailable_inner(None, "binding-mismatch")
        elif read_error == "missing":
            if err_art is not None:
                return _unavailable_inner(None, "binding-mismatch")
        elif read_error == "symlink":
            if err_art is not None and err_art.get("symlink") is not True:
                return _unavailable_inner(None, "binding-mismatch")
        elif read_error == "nonregular":
            if err_art is None or err_art.get("regular") is not False or err_art.get("symlink") is not False:
                return _unavailable_inner(None, "binding-mismatch")
        elif read_error == "oversize":
            if (err_art is None or err_art.get("regular") is not True or
                    err_art.get("symlink") is not False or err_art.get("bytes") != byte_count):
                return _unavailable_inner(None, "binding-mismatch")
    return {
        "stage": INNER_STAGE,
        "bytes": byte_count,
        "sha256": sha256,
        "complete": complete,
        "read_error": read_error,
        "line_count": line_count,
        "utf8_valid": utf8_valid,
        "tokens": list(tokens),
        "tokens_omitted": omitted,
        "withheld_reason": reason,
    }


def collect_failure_diagnostics(stderr, fields, evidence, platform, scenario, record=None, *, system=None, current071=False):
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
    if platform == "darwin-arm64" and scenario == "A":
        try:
            result["harness_run_record"] = project_run_record(
                record, fields.get("receipt"), receipt_error=fields.get("receipt_error")
            )
        except Exception:
            pass
        try:
            result["inner_stderr_diagnostic"] = read_inner_stderr(evidence, platform, scenario)
        except Exception:
            pass
    elif (all(isinstance(v, str) for v in (system, platform, scenario)) and
          (system, platform, scenario) in _CATEGORY_BINDINGS):
        # Linux B/C: same released <platform>-<scenario>.stderr.log; no retry, EOF or cause claim.
        try:
            result["inner_stderr_diagnostic"] = read_inner_stderr(evidence, platform, scenario)
        except Exception:  # noqa: BLE001, S110 - optional fault must not mask failure or log private payloads.
            pass
    try:
        categories = project_problem_categories(
            record, fields.get("receipt"), system=system, platform=platform, scenario=scenario,
            **({"current071": True} if current071 is True else {}),
        )
        if categories is not None:
            result["harness_problem_categories"] = categories
    except Exception:
        pass
    return result
