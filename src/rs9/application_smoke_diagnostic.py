"""Wheel-only bounded smoke failure records; raw process output is never retained."""
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import tempfile
import time
import signal

from rs9.errors import ContractError
from rs9.release_core import digest
from rs9.scratch import canonical
from rs9.security import scan_for_credentials

MAX_RECEIPT = 1024 * 1024
MAX_STREAM = 1024 * 1024
MAX_LOG = 64 * 1024
MAX_DIAGNOSTIC = 60 * 1024
CAUSE_CATEGORIES = frozenset({"process-timeout", "process-nonzero", "process-signal",
    "process-output-limit", "dbus-session-failure", "xvfb-failure", "display-unavailable",
    "socket-unavailable", "receipt-missing", "receipt-invalid", "receipt-corrupt",
    "receipt-malformed", "receipt-oversize", "receipt-failed", "harness-error", "process-cleanup-failure",
    "execution-source-unverified", "shared-library-missing", "webkit-crash", "assertion", "unknown"})
SAFE_LOG_CATEGORIES = frozenset({"dbus-session-conf-missing", "dbus-daemon-error",
    "xvfb-display-error", "xvfb-auth-error", "module-not-found", "command-not-found",
    "shared-library-missing", "webkit-crash", "assertion", "socket-unavailable", "unclassified"})
SAFE_FAILURE_ROLES = frozenset({"dbus-wrapper", "dbus-daemon", "dbus-config", "node",
    "smoke-script", "loader", "unknown"})
PROBE_COMMAND_TIMEOUT = 5
PROBE_TOTAL_TIMEOUT = 30
PROBE_CLEANUP_TIMEOUT = 1
PROBE_SCHEMA = "rs9.application-smoke-boundary-probes.v1"
# The released harness accepts --timeout-ms.  This value is reserved for the
# optional post-failure replay so the unchanged 240-second outer attempt still
# has time to reap the harness and retain its bounded evidence.
DIAGNOSTIC_REPLAY_HARNESS_TIMEOUT_MS = 180_000
# The current 0.7.1 required observation may ask the released harness to
# finish its own watchdog/finalization before the unchanged 240-second Python
# boundary. This is an owner-decision value; it does not alter the optional
# replay budget above.
CURRENT071_REQUIRED_HARNESS_TIMEOUT_MS = 210_000
CURRENT071_SIGNAL_HARNESS_TIMEOUT_MS = 180_000
REPLAY_SKIP_REASON_ORIGINAL_CLEANUP_UNPROVEN = "original-cleanup-unproven"
REPLAY_SKIP_REASON_ORIGINAL_HARNESS_NOT_PASSED = "original-harness-not-passed"
DIAGNOSTIC_REPLAY_TIMEOUT_TARGETS = frozenset({
    ("linux-arm64", "B"), ("linux-x64", "C"),
})
RELEASED_NATIVE_RC_SMOKE_SHA256 = "3d1eb991bd586dbb90e926049b516549e7518c0851c2e90ecbcc4e20838963f2"
RELEASED_NATIVE_RC_SNAPSHOT_SHA256 = "a85cd9e81602ddc585baa4164f98707debe5158d260130e489431e9ae699bbde"
CURRENT_REPLAY_PROGRESS_PROFILE = {'id': 'nebular070',
 'commit': 'cadb40c4972f68f314096ff60fbcfb4da950c161',
 'tree': '27c643b6375c2aafde314799c4f08e844c14992c',
 'modules': {'candidate-provenance.mjs': {'sha256': '20244b6765d6e7d0ee5fd86452096a4546f189103b0acb9f065c4a1479c23155',
                                          'blob': '129b0da16329d07697daab619f8fdbc5690f72fa',
                                          'size': 15484},
             'fs-snapshot.mjs': {'sha256': '30ad6c3f0394126a7d3e5534507fe46c78c34946edd15bd5c91b36e2b36df351',
                                 'blob': '841cfecd874517d0c619cf9a3866c2697e12ecd6',
                                 'size': 13794},
             'native-launcher.mjs': {'sha256': '3595cfaf0a2f1ac51a48862dc5f6aa842db6d3431a62159bcb93cb0abc812f2d',
                                     'blob': '9c84fff880957edcb98925bbaea941fc0f7e66fe',
                                     'size': 7193},
             'native-rc-package.mjs': {'sha256': '0ef948c2f9f45a9343586288681ae5ed6f6527b85912a52bd8c37aa50e3682c6',
                                       'blob': '570d4d2b6cee8551bb0d77417e54ee4a0d308ca8',
                                       'size': 33102},
             'native-rc-smoke.mjs': {'sha256': '874355e36496884e55a6e4dae6986ecde817d20863bb3fe26d1b1b5a1d283e69',
                                     'blob': 'cbf6a2148c11ed1516ba5d7fc2d4dd32dee3ee9f',
                                     'size': 30732},
             'native-runtime.mjs': {'sha256': 'a9d6c8e885b9db41877c5d2d79efe48f2e47daf791e0f1ad1ca06636d37d962e',
                                    'blob': '333192471147289f232bd915c6813ae23b39f1bb',
                                    'size': 118749},
             'platform-targets.mjs': {'sha256': '35321c7e888038210589612873136c96bf697789f6f4e90918442faa41e13aec',
                                      'blob': 'ebe518bbf27856c496541bca46bf13066805a606',
                                      'size': 7292}},
 'support': {'sha256': '15d3f118dfdc0014129fc37d63533a6a02cf355fdb89961a215eca77e95b7cd2',
             'blob': '161ee788b7a8660916e2b6fbbebbac0de4a87f42',
             'size': 1833}}
from rs9.current_os071 import CURRENT071_REPLAY_PROGRESS_PROFILE

REPLAY_PROGRESS_SCHEMA = "rs9.application-smoke-replay-progress.v1"
REPLAY_PROGRESS_MAX_BYTES = 16 * 1024
REPLAY_PROGRESS_MAX_EVENTS = 32
INITIAL_OBSERVATION_SCHEMA = "rs9.application-smoke-initial-observation.v1"
INITIAL_OBSERVATION_KIND = "initial-observation"
INITIAL_OBSERVATION_MAX_BYTES = 16 * 1024
INITIAL_OBSERVATION_MAX_STREAM_BYTES = 1024 * 1024
CURRENT_NIX_ENVIRONMENT_TRANSFORM_SCHEMA = "rs9.current-nix-smoke-environment-transform.v1"
CURRENT_NIX_ENVIRONMENT_TRANSFORM_ID = "current071-nix-inherited-xdg-fontconfig-v1"
CURRENT_NIX_ENVIRONMENT_EXECUTION_MODE = "execution-transform-and-observation"
CURRENT_NIX_EXECUTION_SOURCE_SCHEMA = "rs9.current-nix-execution-source-provenance.v1"
EXECUTION_SOURCE_UNVERIFIED_CAUSE = "execution-source-unverified"
CURRENT071_UPSTREAM_HARNESS_SHA256 = "874355e36496884e55a6e4dae6986ecde817d20863bb3fe26d1b1b5a1d283e69"
CURRENT071_UPSTREAM_HARNESS_BYTES = 30732
CURRENT071_DERIVED_HARNESS_SHA256 = "15b34fe8680f1df983be3f79b72404c78bc4c5506bf9f1943b5e9b24bc4f633f"
CURRENT071_DERIVED_HARNESS_BYTES = 30772
CURRENT_NIX_RESTORED_ENV_KEYS = ("XDG_DATA_DIRS", "FONTCONFIG_FILE")
_REQUIRED_OBSERVATION_COMPLETION_EVENTS = frozenset({
    ("candidate", "exited"), ("receipt", "finalized"),
    ("run-record", "finalized"), ("run-smoke", "returned"),
})
_OBSERVATION_FAILURE_EVENTS = frozenset({
    ("harness", "import-failed"), ("harness", "export-missing"),
    ("candidate", "launch-failed"), ("run-smoke", "error"),
    ("receipt", "write-failed"), ("run-record", "write-failed"),
})
EXPECTED_CURRENT_NIX_EXECUTION_TRANSFORM = {
    "schema": CURRENT_NIX_ENVIRONMENT_TRANSFORM_SCHEMA,
    "transform_id": CURRENT_NIX_ENVIRONMENT_TRANSFORM_ID,
    "mode": CURRENT_NIX_ENVIRONMENT_EXECUTION_MODE,
    "target_module": "native-rc-smoke.mjs",
    "upstream_sha256": CURRENT071_UPSTREAM_HARNESS_SHA256,
    "upstream_bytes": CURRENT071_UPSTREAM_HARNESS_BYTES,
    "executed_derived_sha256": CURRENT071_DERIVED_HARNESS_SHA256,
    "executed_derived_bytes": CURRENT071_DERIVED_HARNESS_BYTES,
    "restored_env_keys": list(CURRENT_NIX_RESTORED_ENV_KEYS),
    "modified_from_upstream": True,
    "non_admitting": True,
    "fhs_origin_proven": False,
    "native_qualified": False,
    "causal_attribution_proven": False,
}
REPLAY_PROGRESS_EVENTS = {
    ("harness", "import-start"), ("harness", "imported"),
    ("harness", "import-failed"), ("harness", "export-missing"),
    ("candidate", "launch-failed"), ("candidate", "launched"),
    ("candidate", "exited"), ("application", "release-smoke-active"), ("run-smoke", "enter"),
    ("run-smoke", "returned"), ("run-smoke", "error"),
    ("receipt", "write-start"), ("receipt", "finalized"),
    ("receipt", "write-failed"), ("run-record", "write-start"),
    ("run-record", "finalized"), ("run-record", "write-failed"),
}
INITIAL_ERROR_CATEGORIES = frozenset({
    "dbus-session-conf-missing", "dbus-daemon-error", "xvfb-display-error", "xvfb-auth-error",
    "module-not-found", "command-not-found", "shared-library-missing", "webkit-crash",
    "assertion", "socket-unavailable",
})
INITIAL_HELPER_IDENTIFIERS = frozenset({"dbus-run-session", "dbus-daemon", "node", "native-rc-smoke.mjs"})
INITIAL_ENV_KEYS = (
    "LD_LIBRARY_PATH", "XDG_DATA_DIRS", "GIO_EXTRA_MODULES", "GDK_PIXBUF_MODULE_FILE",
    "GSETTINGS_SCHEMA_DIR", "FONTCONFIG_FILE", "PATH", "DBUS_SESSION_BUS_ADDRESS", "DISPLAY",
)
INITIAL_CATEGORY_COUNT_MAX = 4096
RESOLUTION_MATCH_STREAMS = ("stderr", "stdout")
RESOLUTION_MATCH_TEMPLATES = (
    "failed-to-exec",
    "env-target",
    "command-not-found",
    "colon-not-found",
    "no-such-file-marker",
    "cannot-execute-marker",
    "exec-format-error-marker",
    "not-found-marker",
)
KNOWN_RESOLUTION_TARGET_BASENAMES = (
    "dbus-run-session", "dbus-daemon", "node", "native-rc-smoke.mjs",
)
RESOLUTION_TARGET_BASENAMES = (*KNOWN_RESOLUTION_TARGET_BASENAMES, "unknown")
MARKER_ONLY_RESOLUTION_TEMPLATES = frozenset({
    "no-such-file-marker",
    "cannot-execute-marker",
    "exec-format-error-marker",
    "not-found-marker",
})
RESOLUTION_MATCH_MAX_ENTRIES = 48
REPLAY_RECEIPT_PROJECTION_SCHEMA = "rs9.application-smoke-replay-receipt-stage.v1"
REPLAY_RECEIPT_MAX_STEPS = 64
REPLAY_LINUX_SCENARIOS = {"linux-arm64": "B", "linux-x64": "C"}
REPLAY_LINUX_TARGETS = {"linux-arm64": "aarch64-unknown-linux-gnu", "linux-x64": "x86_64-unknown-linux-gnu"}


def extract_log_categories(stdout, stderr, exit_code=None):
    """Closed observations, never guessed tool identity from a generic exit 127."""
    text = (stderr + b"\n" + stdout).lower()
    failure_tokens = (b"failed", b"error", b"no such", b"not found", b"refused")
    records = text.splitlines()
    categories = []
    if any(
        b"session.conf" in record
        and any(token in record for token in (b"no such", b"failed"))
        for record in records
    ):
        categories.append("dbus-session-conf-missing")
    elif any(
        (b"dbus-daemon" in record or b"dbus-run-session" in record)
        and any(token in record for token in failure_tokens)
        for record in records
    ):
        categories.append("dbus-daemon-error")
    patterns = {"xvfb-display-error": (b"cannot open display", b"xvfb failed", b"x server failed", b"xvfb-run: error"),
        "xvfb-auth-error": (b"xauth: error", b"authorization required", b"no protocol specified"),
        "module-not-found": (b"err_module_not_found", b"cannot find module"),
        "shared-library-missing": (b"error while loading shared libraries",),
        "webkit-crash": (b"webkitwebprocess crashed", b"webkit process crashed"),
        "assertion": (b"assertionerror", b"assertion failed"),
        "socket-unavailable": (b"failed to bind socket", b"socket: no such file", b"connection refused")}
    categories.extend(k for k, tokens in patterns.items() if any(t in text for t in tokens))
    if exit_code == 127:
        categories.append("command-not-found")
    return sorted(set(categories)) or ["unclassified"]


def classify_smoke_cause(*, exit_code=None, signal=None, timed_out=False, receipt_error=None,
                         log_categories=(), has_problems=False, receipt_status=None):
    if timed_out:
        return "process-timeout"
    if "dbus-session-conf-missing" in log_categories or "dbus-daemon-error" in log_categories:
        return "dbus-session-failure"
    if "xvfb-display-error" in log_categories or "xvfb-auth-error" in log_categories:
        return "xvfb-failure"
    for category in ("shared-library-missing", "webkit-crash", "assertion", "socket-unavailable"):
        if category in log_categories:
            return category
    if "module-not-found" in log_categories:
        return "harness-error"
    if signal is not None:
        return "process-signal"
    if exit_code is not None and exit_code < 0:
        return "process-signal"
    if exit_code:
        return "process-nonzero"
    if receipt_error:
        return receipt_error
    if has_problems or receipt_status not in (None, "pass"):
        return "receipt-failed"
    return "unknown"


def _role_for_target(target):
    """Map only a recognized failed-callee basename; never return the path."""
    cleaned = target.strip().strip(b"'\"")
    for quote in (b"\xe2\x80\x98", b"\xe2\x80\x99", b"\xe2\x80\x9c", b"\xe2\x80\x9d"):
        cleaned = cleaned.removeprefix(quote).removesuffix(quote)
    basename = cleaned.strip(b"'\"").rsplit(b"/", 1)[-1]
    return {
        b"dbus-run-session": "dbus-wrapper",
        b"dbus-daemon": "dbus-daemon",
        b"node": "node",
        b"native-rc-smoke.mjs": "smoke-script",
    }.get(basename)


def _resolution_role(text):
    """Read closed transient failure templates and return the failed callee role."""
    markers = (b"not found", b"no such file", b"cannot execute", b"exec format error")
    roles, saw_marker = set(), False
    for line in text.splitlines():
        line = line.strip()
        if b"failed to exec" in line:
            target = line.split(b"failed to exec", 1)[1].split(b":", 1)[0]
            roles.add(_role_for_target(target) or "unknown")
            continue
        if not any(marker in line for marker in markers):
            continue
        saw_marker = True
        if line.startswith((b"/usr/bin/env:", b"env:")):
            target = line.split(b":", 1)[1].split(b":", 1)[0]
            roles.add(_role_for_target(target) or "unknown")
            continue
        if b"command not found" in line or b": not found" in line:
            parts = line.split(b":")
            for index, part in enumerate(parts):
                if index > 0 and (b"command not found" in part or b"not found" in part):
                    roles.add(_role_for_target(parts[index - 1]) or "unknown")
                    break
            else:
                roles.add("unknown")
    if len(roles) == 1:
        return next(iter(roles))
    return "unknown" if roles or saw_marker else None


def _module_not_found_role(text):
    roles = set()
    for line in text.splitlines():
        if b"cannot find module" in line:
            target = line.split(b"cannot find module", 1)[1].split(b"imported from", 1)[0]
            roles.add("smoke-script" if _role_for_target(target) == "smoke-script" else "unknown")
    return "smoke-script" if roles == {"smoke-script"} else "unknown"


def _has_dbus_daemon_token(text):
    return re.search(rb"(?<![a-z0-9._-])dbus-daemon(?![a-z0-9._-])", text) is not None


def classify_failure_binding(stdout, stderr, exit_code=None, log_categories=()):
    """Classify a bounded failure into a safe role/phase binding."""
    text = (stderr + b"\n" + stdout).lower()
    categories = set(log_categories)
    if "dbus-session-conf-missing" in categories:
        return {"role": "dbus-config", "phase": "resolution", "evidence": "dbus-session-conf-missing"}
    if "shared-library-missing" in categories:
        return {"role": "loader", "phase": "loader", "evidence": "shared-library-missing"}
    role = _resolution_role(text)
    if role is not None:
        return {"role": role, "phase": "resolution", "evidence": "command-not-found"}
    if "dbus-daemon-error" in categories:
        role = "dbus-daemon" if _has_dbus_daemon_token(text) else "unknown"
        return {"role": role, "phase": "startup", "evidence": "dbus-daemon-error"}
    if "module-not-found" in categories:
        return {"role": _module_not_found_role(text), "phase": "module-resolution", "evidence": "module-not-found"}
    if exit_code == 127 or "command-not-found" in categories:
        return {"role": "unknown", "phase": "resolution", "evidence": "command-not-found"}
    if categories or exit_code not in (None, 0):
        return {"role": "unknown", "phase": "runtime", "evidence": "unclassified"}
    return None


def _target_basename_for_target(target):
    """Map only a recognized failed-callee basename or 'unknown'; never return the path."""
    if not target:
        return "unknown"
    cleaned = target.strip().strip(b"'\"")
    for quote in (b"\xe2\x80\x98", b"\xe2\x80\x99", b"\xe2\x80\x9c", b"\xe2\x80\x9d"):
        cleaned = cleaned.removeprefix(quote).removesuffix(quote)
    basename = cleaned.strip(b"'\"").rsplit(b"/", 1)[-1]
    return {
        b"dbus-run-session": "dbus-run-session",
        b"dbus-daemon": "dbus-daemon",
        b"node": "node",
        b"native-rc-smoke.mjs": "native-rc-smoke.mjs",
    }.get(basename, "unknown")


def _line_resolution_match(line):
    """Classify one lowercased line into a closed (template, target_basename) pair or None."""
    markers = (b"not found", b"no such file", b"cannot execute", b"exec format error")
    line = line.strip()
    if b"failed to exec" in line:
        target = line.split(b"failed to exec", 1)[1].split(b":", 1)[0]
        return "failed-to-exec", _target_basename_for_target(target)
    if not any(marker in line for marker in markers):
        return None
    if line.startswith((b"/usr/bin/env:", b"env:")):
        target = line.split(b":", 1)[1].split(b":", 1)[0]
        return "env-target", _target_basename_for_target(target)
    if b"command not found" in line or b": not found" in line:
        template = "command-not-found" if b"command not found" in line else "colon-not-found"
        parts = line.split(b":")
        for index, part in enumerate(parts):
            if index > 0 and (b"command not found" in part or b"not found" in part):
                return template, _target_basename_for_target(parts[index - 1])
        return template, "unknown"
    if b"no such file" in line:
        return "no-such-file-marker", "unknown"
    if b"cannot execute" in line:
        return "cannot-execute-marker", "unknown"
    if b"exec format error" in line:
        return "exec-format-error-marker", "unknown"
    return "not-found-marker", "unknown"


def extract_resolution_matches(stdout, stderr):
    """Extract closed resolution-match evidence separately over held outer stderr and stdout."""
    matches = []
    seen = set()
    for stream_name, raw_stream in (("stderr", stderr or b""), ("stdout", stdout or b"")):
        if not isinstance(raw_stream, (bytes, bytearray)):
            continue
        for raw_line in bytes(raw_stream).lower().splitlines():
            matched = _line_resolution_match(raw_line)
            if matched is None:
                continue
            template, target_basename = matched
            key = (stream_name, template, target_basename)
            if key in seen:
                continue
            seen.add(key)
            matches.append({
                "stream": stream_name,
                "template": template,
                "target_basename": target_basename,
            })
            if len(matches) >= RESOLUTION_MATCH_MAX_ENTRIES:
                return matches
    return matches


def validate_resolution_matches(raw, *, complete=True, mismatch=False):
    """Validate a closed list of resolution matches; withhold on incomplete, mismatch, or invalid shape."""
    if raw is None or not complete or mismatch or not isinstance(raw, list):
        return []
    if len(raw) == 0 or len(raw) > RESOLUTION_MATCH_MAX_ENTRIES:
        return []
    validated = []
    seen = set()
    for item in raw:
        if (not isinstance(item, dict)
                or set(item) != {"stream", "template", "target_basename"}
                or not isinstance(item.get("stream"), str)
                or item["stream"] not in RESOLUTION_MATCH_STREAMS
                or not isinstance(item.get("template"), str)
                or item["template"] not in RESOLUTION_MATCH_TEMPLATES
                or not isinstance(item.get("target_basename"), str)
                or item["target_basename"] not in RESOLUTION_TARGET_BASENAMES
                or (item["template"] in MARKER_ONLY_RESOLUTION_TEMPLATES
                    and item["target_basename"] != "unknown")):
            return []
        key = (item["stream"], item["template"], item["target_basename"])
        if key in seen:
            return []
        seen.add(key)
        validated.append({
            "stream": item["stream"],
            "template": item["template"],
            "target_basename": item["target_basename"],
        })
    return validated


def validate_problem_codes(problems):
    if not problems:
        return []
    if not isinstance(problems, (list, dict)):
        return ["withheld-token"]
    codes = []
    for item in list(problems)[:16]:
        if isinstance(item, dict):
            item = item.get("code")
        try:
            if not isinstance(item, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{0,63}", item):
                raise ValueError
            scan_for_credentials(item)
            codes.append(item)
        except (ValueError, ContractError):
            codes.append("withheld-token")
    return codes


def _read_regular(path, limit):
    """One no-follow bounded read; subsequent use never reopens the pathname."""
    meta = {"present": False}
    try:
        if path.is_symlink():
            return b"", {"present": True}, "invalid"
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(fd, "rb") as stream:
            info = os.fstat(stream.fileno())
            meta = {"present": True, "bytes": info.st_size}
            if not stat.S_ISREG(info.st_mode):
                return b"", meta, "invalid"
            if info.st_size > limit:
                return b"", meta, "oversize"
            raw = stream.read(limit + 1)
    except FileNotFoundError:
        return b"", meta, "missing"
    except OSError:
        return b"", meta, "invalid"
    if len(raw) > limit:
        return b"", meta, "oversize"
    return raw, {"present": True, "bytes": len(raw), "sha256": digest(raw)}, None


def _read_stable_json(path, limit):
    """Read one fixed evidence file through one no-follow FD and reject mutation."""
    meta = {"present": False}
    flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
    try:
        fd = os.open(path, flags)
    except FileNotFoundError:
        return None, meta, "missing"
    except OSError:
        return None, {"present": True}, "invalid"
    try:
        before = os.fstat(fd)
        meta = {"present": True, "bytes": before.st_size}
        if not stat.S_ISREG(before.st_mode):
            return None, meta, "invalid"
        if before.st_size > limit:
            return None, meta, "oversize"
        chunks = []
        total = 0
        while total <= limit:
            chunk = os.read(fd, min(65536, limit + 1 - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
        raw = b"".join(chunks)
        after = os.fstat(fd)
    except OSError:
        return None, meta, "invalid"
    finally:
        os.close(fd)
    stable = (
        before.st_dev == after.st_dev and before.st_ino == after.st_ino
        and before.st_mode == after.st_mode and before.st_size == after.st_size
        and before.st_mtime_ns == after.st_mtime_ns and before.st_ctime_ns == after.st_ctime_ns
        and len(raw) == before.st_size
    )
    if len(raw) > limit:
        return None, {"present": True, "bytes": len(raw)}, "oversize"
    meta = {"present": True, "bytes": len(raw), "sha256": digest(raw)}
    if not stable:
        return None, meta, "unstable"
    try:
        value = json.loads(raw)
    except (ValueError, UnicodeError, RecursionError):
        return None, meta, "malformed"
    if not isinstance(value, dict):
        return None, meta, "malformed"
    return value, meta, None


def _replay_expected_steps(scenario):
    """Read the maintained consumer step contract; no caller-supplied steps are accepted."""
    try:
        from rs9.tf_pypi_consumer import _NEBULAR_NATIVE_RC_STEPS
        steps = _NEBULAR_NATIVE_RC_STEPS.get(scenario)
    except (ImportError, AttributeError, TypeError):
        steps = None
    if not isinstance(steps, tuple) or not steps or any(not isinstance(step, str) for step in steps):
        return None
    return steps


def _closed_replay_value(value, allowed, fallback="unknown"):
    """Return only a scalar enum value; malformed JSON shapes stay observational."""
    return value if type(value) is str and value in allowed else fallback


def _project_replay_steps(raw_steps, expected):
    """Project only fixed expected step IDs and boolean pass/fail states."""
    if not isinstance(raw_steps, list):
        return {
            "steps": [{"id": step, "state": "unknown"} for step in expected],
            "entries_observed": 0, "entries_unlisted": 0, "entries_omitted": 0,
        }
    window = raw_steps[:REPLAY_RECEIPT_MAX_STEPS]
    seen = {}
    unlisted = 0
    expected_set = set(expected)
    for item in window:
        if not isinstance(item, dict) or not isinstance(item.get("id"), str) or item["id"] not in expected_set:
            unlisted += 1
            continue
        step_id = item["id"]
        if step_id in seen:
            seen[step_id] = "duplicate"
        else:
            ok = item.get("ok")
            seen[step_id] = "pass" if ok is True else "fail" if ok is False else "unknown"
    omitted = max(0, len(raw_steps) - REPLAY_RECEIPT_MAX_STEPS)
    default = "unknown" if omitted else "missing"
    return {
        "steps": [{"id": step, "state": seen.get(step, default)} for step in expected],
        "entries_observed": len(window), "entries_unlisted": unlisted, "entries_omitted": omitted,
    }


def _project_replay_receipt(record, identity, error, scenario, target, expected):
    status = _closed_replay_value(
        record.get("status") if isinstance(record, dict) else None, {"pass", "fail"})
    driver = record.get("driver") if isinstance(record, dict) else None
    driver_status = _closed_replay_value(
        driver.get("status") if isinstance(driver, dict) else None, {"pass", "fail"})
    executable = record.get("executable") if isinstance(record, dict) else None
    executable_sha = executable.get("sha256") if isinstance(executable, dict) else None
    valid = (
        isinstance(record, dict)
        and record.get("schema") == "nebular.release-smoke-receipt-v1"
        and record.get("scenario") == scenario
        and record.get("target") == target
        and status in {"pass", "fail"}
        and isinstance(driver, dict) and driver.get("scenario") == scenario
        and driver_status in {"pass", "fail"}
        and isinstance(executable_sha, str) and re.fullmatch(r"[0-9a-f]{64}", executable_sha)
    )
    steps = _project_replay_steps(driver.get("steps") if isinstance(driver, dict) else None, expected)
    return {
        "present": bool(identity.get("present")),
        "bytes": identity.get("bytes") if type(identity.get("bytes")) is int else None,
        "sha256": identity.get("sha256") if isinstance(identity.get("sha256"), str) else None,
        "valid": bool(valid), "read_error": error,
        "status": status, "driver_status": driver_status,
        "problem_codes": validate_problem_codes(record.get("problems") if isinstance(record, dict) else None),
        **steps,
    }


def _project_replay_run(record, identity, error, platform, scenario, expected):
    status = _closed_replay_value(
        record.get("status") if isinstance(record, dict) else None, {"pass", "fail"})
    run_receipt = record.get("receipt") if isinstance(record, dict) else None
    run_receipt_status = _closed_replay_value(
        run_receipt.get("status") if isinstance(run_receipt, dict) else None, {"pass", "fail"})
    finalization = record.get("finalization") if isinstance(record, dict) else None
    final_status = _closed_replay_value(
        finalization.get("status") if isinstance(finalization, dict) else None,
        {"complete", "fail", "failed", "partial"})
    final_phase = _closed_replay_value(
        finalization.get("phase") if isinstance(finalization, dict) else None,
        {"complete", "fail", "failed", "partial"})
    finalization_status = "complete" if final_status == "complete" and final_phase == "complete" else (
        "failed" if final_status in {"fail", "failed", "partial"} or final_phase in {"fail", "failed", "partial"}
        else "unknown")
    observation = finalization.get("applicationReceiptObservation") if isinstance(finalization, dict) else None
    observation = _closed_replay_value(observation, {"present-at-read", "missing-at-read"})
    copy_status = finalization.get("applicationReceiptCopy") if isinstance(finalization, dict) else None
    copy_status = _closed_replay_value(copy_status, {"written", "not-written"})
    try:
        from rs9.smoke_stream_tokens import _classify_problems
        problems = _classify_problems(record.get("problems") if isinstance(record, dict) else None)
    except (ImportError, AttributeError, TypeError):
        problems = {"categories": [], "total": None, "scanned": 0, "unrecognized": 0,
                    "non_string": 0, "unavailable": 1}
    derived_count = next((item["count"] for item in problems.get("categories", [])
                          if item.get("category") == "derived-asset-not-written"), 0)
    derived_status = "missing" if derived_count else "unobserved"
    return {
        "present": bool(identity.get("present")),
        "bytes": identity.get("bytes") if type(identity.get("bytes")) is int else None,
        "sha256": identity.get("sha256") if isinstance(identity.get("sha256"), str) else None,
        "valid": isinstance(record, dict) and record.get("schema") == "nebular.native-rc-smoke-run-v1"
            and record.get("scenario") == scenario and record.get("platform") == platform,
        "read_error": error, "status": status, "receipt_status": run_receipt_status,
        "finalization": {"status": finalization_status, "receipt_observation": observation, "receipt_copy": copy_status},
        "receipt": _project_replay_steps(run_receipt.get("steps") if isinstance(run_receipt, dict) else None, expected),
        "problem_categories": problems.get("categories", []),
        # The current run/receipt contract has no typed derived-output member;
        # preserve only the closed missing category and never infer a path/type/digest.
        "derived_output": {"status": derived_status, "type": None, "sha256": None},
    }


def _replay_projection_fallback(reason):
    """Typed non-authoritative fallback for faults in this optional observation."""
    return {
        "schema": REPLAY_RECEIPT_PROJECTION_SCHEMA,
        "status": "unavailable",
        "reason": reason,
        "qualification_authority": False,
        "application_qualified": False,
    }


def project_replay_receipt_stage(evidence, platform, scenario):
    """Read only the two released replay JSONs and emit a non-qualifying projection."""
    expected = _replay_expected_steps(scenario)
    expected_scenario = REPLAY_LINUX_SCENARIOS.get(platform)
    if (expected is None or expected_scenario is None or scenario not in {expected_scenario, "C-signal"}
            or scenario == "C-signal" and platform != "linux-x64"):
        return {"schema": REPLAY_RECEIPT_PROJECTION_SCHEMA, "status": "unavailable",
                "scenario": scenario if scenario in {"B", "C", "C-signal"} else "unknown",
                "reason": "unknown-scenario", "qualification_authority": False, "application_qualified": False}
    run, run_identity, run_error = _read_stable_json(
        Path(evidence) / f"{platform}-{scenario}.run.json", MAX_RECEIPT)
    receipt, receipt_identity, receipt_error = _read_stable_json(
        Path(evidence) / f"{platform}-{scenario}.receipt.json", MAX_RECEIPT)
    present = [bool(run_identity.get("present")), bool(receipt_identity.get("present"))]
    status = "observed" if all(present) else "partial" if any(present) else "unavailable"
    return {
        "schema": REPLAY_RECEIPT_PROJECTION_SCHEMA, "status": status, "platform": platform,
        "scenario": scenario,
        "run_record": _project_replay_run(run, run_identity, run_error, platform, scenario, expected),
        "receipt": _project_replay_receipt(
            receipt, receipt_identity, receipt_error, scenario, REPLAY_LINUX_TARGETS[platform], expected,
        ),
        "qualification_authority": False, "application_qualified": False,
    }


def _current_replay_progress_profile(prepared):
    """A closed current source observation profile, never a release capability."""
    if prepared.get("source_generation") != "theme-forge-current-202610":
        return None
    from rs9.hosted_smoke import verify_execution_source_readback
    try:
        verify_execution_source_readback(prepared)
        source = Path(prepared["source"])
        if Path(prepared["tools"]).resolve() != (source / "tools").resolve():
            return None
        package_raw, _, package_error = _read_regular(source / "package.json", 4 * 1024 * 1024)
        if package_error:
            return None
        version = json.loads(package_raw).get("version")
        profile = ({"0.7.0": CURRENT_REPLAY_PROGRESS_PROFILE,
                    "0.7.1": CURRENT071_REPLAY_PROGRESS_PROFILE}).get(version)
        if profile is None:
            return None
        pins = {"tools/" + name: pin for name, pin in profile["modules"].items()}
        pins["package.json"] = profile["support"]
        for name, pin in pins.items():
            raw, meta, error = _read_regular(source / name, 4 * 1024 * 1024)
            blob = hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest()
            if error or meta.get("sha256") != pin["sha256"] or len(raw) != pin["size"] or blob != pin["blob"]:
                return None
        if json.loads(raw).get("version") != version:
            return None
        return profile
    except (ContractError, OSError, ValueError, TypeError, KeyError):
        return None



def _current071_problem_projection(prepared, platform):
    """Recognize only the authenticated current Linux problem vocabulary."""
    if platform not in {"linux-arm64", "linux-x64"}:
        return False
    try:
        return _current_replay_progress_profile(prepared) == CURRENT071_REPLAY_PROGRESS_PROFILE
    except Exception:
        # Optional source observation cannot mask a fixed failed result or
        # suppress the other independent diagnostic projections.
        return False


def _replay_progress_wrapper(prepared):
    """Return the owned observer only for the authenticated harness pair."""
    tools = prepared.get("tools")
    if not isinstance(tools, (str, Path)):
        return None
    # ``source`` is the maintained Theme Forge checkout in the real Nix lane;
    # the observer is an RS9-owned module and therefore is not expected inside
    # that checkout.  Resolve the sibling from this authenticated module.
    candidate = Path(__file__).with_name("replay_progress_wrapper.mjs")
    harness = Path(tools) / "native-rc-smoke.mjs"
    snapshot = Path(tools) / "fs-snapshot.mjs"
    try:
        _raw, _meta, error = _read_regular(candidate, 4 * 1024 * 1024)
        if error:
            return None
        if prepared.get("source_generation") == "theme-forge-current-202610":
            return candidate if _current_replay_progress_profile(prepared) is not None else None
        raw, _meta, error = _read_regular(harness, 4 * 1024 * 1024)
        if error or digest(raw) != RELEASED_NATIVE_RC_SMOKE_SHA256:
            return None
        raw, _meta, error = _read_regular(snapshot, 4 * 1024 * 1024)
        if error or digest(raw) != RELEASED_NATIVE_RC_SNAPSHOT_SHA256:
            return None
        return candidate
    except OSError:
        return None


def _read_replay_progress(path):
    """Validate only fixed progress enums; never retain raw sink bytes."""
    raw, meta, error = _read_regular(path, REPLAY_PROGRESS_MAX_BYTES)
    if error:
        return {"status": "unobserved", "reason": "missing" if error == "missing" else error}
    try:
        lines = raw.splitlines()
        if not lines or len(lines) > REPLAY_PROGRESS_MAX_EVENTS:
            raise ValueError
        events = []
        for expected_seq, line in enumerate(lines, 1):
            record = json.loads(line)
            if not isinstance(record, dict) or set(record) != {"schema", "seq", "stage", "event"}:
                raise ValueError
            if record["schema"] != REPLAY_PROGRESS_SCHEMA or type(record["seq"]) is not int:
                raise ValueError
            if record["seq"] != expected_seq or (record["stage"], record["event"]) not in REPLAY_PROGRESS_EVENTS:
                raise ValueError
            events.append({"seq": expected_seq, "stage": record["stage"], "event": record["event"]})
    except (ValueError, TypeError, UnicodeError, RecursionError):
        return {"status": "unobserved", "reason": "invalid"}
    return {"status": "observed", "event_count": len(events), "events": events}


def _initial_observation_profile(profile):
    if not isinstance(profile, dict) or not isinstance(profile.get("modules"), dict):
        return None
    harness = profile["modules"].get("native-rc-smoke.mjs")
    if not isinstance(harness, dict):
        return None
    closure = {name: row.get("sha256") for name, row in profile["modules"].items()
               if isinstance(name, str) and isinstance(row, dict)}
    return {
        "id": profile.get("id"), "source_commit": profile.get("commit"),
        "source_tree": profile.get("tree"), "harness_sha256": harness.get("sha256"),
        "closure_sha256s": closure,
    }


def _unobserved_initial_observation(reason):
    return {"schema": INITIAL_OBSERVATION_SCHEMA, "status": "unobserved",
            "attempt_kind": INITIAL_OBSERVATION_KIND, "reason": reason,
            "non_admitting": True}


def _validate_initial_environment_presence(env_presence):
    """Validate optional current071 boolean environment presence; return None to withhold when malformed."""
    if not isinstance(env_presence, dict) or set(env_presence) != {"wrapper_entry", "first_spawn"}:
        return None
    validated = {}
    for stage_name in ("wrapper_entry", "first_spawn"):
        stage_env = env_presence[stage_name]
        if stage_env is None:
            validated[stage_name] = None
            continue
        if (not isinstance(stage_env, dict)
                or set(stage_env) != set(INITIAL_ENV_KEYS)
                or any(type(flag) is not bool for flag in stage_env.values())):
            return None
        validated[stage_name] = {key: stage_env[key] for key in INITIAL_ENV_KEYS}
    return validated


def _carrier_entry_matches(actual, expected_value):
    """Return whether one execution-transform field matches its exact typed contract."""
    if isinstance(expected_value, list):
        return (isinstance(actual, list)
                and [type(item) for item in actual] == [str] * len(expected_value)
                and actual == expected_value)
    return type(actual) is type(expected_value) and actual == expected_value


def _validate_current_nix_execution_transform(carrier):
    """Validate the closed non-admitting current-Nix environment transform carrier."""
    if not isinstance(carrier, dict) or set(carrier) != set(EXPECTED_CURRENT_NIX_EXECUTION_TRANSFORM):
        return None
    for key, expected_value in EXPECTED_CURRENT_NIX_EXECUTION_TRANSFORM.items():
        if not _carrier_entry_matches(carrier.get(key), expected_value):
            return None
    return {
        **EXPECTED_CURRENT_NIX_EXECUTION_TRANSFORM,
        "restored_env_keys": list(CURRENT_NIX_RESTORED_ENV_KEYS),
    }


def _project_restored_environment_presence(env_presence):
    """Project the two restored Nix keys from a validated nine-key observation map."""
    validated = _validate_initial_environment_presence(env_presence)
    if validated is None:
        return None
    return {
        stage_name: (
            None if stage_env is None
            else {key: stage_env[key] for key in CURRENT_NIX_RESTORED_ENV_KEYS}
        )
        for stage_name, stage_env in validated.items()
    }


def _restored_environment_stage_ok(projected_env, stage_name):
    """Return whether one stage recorded boolean True for both restored Nix env keys."""
    if not isinstance(projected_env, dict) or set(projected_env) != {"wrapper_entry", "first_spawn"}:
        return False
    stage_env = projected_env.get(stage_name)
    expected_stage = {key: True for key in CURRENT_NIX_RESTORED_ENV_KEYS}
    if stage_env != expected_stage:
        return False
    return all(type(stage_env[key]) is bool for key in CURRENT_NIX_RESTORED_ENV_KEYS)


def _stream_summary_untruncated(stream):
    """Return whether one initial-observation stream summary is a non-truncated dict."""
    return isinstance(stream, dict) and stream.get("truncated") is False


def _observation_streams_and_errors_clean(observation):
    """Return whether initial observation has zero observer faults and untruncated streams."""
    if not isinstance(observation, dict) or observation.get("truncated") is not False:
        return False
    counts = observation.get("error_counts")
    expected_zero = {"observer-fault": 0, "stream-fault": 0, "write-failure": 0}
    if counts != expected_zero or any(type(val) is not int for val in counts.values()):
        return False
    streams = observation.get("streams")
    if not isinstance(streams, dict) or set(streams) != {"stdout", "stderr"}:
        return False
    return (_stream_summary_untruncated(streams["stdout"])
            and _stream_summary_untruncated(streams["stderr"]))


def _observation_completion_events_present(observation):
    """Return whether all four finalization events are present without failure events."""
    events = observation.get("phase_events") if isinstance(observation, dict) else None
    if not isinstance(events, list):
        return False
    pairs = {(item.get("stage"), item.get("event")) for item in events if isinstance(item, dict)}
    return _REQUIRED_OBSERVATION_COMPLETION_EVENTS <= pairs and not (pairs & _OBSERVATION_FAILURE_EVENTS)


def _observation_envelope_failure(observation):
    """Return an initial-observation envelope error token, or None when readable."""
    if not isinstance(observation, dict):
        return "initial-observation-invalid"
    if observation.get("status") == "unobserved":
        reason = observation.get("reason")
        suffix = reason if isinstance(reason, str) and reason else "unobserved"
        return "initial-observation-" + suffix
    envelope = (
        observation.get("schema"),
        observation.get("attempt_kind"),
        observation.get("non_admitting") is True,
    )
    if envelope != (INITIAL_OBSERVATION_SCHEMA, INITIAL_OBSERVATION_KIND, True):
        return "initial-observation-invalid"
    return None


def _classify_current_nix_provenance_failure(observation, profile_matches, carrier, projected_env, *, require_completed):
    """Return the first fail-closed provenance failure reason, or None when verified."""
    envelope_error = _observation_envelope_failure(observation)
    if envelope_error is not None:
        return envelope_error
    allowed_statuses = {"completed"} if require_completed else {"completed", "failed"}
    checks = (
        (profile_matches, "source-profile-mismatch"),
        (carrier is not None, "execution-transform-mismatch"),
        (_observation_streams_and_errors_clean(observation), "observer-error-or-truncation"),
        (_restored_environment_stage_ok(projected_env, "wrapper_entry"), "wrapper-entry-environment-missing"),
        (_restored_environment_stage_ok(projected_env, "first_spawn"), "first-spawn-environment-missing"),
        (_observation_completion_events_present(observation), "initial-observation-incomplete"),
        (observation.get("status") in allowed_statuses, "initial-observation-not-completed"),
    )
    for ok, reason in checks:
        if not ok:
            return reason
    return None


def _evaluate_current_nix_execution_source(observation, expected_profile, *, require_completed):
    """Build the closed non-admitting current-Nix execution-source provenance summary."""
    expected_obs_profile = _initial_observation_profile(CURRENT071_REPLAY_PROGRESS_PROFILE)
    actual_profile = observation.get("source_profile") if isinstance(observation, dict) else None
    profile_matches = (
        expected_profile == CURRENT071_REPLAY_PROGRESS_PROFILE
        and actual_profile == expected_obs_profile
    )
    raw_carrier = observation.get("execution_transform") if isinstance(observation, dict) else None
    carrier = _validate_current_nix_execution_transform(raw_carrier)
    raw_env = observation.get("environment_presence") if isinstance(observation, dict) else None
    projected_env = _project_restored_environment_presence(raw_env)
    reason = _classify_current_nix_provenance_failure(
        observation, profile_matches, carrier, projected_env,
        require_completed=require_completed,
    )
    record = {
        "schema": CURRENT_NIX_EXECUTION_SOURCE_SCHEMA,
        "status": "verified" if reason is None else "failed",
        "non_admitting": True,
        "source_profile": _initial_observation_profile(CURRENT071_REPLAY_PROGRESS_PROFILE) if profile_matches else None,
        "execution_transform": carrier,
        "environment_presence": projected_env,
    }
    if reason is not None:
        record["reason"] = reason
    return record


def _validate_verified_execution_source(source_record):
    """Validate a closed verified current-Nix execution-source provenance record."""
    expected_keys = {
        "schema", "status", "non_admitting",
        "source_profile", "execution_transform", "environment_presence",
    }
    if not isinstance(source_record, dict) or set(source_record) != expected_keys:
        return None
    expected_profile = _initial_observation_profile(CURRENT071_REPLAY_PROGRESS_PROFILE)
    header = (
        source_record.get("schema"),
        source_record.get("status"),
        source_record.get("non_admitting") is True,
        source_record.get("source_profile"),
    )
    carrier = _validate_current_nix_execution_transform(source_record.get("execution_transform"))
    projected_env = source_record.get("environment_presence")
    stages_ok = (
        _restored_environment_stage_ok(projected_env, "wrapper_entry")
        and _restored_environment_stage_ok(projected_env, "first_spawn")
    )
    if header != (CURRENT_NIX_EXECUTION_SOURCE_SCHEMA, "verified", True, expected_profile):
        return None
    if carrier is None or not stages_ok:
        return None
    return {
        "schema": CURRENT_NIX_EXECUTION_SOURCE_SCHEMA,
        "status": "verified",
        "non_admitting": True,
        "source_profile": expected_profile,
        "execution_transform": carrier,
        "environment_presence": {
            "wrapper_entry": {key: True for key in CURRENT_NIX_RESTORED_ENV_KEYS},
            "first_spawn": {key: True for key in CURRENT_NIX_RESTORED_ENV_KEYS},
        },
    }


def _bind_attempt_execution_source(fields, initial_observation):
    """Attach and enforce fail-closed execution-source provenance on transformed attempts."""
    if not isinstance(initial_observation, dict):
        return
    if initial_observation.get("environment_transform") != CURRENT_NIX_ENVIRONMENT_TRANSFORM_ID:
        return
    process_failed = bool(
        fields.get("error")
        or fields.get("raw_returncode") != 0
        or fields.get("receipt_error")
        or fields.get("cleanup_error")
    )
    provenance = _evaluate_current_nix_execution_source(
        fields.get("initial_observation"),
        initial_observation.get("profile"),
        require_completed=not process_failed,
    )
    fields["execution_source"] = provenance
    if provenance["status"] != "verified" and not process_failed:
        fields["failed"] = True
        fields["cause"] = EXECUTION_SOURCE_UNVERIFIED_CAUSE
        fields["reason_token"] = EXECUTION_SOURCE_UNVERIFIED_CAUSE


def _scenario_run_projection(scenario, fields, *, environment_transform):
    """Build the public scenario smoke summary, requiring verified provenance when transformed."""
    run = {
        "scenario": scenario,
        "receipt_sha256": fields["receipt"]["sha256"],
        "executable_sha256": fields["receipt"]["executable_sha256"],
    }
    if not environment_transform:
        if "execution_source" in fields:
            raise ContractError("APPLICATION_SMOKE", "Unexpected current Nix execution provenance")
        return run
    verified = _validate_verified_execution_source(fields.get("execution_source"))
    if verified is None:
        raise ContractError("APPLICATION_SMOKE", "Verified current Nix execution provenance required")
    run["execution_source"] = verified
    return run


def _validate_initial_execution_transform(value, expected_profile, expected_execution_transform):
    """Validate expected vs actual execution-transform carrier on initial observation."""
    if type(expected_execution_transform) is not bool:
        raise ValueError("initial observation execution transform expectation")
    if not expected_execution_transform:
        if "execution_transform" in value:
            raise ValueError("unexpected initial observation execution transform")
        return
    profile = value["source_profile"]
    allowed_profile = (profile["id"], profile["harness_sha256"]) == (
        "nebular071", CURRENT071_UPSTREAM_HARNESS_SHA256
    )
    if expected_profile is not None:
        allowed_profile = allowed_profile and expected_profile == CURRENT071_REPLAY_PROGRESS_PROFILE
    validated = _validate_current_nix_execution_transform(value.get("execution_transform"))
    if not allowed_profile or validated is None:
        raise ValueError("invalid initial observation execution transform")
    value["execution_transform"] = validated


def _read_initial_observation(path, expected_profile=None, *, expected_execution_transform=False):
    """Read only the closed live-observation summary; never retain child bytes."""
    raw, _meta, error = _read_regular(path, INITIAL_OBSERVATION_MAX_BYTES)
    if error:
        return _unobserved_initial_observation("missing" if error == "missing" else error)
    try:
        text = raw.decode("utf-8")
        scan_for_credentials(text)
        value = json.loads(text)
        required = {"schema", "attempt_kind", "non_admitting", "status", "source_profile",
                    "phase_events", "error_counts", "error_category_counts", "helper_identifier_counts",
                    "streams", "truncated"}
        optional = {"environment_presence", "execution_transform"}
        if not isinstance(value, dict) or not (required <= set(value) <= (required | optional)):
            raise ValueError("initial observation fields")
        if (value["schema"] != INITIAL_OBSERVATION_SCHEMA
                or value["attempt_kind"] != INITIAL_OBSERVATION_KIND
                or value["non_admitting"] is not True
                or value["status"] not in {"observing", "partial", "completed", "failed"}
                or type(value["truncated"]) is not bool):
            raise ValueError("initial observation identity")
        profile = value["source_profile"]
        profile_keys = {"id", "source_commit", "source_tree", "harness_sha256", "closure_sha256s"}
        if (not isinstance(profile, dict) or set(profile) != profile_keys
                or not all(isinstance(profile[key], str) for key in profile_keys - {"closure_sha256s"})
                or not re.fullmatch(r"[0-9a-f]{64}", profile["harness_sha256"])
                or not isinstance(profile["closure_sha256s"], dict)
                or len(profile["closure_sha256s"]) > 8
                or any(not isinstance(name, str) or not re.fullmatch(r"[A-Za-z0-9._-]+\.mjs", name)
                       or not isinstance(sha, str) or not re.fullmatch(r"[0-9a-f]{64}", sha)
                       for name, sha in profile["closure_sha256s"].items())):
            raise ValueError("initial observation source profile")
        events = value["phase_events"]
        if not isinstance(events, list) or len(events) > REPLAY_PROGRESS_MAX_EVENTS:
            raise ValueError("initial observation phase bound")
        for expected_seq, event in enumerate(events, 1):
            if (not isinstance(event, dict) or set(event) != {"seq", "stage", "event"}
                    or event["seq"] != expected_seq or type(event["seq"]) is not int
                    or (event["stage"], event["event"]) not in REPLAY_PROGRESS_EVENTS):
                raise ValueError("initial observation phase")
        counts = value["error_counts"]
        if (not isinstance(counts, dict) or set(counts) != {"observer-fault", "stream-fault", "write-failure"}
                or any(type(item) is not int or item < 0 for item in counts.values())):
            raise ValueError("initial observation errors")
        categories = value["error_category_counts"]
        if (not isinstance(categories, dict) or set(categories) != INITIAL_ERROR_CATEGORIES
                or any(type(item) is not int or not 0 <= item <= INITIAL_CATEGORY_COUNT_MAX
                       for item in categories.values())):
            raise ValueError("initial observation error categories")
        helpers = value["helper_identifier_counts"]
        if (not isinstance(helpers, dict) or set(helpers) != INITIAL_HELPER_IDENTIFIERS
                or any(type(item) is not int or not 0 <= item <= INITIAL_CATEGORY_COUNT_MAX
                       for item in helpers.values())):
            raise ValueError("initial observation helper identifiers")
        streams = value["streams"]
        stream_keys = {"bytes_seen", "bytes_hashed", "sha256", "truncated"}
        if not isinstance(streams, dict) or set(streams) != {"stdout", "stderr"}:
            raise ValueError("initial observation streams")
        for stream in streams.values():
            if (not isinstance(stream, dict) or set(stream) != stream_keys
                    or type(stream["bytes_seen"]) is not int
                    or type(stream["bytes_hashed"]) is not int
                    or stream["bytes_seen"] < 0
                    or stream["bytes_seen"] > INITIAL_OBSERVATION_MAX_STREAM_BYTES + 1
                    or stream["bytes_hashed"] < 0
                    or stream["bytes_hashed"] > INITIAL_OBSERVATION_MAX_STREAM_BYTES
                    or stream["bytes_hashed"] > stream["bytes_seen"]
                    or not re.fullmatch(r"[0-9a-f]{64}", stream["sha256"])
                    or type(stream["truncated"]) is not bool):
                raise ValueError("initial observation stream")
        if "environment_presence" in value:
            if profile["id"] != "nebular071":
                raise ValueError("initial observation environment presence profile")
            validated_env = _validate_initial_environment_presence(value["environment_presence"])
            if validated_env is None:
                value.pop("environment_presence", None)
            else:
                value["environment_presence"] = validated_env
        if expected_profile is not None and profile != _initial_observation_profile(expected_profile):
            return _unobserved_initial_observation("source-binding-mismatch")
        _validate_initial_execution_transform(value, expected_profile, expected_execution_transform)
        return value
    except (ContractError, UnicodeError, ValueError, TypeError, json.JSONDecodeError, RecursionError):
        return _unobserved_initial_observation("invalid")


def _current071_initial_timeout_ms(platform, scenario):
    """Return the bounded inner budget for an authenticated current071 lane."""
    return {
        ("linux-arm64", "B"): CURRENT071_REQUIRED_HARNESS_TIMEOUT_MS,
        ("linux-x64", "C"): CURRENT071_REQUIRED_HARNESS_TIMEOUT_MS,
        ("linux-x64", "C-signal"): CURRENT071_SIGNAL_HARNESS_TIMEOUT_MS,
    }.get((platform, scenario))


def _original_attempt_finalization_clean(fields, allowed_statuses):
    """Return whether the initial attempt exited and recorded all four finalization events."""
    if not isinstance(fields, dict):
        return False
    attempt_state = (
        fields.get("error"),
        (type(fields.get("stream_capture_complete")), fields.get("stream_capture_complete")),
        fields.get("raw_returncode") is not None,
        fields.get("cleanup_error"),
    )
    if attempt_state != (None, (bool, True), True, None):
        return False
    observation = fields.get("initial_observation")
    if not isinstance(observation, dict) or observation.get("status") not in allowed_statuses:
        return False
    events = {
        (item.get("stage"), item.get("event"))
        for item in observation.get("phase_events", [])
        if isinstance(item, dict)
    }
    return _REQUIRED_OBSERVATION_COMPLETION_EVENTS <= events


def _original_replay_cleanup_proven(fields):
    """Allow a follow-up replay only after source-owned finalization completed."""
    if not _original_attempt_finalization_clean(fields, {"completed"}):
        return False
    # This is only a replay-scheduling guard. It is not a claim that arbitrary
    # descendants outside the harness candidate-root scan are absent.
    return "execution_source" not in fields


def _original_replay_skip_reason(fields):
    """Return the bounded reason for suppressing a current071 replay."""
    if _original_replay_cleanup_proven(fields):
        return None
    if _original_attempt_finalization_clean(fields, {"failed", "completed"}):
        # The harness reached its terminal failed result; conservative
        # replay suppression remains in force without mislabeling cleanup.
        return REPLAY_SKIP_REASON_ORIGINAL_HARNESS_NOT_PASSED
    return REPLAY_SKIP_REASON_ORIGINAL_CLEANUP_UNPROVEN


def read_and_validate_receipt(path, command_details):
    raw, meta, error = _read_regular(path, MAX_RECEIPT)
    command_details["receipt_identity"] = meta
    if error:
        return None, "receipt-" + error, []
    try:
        record = json.loads(raw)
    except (ValueError, UnicodeError, RecursionError):
        return None, "receipt-corrupt", []
    if not isinstance(record, dict):
        return None, "receipt-malformed", []
    codes = validate_problem_codes(record.get("problems"))
    exe = record.get("executable")
    if not isinstance(exe, dict) or not isinstance(exe.get("sha256"), str) or not re.fullmatch(r"[0-9a-f]{64}", exe["sha256"]):
        return record, "receipt-malformed", codes
    if record.get("status") != "pass" or record.get("problems"):
        return record, "receipt-failed", codes
    return record, None, codes


def sanitize_receipt_summary(record, identity=None):
    """Keep only validated values and the identity captured by the original descriptor."""
    result = dict(identity) if isinstance(identity, dict) else {}
    if record is None:
        return result
    status = record.get("status")
    result["status"] = status if isinstance(status, str) and status in {"pass", "fail"} else "unknown"
    result["problem_codes"] = validate_problem_codes(record.get("problems"))
    probs = record.get("problems")
    result["problem_count"] = len(probs) if isinstance(probs, (list, dict)) else int(bool(probs))
    exe = record.get("executable")
    sha = exe.get("sha256") if isinstance(exe, dict) else None
    if isinstance(sha, str) and re.fullmatch(r"[0-9a-f]{64}", sha):
        result["executable_sha256"] = sha
    return result


def _bounded_run(argv, *, env, timeout, cleanup_timeout=10):
    """Cap replay capture; report group cleanup separately from child status."""
    with tempfile.TemporaryFile() as out, tempfile.TemporaryFile() as err:
        child = subprocess.Popen(argv, env=env, stdin=subprocess.DEVNULL, stdout=out,
                                 stderr=err, start_new_session=True)
        deadline, error, cleanup_error = time.monotonic() + timeout, None, None
        try:
            while child.poll() is None:
                if max(os.fstat(out.fileno()).st_size, os.fstat(err.fileno()).st_size) > MAX_STREAM:
                    error = "process-output-limit"
                    break
                if time.monotonic() >= deadline:
                    error = "process-timeout"
                    break
                time.sleep(0.02)
        finally:
            try:
                os.killpg(child.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            except PermissionError:
                cleanup_error = "process-group-permission-denied"
            try:
                child.wait(timeout=cleanup_timeout)
            except subprocess.TimeoutExpired:
                cleanup_error = "process-reap-timeout"
        sizes = (os.fstat(out.fileno()).st_size, os.fstat(err.fileno()).st_size)
        out.seek(0); err.seek(0)
        result = subprocess.CompletedProcess(argv, child.returncode, out.read(MAX_STREAM), err.read(MAX_STREAM))
        result.capture_error = error or ("process-output-limit" if max(sizes) > MAX_STREAM else None)
        result.cleanup_error = cleanup_error
        result.child_reaped = child.returncode is not None
        result.stream_sizes = sizes
        return result


def _probe_output_shape(label, raw):
    """Retain only a fixed output shape; probe bytes are never serialized."""
    if label == "node-direct":
        if len(raw) <= 64 and re.fullmatch(rb"[0-9]+\.[0-9]+\.[0-9]+\r?\n?", raw):
            return "node-semver"
        return "unexpected"
    return "empty" if not raw else "unexpected"


def _probe_remaining(started):
    return PROBE_TOTAL_TIMEOUT - (time.monotonic() - started)


def _unstarted_boundary_probe(probe, reason):
    label, argv, role, expected_shape, expected_child = probe
    result = {
        "label": label,
        "role": role,
        "expected_child": expected_child,
        "expected_output": expected_shape,
        "status": "unavailable",
        "reason": reason,
        "qualification_authority": False,
        "application_qualified": False,
        "not_started": True,
    }
    if argv is not None:
        result["argv_sha256"] = digest(b"\0".join(arg.encode() for arg in argv))
    return result


def _boundary_probe_record(probe):
    label, argv, role, expected_shape, expected_child = probe
    result = {
        "label": label,
        "role": role,
        "expected_child": expected_child or role,
        "expected_output": expected_shape,
        "argv_sha256": digest(b"\0".join(arg.encode() for arg in argv)),
        "qualification_authority": False,
        "application_qualified": False,
    }
    return result


def _boundary_probe_execution(probe, prefix, env, started):
    _, argv, _, _, _ = probe
    remaining = _probe_remaining(started)
    if remaining <= 0:
        return None, "probe-total-deadline"
    try:
        completed = _bounded_run([*prefix, *argv], env=env,
                                 timeout=min(PROBE_COMMAND_TIMEOUT, remaining),
                                 cleanup_timeout=PROBE_CLEANUP_TIMEOUT)
    except (OSError, subprocess.SubprocessError, TypeError, ValueError):
        return None, "probe-execution-failed"
    return completed, None


def _boundary_probe_reason(completed, shape, expected_shape):
    returncode = completed.returncode
    capture_error = getattr(completed, "capture_error", None)
    cleanup_error = getattr(completed, "cleanup_error", None)
    child_reaped = getattr(completed, "child_reaped", None)
    if cleanup_error:
        return "process-cleanup-failure"
    if child_reaped is not True:
        return "process-reap-unconfirmed"
    if capture_error:
        return capture_error
    if returncode is not None and returncode < 0:
        return "process-signal"
    if returncode != 0:
        return "process-nonzero"
    if shape != expected_shape:
        return "unexpected-output"
    return None


def _boundary_probe_streams(completed):
    stdout = completed.stdout or b""
    stderr = completed.stderr or b""
    sizes = getattr(completed, "stream_sizes", None)
    stdout_bytes = sizes[0] if isinstance(sizes, tuple) and len(sizes) == 2 else len(stdout)
    stderr_bytes = sizes[1] if isinstance(sizes, tuple) and len(sizes) == 2 else len(stderr)
    return stdout, stderr, stdout_bytes, stderr_bytes


def _boundary_probe_snapshot(probe, completed):
    label, _, _, expected_shape, _ = probe
    stdout, stderr, stdout_bytes, stderr_bytes = _boundary_probe_streams(completed)
    returncode = completed.returncode
    shape = _probe_output_shape(label, stdout)
    capture_error = getattr(completed, "capture_error", None)
    cleanup_error = getattr(completed, "cleanup_error", None)
    child_reaped = getattr(completed, "child_reaped", None)
    reason = _boundary_probe_reason(completed, shape, expected_shape)
    status = "pass" if (returncode == 0 and capture_error is None and cleanup_error is None
                         and child_reaped is True and shape == expected_shape) else "fail"
    result = {
        "status": status,
        "exit_code": returncode if isinstance(returncode, int) and returncode >= 0 else None,
        "signal": -returncode if isinstance(returncode, int) and returncode < 0 else None,
        "stdout_bytes": stdout_bytes,
        "stderr_bytes": stderr_bytes,
        "stdout_sha256": digest(stdout),
        "stderr_sha256": digest(stderr),
        "output_shape": shape,
        "stream_capture_complete": capture_error not in {"process-output-limit", "process-timeout", "harness-error"},
        "cleanup_error": cleanup_error,
        "child_reaped": child_reaped,
        "_stop_following": bool(cleanup_error or child_reaped is not True),
    }
    if reason is not None:
        result["reason"] = reason
    return result


def _run_boundary_probe(probe, prefix, env, started):
    """Run one fixed child in the caller's exact FHS prefix and environment."""
    result = _boundary_probe_record(probe)
    completed, execution_error = _boundary_probe_execution(probe, prefix, env, started)
    if completed is None:
        result.update(status="unavailable", reason=execution_error)
        if execution_error == "probe-total-deadline":
            result["not_started"] = True
        return result
    result.update(_boundary_probe_snapshot(probe, completed))
    return result


def _discover_pinned_session_bus(*, prefix, env, started):
    """Resolve the pinned DBus store root inside the same FHS boundary."""
    remaining = _probe_remaining(started)
    if remaining <= 0:
        return None, "probe-total-deadline"
    try:
        result = _bounded_run([*prefix, "sh", "-c", "command -v dbus-run-session"],
                              env=env, timeout=min(PROBE_COMMAND_TIMEOUT, remaining),
                              cleanup_timeout=PROBE_CLEANUP_TIMEOUT)
    except (OSError, subprocess.SubprocessError, TypeError, ValueError):
        return None, None
    if getattr(result, "cleanup_error", None):
        return None, "process-cleanup-failure"
    if getattr(result, "child_reaped", None) is not True:
        return None, "process-reap-unconfirmed"
    raw = result.stdout or b""
    if (result.returncode != 0 or getattr(result, "capture_error", None) is not None
            or len(raw) > 512 or not re.fullmatch(
                rb"/nix/store/[0-9a-df-np-sv-z]{32}-[A-Za-z0-9+._-]+/bin/dbus-run-session\r?\n?", raw)):
        return None, None
    run_session = raw.rstrip(b"\r\n").decode("ascii")
    root = run_session[:-len("/bin/dbus-run-session")]
    try:
        from rs9.nix_proot_dbus_command import validate_session_bus_argv
        return validate_session_bus_argv([
            run_session,
            "--dbus-daemon=" + root + "/bin/dbus-daemon",
            "--config-file=" + root + "/share/dbus-1/session.conf",
            "--",
        ]), None
    except (ContractError, UnicodeError):
        return None, None


def _boundary_probe_plan(pinned_bus):
    """Build fixed probe argv; only the validated pinned argv may enter the plan."""
    default_bus = ["dbus-run-session", "--"]
    display_child = ["sh", "-c", 'test -n "$DISPLAY"']
    dbus_child = ["sh", "-c", 'test -n "$DBUS_SESSION_BUS_ADDRESS"']
    node_child = ["node", "-e", "process.exit(process.env.DBUS_SESSION_BUS_ADDRESS ? 0 : 2)"]
    plan = [
        ("display-wrapper", ["xvfb-run", "-a", *display_child], "display-wrapper", "empty", "xvfb-run+sh"),
        ("dbus-default", [*default_bus, *dbus_child], "dbus-default", "empty", "dbus-run-session+sh"),
        ("node-direct", ["node", "-p", "process.versions.node"], "node-direct", "node-semver", "node"),
        ("dbus-node", [*(pinned_bus or default_bus), *node_child], "dbus-node", "empty", "dbus-run-session+node"),
    ]
    if pinned_bus is not None:
        plan.insert(2, ("dbus-pinned", [*pinned_bus, *dbus_child], "dbus-pinned", "empty",
                         "dbus-run-session+dbus-daemon+session.conf+sh"))
    return plan, pinned_bus is not None


def run_boundary_probes(*, prefix=(), env=None, session_bus_argv=None):
    """Run non-qualifying display/DBus/Node boundary controls after a failed smoke."""
    started = time.monotonic()
    pinned_source = "unavailable"
    pinned_bus = None
    discovery_stop_reason = None
    if session_bus_argv is not None:
        try:
            from rs9.nix_proot_dbus_command import validate_session_bus_argv
            pinned_bus = validate_session_bus_argv(session_bus_argv)
            pinned_source = "caller"
        except ContractError:
            pinned_bus = None
    else:
        pinned_bus, discovery_stop_reason = _discover_pinned_session_bus(
            prefix=prefix, env=env, started=started)
        if pinned_bus is not None:
            pinned_source = "same-fhs-command-v"
    plan, pinned_available = _boundary_probe_plan(pinned_bus)
    if not pinned_available:
        plan.insert(2, ("dbus-pinned", None, "dbus-pinned", "empty",
                        "dbus-run-session+dbus-daemon+session.conf+sh"))
    rows = []
    for probe in plan:
        label, argv, role, expected_shape, expected_child = probe
        if discovery_stop_reason is not None:
            rows.append(_unstarted_boundary_probe(probe, discovery_stop_reason))
            continue
        if argv is None:
            rows.append(_unstarted_boundary_probe(probe, "pinned-argv-unavailable"))
            continue
        if _probe_remaining(started) <= 0:
            discovery_stop_reason = "probe-total-deadline"
            rows.append(_unstarted_boundary_probe(probe, discovery_stop_reason))
            continue
        row = _run_boundary_probe(probe, prefix, env, started)
        stop_following = row.pop("_stop_following", False)
        rows.append(row)
        if stop_following:
            discovery_stop_reason = row.get("reason", "process-cleanup-failure")
    return {
        "schema": PROBE_SCHEMA,
        "status": "incomplete" if discovery_stop_reason is not None else "complete",
        "command_timeout_seconds": PROBE_COMMAND_TIMEOUT,
        "total_timeout_seconds": PROBE_TOTAL_TIMEOUT,
        "cleanup_timeout_seconds": PROBE_CLEANUP_TIMEOUT,
        "execution_budget_only": True,
        "wall_clock_bound_includes_cleanup": False,
        "execution_budget_exhausted": discovery_stop_reason == "probe-total-deadline",
        "elapsed_ms": int((time.monotonic() - started) * 1000),
        "probe_count": len(rows),
        "pinned_argv_available": pinned_available,
        "pinned_argv_source": pinned_source,
        "qualification_authority": False,
        "application_qualified": False,
        "stop_reason": discovery_stop_reason,
        "probes": rows,
    }


def _initial_observation_transform_args(initial_observation, profile, platform, scenario):
    """Return validated wrapper args for the optional current-Nix environment transform."""
    transform = initial_observation.get("environment_transform")
    if transform is None:
        return []
    if transform != CURRENT_NIX_ENVIRONMENT_TRANSFORM_ID:
        raise ContractError("APPLICATION_SMOKE", "Unsupported current Nix environment transform")
    if profile != CURRENT071_REPLAY_PROGRESS_PROFILE:
        raise ContractError("APPLICATION_SMOKE", "Current Nix environment transform requires current 0.7.1 profile")
    if (platform, scenario) not in {("linux-arm64", "B"), ("linux-x64", "C"), ("linux-x64", "C-signal")}:
        raise ContractError("APPLICATION_SMOKE", "Current Nix environment transform requires current Linux scenario")
    return ["--rs9-current-nix-environment-transform", transform]


def _resolve_initial_observation_source(prepared, system, *, environment_transform=False):
    """Authenticate the current source profile and wrapper for initial observation."""
    if not system.endswith("-linux"):
        raise ContractError("APPLICATION_SMOKE", "Initial observation is Linux-only")
    wrapper = _replay_progress_wrapper(prepared)
    profile = _current_replay_progress_profile(prepared) if wrapper else None
    if profile is None:
        raise ContractError("APPLICATION_SMOKE", "Authenticated initial-observation source is unavailable")
    if environment_transform and profile != CURRENT071_REPLAY_PROGRESS_PROFILE:
        raise ContractError(
            "APPLICATION_SMOKE",
            "Current Nix environment transform requires current 0.7.1 source profile",
        )
    return wrapper, profile


def _build_initial_observation_descriptor(
    prepared, system, platform, scenario, evidence, *, enabled, environment_transform=False
):
    """Build and validate the optional initial-observation descriptor for one scenario."""
    if type(environment_transform) is not bool:
        raise ContractError("APPLICATION_SMOKE", "Invalid current Nix environment transform option")
    if not enabled:
        if environment_transform:
            raise ContractError(
                "APPLICATION_SMOKE",
                "Current Nix environment transform requires diagnostic initial observation",
            )
        return None
    wrapper, profile = _resolve_initial_observation_source(
        prepared, system, environment_transform=environment_transform)
    descriptor = {
        "wrapper": wrapper,
        "harness": prepared["tools"] / "native-rc-smoke.mjs",
        "progress": evidence / (platform + "-" + scenario + ".initial-progress.jsonl"),
        "path": evidence / (platform + "-" + scenario + ".initial-observation.json"),
        "profile": profile,
        "harness_timeout_ms": (_current071_initial_timeout_ms(platform, scenario)
                                if profile.get("id") == "nebular071" else None),
    }
    if environment_transform:
        descriptor["environment_transform"] = CURRENT_NIX_ENVIRONMENT_TRANSFORM_ID
    return descriptor


def _command(prepared, platform, scenario, launch_root, evidence, *, extras,
             session_bus_argv=None, harness_timeout_ms=None, replay_progress=None,
             initial_observation=None):
    if session_bus_argv is not None:
        from rs9.nix_proot_dbus_command import validate_session_bus_argv
        session_bus_argv = validate_session_bus_argv(session_bus_argv)
    harness = (replay_progress["wrapper"] if replay_progress else
               initial_observation["wrapper"] if initial_observation else
               prepared["tools"] / "native-rc-smoke.mjs")
    command = ["node", str(harness), "--platform", platform,
        "--scenario", scenario, "--launch-root", str(launch_root),
        "--checkout", str(prepared.get("checkout", prepared["source"])),
        "--evidence", str(evidence), "--label", platform + "-" + scenario]
    if replay_progress:
        if replay_progress.get("profile") is not None:
            profile = replay_progress["profile"]
            if profile not in (CURRENT_REPLAY_PROGRESS_PROFILE, CURRENT071_REPLAY_PROGRESS_PROFILE):
                raise ContractError("APPLICATION_SMOKE", "Unknown replay source profile")
            command[2:2] = [
                "--rs9-replay-progress-profile", profile["id"],
                "--rs9-replay-progress-source-commit", profile["commit"],
                "--rs9-replay-progress-source-tree", profile["tree"],
                "--rs9-replay-progress-support-member", "package.json=" + profile["support"]["sha256"],
            ]
        command[2:2] = [
            "--rs9-replay-progress-harness", str(replay_progress["harness"]),
            "--rs9-replay-progress-file", str(replay_progress["progress"]),
            "--rs9-replay-progress-expected-sha256", replay_progress["expected_sha256"],
        ]
        for name, expected_sha256 in sorted(replay_progress.get("closure", {}).items()):
            command[2:2] = [
                "--rs9-replay-progress-closure-member", name + "=" + expected_sha256,
            ]
    if initial_observation is not None:
        if replay_progress is not None or harness_timeout_ms is not None:
            raise ContractError("APPLICATION_SMOKE", "Initial observation options cannot be combined with replay timeout")
        profile = initial_observation.get("profile")
        if profile not in (CURRENT_REPLAY_PROGRESS_PROFILE, CURRENT071_REPLAY_PROGRESS_PROFILE):
            raise ContractError("APPLICATION_SMOKE", "Unknown initial observation source profile")
        initial_timeout_ms = initial_observation.get("harness_timeout_ms")
        if profile.get("id") == "nebular071":
            expected_timeout_ms = _current071_initial_timeout_ms(platform, scenario)
            if expected_timeout_ms is None or initial_timeout_ms != expected_timeout_ms:
                raise ContractError("APPLICATION_SMOKE", "Unsupported current required harness timeout")
        elif initial_timeout_ms is not None:
            raise ContractError("APPLICATION_SMOKE", "Unsupported historical harness timeout")
        command[2:2] = [
            "--rs9-replay-progress-harness", str(initial_observation["harness"]),
            "--rs9-replay-progress-file", str(initial_observation["progress"]),
            "--rs9-replay-progress-expected-sha256",
            profile["modules"]["native-rc-smoke.mjs"]["sha256"],
            "--rs9-initial-observation-kind", INITIAL_OBSERVATION_KIND,
            "--rs9-initial-observation-file", str(initial_observation["path"]),
            *_initial_observation_transform_args(initial_observation, profile, platform, scenario),
            "--rs9-replay-progress-profile", profile["id"],
            "--rs9-replay-progress-source-commit", profile["commit"],
            "--rs9-replay-progress-source-tree", profile["tree"],
            "--rs9-replay-progress-support-member", "package.json=" + profile["support"]["sha256"],
        ]
        for name, row in profile["modules"].items():
            command[2:2] = ["--rs9-replay-progress-closure-member", name + "=" + row["sha256"]]
        if initial_timeout_ms is not None:
            command.extend(["--timeout-ms", str(initial_timeout_ms)])
    if harness_timeout_ms is not None:
        if harness_timeout_ms != DIAGNOSTIC_REPLAY_HARNESS_TIMEOUT_MS:
            raise ContractError("APPLICATION_SMOKE", "Unsupported diagnostic harness timeout")
        command.extend(["--timeout-ms", str(harness_timeout_ms)])
    if platform != "darwin-arm64":
        display = ["xvfb-run", "-a"]
        if extras:
            display += ["-e", str(evidence / "xvfb-error.log")]
        dbus_cmd = session_bus_argv if session_bus_argv is not None else ["dbus-run-session", "--"]
        command = [*display, *dbus_cmd, *command]
    return command


def _attempt(prepared, platform, scenario, launch_root, evidence, prefix, env, extras, timeout=240, session_bus_argv=None,
             system=None, harness_timeout_ms=None, replay_progress=None, initial_observation=None):
    if session_bus_argv is not None:
        from rs9.nix_proot_dbus_command import validate_session_bus_argv
        session_bus_argv = validate_session_bus_argv(session_bus_argv)
    command = _command(prepared, platform, scenario, launch_root, evidence, extras=extras,
                       session_bus_argv=session_bus_argv, harness_timeout_ms=harness_timeout_ms,
                       replay_progress=replay_progress, initial_observation=initial_observation)
    start = time.monotonic()
    error, rc, out, err = None, None, b"", b""
    sizes, cleanup_error, child_reaped = None, None, None
    try:
        result = (_bounded_run([*prefix, *command], env=env, timeout=timeout) if extras else
                  subprocess.run([*prefix, *command], env=env, capture_output=True, timeout=timeout))
        rc, out, err = result.returncode, result.stdout or b"", result.stderr or b""
        error = getattr(result, "capture_error", None)
        sizes = getattr(result, "stream_sizes", None)
        cleanup_error = getattr(result, "cleanup_error", None)
        child_reaped = getattr(result, "child_reaped", None)
    except subprocess.TimeoutExpired as expired:
        error, out, err = "process-timeout", expired.output or b"", expired.stderr or b""
    except OSError:
        error = "harness-error"
    if rc is not None and rc < 0:
        sig_val = -rc
        ec_val = None
    elif rc is not None and rc >= 0:
        sig_val = None
        ec_val = rc
    else:
        sig_val = None
        ec_val = None
    fields = {"scenario": scenario, "raw_returncode": rc, "exit_code": ec_val,
        "signal": sig_val, "elapsed_ms": int((time.monotonic()-start)*1000),
        "stdout_bytes": sizes[0] if sizes else len(out), "stderr_bytes": sizes[1] if sizes else len(err),
        "stdout_sha256": digest(out), "stderr_sha256": digest(err),
        "stream_capture_complete": error not in {"process-output-limit", "process-timeout", "harness-error"}, "error": error,
        "cleanup_error": cleanup_error, "child_reaped": child_reaped,
        "log_categories": extract_log_categories(out, err, rc)}
    fields["failure_binding"] = classify_failure_binding(
        out, err, rc, log_categories=fields["log_categories"])
    record, receipt_error, codes = read_and_validate_receipt(evidence / (platform+"-"+scenario+".run.json"), fields)
    fields["receipt"] = sanitize_receipt_summary(record, fields.pop("receipt_identity"))
    fields["receipt_error"], fields["problem_codes"] = receipt_error, codes
    if initial_observation is not None:
        fields["initial_observation"] = _read_initial_observation(
            initial_observation["path"],
            expected_profile=initial_observation.get("profile"),
            expected_execution_transform=(
                initial_observation.get("environment_transform") == CURRENT_NIX_ENVIRONMENT_TRANSFORM_ID
            ),
        )
    fields["cause"] = error or classify_smoke_cause(exit_code=ec_val, signal=sig_val, timed_out=(error == "process-timeout"), receipt_error=receipt_error,
        log_categories=fields["log_categories"], has_problems=bool(codes))
    if cleanup_error and fields["cause"] == "unknown":
        fields["cause"] = "process-cleanup-failure"
    fields["reason_token"] = error or ("process-signal" if sig_val is not None else ("process-nonzero" if ec_val else receipt_error)) or cleanup_error or "pass"
    fields["failed"] = bool(error or rc != 0 or receipt_error or cleanup_error)
    _bind_attempt_execution_source(fields, initial_observation)
    current071_observation = (
        isinstance(initial_observation, dict)
        and initial_observation.get("profile") == CURRENT071_REPLAY_PROGRESS_PROFILE
    )
    if (fields["failed"] and platform != "darwin-arm64" and fields["stream_capture_complete"]
            and current071_observation):
        try:
            matches = extract_resolution_matches(out, err)
            if matches:
                fields["resolution_matches"] = matches
        except Exception:
            pass
    if fields["failed"] and not extras:
        # Optional observations happen after the original outcome is fixed.
        from rs9.smoke_stream_tokens import collect_failure_diagnostics
        try:
            # Classify the existing 0.7.1 cleanup token only after exact source
            # authentication, independently of optional Nix observer activation.
            # This enables no observer/finalization fields for other routes.
            current071_problems = _current071_problem_projection(prepared, platform)
            diagnostic = collect_failure_diagnostics(err, dict(fields), evidence, platform, scenario, record=record,
                                                     system=system,
                                                     **({"current071": True} if current071_observation else {}),
                                                     **({"current071_problems": True} if current071_problems else {}))
            fields.update({k: diagnostic[k] for k in (
                "stderr_diagnostic", "evidence_inventory", "harness_run_record", "inner_stderr_diagnostic",
                "harness_problem_categories",
            ) if k in diagnostic})
        except Exception:
            pass
    if fields["failed"] and extras:
        # Reuse only the closed enum/count projection of the already-read replay
        # receipt. Its original-attempt envelope must not label replay evidence.
        from rs9.smoke_stream_tokens import project_problem_categories
        try:
            categories = project_problem_categories(
                record, fields["receipt"], system=system, platform=platform, scenario=scenario)
            if categories is not None:
                fields["harness_problem_categories"] = {
                    "origin": "diagnostic-replay", "receipt": categories["receipt"],
                    "problems": categories["problems"],
                }
        except Exception:
            pass
    if extras:
        raw, meta, log_error = _read_regular(evidence / "xvfb-error.log", MAX_LOG)
        fields["display_log"] = {**meta, "error": log_error,
            "categories": extract_log_categories(b"", raw) if not log_error else []}
        if replay_progress:
            fields["progress"] = _read_replay_progress(replay_progress["progress"])
        try:
            fields["replay_receipt_projection"] = project_replay_receipt_stage(evidence, platform, scenario)
        except Exception:
            # This is optional diagnostic data. Never change the original failure,
            # custody result, or retention path if the projection itself is malformed.
            fields["replay_receipt_projection"] = _replay_projection_fallback("projection-failed")
    return fields


def run_replay(*, scenario, platform, launch_root, checkout, tools, prefix, env,
               scratch, timeout=240, session_bus_argv=None, replay_progress_wrapper=None, system=None, replay_progress_profile=None):
    if session_bus_argv is not None:
        from rs9.nix_proot_dbus_command import validate_session_bus_argv
        session_bus_argv = validate_session_bus_argv(session_bus_argv)
    evidence = scratch / ("evidence-replay-" + scenario)
    try:
        evidence.mkdir(mode=0o777)
        evidence.chmod(0o777)
    except OSError:
        return "replay-not-run", {"status": "replay-not-run", "reason_token": "fresh-evidence-unavailable"}
    prepared = {"tools": tools, "source": checkout, "checkout": checkout}
    harness_timeout_ms = (DIAGNOSTIC_REPLAY_HARNESS_TIMEOUT_MS
                          if (platform, scenario) in DIAGNOSTIC_REPLAY_TIMEOUT_TARGETS else None)
    replay_progress = None
    if replay_progress_wrapper is not None:
        replay_progress = {
            "wrapper": Path(replay_progress_wrapper),
            "harness": Path(tools) / "native-rc-smoke.mjs",
            "progress": evidence / "replay-progress.jsonl",
            "expected_sha256": RELEASED_NATIVE_RC_SMOKE_SHA256,
            "closure": {
                "native-rc-smoke.mjs": RELEASED_NATIVE_RC_SMOKE_SHA256,
                "fs-snapshot.mjs": RELEASED_NATIVE_RC_SNAPSHOT_SHA256,
            },
        }
    if replay_progress is not None and replay_progress_profile is not None:
        if replay_progress_profile not in (CURRENT_REPLAY_PROGRESS_PROFILE, CURRENT071_REPLAY_PROGRESS_PROFILE):
            raise ContractError("APPLICATION_SMOKE", "Unknown replay source profile")
        replay_progress.update(profile=replay_progress_profile,
            expected_sha256=replay_progress_profile["modules"]["native-rc-smoke.mjs"]["sha256"],
            closure={name: pin["sha256"] for name, pin in replay_progress_profile["modules"].items()})
    fields = _attempt(prepared, platform, scenario, launch_root, evidence, prefix, env, True, timeout,
                      session_bus_argv=session_bus_argv, system=system,
                      harness_timeout_ms=harness_timeout_ms, replay_progress=replay_progress)
    label = "replay-reproduced" if fields["failed"] else "replay-passed"
    if fields["error"] == "harness-error" or fields["cleanup_error"]:
        label = "replay-not-run"
    return label, {**fields, "status": label}


def _failure_details(fields, *, extras, receipt_name):
    keys = ("exit_code", "stdout_sha256", "stderr_sha256", "reason_token")
    details = {k: fields[k] for k in keys if fields.get(k) is not None}
    binding = fields.get("failure_binding")
    if binding is not None:
        details["diagnostic_token"] = binding["role"] + "-" + binding["phase"]
    if fields.get("error") == "process-timeout":
        details["exception_type"] = "TimeoutExpired"
        details.pop("exit_code", None)
    if extras:
        details.update(scenario=fields["scenario"], cause=fields["cause"])
    elif fields.get("reason_token") == "receipt-missing":
        details.update(cause="smoke-evidence", missing_path="output/evidence/" + receipt_name)
    else:
        if fields.get("scenario"):
            details["scenario"] = fields["scenario"]
        if fields.get("cause"):
            details["cause"] = fields["cause"]
    details.setdefault("scenario", fields["scenario"])
    details["elapsed_ms"] = fields["elapsed_ms"]
    return details


def _compact_execution_source_for_size_cap(source_record):
    """Retain a compact typed execution-source marker when diagnostic size cap is reached."""
    status = source_record.get("status") if isinstance(source_record, dict) else None
    reason = source_record.get("reason") if isinstance(source_record, dict) else None
    compact = {
        "schema": CURRENT_NIX_EXECUTION_SOURCE_SCHEMA,
        "status": status if status in {"verified", "failed"} else "failed",
        "non_admitting": True,
        "omitted": "diagnostic-size-cap",
    }
    if isinstance(reason, str) and reason:
        compact["reason"] = reason
    return compact


def _shed_execution_source_for_size_cap(record, raw):
    """Compact or drop execution_source only after larger optional observation fields are shed."""
    if len(raw) <= MAX_DIAGNOSTIC or "execution_source" not in record["initial_run"]:
        return raw
    initial = dict(record["initial_run"])
    initial["execution_source"] = _compact_execution_source_for_size_cap(initial["execution_source"])
    record["initial_run"] = initial
    raw = canonical(record)
    if len(raw) > MAX_DIAGNOSTIC:
        initial.pop("execution_source")
        record["initial_run"] = initial
        raw = canonical(record)
    return raw


def _retain_failure(prepared, system, platform, scenario, launch_root, prefix, env, fields, not_run,
                    session_bus_argv=None, include_replay=True, boundary_probes=False,
                    replay_skip_reason=None):
    if include_replay:
        replay_progress_wrapper = _replay_progress_wrapper(prepared)
        _, replay = run_replay(scenario=scenario, platform=platform, launch_root=launch_root,
            checkout=prepared.get("checkout", prepared["source"]), tools=prepared["tools"], prefix=prefix,
            env=env, scratch=prepared["scratch"], session_bus_argv=session_bus_argv,
            replay_progress_wrapper=replay_progress_wrapper, system=system,
            replay_progress_profile=(_current_replay_progress_profile(prepared)
                                     if replay_progress_wrapper is not None else None))
    else:
        replay = {"status": "not-run", "reason": replay_skip_reason or "boundary-probe-only"}
    if boundary_probes:
        try:
            probes = run_boundary_probes(prefix=prefix, env=env, session_bus_argv=session_bus_argv)
        except Exception:
            probes = {
                "schema": PROBE_SCHEMA,
                "status": "unavailable",
                "reason": "probe-execution-failed",
                "qualification_authority": False,
                "application_qualified": False,
                "probes": [],
            }
    else:
        probes = None
    record = {"schema": "rs9.application-smoke-diagnostic.v1alpha1", "system": system,
        "product": "theme-forge-nebular-fusion", "substage": "application_smoke",
        "scenario": scenario, "cause": fields["cause"], "status": "fail", "gate_status": "fail",
        "initial_run": fields, "replay": replay, "scenarios_not_run": not_run,
        "initial_process_policy": "legacy-subprocess-run-and-argv",
        "replay_process_policy": "bounded-created-process-group-with-xvfb-error-file" if include_replay else "not-run",
        "replay_equivalent_to_original": False,
        "cause_withheld_or_unresolved": fields["cause"] in {"process-nonzero", "unknown"} or
            "withheld-token" in fields["problem_codes"],
        "descendant_cleanup_scope": "replay-created-process-group" if include_replay else "boundary-probe-process-groups",
        "detached_descendants_proven_absent": False}
    if boundary_probes:
        record["boundary_probes"] = probes
    raw = canonical(record)
    # New optional fields must not displace established observation evidence.
    if len(raw) > MAX_DIAGNOSTIC and "resolution_matches" in record["initial_run"]:
        initial = dict(record["initial_run"])
        initial.pop("resolution_matches")
        record["initial_run"] = initial
        raw = canonical(record)
    if len(raw) > MAX_DIAGNOSTIC:
        observation = record["initial_run"].get("initial_observation")
        if isinstance(observation, dict) and "environment_presence" in observation:
            initial = dict(record["initial_run"])
            observation = dict(observation)
            observation.pop("environment_presence")
            initial["initial_observation"] = observation
            record["initial_run"] = initial
            raw = canonical(record)
    if len(raw) > MAX_DIAGNOSTIC:
        categories = record["initial_run"].get("harness_problem_categories")
        if isinstance(categories, dict) and "finalization" in categories:
            initial = dict(record["initial_run"])
            categories = dict(categories)
            categories.pop("finalization")
            initial["harness_problem_categories"] = categories
            record["initial_run"] = initial
            raw = canonical(record)
    if len(raw) > MAX_DIAGNOSTIC and "initial_observation" in record["initial_run"]:
        # The live stream projection is optional; shed it before pruning any
        # established failure fields. If even its typed omission marker would
        # exceed the legacy diagnostic bound, remove the optional field.
        initial = dict(record["initial_run"])
        initial["initial_observation"] = _unobserved_initial_observation("diagnostic-size-cap")
        record["initial_run"] = initial
        raw = canonical(record)
        if len(raw) > MAX_DIAGNOSTIC:
            initial.pop("initial_observation")
            record["initial_run"] = initial
            raw = canonical(record)
    if len(raw) > MAX_DIAGNOSTIC and isinstance(replay, dict) and "replay_receipt_projection" in replay:
        # Keep a small typed omission marker instead of allowing the new optional
        # projection to exceed the established diagnostic cap.
        replay = dict(replay)
        replay["replay_receipt_projection"] = _replay_projection_fallback("diagnostic-size-cap")
        record["replay"] = replay
        raw = canonical(record)
        if len(raw) > MAX_DIAGNOSTIC:
            # Even the omission marker is optional. Preserve a legacy record
            # that fits with less space than that marker requires.
            replay.pop("replay_receipt_projection")
            raw = canonical(record)
    if len(raw) > MAX_DIAGNOSTIC and "harness_problem_categories" in replay:
        # Optional replay projection cannot displace the original failure record.
        replay = dict(replay)
        replay.pop("harness_problem_categories")
        record["replay"] = replay
        raw = canonical(record)
    if len(raw) > MAX_DIAGNOSTIC and "harness_problem_categories" in fields:
        # The new optional field must not turn an otherwise bounded legacy diagnostic into an error.
        initial = dict(record["initial_run"])
        initial.pop("harness_problem_categories")
        record["initial_run"] = initial
        raw = canonical(record)
    raw = _shed_execution_source_for_size_cap(record, raw)
    if len(raw) > MAX_DIAGNOSTIC:
        raise ContractError("APPLICATION_SMOKE", "Smoke diagnostic bound exceeded")
    scan_for_credentials(raw.decode())
    directory = prepared["scratch"].parent / "diagnostics"
    directory.mkdir(exist_ok=True)
    path = directory / "application-smoke-diagnostic.json"
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600)
    with os.fdopen(fd, "wb") as stream:
        if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
            raise ContractError("APPLICATION_SMOKE", "Regular diagnostic output required")
        stream.write(raw)
    return digest(raw)


def execute_application_smoke(*, prepared, system, launch_root, prefix=(), env=None, diagnostic_extras=False,
                             diagnostic_boundary_probes=False, diagnostic_replay=False,
                             diagnostic_initial_observation=False,
                             diagnostic_current_nix_environment_transform=False,
                             current_nix_environment_transform=False,
                             session_bus_argv=None):
    if (type(diagnostic_current_nix_environment_transform) is not bool
            or type(current_nix_environment_transform) is not bool):
        raise ContractError("APPLICATION_SMOKE", "Invalid current Nix environment transform option")
    environment_transform = (
        diagnostic_current_nix_environment_transform or current_nix_environment_transform
    )
    if session_bus_argv is not None:
        from rs9.nix_proot_dbus_command import validate_session_bus_argv
        session_bus_argv = validate_session_bus_argv(session_bus_argv)
    platform = "darwin-arm64" if system == "aarch64-darwin" else "linux-arm64" if system == "aarch64-linux" else "linux-x64"
    scenarios = ["A"] if platform == "darwin-arm64" else ["B"] if platform == "linux-arm64" else ["C", "C-signal"]
    extras = bool(diagnostic_extras and system == "x86_64-linux")
    evidence = prepared["scratch"] / "evidence"
    evidence.mkdir(exist_ok=True)
    evidence.chmod(0o755 if prepared.get("container_client") else 0o777)
    runs = []
    for index, scenario in enumerate(scenarios):
        # Keep the qualification attempt comparable with run 15/16. Only a
        # explicitly requested initial observation uses the instrumented process/argv path.
        initial_observation = _build_initial_observation_descriptor(
            prepared, system, platform, scenario, evidence,
            enabled=bool(diagnostic_initial_observation),
            environment_transform=environment_transform,
        )
        fields = _attempt(prepared, platform, scenario, launch_root, evidence, prefix, env, False, session_bus_argv=session_bus_argv,
                          system=system, initial_observation=initial_observation)
        if fields["failed"]:
            from rs9.pages_smoke_diagnostic import validate_smoke_observation
            observation = validate_smoke_observation(fields, system=system)
            details = _failure_details(fields, extras=extras, receipt_name=platform+"-"+scenario+".run.json")
            replay_requested = bool(extras or diagnostic_replay)
            replay_allowed = replay_requested
            replay_skip_reason = None
            current071_observation = (
                isinstance(initial_observation, dict)
                and isinstance(initial_observation.get("profile"), dict)
                and initial_observation["profile"].get("id") == "nebular071"
            )
            if replay_requested and current071_observation:
                replay_skip_reason = _original_replay_skip_reason(fields)
                if replay_skip_reason is not None:
                    replay_allowed = False
            if extras or diagnostic_boundary_probes or diagnostic_replay or diagnostic_initial_observation:
                details["diagnostic_sha256"] = _retain_failure(prepared, system, platform, scenario,
                    launch_root, prefix, env, fields, scenarios[index+1:], session_bus_argv=session_bus_argv,
                    include_replay=replay_allowed, boundary_probes=diagnostic_boundary_probes,
                    replay_skip_reason=replay_skip_reason)
            err = ContractError("APPLICATION_SMOKE", "Released application-aware smoke failed", details=details)
            err.smoke_observation = observation
            raise err
        runs.append(_scenario_run_projection(
            scenario, fields, environment_transform=environment_transform))
    return runs
