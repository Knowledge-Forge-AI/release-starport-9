"""Wheel-only bounded smoke failure records; raw process output is never retained."""
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
    "shared-library-missing", "webkit-crash", "assertion", "unknown"})
SAFE_LOG_CATEGORIES = frozenset({"dbus-session-conf-missing", "dbus-daemon-error",
    "xvfb-display-error", "xvfb-auth-error", "module-not-found", "command-not-found",
    "shared-library-missing", "webkit-crash", "assertion", "socket-unavailable", "unclassified"})
SAFE_FAILURE_ROLES = frozenset({"dbus-wrapper", "dbus-daemon", "dbus-config", "node",
    "smoke-script", "loader", "unknown"})


def extract_log_categories(stdout, stderr, exit_code=None):
    """Closed observations, never guessed tool identity from a generic exit 127."""
    text = (stderr + b"\n" + stdout).lower()
    failure = any(t in text for t in (b"failed", b"error", b"no such", b"not found", b"refused"))
    categories = []
    if b"session.conf" in text and (b"no such" in text or b"failed" in text):
        categories.append("dbus-session-conf-missing")
    elif failure and (b"dbus-daemon" in text or b"dbus-run-session" in text):
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


def _bounded_run(argv, *, env, timeout):
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
                child.wait(timeout=10)
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


def _command(prepared, platform, scenario, launch_root, evidence, *, extras, session_bus_argv=None):
    if session_bus_argv is not None:
        from rs9.nix_proot_dbus_command import validate_session_bus_argv
        session_bus_argv = validate_session_bus_argv(session_bus_argv)
    command = ["node", str(prepared["tools"] / "native-rc-smoke.mjs"), "--platform", platform,
        "--scenario", scenario, "--launch-root", str(launch_root),
        "--checkout", str(prepared.get("checkout", prepared["source"])),
        "--evidence", str(evidence), "--label", platform + "-" + scenario]
    if platform != "darwin-arm64":
        display = ["xvfb-run", "-a"]
        if extras:
            display += ["-e", str(evidence / "xvfb-error.log")]
        dbus_cmd = session_bus_argv if session_bus_argv is not None else ["dbus-run-session", "--"]
        command = [*display, *dbus_cmd, *command]
    return command


def _attempt(prepared, platform, scenario, launch_root, evidence, prefix, env, extras, timeout=240, session_bus_argv=None,
             system=None):
    if session_bus_argv is not None:
        from rs9.nix_proot_dbus_command import validate_session_bus_argv
        session_bus_argv = validate_session_bus_argv(session_bus_argv)
    command = _command(prepared, platform, scenario, launch_root, evidence, extras=extras, session_bus_argv=session_bus_argv)
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
    fields["cause"] = error or classify_smoke_cause(exit_code=ec_val, signal=sig_val, timed_out=(error == "process-timeout"), receipt_error=receipt_error,
        log_categories=fields["log_categories"], has_problems=bool(codes))
    if cleanup_error and fields["cause"] == "unknown":
        fields["cause"] = "process-cleanup-failure"
    fields["reason_token"] = error or ("process-signal" if sig_val is not None else ("process-nonzero" if ec_val else receipt_error)) or cleanup_error or "pass"
    fields["failed"] = bool(error or rc != 0 or receipt_error or cleanup_error)
    if fields["failed"] and not extras:
        # Optional observations happen after the original outcome is fixed.
        from rs9.smoke_stream_tokens import collect_failure_diagnostics
        try:
            diagnostic = collect_failure_diagnostics(err, dict(fields), evidence, platform, scenario, record=record,
                                                     system=system)
            fields.update({k: diagnostic[k] for k in (
                "stderr_diagnostic", "evidence_inventory", "harness_run_record", "inner_stderr_diagnostic",
                "harness_problem_categories",
            ) if k in diagnostic})
        except Exception:
            pass
    if extras:
        raw, meta, log_error = _read_regular(evidence / "xvfb-error.log", MAX_LOG)
        fields["display_log"] = {**meta, "error": log_error,
            "categories": extract_log_categories(b"", raw) if not log_error else []}
    return fields


def run_replay(*, scenario, platform, launch_root, checkout, tools, prefix, env,
               scratch, timeout=240, session_bus_argv=None):
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
    fields = _attempt(prepared, platform, scenario, launch_root, evidence, prefix, env, True, timeout, session_bus_argv=session_bus_argv)
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


def _retain_failure(prepared, system, platform, scenario, launch_root, prefix, env, fields, not_run, session_bus_argv=None):
    _, replay = run_replay(scenario=scenario, platform=platform, launch_root=launch_root,
        checkout=prepared.get("checkout", prepared["source"]), tools=prepared["tools"], prefix=prefix,
        env=env, scratch=prepared["scratch"], session_bus_argv=session_bus_argv)
    record = {"schema": "rs9.application-smoke-diagnostic.v1alpha1", "system": system,
        "product": "theme-forge-nebular-fusion", "substage": "application_smoke",
        "scenario": scenario, "cause": fields["cause"], "status": "fail", "gate_status": "fail",
        "initial_run": fields, "replay": replay, "scenarios_not_run": not_run,
        "initial_process_policy": "legacy-subprocess-run-and-argv",
        "replay_process_policy": "bounded-created-process-group-with-xvfb-error-file",
        "replay_equivalent_to_original": False,
        "cause_withheld_or_unresolved": fields["cause"] in {"process-nonzero", "unknown"} or
            "withheld-token" in fields["problem_codes"],
        "descendant_cleanup_scope": "replay-created-process-group", "detached_descendants_proven_absent": False}
    raw = canonical(record)
    if len(raw) > MAX_DIAGNOSTIC and "harness_problem_categories" in fields:
        # The new optional field must not turn an otherwise bounded legacy diagnostic into an error.
        initial = dict(fields)
        initial.pop("harness_problem_categories")
        record["initial_run"] = initial
        raw = canonical(record)
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


def execute_application_smoke(*, prepared, system, launch_root, prefix=(), env=None, diagnostic_extras=False, session_bus_argv=None):
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
        # separate diagnostic replay uses the instrumented process/argv path.
        fields = _attempt(prepared, platform, scenario, launch_root, evidence, prefix, env, False, session_bus_argv=session_bus_argv,
                          system=system)
        if fields["failed"]:
            from rs9.pages_smoke_diagnostic import validate_smoke_observation
            observation = validate_smoke_observation(fields, system=system)
            details = _failure_details(fields, extras=extras, receipt_name=platform+"-"+scenario+".run.json")
            if extras:
                details["diagnostic_sha256"] = _retain_failure(prepared, system, platform, scenario,
                    launch_root, prefix, env, fields, scenarios[index+1:], session_bus_argv=session_bus_argv)
            err = ContractError("APPLICATION_SMOKE", "Released application-aware smoke failed", details=details)
            err.smoke_observation = observation
            raise err
        runs.append({"scenario": scenario, "receipt_sha256": fields["receipt"]["sha256"],
                     "executable_sha256": fields["receipt"]["executable_sha256"]})
    return runs
