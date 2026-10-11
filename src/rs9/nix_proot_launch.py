"""Safe causal launch receipts and measured diagnostic command stages."""
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import secrets
import stat
import statistics
import subprocess
import time

from rs9.nix_proot_audit import guest_audit
from rs9.errors import ContractError
from rs9.security import scan_for_credentials

TOOLS = {"xvfb-run", "dbus-run-session", "dbus-daemon", "Xvfb", "xauth", "xkbcomp", "getopt",
         "mktemp", "mcookie", "env", "proot", "node", "python3", "python", "sh", "bash", "bwrap"}
PUBLIC = ("/etc/dbus-1", "/etc/X11", "/usr/share/X11", "/run", "/var/run", "/bin", "/lib", "/lib64", "/dev")
DIAGNOSTIC_ERRORS = (ContractError, OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError)


def diagnostic_failure(stage, error):
    """Retain safe exception categories, never exception messages or host filenames."""
    return {"stage": stage, "status": "unobserved", "reason": "diagnostic-execution-failed",
            "exception_type": type(error).__name__,
            **({"errno": error.errno} if isinstance(error, OSError) and type(error.errno) is int else {})}


def _sha(raw):
    return hashlib.sha256(raw).hexdigest()


def redact_text(text, host_binds=()):
    """Used only for bounded classifications; raw diagnostic text is never retained."""
    for source in sorted(host_binds, key=len, reverse=True):
        if source and len(source) > 1:
            text = text.replace(source, "<host-bind>")
    return re.sub(r"/(?:Users|home|private|var/folders)/[^\s:'\"]+", "<host-path>", text)


def classify_path(path):
    if not path:
        return "none"
    if path.startswith("/nix/store/"):
        return "guest-store"
    if any(path == p or path.startswith(p + "/") for p in PUBLIC):
        return "guest-system"
    return "guest-tmp" if path.startswith("/tmp/") else "unknown"


def classify_failure(run, *, tool_hint=None, role_hint=None, host_binds=(), closure=()):
    """No generic ENOENT can identify a payload; retain causal role and bounded stream identities."""
    stdout, stderr = run.stdout or b"", run.stderr or b""
    text = stderr.decode("utf-8", "replace")
    lines, warnings = [], []
    for line in text.splitlines()[:256]:
        line = line[:512]
        if re.search(r"can'?t\s+chdir", line, re.I):
            warnings.append("proot-cwd-fallback")
        elif not line.lower().startswith("proot info:"):
            lines.append(line)
    causal = "\n".join(lines)
    lower = causal.lower()
    denial = "permission denied" in lower or "operation not permitted" in lower or "denied" in lower
    tool, path = "unknown", None
    for line in lines:
        match = re.search(r"(?:execve\(|cannot (?:open|execute|access)\s+|failed to (?:exec|open)\s+)[\"']?([^\s\"':,)]+)", line, re.I)
        if match is None:
            match = re.search(r"([^\s\"':]+):\s*(?:no such file or directory|(?:command )?not found|permission denied)", line, re.I)
        if match:
            candidate = match.group(1)
            if candidate.startswith("/"):
                path = candidate
            basename = os.path.basename(candidate)
            if basename in TOOLS:
                tool = basename
            break
    if tool == "unknown":
        tool = next((name for name in sorted(TOOLS, key=len, reverse=True)
                     if re.search(r"(?<![\w-])" + re.escape(name) + r"(?![\w-])", causal)), "unknown")
    tool_source = "stderr" if tool != "unknown" else "unknown"
    if tool == "unknown" and tool_hint:
        hint = os.path.basename(tool_hint)
        tool = hint if hint in TOOLS else "other"
        tool_source = "hint"
    role = {"xvfb-run": "display", "Xvfb": "display-server", "xauth": "display-authentication",
            "getopt": "argument-parser", "dbus-run-session": "dbus-session", "dbus-daemon": "dbus-daemon",
            "bwrap": "sandbox", "python": "observer", "python3": "observer"}.get(tool, role_hint or "unknown")
    error = getattr(run, "error", None)
    if error:
        reason = {"timeout": "probe-timeout", "output-limit": "probe-output-limit", "spawn-failed": "probe-spawn-failed"}.get(error, "probe-execution-failed")
        error_class = error
    elif "ptrace" in lower and denial:
        reason, error_class = "ptrace-denied", "EACCES"
    elif "user namespace" in lower or "creating new namespace" in lower or ("bwrap" in lower and denial):
        reason, error_class = "userns-denied", "EACCES"
    elif "command not found" in lower or re.search(r":\s*not found", lower):
        reason, error_class = "guest-command-not-found", "command-not-found"
    elif "no such file or directory" in lower:
        reason = "guest-file-missing" if path else "guest-path-missing"
        error_class = "ENOENT"
    elif denial:
        reason, error_class = "guest-permission-denied", "EACCES"
    elif "exec format error" in lower:
        reason, error_class = "guest-executable-format", "ENOEXEC"
    else:
        reason, error_class = "proot-launch-failed", "unclassified"
    path_class = classify_path(path)
    cause_path = {}
    if path:
        credential_path = False
        try:
            scan_for_credentials(path)
        except ContractError:
            credential_path = True
        if credential_path:
            path_class = "withheld-path"
        elif any(path == b or path.startswith(b + "/") for b in host_binds):
            path_class = "host-bind-state"
        elif path_class == "guest-store":
            top = "/".join(path.split("/")[:4])
            path_class = "closure-store" if top in closure else "store-outside-closure" if closure else "guest-store"
            cause_path["path"] = path
        elif path_class == "guest-system":
            cause_path["path"] = path
        cause_path["path_sha256"] = _sha(path.encode())
    rc = run.returncode
    return {"reason": reason, "tool": tool, "tool_source": tool_source, "role": role, "error_class": error_class,
            "path_class": path_class, **cause_path, "exit_code": rc if rc is not None and rc >= 0 else None,
            "signal": -rc if rc is not None and rc < 0 else None, "raw_returncode": rc,
            "stdout_length": len(stdout), "stderr_length": len(stderr),
            "stdout_sha256": _sha(stdout), "stderr_sha256": _sha(stderr),
            "bounded_capture_complete": error != "output-limit",
            "elapsed_seconds": round(run.elapsed, 3), "warnings": sorted(set(warnings))}


_DISPLAY_STATE = """import json,os,sys
d=os.environ.get('DISPLAY','');a=os.environ.get('XAUTHORITY','')
socket_present=bool(d and os.path.exists('/tmp/.X11-unix/X'+d.lstrip(':').split('.')[0]))
ok=bool(d and a and os.path.isfile(a) and socket_present)
print(json.dumps({'display_set':bool(d),'authority_file_present':bool(a and os.path.isfile(a)),'socket_present':socket_present}))
sys.exit(0 if ok else 3)
"""
_DBUS_STATE = """import json,os,socket,sys
a=os.environ.get('DBUS_SESSION_BUS_ADDRESS','');ok=False;error=None
for entry in a.split(';'):
    if not entry.startswith('unix:'):continue
    fields=dict(v.split('=',1) for v in entry[5:].split(',') if '=' in v)
    target=fields.get('path') or ('\\0'+fields['abstract'] if 'abstract' in fields else None)
    if target:
        s=socket.socket(socket.AF_UNIX);s.settimeout(2)
        try:s.connect(target);ok=True
        except OSError as e:error=e.errno
        finally:s.close()
print(json.dumps({'address_set':bool(a),'socket_connectable':ok,'errno':error}));sys.exit(0 if ok else 3)
"""


def run_launch_chain(rt, elfs=None):
    """Actual guest static facts and separate command roles; no new qualification gate."""
    facts = rt.facts
    audit = guest_audit(rt)
    python = [facts["python"], "-I", "-S", "-B", "-c"]
    cwd_code = ("import hashlib,json,os;cwd=os.getcwd();print(json.dumps({'is_tmp':cwd=='/tmp',"
                "'is_root':cwd=='/','cwd_sha256':hashlib.sha256(cwd.encode()).hexdigest()}))")
    cwd_run = rt.run("launch-chain-default-cwd", [*python, cwd_code], timeout=20, cwd=None)
    try:
        cwd_state = json.loads(cwd_run.stdout) if cwd_run.returncode == 0 and not cwd_run.error else None
        if not isinstance(cwd_state, dict) or set(cwd_state) != {"is_tmp", "is_root", "cwd_sha256"}:
            cwd_state = None
    except (ValueError, UnicodeError):
        cwd_state = None
    supports_error = any(row.get("error_file_option") for row in audit.get("files", []))
    error_paths = {label: "/tmp/rs9-xvfb-error-" + secrets.token_hex(8)
                   for label in ("display-only", "combined-pinned-python")}
    def display(label):
        return [facts["xvfb_run"], "-a", *(["-e", error_paths[label]] if supports_error else [])]
    stages = [
        ("display-only", [*display("display-only"), *python, _DISPLAY_STATE], "xvfb-run", "display", "/tmp"),
        ("dbus-only", [facts["dbus_run_session"], "--", *python, _DBUS_STATE], "dbus-run-session", "dbus", "/tmp"),
        ("combined-pinned-python", [*display("combined-pinned-python"), facts["dbus_run_session"], "--", *python, _DISPLAY_STATE], "xvfb-run", "display+dbus", "/tmp"),
        ("baseline-original-main", ["xvfb-run", "-a", "dbus-run-session", "--", *python, _DISPLAY_STATE], "xvfb-run", "baseline-main-display", "/tmp"),
        ("baseline-original-smoke", ["xvfb-run", "-a", "dbus-run-session", "--", "node", "-e", "console.log(process.version)"], "xvfb-run", "baseline-smoke", None),
    ]
    receipts = []
    host_binds = tuple(str(p) for p in (rt.layout.tmp_dir, rt.layout.cache_dir, rt.layout.loader_tmp,
                                       rt.layout.etc_dir, *rt.layout.workspaces))
    for label, command, tool, role, cwd in stages:
        run = rt.run("launch-chain-" + label, command, timeout=45, cwd=cwd)
        passed = not run.error and run.returncode == 0
        safe_argv = [redact_text(a, host_binds) for a in command]
        receipt = {"stage": label, "status": "pass" if passed else "fail", "guest_cwd_policy": cwd or "inherit-or-proot-fallback",
                   "argv_sha256": _sha(json.dumps(command).encode()),
                   "stage_argv": safe_argv,
                   **classify_failure(run, tool_hint=tool, role_hint=role, host_binds=host_binds, closure=rt.closure)}
        if passed:
            receipt.pop("reason", None)
            receipt["error_class"] = "none"
        else:
            from rs9.nix_proot_stderr import stream_diagnostic
            receipt["stderr_diagnostic"] = stream_diagnostic(
                run.stderr, stage=label, argv_sha256=receipt["argv_sha256"],
                returncode=run.returncode, run_error=run.error,
                host_binds=host_binds, closure=rt.closure,
                allow_excerpt="dbus" in role or "dbus-run-session" in command)
        has_dbus = ("dbus" in role or tool in ("dbus-run-session", "dbus-daemon") or any("dbus-run-session" in a for a in command))
        receipt["config_identity"] = {
            "guest_config": "/etc/dbus-1/session.conf",
            "store_config": facts.get("dbus_session_config"),
            "daemon": facts.get("dbus_daemon"),
        } if has_dbus else None
        if supports_error and label in {"display-only", "combined-pinned-python"}:
            path = rt.layout.tmp_dir / Path(error_paths[label]).name
            try:
                fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
                with os.fdopen(fd, "rb") as stream:
                    info = os.fstat(stream.fileno())
                    raw = stream.read(65537) if stat.S_ISREG(info.st_mode) else b""
                receipt["xvfb_error_stream"] = {"bytes": len(raw), "sha256": _sha(raw), "complete": len(raw) <= 65536}
                if not passed and raw and len(raw) <= 65536:
                    log_run = type(run)(run.returncode, b"", raw, run.elapsed, None)
                    receipt["xvfb_error_cause"] = classify_failure(log_run, tool_hint="Xvfb", role_hint="display-server",
                                                                 host_binds=host_binds, closure=rt.closure)
            except OSError:
                receipt["xvfb_error_stream"] = {"status": "unavailable"}
        receipts.append(receipt)
    first = next((r for r in receipts if r["status"] != "pass"), None)
    if first is None and audit.get("dbus_config", {}).get("status") == "fail":
        dbus_diag = audit["dbus_config"]
        first = {
            "stage": "dbus-config-audit",
            "status": "fail",
            "reason": dbus_diag.get("reason"),
            "tool": "dbus-daemon",
            "role": "dbus-config",
            "error_class": "config-audit-failed",
            "path": dbus_diag.get("failing_path"),
        }
    elif first is None and audit.get("status") == "fail":
        first = {
            "stage": "helper-audit",
            "status": "fail",
            "reason": audit.get("reason"),
            "tool": "guest-audit",
            "role": "helper-audit",
            "error_class": "audit-failed",
        }
    from rs9.nix_proot_dbus_probe import config_include_structure
    include_structure = config_include_structure(audit.get("dbus_config", {}))
    decomposition = {"status": "not-run", "reason": "dbus-positive-control-did-not-fail",
                     "qualification_authority": False}
    if receipts[1]["status"] == "fail":
        from rs9.nix_proot_dbus_probe import run_dbus_decomposition
        try:
            decomposition = run_dbus_decomposition(rt, True, _DBUS_STATE)
        except DIAGNOSTIC_ERRORS as error:
            decomposition = {**diagnostic_failure("dbus-decomposition", error), "qualification_authority": False}
    return {"status": "fail" if first else "observed" if audit.get("status") == "observed" else "incomplete",
            "helper_audit": audit, "default_guest_cwd": {"state": cwd_state, "streams": classify_failure(cwd_run)}, "stages": receipts,
            "first_failure": first, "dbus_decomposition": decomposition,
            "dbus_config_include_structure": include_structure, "qualification_authority": False}


def measure_proot_latency(rt, sample_count=5):
    """Same host prefix/environment, successful samples only; failures retain receipts."""
    count = min(5, max(1, sample_count))
    command = [rt.facts["python"], "-I", "-S", "-B", "-c", "pass"]
    arms = {}
    for arm in ("native", "raw-proot", "guest-wait-diagnostic"):
        if platform.system() != "Linux":
            arms[arm] = {"status": "unavailable", "reason": "linux-native-latency-unavailable-on-provider"}
            continue
        receipts, samples = [], []
        for _ in range(count):
            if arm == "raw-proot":
                run = rt.run("raw-latency", command, timeout=20)
                wait = None
            elif arm == "guest-wait-diagnostic":
                from rs9.nix_proot_wait import diagnostic_guest_run
                run, wait = diagnostic_guest_run(rt, "wait-latency", command, timeout=20)
            else:
                start = time.monotonic()
                try:
                    result = rt.runner([*rt.prefix, *command], env=rt.host_env(), capture_output=True, timeout=20)
                    from rs9.nix_proot import Run
                    run = Run(result.returncode, result.stdout, result.stderr, time.monotonic() - start, None)
                except OSError:
                    from rs9.nix_proot import Run
                    run = Run(None, b"", b"", time.monotonic() - start, "spawn-failed")
                except subprocess.TimeoutExpired:
                    from rs9.nix_proot import Run
                    run = Run(None, b"", b"", time.monotonic() - start, "timeout")
                wait = None
            passed = not run.error and run.returncode == 0 and (wait is None or wait.get("compatible_status") is True)
            receipt = {"status": "pass" if passed else "fail", **classify_failure(run)}
            if passed:
                receipt.pop("reason", None)
                receipt["error_class"] = "none"
            if wait is not None:
                receipt["wait"] = wait
            receipts.append(receipt)
            if passed:
                samples.append(run.elapsed)
        arms[arm] = {"status": "measured" if len(samples) == count else "fail", "sample_count": count,
                     "successful_samples": len(samples), "receipts": receipts,
                     "median_seconds": round(statistics.median(samples), 4) if samples else None,
                     "max_seconds": round(max(samples), 4) if samples else None}
    return {"metric_type": "diagnostic", "same_host_prefix": True, "arms": arms}
