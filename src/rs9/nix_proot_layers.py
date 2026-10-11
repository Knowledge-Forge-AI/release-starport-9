"""Bounded read-only /proc descendant layer observation and stderr attribution.

Walks PPid descendants from exact owned Popen pid with start-time (field 22) binding,
recording process hierarchy across sudo/unshare session changes without signaling.
"""
from collections import defaultdict
import hashlib
import os
from pathlib import Path
import re
import stat
from typing import Any

ALLOWED_CLASSES = ("sudo", "unshare", "setpriv", "env", "proot", "guest-python", "other")
MAX_DESCENDANTS = 64
MAX_STDERR = 4096
MAX_PROC_ENTRIES = 4096
SIGTERM_BIT_MASK = 1 << 14  # SIGTERM is signal 15; bit index 14


def classify_process_basename(name: str) -> str:
    """Classify executable basename into canonical layer classes."""
    base = os.path.basename(name).lower()
    if base == "sudo":
        return "sudo"
    if base == "unshare":
        return "unshare"
    if base == "setpriv":
        return "setpriv"
    if base == "env":
        return "env"
    if base == "proot":
        return "proot"
    if base == "python" or base.startswith("python3") or base.startswith("python"):
        return "guest-python"
    return "other"


def parse_proc_stat(stat_text: str) -> dict[str, Any] | None:
    """Parse /proc/[pid]/stat text handling parenthesized comm with spaces/parens.

    Field 1: pid
    Field 2: comm (in parentheses)
    Field 3: state
    Field 4: ppid
    Field 5: pgrp (pgid)
    Field 6: session (sid)
    ...
    Field 22: starttime
    """
    first_paren = stat_text.find("(")
    last_paren = stat_text.rfind(")")
    if first_paren == -1 or last_paren == -1 or last_paren <= first_paren:
        return None
    pid_str = stat_text[:first_paren].strip()
    comm = stat_text[first_paren + 1:last_paren]
    rest = stat_text[last_paren + 1:].strip().split()
    # rest[0] is field 3 (state), rest[1] is field 4 (ppid), rest[19] is field 22 (starttime)
    if len(rest) < 20:
        return None
    try:
        pid = int(pid_str)
        state = rest[0]
        ppid = int(rest[1])
        pgid = int(rest[2])
        sid = int(rest[3])
        starttime = int(rest[19])
    except (ValueError, IndexError):
        return None
    if (state not in {"R", "S", "D", "Z", "T", "t", "W", "X", "x", "K", "P", "I"}
            or pid < 1 or min(ppid, pgid, sid, starttime) < 0):
        return None
    return {
        "pid": pid,
        "comm": comm,
        "state": state,
        "ppid": ppid,
        "pgid": pgid,
        "sid": sid,
        "starttime": starttime,
    }


def parse_proc_status(status_text: str) -> dict[str, str]:
    """Parse /proc/[pid]/status key-value lines."""
    info = {}
    for line in status_text.splitlines():
        if ":" in line:
            key, val = line.split(":", 1)
            info[key.strip()] = val.strip()
    return info


def parse_sigterm_bits(status_info: dict[str, str]) -> dict[str, bool]:
    """Extract SIGTERM (signal 15) ignored, caught, blocked bit states."""
    def has_sigterm(hex_str: str | None) -> bool:
        if not hex_str:
            return None
        try:
            return bool(int(hex_str, 16) & SIGTERM_BIT_MASK)
        except (ValueError, TypeError):
            return None

    return {
        "ignored": has_sigterm(status_info.get("SigIgn")),
        "caught": has_sigterm(status_info.get("SigCgt")),
        "blocked": has_sigterm(status_info.get("SigBlk")),
    }


def _read_text(path, limit=16384):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as stream:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise ValueError("process-file-not-regular")
        raw = stream.read(limit + 1)
    if len(raw) > limit:
        raise ValueError("process-file-limit")
    return raw.decode("utf-8")


def read_process_layer(proc_root: Path, pid: int) -> dict[str, Any]:
    """Read a single process's stat, status, and classification without leaking cmdline."""
    proc_dir = proc_root / str(pid)
    stat_file = proc_dir / "stat"
    try:
        stat_text = _read_text(stat_file)
    except (OSError, ValueError):
        return {"pid": pid, "status": "unreadable", "error": "stat-read-error"}

    parsed = parse_proc_stat(stat_text)
    if not parsed or parsed["pid"] != pid:
        return {"pid": pid, "status": "unreadable", "error": "stat-parse-failed"}

    status_file = proc_dir / "status"
    sigterm_bits = {"ignored": None, "caught": None, "blocked": None}
    try:
        status_text = _read_text(status_file)
        status_info = parse_proc_status(status_text)
        sigterm_bits = parse_sigterm_bits(status_info)
    except (OSError, ValueError):
        pass

    exe_name = None
    try:
        exe_link = os.readlink(proc_dir / "exe")
        exe_name = Path(exe_link).name
    except OSError:
        pass

    target_name = exe_name or parsed["comm"]
    b_class = classify_process_basename(target_name)

    return {
        "pid": pid,
        "ppid": parsed["ppid"],
        "pgid": parsed["pgid"],
        "sid": parsed["sid"],
        "starttime": parsed["starttime"],
        "basename_class": b_class,
        "sigterm": sigterm_bits,
        "state": parsed["state"],
        "status": "observed",
    }


def _descendant_snapshot(proc_root):
    pid_entries = []
    with os.scandir(proc_root) as entries:
        for entry in entries:
            if entry.name.isdigit():
                pid_entries.append(proc_root / entry.name)
                if len(pid_entries) > MAX_PROC_ENTRIES:
                    break
    children, bindings = defaultdict(list), {}
    incomplete = len(pid_entries) > MAX_PROC_ENTRIES
    for entry in pid_entries[:MAX_PROC_ENTRIES]:
        try:
            parsed = parse_proc_stat(_read_text(entry / "stat"))
            if parsed and parsed["pid"] == int(entry.name):
                children[parsed["ppid"]].append(int(entry.name))
                bindings[int(entry.name)] = (parsed["starttime"], parsed["ppid"])
            else:
                incomplete = True
        except (OSError, ValueError):
            incomplete = True
    return children, bindings, incomplete


def observe_descendant_layers(proc_root: Path, root_pid: int | None,
                              max_descendants: int = MAX_DESCENDANTS) -> dict[str, Any]:
    """Bounded read-only walk of PPid descendants from exact owned root_pid.

    Does not filter by session (records separate sessions).
    Binds each entry with field 22 start-time.
    Never signals observed processes.
    """
    if root_pid is None:
        return {
            "status": "unavailable",
            "reason": "process-pid-unavailable",
            "root_pid": None,
            "layers": [],
            "sessions": [],
            "session_count": 0,
            "separate_sessions": False,
            "limit_exceeded": False,
        }
    if not proc_root.exists():
        return {
            "status": "unavailable",
            "reason": "proc-root-unavailable",
            "root_pid": root_pid,
            "layers": [],
            "sessions": [],
            "session_count": 0,
            "separate_sessions": False,
            "limit_exceeded": False,
        }

    initial_root = read_process_layer(proc_root, root_pid)
    try:
        children, bindings, scan_incomplete = _descendant_snapshot(proc_root)
    except OSError:
        return {
            "status": "unreadable",
            "reason": "proc-scan-failed",
            "error": "proc-scan-error",
            "root_pid": root_pid,
            "layers": [],
            "sessions": [],
            "session_count": 0,
            "separate_sessions": False,
            "limit_exceeded": False,
        }

    layers = []
    visited = set()
    queue = [root_pid]
    limit_exceeded = False

    while queue:
        if len(layers) >= max_descendants:
            limit_exceeded = True
            break
        curr = queue.pop(0)
        if curr in visited:
            continue
        visited.add(curr)

        layer_data = read_process_layer(proc_root, curr)
        expected = bindings.get(curr)
        if layer_data.get("status") == "observed" and (
                expected != (layer_data["starttime"], layer_data["ppid"]) or
                (curr == root_pid and initial_root.get("starttime") != layer_data["starttime"])):
            layer_data = {"pid": curr, "status": "unreadable", "error": "process-identity-changed"}
        layers.append(layer_data)

        # Enqueue children regardless of session or process group
        for child_pid in sorted(children.get(curr, [])) if layer_data.get("status") == "observed" else []:
            if child_pid not in visited:
                queue.append(child_pid)

    sessions = sorted(list({p["sid"] for p in layers if "sid" in p and p["sid"] is not None}))
    separate_sessions = len(sessions) > 1

    return {
        "status": "observed",
        "root_pid": root_pid,
        "layers": layers,
        "count": len(layers),
        "sessions": sessions,
        "session_count": len(sessions),
        "separate_sessions": separate_sessions,
        "limit_exceeded": limit_exceeded,
        "scan_incomplete": scan_incomplete,
        "kill_authority": False,
    }


def _layer_survival_snapshot(proc_root: Path, observation: dict[str, Any]) -> dict[str, Any]:
    """Recheck survival of observed processes via bound start-time (field 22).

    Distinguishes termination, zombie, PID reuse with changed starttime, and survival.
    Retains unreadable errors.
    """
    layers = observation.get("layers", [])
    survivors = []
    records = []
    errors = []

    for proc in layers:
        pid = proc.get("pid")
        bound_starttime = proc.get("starttime")
        if pid is None or bound_starttime is None:
            if proc.get("status") == "unreadable":
                errors.append(f"pid {pid} was initially unreadable")
                records.append({"pid": pid, "survived": None, "status": "unreadable", "error": proc.get("error")})
            continue

        stat_file = proc_root / str(pid) / "stat"
        try:
            stat_text = _read_text(stat_file)
            parsed = parse_proc_stat(stat_text)
        except FileNotFoundError:
            records.append({"pid": pid, "survived": False, "reason": "terminated"})
            continue
        except (OSError, ValueError):
            errors.append("process-stat-unreadable")
            records.append({"pid": pid, "survived": None, "status": "unreadable", "error": "stat-read-error"})
            continue

        if not parsed or parsed['pid'] != pid:
            errors.append(f"pid {pid} stat unparseable on survival check")
            records.append({"pid": pid, "survived": None, "status": "unreadable", "error": "stat-unparseable"})
            continue

        if parsed["starttime"] != bound_starttime:
            # PID reused by a different process
            records.append({
                "pid": pid,
                "survived": False,
                "reason": "pid-reused",
                "expected_starttime": bound_starttime,
                "observed_starttime": parsed["starttime"],
            })
            continue

        if parsed["state"] == "Z":
            records.append({"pid": pid, "survived": False, "reason": "zombie", "state": "Z"})
        else:
            survivors.append(pid)
            records.append({
                "pid": pid,
                "survived": True,
                "state": parsed["state"],
                "basename_class": proc.get("basename_class"),
            })

    return {
        "status": "unobserved" if (errors or not layers or observation.get('status') != 'observed'
                                    or observation.get('scan_incomplete') or observation.get('limit_exceeded'))
                  else "completed",
        "survivors": survivors,
        "survivor_count": len(survivors),
        "records": records,
        "errors": errors,
    }


def check_layer_survival(proc_root: Path, observation: dict[str, Any], *, sleep=None) -> dict[str, Any]:
    """Observe graceful exits before forced cleanup, with at most 0.9s settling.

    Missing/incomplete identity records never establish zero survivors. No
    observed PID gains signal authority. Cleanup has its own later readback.
    """
    result = _layer_survival_snapshot(proc_root, observation)
    checks = 1
    while sleep is not None and result['survivors'] and checks < 10:
        sleep(.1)
        result = _layer_survival_snapshot(proc_root, observation)
        checks += 1
    return {**result, 'settle_checks': checks,
            'observation_phase': 'after-delivery-before-forced-cleanup', 'kill_authority': False}


def categorize_stderr(stderr_text):
    """Use the same closed classifier as the D-Bus readback."""
    from rs9.nix_proot_stderr import stream_diagnostic
    return [stream_diagnostic(stderr_text.encode(), stage="external-sigterm",
                              argv_sha256=None, returncode=None, allow_excerpt=False)["cause_token"]]


def capture_bounded_stderr(source, max_bytes=MAX_STDERR, *, stage="external-sigterm",
                           argv_sha256=None, returncode=None, run_error=None):
    """Capture a prefix only; never reread arbitrary guest-writable path content."""
    from rs9.nix_proot_stderr import stream_diagnostic
    close = False
    try:
        if isinstance(source, (str, Path)):
            fd = os.open(source, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
            source = os.fdopen(fd, "rb")
            close = True
        fd = source.fileno()
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode):
            raise ValueError("stderr-not-regular")
        size = info.st_size
        content = os.pread(fd, min(max_bytes, MAX_STDERR), 0)
    except (OSError, ValueError):
        return {"completed": False, "status": "unobserved", "reason": "stderr-unreadable",
                "truncated": False}
    finally:
        if close:
            source.close()
    truncated = size > len(content)
    diagnostic = stream_diagnostic(content, stage=stage, argv_sha256=argv_sha256,
        returncode=returncode, run_error=run_error, truncated=truncated, allow_excerpt=False)
    return {"raw_length": size, "sha256": hashlib.sha256(content).hexdigest(),
            "sha256_scope": "captured-prefix" if truncated else "complete-stream",
            "completed": diagnostic["complete"], "truncated": truncated,
            "diagnostic_categories": [diagnostic["cause_token"]], "stderr_diagnostic": diagnostic}
