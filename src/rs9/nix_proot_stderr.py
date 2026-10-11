"""Closed bounded stderr observations; status alone never identifies a cause."""
import hashlib
import json
import posixpath
import re
import unicodedata
from rs9.errors import ContractError
from rs9.security import scan_for_credentials

MAX_STREAM_BYTES = 4096
MAX_EXCERPT_BYTES = 512
PUBLIC_GUEST_PATHS = ("/etc/dbus-1", "/etc/X11", "/usr/share/X11", "/run",
                      "/var/run", "/bin", "/lib", "/lib64", "/dev")
ERRNOS = {
    "no such file or directory": "ENOENT", "permission denied": "EACCES",
    "operation not permitted": "EPERM", "function not implemented": "ENOSYS",
    "invalid argument": "EINVAL", "file name too long": "ENAMETOOLONG",
    "address already in use": "EADDRINUSE", "not a directory": "ENOTDIR",
    "too many levels of symbolic links": "ELOOP", "read-only file system": "EROFS",
    "socket operation on non-socket": "ENOTSOCK", "address family not supported": "EAFNOSUPPORT",
    "connection refused": "ECONNREFUSED", "cannot allocate memory": "ENOMEM",
    "bad file descriptor": "EBADF", "too many open files": "EMFILE", "exec format error": "ENOEXEC",
}


def redact_paths_and_privacy(text, host_binds=(), closure=()):
    for source in sorted(host_binds, key=len, reverse=True):
        if len(source) > 1:
            text = text.replace(source, "<host-bind>")
    def path(match):
        value = match.group()
        if posixpath.normpath(value) != value:
            return "<path>"
        if any(value == p or value.startswith(p + "/") for p in PUBLIC_GUEST_PATHS):
            return value
        if value.startswith("/nix/store/") and "/".join(value.split("/")[:4]) in closure:
            return value
        return "<path>"
    text = re.sub(r"/[^\s:'\"<>,()\[\]{};]+", path, text)
    text = re.sub(r"(?<!/nix/store/)(?<![\w])[0-9a-fA-F]{16,}(?![\w])", "<hex>", text)
    text = re.sub(r"\[\d+\]", "[<pid>]", text)
    text = re.sub(r"(?i)\b(pid|process|vpid)[=:\s]+\d+\b", r"\1 <pid>", text)
    return re.sub(r"(?i)\b(uid|euid|gid)[=:\s]+\d+\b", r"\1 <uid>", text)


def _errno(text):
    found = {token for message, token in ERRNOS.items() if message in text.lower()}
    return next(iter(found)) if len(found) == 1 else "conflicting" if found else None


def _origin(line):
    for prefix, origin in (("proot error:", "proot"), ("proot info:", "advisory"),
            ("proot warning:", "advisory"), ("dbus-run-session:", "dbus-run-session"),
            ("bwrap:", "bwrap"), ("xvfb-run:", "xvfb-run"),
            ("rs9 guest exec failed errno=", "supervisor")):
        if line.startswith(prefix):
            return origin
    return "dbus-daemon" if re.match(r"^dbus-daemon(?:\[\d+\])?:", line) else None


def _lines(text):
    """Continuation inherits only a Python traceback; never a tool hint."""
    rows, traceback = [], False
    for line in text.splitlines():
        if not line.strip():
            continue
        origin = _origin(line)
        if line == "Traceback (most recent call last):":
            traceback, origin = True, "python"
        elif traceback and (line[:1].isspace() or re.match(r"^[A-Za-z_][\w.]*(?:Error|Exception):", line)):
            origin = "python"
            if not line[:1].isspace():
                traceback = False
        else:
            traceback = False
        rows.append((origin, line))
    return rows


def _cause(rows, origins, errno):
    if len(origins) > 1:
        sequence = [o for o, _ in rows if o != "advisory"]
        if set(origins) == {"dbus-daemon", "dbus-run-session"} and None not in sequence and sequence == sorted(
                sequence, key=lambda o: o == "dbus-run-session"):
            return "unclassified"
        return "conflicting"
    if not origins or any(o is None for o, _ in rows):
        return "unknown"
    origin = origins[0]
    if origin.startswith("dbus-"):
        return "unclassified"
    causal = "\n".join(line for o, line in rows if o != "advisory").lower()
    if origin == "bwrap" and any(t in causal for t in ("user namespace", "creating new namespace", "uid map")):
        return "userns-denied"
    if origin == "proot" and "ptrace" in causal and errno in ("EACCES", "EPERM"):
        return "ptrace-denied"
    return {"ENOENT": "guest-file-missing", "EACCES": "guest-permission-denied",
            "EPERM": "guest-permission-denied", "ENOEXEC": "guest-executable-format"}.get(
                errno, "guest-command-not-found" if "command not found" in causal else "unclassified")


def _excerpt(rows, host_binds, closure):
    """Fixed messages or scrubbed traceback structure, never arbitrary prose."""
    clean = []
    for origin, line in rows:
        if origin == "python":
            if line == "Traceback (most recent call last):":
                clean.append(line)
            elif re.match(r'^\s+File "[^"]+", line \d+, in [\w<>]+$', line):
                clean.append(redact_paths_and_privacy(line, host_binds, closure))
            elif line[:1].isspace():
                clean.append("    <python-source>")
            elif re.fullmatch(r"([A-Za-z_][\w.]*(?:Error|Exception)): \[Errno (\d+)\] (No such file or directory|Permission denied): '(/[^']+)'", line):
                clean.append(redact_paths_and_privacy(line, host_binds, closure))
            else:
                return None
        elif origin == "bwrap" and re.fullmatch(r"bwrap: creating new namespace: (Operation not permitted|Permission denied)", line):
            clean.append(line)
        elif origin == "advisory" and re.fullmatch(r"proot warning: can't chdir\('[^']+'\): No such file or directory", line):
            clean.append(redact_paths_and_privacy(line, host_binds, closure))
        else:
            # Pinned dbus templates were unavailable: do not invent or retain one.
            return None
    return "\n".join(clean)


def stream_diagnostic(raw, *, stage, argv_sha256, returncode, run_error=None,
                      host_binds=(), closure=(), truncated=False, allow_excerpt=True):
    """Closed observations from the actual separately captured stream."""
    raw = bytes(raw or b"")
    complete = not (truncated or len(raw) > MAX_STREAM_BYTES or run_error)
    try:
        text, valid = raw.decode("utf-8"), True
    except UnicodeDecodeError:
        text, valid = "", False
    controls = any(unicodedata.category(c).startswith("C") and c not in "\n\t" for c in text)
    rows = _lines(text) if complete and valid and not controls else []
    origins = sorted({o for o, _ in rows if o not in (None, "advisory")})
    errno = _errno("\n".join(line for o, line in rows if o != "advisory"))
    cause = _cause(rows, origins, errno)
    if errno == "conflicting":
        cause, errno = "conflicting", None
    if not complete:
        cause, errno = run_error if run_error in ("timeout", "output-limit", "spawn-failed") else "stream-incomplete", None
    elif not valid or controls:
        cause, errno = "stream-invalid", None
    result = {"schema": "rs9.proot-stderr-diagnostic.v1", "raw_bytes": len(raw),
              "sha256": hashlib.sha256(raw).hexdigest(), "stage": stage,
              "argv_sha256": argv_sha256, "raw_returncode": returncode,
              "exit_code": returncode if returncode is not None and returncode >= 0 else None,
              "signal": -returncode if returncode is not None and returncode < 0 else None,
              "utf8_valid": valid, "line_count": len(raw.splitlines()),
              "control": controls, "control_flag": controls, "complete": complete,
              "origin": origins[0] if len(origins) == 1 else None, "origins": origins,
              "origin_basis": "observed-prefix-only", "errno_token": errno, "cause_token": cause,
              "excerpt_status": "withheld"}
    try:
        scan_for_credentials(raw.decode("utf-8", "replace"))
        if complete and valid and not controls and allow_excerpt and raw and cause != "conflicting":
            excerpt = _excerpt(rows, host_binds, closure)
            if excerpt is not None and len(excerpt.encode()) <= MAX_EXCERPT_BYTES:
                scan_for_credentials(excerpt)
                result.update(excerpt=excerpt, excerpt_status="present")
        scan_for_credentials(json.dumps(result))
    except ContractError:
        result.pop("excerpt", None)
        result["excerpt_status"] = "withheld"
    return result

