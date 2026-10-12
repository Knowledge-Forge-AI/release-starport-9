"""Closed observations of an original experimental Nix failure; never a replay."""
import os
from pathlib import Path
import re

from rs9.errors import ContractError
from rs9.nix_proot_dbus_pin import DBUS_SESSION_CONFIG_SHA256
from rs9.release_core import digest
from rs9.scratch import canonical
from rs9.security import scan_for_credentials

MAX_STDERR = 64 * 1024
PIN_FILE = "src/rs9/nix_proot_dbus_pin.py"
_PIN = re.compile(rb'DBUS_SESSION_CONFIG_SHA256 = "([0-9a-f]{64})"\n')
_STORE = r"/nix/store/[0-9a-df-np-sv-z]{32}-"
_SECRET = re.compile(r"(?i)(?:password|passwd|token|secret|api[_-]?key|authorization|cookie)\s*[:=]")
# Plain-text message formats checked against NixOS/nix 2.31.2 source.
# Colored/control-bearing output still fails closed in _stream_state.
_PATTERNS = (
    ("evaluation", "eval-path-missing", r"error: (?:path [^\n]+ does not exist|(?:getting status of|opening file) [^\n]+: No such file or directory)"),
    ("evaluation", "eval-assertion-failed", r"error: assertion .+ failed"),
    ("evaluation", "eval-attribute-missing", r"error: attribute .+ missing"),
    ("build", "builder-failed", r"error: (?:builder for [^\n]+ failed with exit code [0-9]+|Cannot build '[^\n]+'\.\n[ \t]*Reason: builder failed with exit code [0-9]+\.)"),
    ("build", "fixed-output-hash-mismatch", r"error: hash mismatch in fixed-output derivation"),
    ("fetch", "fetch-failed", r"error: (?:unable to download|cannot download|failed to fetch)"),
    ("unknown", "permission-or-sandbox", r"(?:Permission denied|Operation not permitted|creating sandbox|unable to start build process)"),
)


def stage_experiment_pin(repository, source):
    """Stage exactly the source-owned pin missing from the original flake copy."""
    path = Path(repository) / PIN_FILE
    try:
        if any(p.is_symlink() for p in (path, *path.parents)) or not path.is_file():
            raise OSError
        with path.open("rb") as stream:
            raw = stream.read(257)
        match = _PIN.fullmatch(raw)
        if not match or match[1].decode("ascii") != DBUS_SESSION_CONFIG_SHA256:
            raise ValueError
        target = Path(source) / PIN_FILE
        if any(p.is_symlink() for p in (target, *target.parents)):
            raise OSError
        target.parent.mkdir(parents=True, exist_ok=True)
        if target.exists():
            if not target.is_file():
                raise ValueError
            with target.open("rb") as stream:
                existing = stream.read(257)
            if existing != raw:
                raise ValueError
        else:
            with target.open("xb") as stream:
                stream.write(raw)
    except (OSError, ValueError):
        raise ContractError("NIX_PIN", "Physical exact source-owned D-Bus pin required") from None
    return {"path": PIN_FILE, "sha256": digest(raw), "size": len(raw)}


def experiment_source_identity(repository, source):
    """Bind the actual staged evaluator inputs to source bytes before invoking Nix."""
    identity = {}
    for relative in ("flake.nix", "nix/nebular-proot-experiment.nix"):
        original, staged = Path(repository) / relative, Path(source) / relative
        try:
            if any(p.is_symlink() for p in (original, *original.parents, staged, *staged.parents)):
                raise OSError
            with original.open("rb") as stream:
                before = stream.read(MAX_STDERR + 1)
            with staged.open("rb") as stream:
                after = stream.read(MAX_STDERR + 1)
            if len(before) > MAX_STDERR or before != after:
                raise ValueError
        except (OSError, ValueError):
            raise ContractError("NIX_PIN", "Staged experiment source differs from repository") from None
        identity[relative] = digest(after)
    return identity


def _stream_state(stderr, complete):
    raw = stderr if isinstance(stderr, bytes) else b""
    bounded = raw[:MAX_STDERR]
    try:
        text = bounded.decode("utf-8")
        valid = True
    except UnicodeDecodeError:
        text, valid = "", False
    control = any(ord(c) < 32 and c not in "\n\r\t" or 127 <= ord(c) < 160 for c in text)
    whole = bool(complete and isinstance(stderr, bytes) and len(raw) <= MAX_STDERR)
    state = {"raw_bytes": len(raw), "sha256": digest(raw), "present": isinstance(stderr, bytes),
             "utf8_valid": valid, "control": control, "complete": whole,
             "line_count": len(bounded.splitlines()), "phase": "unknown"}
    token = ("stream-absent" if stderr is None else "stream-incomplete" if not whole else
             "stream-invalid" if not valid or control else "stream-empty" if not raw else None)
    return state, text, token


def classify_stderr(stderr, *, complete=True):
    """No prose, arbitrary paths or derivation names can cross this boundary."""
    record, text, token = _stream_state(stderr, complete)
    if token:
        return {**record, "cause_token": token}
    try:
        scan_for_credentials(text)
        if _SECRET.search(text):
            raise ContractError("CREDENTIAL_DETECTED", "Credential assignment withheld")
    except ContractError:
        return {**record, "cause_token": "stream-withheld"}
    matches = [(phase, cause) for phase, cause, pattern in _PATTERNS if re.search(pattern, text)]
    if len(matches) > 1:
        return {**record, "cause_token": "conflicting"}
    phase, cause = matches[0] if matches else ("unknown", "unknown")
    record.update(phase=phase, cause_token=cause)
    # Only a fixed repository-owned relative path and fixed builder name survive.
    if cause == "eval-path-missing" and re.search(
            _STORE + r"source/" + re.escape(PIN_FILE) + r"['’]", text):
        record["missing_path"] = PIN_FILE
    if cause == "builder-failed" and re.search(
            _STORE + r"rs9-nebular-proot-guest-root\.drv['’]", text):
        record["failed_drv_name"] = "rs9-nebular-proot-guest-root"
    return record


def retain_failure(directory, provenance, stderr, details, *, complete):
    """Exclusive 0600, no-follow write. Caller preserves the producer on any error."""
    if complete and (type(details.get("exit_code")) is not int or details["exit_code"] == 0):
        raise ValueError("Failure-only observation required")
    record = {"schema": "rs9.nix-build-diagnostic.v1", "origin": "original-producer-attempt",
              "diagnostic_replay": False, "application_qualified": False,
              "producer": {"code": "NIX_EXECUTION" if complete else "TOOL_TIMEOUT", **details}, "source": provenance,
              "stderr": classify_stderr(stderr, complete=complete)}
    raw = canonical(record)
    scan_for_credentials(raw.decode("utf-8"))
    directory = Path(directory)
    if any(p.is_symlink() for p in (directory, *directory.parents)):
        raise OSError("Physical diagnostic directory required")
    directory_fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        fd = os.open("nix-build-failure.json", os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                     0o600, dir_fd=directory_fd)
        with os.fdopen(fd, "wb") as stream:
            stream.write(raw)
    finally:
        os.close(directory_fd)
    observation = record["stderr"]
    return {"diagnostic_token": observation["cause_token"], "diagnostic_sha256": digest(raw),
            **({"missing_path": observation["missing_path"]} if "missing_path" in observation else {})}
