"""POSIX FHS capture: bounded reads, honest EOF custody, and bounded cancellation.

This is deliberately scoped to the native FHS probe, not a general command runner.
Counts and prefix hashes describe bytes read before capture stopped, never an
inferred child total. No drainage after cancellation can authenticate an EOF.
"""
from dataclasses import dataclass, field
import hashlib
import math
import os
import re
import selectors
import signal
import subprocess
import time

FHS_TIMEOUT_SECONDS = 30
FHS_STREAM_LIMIT = 1024 * 1024
CHUNK_BYTES = 64 * 1024
TERM_GRACE_SECONDS = 0.1
REAP_SECONDS = 3


@dataclass
class StreamCapture:
    data: bytearray = field(default_factory=bytearray, repr=False)
    hasher: object = field(default_factory=hashlib.sha256, repr=False)
    complete: bool = False

    def read(self, fd, limit):
        raw = os.read(fd, min(CHUNK_BYTES, limit + 1 - len(self.data)))
        if not raw:
            self.complete = True
            return "eof"
        self.hasher.update(raw)
        self.data.extend(raw)
        return "overflow" if len(self.data) > limit else "data"

    def custody(self):
        row = {"bytes": len(self.data), "complete": self.complete}
        if not self.complete:
            row["prefix_sha256"] = self.hasher.hexdigest()
        return row


@dataclass
class BoundedRun:
    returncode: int | None
    termination: str
    reaped: bool
    cleanup: str
    deadline_ms: int
    limit_bytes: int
    stdout: StreamCapture = field(repr=False)
    stderr: StreamCapture = field(repr=False)

    def diagnostic_result(self):
        return subprocess.CompletedProcess([], self.returncode, self.stdout.data, self.stderr.data)

    def custody(self):
        return {"termination": self.termination, "reaped": self.reaped,
                "cleanup": self.cleanup, "returncode": self.returncode,
                "deadline_ms": self.deadline_ms, "limit_bytes": self.limit_bytes,
                "stdout": self.stdout.custody(), "stderr": self.stderr.custody()}


def _capture(child, streams, selector, deadline, limit):
    for pipe, stream in zip((child.stdout, child.stderr), streams):
        os.set_blocking(pipe.fileno(), False)
        selector.register(pipe, selectors.EVENT_READ, stream)
    while selector.get_map():
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return "deadline"
        for key, _ in selector.select(remaining):
            if time.monotonic() >= deadline:
                return "deadline"
            try:
                state = key.data.read(key.fd, limit)
            except (BlockingIOError, InterruptedError):
                continue
            if state == "overflow":
                return "overflow"
            if state == "eof":
                selector.unregister(key.fileobj)
    return "exited"


def _signal_owned(child, sig):
    """Do not poll/reap here: the unreaped leader protects its PID from reuse."""
    problem = None
    for send in (os.killpg, os.kill):
        try:
            send(child.pid, sig)
        except ProcessLookupError:
            pass
        except PermissionError:
            problem = "process-group-permission-denied"
        except OSError:
            problem = problem or "process-signal-error"
    return problem


def _stop(child):
    # Never wait/poll between group signals, even if TERM exits the leader.
    # Popen.send_signal also polls, so use os.kill for the direct-child fallback.
    problem = _signal_owned(child, signal.SIGTERM)
    reaped = False
    cleanup = problem or "process-reap-error"
    try:
        time.sleep(TERM_GRACE_SECONDS)
    finally:
        problem = _signal_owned(child, signal.SIGKILL) or problem
        try:
            child.wait(timeout=REAP_SECONDS)
            reaped = True
            cleanup = problem or "complete"
        except subprocess.TimeoutExpired:
            reaped = False
            cleanup = "process-reap-timeout"
        except OSError:
            reaped = False
            cleanup = problem or "process-reap-error"
    return reaped, cleanup


def run_bounded(argv, *, env, timeout=FHS_TIMEOUT_SECONDS, limit=FHS_STREAM_LIMIT):
    """Capture each pipe through EOF or cap+1; never communicate or replay.

    The deadline includes spawn elapsed time, but POSIX process creation itself
    is not interruptible here. After a stop, allow 0.1s for TERM then at most 3s
    to reap. Reaping proves only direct-child custody, not a privileged tree.
    Inherit stdin/session; isolate the process group with Python 3.11+ setpgid.
    """
    if (type(timeout) not in {int, float} or not math.isfinite(timeout)
            or not 0.001 <= timeout <= FHS_TIMEOUT_SECONDS
            or type(limit) is not int or not 1 <= limit <= FHS_STREAM_LIMIT):
        raise ValueError("Invalid FHS capture bounds")
    streams = (StreamCapture(), StreamCapture())
    deadline = time.monotonic() + timeout
    child = subprocess.Popen(argv, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                             bufsize=0, process_group=0)
    reaped, cleanup, termination = False, "not-needed", "capture-error"
    try:
        with selectors.DefaultSelector() as selector:
            termination = _capture(child, streams, selector, deadline, limit)
        if termination == "exited":
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                termination = "deadline"
            else:
                try:
                    child.wait(timeout=remaining)
                    reaped = True
                except subprocess.TimeoutExpired:
                    termination = "deadline"
    except OSError:
        termination = "capture-error"
    finally:
        try:
            if not reaped:
                reaped, cleanup = _stop(child)
        finally:
            for pipe in (child.stdout, child.stderr):
                pipe.close()
    return BoundedRun(child.returncode, termination, reaped, cleanup,
                      round(timeout * 1000), limit, *streams)


def valid_stream_custody(value):
    """Closed, consistent custody shared by sanitization and FHS summary validation."""
    fields = {"termination", "reaped", "cleanup", "returncode", "deadline_ms",
              "limit_bytes", "stdout", "stderr"}
    if type(value) is not dict or set(value) != fields:
        return False
    if (type(value["termination"]) is not str
            or value["termination"] not in {"exited", "deadline", "overflow", "capture-error"}
            or type(value["reaped"]) is not bool
            or type(value["cleanup"]) is not str or value["cleanup"] not in {
                "not-needed", "complete", "process-group-permission-denied",
                "process-signal-error", "process-reap-timeout", "process-reap-error"}):
        return False
    rc = value["returncode"]
    if not ((type(rc) is int and -128 <= rc <= 255) if value["reaped"] else rc is None):
        return False
    if (type(value["deadline_ms"]) is not int or not 1 <= value["deadline_ms"] <= 30000
            or type(value["limit_bytes"]) is not int or not 1 <= value["limit_bytes"] <= FHS_STREAM_LIMIT):
        return False
    return (all(_valid_stream(value[name], value["limit_bytes"]) for name in ("stdout", "stderr"))
            and _consistent_custody(value))


def _consistent_custody(value):
    streams = (value["stdout"], value["stderr"])
    exceeded = any(row["bytes"] > value["limit_bytes"] for row in streams)
    if value["termination"] == "exited":
        return (value["reaped"] and value["cleanup"] == "not-needed"
                and all(row["complete"] for row in streams))
    if value["cleanup"] == "not-needed":
        return False
    if value["reaped"] and value["cleanup"] in {"process-reap-timeout", "process-reap-error"}:
        return False
    if not value["reaped"] and value["cleanup"] == "complete":
        return False
    return exceeded if value["termination"] == "overflow" else not exceeded


def _valid_stream(row, limit):
    if (type(row) is not dict or type(row.get("complete")) is not bool
            or type(row.get("bytes")) is not int or not 0 <= row["bytes"] <= limit + 1):
        return False
    if row["complete"]:
        return set(row) == {"bytes", "complete"} and row["bytes"] <= limit
    return (set(row) == {"bytes", "complete", "prefix_sha256"}
            and type(row["prefix_sha256"]) is str
            and re.fullmatch(r"[0-9a-f]{64}", row["prefix_sha256"]) is not None)
