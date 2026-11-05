"""SDK-only bounded dual-pipe capture using existing RS9 primitives."""
from dataclasses import dataclass
import math
import selectors
import subprocess
import time
from rs9 import bounded_process as bp
from rs9.errors import ContractError


@dataclass(frozen=True)
class Capture:
    returncode: int
    stdout: bytes
    stderr: bytes


def capture(argv, *, cwd, env, timeout, limit):
    if (type(timeout) not in {int, float} or not math.isfinite(timeout)
            or not 0.001 <= timeout <= 5400
            or type(limit) is not int or not 1 <= limit <= 8 * 1024 * 1024):
        raise ContractError("ARCHARM_CAPTURE_BOUNDS", "Closed SDK capture bounds required")
    streams = (bp.StreamCapture(), bp.StreamCapture())
    deadline = time.monotonic() + timeout
    child = subprocess.Popen(argv, cwd=cwd, env=env, stdin=subprocess.DEVNULL,
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                             bufsize=0, process_group=0)
    reaped, cleanup, termination = False, "not-needed", "capture-error"
    try:
        with selectors.DefaultSelector() as selector:
            termination = bp._capture(child, streams, selector, deadline, limit)
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
                reaped, cleanup = bp._stop(child)
        finally:
            for pipe in (child.stdout, child.stderr):
                pipe.close()
    if (termination != "exited" or not reaped
            or not all(stream.complete for stream in streams)
            or type(child.returncode) is not int):
        label = {"deadline":"TOOL_TIMEOUT", "overflow":"ARCHARM_COMMAND_OUTPUT_LIMIT"}.get(
            termination, "ARCHARM_CAPTURE_FAILED")
        raise ContractError(label, "SDK command capture did not complete",
                            details={"cleanup":cleanup, "reaped":reaped})
    return Capture(child.returncode, bytes(streams[0].data), bytes(streams[1].data))
