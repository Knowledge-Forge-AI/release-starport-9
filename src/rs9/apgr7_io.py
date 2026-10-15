"""Bounded public HTTPS and ambient attended subprocess boundaries."""
import os
import selectors
import signal
import subprocess
import time
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import Request, build_opener, HTTPRedirectHandler

from rs9.apgr7_common import strict_json
from rs9.errors import ContractError

HOSTS = {"registry.npmjs.org", "pypi.org", "files.pythonhosted.org", "api.github.com",
         "raw.githubusercontent.com", "rs9.knowledge-forge.ai"}


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


class Boundary:
    def __init__(self, *, opener=None, runner=None, qualify=False):
        self.opener = opener or build_opener(NoRedirect())
        self.runner = runner or bounded_run
        self.qualify = qualify
        self.outputs = {}

    def retain(self, name, body):
        from rs9.security import validate_safe_relative_posix_path
        validate_safe_relative_posix_path(name)
        if name in self.outputs and self.outputs[name] != body:
            raise ContractError("APGR7_OUTPUT_CONFLICT", "Prepared artifact changed")
        self.outputs[name] = body

    def get(self, url):
        parsed = urlsplit(url)
        if (parsed.scheme != "https" or parsed.hostname not in HOSTS or parsed.username
                or parsed.password or parsed.port not in (None, 443) or parsed.fragment):
            raise ContractError("REMOTE_UNKNOWN", "Destination outside bounded HTTPS authority")
        try:
            with self.opener.open(Request(url, headers={"User-Agent": "RS9-APGR7/1"}), timeout=20) as response:
                if response.status != 200 or response.geturl() != url:
                    raise ContractError("REMOTE_UNKNOWN", "Exact successful read required")
                body = response.read(64 * 1024 ** 2 + 1)
                if len(body) > 64 * 1024 ** 2:
                    raise ContractError("REMOTE_UNKNOWN", "Remote size bound exceeded")
                return body
        except HTTPError as error:
            absent = error.code == 404 and error.geturl() == url
            error.close()
            raise ContractError("REMOTE_ABSENT" if absent else "REMOTE_UNKNOWN", "HTTP read not successful") from None
        except (URLError, OSError, ValueError):
            raise ContractError("REMOTE_UNKNOWN", "Public transport unavailable") from None

    def json(self, url):
        try:
            return strict_json(self.get(url))
        except (ValueError, UnicodeError):
            raise ContractError("REMOTE_UNKNOWN", "Malformed destination metadata") from None

    def run(self, argv, cwd=None, timeout=120, **kwargs):
        # Child output is never logged; credentials remain in ambient child custody.
        try:
            completed = self.runner(list(argv), cwd=cwd, timeout=timeout, stdin=subprocess.DEVNULL,
                                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False,
                                    **kwargs)
            if len(completed.stdout) > 8 * 1024 ** 2:
                raise ContractError("PROCESS_UNCERTAIN", "Process output exceeds bound")
            return {
                "returncode": completed.returncode,
                "stdout": completed.stdout,
                "stderr": getattr(completed, "stderr", b""),
            }
        except subprocess.TimeoutExpired:
            raise ContractError("PROCESS_UNCERTAIN", "Process timed out; reconcile before another write") from None
        except OSError:
            raise ContractError("PROCESS_UNAVAILABLE", "Required executable unavailable") from None


def bounded_run(argv, *, cwd, timeout, **unused):
    """Capture bounded stdout and 64KiB bounded stderr, discarding stderr overflow.

    Concurrent selector draining prevents chatty child deadlocks.
    Reaps the process group on timeout or overflow.
    Ensures GIT_TERMINAL_PROMPT=0 in ambient child execution.
    """
    env = dict(unused.get("env") or os.environ)
    env["GIT_TERMINAL_PROMPT"] = "0"
    child = subprocess.Popen(argv, cwd=cwd, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE, start_new_session=True, env=env)
    stdout_data, stderr_data = bytearray(), bytearray()
    deadline = time.monotonic() + timeout
    reaped = False
    try:
        with selectors.DefaultSelector() as selector:
            os.set_blocking(child.stdout.fileno(), False)
            os.set_blocking(child.stderr.fileno(), False)
            selector.register(child.stdout, selectors.EVENT_READ, data="stdout")
            selector.register(child.stderr, selectors.EVENT_READ, data="stderr")
            while selector.get_map():
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise subprocess.TimeoutExpired(argv, timeout)
                for key, _ in selector.select(remaining):
                    chunk = os.read(key.fd, 65536)
                    if not chunk:
                        selector.unregister(key.fileobj)
                        continue
                    if key.data == "stdout":
                        stdout_data.extend(chunk)
                        if len(stdout_data) > 8 * 1024 ** 2:
                            raise ContractError("PROCESS_UNCERTAIN", "Process capture exceeded bound")
                    else:
                        if len(stderr_data) < 64 * 1024:
                            needed = (64 * 1024) - len(stderr_data)
                            stderr_data.extend(chunk[:needed])
        code = child.wait(timeout=max(0.001, deadline - time.monotonic()))
        reaped = True
        return subprocess.CompletedProcess(argv, code, bytes(stdout_data), bytes(stderr_data))
    finally:
        if not reaped:
            try:
                os.killpg(child.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            try:
                child.wait(timeout=5)
            except (subprocess.TimeoutExpired, OSError):
                pass
        if child.stdout:
            child.stdout.close()
        if child.stderr:
            child.stderr.close()
