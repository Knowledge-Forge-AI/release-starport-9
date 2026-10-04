"""Release-bound supported command probes, including the studio NDJSON protocol."""
import hashlib
import json
import os
from pathlib import Path
import selectors
import subprocess
import tarfile
import time

from rs9.errors import ContractError
from rs9.release_core import authenticated_record_hash
from rs9.scratch import canonical

_BOUND = {}


def contracts(repository=None):
    root = Path(repository) if repository else Path(__file__).resolve().parents[2]
    return json.loads((root / "operators/live1/command-contracts.json").read_bytes())["commands"]


def probes_for(command, repository=None):
    row = contracts(repository).get(command)
    if row is None:
        raise ContractError("COMMAND_CONTRACT", "Unknown application command")
    return row["probes"]


def bind_commands(captures, repository, output):
    """Inspect authenticated implementation bytes before allowing a declared probe.

    Local research alone cannot qualify the released command. The hosted capture
    must contain its declared implementation and every source guard. The receipt
    binds those exact bytes and asset identities, rather than an ambient checkout.
    """
    rows = contracts(repository)
    bindings = {}
    for capture, intent, _ in captures:
        release_hash = authenticated_record_hash(capture)
        for name, row in rows.items():
            if row["project"] != intent["project"]["id"]:
                continue
            evidence = dict(capture.source)
            for payload in capture.record["payloads"]:
                with tarfile.open(capture.archives[payload["id"]], "r:*") as archive:
                    for member in archive:
                        if member.isfile() and member.size <= 2 * 1024 ** 2:
                            suffix = member.name.split("/", 1)[-1]
                            if suffix in row["implementation_paths"]:
                                evidence[suffix] = archive.extractfile(member).read()
            inspected = {p: evidence[p] for p in row["implementation_paths"] if p in evidence}
            text = "\n".join(b.decode("utf-8", errors="replace") for b in inspected.values())
            missing = [guard for guard in row["source_guards"] if guard not in text]
            established = bool(inspected) and not missing
            # Launcher metadata is independently authenticated by the Nebular profile.
            if name == "tfnf":
                established = any("tfnf" in p.get("launchers", {}) for p in capture.record["payloads"])
            bindings[name] = {"status": "bound" if established else "unresearched",
                              "release_record_sha256": release_hash,
                              "asset_sha256": [p["sha256"] for p in capture.record["payloads"]],
                              "implementation_sha256": {p: hashlib.sha256(b).hexdigest() for p, b in inspected.items()},
                              "reason": None if established else "released-implementation-guard-missing"}
    _BOUND.clear()
    _BOUND.update(bindings)
    target = Path(output) / "command-bindings.json"
    target.write_bytes(canonical({"schema": "rs9.command-bindings.v1alpha1", "production_enabled": False,
                                  "commands": bindings}))
    return target


def _read_frame(child, selector, deadline):
    buffered = bytearray()
    while time.monotonic() < deadline:
        if selector.select(min(1, max(0, deadline - time.monotonic()))):
            raw = os.read(child.stdout.fileno(), 1)
            if not raw:
                raise ContractError("SERVICE_FRAME", "Bounded NDJSON response required")
            buffered.extend(raw)
            if len(buffered) > 1024 * 1024:
                raise ContractError("SERVICE_FRAME", "Studio response exceeded bound")
            if raw == b"\n":
                return json.loads(buffered)
    raise ContractError("SERVICE_TIMEOUT", "Studio response timed out")


def service_protocol(argv, env=None):
    """Supported initialize/initialized/shutdown/exit lifecycle; no metadata flags."""
    child = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE, env=env, bufsize=0)
    selector = selectors.DefaultSelector()
    selector.register(child.stdout, selectors.EVENT_READ)
    deadline = time.monotonic() + 30
    def send(method, params, ident=None):
        frame = {"jsonrpc": "2.0", "method": method, "params": params}
        if ident is not None:
            frame["id"] = ident
        child.stdin.write((json.dumps(frame, separators=(",", ":")) + "\n").encode())
        child.stdin.flush()
    try:
        send("initialize", {"protocol": "tfsb.studio", "minVersion": "1.0", "maxVersion": "1.0",
                            "client": {"name": "rs9-hosted-candidate", "version": "1"},
                            "capabilities": {"progress": True, "cancellation": True}}, 1)
        initial = _read_frame(child, selector, deadline)
        result = initial.get("result", {})
        if (initial.get("jsonrpc") != "2.0" or initial.get("id") != 1 or "error" in initial
                or result.get("selectedVersion") != "1.0" or not isinstance(result.get("sessionNonce"), str)
                or not result["sessionNonce"]):
            raise ContractError("SERVICE_INITIALIZE", "Studio negotiation failed")
        send("initialized", {"sessionNonce": result["sessionNonce"]})
        send("shutdown", {"sessionNonce": result["sessionNonce"]}, 2)
        shutdown = _read_frame(child, selector, deadline)
        if shutdown != {"jsonrpc": "2.0", "id": 2, "result": None}:
            raise ContractError("SERVICE_SHUTDOWN", "Studio shutdown failed")
        send("exit", {})
        child.stdin.close()
        child.stdin = None
        stdout, stderr = child.communicate(timeout=max(1, deadline - time.monotonic()))
        if child.returncode != 0 or stdout or stderr:
            raise ContractError("SERVICE_TERMINATION", "Studio lifecycle did not terminate cleanly")
        return {"selected_version": result["selectedVersion"], "exit_code": child.returncode}
    finally:
        selector.close()
        if child.poll() is None:
            child.kill()
        child.wait(timeout=5)
        for stream in (child.stdin, child.stdout, child.stderr):
            if stream is not None:
                stream.close()


def runtime_environment(env=None):
    allowed = {"PATH","HOME","TMPDIR","LANG","LC_ALL","TZ","THEME_FORGE_CACHE_DIR",
        "PYTHONDONTWRITEBYTECODE","DISPLAY","XAUTHORITY","DBUS_SESSION_BUS_ADDRESS",
        "WAYLAND_DISPLAY","LD_LIBRARY_PATH","DYLD_LIBRARY_PATH","XDG_RUNTIME_DIR",
        "XDG_CONFIG_HOME","XDG_DATA_HOME","XDG_STATE_HOME","XDG_CACHE_HOME"}
    source = os.environ if env is None else env
    return {key:value for key,value in source.items() if key in allowed}


def linux_runtime_prefix(env=None):
    """Deny network, drop privileges, then restore only the runtime environment.

    sudo's env_reset and secure_path run before this explicit env command. Keep
    the command inside setpriv so HOME, PATH and writable caches belong to the
    original runner, without preserving capture or Actions credentials.
    """
    uid, gid = os.getuid(), os.getgid()
    if not uid or not gid:
        raise ContractError("UNPRIVILEGED_CLIENT_REQUIRED", "Runtime probes require nonroot identity")
    env = runtime_environment(env)
    return ["sudo", "-n", "unshare", "--net", "--", "setpriv",
            f"--reuid={uid}", f"--regid={gid}", "--clear-groups", "--",
            "/usr/bin/env", "-i", *[key + "=" + env[key] for key in sorted(env)]]


def run_probes(command, path, repository=None, prefix=None, env=None):
    env = runtime_environment(env)
    if _BOUND.get(command, {}).get("status") != "bound":
        return [{"name": "command." + command + ".supported-behavior", "status": "not-run",
                 "reason": "released-command-contract-unbound"}]
    gates = []
    for probe in probes_for(command, repository):
        argv = [*(prefix or []), str(path), *probe["argv"]]
        if probe["kind"] == "service-protocol":
            service_protocol(argv, env)
        else:
            result = subprocess.run(argv, input=probe.get("input", ""), capture_output=True,
                                    text=True, env=env, timeout=30)
            if (result.returncode != probe["expect_exit"]
                    or any(s not in result.stdout for s in probe.get("stdout_contains", []))
                    or any(s not in result.stderr for s in probe.get("stderr_contains", []))):
                raise ContractError("COMMAND_BEHAVIOR", "Released command expectation failed")
        gates.append({"name": "command." + command + ".supported-behavior", "status": "pass"})
    return gates
