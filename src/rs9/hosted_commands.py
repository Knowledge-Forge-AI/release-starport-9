"""Release-bound supported command probes, including the studio NDJSON protocol."""
import hashlib
import io
import json
import os
from pathlib import Path
import selectors
import subprocess
import tarfile
import time

from rs9.current_generation import HISTORICAL_GENERATION, CURRENT_GENERATION, command_contract_path
from rs9.errors import ContractError
from rs9.release_core import authenticated_record_hash
from rs9.scratch import canonical

_BOUND = {}
# References to freshly created binding objects never cross the JSON boundary.
_CAPABILITIES = {}


def contracts(repository=None, *, generation=HISTORICAL_GENERATION):
    relative = command_contract_path(generation)
    root = Path(repository) if repository else Path(__file__).resolve().parents[2]
    document = json.loads((root / relative).read_bytes())
    if generation == CURRENT_GENERATION and document.get("generation") != generation:
        raise ContractError("COMMAND_CONTRACT", "Selected command contract generation differs")
    return document["commands"]


def probes_for(command, repository=None, *, generation=HISTORICAL_GENERATION):
    row = contracts(repository, generation=generation).get(command)
    if row is None:
        raise ContractError("COMMAND_CONTRACT", "Unknown application command")
    return row["probes"]


def bind_commands(captures, repository, output, *, generation=HISTORICAL_GENERATION):
    """Inspect authenticated implementation bytes before allowing a declared probe.

    Local research alone cannot qualify the released command. The hosted capture
    must contain its declared implementation and every source guard. The receipt
    binds those exact bytes and asset identities, rather than an ambient checkout.
    """
    rows = contracts(repository, generation=generation)
    identity = hashlib.sha256(canonical(rows)).hexdigest()
    bindings = {}
    if generation == CURRENT_GENERATION:
        _BOUND.clear()
        _CAPABILITIES.clear()
    for capture, intent, _ in captures:
        release_hash = authenticated_record_hash(capture)
        for name, row in rows.items():
            if row["project"] != intent["project"]["id"]:
                continue
            if generation == CURRENT_GENERATION and (
                    capture.record["tag"]["commit"] != row["evidence"]["commit"]
                    or capture.record["release"]["tag"] != row["evidence"]["tag"]
                    or capture.record["repository"]["full_name"] != row["evidence"]["repository"]):
                raise ContractError("COMMAND_BINDING", "Selected command release differs from authenticated capture")
            evidence = dict(capture.source)
            archived = {}
            for payload in capture.record["payloads"]:
                archive_input = capture.archives[payload["id"]]
                if generation == CURRENT_GENERATION:
                    data = archive_input.read_bytes()
                    if hashlib.sha256(data).hexdigest() != payload["sha256"]:
                        raise ContractError("COMMAND_BINDING", "Authenticated command archive changed")
                    archive_input = io.BytesIO(data)
                opened = (tarfile.open(fileobj=archive_input, mode="r:*") if generation == CURRENT_GENERATION
                          else tarfile.open(archive_input, "r:*"))
                with opened as archive:
                    for member in archive:
                        if member.isfile() and member.size <= 2 * 1024 ** 2:
                            suffix = member.name.split("/", 1)[-1]
                            if suffix in row["implementation_paths"]:
                                implementation = archive.extractfile(member).read()
                                if (generation == CURRENT_GENERATION and suffix in archived
                                        and archived[suffix] != implementation):
                                    raise ContractError("COMMAND_BINDING", "Released implementation differs between payloads")
                                archived[suffix] = implementation
                                evidence[suffix] = implementation
            inspected = {p: evidence[p] for p in row["implementation_paths"] if p in evidence}
            text = "\n".join(b.decode("utf-8", errors="replace") for b in inspected.values())
            missing = [guard for guard in row["source_guards"] if guard not in text]
            established = bool(inspected) and not missing
            # Launcher metadata is independently authenticated by the Nebular profile.
            if name == "tfnf" and generation == HISTORICAL_GENERATION:
                established = any("tfnf" in p.get("launchers", {}) for p in capture.record["payloads"])
            if generation == CURRENT_GENERATION:
                established = established and {p: hashlib.sha256(b).hexdigest() for p, b in inspected.items()} == row["implementation_sha256"]
            bindings[name] = {"status": "bound" if established else "unresearched",
                              "release_record_sha256": release_hash,
                              "asset_sha256": [p["sha256"] for p in capture.record["payloads"]],
                              "implementation_sha256": {p: hashlib.sha256(b).hexdigest() for p, b in inspected.items()},
                              "reason": None if established else "released-implementation-guard-missing"}
            if generation == CURRENT_GENERATION:
                bindings[name].update(generation=generation, contract_sha256=identity)
    _BOUND.clear()
    _BOUND.update(bindings)
    _CAPABILITIES.clear()
    if generation == CURRENT_GENERATION:
        _CAPABILITIES.update(bindings)
    target = Path(output) / "command-bindings.json"
    receipt = {"schema": "rs9.command-bindings.v1alpha1", "production_enabled": False, "commands": bindings}
    if generation == CURRENT_GENERATION:
        receipt.update(generation=generation, contract_sha256=identity)
    target.write_bytes(canonical(receipt))
    return target


def _read_frame(child, selector, deadline, observed=None):
    buffered = bytearray()
    while time.monotonic() < deadline:
        if selector.select(min(1, max(0, deadline - time.monotonic()))):
            raw = os.read(child.stdout.fileno(), 1)
            if not raw:
                raise ContractError("SERVICE_FRAME", "Bounded NDJSON response required")
            buffered.extend(raw)
            if observed is not None:
                observed.update(raw)
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
    observed = hashlib.sha256()
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
        initial = _read_frame(child, selector, deadline, observed)
        result = initial.get("result", {})
        if (initial.get("jsonrpc") != "2.0" or initial.get("id") != 1 or "error" in initial
                or result.get("selectedVersion") != "1.0" or not isinstance(result.get("sessionNonce"), str)
                or not result["sessionNonce"]):
            raise ContractError("SERVICE_INITIALIZE", "Studio negotiation failed")
        send("initialized", {"sessionNonce": result["sessionNonce"]})
        send("shutdown", {"sessionNonce": result["sessionNonce"]}, 2)
        shutdown = _read_frame(child, selector, deadline, observed)
        if shutdown != {"jsonrpc": "2.0", "id": 2, "result": None}:
            raise ContractError("SERVICE_SHUTDOWN", "Studio shutdown failed")
        send("exit", {})
        child.stdin.close()
        child.stdin = None
        stdout, stderr = child.communicate(timeout=max(1, deadline - time.monotonic()))
        if child.returncode != 0 or stdout or stderr:
            raise ContractError("SERVICE_TERMINATION", "Studio lifecycle did not terminate cleanly")
        observed.update(stdout)
        return {"selected_version": result["selectedVersion"], "exit_code": child.returncode,
                "stdout_sha256": observed.hexdigest(), "stderr_sha256": hashlib.sha256(stderr).hexdigest()}
    except (ContractError, ValueError, OSError, subprocess.TimeoutExpired) as error:
        if child.poll() is None:
            child.kill()
        stdout, stderr = child.communicate(timeout=5)
        observed.update(stdout or b"")
        raise ContractError(error.code if isinstance(error, ContractError) else "SERVICE_PROTOCOL",
                            "Released service protocol failed", details={"exit_code": child.returncode,
                                "stdout_sha256": observed.hexdigest(),
                                "stderr_sha256": hashlib.sha256(stderr or b"").hexdigest()}) from None
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
        "WEBKIT_DISABLE_COMPOSITING_MODE","WEBKIT_DISABLE_DMABUF_RENDERER",
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


def command_diagnostic(command, index, probe, result, repository=None, system=None, substage="command-probe", *, generation=HISTORICAL_GENERATION):
    """Fixed contract identity and stream digests; never retain raw command output."""
    stdout = result.stdout or ""
    stderr = result.stderr or ""
    stdout = stdout.encode() if isinstance(stdout, str) else stdout
    stderr = stderr.encode() if isinstance(stderr, str) else stderr
    text = stderr.decode("utf-8", errors="replace").lower()
    tokens = (("uid-map-denied", ("uid_map", "permission denied")),
              ("uid-map-denied", ("uid map", "permission denied")),
              ("userns-denied", ("no permissions to create new namespace",)),
              ("userns-denied", ("creating new namespace", "operation not permitted")),
              ("userns-denied", ("user namespace", "permission denied")),
              ("shared-library-missing", ("error while loading shared libraries",)),
              ("display-unavailable", ("cannot open display",)),
              ("no-such-file", ("no such file or directory",)))
    token = next((name for name, parts in tokens if all(p in text for p in parts)), "unclassified-command-failure")
    rows = contracts(repository, generation=generation)
    identity = {"product": rows[command]["project"], "command": command,
                "probe_id": f"{command}.{index}.{probe['kind']}", "substage": substage,
                "exit_code": result.returncode, "stdout_sha256": hashlib.sha256(stdout).hexdigest(),
                "stderr_sha256": hashlib.sha256(stderr).hexdigest(), "diagnostic_token": token}
    if generation == CURRENT_GENERATION:
        identity.update(generation=generation, contract_sha256=hashlib.sha256(canonical(rows)).hexdigest())
    if system:
        identity["system"] = system
    if "expect_exit" in probe:
        identity.update(expected_exit=probe["expect_exit"],
                        stdout_matches=all(s.encode() in stdout for s in probe.get("stdout_contains", [])),
                        stderr_matches=all(s.encode() in stderr for s in probe.get("stderr_contains", [])))
    return identity


def run_probes(command, path, repository=None, prefix=None, env=None, after_probe=None, *, system=None, substage="command-probe", generation=HISTORICAL_GENERATION):
    command_contract_path(generation)  # Validate the closed selector before any I/O.
    binding = _BOUND.get(command, {})
    if (binding.get("status") != "bound"
            or binding.get("generation", HISTORICAL_GENERATION) != generation
            or (generation == CURRENT_GENERATION and _CAPABILITIES.get(command) is not binding)):
        return [{"name": "command." + command + ".supported-behavior", "status": "not-run",
                 "reason": "released-command-contract-unbound"}]
    if generation == CURRENT_GENERATION:
        rows = contracts(repository, generation=generation)
        if binding.get("contract_sha256") != hashlib.sha256(canonical(rows)).hexdigest():
            return [{"name": "command." + command + ".supported-behavior", "status": "not-run",
                     "reason": "released-command-contract-unbound"}]
    env = runtime_environment(env)
    gates = []
    for index, probe in enumerate(probes_for(command, repository, generation=generation)):
        argv = [*(prefix or []), str(path), *probe["argv"]]
        if probe["kind"] == "service-protocol":
            try:
                service_protocol(argv, env)
            except ContractError as error:
                raise error.with_details(product=contracts(repository, generation=generation)[command]["project"], command=command,
                                         probe_id=f"{command}.{index}.{probe['kind']}", system=system,
                                         substage=substage) from None
            except OSError:
                raise ContractError("SERVICE_EXECUTION", "Released service probe unavailable",
                                    details={"product": contracts(repository, generation=generation)[command]["project"], "command": command,
                                             "probe_id": f"{command}.{index}.{probe['kind']}", "system": system,
                                             "substage": substage, "diagnostic_token": "spawn-unavailable"}) from None
        else:
            try:
                result = subprocess.run(argv, input=probe.get("input", ""), capture_output=True,
                                        text=True, env=env, timeout=30)
            except subprocess.TimeoutExpired as error:
                result = subprocess.CompletedProcess([], None, error.stdout, error.stderr)
                raise ContractError("COMMAND_TIMEOUT", "Released command probe timed out",
                                    details=command_diagnostic(command, index, probe, result, repository, system, substage, generation=generation)) from None
            except OSError:
                raise ContractError("COMMAND_EXECUTION", "Released command probe unavailable",
                                    details={"product": contracts(repository, generation=generation)[command]["project"], "command": command,
                                             "probe_id": f"{command}.{index}.{probe['kind']}", "system": system,
                                             "substage": substage, "diagnostic_token": "spawn-unavailable"}) from None
            if (result.returncode != probe["expect_exit"]
                    or any(s not in result.stdout for s in probe.get("stdout_contains", []))
                    or any(s not in result.stderr for s in probe.get("stderr_contains", []))):
                raise ContractError("COMMAND_BEHAVIOR", "Released command expectation failed",
                                    details=command_diagnostic(command, index, probe, result, repository, system, substage, generation=generation))
        gates.append({"name": "command." + command + ".supported-behavior", "status": "pass"})
        if after_probe is not None:
            after_probe()
    return gates
