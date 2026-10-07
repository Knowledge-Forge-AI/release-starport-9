"""Explicit installed-client filesystem boundary for Nebular (stdlib only).

Authenticated inputs and wrappers are read-only mounts. Only bounded JSON is
returned from the unprivileged, disconnected client; raw harness logs stay local.
"""
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess

from rs9.errors import ContractError, safe_details
from rs9.hosted_commands import runtime_environment
from rs9.hosted_smoke import (
    _control_verifier, _import_preflight_script, _verifier_script,
    bound_diagnostic, expected_runtime_members, verify_nebular_runtime,
    verify_source_readback,
)
from rs9.release_core import digest
from rs9.scratch import canonical
from rs9.security import scan_for_credentials, validate_safe_relative_posix_path

GUEST = Path("/srv/rs9/smoke")
RUNTIME = "/usr/lib/theme-forge-nebular-fusion"
SCHEMA = "rs9.container-nebular-smoke.v1"
MAX_OUTPUT = 1024 * 1024
MAX_INPUT = 32 * 1024 * 1024


def read_output(path, limit=MAX_OUTPUT):
    """Never follow a client-planted symlink or read an unbounded/special file."""
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(fd, "rb") as stream:
            info = os.fstat(stream.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_size > limit:
                raise ContractError("SMOKE_OUTPUT", "Bounded regular client output required")
            data = stream.read(limit + 1)
    except OSError:
        raise ContractError("SMOKE_OUTPUT", "Client output unavailable",
                            details={"cause": "verifier-output", "missing_path": "output/result.json"}) from None
    if len(data) > limit:
        raise ContractError("SMOKE_OUTPUT", "Client output exceeded bound")
    try:
        scan_for_credentials(data.decode("utf-8"))
        doc = json.loads(data)
    except (ValueError, UnicodeError):
        raise ContractError("SMOKE_OUTPUT", "Client JSON output malformed") from None
    if not isinstance(doc, dict):
        raise ContractError("SMOKE_OUTPUT", "Client object output required")
    return doc


def prepare_container_smoke(prepared, system, family):
    """Bind host-authenticated manifests and explicit guest locations before launch."""
    if system not in {"x86_64-linux", "aarch64-linux"} or family not in {"apt", "dnf", "pacman"}:
        raise ContractError("SMOKE_INPUT", "Reviewed client family/system required")
    source = Path(prepared["source"])
    tools_relative = Path(prepared["tools"]).relative_to(source).as_posix()
    validate_safe_relative_posix_path(tools_relative)
    expected = expected_runtime_members(prepared, system)
    if not expected:
        raise ContractError("SIDECAR_MANIFEST_BINDING", "Authenticated installed manifest required")
    verify_source_readback(prepared)
    work = Path(prepared["scratch"]) / ("container-" + family)
    work.mkdir(exist_ok=False)
    inputs, output = work / "input", work / "output"
    inputs.mkdir(); output.mkdir()
    probe = inputs / "probe"
    probe.mkdir()
    guest_source, guest_tools = GUEST / "source", GUEST / "source" / tools_relative
    (probe / "verify-runtime.mjs").write_text(_verifier_script(guest_tools / "sidecar-common.mjs"))
    (probe / "verify-import-preflight.mjs").write_text(_import_preflight_script(guest_source, guest_tools))
    request = {"schema": SCHEMA, "family": family, "system": system,
               "tools_relative": tools_relative, "records": prepared["records"],
               "expected_members": expected, "manifest_sha256": digest(canonical(expected)),
               "probe_sha256": {p.name: digest(p.read_bytes()) for p in probe.iterdir()}}
    raw = canonical(request)
    if len(raw) > MAX_INPUT:
        raise ContractError("SMOKE_INPUT", "Client manifest closure exceeded bound")
    (inputs / "request.json").write_bytes(raw)
    # Public authenticated source copies and probe inputs need readable modes
    # regardless of the producer's umask. No private fixture keyring is touched.
    for directory in [work, inputs, probe, output, source, *[p for p in source.rglob("*") if p.is_dir()]]:
        if directory.is_symlink():
            raise ContractError("SMOKE_INPUT", "Physical source/probe directories required")
        directory.chmod(0o755)
    for path in [*inputs.rglob("*"), *source.rglob("*")]:
        if path.is_symlink():
            raise ContractError("SMOKE_INPUT", "Regular source/probe inputs required")
        if path.is_file():
            path.chmod(0o644)
    return {"prepared": prepared, "request": request, "request_sha256": digest(raw),
            "output": output, "family": family, "system": system,
            "mounts": [(str(source), str(GUEST / "source"), False),
                       (str(inputs), str(GUEST / "input"), False),
                       (str(output), str(GUEST / "out"), True)]}


def configure_container_output(client, *, user):
    """The writer is unprivileged; fixed public output modes do not depend on umask."""
    if user != "65534:65534":
        raise ContractError("UNPRIVILEGED_CLIENT_REQUIRED", "Reviewed client identity required")
    result = client.exec(["python3", "-c",
        "import os; p='/srv/rs9/smoke/out'; os.chown(p,65534,65534); os.chmod(p,0o755)"])
    if result.exit_code:
        raise ContractError("SMOKE_OUTPUT", "Client output ownership setup failed")


def verify_container_nebular(client, binding, *, user):
    command = ["python3", "-B", "-c",
               "import sys;sys.path.insert(0,'/rs9-source');"
               "from rs9.hosted_container_smoke import guest_main;sys.exit(guest_main())"]
    receipt = client.exec(command, user=user)
    try:
        return _accept_container_output(binding, receipt)
    except ContractError as error:
        # A crash or malformed/missing output must not discard command evidence.
        if error.code != "SMOKE_OUTPUT":
            raise
        raise error.with_details(family=binding["family"], stage="smoke",
                                 exit_code=receipt.exit_code, stdout_sha256=receipt.stdout_sha256,
                                 stderr_sha256=receipt.stderr_sha256) from None
    except Exception as error:
        raise ContractError("SMOKE_OUTPUT", "Client output processing failed", details={
            "exception_type": type(error).__name__, "family": binding["family"], "stage": "smoke",
            "exit_code": receipt.exit_code, "stdout_sha256": receipt.stdout_sha256,
            "stderr_sha256": receipt.stderr_sha256}) from None


def _accept_container_output(binding, receipt):
    doc = read_output(binding["output"] / "result.json")
    if (doc.get("schema") != SCHEMA or doc.get("request_sha256") != binding["request_sha256"]
            or doc.get("family") != binding["family"] or doc.get("system") != binding["system"]
            or doc.get("uid") != 65534 or doc.get("status") not in {"pass", "fail"}):
        raise ContractError("SMOKE_OUTPUT", "Client result binding differs")
    diagnostic = doc.get("diagnostic")
    if diagnostic is not None:
        if not isinstance(diagnostic, dict) or len(canonical(diagnostic)) > 60 * 1024:
            raise ContractError("SMOKE_OUTPUT", "Client diagnostic exceeded bound")
        diagnostic = bound_diagnostic(diagnostic)
        # The archive control deliberately executes on the host and is never
        # substituted for installed-client evidence. It has no guest prefix.
        prepared = binding["prepared"]
        capture = prepared.get("capture")
        if capture:
            script = Path(prepared["scratch"]) / "verify-host-control.mjs"
            script.write_text(_verifier_script(Path(prepared["tools"]) / "sidecar-common.mjs"))
            diagnostic["archive_control"] = _control_verifier(
                capture, binding["system"], prepared, script, (), runtime_environment(), runtime_identity=diagnostic)
            diagnostic["archive_control"]["filesystem"] = "host-control"
        diagnostic = bound_diagnostic(diagnostic)
        directory = Path(prepared["scratch"]).parent / "diagnostics"
        directory.mkdir(exist_ok=True)
        (directory / ("sidecar-verifier-" + binding["family"] + ".json")).write_bytes(canonical(diagnostic))
    if receipt.exit_code or not receipt.executed or doc["status"] != "pass":
        code = doc.get("code", "SMOKE_EXECUTION")
        if not isinstance(code, str) or not re.fullmatch(r"[A-Z][A-Z0-9_]{0,63}", code):
            code = "SMOKE_EXECUTION"
        raise ContractError(code, "Installed client verifier/smoke failed", details={
            "exit_code": receipt.exit_code, "stdout_sha256": receipt.stdout_sha256,
            "stderr_sha256": receipt.stderr_sha256,
            **safe_details(doc.get("details", {})), "family": binding["family"], "stage": "smoke"})
    result = doc.get("result")
    if (not isinstance(result, dict) or result.get("sidecar", {}).get("verified") is not True
            or not isinstance(result.get("scenarios"), list) or not result["scenarios"]
            or result.get("source_bindings_sha256") != digest(canonical(binding["request"]["records"]))):
        raise ContractError("SMOKE_OUTPUT", "Complete client qualification output required")
    expected = ["B"] if binding["system"] == "aarch64-linux" else ["C", "C-signal"]
    if ([r.get("scenario") for r in result["scenarios"] if isinstance(r, dict)] != expected
            or any(not isinstance(r, dict) or any(not isinstance(r.get(k), str)
                   or not re.fullmatch(r"[0-9a-f]{64}", r[k])
                   for k in ("receipt_sha256", "executable_sha256")) for r in result["scenarios"])):
        raise ContractError("SMOKE_OUTPUT", "Complete bound scenario receipts required")
    return {**result, "source_bindings": binding["request"]["records"], "filesystem": "installed-client"}


def _logical_io(error):
    path = Path(error.filename) if error.filename else None
    for root, location, resource in ((Path(RUNTIME), "runtime", "installed-runtime"),
                                     (GUEST / "source", "source", "verifier-source"),
                                     (GUEST / "input", "input", "verifier-source"),
                                     (GUEST / "out", "output", "smoke-evidence")):
        if path and path.is_relative_to(root):
            relative = path.relative_to(root).as_posix()
            try:
                validate_safe_relative_posix_path(relative)
            except ContractError:
                relative = "unclassified-resource"
            return {"cause": resource, "missing_path": location + "/" + relative,
                    "exception_type": type(error).__name__, "substage": "client-filesystem"}
    return {"cause": "verifier-output", "missing_path": "unclassified-resource",
            "exception_type": type(error).__name__, "substage": "client-filesystem"}


def guest_main():
    """Only called in the actual client. All Path/read/hash/subprocess work is local."""
    os.umask(0o022)
    result = {"schema": SCHEMA, "request_sha256": None,
              "family": None, "system": None, "uid": os.getuid(), "status": "fail"}
    scratch = GUEST / "out/work"
    try:
        with (GUEST / "input/request.json").open("rb") as stream:
            request_raw = stream.read(MAX_INPUT + 1)
        result["request_sha256"] = digest(request_raw)
        if len(request_raw) > MAX_INPUT:
            raise ContractError("SMOKE_INPUT", "Client request exceeded bound")
        try:
            request = json.loads(request_raw)
            if (not isinstance(request, dict) or request.get("family") not in {"apt", "dnf", "pacman"}
                    or request.get("system") not in {"x86_64-linux", "aarch64-linux"}):
                raise ValueError()
        except (ValueError, TypeError):
            raise ContractError("SMOKE_INPUT", "Client request malformed",
                                details={"reason_token": "request-malformed"}) from None
        result.update(family=request["family"], system=request["system"])
        if os.getuid() != 65534 or request.get("schema") != SCHEMA:
            raise ContractError("UNPRIVILEGED_CLIENT_REQUIRED", "Installed client identity required")
        source = GUEST / "source"
        scratch.mkdir()
        prepared = {"source": source, "tools": source / request["tools_relative"],
                    "scratch": scratch, "probe": GUEST / "input/probe", "container_client": True,
                    "records": request["records"], "expected_members": request["expected_members"],
                    "manifest_sha256": request["manifest_sha256"], "label": request["family"]}
        for name, sha in request["probe_sha256"].items():
            if name not in {"verify-runtime.mjs", "verify-import-preflight.mjs"} or digest((prepared["probe"] / name).read_bytes()) != sha:
                raise ContractError("SIDECAR_HARNESS_IMPORT", "Verifier wrapper identity differs")
        verify_source_readback(prepared)
        # Some released harnesses use checkout for temporary fixture work.
        # Execute modules from immutable source, give checkout a checked copy.
        checkout = GUEST / "out/checkout"
        shutil.copytree(source, checkout)
        verify_source_readback({**prepared, "source": checkout})
        prepared["checkout"] = checkout
        if not Path(RUNTIME).is_dir():
            raise FileNotFoundError(2, "Installed runtime absent", RUNTIME)
        evidence = verify_nebular_runtime(RUNTIME, prepared, request["system"], env={
            "PATH": os.environ.get("PATH", "/usr/bin:/bin"), "HOME": "/tmp",
            "PYTHONDONTWRITEBYTECODE": "1", "TMPDIR": "/tmp"})
        verify_source_readback(prepared)
        verify_source_readback({**prepared, "source": checkout})
        evidence.pop("source_bindings", None)
        result.update(status="pass", result={**evidence,
                      "source_bindings_sha256": digest(canonical(request["records"]))})
    except ContractError as error:
        details = dict(error.details)
        if error.code == "SIDECAR_HARNESS_IMPORT":
            details.setdefault("cause", "verifier-source")
            details.setdefault("missing_path", "source/verifier-closure")
        elif error.code == "SIDECAR_REPRESENTATION":
            details.update(cause="installed-runtime", missing_path="runtime/sidecar-representation")
        result.update(code=error.code, details=safe_details(details))
    except OSError as error:
        result.update(code="SMOKE_RESOURCE", details=_logical_io(error))
    except subprocess.TimeoutExpired as error:
        result.update(code="SMOKE_EXECUTION", details={"exception_type": "TimeoutExpired",
                      "reason_token": "process-timeout", "stdout_sha256": digest(error.output or b""),
                      "stderr_sha256": digest(error.stderr or b"")})
    except Exception as error:
        result.update(code="SMOKE_EXECUTION", details=safe_details({
            "exception_type": type(error).__name__, "reason_token": "guest-exception"}))
    if result["family"] is not None:
        try:
            diagnostic = GUEST / ("out/diagnostics/sidecar-verifier-" + result["family"] + ".json")
            if diagnostic.exists() or diagnostic.is_symlink():
                result["diagnostic"] = read_output(diagnostic, 60 * 1024)
        except Exception as error:
            failure = {"code": error.code if isinstance(error, ContractError) else "SMOKE_OUTPUT",
                       "exception_type": type(error).__name__, "reason_token": "diagnostic-unavailable"}
            result["diagnostic_error"] = safe_details(failure)
            if result["status"] == "pass":
                result.update(status="fail", code="SMOKE_OUTPUT", details=safe_details(failure))
    raw = canonical(result)
    if len(raw) > MAX_OUTPUT:
        return 2
    # This fixed output parent is client-owned, while the host refuses symlinks.
    try:
        fd = os.open(GUEST / "out/result.json", os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o644)
        with os.fdopen(fd, "wb") as stream:
            stream.write(raw)
    except OSError:
        # The host will retain the exit/stream hashes even if output storage fails.
        return 2
    return 0 if result["status"] == "pass" else 2
