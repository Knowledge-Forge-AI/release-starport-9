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
    export_current_source_readback,
)
from rs9.release_core import digest, read_evidence
from rs9.smoke_source_envelope import (GENERATION, checked_envelope, mint_guest_readback,
    verify_guest_prepared, verify_checkout)
from rs9.scratch import canonical
from rs9.security import scan_for_credentials, validate_safe_relative_posix_path

GUEST = Path("/srv/rs9/smoke")
RUNTIME = "/usr/lib/theme-forge-nebular-fusion"
SCHEMA = "rs9.container-nebular-smoke.v1"
MAX_OUTPUT = 1024 * 1024
MAX_INPUT = 32 * 1024 * 1024
_CURRENT_REQUEST_KEYS = {"schema", "family", "system", "tools_relative", "records", "expected_members",
                         "manifest_sha256", "probe_sha256", "source_readback"}


def _checked_current_request(request, raw, expected_sha256):
    if (not isinstance(request, dict) or not isinstance(raw, bytes) or len(raw) > MAX_INPUT
            or not isinstance(expected_sha256, str) or not re.fullmatch(r"[0-9a-f]{64}", expected_sha256)
            or digest(raw) != expected_sha256 or raw != canonical(request)
            or set(request) != _CURRENT_REQUEST_KEYS or request.get("schema") != SCHEMA
            or request.get("family") not in {"apt", "dnf", "pacman"}
            or request.get("system") not in {"x86_64-linux", "aarch64-linux"}
            or request.get("tools_relative") != "tools"):
        raise ContractError("SMOKE_INPUT", "Exact canonical current client request required")
    envelope = checked_envelope(request["source_readback"])
    members, probes = request.get("expected_members"), request.get("probe_sha256")
    if (request.get("records") != envelope["records"] or not isinstance(members, list)
            or not 1 <= len(members) <= 20000 or request.get("manifest_sha256") != digest(canonical(members))
            or not isinstance(probes, dict) or set(probes) != {"verify-runtime.mjs", "verify-import-preflight.mjs"}
            or any(not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{64}", value) for value in probes.values())):
        raise ContractError("SMOKE_INPUT", "Current source, manifest or wrapper request binding differs")
    return envelope


def _current_binding(binding):
    request = binding.get("request", {})
    prepared = binding.get("prepared")
    return ("request_bytes" in binding or "source_readback_sha256" in binding
            or isinstance(request, dict) and "source_readback" in request
            or isinstance(prepared, dict) and prepared.get("source_generation") == GENERATION)


def _recheck_current_binding(binding):
    """Parent acceptance always re-authenticates the original live objects."""
    try:
        return _recheck_current_binding_data(binding)
    except (OSError, ValueError, KeyError, TypeError, AttributeError):
        raise ContractError("SMOKE_INPUT", "Malformed current parent request binding") from None


def _check_current_probes(probe, request, source, tools):
    expected = {"verify-runtime.mjs": _verifier_script(tools / "sidecar-common.mjs"),
                "verify-import-preflight.mjs": _import_preflight_script(source, tools)}
    if set(path.name for path in probe.iterdir()) != set(expected):
        raise ContractError("SIDECAR_HARNESS_IMPORT", "Exact current wrapper file set required")
    for name, text in expected.items():
        if (request["probe_sha256"][name] != digest(text.encode())
                or read_evidence(probe, name, 64 * 1024) != text.encode()):
            raise ContractError("SIDECAR_HARNESS_IMPORT", "Current source-owned wrapper differs")


def _recheck_current_binding_data(binding):
    prepared, request = binding["prepared"], binding["request"]
    exported = export_current_source_readback(prepared)
    raw = binding["request_bytes"]
    envelope = _checked_current_request(request, raw, binding["request_sha256"])
    if (envelope != exported or digest(canonical(envelope)) != binding["source_readback_sha256"]
            or request["family"] != binding["family"] or request["system"] != binding["system"]
            or request["expected_members"] != expected_runtime_members(prepared, binding["system"])
            or read_evidence(binding["request_path"].parent, "request.json", MAX_INPUT) != raw):
        raise ContractError("SMOKE_INPUT", "Parent live source or exact request/envelope differs")
    source, tools = GUEST / "source", GUEST / "source/tools"
    _check_current_probes(binding["request_path"].parent / "probe", request, source, tools)
    return binding["source_readback_sha256"]


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
    current = prepared.get("source_generation") == GENERATION
    if current:
        source = source.resolve()
        tools_relative = Path(prepared["tools"]).resolve().relative_to(source).as_posix()
    else:
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
    if current:
        request["source_readback"] = export_current_source_readback(prepared)
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
    binding = {"prepared": prepared, "request": request, "request_sha256": digest(raw),
            "output": output, "family": family, "system": system,
            "mounts": [(str(source), str(GUEST / "source"), False),
                       (str(inputs), str(GUEST / "input"), False),
                       (str(output), str(GUEST / "out"), True)]}
    if current:
        binding.update(request_bytes=raw, request_path=inputs / "request.json",
                       source_readback_sha256=digest(canonical(request["source_readback"])))
    return binding


def configure_container_output(client, *, user):
    """The writer is unprivileged; fixed public output modes do not depend on umask."""
    if user != "65534:65534":
        raise ContractError("UNPRIVILEGED_CLIENT_REQUIRED", "Reviewed client identity required")
    result = client.exec(["python3", "-c",
        "import os; p='/srv/rs9/smoke/out'; os.chown(p,65534,65534); os.chmod(p,0o755)"])
    if result.exit_code:
        raise ContractError("SMOKE_OUTPUT", "Client output ownership setup failed")


def verify_container_nebular(client, binding, *, user):
    current = _current_binding(binding)
    if current:
        _recheck_current_binding(binding)
    guest_call = ("guest_main(expected_request_sha256=" + repr(binding["request_sha256"]) + ")"
                  if current else "guest_main()")
    command = ["python3", "-B", "-c",
               "import sys;sys.path.insert(0,'/rs9-source');"
               "from rs9.hosted_container_smoke import guest_main;sys.exit(" + guest_call + ")"]
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
    current_digest = _recheck_current_binding(binding) if _current_binding(binding) else None
    doc = read_output(binding["output"] / "result.json")
    if current_digest is not None:
        if (doc.get("status") == "pass" and doc.get("source_readback_sha256") != current_digest
                or "source_readback_sha256" in doc and doc["source_readback_sha256"] != current_digest):
            raise ContractError("SMOKE_OUTPUT", "Client source-readback envelope digest differs")
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
        smoke_obs = doc.get("smoke_observation")
        validated_obs = None
        diagnostic_sha = None
        if smoke_obs or code == "APPLICATION_SMOKE":
            from rs9.pages_smoke_diagnostic import validate_smoke_observation, retain_host_smoke_diagnostic
            validated_obs = validate_smoke_observation(smoke_obs, system=binding["system"])
            prepared = binding.get("prepared")
            if prepared and "scratch" in prepared:
                try:
                    diag_dir = Path(prepared["scratch"]).parent / "diagnostics"
                    diagnostic_sha = retain_host_smoke_diagnostic(diag_dir, validated_obs, family=binding["family"], system=binding["system"])
                except Exception:
                    pass

        err_details = {
            "exit_code": receipt.exit_code, "stdout_sha256": receipt.stdout_sha256,
            "stderr_sha256": receipt.stderr_sha256,
            **safe_details(doc.get("details", {})), "family": binding["family"], "stage": "smoke"}
        err = ContractError(code, "Installed client verifier/smoke failed", details=err_details)
        if validated_obs and isinstance(diagnostic_sha, str):
            err = err.with_details(diagnostic_sha256=diagnostic_sha)
        if validated_obs:
            err.smoke_observation = validated_obs
        raise err
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
    accepted = {**result, "source_bindings": binding["request"]["records"], "filesystem": "installed-client"}
    if current_digest is not None:
        accepted["source_readback_sha256"] = current_digest
    return accepted


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


def _guest_source_readback(prepared):
    if "_source_readback_proof" in prepared:
        return verify_guest_prepared(prepared)
    return verify_source_readback(prepared)


def _guest_checkout_readback(prepared, checkout):
    if "_source_readback_proof" in prepared:
        return verify_checkout(prepared["source_readback"], checkout)
    return verify_source_readback({**prepared, "source": checkout,
                                   "tools": checkout / Path(prepared["tools"]).relative_to(prepared["source"])})


def guest_main(*, expected_request_sha256=None):
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
        current = expected_request_sha256 is not None or "source_readback" in request
        envelope = _checked_current_request(request, request_raw, expected_request_sha256) if current else None
        if current:
            result["source_readback_sha256"] = digest(canonical(envelope))
        source = GUEST / "source"
        scratch.mkdir()
        prepared = {"source": source, "tools": source / request["tools_relative"],
                    "scratch": scratch, "probe": GUEST / "input/probe", "container_client": True,
                    "records": request["records"], "expected_members": request["expected_members"],
                    "manifest_sha256": request["manifest_sha256"], "label": request["family"]}
        if current:
            prepared.update(source_generation=GENERATION, source_readback=envelope,
                            _source_readback_proof=mint_guest_readback(envelope, source, prepared["tools"]))
        for name, sha in request["probe_sha256"].items():
            if name not in {"verify-runtime.mjs", "verify-import-preflight.mjs"} or digest((prepared["probe"] / name).read_bytes()) != sha:
                raise ContractError("SIDECAR_HARNESS_IMPORT", "Verifier wrapper identity differs")
        if current:
            _check_current_probes(prepared["probe"], request, source, prepared["tools"])
        _guest_source_readback(prepared)
        # Execute modules from immutable source and give the harness a checked
        # fixture-input copy. Current prepareFixtures writes to smokeDir, not checkout.
        checkout = GUEST / "out/checkout"
        shutil.copytree(source, checkout)
        _guest_checkout_readback(prepared, checkout)
        prepared["checkout"] = checkout
        if not Path(RUNTIME).is_dir():
            raise FileNotFoundError(2, "Installed runtime absent", RUNTIME)
        evidence = verify_nebular_runtime(RUNTIME, prepared, request["system"], env={
            "PATH": os.environ.get("PATH", "/usr/bin:/bin"), "HOME": "/tmp",
            "PYTHONDONTWRITEBYTECODE": "1", "TMPDIR": "/tmp"})
        _guest_source_readback(prepared)
        _guest_checkout_readback(prepared, checkout)
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
        smoke_obs = getattr(error, "smoke_observation", None)
        if smoke_obs:
            result["smoke_observation"] = smoke_obs
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
