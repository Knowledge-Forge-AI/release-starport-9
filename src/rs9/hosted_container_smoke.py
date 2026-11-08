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
from rs9.current_os080 import CURRENT080_COMMIT, CURRENT080_TAG, CURRENT080_TREE

GUEST = Path("/srv/rs9/smoke")
RUNTIME = "/usr/lib/theme-forge-nebular-fusion"
SCHEMA = "rs9.container-nebular-smoke.v1"
MAX_OUTPUT = 1024 * 1024
MAX_INPUT = 32 * 1024 * 1024
# Current pacman/aarch64-linux route only (owner policy option A). The guest constants
# equal rs9.archarm_sdk.PROBE_OUTPUT_TARGET/GUEST_HOME; the host re-checks the target.
ARCHARM_PLATFORM = "linux/arm64"
ARCHARM_SYSTEM = "aarch64-linux"
ARCHARM_PROBE_OUTPUT_GUEST = "/srv/rs9/probe-output"
ARCHARM_GUEST_SOURCE = "/srv/rs9/rs9-source"
ARCHARM_GUEST_HOME = "/tmp/home"
ARCHARM_GUEST_WORK = ARCHARM_GUEST_HOME + "/rs9-smoke"
ARCHARM_SMOKE_OUTPUT = "smoke"
ARCHARM_RESULT = ARCHARM_SMOKE_OUTPUT + "/result.json"
_ARCHARM_MAX_ID = 2147483647
_ARCHARM_IMAGE_RE = re.compile(r"sha256:[0-9a-f]{64}")
_ARCHARM_NAME_RE = re.compile(r"[a-z0-9][a-z0-9.-]{0,127}")
_ARCHARM_NO_OUTPUT = "rs9-no-declared-output"
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
    return _parse_output(data, limit)


def _parse_output(data, limit=MAX_OUTPUT):
    """Bounded credential-free JSON object; shared by the file and held-evidence readers."""
    if not isinstance(data, bytes):
        raise ContractError("SMOKE_OUTPUT", "Client JSON output malformed")
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
    return _prepare_container_binding(prepared, system, family, archarm=False)


def _prepare_container_binding(prepared, system, family, *, archarm):
    """Shared preparation. ``archarm`` omits the generic writable output bind; that route
    writes only below the lease's single owner-only probe-output tree."""
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
    inputs, output = work / "input", (None if archarm else work / "output")
    inputs.mkdir()
    if output is not None:
        output.mkdir()
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
    for directory in [work, inputs, probe, *([] if output is None else [output]), source,
                      *[p for p in source.rglob("*") if p.is_dir()]]:
        if directory.is_symlink():
            raise ContractError("SMOKE_INPUT", "Physical source/probe directories required")
        directory.chmod(0o755)
    for path in [*inputs.rglob("*"), *source.rglob("*")]:
        if path.is_symlink():
            raise ContractError("SMOKE_INPUT", "Regular source/probe inputs required")
        if path.is_file():
            path.chmod(0o644)
    if archarm:
        # Read-only inputs only. The result is written below the lease's probe-output
        # target and accepted solely from post-quiescence held SDK ingestion.
        binding = {"prepared": prepared, "request": request, "request_sha256": digest(raw),
                   "archarm_result": ARCHARM_RESULT, "family": family, "system": system,
                   "mounts": [(str(source), str(GUEST / "source"), False),
                              (str(inputs), str(GUEST / "input"), False)]}
    else:
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
    return _accept_with_receipt_details(binding, receipt, lambda: _accept_container_output(binding, receipt))


def _accept_with_receipt_details(binding, receipt, accept):
    try:
        return accept()
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


def _accept_container_output(binding, receipt, *, document=None, expected_uid=65534):
    """``document``/``expected_uid`` are supplied only by the current ArchARM acceptance,
    after held post-quiescence ingestion; the uid field is a binding check, never proof."""
    current_digest = _recheck_current_binding(binding) if _current_binding(binding) else None
    doc = read_output(binding["output"] / "result.json") if document is None else document
    if current_digest is not None:
        if (doc.get("status") == "pass" and doc.get("source_readback_sha256") != current_digest
                or "source_readback_sha256" in doc and doc["source_readback_sha256"] != current_digest):
            raise ContractError("SMOKE_OUTPUT", "Client source-readback envelope digest differs")
    if (doc.get("schema") != SCHEMA or doc.get("request_sha256") != binding["request_sha256"]
            or doc.get("family") != binding["family"] or doc.get("system") != binding["system"]
            or doc.get("uid") != expected_uid or doc.get("status") not in {"pass", "fail"}):
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
            validated_obs = validate_smoke_observation(smoke_obs, system=binding["system"], family=binding["family"])
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


# --------------------------------------------------------------------------- current ArchARM client boundary


def _archarm_refuse(reason):
    return ContractError("ARCHARM_CLIENT_LEASE", "A genuine held current ArchARM SDK lease is required",
                         details={"substage": "sdk-lease", "reason": reason})


def _archarm_sdk_module():
    """The authenticated sibling ``rs9.archarm_sdk``; a relocated or missing module is refused."""
    try:
        from rs9 import archarm_sdk
    except ImportError:
        raise ContractError("ARCHARM_SDK_UNAVAILABLE", "Current ArchARM SDK module is unavailable",
                            details={"substage": "sdk-lease"}) from None
    origin = getattr(archarm_sdk, "__file__", None)
    if not isinstance(origin, str) or Path(origin).resolve().parent != Path(__file__).resolve().parent:
        raise _archarm_refuse("sdk-module-origin")
    return archarm_sdk


def archarm_lease_identity(lease, client=None):
    """Bounded identity derived only from the actual held lease (and its own client).

    The lease must be exactly ``ArchArmSDK`` (not a subclass, dict, namespace or JSON),
    read back ``ready``, carry the current generation, ``linux/arm64`` and an immutable image
    ID, and be bound to this process's actual nonroot numeric UID/GID. A client must be the
    lease's own ``ArchArmClient`` on the same image/platform/probe-output target.
    """
    sdk = _archarm_sdk_module()
    if type(lease) is not sdk.ArchArmSDK:
        raise _archarm_refuse("lease-type")
    if lease.state != "ready":
        raise _archarm_refuse("lease-not-ready")
    uid, gid = lease.uid, lease.gid
    if (type(uid) is not int or type(gid) is not int or not 0 < uid <= _ARCHARM_MAX_ID
            or not 0 < gid <= _ARCHARM_MAX_ID or (uid, gid) != (os.getuid(), os.getgid())
            or lease.user != f"{uid}:{gid}"):
        raise _archarm_refuse("runner-identity")
    from rs9.current_generation import CURRENT_GENERATION
    image, records = lease.image, lease.records
    identity = records.get("identity") if isinstance(records, dict) else None
    if (lease.platform != ARCHARM_PLATFORM or type(image) is not str or not _ARCHARM_IMAGE_RE.fullmatch(image)
            or records.get("generation") != CURRENT_GENERATION or records.get("platform") != ARCHARM_PLATFORM
            or records.get("state") != "ready" or records.get("imageId") != image
            or not isinstance(identity, dict) or identity.get("uid") != uid or identity.get("gid") != gid
            or sdk.PROBE_OUTPUT_TARGET != ARCHARM_PROBE_OUTPUT_GUEST):
        raise _archarm_refuse("lease-join")
    if client is not None and (
            type(client) is not sdk.ArchArmClient or getattr(client, "_sdk", None) is not lease
            or client.image != image or client.platform != ARCHARM_PLATFORM
            or client.probe_output_target != ARCHARM_PROBE_OUTPUT_GUEST):
        raise _archarm_refuse("client-join")
    return {"uid": uid, "gid": gid, "user": f"{uid}:{gid}", "image": image}


def _archarm_output_refuse(reason):
    return ContractError("ARCHARM_PROBE_OUTPUT", "Owner-only probe-output tree required",
                         details={"substage": "probe-output-custody", "reason": reason})


def _archarm_owner_only_dir(info, identity):
    return (stat.S_ISDIR(info.st_mode) and info.st_uid == identity["uid"] and info.st_gid == identity["gid"]
            and stat.S_IMODE(info.st_mode) == 0o700)


def archarm_probe_root(path, identity):
    """The one owned probe-output root: a fresh 0700 directory, or the caller's existing
    empty 0700 owned one (P creates it); never world-writable, never a symlink."""
    if not isinstance(path, Path) or not path.is_absolute():
        raise _archarm_output_refuse("probe-root-path")
    text = str(path)
    try:
        if not os.path.lexists(text):
            parent = os.path.dirname(text)
            if not stat.S_ISDIR(os.lstat(parent).st_mode) or os.path.realpath(parent) != parent:
                raise _archarm_output_refuse("probe-root-parent")
            os.mkdir(text, 0o700)
            os.chmod(text, 0o700)
        info = os.lstat(text)
        entries = os.listdir(text) if stat.S_ISDIR(info.st_mode) else None
    except OSError:
        raise _archarm_output_refuse("probe-root-unavailable") from None
    if not _archarm_owner_only_dir(info, identity) or entries or os.path.realpath(text) != text:
        raise _archarm_output_refuse("probe-root-unsafe")
    return path


def archarm_product_output(root, name, identity):
    """A fresh owner-only child: the client's sole writable bind (no 0777, no reuse)."""
    if not isinstance(name, str) or not _ARCHARM_NAME_RE.fullmatch(name):
        raise _archarm_output_refuse("product-output-name")
    path = Path(root) / name
    try:
        os.mkdir(path, 0o700)
        os.chmod(path, 0o700)
        info = os.lstat(path)
    except OSError:
        raise _archarm_output_refuse("product-output-unavailable") from None
    if not _archarm_owner_only_dir(info, identity):
        raise _archarm_output_refuse("product-output-unsafe")
    return path


def archarm_bounded_bytes(limit, *, text=False):
    """Existing-schema byte bound for one declared untrusted probe-output file."""
    def validate(data):
        if not isinstance(data, bytes) or len(data) > limit:
            raise ValueError("bounded probe output required")
        if text:
            data.decode("utf-8")
        return data
    return validate


def _archarm_no_output(data):
    raise ValueError("no probe output is declared")


def archarm_smoke_declarations():
    return {ARCHARM_RESULT: archarm_bounded_bytes(MAX_OUTPUT)}


def archarm_ingest_output(client, lease, declared):
    """Untrusted probe-output ingestion through the SDK only after the client was quiesced.

    The SDK refuses unless its own client writer was stopped and read back
    (``EVIDENCE_NOT_QUIESCED``), then walks held no-follow descriptors with owner/mode/link/
    stable-identity checks. Undeclared entries fail; an empty declaration proves the tree
    is empty. The result is never qualification authority.
    """
    sdk = _archarm_sdk_module()
    archarm_lease_identity(lease, client)
    declared = dict(declared) or {_ARCHARM_NO_OUTPUT: _archarm_no_output}
    evidence = client.ingest_output(declared, ())
    if type(evidence) is not sdk.UntrustedEvidence or evidence.authority is not False:
        raise _archarm_output_refuse("ingestion-type")
    return evidence


def prepare_archarm_container_smoke(prepared, system, family, *, lease):
    """Read-only smoke inputs for the current ArchARM client; no generic writable bind."""
    archarm_lease_identity(lease)
    if (system != ARCHARM_SYSTEM or family != "pacman" or not isinstance(prepared, dict)
            or prepared.get("source_generation") != GENERATION):
        raise ContractError("SMOKE_INPUT", "Current pacman/aarch64-linux smoke binding required")
    return _prepare_container_binding(prepared, system, family, archarm=True)


def _archarm_binding(binding):
    if (not isinstance(binding, dict) or "output" in binding or binding.get("archarm_result") != ARCHARM_RESULT
            or binding.get("family") != "pacman" or binding.get("system") != ARCHARM_SYSTEM
            or not _current_binding(binding)):
        raise ContractError("SMOKE_INPUT", "Current ArchARM client smoke binding required")


def run_archarm_container_nebular(client, binding, *, lease):
    """Run the guest verifier as the verified runner through the SDK drop-only preamble.

    Returns only the trusted host receipt. Nothing from the probe-output tree is read
    here: the client writer is still live.
    """
    identity = archarm_lease_identity(lease, client)
    _archarm_binding(binding)
    _recheck_current_binding(binding)
    guest_call = "guest_main(expected_request_sha256=%r,archarm_identity=(%d,%d))" % (
        binding["request_sha256"], identity["uid"], identity["gid"])
    command = ["python3", "-B", "-c",
               "import sys;sys.path.insert(0," + repr(ARCHARM_GUEST_SOURCE) + ");"
               "from rs9.hosted_container_smoke import guest_main;sys.exit(" + guest_call + ")"]
    return client.exec(command, user=identity["user"])


def accept_archarm_container_nebular(binding, receipt, evidence, *, lease):
    """Accept the guest result only from post-quiescence held SDK ingestion.

    The result's uid/gid must equal the lease identity, but that is a binding check, not
    proof: identity comes from the SDK's attested preamble and the held-owner checks.
    """
    sdk = _archarm_sdk_module()
    identity = archarm_lease_identity(lease)
    _archarm_binding(binding)
    if type(evidence) is not sdk.UntrustedEvidence:
        raise ContractError("SMOKE_OUTPUT", "Quiesced held probe-output evidence required")

    def accept():
        row = evidence.files.get(ARCHARM_RESULT)
        if row is None:
            raise ContractError("SMOKE_OUTPUT", "Client output unavailable",
                                details={"cause": "verifier-output", "missing_path": "output/result.json"})
        doc = _parse_output(row["value"])
        if type(doc.get("uid")) is not int or type(doc.get("gid")) is not int or doc["gid"] != identity["gid"]:
            raise ContractError("SMOKE_OUTPUT", "Client result binding differs")
        return _accept_container_output(binding, receipt, document=doc, expected_uid=identity["uid"])
    return _accept_with_receipt_details(binding, receipt, accept)


def _logical_io(error, *, archarm=False):
    path = Path(error.filename) if error.filename else None
    roots = ((Path(RUNTIME), "runtime", "installed-runtime"),
             (GUEST / "source", "source", "verifier-source"),
             (GUEST / "input", "input", "verifier-source"),
             (GUEST / "out", "output", "smoke-evidence"))
    if archarm:
        roots += ((Path(ARCHARM_PROBE_OUTPUT_GUEST), "output", "smoke-evidence"),
                  (Path(ARCHARM_GUEST_WORK), "output", "smoke-evidence"))
    for root, location, resource in roots:
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


def _guest_archarm_identity(identity, expected_request_sha256):
    """Guest-side check of the host-source-supplied expected identity (never self-proof)."""
    if (type(identity) is not tuple or len(identity) != 2
            or any(type(value) is not int or not 0 < value <= _ARCHARM_MAX_ID for value in identity)
            or (os.getuid(), os.getgid()) != identity or expected_request_sha256 is None):
        raise ContractError("UNPRIVILEGED_CLIENT_REQUIRED", "Verified ArchARM runner identity required")


def guest_main(*, expected_request_sha256=None, archarm_identity=None):
    """Only called in the actual client. All Path/read/hash/subprocess work is local.

    ``archarm_identity`` (current ArchARM route only) is the verified runner UID/GID from
    the trusted host program. The result goes to an owner-only directory below the lease's
    single probe-output bind, and scratch/checkout stay in the fresh guest home tmpfs.
    """
    archarm = archarm_identity is not None
    os.umask(0o077 if archarm else 0o022)
    result = {"schema": SCHEMA, "request_sha256": None,
              "family": None, "system": None, "uid": os.getuid(), "status": "fail"}
    if archarm:
        result["gid"] = os.getgid()
    output = Path(ARCHARM_PROBE_OUTPUT_GUEST) / ARCHARM_SMOKE_OUTPUT if archarm else GUEST / "out"
    work_root = Path(ARCHARM_GUEST_WORK) if archarm else GUEST / "out"
    scratch = work_root / "work"
    try:
        if archarm:
            _guest_archarm_identity(archarm_identity, expected_request_sha256)
            os.mkdir(output, 0o700)
            os.mkdir(work_root, 0o700)
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
        if (not archarm and os.getuid() != 65534) or request.get("schema") != SCHEMA:
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
                    "manifest_sha256": request["manifest_sha256"], "family": request["family"], "label": request["family"]}
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
        checkout = work_root / "checkout"
        shutil.copytree(source, checkout)
        _guest_checkout_readback(prepared, checkout)
        prepared["checkout"] = checkout
        if not Path(RUNTIME).is_dir():
            raise FileNotFoundError(2, "Installed runtime absent", RUNTIME)
        from rs9.current_os071 import CURRENT071_COMMIT, CURRENT071_TREE
        nebular_producer = (envelope.get("producers", {}).get("nebular")
                            if isinstance(envelope, dict) and isinstance(envelope.get("producers"), dict)
                            else None)
        current080_source = (
            current
            and isinstance(nebular_producer, dict)
            and nebular_producer.get("tag") == CURRENT080_TAG
            and nebular_producer.get("commit") == CURRENT080_COMMIT
            and nebular_producer.get("tree") == CURRENT080_TREE
        )
        current071_apt = (
            current
            and request["family"] == "apt"
            and not current080_source
            and isinstance(nebular_producer, dict)
            and nebular_producer.get("tag") == "v0.7.1"
            and nebular_producer.get("commit") == CURRENT071_COMMIT
            and nebular_producer.get("tree") == CURRENT071_TREE
        )
        runtime_kwargs = {"current071_cleanup_observation": True} if current071_apt else {}
        evidence = verify_nebular_runtime(RUNTIME, prepared, request["system"], env={
            "PATH": os.environ.get("PATH", "/usr/bin:/bin"), "HOME": ARCHARM_GUEST_HOME if archarm else "/tmp",
            "PYTHONDONTWRITEBYTECODE": "1", "TMPDIR": "/tmp"}, **runtime_kwargs)
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
        result.update(code="SMOKE_RESOURCE", details=_logical_io(error, archarm=archarm))
    except subprocess.TimeoutExpired as error:
        result.update(code="SMOKE_EXECUTION", details={"exception_type": "TimeoutExpired",
                      "reason_token": "process-timeout", "stdout_sha256": digest(error.output or b""),
                      "stderr_sha256": digest(error.stderr or b"")})
    except Exception as error:
        result.update(code="SMOKE_EXECUTION", details=safe_details({
            "exception_type": type(error).__name__, "reason_token": "guest-exception"}))
    if result["family"] is not None:
        try:
            diagnostic = work_root / "diagnostics" / ("sidecar-verifier-" + result["family"] + ".json")
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
        fd = os.open(output / "result.json", os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                     0o600 if archarm else 0o644)
        with os.fdopen(fd, "wb") as stream:
            stream.write(raw)
    except OSError:
        # The host will retain the exit/stream hashes even if output storage fails.
        return 2
    return 0 if result["status"] == "pass" else 2
