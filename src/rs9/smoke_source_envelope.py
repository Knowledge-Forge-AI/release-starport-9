"""Fixed current source readback only; no release or configuration capability.

Guest validation trusts source-owned expectations, not publisher assertions or
serialized capture objects. This module never constructs a ReleaseCapture.
"""
import hashlib
from pathlib import Path
import json

from rs9.errors import ContractError
from rs9.release_core import digest, read_evidence
from rs9.scratch import canonical

SCHEMA = "rs9.current-smoke-source-readback.v1"
GENERATION = "theme-forge-current-202610"
MAX_ENVELOPE = 64 * 1024
AUTHORITY = {"scope": "source-readback-only", "release_authentication": False,
             "configuration_authority": False, "profile_authority": False,
             "publication_authority": False}
_READBACK_ONLY = object()


def _fail():
    raise ContractError("SIDECAR_HARNESS_IMPORT", "Current source readback envelope or files differ",
                        details={"substage": "verifier-source-readback", "reason": "source-envelope-binding"})


def _expectations(commit=None):
    # Lazy import keeps the fixed expectations owned by hosted_smoke, and does
    # not load the checkout-only caller JSON or invoke authentication APIs.
    from rs9 import hosted_smoke as s
    if commit is None or commit == s.CURRENT070_COMMIT:
        files, imports = s.CURRENT070_VERIFIER_FILES, s.CURRENT070_VERIFIER_IMPORTS
        commit, tree, tag = s.CURRENT070_COMMIT, s.CURRENT070_TREE, "v0.7.0"
    elif commit == s.CURRENT071_COMMIT:
        files, imports = s.CURRENT071_VERIFIER_FILES, s.CURRENT071_VERIFIER_IMPORTS
        commit, tree, tag = s.CURRENT071_COMMIT, s.CURRENT071_TREE, "v0.7.1"
    else:
        _fail()
    modules = set(files) - {"package.json"}
    if (set(imports) != modules
            or any(set(edges) - modules for edges in imports.values())):
        _fail()
    pins = {**files, **s.CURRENT070_FIXTURE_FILES}
    records = {}
    for name, pin in pins.items():
        fixture = name in s.CURRENT070_FIXTURE_FILES
        role = ("fixture" if fixture else "verifier-support" if name == "package.json"
                else "application-smoke" if name == "tools/native-rc-smoke.mjs" else "verifier-module")
        records[name] = {"path": name, **pin, "role": role,
                         "tag_commit": s.CURRENT070_FIXTURE_COMMIT if fixture else commit}
    producers = {
        "nebular": {"repository": "Knowledge-Forge-AI/theme-forge-nebular-fusion", "tag": tag,
                    "commit": commit, "tree": tree},
        "fixture": {"repository": "Knowledge-Forge-AI/theme-forge-stellar-burst", "tag": "v0.7.0",
                    "commit": s.CURRENT070_FIXTURE_COMMIT, "tree": s.CURRENT070_FIXTURE_TREE}}
    return records, producers


def _record_expectations(records):
    if not isinstance(records, list) or any(not isinstance(row, dict) for row in records):
        _fail()
    values = [row.get("tag_commit") for row in records if row.get("role") != "fixture"]
    if any(not isinstance(value, str) for value in values):
        _fail()
    commits = set(values)
    if len(commits) != 1:
        _fail()
    commit = next(iter(commits))
    if not isinstance(commit, str):
        _fail()
    return _expectations(commit)


def checked_records(records):
    expected, _ = _record_expectations(records)
    if (not isinstance(records, list) or len(records) != len(expected)
            or any(not isinstance(row, dict) or not isinstance(row.get("path"), str) for row in records)):
        _fail()
    if {row["path"] for row in records} != set(expected):
        _fail()
    for row in records:
        pin = expected[row["path"]]
        if (set(row) != set(pin) or type(row.get("size")) is not int
                or any(row.get(key) != value for key, value in pin.items())):
            _fail()
    return json.loads(canonical(records))


def verify_members(source, tools, records):
    """Pure fixed-source/producer/role/hash readback; confers no authentication."""
    records = checked_records(records)
    source, tools = Path(source), Path(tools)
    if source.is_symlink() or tools.resolve() != source.resolve() / "tools":
        _fail()
    source = source.resolve()
    observed = set()
    for path in source.rglob("*"):
        if path.is_symlink():
            _fail()
        if path.is_file():
            observed.add(path.relative_to(source).as_posix())
        elif not path.is_dir():
            _fail()
    if observed != {row["path"] for row in records}:
        _fail()
    for row in records:
        if row["size"] > 2 * 1024 * 1024:
            _fail()
        try:
            data = read_evidence(source, row["path"], row["size"])
        except ContractError:
            _fail()
        blob = hashlib.sha1(b"blob " + str(len(data)).encode() + b"\0" + data).hexdigest()
        if len(data) != row["size"] or digest(data) != row["sha256"] or blob != row["blob"]:
            _fail()
    return records


def _make_envelope(records):
    """Data constructor only. Parent export separately requires live captures."""
    records = checked_records(records)
    return {"schema": SCHEMA, "generation": GENERATION, "authority": dict(AUTHORITY),
            "producers": _record_expectations(records)[1], "importer": "tools", "records": records,
            "source_bindings_sha256": digest(canonical(records))}


def checked_envelope(envelope):
    if not isinstance(envelope, dict) or set(envelope) != {
            "schema", "generation", "authority", "producers", "importer", "records", "source_bindings_sha256"}:
        _fail()
    records = checked_records(envelope["records"])
    expected = _make_envelope(records)
    if (envelope != expected or len(canonical(envelope)) > MAX_ENVELOPE
            or any(envelope["authority"].get(key) is not False for key in
                   ("release_authentication", "configuration_authority", "profile_authority", "publication_authority"))):
        _fail()
    return json.loads(canonical(expected))


class _SourceReadbackProof:
    """Guest-local source proof only; intentionally lacks all release APIs."""
    def __init__(self, envelope, source, tools, *, token=None):
        if token is not _READBACK_ONLY:
            _fail()
        self._token = token
        self._digest = digest(canonical(envelope))
        self._source = Path(source).resolve()
        self._tools = Path(tools).resolve()


def mint_guest_readback(envelope, source, tools):
    """Explicit guest validation against fixed code expectations and files."""
    envelope = checked_envelope(envelope)
    verify_members(source, tools, envelope["records"])
    return _SourceReadbackProof(envelope, source, tools, token=_READBACK_ONLY)


def verify_guest_prepared(prepared):
    proof = prepared.get("_source_readback_proof")
    envelope = checked_envelope(prepared.get("source_readback"))
    if (not isinstance(proof, _SourceReadbackProof) or proof._token is not _READBACK_ONLY
            or "capture" in prepared or "fixture_capture" in prepared
            or prepared.get("container_client") is not True
            or prepared.get("source_generation") != GENERATION
            or proof._digest != digest(canonical(envelope))
            or Path(prepared["source"]).resolve() != proof._source
            or Path(prepared["tools"]).resolve() != proof._tools
            or prepared.get("records") != envelope["records"]):
        _fail()
    verify_members(prepared["source"], prepared["tools"], envelope["records"])
    return proof._digest


def verify_checkout(envelope, checkout):
    """Rebase both readback roots; does not change the immutable importer root."""
    envelope = checked_envelope(envelope)
    verify_members(checkout, Path(checkout) / envelope["importer"], envelope["records"])
