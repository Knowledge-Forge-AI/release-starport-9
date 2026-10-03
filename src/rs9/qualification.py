"""Qualification from attended local execution, never from imported verdict JSON.

The trusted boundary is reviewed verifier code run by the operator. A verifier
must inspect the real adapter boundary; exit zero from an arbitrary user command
is not a verifier. CI attestation import is intentionally unsupported.
"""
import hashlib
import inspect
import platform
from pathlib import Path

from rs9.errors import ContractError
from rs9.records import record_sha256, snapshot, validate_sha256, validate_sanitized_string, closed, validate_bounded_int
from rs9.release_core import authenticated_record_hash
from rs9.scratch import physical_directory
from rs9.security import validate_safe_relative_posix_path

_PROOF = object()


class Qualification:
    def __init__(self, record, *, _proof=None):
        self.record = snapshot(record)
        self._hash = record_sha256(record)
        self._proof = _proof


def artifact_inventory(root, artifacts):
    root = physical_directory(root)
    rows = []
    for expected in artifacts:
        validate_safe_relative_posix_path(expected["path"])
        path = root / expected["path"]
        if any(p.is_symlink() for p in (path, *path.parents)) or not path.is_file():
            raise ContractError("QUALIFICATION_ARTIFACT", "Physical candidate artifact required")
        data = path.read_bytes()
        actual = {"path": expected["path"], "size": len(data),
                  "sha256": hashlib.sha256(data).hexdigest()}
        if actual != expected:
            raise ContractError("QUALIFICATION_ARTIFACT", "Candidate bytes differ from reviewed inventory")
        rows.append(actual)
    return sorted(rows, key=lambda row: row["path"])


def execute_qualification(capture, output, gate_id, root, verifier, *, verifier_id,
                          verifier_source_sha256, environment):
    """Rehash before/after a reviewed verifier; store only hashes, never logs.

    verifier returns observations, not a pass flag: a nonempty list of command
    receipts with exit_code and stdout/stderr SHA256. The reviewed verifier owns
    expected nonzero statuses, protocol assertions and independent double build.
    It raises on any failure. Caller must separately allowlist this record hash.
    This is a local code trust boundary, not a sandbox for untrusted callables.
    """
    release_hash = authenticated_record_hash(capture)
    validate_sanitized_string(gate_id)
    validate_sanitized_string(verifier_id)
    validate_sha256(verifier_source_sha256)
    closed(environment, {"purpose", "os", "architecture", "python", "node", "platform",
                        "container_image_sha256", "nixpkgs_revision", "builder_source_sha256"}, required=[])
    if not environment:
        raise ContractError("QUALIFICATION_ENVIRONMENT", "Explicit bounded execution environment required")
    for key, value in environment.items():
        validate_sanitized_string(value)
        if key.endswith("_sha256"):
            validate_sha256(value)
    source_path = inspect.getsourcefile(verifier)
    if source_path is None or hashlib.sha256(Path(source_path).read_bytes()).hexdigest() != verifier_source_sha256:
        raise ContractError("QUALIFICATION_VERIFIER", "Executed verifier source differs from reviewed source hash")
    inventory = artifact_inventory(root, output["artifacts"])
    commands = verifier(Path(root))
    if not isinstance(commands, list) or not commands:
        raise ContractError("QUALIFICATION_EXECUTION", "Independent execution evidence required")
    for command in commands:
        if set(command) != {"id", "exit_code", "stdout_sha256", "stderr_sha256"}:
            raise ContractError("QUALIFICATION_EXECUTION", "Bounded command receipt required")
        validate_sanitized_string(command["id"])
        validate_bounded_int(command["exit_code"], min_val=-128, max_val=255)
        validate_sha256(command["stdout_sha256"])
        validate_sha256(command["stderr_sha256"])
    if artifact_inventory(root, output["artifacts"]) != inventory:
        raise ContractError("QUALIFICATION_ARTIFACT", "Verifier modified candidate bytes")
    record = {"schema": "rs9.qualification-record.v1alpha1", "gate": gate_id,
              "trust_root": "attended-local-rerun", "release_record_sha256": release_hash,
              "adapter": output["destination"]["adapter"],
              "content_identity_sha256": output["content_identity_sha256"],
              "source_manifest_sha256": output["source_manifest_sha256"],
              "artifacts": inventory, "verifier": {"id": verifier_id,
              "source_sha256": verifier_source_sha256}, "environment": environment,
              "host": {"os": platform.system(), "architecture": platform.machine()},
              "commands": commands}
    proof = Qualification(record, _proof=_PROOF)
    capture.__dict__.setdefault("_qualification_records", []).append(proof)
    return snapshot(record)


def bound_qualifications(capture, output, gate_id):
    release_hash = authenticated_record_hash(capture)
    rows = []
    for proof in capture.__dict__.get("_qualification_records", []):
        if not isinstance(proof, Qualification) or proof._proof is not _PROOF:
            continue
        record = proof.record
        if record_sha256(record) != proof._hash:
            raise ContractError("QUALIFICATION_CHANGED", "Execution evidence changed after verification")
        bindings = {"release_record_sha256": release_hash, "gate": gate_id,
                    "adapter": output["destination"]["adapter"],
                    "content_identity_sha256": output["content_identity_sha256"],
                    "source_manifest_sha256": output["source_manifest_sha256"],
                    "artifacts": sorted(output["artifacts"], key=lambda r: r["path"])}
        if all(record.get(key) == value for key, value in bindings.items()):
            rows.append(proof._hash)
    return rows
