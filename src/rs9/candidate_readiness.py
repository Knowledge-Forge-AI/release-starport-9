"""Closed source-adoption scope; this contract cannot authorize publication."""
import hashlib
import json
from pathlib import Path
import re

from rs9.errors import ContractError
from rs9.security import scan_for_credentials

SCHEMA = "rs9.live1-candidate-readiness.v1alpha1"
LINUX_A = {("nix", "x86_64-linux"), ("nix", "aarch64-linux")}
KEYS = {"schema", "source_adoption_scope", "known_unqualified_lanes",
        "full_live1_qualification", "published_linux_nix_ready",
        "production_enabled", "publication_authority"}


def readiness_record():
    return {"schema": SCHEMA, "source_adoption_scope": "partial-diagnostic",
            "known_unqualified_lanes": [
                {"lane": lane, "system": system, "track": "A",
                 "reason": "linux-nix-userns-runtime-unresolved"}
                for lane, system in sorted(LINUX_A)],
            "full_live1_qualification": False, "published_linux_nix_ready": False,
            "production_enabled": False, "publication_authority": False}


def validate_readiness(manifest, contract=None, *, require_ready=True):
    block = manifest.get("readiness")
    valid = (isinstance(block, dict) and set(block) == KEYS
             and block == readiness_record()
             and all(block[k] is False for k in ("full_live1_qualification", "published_linux_nix_ready",
                                                "production_enabled", "publication_authority"))
             and manifest.get("adoption_scope") == "partial-diagnostic"
             and type(manifest.get("candidate_adoption_ready")) is bool
             and manifest.get("production_enabled") is False
             and manifest.get("publication_authority") is False)
    if require_ready:
        valid = valid and manifest.get("candidate_adoption_ready") is True
    if contract is not None:
        required = {(r["lane"], r["system"]) for r in contract["lanes"] if r.get("module")}
        valid = valid and LINUX_A <= required
    if not valid:
        raise ContractError("ADOPTION_NOT_READY", "Explicit partial diagnostic source contract required")
    return block


def _attestation_bytes(path, digest, repository):
    path = Path(path)
    if (not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest)
            or any(p.is_symlink() for p in (path, *path.parents))
            or not path.is_file() or path.stat().st_size > 16384
            or path.resolve().is_relative_to(Path(repository).resolve())):
        raise ContractError("ADOPTION_REVIEW", "Bounded external manager attestation required")
    raw = path.read_bytes()
    if len(raw) > 16384 or hashlib.sha256(raw).hexdigest() != digest:
        raise ContractError("ADOPTION_REVIEW", "Manager attestation differs from supplied digest")
    scan_for_credentials(raw.decode("utf-8"))
    return raw


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ContractError("ADOPTION_REVIEW", "Duplicate manager attestation field")
        result[key] = value
    return result


def validate_adoption_authority(manifest, repository, binding, *, contract=None,
                                manager_attestation=None, manager_attestation_sha256=None):
    """Attended manager acceptance binds unchanged source; it is not source readiness.

    The supplied digest is an attended input, not an independent signature or
    proof of reviewer identity. This module never issues an attestation.
    """
    if (manager_attestation is None) != (manager_attestation_sha256 is None):
        raise ContractError("ADOPTION_REVIEW", "Attestation path and digest must be supplied together")
    validate_readiness(manifest, contract, require_ready=manager_attestation is None)
    if manager_attestation is None:
        return None
    raw = _attestation_bytes(manager_attestation, manager_attestation_sha256, repository)
    doc = json.loads(raw, object_pairs_hook=_unique_object)
    expected = {"schema": "rs9.manager-source-adoption-attestation.v1alpha1",
                "decision": "accept", "source_adoption_scope": "partial-diagnostic",
                **binding, "full_live1_qualification": False,
                "production_enabled": False, "publication_authority": False}
    if (not isinstance(doc, dict) or doc != expected or set(doc) != set(expected)
            or any(doc[k] is not False for k in ("full_live1_qualification",
                                                "production_enabled", "publication_authority"))):
        raise ContractError("ADOPTION_REVIEW", "Manager acceptance must bind exact diagnostic source")
    return doc
