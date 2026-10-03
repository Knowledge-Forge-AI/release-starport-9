"""Deterministic, sanitized record primitives. Hashes bind bytes, not authority."""
import copy
from datetime import datetime
import re
from urllib.parse import urlsplit

from rs9.errors import ContractError
from rs9.release_core import digest
from rs9.scratch import canonical
from rs9.security import scan_for_credentials, validate_safe_relative_posix_path


class Record(dict):
    @property
    def sha256(self):
        return record_sha256(self)

    def to_dict(self):
        return copy.deepcopy(dict(self))

    def __getattr__(self, name):
        try:
            return self[name]
        except KeyError:
            raise AttributeError(name) from None


def record_sha256(record):
    return digest(canonical(record))


def validate_sha256(value, name="hash"):
    if not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{64}", value):
        raise ContractError("INVALID_HASH", "A lowercase SHA-256 identity is required")
    return value


def validate_sanitized_string(value, name="string", max_length=1024, allow_newlines=False):
    if not isinstance(value, str) or not 0 < len(value) <= max_length:
        raise ContractError("INVALID_STRING", "A bounded nonempty string is required")
    if any(ord(c) < 32 or ord(c) == 127 for c in value):
        raise ContractError("INVALID_CONTENT", "Control characters are forbidden in records")
    if re.search(r"/(?:" + "Users" + r"|home|root|private|tmp)/|~[/\\]|[A-Za-z]:\\", value):
        raise ContractError("PRIVATE_PATH", "Private filesystem paths are forbidden in records")
    scan_for_credentials(value)
    for match in re.findall(r"[A-Za-z][A-Za-z0-9+.-]*://[^\s]+", value):
        url = urlsplit(match)
        if url.username or url.password or url.query or url.fragment:
            raise ContractError("UNSAFE_URL", "Record URLs cannot contain credentials, query or fragment")
    return value


def validate_rfc3339_utc(value, name="timestamp"):
    if not isinstance(value, str) or not re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?Z", value):
        raise ContractError("INVALID_TIMESTAMP", "Explicit RFC3339 UTC timestamp required")
    try:
        datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        raise ContractError("INVALID_TIMESTAMP", "Timestamp has an invalid calendar date") from None
    return value


def parse_rfc3339_utc(value, name="timestamp"):
    return datetime.fromisoformat(validate_rfc3339_utc(value).replace("Z", "+00:00"))


def validate_bounded_int(value, name="integer", min_val=0, max_val=2147483647):
    if type(value) is not int or not min_val <= value <= max_val:
        raise ContractError("INVALID_INTEGER", "A bounded integer is required")
    return value


def closed(value, fields, required=None):
    if not isinstance(value, dict) or set(value) - set(fields) or set(fields if required is None else required) - set(value):
        raise ContractError("RECORD_SCHEMA", "Record does not satisfy its closed field contract")
    return value


def sanitized(value, depth=0):
    if depth > 12:
        raise ContractError("RECORD_LIMIT", "Record nesting bound exceeded")
    if isinstance(value, str):
        validate_sanitized_string(value)
    elif isinstance(value, dict):
        if len(value) > 256:
            raise ContractError("RECORD_LIMIT", "Record field bound exceeded")
        for key, item in value.items():
            validate_sanitized_string(key)
            sanitized(item, depth + 1)
    elif isinstance(value, list):
        if len(value) > 20000:
            raise ContractError("RECORD_LIMIT", "Record list bound exceeded")
        for item in value:
            sanitized(item, depth + 1)
    elif value is not None and type(value) not in (int, bool):
        raise ContractError("RECORD_TYPE", "Only deterministic JSON primitives are supported")
    if depth == 0 and len(canonical(value)) > 512 * 1024:
        raise ContractError("RECORD_LIMIT", "Durable record exceeds byte bound")
    return value


def snapshot(value):
    sanitized(value)
    return copy.deepcopy(value)


def hash_map(value):
    if not isinstance(value, dict) or not value or len(value) > 20000:
        raise ContractError("INVALID_HASHES", "Nonempty bounded hash mapping required")
    for key, sha in value.items():
        validate_safe_relative_posix_path(key)
        validate_sha256(sha)
    return dict(sorted(value.items()))


def build_semantic_content_identity(project_id, version, target_id, adapter, artifact_payload_hashes, configuration_identity):
    # Configuration is explicitly a mapping of semantic input hashes. No recipe
    # rewriting or filename/field heuristics hide a packaging revision.
    for value in (project_id, version, target_id, adapter):
        validate_sanitized_string(value)
    result = {"schema": "rs9.semantic-content-identity.v1alpha1", "project_id": project_id,
              "version": version, "target_id": target_id, "adapter": adapter,
              "artifact_payload_hashes": hash_map(artifact_payload_hashes),
              "configuration_identity": hash_map(configuration_identity)}
    return Record(snapshot(result))


def semantic_identity_sha256(identity):
    closed(identity, {"schema", "project_id", "version", "target_id", "adapter", "artifact_payload_hashes", "configuration_identity"})
    if identity["schema"] != "rs9.semantic-content-identity.v1alpha1":
        raise ContractError("RECORD_SCHEMA", "Unknown semantic identity contract")
    rebuilt = build_semantic_content_identity(identity["project_id"], identity["version"], identity["target_id"], identity["adapter"], identity["artifact_payload_hashes"], identity["configuration_identity"])
    return record_sha256(rebuilt)
