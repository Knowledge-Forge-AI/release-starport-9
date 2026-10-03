"""Strict fields and single-read TOML snapshots."""
import hashlib
from pathlib import Path
import tomllib
from rs9.constants import CANONICAL_CONCRETE_PLATFORMS
from rs9.errors import ContractError
from rs9.security import scan_for_credentials, scan_keys_for_credentials


def typed(value, expected, context):
    if type(value) is not expected:
        raise ContractError("INVALID_TYPE", f"Invalid type for {context}")
    return value


def table(value, allowed, context, *, required=()):
    typed(value, dict, context)
    if set(value) - set(allowed):
        raise ContractError("UNKNOWN_KEY", f"Unknown key in {context}")
    if set(required) - set(value):
        raise ContractError("MISSING_REQUIRED_KEY", f"Required key is missing in {context}")
    return value


def choice(value, allowed, context):
    typed(value, str, context)
    if value not in allowed:
        raise ContractError("INVALID_CONFIG", f"Invalid choice for {context}")
    return value


def strings(value, context):
    typed(value, list, context)
    if not value:
        raise ContractError("INVALID_CONFIG", f"Empty list for {context}")
    for item in value:
        typed(item, str, context)
    if len(set(value)) != len(value):
        raise ContractError("DUPLICATE_IDENTIFIER", f"Duplicate entry in {context}")
    return value


def platforms(value, allow_any=True):
    values = strings(value, "platforms")
    if values == ["any"] and allow_any:
        return values
    if not set(values) <= CANONICAL_CONCRETE_PLATFORMS:
        raise ContractError("INVALID_PLATFORM", "Unknown or mixed platform vocabulary")
    return values


def schema(doc, expected):
    if doc.get("schema") != expected:
        raise ContractError("SCHEMA_MISMATCH", "Unsupported configuration schema")


def unique_rows(rows, key):
    identifiers = [row[key] for row in rows]
    if len(set(identifiers)) != len(identifiers):
        raise ContractError("DUPLICATE_IDENTIFIER", "Duplicate entity identifier")


def read_toml(path):
    path = Path(path)
    if path.is_symlink():
        raise ContractError("SYMLINK_REJECTED", "Configuration cannot be a symlink")
    if not path.exists():
        raise ContractError("MISSING_REQUIRED_FILE", "Required configuration file is missing")
    if not path.is_file():
        raise ContractError("INVALID_FILE", "Configuration must be a regular file")
    try:
        raw = path.read_bytes()
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        raise ContractError("INVALID_ENCODING", "Configuration must be UTF-8") from None
    except OSError:
        raise ContractError("INPUT_UNREADABLE", "Configuration cannot be read") from None
    scan_for_credentials(text)
    try:
        doc = tomllib.loads(text)
    except tomllib.TOMLDecodeError:
        raise ContractError("INVALID_TOML", "Invalid TOML configuration") from None
    scan_keys_for_credentials(doc)
    return doc, hashlib.sha256(raw).hexdigest()
