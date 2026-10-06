"""Descriptor-relative, exclusive writes into a caller-owned empty directory."""
import json
import math
import os
from pathlib import Path
import re

from rs9.errors import ContractError
from rs9.security import validate_safe_relative_posix_path


def validate_safe_json(value, *, lane=None, product=None, field=None, path="root", max_depth=32, max_nodes=100000):
    """Reject non-JSON values with bounded logical identity, never arbitrary values."""
    import hashlib
    from rs9.security import scan_for_credentials
    count, active = 0, set()

    def component(key):
        if isinstance(key, str) and re.fullmatch(r"[A-Za-z_][A-Za-z0-9_-]{0,63}", key):
            try:
                scan_for_credentials(key)
                return key
            except ContractError:
                pass
        # Hash only strings; do not invoke arbitrary user methods for other keys.
        return "key-sha256-" + hashlib.sha256(key.encode()).hexdigest()[:16] if isinstance(key, str) else "non-string-key"

    def fail(val, location, reason):
        name = type(val).__name__
        safe_type = name if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,63}", name) else "unknown_type"
        details = {"origin": location, "exception_type": safe_type, "reason": reason}
        if product:
            details["product"] = product
        if lane:
            details["substage"] = lane
        raise ContractError("INVALID_JSON", f"Non-JSON value of type {safe_type} at {location}", details=details)

    def walk(val, location, depth):
        nonlocal count
        count += 1
        if len(location) > 240:
            location = "logical-path-sha256-" + hashlib.sha256(location.encode()).hexdigest()
        if count > max_nodes:
            fail(val, location, "max-nodes-exceeded")
        if depth > min(max_depth, 64):
            fail(val, location, "max-depth-exceeded")
        if type(val) in (str, bool, int) or val is None:
            return
        if type(val) is float:
            if not math.isfinite(val):
                fail(val, location, "non-finite-float")
            return
        if type(val) not in (dict, list):
            fail(val, location, "non-json-value")
        if id(val) in active:
            fail(val, location, "circular-reference")
        active.add(id(val))
        try:
            if type(val) is dict:
                for key, item in val.items():
                    if type(key) is not str:
                        fail(key, location, "non-string-dict-key")
                    walk(item, location + "." + component(key), depth + 1)
            else:
                for index, item in enumerate(val):
                    walk(item, location + "." + str(index), depth + 1)
        finally:
            active.remove(id(val))
    walk(value, component(field or path), 0)
    return value


def canonical(value, *, validate=False, lane=None, product=None):
    if validate:
        validate_safe_json(value, lane=lane, product=product)
    return (json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False) + "\n").encode("utf-8")


def physical_directory(root):
    path = Path(root).absolute()
    if any(parent.is_symlink() for parent in (path, *path.parents)):
        raise ContractError("SYMLINK_REJECTED", "Directory ancestry contains a symlink")
    if not path.is_dir():
        raise ContractError("INVALID_DIRECTORY", "An existing physical directory is required")
    return path


class ConfinedWriter:
    """Never overwrite existing output or follow a directory/link component."""

    def __init__(self, root):
        path = physical_directory(root)
        self.fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        if os.listdir(self.fd):
            self.close()
            raise ContractError("OUTPUT_NOT_EMPTY", "Output root must be empty")

    def close(self):
        if self.fd is not None:
            os.close(self.fd)
            self.fd = None

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()

    def write(self, relative, content):
        validate_safe_relative_posix_path(relative)
        if not isinstance(content, bytes):
            raise ContractError("INVALID_TYPE", "Output content must be bytes")
        current = os.dup(self.fd)
        try:
            parts = relative.split("/")
            for part in parts[:-1]:
                try:
                    os.mkdir(part, 0o755, dir_fd=current)
                except FileExistsError:
                    pass
                child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=current)
                os.close(current)
                current = child
            descriptor = os.open(parts[-1], os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                                 0o644, dir_fd=current)
            with os.fdopen(descriptor, "wb") as output:
                output.write(content)
        except OSError:
            raise ContractError("OUTPUT_CONFINEMENT", "Confined output write failed") from None
        finally:
            os.close(current)
