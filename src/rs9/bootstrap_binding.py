"""Custody-checked immutable bindings for the anchored bootstrap seam.

The accepted provision journal deliberately stores hashes rather than the
timestamped inner plan and configuration.  This module closes that crash
window without changing that journal: it stores one normalized, immutable
copy of the accepted inner records before a remote-apply journal or writer is
opened.

This is an internal source boundary.  It intentionally does not know the
shape of an ``instance_github`` plan or an engine configuration; the caller
owns those validators.  It only enforces the persistence, canonicalization,
and custody rules that make the caller's validated records recoverable.
"""

from __future__ import annotations

import copy
import hashlib
import os
import re
import stat
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import Any

from rs9 import instance as _instance
from rs9.errors import ContractError
from rs9.security import scan_for_credentials


SCHEMA = "rs9.instance-github-anchored-bootstrap-binding.v1alpha1"
BINDING_DIRECTORY = ".rs9-instance/anchored-bootstrap"
BINDING_SUFFIX = ".binding.json"
MAX_BINDING_BYTES = 512 * 1024
_OPERATION = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,62}[a-z0-9])?\Z")
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")


def _fail(code: str, message: str) -> None:
    raise ContractError(code, message)


def _operation_id(value: Any) -> str:
    if not isinstance(value, str) or _OPERATION.fullmatch(value) is None:
        _fail("BOOTSTRAP_BINDING", "Binding operation identity is invalid")
    try:
        if len(value.encode("utf-8")) > 64:
            _fail("BOOTSTRAP_BINDING", "Binding operation identity is too long")
    except UnicodeError:
        _fail("BOOTSTRAP_BINDING", "Binding operation identity is invalid")
    scan_for_credentials(value)
    return value


def _sha(value: Any, context: str) -> str:
    if not isinstance(value, str) or _SHA256.fullmatch(value) is None:
        _fail("BOOTSTRAP_BINDING", f"Binding {context} digest is invalid")
    scan_for_credentials(value)
    return value


def _record(value: Any, context: str) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        _fail("BOOTSTRAP_BINDING", f"Binding {context} is not a record")
    try:
        normalized = _instance.snapshot(dict(value))
        raw = _instance.canonical(normalized, validate=True)
    except ContractError:
        raise
    except (TypeError, ValueError, UnicodeError, RecursionError):
        _fail("BOOTSTRAP_BINDING", f"Binding {context} is not canonical")
    if len(raw) > MAX_BINDING_BYTES:
        _fail("BOOTSTRAP_LIMIT", "Binding record exceeds the bounded size")
    return normalized


def record_sha256(value: Mapping[str, Any]) -> str:
    """Return the accepted record digest used by ``remote_journal``."""

    return _instance.record_sha256(value)


def binding_path(publisher_root: str | os.PathLike[str], operation_id: str) -> Path:
    """Return the deterministic binding path without creating anything."""

    operation_id = _operation_id(operation_id)
    root = _instance._validate_root(publisher_root)
    return root / BINDING_DIRECTORY / f"{operation_id}{BINDING_SUFFIX}"


def _check_directory(info: os.stat_result, *, exact: bool) -> None:
    mode = stat.S_IMODE(info.st_mode)
    if (not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid()
            or (mode != 0o700 if exact else bool(mode & 0o022))):
        _fail("BOOTSTRAP_BINDING_CUSTODY", "Binding directory custody is unsafe")


def _open_binding_directory(root: Path, *, create: bool) -> tuple[int, int]:
    """Open root, ``.rs9-instance``, and anchored-bootstrap without symlinks."""

    flags = os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_NOFOLLOW", 0)
    try:
        root_fd = os.open(root, flags)
    except OSError:
        _fail("BOOTSTRAP_BINDING_CUSTODY", "Publisher root cannot be opened safely")
    current = root_fd
    try:
        root_info = os.fstat(root_fd)
        if not stat.S_ISDIR(root_info.st_mode) or root_info.st_uid != os.getuid():
            _fail("BOOTSTRAP_BINDING_CUSTODY", "Publisher root custody is unsafe")
        for index, component in enumerate((".rs9-instance", "anchored-bootstrap")):
            if create:
                try:
                    os.mkdir(component, 0o700, dir_fd=current)
                    os.fsync(current)
                except FileExistsError:
                    pass
                except OSError:
                    _fail("BOOTSTRAP_BINDING_CUSTODY", "Binding directory cannot be created safely")
            try:
                child = os.open(component, flags, dir_fd=current)
            except FileNotFoundError:
                _fail("BOOTSTRAP_BINDING_MISSING", "Binding directory is absent")
            except OSError:
                _fail("BOOTSTRAP_BINDING_CUSTODY", "Binding directory cannot be opened safely")
            info = os.fstat(child)
            _check_directory(info, exact=index == 1)
            if current != root_fd:
                os.close(current)
            current = child
        return root_fd, current
    except BaseException:
        if current != root_fd:
            try:
                os.close(current)
            except OSError:
                pass
        try:
            os.close(root_fd)
        except OSError:
            pass
        raise


def _safe_read(parent_fd: int, name: str) -> bytes:
    try:
        preliminary = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    except FileNotFoundError:
        _fail("BOOTSTRAP_BINDING_MISSING", "Binding record is absent")
    except OSError:
        _fail("BOOTSTRAP_BINDING_CUSTODY", "Binding record cannot be inspected")
    if (not stat.S_ISREG(preliminary.st_mode) or preliminary.st_nlink != 1
            or preliminary.st_uid != os.getuid() or stat.S_IMODE(preliminary.st_mode) != 0o600
            or preliminary.st_size > MAX_BINDING_BYTES):
        _fail("BOOTSTRAP_BINDING_CUSTODY", "Binding record custody is unsafe")
    fd = None
    try:
        fd = os.open(name, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0), dir_fd=parent_fd)
        info = os.fstat(fd)
        if (info.st_dev != preliminary.st_dev or info.st_ino != preliminary.st_ino
                or info.st_uid != os.getuid() or info.st_nlink != 1
                or stat.S_IMODE(info.st_mode) != 0o600 or info.st_size > MAX_BINDING_BYTES):
            _fail("BOOTSTRAP_BINDING_CUSTODY", "Binding record changed during read")
        chunks: list[bytes] = []
        total = 0
        while total <= MAX_BINDING_BYTES:
            chunk = os.read(fd, min(64 * 1024, MAX_BINDING_BYTES + 1 - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
        if total > MAX_BINDING_BYTES:
            _fail("BOOTSTRAP_LIMIT", "Binding record exceeds the bounded size")
        return b"".join(chunks)
    except ContractError:
        raise
    except OSError:
        _fail("BOOTSTRAP_BINDING_CUSTODY", "Binding record cannot be read safely")
    finally:
        if fd is not None:
            os.close(fd)


def _strict_json(raw: bytes) -> dict[str, Any]:
    import json

    if not isinstance(raw, bytes) or len(raw) > MAX_BINDING_BYTES:
        _fail("BOOTSTRAP_LIMIT", "Binding record exceeds the bounded size")

    def pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in items:
            if key in result:
                _fail("BOOTSTRAP_BINDING", "Binding record contains duplicate keys")
            result[key] = value
        return result

    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=pairs, parse_constant=lambda _v: _fail("BOOTSTRAP_BINDING", "Binding record contains a non-finite value"))
    except ContractError:
        raise
    except (UnicodeError, ValueError, TypeError, RecursionError):
        _fail("BOOTSTRAP_BINDING", "Binding record is not valid JSON")
    if not isinstance(value, dict):
        _fail("BOOTSTRAP_BINDING", "Binding record is not an object")
    return value


def validate_binding(value: Mapping[str, Any]) -> dict[str, Any]:
    """Validate only the generic immutable binding envelope."""

    allowed = {
        "schema", "operation_id", "provision_operation_id", "plan", "config",
        "plan_sha256", "config_sha256",
    }
    if not isinstance(value, Mapping) or set(value) != allowed:
        _fail("BOOTSTRAP_BINDING", "Binding envelope is not closed")
    if value["schema"] != SCHEMA:
        _fail("BOOTSTRAP_BINDING", "Binding schema is unsupported")
    operation_id = _operation_id(value["operation_id"])
    provision_operation_id = _operation_id(value["provision_operation_id"])
    plan = _record(value["plan"], "plan")
    config = _record(value["config"], "config")
    plan_sha256 = _sha(value["plan_sha256"], "plan")
    config_sha256 = _sha(value["config_sha256"], "config")
    if record_sha256(plan) != plan_sha256 or record_sha256(config) != config_sha256:
        _fail("BOOTSTRAP_BINDING_DRIFT", "Binding record digest does not match its accepted records")
    normalized = {
        "schema": SCHEMA,
        "operation_id": operation_id,
        "provision_operation_id": provision_operation_id,
        "plan": plan,
        "config": config,
        "plan_sha256": plan_sha256,
        "config_sha256": config_sha256,
    }
    try:
        canonical = _instance.canonical(normalized, validate=True)
    except ContractError:
        raise
    if len(canonical) > MAX_BINDING_BYTES:
        _fail("BOOTSTRAP_LIMIT", "Binding record exceeds the bounded size")
    return normalized


def _encoded(value: Mapping[str, Any]) -> bytes:
    # The binding is deliberately the project's human-readable canonical
    # record format, while the remote journal remains the owner of its own
    # compact wire format.
    normalized = validate_binding(value)
    return _instance.canonical(normalized, validate=True)


def _write_new(parent_fd: int, name: str, data: bytes) -> None:
    """Install one complete file with an atomic hard-link no-clobber step."""

    temporary = f".{name}.tmp"
    fd = None
    created = False
    linked = False
    try:
        fd = os.open(
            temporary,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
            0o600,
            dir_fd=parent_fd,
        )
        created = True
        view = memoryview(data)
        while view:
            count = os.write(fd, view)
            if count <= 0:
                _fail("BOOTSTRAP_BINDING_IO", "Binding record write made no progress")
            view = view[count:]
        os.fsync(fd)
        os.fchmod(fd, 0o600)
        info = os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                or info.st_nlink != 1 or stat.S_IMODE(info.st_mode) != 0o600):
            _fail("BOOTSTRAP_BINDING_CUSTODY", "Temporary binding custody is unsafe")
    except FileExistsError:
        _fail("BOOTSTRAP_BINDING_TEMP", "Binding temporary residue requires operator recovery")
    except ContractError:
        raise
    except OSError:
        _fail("BOOTSTRAP_BINDING_IO", "Binding record cannot be written safely")
    finally:
        if fd is not None:
            os.close(fd)
    try:
        os.link(temporary, name, src_dir_fd=parent_fd, dst_dir_fd=parent_fd, follow_symlinks=False)
        linked = True
        os.unlink(temporary, dir_fd=parent_fd)
        os.fsync(parent_fd)
    except FileExistsError:
        _fail("BOOTSTRAP_BINDING_EXISTS", "Binding operation is already persisted")
    except OSError:
        _fail("BOOTSTRAP_BINDING_IO", "Binding record cannot be installed safely")
    finally:
        if created and not linked:
            try:
                current = os.stat(temporary, dir_fd=parent_fd, follow_symlinks=False)
                if (stat.S_ISREG(current.st_mode) and current.st_nlink == 1
                        and current.st_uid == os.getuid()):
                    os.unlink(temporary, dir_fd=parent_fd)
            except OSError:
                pass


def write_binding(publisher_root: str | os.PathLike[str], value: Mapping[str, Any]) -> dict[str, Any]:
    """Persist ``value`` once, returning the canonical accepted record.

    Repeating the exact record is idempotent.  A different record for the
    same operation is a drift and is never overwritten.
    """

    normalized = validate_binding(value)
    raw = _encoded(normalized)
    root = _instance._validate_root(publisher_root)
    root_fd = parent_fd = None
    name = f"{normalized['operation_id']}{BINDING_SUFFIX}"
    try:
        root_fd, parent_fd = _open_binding_directory(root, create=True)
        try:
            existing = _safe_read(parent_fd, name)
        except ContractError as error:
            if getattr(error, "code", None) != "BOOTSTRAP_BINDING_MISSING":
                raise
            _write_new(parent_fd, name, raw)
            return copy.deepcopy(normalized)
        if existing != raw:
            _fail("BOOTSTRAP_BINDING_DRIFT", "Persisted binding differs from the accepted records")
        return copy.deepcopy(normalized)
    finally:
        if parent_fd is not None:
            os.close(parent_fd)
        if root_fd is not None and root_fd != parent_fd:
            os.close(root_fd)


def load_binding(publisher_root: str | os.PathLike[str], operation_id: str) -> dict[str, Any]:
    """Read one custody-checked canonical binding without mutation."""

    root = _instance._validate_root(publisher_root)
    operation_id = _operation_id(operation_id)
    name = f"{operation_id}{BINDING_SUFFIX}"
    root_fd = parent_fd = None
    try:
        root_fd, parent_fd = _open_binding_directory(root, create=False)
        raw = _safe_read(parent_fd, name)
    finally:
        if parent_fd is not None:
            os.close(parent_fd)
        if root_fd is not None and root_fd != parent_fd:
            os.close(root_fd)
    value = _strict_json(raw)
    normalized = validate_binding(value)
    if raw != _encoded(normalized):
        _fail("BOOTSTRAP_BINDING", "Binding record is not canonical")
    return normalized


__all__ = [
    "BINDING_DIRECTORY",
    "BINDING_SUFFIX",
    "MAX_BINDING_BYTES",
    "SCHEMA",
    "binding_path",
    "load_binding",
    "record_sha256",
    "validate_binding",
    "write_binding",
]
