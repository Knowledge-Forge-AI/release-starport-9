"""Local hash-only journal for a future RS9 remote apply boundary.

This module owns no GitHub transport, subprocess, CLI, retry, or replay path.
It records the bounded identity of one create-only operation and makes the
write-ahead boundary explicit before each blob, tree, commit, and ref call.
The journal is local control state, never a managed remote file.
"""

from __future__ import annotations

import copy
import hashlib
import json
import os
import re
import stat
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from rs9 import instance as _instance
from rs9.errors import ContractError
from rs9.security import (
    scan_for_credentials,
    validate_repository,
    validate_safe_relative_posix_path,
)


SCHEMA = "rs9.instance-github-apply.v1alpha1"
SCHEMA_REMOTE_JOURNAL = SCHEMA
SCHEMA_RESUME = "rs9.instance-github-apply-resume.v1alpha1"
SCHEMA_INVENTORY = "rs9.instance-github-journal-inventory.v1alpha1"
JOURNAL_DIRECTORY = ".rs9-instance/remote-apply"
MAX_JOURNAL_BYTES = 256 * 1024
MAX_BLOB_EFFECTS = 64
MAX_EFFECTS = MAX_BLOB_EFFECTS + 3
MAX_PATH_BYTES = 512
MAX_OPERATION_ID_BYTES = 64
MAX_REPOSITORY_BYTES = 255
MAX_BRANCH_BYTES = 256

_OPERATION_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,62}[a-z0-9])?$")
_BRANCH_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/-]{0,127}$")
_SHA1_RE = re.compile(r"^[0-9a-f]{40}$")
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_STEPS = ("blob", "tree", "commit", "ref")
_STATUSES = ("submitting", "completed", "uncertain", "failed")
_PHASES = (
    "prepared",
    "blob-submitting",
    "blob-created",
    "tree-submitting",
    "tree-created",
    "commit-submitting",
    "commit-created",
    "ref-submitting",
    "readback-pending",
    "completed",
    "failed",
    "uncertain",
)
_REASONS = frozenset({
    "operator-hold",
    "transport-timeout",
    "transport-lost",
    "malformed-response",
    "stale-parent",
    "protected-branch",
    "readback-failed",
    "permission-denied",
    "journal-stale",
    "unsafe-journal",
    "invalid-response",
})
_EFFECT_KEYS = {"step", "status", "path", "sha1", "reason"}
_RECORD_KEYS = {
    "schema",
    "operation_id",
    "repository",
    "branch",
    "plan_sha256",
    "config_sha256",
    "expected_parent",
    "expected_tree",
    "target_tree",
    "target_commit",
    "phase",
    "reason",
    "effects",
}


def _error(code: str) -> None:
    raise ContractError(code, "Remote apply journal contract rejected")


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _validate_hash(value: Any, pattern: re.Pattern[str], code: str = "JOURNAL_SCHEMA") -> str:
    if not isinstance(value, str) or pattern.fullmatch(value) is None:
        _error(code)
    scan_for_credentials(value)
    return value


def _validate_operation_id(value: Any) -> str:
    if not isinstance(value, str) or _OPERATION_RE.fullmatch(value) is None:
        _error("JOURNAL_OPERATION")
    try:
        encoded_length = len(value.encode("utf-8"))
    except UnicodeError:
        _error("JOURNAL_OPERATION")
    if encoded_length > MAX_OPERATION_ID_BYTES:
        _error("JOURNAL_OPERATION")
    scan_for_credentials(value)
    return value


def _validate_branch(value: Any) -> str:
    if (not isinstance(value, str) or _BRANCH_RE.fullmatch(value) is None
            or ".." in value or value.endswith(("/", "."))):
        _error("JOURNAL_IDENTITY")
    try:
        encoded_length = len(value.encode("utf-8"))
    except UnicodeError:
        _error("JOURNAL_IDENTITY")
    if encoded_length > MAX_BRANCH_BYTES:
        _error("JOURNAL_IDENTITY")
    scan_for_credentials(value)
    return value


def _validate_path(value: Any) -> str:
    try:
        validate_safe_relative_posix_path(value, "journal effect path")
    except ContractError:
        raise
    try:
        encoded_length = len(value.encode("utf-8"))
    except UnicodeError:
        _error("JOURNAL_PATH")
    if encoded_length > MAX_PATH_BYTES:
        _error("JOURNAL_LIMIT")
    reserved = tuple(component.casefold() for component in JOURNAL_DIRECTORY.split("/"))
    components = tuple(component.casefold() for component in value.split("/"))
    if components[:len(reserved)] == reserved:
        _error("JOURNAL_PATH")
    scan_for_credentials(value)
    return value


def _validate_reason(value: Any) -> str:
    if not isinstance(value, str) or value not in _REASONS:
        _error("JOURNAL_REASON")
    scan_for_credentials(value)
    return value


def _strict_json(raw: bytes) -> dict[str, Any]:
    if not isinstance(raw, bytes) or len(raw) > MAX_JOURNAL_BYTES:
        _error("JOURNAL_LIMIT")

    def pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in items:
            if key in result:
                _error("JOURNAL_SCHEMA")
            result[key] = value
        return result

    def constant(_value: str) -> None:
        _error("JOURNAL_SCHEMA")

    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=pairs, parse_constant=constant)
    except ContractError:
        raise
    except (UnicodeError, ValueError, TypeError, RecursionError):
        _error("JOURNAL_SCHEMA")
    if not isinstance(value, dict):
        _error("JOURNAL_SCHEMA")
    return value


def _effect_key(effect: Mapping[str, Any]) -> tuple[int, str]:
    return (_STEPS.index(effect["step"]), effect["path"] or "")


def _validate_effect(value: Any) -> dict[str, Any]:
    if not isinstance(value, Mapping) or set(value) != _EFFECT_KEYS:
        _error("JOURNAL_SCHEMA")
    step = value["step"]
    status = value["status"]
    if not isinstance(step, str) or step not in _STEPS or not isinstance(status, str) or status not in _STATUSES:
        _error("JOURNAL_SCHEMA")
    path = value["path"]
    if step == "blob":
        if path is None:
            _error("JOURNAL_SCHEMA")
        path = _validate_path(path)
    elif path is not None:
        _error("JOURNAL_SCHEMA")
    sha1 = value["sha1"]
    if sha1 is not None:
        sha1 = _validate_hash(sha1, _SHA1_RE)
    reason = value["reason"]
    if status in {"uncertain", "failed"}:
        reason = _validate_reason(reason)
    elif reason is not None:
        _error("JOURNAL_SCHEMA")
    if status == "completed" and sha1 is None:
        _error("JOURNAL_SCHEMA")
    return {"step": step, "status": status, "path": path, "sha1": sha1, "reason": reason}


def _phase_effects(
    phase: str,
    reason: str | None,
    target_tree: str | None,
    target_commit: str | None,
    effects: list[dict[str, Any]],
) -> None:
    """Reject hand-edited records whose state does not describe its effects."""

    by_step: dict[str, list[dict[str, Any]]] = {step: [] for step in _STEPS}
    for effect in effects:
        by_step[effect["step"]].append(effect)
    if len(by_step["blob"]) > MAX_BLOB_EFFECTS:
        _error("JOURNAL_LIMIT")
    if any(len(rows) > 1 for step, rows in by_step.items() if step != "blob"):
        _error("JOURNAL_SCHEMA")
    submitting = [row for row in effects if row["status"] == "submitting"]
    uncertain = [row for row in effects if row["status"] == "uncertain"]
    failed = [row for row in effects if row["status"] == "failed"]
    if phase == "prepared":
        if effects or target_tree is not None or target_commit is not None:
            _error("JOURNAL_SCHEMA")
        return
    if phase in {"uncertain", "failed"}:
        active = uncertain if phase == "uncertain" else failed
        if len(active) != 1 or active[0]["reason"] != reason or submitting:
            _error("JOURNAL_SCHEMA")
        active_step = active[0]["step"]
        active_status = phase
    elif phase.endswith("-submitting"):
        active_step = phase[:-len("-submitting")]
        if active_step not in _STEPS or len(submitting) != 1 or submitting[0]["step"] != active_step:
            _error("JOURNAL_SCHEMA")
        if uncertain or failed:
            _error("JOURNAL_SCHEMA")
        active_status = "submitting"
    elif phase.endswith("-created"):
        active_step = phase[:-len("-created")]
        if active_step not in _STEPS or uncertain or failed or submitting:
            _error("JOURNAL_SCHEMA")
        if active_step == "blob":
            if not by_step[active_step] or any(row["status"] != "completed" for row in by_step[active_step]):
                _error("JOURNAL_SCHEMA")
        elif len(by_step[active_step]) != 1 or by_step[active_step][0]["status"] != "completed":
            _error("JOURNAL_SCHEMA")
        active_status = "completed"
    elif phase in {"readback-pending", "completed"}:
        active_step = "ref"
        if uncertain or failed or submitting:
            _error("JOURNAL_SCHEMA")
        active_status = "completed"
    else:
        _error("JOURNAL_SCHEMA")

    rank = _STEPS.index(active_step)
    for effect in effects:
        if _STEPS.index(effect["step"]) > rank:
            _error("JOURNAL_SCHEMA")
        if effect["step"] == active_step and effect["status"] == active_status:
            continue
        if effect["status"] != "completed":
            _error("JOURNAL_SCHEMA")
    if active_step == "blob" and not by_step["blob"]:
        _error("JOURNAL_SCHEMA")
    for step in _STEPS[1:rank + 1]:
        if len(by_step[step]) != 1:
            _error("JOURNAL_SCHEMA")
        if step != active_step and by_step[step][0]["status"] != "completed":
            _error("JOURNAL_SCHEMA")

    tree = by_step["tree"][0] if by_step["tree"] else None
    commit = by_step["commit"][0] if by_step["commit"] else None
    ref = by_step["ref"][0] if by_step["ref"] else None
    if target_tree is not None:
        if tree is None or tree["status"] != "completed" or tree["sha1"] != target_tree:
            _error("JOURNAL_SCHEMA")
    elif tree is not None and tree["status"] == "completed":
        _error("JOURNAL_SCHEMA")
    if target_commit is not None:
        if commit is None or commit["status"] != "completed" or commit["sha1"] != target_commit:
            _error("JOURNAL_SCHEMA")
    elif commit is not None and commit["status"] == "completed":
        _error("JOURNAL_SCHEMA")
    if ref is not None:
        if target_commit is None or ref["sha1"] != target_commit:
            _error("JOURNAL_SCHEMA")
    if phase in {"readback-pending", "completed"}:
        if (tree is None or commit is None or ref is None
                or tree["status"] != "completed" or commit["status"] != "completed"
                or ref["status"] != "completed" or target_tree is None or target_commit is None):
            _error("JOURNAL_SCHEMA")
    if phase == "completed" and any(effect["status"] != "completed" for effect in effects):
        _error("JOURNAL_SCHEMA")


def _validate_record(value: Any) -> dict[str, Any]:
    if not isinstance(value, Mapping) or set(value) != _RECORD_KEYS:
        _error("JOURNAL_SCHEMA")
    if value["schema"] != SCHEMA:
        _error("JOURNAL_SCHEMA")
    operation_id = _validate_operation_id(value["operation_id"])
    repository = value["repository"]
    try:
        validate_repository(repository)
    except ContractError:
        raise
    if len(repository.encode("utf-8")) > MAX_REPOSITORY_BYTES:
        _error("JOURNAL_LIMIT")
    scan_for_credentials(repository)
    branch = _validate_branch(value["branch"])
    plan_sha256 = _validate_hash(value["plan_sha256"], _SHA256_RE)
    config_sha256 = _validate_hash(value["config_sha256"], _SHA256_RE)
    expected_parent = _validate_hash(value["expected_parent"], _SHA1_RE)
    expected_tree = _validate_hash(value["expected_tree"], _SHA1_RE)
    target_tree = value["target_tree"]
    if target_tree is not None:
        target_tree = _validate_hash(target_tree, _SHA1_RE)
    target_commit = value["target_commit"]
    if target_commit is not None:
        target_commit = _validate_hash(target_commit, _SHA1_RE)
    phase = value["phase"]
    if not isinstance(phase, str) or phase not in _PHASES:
        _error("JOURNAL_SCHEMA")
    reason = value["reason"]
    if reason is not None:
        reason = _validate_reason(reason)
    if phase in {"uncertain", "failed"} and reason is None:
        _error("JOURNAL_SCHEMA")
    if phase not in {"uncertain", "failed"} and reason is not None:
        _error("JOURNAL_SCHEMA")
    effects_value = value["effects"]
    if not isinstance(effects_value, list) or len(effects_value) > MAX_EFFECTS:
        _error("JOURNAL_LIMIT")
    effects = [_validate_effect(row) for row in effects_value]
    if effects != sorted(effects, key=_effect_key):
        _error("JOURNAL_SCHEMA")
    keys = [(row["step"], row["path"]) for row in effects]
    if len(keys) != len(set(keys)):
        _error("JOURNAL_SCHEMA")
    _phase_effects(phase, reason, target_tree, target_commit, effects)
    return {
        "schema": SCHEMA,
        "operation_id": operation_id,
        "repository": repository,
        "branch": branch,
        "plan_sha256": plan_sha256,
        "config_sha256": config_sha256,
        "expected_parent": expected_parent,
        "expected_tree": expected_tree,
        "target_tree": target_tree,
        "target_commit": target_commit,
        "phase": phase,
        "reason": reason,
        "effects": effects,
    }


def _encode(record: Mapping[str, Any]) -> bytes:
    value = _validate_record(record)
    try:
        raw = (json.dumps(value, ensure_ascii=True, allow_nan=False, sort_keys=True, separators=(",", ":")) + "\n").encode("ascii")
    except (TypeError, UnicodeError, ValueError):
        _error("JOURNAL_SCHEMA")
    if len(raw) > MAX_JOURNAL_BYTES:
        _error("JOURNAL_LIMIT")
    return raw


def _flags(*names: str) -> int:
    return sum(getattr(os, name, 0) for name in names)


def _check_directory(fd: int) -> None:
    try:
        info = os.fstat(fd)
    except OSError:
        _error("JOURNAL_UNSAFE")
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) & 0o022:
        _error("JOURNAL_UNSAFE")


def _open_parent(root: str | os.PathLike[str], *, create: bool) -> tuple[int, int]:
    root_path = _instance._validate_root(root)
    flags = _flags("O_RDONLY", "O_DIRECTORY", "O_NOFOLLOW", "O_NONBLOCK")
    try:
        root_fd = os.open(root_path, flags)
    except OSError:
        _error("JOURNAL_UNSAFE")
    try:
        _check_directory(root_fd)
        current = os.dup(root_fd)
        for component in (".rs9-instance", "remote-apply"):
            if create:
                try:
                    os.mkdir(component, 0o700, dir_fd=current)
                    os.fsync(current)
                except FileExistsError:
                    pass
                except OSError:
                    os.close(current)
                    _error("JOURNAL_UNSAFE")
            child = None
            advanced = False
            try:
                child = os.open(component, flags, dir_fd=current)
                _check_directory(child)
                advanced = True
            except FileNotFoundError:
                _error("JOURNAL_MISSING")
            except OSError:
                _error("JOURNAL_UNSAFE")
            finally:
                os.close(current)
                if child is not None and not advanced:
                    os.close(child)
            current = child
        return root_fd, current
    except BaseException:
        os.close(root_fd)
        raise


def _same_stat(left: os.stat_result, right: os.stat_result) -> bool:
    return (left.st_dev == right.st_dev and left.st_ino == right.st_ino
            and left.st_uid == right.st_uid and left.st_nlink == right.st_nlink
            and stat.S_IMODE(left.st_mode) == stat.S_IMODE(right.st_mode))


def _read_control(parent_fd: int, name: str) -> tuple[bytes, str]:
    try:
        preliminary = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    except FileNotFoundError:
        _error("JOURNAL_MISSING")
    except OSError:
        _error("JOURNAL_UNSAFE")
    if (not stat.S_ISREG(preliminary.st_mode) or preliminary.st_nlink != 1
            or preliminary.st_uid != os.getuid() or stat.S_IMODE(preliminary.st_mode) != 0o600
            or preliminary.st_size > MAX_JOURNAL_BYTES):
        _error("JOURNAL_UNSAFE")
    fd = None
    flags = _flags("O_RDONLY", "O_NOFOLLOW", "O_NONBLOCK")
    try:
        fd = os.open(name, flags, dir_fd=parent_fd)
        info = os.fstat(fd)
        if (not _same_stat(preliminary, info) or not stat.S_ISREG(info.st_mode)
                or info.st_size > MAX_JOURNAL_BYTES):
            _error("JOURNAL_UNSAFE")
        os.set_blocking(fd, True)
        chunks: list[bytes] = []
        total = 0
        while total <= MAX_JOURNAL_BYTES:
            chunk = os.read(fd, min(64 * 1024, MAX_JOURNAL_BYTES + 1 - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
        if total > MAX_JOURNAL_BYTES:
            _error("JOURNAL_LIMIT")
        raw = b"".join(chunks)
    except ContractError:
        raise
    except OSError:
        _error("JOURNAL_UNSAFE")
    finally:
        if fd is not None:
            os.close(fd)
    return raw, _sha256(raw)


def _write_fd(fd: int, data: bytes) -> None:
    view = memoryview(data)
    while view:
        try:
            count = os.write(fd, view)
        except OSError:
            _error("JOURNAL_IO")
        if count <= 0:
            _error("JOURNAL_IO")
        view = view[count:]
    try:
        os.fsync(fd)
        os.fchmod(fd, 0o600)
        info = os.fstat(fd)
    except OSError:
        _error("JOURNAL_IO")
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
            or info.st_nlink != 1 or stat.S_IMODE(info.st_mode) != 0o600):
        _error("JOURNAL_UNSAFE")


def _create_control(parent_fd: int, name: str, data: bytes) -> str:
    try:
        existing = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    except FileNotFoundError:
        existing = None
    except OSError:
        _error("JOURNAL_UNSAFE")
    if existing is not None:
        if (not stat.S_ISREG(existing.st_mode) or existing.st_nlink != 1
                or existing.st_uid != os.getuid() or stat.S_IMODE(existing.st_mode) != 0o600):
            _error("JOURNAL_UNSAFE")
        _error("JOURNAL_EXISTS")
    fd = None
    created = False
    success = False
    flags = _flags("O_WRONLY", "O_CREAT", "O_EXCL", "O_NOFOLLOW", "O_NONBLOCK")
    try:
        fd = os.open(name, flags, 0o600, dir_fd=parent_fd)
        created = True
        _write_fd(fd, data)
        success = True
    except FileExistsError:
        _error("JOURNAL_EXISTS")
    except ContractError:
        raise
    except OSError:
        _error("JOURNAL_UNSAFE")
    finally:
        if fd is not None:
            os.close(fd)
        if created and not success:
            try:
                current = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
                if stat.S_ISREG(current.st_mode) and current.st_nlink == 1 and current.st_uid == os.getuid():
                    os.unlink(name, dir_fd=parent_fd)
            except OSError:
                pass
    if not created:
        _error("JOURNAL_EXISTS")
    try:
        os.fsync(parent_fd)
    except OSError:
        _error("JOURNAL_IO")
    return _sha256(data)


def _replace_control(parent_fd: int, name: str, data: bytes, expected_digest: str) -> str:
    current, current_digest = _read_control(parent_fd, name)
    del current
    _validate_hash(expected_digest, _SHA256_RE, "JOURNAL_STALE")
    if current_digest != expected_digest:
        _error("JOURNAL_STALE")
    temporary = f".{name}.tmp"
    fd = None
    created = False
    success = False
    flags = _flags("O_WRONLY", "O_CREAT", "O_EXCL", "O_NOFOLLOW", "O_NONBLOCK")
    try:
        fd = os.open(temporary, flags, 0o600, dir_fd=parent_fd)
        created = True
        _write_fd(fd, data)
        success = True
    except FileExistsError:
        _error("JOURNAL_TEMP_PRESENT")
    except ContractError:
        raise
    except OSError:
        _error("JOURNAL_IO")
    finally:
        if fd is not None:
            os.close(fd)
        if created and not success:
            try:
                current = os.stat(temporary, dir_fd=parent_fd, follow_symlinks=False)
                if stat.S_ISREG(current.st_mode) and current.st_nlink == 1 and current.st_uid == os.getuid():
                    os.unlink(temporary, dir_fd=parent_fd)
            except OSError:
                pass
    try:
        os.replace(temporary, name, src_dir_fd=parent_fd, dst_dir_fd=parent_fd)
    except OSError:
        try:
            os.unlink(temporary, dir_fd=parent_fd)
        except OSError:
            pass
        _error("JOURNAL_IO")
    try:
        os.fsync(parent_fd)
    except OSError:
        _error("JOURNAL_UNCERTAIN")
    try:
        observed, observed_digest = _read_control(parent_fd, name)
        del observed
    except ContractError:
        _error("JOURNAL_UNCERTAIN")
    if observed_digest != _sha256(data):
        _error("JOURNAL_UNCERTAIN")
    return observed_digest


def _journal_name(operation_id: str) -> str:
    _validate_operation_id(operation_id)
    return operation_id + ".json"


def _inventory_bytes(entries: list[dict[str, str]]) -> bytes:
    value = {"schema": SCHEMA_INVENTORY, "entries": entries}
    try:
        return (json.dumps(value, ensure_ascii=True, allow_nan=False,
                           sort_keys=True, separators=(",", ":")) + "\n").encode("ascii")
    except (TypeError, UnicodeError, ValueError):
        _error("JOURNAL_INVENTORY")


def _inventory_result(entries: list[dict[str, str]]) -> dict[str, Any]:
    normalized = sorted(entries, key=lambda row: row["operation_id"])
    return {
        "schema": SCHEMA_INVENTORY,
        "entries": copy.deepcopy(normalized),
        "inventory_sha256": _sha256(_inventory_bytes(normalized)),
    }


def _find_effect(record: Mapping[str, Any], step: str, path: str | None) -> dict[str, Any]:
    if step not in _STEPS or (step == "blob") != (path is not None):
        _error("JOURNAL_STEP")
    for effect in record["effects"]:
        if effect["step"] == step and effect["path"] == path:
            return effect
    _error("JOURNAL_STEP")


def _effect_sort(record: dict[str, Any]) -> None:
    record["effects"] = sorted(record["effects"], key=_effect_key)


def _check_predecessor(journal: "RemoteApplyJournal", predecessor_sha256: str | None) -> None:
    if predecessor_sha256 is not None:
        _validate_hash(predecessor_sha256, _SHA256_RE, "JOURNAL_STALE")
        if predecessor_sha256 != journal.digest:
            _error("JOURNAL_STALE")


class RemoteApplyJournal:
    """One loaded local journal; methods persist one transition atomically."""

    def __init__(self, root: str | os.PathLike[str], operation_id: str, record: dict[str, Any], digest: str) -> None:
        self._root = _instance._validate_root(root)
        self._operation_id = _validate_operation_id(operation_id)
        self._record = _validate_record(record)
        if self._record["operation_id"] != self._operation_id:
            _error("JOURNAL_IDENTITY")
        self._digest = _validate_hash(digest, _SHA256_RE)
        if _sha256(_encode(self._record)) != self._digest:
            _error("JOURNAL_SCHEMA")

    @property
    def operation_id(self) -> str:
        return self._operation_id

    @property
    def digest(self) -> str:
        return self._digest

    @property
    def record(self) -> dict[str, Any]:
        return copy.deepcopy(self._record)

    @classmethod
    def prepare(
        cls,
        root: str | os.PathLike[str],
        operation_id: str,
        *,
        repository: str,
        branch: str,
        plan_sha256: str,
        config_sha256: str,
        expected_parent: str,
        expected_tree: str,
    ) -> "RemoteApplyJournal":
        operation_id = _validate_operation_id(operation_id)
        record = _validate_record({
            "schema": SCHEMA,
            "operation_id": operation_id,
            "repository": repository,
            "branch": branch,
            "plan_sha256": plan_sha256,
            "config_sha256": config_sha256,
            "expected_parent": expected_parent,
            "expected_tree": expected_tree,
            "target_tree": None,
            "target_commit": None,
            "phase": "prepared",
            "reason": None,
            "effects": [],
        })
        data = _encode(record)
        root_fd = parent_fd = None
        try:
            root_fd, parent_fd = _open_parent(root, create=True)
            digest = _create_control(parent_fd, _journal_name(operation_id), data)
        finally:
            if parent_fd is not None:
                os.close(parent_fd)
            if root_fd is not None:
                os.close(root_fd)
        return cls(root, operation_id, record, digest)

    @classmethod
    def load(cls, root: str | os.PathLike[str], operation_id: str) -> "RemoteApplyJournal":
        operation_id = _validate_operation_id(operation_id)
        root_fd = parent_fd = None
        try:
            root_fd, parent_fd = _open_parent(root, create=False)
            raw, digest = _read_control(parent_fd, _journal_name(operation_id))
        finally:
            if parent_fd is not None:
                os.close(parent_fd)
            if root_fd is not None:
                os.close(root_fd)
        value = _strict_json(raw)
        record = _validate_record(value)
        if raw != _encode(record) or record["operation_id"] != operation_id:
            _error("JOURNAL_SCHEMA")
        return cls(root, operation_id, record, digest)

    def _persist(self, record: dict[str, Any], predecessor_sha256: str | None) -> dict[str, Any]:
        _check_predecessor(self, predecessor_sha256)
        data = _encode(record)
        root_fd = parent_fd = None
        try:
            root_fd, parent_fd = _open_parent(self._root, create=False)
            digest = _replace_control(parent_fd, _journal_name(self._operation_id), data, self._digest)
        finally:
            if parent_fd is not None:
                os.close(parent_fd)
            if root_fd is not None:
                os.close(root_fd)
        self._record = _validate_record(record)
        self._digest = digest
        return self.record

    def begin_submission(
        self,
        step: str,
        *,
        path: str | None = None,
        sha1: str | None = None,
        predecessor_sha256: str | None = None,
    ) -> dict[str, Any]:
        if not isinstance(step, str):
            _error("JOURNAL_STEP")
        if self._record["phase"] in {"completed", "failed", "uncertain", "readback-pending"}:
            _error("JOURNAL_CLOSED")
        if any(effect["status"] == "submitting" for effect in self._record["effects"]):
            _error("JOURNAL_IN_FLIGHT")
        if step == "blob":
            path = _validate_path(path)
            if sha1 is None:
                _error("JOURNAL_STEP")
            sha1 = _validate_hash(sha1, _SHA1_RE)
            if any(effect["step"] == "blob" and effect["path"] == path for effect in self._record["effects"]):
                _error("JOURNAL_STEP")
            if sum(effect["step"] == "blob" for effect in self._record["effects"]) >= MAX_BLOB_EFFECTS:
                _error("JOURNAL_LIMIT")
            if any(effect["step"] in {"tree", "commit", "ref"} for effect in self._record["effects"]):
                _error("JOURNAL_ORDER")
        else:
            if path is not None:
                _error("JOURNAL_STEP")
            if step not in _STEPS:
                _error("JOURNAL_STEP")
            if any(effect["step"] == step for effect in self._record["effects"]):
                _error("JOURNAL_STEP")
            if step == "tree":
                if any(effect["step"] == "blob" and effect["status"] != "completed" for effect in self._record["effects"]):
                    _error("JOURNAL_ORDER")
            elif step == "commit":
                if not any(effect["step"] == "tree" and effect["status"] == "completed" for effect in self._record["effects"]):
                    _error("JOURNAL_ORDER")
            elif step == "ref":
                if not any(effect["step"] == "commit" and effect["status"] == "completed" for effect in self._record["effects"]):
                    _error("JOURNAL_ORDER")
                if self._record["target_commit"] is None:
                    _error("JOURNAL_ORDER")
                sha1 = self._record["target_commit"]
            if sha1 is not None:
                sha1 = _validate_hash(sha1, _SHA1_RE)
        effect = {"step": step, "status": "submitting", "path": path, "sha1": sha1, "reason": None}
        record = self.record
        record["effects"].append(effect)
        record["phase"] = f"{step}-submitting"
        record["reason"] = None
        _effect_sort(record)
        return self._persist(record, predecessor_sha256)

    def acknowledge(
        self,
        step: str,
        *,
        path: str | None = None,
        sha1: str,
        predecessor_sha256: str | None = None,
    ) -> dict[str, Any]:
        sha1 = _validate_hash(sha1, _SHA1_RE)
        effect = _find_effect(self._record, step, path)
        if effect["status"] != "submitting" or (effect["sha1"] is not None and effect["sha1"] != sha1):
            _error("JOURNAL_ACK")
        record = self.record
        current = _find_effect(record, step, path)
        current["status"] = "completed"
        current["sha1"] = sha1
        current["reason"] = None
        if step == "tree":
            record["target_tree"] = sha1
        elif step == "commit":
            record["target_commit"] = sha1
        elif step == "ref" and record["target_commit"] != sha1:
            _error("JOURNAL_ACK")
        record["phase"] = "readback-pending" if step == "ref" else f"{step}-created"
        record["reason"] = None
        _effect_sort(record)
        return self._persist(record, predecessor_sha256)

    def mark_uncertain(
        self,
        step: str,
        *,
        reason: str,
        path: str | None = None,
        predecessor_sha256: str | None = None,
    ) -> dict[str, Any]:
        reason = _validate_reason(reason)
        if self._record["phase"] == "completed":
            _error("JOURNAL_CLOSED")
        effect = _find_effect(self._record, step, path)
        if effect["status"] not in {"submitting", "completed"}:
            _error("JOURNAL_STATE")
        if effect["status"] == "completed" and (step != "ref" or self._record["phase"] != "readback-pending"):
            _error("JOURNAL_STATE")
        record = self.record
        current = _find_effect(record, step, path)
        current["status"] = "uncertain"
        current["reason"] = reason
        record["phase"] = "uncertain"
        record["reason"] = reason
        _effect_sort(record)
        return self._persist(record, predecessor_sha256)

    def mark_ref_readback_complete(
        self,
        *,
        commit: str,
        tree: str,
        predecessor_sha256: str | None = None,
    ) -> dict[str, Any]:
        """Close only an unresolved ref after an exact external readback.

        The caller owns authentication and managed-file proof.  This local
        transition records only that the already-known ref target was observed;
        it never performs or authorizes a remote operation.
        """

        if self._record["phase"] == "completed":
            _error("JOURNAL_CLOSED")
        if self._record["phase"] not in {"ref-submitting", "uncertain"}:
            _error("JOURNAL_READBACK")
        commit = _validate_hash(commit, _SHA1_RE, "JOURNAL_READBACK")
        tree = _validate_hash(tree, _SHA1_RE, "JOURNAL_READBACK")
        zero = "0" * 40
        if commit == zero or tree == zero:
            _error("JOURNAL_READBACK")
        target_commit = self._record["target_commit"]
        target_tree = self._record["target_tree"]
        if (target_commit is None or target_tree is None
                or target_commit == zero or target_tree == zero
                or commit != target_commit or tree != target_tree):
            _error("JOURNAL_READBACK")

        by_step: dict[str, list[dict[str, Any]]] = {step: [] for step in _STEPS}
        for effect in self._record["effects"]:
            by_step[effect["step"]].append(effect)
        prior_steps = ("blob", "tree", "commit")
        if any(effect["status"] != "completed"
               for step in prior_steps for effect in by_step[step]):
            _error("JOURNAL_READBACK")
        if (len(by_step["tree"]) != 1 or len(by_step["commit"]) != 1
                or by_step["tree"][0]["status"] != "completed"
                or by_step["commit"][0]["status"] != "completed"):
            _error("JOURNAL_READBACK")
        if len(by_step["ref"]) != 1:
            _error("JOURNAL_READBACK")
        ref = by_step["ref"][0]
        expected_ref_status = "uncertain" if self._record["phase"] == "uncertain" else "submitting"
        if ref["status"] != expected_ref_status or ref["sha1"] != target_commit:
            _error("JOURNAL_READBACK")

        record = self.record
        current = _find_effect(record, "ref", None)
        current["status"] = "completed"
        current["sha1"] = target_commit
        current["reason"] = None
        record["phase"] = "completed"
        record["reason"] = None
        _effect_sort(record)
        return self._persist(record, predecessor_sha256)

    def mark_readback_complete(
        self,
        *,
        commit: str,
        tree: str,
        predecessor_sha256: str | None = None,
    ) -> dict[str, Any]:
        commit = _validate_hash(commit, _SHA1_RE)
        tree = _validate_hash(tree, _SHA1_RE)
        if self._record["phase"] != "readback-pending" or commit != self._record["target_commit"] or tree != self._record["target_tree"]:
            _error("JOURNAL_READBACK")
        record = self.record
        record["phase"] = "completed"
        record["reason"] = None
        return self._persist(record, predecessor_sha256)

    def resume_decision(self) -> dict[str, Any]:
        phase = self._record["phase"]
        if phase == "prepared":
            decision, reason = "new-operation-required", "prepared"
        elif phase.endswith("-submitting"):
            decision, reason = "hold", "submission-in-flight"
        elif phase in {"blob-created", "tree-created", "commit-created"}:
            decision, reason = "explicit-next-step", "acknowledged-object"
        elif phase == "readback-pending":
            decision, reason = "readback-required", "readback-pending"
        elif phase == "completed":
            decision, reason = "closed", "completed"
        elif phase == "uncertain":
            decision, reason = "hold", "uncertain"
        else:
            decision, reason = "hold", "failed"
        pending = [
            {"step": effect["step"], "path": effect["path"], "status": effect["status"]}
            for effect in self._record["effects"] if effect["status"] != "completed"
        ]
        return {
            "schema": SCHEMA_RESUME,
            "operation_id": self._operation_id,
            "phase": phase,
            "decision": decision,
            "reason": reason,
            "replay": False,
            "pending_effects": pending,
        }


def prepare(root: str | os.PathLike[str], operation_id: str, **identity: str | None) -> RemoteApplyJournal:
    """Create a new prepared journal; an existing operation is never replaced."""

    if identity.pop("target_tree", None) is not None or identity.pop("target_commit", None) is not None:
        _error("JOURNAL_TARGET")

    return RemoteApplyJournal.prepare(root, operation_id, **identity)  # type: ignore[arg-type]


def load(root: str | os.PathLike[str], operation_id: str) -> RemoteApplyJournal:
    """Load and strictly validate one journal without performing remote I/O."""

    return RemoteApplyJournal.load(root, operation_id)


def inventory(root: str | os.PathLike[str]) -> dict[str, Any]:
    """Return a custody-checked summary of every journal control record.

    Inventory never creates the control directory and never exposes record
    bodies, effect paths, or local filesystem paths. Unexpected directory
    entries, temporary controls, unsafe custody, malformed JSON, and
    non-canonical records fail closed before a summary is returned.
    """

    root_fd = parent_fd = None
    try:
        try:
            root_fd, parent_fd = _open_parent(root, create=False)
        except ContractError as error:
            if getattr(error, "code", None) == "JOURNAL_MISSING":
                return _inventory_result([])
            raise
        try:
            entries = sorted(os.scandir(parent_fd), key=lambda entry: entry.name)
        except OSError:
            _error("JOURNAL_INVENTORY")
        summary: list[dict[str, str]] = []
        for entry in entries:
            name = entry.name
            if (not isinstance(name, str) or not name.endswith(".json")
                    or name == ".json"):
                _error("JOURNAL_INVENTORY")
            operation_id = name[:-5]
            try:
                _validate_operation_id(operation_id)
                raw, digest = _read_control(parent_fd, name)
                record = _validate_record(_strict_json(raw))
                if (raw != _encode(record)
                        or record["operation_id"] != operation_id):
                    _error("JOURNAL_INVENTORY")
            except ContractError:
                _error("JOURNAL_INVENTORY")
            summary.append({
                "operation_id": operation_id,
                "phase": record["phase"],
                "digest": digest,
            })
        return _inventory_result(summary)
    finally:
        if parent_fd is not None:
            os.close(parent_fd)
        if root_fd is not None:
            os.close(root_fd)


def begin_submission(journal: RemoteApplyJournal, step: str, **kwargs: str | None) -> dict[str, Any]:
    return journal.begin_submission(step, **kwargs)  # type: ignore[arg-type]


def acknowledge(journal: RemoteApplyJournal, step: str, **kwargs: str | None) -> dict[str, Any]:
    return journal.acknowledge(step, **kwargs)  # type: ignore[arg-type]


def mark_uncertain(journal: RemoteApplyJournal, step: str, **kwargs: str | None) -> dict[str, Any]:
    return journal.mark_uncertain(step, **kwargs)  # type: ignore[arg-type]


def resume_decision(journal: RemoteApplyJournal) -> dict[str, Any]:
    return journal.resume_decision()


def mark_readback_complete(
    journal: RemoteApplyJournal,
    *,
    commit: str,
    tree: str,
    predecessor_sha256: str | None = None,
) -> dict[str, Any]:
    return journal.mark_readback_complete(
        commit=commit,
        tree=tree,
        predecessor_sha256=predecessor_sha256,
    )


def mark_ref_readback_complete(
    journal: RemoteApplyJournal,
    *,
    commit: str,
    tree: str,
    predecessor_sha256: str | None = None,
) -> dict[str, Any]:
    return journal.mark_ref_readback_complete(
        commit=commit,
        tree=tree,
        predecessor_sha256=predecessor_sha256,
    )


def closed_readonly_resume(journal: RemoteApplyJournal) -> dict[str, Any]:
    """Alias naming the deliberately non-replaying recovery decision."""

    return journal.resume_decision()


__all__ = [
    "JOURNAL_DIRECTORY",
    "MAX_BLOB_EFFECTS",
    "MAX_EFFECTS",
    "MAX_JOURNAL_BYTES",
    "RemoteApplyJournal",
    "SCHEMA",
    "SCHEMA_REMOTE_JOURNAL",
    "SCHEMA_RESUME",
    "SCHEMA_INVENTORY",
    "acknowledge",
    "begin_submission",
    "closed_readonly_resume",
    "inventory",
    "load",
    "mark_readback_complete",
    "mark_ref_readback_complete",
    "mark_uncertain",
    "prepare",
    "resume_decision",
]
