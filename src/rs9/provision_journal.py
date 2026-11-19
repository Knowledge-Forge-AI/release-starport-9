"""Durable local journal and exclusive lock for repository provisioning.

This module is deliberately transport-agnostic.  It owns custody-checked
control files, canonical digests, and the physical publisher-root lock; the
provisioning state machine owns the meaning of each transition.
"""

from __future__ import annotations

import copy
import fcntl
import hashlib
import json
import os
import re
import stat
from collections.abc import Mapping
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator

from rs9 import instance as _instance
from rs9.errors import ContractError
from rs9.security import scan_for_credentials, validate_repository, validate_slug

SCHEMA = "rs9.instance-github-provision-journal.v1alpha3"
SCHEMA_INVENTORY = "rs9.instance-github-provision-inventory.v1alpha3"
JOURNAL_DIRECTORY = ".rs9-instance/provision"
LOCK_NAME = "provision.lock"
MAX_JOURNAL_BYTES = 512 * 1024
MAX_RECORD_DEPTH = 10
MAX_OPERATION_ID_BYTES = 96

_PHASES = {
    "prepared",
    "repository-create-prepared",
    "repository-created",
    "first-readme-prepared",
    "main-anchor-read",
    "target-ref-prepared",
    "target-ref-created",
    "handoff-prepared",
    "handoff-completed",
    "held",
    "completed",
    "no-effect-closed",
    "partial-closed",
    "orphan-closed",
    "superseded",
}
_TERMINAL_STATES = {"nonterminal", "completed", "no-effect-closed", "partial-closed", "orphan-closed", "superseded"}
_OUTCOMES = {"applied", "definite-no-effect", "partial", "orphan", "uncertain"}
_EFFECT_FIELDS = {"repository", "main_anchor", "target_ref", "inner_coordinator"}
_EFFECT_VALUES = {
    "repository": {"not-attempted", "created", "existing", "created-unknown", "unknown"},
    "main_anchor": {"not-attempted", "created", "existing", "unknown"},
    "target_ref": {"not-attempted", "created", "existing-foreign", "unknown"},
    "inner_coordinator": {"not-attempted", "completed", "existing-foreign", "unknown"},
}
_INNER_FIELDS = {"operation_id", "plan_sha256", "config_sha256", "result_sha256", "result"}
_PENDING_FIELDS = {"kind", "request_sha256"}
_TERMINAL_FIELDS = {"state", "outcome_class", "reason"}
_TOKEN = re.compile(r"[a-z][a-z0-9-]{0,95}\Z")
_FIELD = re.compile(r"[A-Za-z][A-Za-z0-9_-]{0,95}\Z")
_BRANCH = re.compile(r"[A-Za-z0-9][A-Za-z0-9._/-]{0,127}\Z")
# Keep operation IDs aligned with the plan/observation token grammar.
_OPERATION = re.compile(r"[a-z][a-z0-9-]{0,95}\Z")
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_HEX40 = re.compile(r"[0-9a-f]{40}\Z")
_DRIVE_PATH = re.compile(r"^[A-Za-z]:[\\\\/]")
_PRIVATE_PATH_MARKERS = ("/Users/", "/private/", "/tmp/", "/var/", "/home/", "/Volumes/", "/opt/", "~/", "\\")


def _fail(code: str, message: str = "Provision journal contract rejected") -> None:
    raise ContractError(code, message)


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def canonical_bytes(value: Mapping[str, Any]) -> bytes:
    try:
        return (json.dumps(value, ensure_ascii=True, allow_nan=False, sort_keys=True,
                           separators=(",", ":")) + "\n").encode("ascii")
    except (TypeError, ValueError, UnicodeError):
        _fail("PROVISION_RECORD", "Provision record is not canonical JSON")
    raise AssertionError("unreachable")


def record_sha256(value: Mapping[str, Any]) -> str:
    return _sha256_bytes(canonical_bytes(value))


def _check_write_bound(data: bytes) -> bytes:
    if len(data) > MAX_JOURNAL_BYTES:
        _fail("PROVISION_LIMIT", "Provision journal record exceeds the bounded byte limit")
    return data


def _validate_hash(value: Any, code: str = "PROVISION_RECORD") -> str:
    if not isinstance(value, str) or _SHA256.fullmatch(value) is None:
        _fail(code, "Provision digest is invalid")
    scan_for_credentials(value)
    return value


def _validate_operation(value: Any) -> str:
    if not isinstance(value, str) or _OPERATION.fullmatch(value) is None:
        _fail("PROVISION_OPERATION", "Provision operation ID is invalid")
    if len(value.encode("utf-8")) > MAX_OPERATION_ID_BYTES:
        _fail("PROVISION_OPERATION", "Provision operation ID is too long")
    scan_for_credentials(value)
    return value


def _validate_token(value: Any, code: str = "PROVISION_RECORD") -> str:
    if not isinstance(value, str) or _TOKEN.fullmatch(value) is None:
        _fail(code, "Provision enum token is invalid")
    scan_for_credentials(value)
    return value


def _validate_timestamp(value: Any) -> str:
    try:
        parsed = _instance.parse_rfc3339_utc(value)
    except ContractError:
        _fail("PROVISION_RECORD", "Provision timestamp is invalid")
    return parsed.isoformat(timespec="microseconds" if "." in value else "seconds").replace("+00:00", "Z")


def _validate_nested(value: Any, depth: int = 0) -> Any:
    if depth > MAX_RECORD_DEPTH:
        _fail("PROVISION_RECORD", "Nested result exceeds the bounded depth")
    if isinstance(value, Mapping):
        if len(value) > 64:
            _fail("PROVISION_RECORD", "Nested result has too many fields")
        result: dict[str, Any] = {}
        for key, child in value.items():
            if not isinstance(key, str) or _FIELD.fullmatch(key) is None:
                _fail("PROVISION_RECORD", "Nested result key is invalid")
            scan_for_credentials(key)
            result[key] = _validate_nested(child, depth + 1)
        return result
    if isinstance(value, list):
        if len(value) > 256:
            _fail("PROVISION_RECORD", "Nested result has too many rows")
        return [_validate_nested(child, depth + 1) for child in value]
    if value is None or type(value) in (bool, int):
        return value
    if isinstance(value, str):
        if len(value) > 512:
            _fail("PROVISION_RECORD", "Nested result string is too long")
        if any(marker in value for marker in _PRIVATE_PATH_MARKERS) or _DRIVE_PATH.search(value):
            _fail("PROVISION_RECORD", "Nested result contains a private path")
        scan_for_credentials(value)
        return value
    _fail("PROVISION_RECORD", "Nested result contains an unsupported value")
    raise AssertionError("unreachable")


def _validate_record(value: Any) -> dict[str, Any]:
    allowed = {
        "schema", "operation_id", "instance_id", "repository", "branch", "plan_sha256",
        "engine_sha256", "phase", "terminal", "effects", "pending", "inner",
        "anchor", "updated_at",
    }
    if not isinstance(value, Mapping) or set(value) != allowed:
        _fail("PROVISION_SCHEMA", "Provision journal fields are not closed")
    if value["schema"] != SCHEMA:
        _fail("PROVISION_SCHEMA", "Provision journal schema is unsupported")
    operation_id = _validate_operation(value["operation_id"])
    try:
        validate_slug(value["instance_id"], "instance.id")
        validate_repository(value["repository"])
    except ContractError:
        raise
    scan_for_credentials(value["instance_id"])
    scan_for_credentials(value["repository"])
    branch = value["branch"]
    if (not isinstance(branch, str) or _BRANCH.fullmatch(branch) is None
            or ".." in branch or branch.endswith(("/", "."))):
        _fail("PROVISION_SCHEMA", "Provision branch is invalid")
    scan_for_credentials(branch)
    plan_sha = _validate_hash(value["plan_sha256"])
    engine_sha = _validate_hash(value["engine_sha256"])
    phase = value["phase"]
    if phase not in _PHASES:
        _fail("PROVISION_SCHEMA", "Provision journal phase is invalid")
    terminal = value["terminal"]
    if not isinstance(terminal, Mapping) or set(terminal) != _TERMINAL_FIELDS:
        _fail("PROVISION_SCHEMA", "Provision terminal record is not closed")
    state = terminal["state"]
    outcome = terminal["outcome_class"]
    reason = terminal["reason"]
    if state not in _TERMINAL_STATES or outcome not in _OUTCOMES:
        _fail("PROVISION_SCHEMA", "Provision terminal classification is invalid")
    if reason is not None:
        _validate_token(reason)
    if state == "nonterminal" and outcome != "uncertain":
        _fail("PROVISION_SCHEMA", "Nonterminal provision state must be uncertain")
    if state != "nonterminal" and outcome == "uncertain":
        _fail("PROVISION_SCHEMA", "Terminal provision state cannot be uncertain")
    if state != "nonterminal" and reason is None:
        _fail("PROVISION_SCHEMA", "Closed provision state requires a reason")
    effects = value["effects"]
    if not isinstance(effects, Mapping) or set(effects) != _EFFECT_FIELDS:
        _fail("PROVISION_SCHEMA", "Provision effects are not closed")
    normalized_effects: dict[str, str] = {}
    for key in sorted(_EFFECT_FIELDS):
        effect = effects[key]
        if effect not in _EFFECT_VALUES[key]:
            _fail("PROVISION_SCHEMA", "Provision effect value is invalid")
        normalized_effects[key] = effect
    pending = value["pending"]
    if not isinstance(pending, Mapping) or set(pending) != _PENDING_FIELDS:
        _fail("PROVISION_SCHEMA", "Provision pending record is not closed")
    pending_kind = pending["kind"]
    pending_sha = pending["request_sha256"]
    if pending_kind is not None:
        _validate_token(pending_kind)
    if pending_sha is not None:
        _validate_hash(pending_sha)
    if (pending_kind is None) != (pending_sha is None):
        _fail("PROVISION_SCHEMA", "Provision pending fields must be paired")
    inner = value["inner"]
    if not isinstance(inner, Mapping) or set(inner) != _INNER_FIELDS:
        _fail("PROVISION_SCHEMA", "Provision inner record is not closed")
    inner_id = inner["operation_id"]
    inner_plan = inner["plan_sha256"]
    inner_config = inner["config_sha256"]
    inner_result_sha = inner["result_sha256"]
    inner_result = inner["result"]
    if inner_id is not None:
        _validate_operation(inner_id)
    for digest in (inner_plan, inner_config, inner_result_sha):
        if digest is not None:
            _validate_hash(digest)
    if inner_id is None and any(item is not None for item in (inner_plan, inner_config, inner_result_sha, inner_result)):
        _fail("PROVISION_SCHEMA", "Inner handoff identity cannot be partially absent")
    if inner_id is not None and (inner_plan is None or inner_config is None):
        _fail("PROVISION_SCHEMA", "Inner handoff plan/config identity is required before call")
    if (inner_result is None) != (inner_result_sha is None):
        _fail("PROVISION_SCHEMA", "Inner result and digest must be paired")
    if inner_result is not None:
        normalized = _validate_nested(inner_result)
        if _sha256_bytes(canonical_bytes(normalized)) != inner_result_sha:
            _fail("PROVISION_SCHEMA", "Inner result digest does not match normalized result")
        inner_result = normalized
    mutation_values = {"created", "completed"}
    if state == "completed":
        if phase != "handoff-completed":
            _fail("PROVISION_SCHEMA", "Completed provision state has an invalid phase")
        if (normalized_effects["repository"] not in {"created", "existing"}
                or normalized_effects["main_anchor"] not in {"created", "existing"}
                or normalized_effects["target_ref"] != "created"
                or normalized_effects["inner_coordinator"] != "completed"
                or inner_id is None or inner_result is None):
            _fail("PROVISION_SCHEMA", "Completed provision state has incomplete effects")
    elif state == "no-effect-closed":
        if phase != "no-effect-closed" or any(effect in mutation_values | {"unknown"} for effect in normalized_effects.values()):
            _fail("PROVISION_SCHEMA", "No-effect provision state has mutation effects")
    elif state == "partial-closed":
        if phase != "partial-closed" or any(effect == "unknown" for effect in normalized_effects.values()) or not any(effect in mutation_values for effect in normalized_effects.values()):
            _fail("PROVISION_SCHEMA", "Partial provision state has incoherent effects")
    elif state == "orphan-closed":
        if phase != "orphan-closed" or any(effect == "unknown" for effect in normalized_effects.values()):
            _fail("PROVISION_SCHEMA", "Orphan provision state has incoherent effects")
    elif state == "superseded" and phase != "superseded":
        _fail("PROVISION_SCHEMA", "Superseded provision state has an invalid phase")
    anchor = value["anchor"]
    if not isinstance(anchor, Mapping) or set(anchor) != {"commit", "tree", "metadata_sha256"}:
        _fail("PROVISION_SCHEMA", "Provision anchor record is not closed")
    for key, length in (("commit", 40), ("tree", 40), ("metadata_sha256", 64)):
        if anchor[key] is not None:
            pattern = _HEX40 if length == 40 else _SHA256
            if not isinstance(anchor[key], str) or pattern.fullmatch(anchor[key]) is None:
                _fail("PROVISION_SCHEMA", "Provision anchor identity is invalid")
    updated = _validate_timestamp(value["updated_at"])
    return {
        "schema": SCHEMA,
        "operation_id": operation_id,
        "instance_id": value["instance_id"],
        "repository": value["repository"],
        "branch": branch,
        "plan_sha256": plan_sha,
        "engine_sha256": engine_sha,
        "phase": phase,
        "terminal": {"state": state, "outcome_class": outcome, "reason": reason},
        "effects": normalized_effects,
        "pending": {"kind": pending_kind, "request_sha256": pending_sha},
        "inner": {
            "operation_id": inner_id,
            "plan_sha256": inner_plan,
            "config_sha256": inner_config,
            "result_sha256": inner_result_sha,
            "result": inner_result,
        },
        "anchor": {
            "commit": anchor["commit"],
            "tree": anchor["tree"],
            "metadata_sha256": anchor["metadata_sha256"],
        },
        "updated_at": updated,
    }


def _root(root: str | os.PathLike[str]) -> Path:
    return _instance._validate_root(root)


def _ensure_directory(path: Path, mode: int) -> None:
    try:
        info = path.lstat()
    except FileNotFoundError:
        try:
            path.mkdir(mode=mode)
        except FileExistsError:
            pass
        except OSError:
            _fail("PROVISION_CUSTODY", "Provision control directory cannot be created")
        info = path.lstat()
    except OSError:
        _fail("PROVISION_CUSTODY", "Provision control directory cannot be inspected")
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
        _fail("PROVISION_CUSTODY", "Provision control directory is unsafe")
    if info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) & 0o022:
        _fail("PROVISION_CUSTODY", "Provision control directory custody is unsafe")


def _directory(root: Path, *, create: bool) -> Path:
    instance_dir = root / ".rs9-instance"
    provision_dir = instance_dir / "provision"
    if create:
        _ensure_directory(instance_dir, 0o700)
        _ensure_directory(provision_dir, 0o700)
    else:
        for directory in (instance_dir, provision_dir):
            try:
                info = directory.lstat()
            except FileNotFoundError:
                _fail("PROVISION_MISSING", "Provision control directory is missing")
            except OSError:
                _fail("PROVISION_CUSTODY", "Provision control directory cannot be inspected")
            if (stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode)
                    or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) & 0o022):
                _fail("PROVISION_CUSTODY", "Provision control directory is unsafe")
    return provision_dir


def _safe_file(path: Path, *, max_bytes: int = MAX_JOURNAL_BYTES) -> bytes:
    try:
        info = path.lstat()
    except FileNotFoundError:
        _fail("PROVISION_MISSING", "Provision journal is missing")
    except OSError:
        _fail("PROVISION_CUSTODY", "Provision journal cannot be inspected")
    if (stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode)
            or info.st_nlink != 1 or info.st_uid != os.getuid()
            or stat.S_IMODE(info.st_mode) != 0o600 or info.st_size > max_bytes):
        _fail("PROVISION_CUSTODY", "Provision journal custody is unsafe")
    try:
        data = path.read_bytes()
    except OSError:
        _fail("PROVISION_CUSTODY", "Provision journal cannot be read")
    if len(data) > max_bytes:
        _fail("PROVISION_LIMIT", "Provision journal is too large")
    return data


def _strict_record(data: bytes) -> dict[str, Any]:
    try:
        value = json.loads(data.decode("ascii"))
    except (UnicodeError, json.JSONDecodeError, TypeError, ValueError, RecursionError):
        _fail("PROVISION_SCHEMA", "Provision journal JSON is invalid")
    if not isinstance(value, Mapping):
        _fail("PROVISION_SCHEMA", "Provision journal JSON is not an object")
    normalized = _validate_record(value)
    if data != canonical_bytes(normalized):
        _fail("PROVISION_SCHEMA", "Provision journal JSON is not canonical")
    return normalized


def _write_new(path: Path, data: bytes) -> str:
    if path.exists() or path.is_symlink():
        _fail("PROVISION_EXISTS", "Provision journal already exists")
    temporary = path.with_name("." + path.name + ".tmp")
    if temporary.exists() or temporary.is_symlink():
        _fail("PROVISION_TEMP", "Provision journal temporary control exists")
    _check_write_bound(data)
    temporary_descriptor = None
    installed = False
    try:
        temporary_descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        view = memoryview(data)
        while view:
            count = os.write(temporary_descriptor, view)
            if count <= 0:
                _fail("PROVISION_IO", "Provision journal write failed")
            view = view[count:]
        os.fsync(temporary_descriptor)
        os.fchmod(temporary_descriptor, 0o600)
    except ContractError:
        try:
            temporary.unlink()
        except (FileNotFoundError, OSError):
            pass
        raise
    except OSError:
        try:
            temporary.unlink()
        except (FileNotFoundError, OSError):
            pass
        _fail("PROVISION_IO", "Provision journal write failed")
    finally:
        if temporary_descriptor is not None:
            os.close(temporary_descriptor)
            temporary_descriptor = None
    try:
        os.replace(temporary, path)
        installed = True
        directory_descriptor = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(directory_descriptor)
        finally:
            os.close(directory_descriptor)
    except OSError:
        # Once os.replace has succeeded, the journal path may already contain
        # the new record even if directory durability/readback fails.  Keep
        # that outcome uncertain rather than classifying it as a definite
        # install failure (which would invite an unsafe retry).
        _fail(
            "PROVISION_UNCERTAIN" if installed else "PROVISION_IO",
            "Provision journal install persistence is uncertain" if installed else "Provision journal install failed",
        )
    finally:
        if not installed:
            try:
                temporary.unlink()
            except FileNotFoundError:
                pass
            except OSError:
                pass
    return _sha256_bytes(data)


def _replace(path: Path, data: bytes, expected_digest: str) -> str:
    current = _safe_file(path)
    actual = _sha256_bytes(current)
    _validate_hash(expected_digest, "PROVISION_STALE")
    if actual != expected_digest:
        _fail("PROVISION_STALE", "Provision journal changed before transition")
    temporary = path.with_name("." + path.name + ".tmp")
    if temporary.exists() or temporary.is_symlink():
        _fail("PROVISION_TEMP", "Provision journal temporary control exists")
    _check_write_bound(data)
    temporary_descriptor = None
    installed = False
    try:
        temporary_descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        view = memoryview(data)
        while view:
            count = os.write(temporary_descriptor, view)
            if count <= 0:
                _fail("PROVISION_IO", "Provision journal transition write failed")
            view = view[count:]
        os.fsync(temporary_descriptor)
        os.fchmod(temporary_descriptor, 0o600)
    except ContractError:
        try:
            temporary.unlink()
        except (FileNotFoundError, OSError):
            pass
        raise
    except OSError:
        try:
            temporary.unlink()
        except (FileNotFoundError, OSError):
            pass
        _fail("PROVISION_IO", "Provision journal transition write failed")
    finally:
        if temporary_descriptor is not None:
            os.close(temporary_descriptor)
            temporary_descriptor = None
    try:
        os.replace(temporary, path)
        installed = True
        directory_descriptor = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(directory_descriptor)
        finally:
            os.close(directory_descriptor)
        observed = _safe_file(path)
    except OSError:
        _fail("PROVISION_UNCERTAIN", "Provision journal transition persistence is uncertain")
    finally:
        if not installed:
            try:
                temporary.unlink()
            except FileNotFoundError:
                pass
            except OSError:
                pass
    digest = _sha256_bytes(observed)
    if digest != _sha256_bytes(data):
        _fail("PROVISION_UNCERTAIN", "Provision journal transition readback differs")
    return digest


@contextmanager
def exclusive_lock(root: str | os.PathLike[str]) -> Iterator[None]:
    """Hold the publisher-root lock across one complete decision."""

    root_path = _root(root)
    instance_dir = root_path / ".rs9-instance"
    _ensure_directory(instance_dir, 0o700)
    path = instance_dir / LOCK_NAME
    descriptor = None
    try:
        descriptor = os.open(path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
        info = os.fstat(descriptor)
        if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
                or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o600):
            _fail("PROVISION_CUSTODY", "Provision lock custody is unsafe")
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            _fail("PROVISION_LOCKED", "Another provision decision holds the publisher lock")
    except ContractError:
        if descriptor is not None:
            os.close(descriptor)
        raise
    except OSError:
        if descriptor is not None:
            os.close(descriptor)
        _fail("PROVISION_LOCK", "Provision publisher lock is unavailable")
    try:
        yield
    finally:
        if descriptor is not None:
            try:
                fcntl.flock(descriptor, fcntl.LOCK_UN)
            except OSError:
                pass
            os.close(descriptor)


class ProvisionJournal:
    """One custody-checked, hash-chained provision journal."""

    def __init__(self, root: str | os.PathLike[str], record: Mapping[str, Any], digest: str) -> None:
        self.root = _root(root)
        normalized = _validate_record(record)
        self._record = copy.deepcopy(normalized)
        self._digest = _validate_hash(digest)
        if self._digest != _sha256_bytes(canonical_bytes(self._record)):
            _fail("PROVISION_SCHEMA", "Provision journal digest is invalid")

    @property
    def record(self) -> dict[str, Any]:
        return copy.deepcopy(self._record)

    @property
    def digest(self) -> str:
        return self._digest

    @property
    def operation_id(self) -> str:
        return self._record["operation_id"]

    @property
    def terminal(self) -> bool:
        return self._record["terminal"]["state"] != "nonterminal"

    @classmethod
    def prepare(
        cls,
        root: str | os.PathLike[str],
        *,
        operation_id: str,
        instance_id: str,
        repository: str,
        branch: str,
        plan_sha256: str,
        engine_sha256: str,
        updated_at: str,
    ) -> "ProvisionJournal":
        operation_id = _validate_operation(operation_id)
        try:
            validate_slug(instance_id, "instance.id")
            validate_repository(repository)
        except ContractError:
            raise
        record = {
            "schema": SCHEMA,
            "operation_id": operation_id,
            "instance_id": instance_id,
            "repository": repository,
            "branch": branch,
            "plan_sha256": _validate_hash(plan_sha256),
            "engine_sha256": _validate_hash(engine_sha256),
            "phase": "prepared",
            "terminal": {"state": "nonterminal", "outcome_class": "uncertain", "reason": None},
            "effects": {
                "repository": "not-attempted",
                "main_anchor": "not-attempted",
                "target_ref": "not-attempted",
                "inner_coordinator": "not-attempted",
            },
            "pending": {"kind": None, "request_sha256": None},
            "inner": {
                "operation_id": None,
                "plan_sha256": None,
                "config_sha256": None,
                "result_sha256": None,
                "result": None,
            },
            "anchor": {"commit": None, "tree": None, "metadata_sha256": None},
            "updated_at": _validate_timestamp(updated_at),
        }
        normalized = _validate_record(record)
        directory = _directory(_root(root), create=True)
        data = canonical_bytes(normalized)
        digest = _write_new(directory / (operation_id + ".json"), data)
        return cls(root, normalized, digest)

    @classmethod
    def load(cls, root: str | os.PathLike[str], operation_id: str) -> "ProvisionJournal":
        operation_id = _validate_operation(operation_id)
        path = _directory(_root(root), create=False) / (operation_id + ".json")
        data = _safe_file(path)
        normalized = _strict_record(data)
        if normalized["operation_id"] != operation_id:
            _fail("PROVISION_SCHEMA", "Provision operation identity differs")
        return cls(root, normalized, _sha256_bytes(data))

    def transition(
        self,
        *,
        phase: str,
        updated_at: str,
        terminal: Mapping[str, Any] | None = None,
        effects: Mapping[str, str] | None = None,
        pending: Mapping[str, Any] | None = None,
        inner: Mapping[str, Any] | None = None,
        anchor: Mapping[str, Any] | None = None,
    ) -> "ProvisionJournal":
        if phase not in _PHASES:
            _fail("PROVISION_SCHEMA", "Provision transition phase is invalid")
        if self.terminal:
            _fail("PROVISION_CLOSED", "Closed provision journal cannot transition")
        next_record = self.record
        next_record["phase"] = phase
        next_record["updated_at"] = _validate_timestamp(updated_at)
        if terminal is not None:
            next_record["terminal"] = dict(terminal)
        if effects is not None:
            next_record["effects"] = dict(effects)
        if pending is not None:
            next_record["pending"] = dict(pending)
        if inner is not None:
            next_record["inner"] = dict(inner)
        if anchor is not None:
            next_record["anchor"] = dict(anchor)
        normalized = _validate_record(next_record)
        data = canonical_bytes(normalized)
        path = _directory(self.root, create=False) / (self.operation_id + ".json")
        digest = _replace(path, data, self.digest)
        return ProvisionJournal(self.root, normalized, digest)

    @classmethod
    def inventory(cls, root: str | os.PathLike[str]) -> dict[str, Any]:
        directory = _directory(_root(root), create=False)
        try:
            entries = sorted(directory.iterdir(), key=lambda item: item.name)
        except OSError:
            _fail("PROVISION_CUSTODY", "Provision journal directory cannot be read")
        rows: list[dict[str, Any]] = []
        for path in entries:
            if path.name == LOCK_NAME:
                _fail("PROVISION_INVENTORY", "Provision lock is not a journal entry")
            if path.name.startswith(".") or path.suffix != ".json":
                _fail("PROVISION_INVENTORY", "Unexpected provision control entry")
            operation_id = path.stem
            journal = cls.load(root, operation_id)
            record = journal.record
            rows.append({
                "operation_id": operation_id,
                "instance_id": record["instance_id"],
                "repository": record["repository"],
                "phase": record["phase"],
                "terminal_state": record["terminal"]["state"],
                "digest": journal.digest,
            })
        material = {"schema": SCHEMA_INVENTORY, "entries": rows}
        return {
            "schema": SCHEMA_INVENTORY,
            "entries": rows,
            "inventory_sha256": record_sha256(material),
        }


def prepare(*args: Any, **kwargs: Any) -> ProvisionJournal:
    return ProvisionJournal.prepare(*args, **kwargs)


def load(root: str | os.PathLike[str], operation_id: str) -> ProvisionJournal:
    return ProvisionJournal.load(root, operation_id)


def inventory(root: str | os.PathLike[str]) -> dict[str, Any]:
    root_path = _root(root)
    try:
        _directory(root_path, create=False)
    except ContractError as error:
        if getattr(error, "code", None) == "PROVISION_MISSING":
            return {"schema": SCHEMA_INVENTORY, "entries": [], "inventory_sha256": record_sha256({"schema": SCHEMA_INVENTORY, "entries": []})}
        raise
    # Only an absent control directory means an empty inventory.  A journal
    # disappearing or changing during iteration remains a custody error.
    return ProvisionJournal.inventory(root_path)


__all__ = [
    "JOURNAL_DIRECTORY",
    "LOCK_NAME",
    "SCHEMA",
    "SCHEMA_INVENTORY",
    "ProvisionJournal",
    "canonical_bytes",
    "exclusive_lock",
    "inventory",
    "load",
    "prepare",
    "record_sha256",
]

