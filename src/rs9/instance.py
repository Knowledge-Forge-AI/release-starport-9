"""Offline publisher-root instance configuration and desired-state planning.

This module deliberately stops before GitHub transport, workflow execution, or
publication.  It owns only a small local publisher manifest, consumer
registrations, inert review scaffolding, and canonical local plan snapshots.
"""

from __future__ import annotations

import copy
import hashlib
import json
import os
import re
import shutil
import stat
import tempfile
import tomllib
from collections.abc import Callable, Mapping
from datetime import datetime
from importlib.resources import files as resource_files
from pathlib import Path
from typing import Any

from rs9.constants import SCHEMA_DESTINATIONS
from rs9.cross_validator import cross_validate, resolve_targets
from rs9.errors import ContractError
from rs9.fields import table, typed
from rs9.normalizer import normalize
from rs9.project import load_project
from rs9.security import (
    scan_for_credentials,
    scan_keys_for_credentials,
    validate_repository,
    validate_safe_relative_posix_path,
    validate_slug,
    validate_version_string,
)

SCHEMA_INSTANCE = "rs9.instance.v1alpha1"
SCHEMA_CONSUMER = "rs9.instance-consumer.v1alpha1"
SCHEMA_DESIRED = "rs9.instance-desired-state.v1alpha1"
SCHEMA_TRANSACTION = "rs9.instance-transaction.v1alpha1"
SCHEMA_PLAN = "rs9.instance-plan.v1alpha1"
SCHEMA_TEMPLATE = "rs9.instance-template.v1alpha1"

INSTANCE_FILE = "rs9-instance.toml"
STATE_FILE = ".rs9-instance/state/desired.json"
TRANSACTION_FILE = ".rs9-instance/transaction.json"
CONSUMER_DIRECTORY = ".rs9-instance/consumers"
SCAFFOLD_DIRECTORY = ".rs9-instance/scaffold"
MAX_FILE_BYTES = 1024 * 1024
MAX_PLAN_BYTES = 512 * 1024
MAX_OBSERVATION_AGE_SECONDS = 300

TEMPLATE_ALLOWLIST = {
    ("github-homebrew-projection", "v1alpha1"): {
        "files": ("template.json", "review-checklist.md", "publisher-registration.json"),
        "sha256": "ff1a1ff2d256653b7ce1f059d4a1d7b492d7d00c2769b49de6e50124a0260f80",
    },
}
SCAFFOLD_OUTPUTS = {
    "review-checklist.md": (SCAFFOLD_DIRECTORY + "/review-checklist.md", "reviewable-scaffold"),
    "publisher-registration.json": (SCAFFOLD_DIRECTORY + "/publisher-registration.json", "reviewable-scaffold"),
}

_BRANCH_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/-]{0,127}$")
_LABEL_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_PRIVATE_PATH_RE = re.compile(r"/(?:Users|home|root|private|tmp)/|~[/\\]|[A-Za-z]:\\")


class Record(dict):
    """Small dependency-free canonical result shape for snapshot outputs."""

    @property
    def sha256(self) -> str:
        return _sha256(canonical(self))

    def to_dict(self) -> dict[str, Any]:
        return copy.deepcopy(dict(self))

    def __getattr__(self, name: str) -> Any:
        try:
            return self[name]
        except KeyError:
            raise AttributeError(name) from None


def _validate_snapshot(value: Any, depth: int = 0, *, check_private_paths: bool = True) -> None:
    if depth > 12:
        raise ContractError("RECORD_LIMIT", "Record nesting bound exceeded")
    if isinstance(value, str):
        if any(ord(char) < 32 or ord(char) == 127 for char in value):
            raise ContractError("PRIVATE_PATH", "Private filesystem paths are forbidden in records")
        if check_private_paths and _PRIVATE_PATH_RE.search(value):
            raise ContractError("PRIVATE_PATH", "Private filesystem paths are forbidden in records")
        scan_for_credentials(value)
        return
    if isinstance(value, dict):
        if len(value) > 256:
            raise ContractError("RECORD_LIMIT", "Record field bound exceeded")
        for key, child in value.items():
            if not isinstance(key, str):
                raise ContractError("RECORD_TYPE", "Record keys must be strings")
            _validate_snapshot(key, depth + 1, check_private_paths=check_private_paths)
            # ``normalizedIntent`` is validated engine output.  The engine
            # owns its public summaries, argv, and relative contract paths;
            # keep credential/control scanning, but do not apply the
            # instance layer's private-path filter to those embedded fields.
            _validate_snapshot(child, depth + 1,
                               check_private_paths=False if key == "normalizedIntent" else check_private_paths)
        return
    if isinstance(value, list):
        if len(value) > 20_000:
            raise ContractError("RECORD_LIMIT", "Record list bound exceeded")
        for child in value:
            _validate_snapshot(child, depth + 1, check_private_paths=check_private_paths)
        return
    if value is None or type(value) in (int, bool):
        return
    raise ContractError("RECORD_TYPE", "Only deterministic JSON primitives are supported")


def snapshot(value: Any) -> Any:
    _validate_snapshot(value)
    return copy.deepcopy(value)


def canonical(value: Any, *, validate: bool = False) -> bytes:
    if validate:
        _validate_snapshot(value)
    try:
        return (json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False, allow_nan=False) + "\n").encode("utf-8")
    except (TypeError, ValueError, UnicodeError):
        raise ContractError("RECORD_TYPE", "Only deterministic JSON primitives are supported") from None


def record_sha256(value: Any) -> str:
    return _sha256(canonical(value))


def validate_sha256(value: Any, context: str = "hash") -> str:
    if not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{64}", value):
        raise ContractError("INVALID_HASH", f"A lowercase SHA-256 identity is required for {context}")
    return value


def parse_rfc3339_utc(value: Any) -> datetime:
    if not isinstance(value, str) or not re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?Z", value):
        raise ContractError("INVALID_TIMESTAMP", "Explicit RFC3339 UTC timestamp required")
    try:
        return datetime.fromisoformat(value)
    except ValueError:
        raise ContractError("INVALID_TIMESTAMP", "Timestamp has an invalid calendar date") from None


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _safe_label(value: Any, context: str) -> str:
    typed(value, str, context)
    if not _LABEL_RE.fullmatch(value):
        raise ContractError("INVALID_CONFIG", f"Invalid label for {context}")
    scan_for_credentials(value)
    return value


def _safe_branch(value: Any) -> str:
    typed(value, str, "hosting.publisher_branch")
    if not _BRANCH_RE.fullmatch(value) or ".." in value or value.endswith(("/", ".")):
        raise ContractError("INVALID_CONFIG", "Invalid publisher branch")
    scan_for_credentials(value)
    return value


def _safe_version(value: Any) -> str:
    typed(value, str, "engine.version")
    if value == "unreleased":
        return value
    if not _LABEL_RE.fullmatch(value):
        raise ContractError("INVALID_CONFIG", "Invalid installed engine version")
    scan_for_credentials(value)
    return value


def _validate_sha(value: Any, context: str) -> str:
    validate_sha256(value, context)
    return value


def _validate_root(root: str | os.PathLike[str]) -> Path:
    path = Path(os.path.abspath(os.fspath(root)))
    current = path
    while True:
        try:
            info = current.lstat()
        except FileNotFoundError:
            if current == path:
                raise ContractError("INVALID_DIRECTORY", "Publisher root must be an existing directory") from None
            current = current.parent
            continue
        except OSError:
            raise ContractError("INPUT_UNREADABLE", "Publisher root cannot be inspected") from None
        if stat.S_ISLNK(info.st_mode):
            raise ContractError("SYMLINK_REJECTED", "Publisher root ancestry cannot contain symlinks")
        if current == path:
            if not stat.S_ISDIR(info.st_mode):
                raise ContractError("INVALID_DIRECTORY", "Publisher root must be a directory")
        if current == current.parent:
            return path
        current = current.parent


def _relative_parts(relative: str) -> list[str]:
    validate_safe_relative_posix_path(relative)
    return relative.split("/")


def _open_root(root: Path) -> int:
    try:
        return os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    except OSError:
        raise ContractError("INPUT_UNREADABLE", "Publisher root cannot be opened") from None


def _reject_parent_components(path: str | os.PathLike[str]) -> None:
    """Reject lexical parent traversal before validating an input path.

    The engine accepts path-like values and resolves them itself.  Passing a
    path containing ``..`` after validating its lexical ``abspath`` could
    therefore validate one ancestry while the engine reads through another
    (for example, through a symlinked ancestor).  Keep the boundary explicit
    by requiring callers to provide a path without parent components.
    """

    if ".." in Path(os.fspath(path)).parts:
        raise ContractError("INVALID_PATH", "Input paths cannot contain parent components")


def _validate_input_file(path: str | os.PathLike[str]) -> Path:
    _reject_parent_components(path)
    candidate = Path(os.path.abspath(os.fspath(path)))
    _validate_root(candidate.parent)
    try:
        info = candidate.lstat()
    except FileNotFoundError:
        raise ContractError("MISSING_REQUIRED_FILE", "Selected input file is missing") from None
    except OSError:
        raise ContractError("INPUT_UNREADABLE", "Selected input file cannot be inspected") from None
    if stat.S_ISLNK(info.st_mode):
        raise ContractError("SYMLINK_REJECTED", "Selected input file cannot be a symlink")
    if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_FILE_BYTES:
        raise ContractError("INVALID_FILE", "Selected input file must be a bounded regular file")
    return candidate


def _validate_project_inputs(project: str | os.PathLike[str]) -> Path:
    """Bound the current engine's path-based project reads before loading."""

    _reject_parent_components(project)
    project_root = _validate_root(project)
    config = project_root / ".rs9"
    try:
        info = config.lstat()
    except FileNotFoundError:
        return project_root
    except OSError:
        raise ContractError("INPUT_UNREADABLE", "Project configuration cannot be inspected") from None
    if stat.S_ISLNK(info.st_mode):
        raise ContractError("SYMLINK_REJECTED", "Project/configuration root cannot be a symlink")
    if not stat.S_ISDIR(info.st_mode):
        return project_root
    _validate_root(config)
    try:
        entries = list(config.iterdir())
    except OSError:
        raise ContractError("INPUT_UNREADABLE", "Project configuration cannot be read") from None
    for entry in entries:
        _validate_input_file(entry)
    return project_root


def _walk_parent(root_fd: int, parts: list[str], *, create: bool = False) -> int:
    current = os.dup(root_fd)
    try:
        for part in parts[:-1]:
            if create:
                try:
                    os.mkdir(part, 0o755, dir_fd=current)
                except FileExistsError:
                    pass
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=current)
            os.close(current)
            current = child
        return current
    except FileNotFoundError:
        os.close(current)
        raise
    except OSError:
        os.close(current)
        raise ContractError("OUTPUT_CONFINEMENT", "Publisher path cannot be traversed") from None


def _inspect_file(root_fd: int, relative: str) -> dict[str, Any]:
    parts = _relative_parts(relative)
    parent = None
    try:
        parent = _walk_parent(root_fd, parts)
    except FileNotFoundError:
        return {"state": "missing", "sha256": None, "size": None, "mode": None}
    try:
        # Refuse special files before opening them.  The non-blocking open is
        # a second boundary for a replacement race between lstat and open;
        # regular files are returned to blocking mode after fstat confirms
        # their type.
        preliminary = os.stat(parts[-1], dir_fd=parent, follow_symlinks=False)
    except FileNotFoundError:
        os.close(parent)
        return {"state": "missing", "sha256": None, "size": None, "mode": None}
    except OSError as error:
        os.close(parent)
        if error.errno in (getattr(os, "ELOOP", 40), getattr(os, "EINVAL", 22)):
            return {"state": "unsafe", "sha256": None, "size": None, "mode": None}
        return {"state": "unreadable", "sha256": None, "size": None, "mode": None}
    if not stat.S_ISREG(preliminary.st_mode) or preliminary.st_size > MAX_FILE_BYTES:
        os.close(parent)
        return {"state": "unsafe", "sha256": None, "size": preliminary.st_size, "mode": None}
    try:
        descriptor = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
    except FileNotFoundError:
        os.close(parent)
        return {"state": "missing", "sha256": None, "size": None, "mode": None}
    except OSError as error:
        os.close(parent)
        if error.errno in (getattr(os, "ELOOP", 40), getattr(os, "EINVAL", 22)):
            return {"state": "unsafe", "sha256": None, "size": None, "mode": None}
        return {"state": "unreadable", "sha256": None, "size": None, "mode": None}
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_FILE_BYTES:
            return {"state": "unsafe", "sha256": None, "size": info.st_size, "mode": None}
        os.set_blocking(descriptor, True)
        data = b""
        while len(data) <= MAX_FILE_BYTES:
            chunk = os.read(descriptor, min(64 * 1024, MAX_FILE_BYTES + 1 - len(data)))
            if not chunk:
                break
            data += chunk
        if len(data) > MAX_FILE_BYTES:
            return {"state": "unsafe", "sha256": None, "size": len(data), "mode": None}
        return {"state": "present", "sha256": _sha256(data), "size": len(data),
                "mode": stat.S_IMODE(info.st_mode), "data": data}
    except OSError:
        return {"state": "unreadable", "sha256": None, "size": None, "mode": None}
    finally:
        os.close(descriptor)
        os.close(parent)


def _read_file(root_fd: int, relative: str) -> bytes:
    info = _inspect_file(root_fd, relative)
    if info["state"] != "present":
        code = "MISSING_REQUIRED_FILE" if info["state"] == "missing" else "INPUT_UNREADABLE"
        raise ContractError(code, "Required publisher file is unavailable")
    return info["data"]


def _write_stage_file(stage: Path, relative: str, data: bytes, *, mode: int = 0o644) -> Path:
    parts = _relative_parts(relative)
    target = stage.joinpath(*parts)
    try:
        target.parent.mkdir(parents=True, exist_ok=True)
    except OSError:
        raise ContractError("OUTPUT_CONFINEMENT", "Private staging write failed") from None
    try:
        descriptor = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    except OSError:
        raise ContractError("OUTPUT_CONFINEMENT", "Private staging write failed") from None
    try:
        with os.fdopen(descriptor, "wb") as stream:
            descriptor = -1
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
            os.fchmod(stream.fileno(), mode)
    except OSError:
        if descriptor >= 0:
            os.close(descriptor)
        raise ContractError("OUTPUT_CONFINEMENT", "Private staging write failed") from None
    return target


def _link_new(root_fd: int, stage_file: Path, relative: str) -> str:
    parts = _relative_parts(relative)
    parent = None
    try:
        parent = _walk_parent(root_fd, parts, create=True)
        os.link(stage_file, parts[-1], dst_dir_fd=parent, follow_symlinks=False)
        os.fsync(parent)
        return "created"
    except FileExistsError:
        return "exists"
    except OSError:
        raise ContractError("OUTPUT_CONFINEMENT", "Publisher file creation failed") from None
    finally:
        if parent is not None:
            os.close(parent)


def _atomic_replace_control(root: Path, stage_file: Path, relative: str, expected_sha256: str | None) -> str:
    """Replace an RS9-owned control file after an exact readback check."""

    parts = _relative_parts(relative)
    root_fd = _open_root(root)
    parent = None
    try:
        parent = _walk_parent(root_fd, parts, create=True)
        current = _inspect_file(parent, parts[-1])
        if current["state"] == "missing":
            if expected_sha256 is not None:
                return "drift"
            os.link(stage_file, parts[-1], dst_dir_fd=parent, follow_symlinks=False)
            os.fsync(parent)
            return "created"
        if current["state"] != "present" or expected_sha256 is None or current["sha256"] != expected_sha256:
            return "drift" if current["state"] == "present" else "unsafe"
        # A controlled state file is not consumer content.  Replacing it is
        # allowed only after the previous bytes match the expected identity.
        os.replace(os.fspath(stage_file), parts[-1], dst_dir_fd=parent)
        os.fsync(parent)
        return "replaced"
    except OSError:
        raise ContractError("OUTPUT_CONFINEMENT", "Publisher state replacement failed") from None
    finally:
        if parent is not None:
            os.close(parent)
        os.close(root_fd)


def _unlink_marker(root_fd: int) -> None:
    parts = _relative_parts(TRANSACTION_FILE)
    parent = None
    try:
        parent = _walk_parent(root_fd, parts)
        try:
            os.unlink(parts[-1], dir_fd=parent)
        except FileNotFoundError:
            pass
    except FileNotFoundError:
        pass
    except OSError:
        raise ContractError("OUTPUT_CONFINEMENT", "Instance transaction marker cannot be cleared") from None
    finally:
        if parent is not None:
            os.close(parent)


def _json_bytes(value: Mapping[str, Any], *, limit: int = MAX_PLAN_BYTES) -> bytes:
    data = canonical(value, validate=True)
    if len(data) > limit:
        raise ContractError("RECORD_LIMIT", "Instance record exceeds size bound")
    return data


def _toml_string(value: str) -> str:
    return json.dumps(value, ensure_ascii=False)


def _render_manifest(manifest: Mapping[str, Any]) -> bytes:
    engine = manifest["engine"]
    template = manifest["template"]
    hosting = manifest["hosting"]
    adapter = manifest["adapter"]
    lines = [
        f"schema = {_toml_string(manifest['schema'])}",
        f"instance_id = {_toml_string(manifest['instance_id'])}",
        "",
        "[engine]",
        f"distribution = {_toml_string(engine['distribution'])}",
        f"version = {_toml_string(engine['version'])}",
        "",
        "[template]",
        f"id = {_toml_string(template['id'])}",
        f"version = {_toml_string(template['version'])}",
        f"sha256 = {_toml_string(template['sha256'])}",
        "",
        "[hosting]",
    ]
    for key in ("provider", "scope", "publisher_repository", "publisher_branch", "runner", "environment", "operator_binding"):
        lines.append(f"{key} = {_toml_string(hosting[key])}")
    lines.extend(("", "[adapter]", f"name = {_toml_string(adapter['name'])}",
                  f"mode = {_toml_string(adapter['mode'])}", ""))
    return ("\n".join(lines)).encode("utf-8")


def _render_registration(registration: Mapping[str, Any]) -> bytes:
    lines = [
        f"schema = {_toml_string(registration['schema'])}",
        f"id = {_toml_string(registration['id'])}",
        f"project_id = {_toml_string(registration['project_id'])}",
        f"repository = {_toml_string(registration['repository'])}",
        f"destination_id = {_toml_string(registration['destination_id'])}",
        f"package_id = {_toml_string(registration['package_id'])}",
        f"package_name = {_toml_string(registration['package_name'])}",
        f"project_inputs_sha256 = {_toml_string(registration['project_inputs_sha256'])}",
        f"destinations_sha256 = {_toml_string(registration['destinations_sha256'])}",
        "",
        "[project_inputs]",
    ]
    for key, value in sorted(registration["project_inputs"].items()):
        lines.append(f"{_toml_string(key)} = {_toml_string(value)}")
    return ("\n".join(lines)).encode("utf-8")


def _render_state(manifest_bytes: bytes, template_sha256: str, files: list[dict[str, Any]]) -> bytes:
    state = {
        "schema": SCHEMA_DESIRED,
        "instance_manifest_sha256": _sha256(manifest_bytes),
        "template_sha256": template_sha256,
        "files": sorted(files, key=lambda row: row["path"]),
    }
    return _json_bytes(state)


def _render_transaction(
    desired_state: bytes,
    files: list[dict[str, Any]],
    *,
    operation: str = "init",
    pending_consumer_id: str | None = None,
) -> bytes:
    if operation == "register":
        if pending_consumer_id is None:
            raise ContractError("TRANSACTION_SCHEMA", "Register transaction target is required")
        pending_path = _registration_path(pending_consumer_id)
    elif pending_consumer_id is not None:
        raise ContractError("TRANSACTION_SCHEMA", "Init transaction cannot have a consumer target")
    transaction = {
        "schema": SCHEMA_TRANSACTION,
        "operation": operation,
        "desired_state_sha256": _sha256(desired_state),
        "state": "prepared",
        "files": [{"path": row["path"], "sha256": row["sha256"], "status": "pending"}
                   for row in sorted(files, key=lambda row: row["path"])],
    }
    if operation == "register":
        transaction["pending_consumer_id"] = pending_consumer_id
        transaction["pending_path"] = pending_path
    return _json_bytes(transaction)


def _resource_bytes(template_id: str, template_version: str) -> dict[str, bytes]:
    if not isinstance(template_id, str) or not isinstance(template_version, str):
        raise ContractError("UNKNOWN_TEMPLATE", "Unknown installed instance template")
    key = (template_id, template_version)
    if key not in TEMPLATE_ALLOWLIST:
        raise ContractError("UNKNOWN_TEMPLATE", "Unknown installed instance template")
    names = TEMPLATE_ALLOWLIST[key]["files"]
    try:
        root = resource_files("rs9").joinpath("_resources", "instance-templates", template_id, template_version)
        result = {name: root.joinpath(name).read_bytes() for name in names}
    except (OSError, FileNotFoundError):
        raise ContractError("TEMPLATE_UNAVAILABLE", "Installed instance template is unavailable") from None
    if any(len(value) > MAX_FILE_BYTES for value in result.values()):
        raise ContractError("TEMPLATE_LIMIT", "Installed instance template exceeds size bound")
    return result


def _template(template_id: str, template_version: str) -> dict[str, Any]:
    resources = _resource_bytes(template_id, template_version)
    try:
        metadata = json.loads(resources["template.json"].decode("utf-8"))
    except (UnicodeError, ValueError):
        raise ContractError("TEMPLATE_SCHEMA", "Installed instance template metadata is invalid") from None
    table(metadata, {"schema", "id", "version", "kind", "qualified", "publication_enabled", "files"},
          "instance template", required={"schema", "id", "version", "kind", "qualified", "publication_enabled", "files"})
    if metadata["schema"] != SCHEMA_TEMPLATE or metadata["id"] != template_id or metadata["version"] != template_version:
        raise ContractError("TEMPLATE_SCHEMA", "Installed instance template identity disagrees")
    if metadata["kind"] != "presence-scaffold" or metadata["qualified"] is not False or metadata["publication_enabled"] is not False:
        raise ContractError("TEMPLATE_AUTHORITY", "Instance template cannot claim publication authority")
    files = typed(metadata["files"], list, "instance template files")
    allowlist = TEMPLATE_ALLOWLIST[(template_id, template_version)]
    expected = {name for name in allowlist["files"] if name != "template.json"}
    actual = set()
    for row in files:
        table(row, {"name", "role"}, "instance template file", required={"name", "role"})
        if type(row["name"]) is not str or type(row["role"]) is not str:
            raise ContractError("TEMPLATE_SCHEMA", "Instance template file identity is invalid")
        if row["name"] not in expected or row["role"] != "reviewable-scaffold":
            raise ContractError("TEMPLATE_SCHEMA", "Instance template file is not an inert scaffold")
        actual.add(row["name"])
    if actual != expected:
        raise ContractError("TEMPLATE_SCHEMA", "Instance template file set is incomplete")
    bundle = hashlib.sha256()
    for name in allowlist["files"]:
        encoded = name.encode("utf-8")
        data = resources[name]
        bundle.update(len(encoded).to_bytes(8, "big"))
        bundle.update(encoded)
        bundle.update(len(data).to_bytes(8, "big"))
        bundle.update(data)
    if bundle.hexdigest() != allowlist["sha256"]:
        raise ContractError("TEMPLATE_INTEGRITY", "Installed instance template bytes are not allowlisted")
    return {"id": template_id, "version": template_version, "sha256": bundle.hexdigest(),
            "metadata": metadata, "resources": resources}


def _read_toml_bytes(root_fd: int, relative: str) -> tuple[dict[str, Any], bytes, str]:
    raw = _read_file(root_fd, relative)
    try:
        text = raw.decode("utf-8")
        scan_for_credentials(text)
        doc = tomllib.loads(text)
        scan_keys_for_credentials(doc)
    except UnicodeError:
        raise ContractError("INVALID_ENCODING", "Publisher configuration must be UTF-8") from None
    except tomllib.TOMLDecodeError:
        raise ContractError("INVALID_TOML", "Publisher configuration is invalid TOML") from None
    return doc, raw, _sha256(raw)


def _load_manifest(root: Path, root_fd: int) -> tuple[dict[str, Any], bytes]:
    doc, raw, _ = _read_toml_bytes(root_fd, INSTANCE_FILE)
    table(doc, {"schema", "instance_id", "engine", "template", "hosting", "adapter"},
          "rs9-instance.toml", required={"schema", "instance_id", "engine", "template", "hosting", "adapter"})
    if doc["schema"] != SCHEMA_INSTANCE:
        raise ContractError("SCHEMA_MISMATCH", "Unsupported instance manifest schema")
    validate_slug(doc["instance_id"], "instance_id")
    engine = table(doc["engine"], {"distribution", "version"}, "engine", required={"distribution", "version"})
    if engine["distribution"] != "release-starport-9":
        raise ContractError("INVALID_CONFIG", "Unsupported instance engine")
    _safe_version(engine["version"])
    template = table(doc["template"], {"id", "version", "sha256"}, "template", required={"id", "version", "sha256"})
    validate_slug(template["id"], "template.id")
    _safe_label(template["version"], "template.version")
    _validate_sha(template["sha256"], "template.sha256")
    hosting = table(doc["hosting"], {"provider", "scope", "publisher_repository", "publisher_branch", "runner", "environment", "operator_binding"},
                    "hosting", required={"provider", "scope", "publisher_repository", "publisher_branch", "runner", "environment", "operator_binding"})
    if hosting["provider"] != "github.com":
        raise ContractError("INVALID_CONFIG", "Only github.com hosting is supported")
    _safe_label(hosting["scope"], "hosting.scope")
    validate_repository(hosting["publisher_repository"])
    _safe_branch(hosting["publisher_branch"])
    _safe_label(hosting["runner"], "hosting.runner")
    _safe_label(hosting["environment"], "hosting.environment")
    _safe_label(hosting["operator_binding"], "hosting.operator_binding")
    adapter = table(doc["adapter"], {"name", "mode"}, "adapter", required={"name", "mode"})
    if adapter != {"name": "homebrew", "mode": "projection"}:
        raise ContractError("INVALID_CONFIG", "Only Homebrew projection instances are supported")
    return doc, raw


def _registration_path(consumer_id: str) -> str:
    validate_slug(consumer_id, "consumer_id")
    return f"{CONSUMER_DIRECTORY}/{consumer_id}.toml"


def _load_registration(root_fd: int, consumer_id: str) -> tuple[dict[str, Any], bytes]:
    path = _registration_path(consumer_id)
    doc, raw, _ = _read_toml_bytes(root_fd, path)
    table(doc, {"schema", "id", "project_id", "repository", "destination_id", "package_id", "package_name",
                "project_inputs_sha256", "destinations_sha256", "project_inputs"},
          "consumer registration", required={"schema", "id", "project_id", "repository", "destination_id", "package_id",
                                              "package_name", "project_inputs_sha256", "destinations_sha256", "project_inputs"})
    if doc["schema"] != SCHEMA_CONSUMER or doc["id"] != consumer_id:
        raise ContractError("REGISTRATION_SCHEMA", "Consumer registration identity disagrees")
    validate_slug(doc["project_id"], "project_id")
    validate_repository(doc["repository"])
    validate_slug(doc["destination_id"], "destination_id")
    validate_slug(doc["package_id"], "package_id")
    _safe_label(doc["package_name"], "package_name")
    _validate_sha(doc["project_inputs_sha256"], "project_inputs_sha256")
    _validate_sha(doc["destinations_sha256"], "destinations_sha256")
    inputs = typed(doc["project_inputs"], dict, "project_inputs")
    if not inputs or any(not isinstance(name, str) for name in inputs):
        raise ContractError("REGISTRATION_SCHEMA", "Consumer input snapshot is invalid")
    for name, value in inputs.items():
        validate_safe_relative_posix_path(name)
        _validate_sha(value, "project_inputs value")
    if record_sha256(dict(sorted(inputs.items()))) != doc["project_inputs_sha256"]:
        raise ContractError("REGISTRATION_SCHEMA", "Consumer input snapshot hash disagrees")
    return doc, raw


def _list_registrations(root_fd: int) -> dict[str, tuple[dict[str, Any], bytes]]:
    directory_parts = _relative_parts(CONSUMER_DIRECTORY)
    parent = None
    descriptor = None
    try:
        parent = _walk_parent(root_fd, directory_parts)
        descriptor = os.open(directory_parts[-1], os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
    except FileNotFoundError:
        if parent is not None:
            os.close(parent)
        return {}
    except OSError:
        if parent is not None:
            os.close(parent)
        raise ContractError("INPUT_UNREADABLE", "Consumer registration directory is unavailable") from None
    try:
        result: dict[str, tuple[dict[str, Any], bytes]] = {}
        with os.scandir(descriptor) as entries:
            for entry in entries:
                if entry.is_symlink():
                    raise ContractError("SYMLINK_REJECTED", "Consumer registration cannot be a symlink")
                if not entry.is_file(follow_symlinks=False) or not entry.name.endswith(".toml"):
                    raise ContractError("UNKNOWN_FILE", "Unknown consumer registration entry")
                consumer_id = entry.name[:-5]
                validate_slug(consumer_id, "consumer_id")
                registration, raw = _load_registration(root_fd, consumer_id)
                result[consumer_id] = (registration, raw)
        return result
    except OSError:
        raise ContractError("INPUT_UNREADABLE", "Consumer registration directory cannot be read") from None
    finally:
        if descriptor is not None:
            os.close(descriptor)
        if parent is not None:
            os.close(parent)


def _selected_project_inputs(project_hashes: Mapping[str, str]) -> dict[str, str]:
    required = {"project.toml", "releases.toml", "homebrew.toml"}
    if not required <= set(project_hashes):
        raise ContractError("INSTANCE_TARGET", "Selected consumer lacks the required Homebrew configuration")
    return {name: project_hashes[name] for name in sorted(required)}


def _load_consumer(project: str | os.PathLike[str], destinations: str | os.PathLike[str], *, version: str | None = None) -> dict[str, Any]:
    project_root = _validate_project_inputs(project)
    destinations_path = _validate_input_file(destinations)
    project_hashes: dict[str, str] = {}
    project_map = load_project(project_root, input_hashes=project_hashes)
    destination_hashes: dict[str, str] = {}
    from rs9.destinations import load_destinations
    destination_doc = load_destinations(destinations_path, input_hashes=destination_hashes)
    destination_digest = destination_hashes["destinations.toml"]
    if destination_doc.get("schema") != SCHEMA_DESTINATIONS:
        raise ContractError("DESTINATION_SCHEMA", "Destination validation disagrees")
    cross_validate(project_map, destination_doc)
    targets = resolve_targets(project_map, destination_doc)
    homebrew = [target for target in targets if target["adapter"] == "homebrew" and target["mode"] == "projection"]
    if not homebrew:
        raise ContractError("INSTANCE_TARGET", "Consumer has no Homebrew projection target")
    if len(homebrew) > 1:
        raise ContractError("INSTANCE_TARGET", "Consumer has multiple Homebrew projection targets")
    target = homebrew[0]
    selected_inputs = _selected_project_inputs(project_hashes)
    if version is None:
        normalized = None
        normalized_hash = None
    else:
        normalized_bytes = normalize(project_root, destinations_path, version)
        try:
            normalized = json.loads(normalized_bytes.decode("utf-8"))
        except (UnicodeError, ValueError):
            raise ContractError("NORMALIZATION_OUTPUT", "Current normalizer produced invalid JSON") from None
        normalized_hash = _sha256(normalized_bytes)
        normalized_targets = [row for row in normalized.get("targets", [])
                              if row.get("adapter") == "homebrew" and row.get("mode") == "projection"]
        selected = normalized_targets[0] if len(normalized_targets) == 1 else None
        if selected is None or any(selected.get(key) != target.get(key)
                                   for key in ("adapter", "mode", "destination", "package", "name")):
            raise ContractError("INSTANCE_TARGET", "Normalized Homebrew target disagrees with routing")
        evidence = normalized.get("evidence")
        evidence_rows = evidence.get("inputs") if isinstance(evidence, dict) else None
        if not isinstance(evidence_rows, list):
            raise ContractError("NORMALIZATION_OUTPUT", "Normalized input evidence is invalid")
        evidence_map: dict[str, str] = {}
        for row in evidence_rows:
            if not isinstance(row, dict) or set(row) != {"filename", "sha256"}:
                raise ContractError("NORMALIZATION_OUTPUT", "Normalized input evidence is invalid")
            filename, digest = row["filename"], row["sha256"]
            if not isinstance(filename, str) or filename in evidence_map:
                raise ContractError("NORMALIZATION_OUTPUT", "Normalized input evidence is invalid")
            _validate_sha(digest, "normalized input evidence")
            evidence_map[filename] = digest
        expected_evidence = {**selected_inputs, "destinations.toml": destination_digest}
        if any(evidence_map.get(name) != digest for name, digest in expected_evidence.items()):
            raise ContractError("INPUT_DRIFT", "Normalized input evidence disagrees with captured inputs")
    project_doc = project_map["project.toml"]
    project_identity = project_doc["project"]
    return {
        "project_id": project_identity["id"],
        "repository": project_identity["repository"],
        "target": target,
        "project_inputs": selected_inputs,
        "project_inputs_sha256": record_sha256(selected_inputs),
        "destinations_sha256": destination_digest,
        "normalized": normalized,
        "normalized_sha256": normalized_hash,
    }


def _manifest_record(*, instance_id: str, engine_version: str, template: Mapping[str, Any],
                     publisher_repository: str, publisher_branch: str, runner: str,
                     environment: str, operator_binding: str) -> dict[str, Any]:
    validate_slug(instance_id, "instance_id")
    validate_repository(publisher_repository)
    _safe_branch(publisher_branch)
    engine_version = _safe_version(engine_version)
    template_id, template_version = template["id"], template["version"]
    return {
        "schema": SCHEMA_INSTANCE,
        "instance_id": instance_id,
        "engine": {"distribution": "release-starport-9", "version": engine_version},
        "template": {"id": template_id, "version": template_version, "sha256": template["sha256"]},
        "hosting": {"provider": "github.com", "scope": publisher_repository.split("/", 1)[0],
                    "publisher_repository": publisher_repository, "publisher_branch": publisher_branch,
                    "runner": _safe_label(runner, "runner"), "environment": _safe_label(environment, "environment"),
                    "operator_binding": _safe_label(operator_binding, "operator_binding")},
        "adapter": {"name": "homebrew", "mode": "projection"},
    }


def _desired_files(manifest_bytes: bytes, template: Mapping[str, Any], registrations: Mapping[str, tuple[Mapping[str, Any], bytes]]) -> list[dict[str, Any]]:
    files: list[dict[str, Any]] = [{"path": INSTANCE_FILE, "role": "instance-manifest", "sha256": _sha256(manifest_bytes), "mode": 0o644}]
    for resource_name, (path, role) in SCAFFOLD_OUTPUTS.items():
        files.append({"path": path, "role": role, "sha256": _sha256(template["resources"][resource_name]), "mode": 0o644})
    for consumer_id, (_, raw) in sorted(registrations.items()):
        files.append({"path": _registration_path(consumer_id), "role": "consumer-registration", "sha256": _sha256(raw), "mode": 0o644})
    return sorted(files, key=lambda row: row["path"])


def _current_files(root_fd: int, desired: list[dict[str, Any]]) -> list[dict[str, Any]]:
    result = []
    for row in desired:
        observed = _inspect_file(root_fd, row["path"])
        state = observed["state"]
        if state == "present":
            state = ("exact" if observed["sha256"] == row["sha256"]
                     and observed["mode"] == row["mode"] else "drift")
        result.append({"path": row["path"], "role": row["role"], "desired_sha256": row["sha256"],
                       "observed_sha256": observed["sha256"], "observed_mode": observed["mode"], "state": state})
    return result


def _local_outcome(current: list[dict[str, Any]], marker_present: bool) -> str:
    states = {row["state"] for row in current}
    if "unsafe" in states or "unreadable" in states:
        return "unsafe"
    if "drift" in states:
        return "drift"
    if "missing" in states:
        return "interrupted" if marker_present else "create"
    return "interrupted" if marker_present else "noop"


def _load_transaction(root_fd: int) -> dict[str, Any] | None:
    info = _inspect_file(root_fd, TRANSACTION_FILE)
    if info["state"] == "missing":
        return None
    if info["state"] != "present":
        raise ContractError("TRANSACTION_UNSAFE", "Instance transaction marker is unavailable")
    try:
        transaction = json.loads(info["data"].decode("utf-8"))
    except (UnicodeError, ValueError):
        raise ContractError("TRANSACTION_SCHEMA", "Instance transaction marker is invalid") from None
    table(transaction, {"schema", "operation", "desired_state_sha256", "state", "files",
                        "pending_consumer_id", "pending_path"},
          "instance transaction", required={"schema", "operation", "desired_state_sha256", "state", "files"})
    if (transaction["schema"] != SCHEMA_TRANSACTION or type(transaction["operation"]) is not str
            or transaction["operation"] not in {"init", "register"}):
        raise ContractError("TRANSACTION_SCHEMA", "Unsupported instance transaction")
    _validate_sha(transaction["desired_state_sha256"], "transaction.desired_state_sha256")
    if type(transaction["state"]) is not str or transaction["state"] not in {"prepared", "committing"}:
        raise ContractError("TRANSACTION_SCHEMA", "Unsupported transaction state")
    has_consumer_id = "pending_consumer_id" in transaction
    has_pending_path = "pending_path" in transaction
    if transaction["operation"] == "register":
        if not has_consumer_id or not has_pending_path:
            raise ContractError("TRANSACTION_SCHEMA", "Register transaction target is missing")
        pending_consumer_id = transaction["pending_consumer_id"]
        pending_path = transaction["pending_path"]
        if type(pending_consumer_id) is not str or type(pending_path) is not str:
            raise ContractError("TRANSACTION_SCHEMA", "Register transaction target is invalid")
        validate_slug(pending_consumer_id, "transaction.pending_consumer_id")
        if pending_path != _registration_path(pending_consumer_id):
            raise ContractError("TRANSACTION_SCHEMA", "Register transaction path disagrees")
    elif has_consumer_id or has_pending_path:
        raise ContractError("TRANSACTION_SCHEMA", "Init transaction cannot have a consumer target")
    files = typed(transaction["files"], list, "instance transaction files")
    for row in files:
        table(row, {"path", "sha256", "status"}, "instance transaction file",
              required={"path", "sha256", "status"})
        validate_safe_relative_posix_path(row["path"])
        _validate_sha(row["sha256"], "transaction file.sha256")
        if row["status"] != "pending":
            raise ContractError("TRANSACTION_SCHEMA", "Unsupported transaction file state")
    return transaction


def _transaction_matches(transaction: Mapping[str, Any], desired_state: bytes,
                         desired: list[dict[str, Any]], operation: str,
                         *, pending_consumer_id: str | None = None) -> bool:
    if transaction["operation"] != operation:
        return False
    if operation == "register":
        if pending_consumer_id is None:
            return False
        if (transaction.get("pending_consumer_id") != pending_consumer_id
                or transaction.get("pending_path") != _registration_path(pending_consumer_id)):
            return False
    elif transaction.get("pending_consumer_id") is not None or transaction.get("pending_path") is not None:
        return False
    return (transaction["desired_state_sha256"] == _sha256(desired_state)
            and transaction["files"] == [
        {"path": row["path"], "sha256": row["sha256"], "status": "pending"} for row in desired
    ])


def _state_matches_transaction_window(
    marker: Mapping[str, Any] | None,
    state_info: Mapping[str, Any],
    *,
    manifest_bytes: bytes,
    template: Mapping[str, Any],
    desired: list[dict[str, Any]],
    registrations: Mapping[str, tuple[Mapping[str, Any], bytes]],
) -> bool:
    """Recognize the durable state window between a file link and state replace.

    A register transaction links its registration before replacing
    ``desired.json``.  During that window the registration set describes the
    *pending* desired state while the state file still describes the prior
    set.  The marker's exact pending consumer is the authority for accepting
    that one expected predecessor state; arbitrary state bytes remain drift.
    """

    if marker is None:
        return False
    desired_state = _render_state(manifest_bytes, template["sha256"], desired)
    pending_consumer_id = marker.get("pending_consumer_id")
    if not _transaction_matches(marker, desired_state, desired, marker["operation"],
                                pending_consumer_id=pending_consumer_id):
        return False
    if state_info["state"] == "present":
        if state_info["mode"] == 0o644 and state_info["sha256"] == _sha256(desired_state):
            return True
        if marker["operation"] != "register" or state_info["mode"] != 0o644:
            return False
        if pending_consumer_id is None or pending_consumer_id not in registrations:
            return False
        previous = dict(registrations)
        del previous[pending_consumer_id]
        previous_desired = _desired_files(manifest_bytes, template, previous)
        previous_state = _render_state(manifest_bytes, template["sha256"], previous_desired)
        if state_info["sha256"] == _sha256(previous_state):
            return True
    return state_info["state"] == "missing"


def _commit(root: Path, desired: list[dict[str, Any]], contents: Mapping[str, bytes], state_bytes: bytes,
            *, allow_state_replace: bool, operation: str,
            expected_predecessor_sha256: str | None = None,
            pending_consumer_id: str | None = None) -> str:
    root_fd = _open_root(root)
    try:
        current = _current_files(root_fd, desired)
        marker = _load_transaction(root_fd)
        current_states = {row["path"]: row["state"] for row in current}
        state_info = _inspect_file(root_fd, STATE_FILE)
    except BaseException:
        # These reads happen before the staging cleanup guard is installed.
        os.close(root_fd)
        raise
    if (marker is None and all(state == "exact" for state in current_states.values())
            and state_info["state"] == "present" and state_info["sha256"] == _sha256(state_bytes)
            and state_info["mode"] == 0o644):
        os.close(root_fd)
        return "noop"
    try:
        stage = Path(tempfile.mkdtemp(prefix=".rs9-instance-stage-", dir=str(root)))
    except OSError:
        os.close(root_fd)
        raise ContractError("OUTPUT_CONFINEMENT", "Private staging directory cannot be created") from None
    try:
        stage_files = {path: _write_stage_file(stage, path, data, mode=0o644) for path, data in contents.items()}
        stage_state = _write_stage_file(stage, STATE_FILE, state_bytes, mode=0o644)
        if "unsafe" in current_states.values() or "unreadable" in current_states.values():
            return "unsafe"
        if "drift" in current_states.values():
            return "drift"
        if marker is not None and not _transaction_matches(
                marker, state_bytes, desired, operation, pending_consumer_id=pending_consumer_id):
            return "interrupted"
        if marker is None:
            marker_bytes = _render_transaction(
                state_bytes, desired, operation=operation, pending_consumer_id=pending_consumer_id)
            marker_stage = _write_stage_file(stage, TRANSACTION_FILE, marker_bytes, mode=0o600)
            marker_result = _link_new(root_fd, marker_stage, TRANSACTION_FILE)
            if marker_result == "exists":
                marker = _load_transaction(root_fd)
                if (marker is None or not _transaction_matches(
                        marker, state_bytes, desired, operation, pending_consumer_id=pending_consumer_id)):
                    return "interrupted"
        else:
            # Existing transactions are intentionally resumed without changing
            # their desired identity.
            pass
        for row in desired:
            if current_states[row["path"]] == "exact":
                continue
            stage_file = stage_files.get(row["path"])
            if stage_file is None:
                # A marker may describe files whose bytes are no longer
                # available to this invocation.  Keep that an explicit
                # resumable outcome rather than leaking a KeyError.
                return "interrupted"
            result = _link_new(root_fd, stage_file, row["path"])
            if result == "exists":
                observed = _inspect_file(root_fd, row["path"])
                if (observed["state"] != "present" or observed["sha256"] != row["sha256"]
                        or observed["mode"] != row["mode"]):
                    return "drift"
        state_info = _inspect_file(root_fd, STATE_FILE)
        if (state_info["state"] == "present" and state_info["sha256"] == _sha256(state_bytes)
                and state_info["mode"] == 0o644):
            pass
        elif state_info["state"] == "missing":
            if allow_state_replace and expected_predecessor_sha256 is not None:
                return "drift"
            if _link_new(root_fd, stage_state, STATE_FILE) == "exists":
                observed = _inspect_file(root_fd, STATE_FILE)
                if (observed["state"] != "present" or observed["sha256"] != _sha256(state_bytes)
                        or observed["mode"] != 0o644):
                    return "drift"
        elif allow_state_replace and state_info["state"] == "present":
            if expected_predecessor_sha256 is None:
                return "drift"
            result = _atomic_replace_control(
                root, stage_state, STATE_FILE, expected_predecessor_sha256)
            if result not in {"replaced", "created"}:
                return result
        else:
            return "drift"
        verified = _current_files(root_fd, desired)
        verified_states = {row["state"] for row in verified}
        if "unsafe" in verified_states or "unreadable" in verified_states:
            return "unsafe"
        if "drift" in verified_states:
            return "drift"
        if "missing" in verified_states:
            return "interrupted"
        verified_state = _inspect_file(root_fd, STATE_FILE)
        if (verified_state["state"] != "present"
                or verified_state["sha256"] != _sha256(state_bytes)
                or verified_state["mode"] != 0o644):
            return "interrupted"
        _unlink_marker(root_fd)
        return "created"
    finally:
        os.close(root_fd)
        shutil.rmtree(stage, ignore_errors=True)


def _instance_result(*, operation: str, manifest: Mapping[str, Any], outcome: str,
                     files: list[dict[str, Any]], extra: Mapping[str, Any] | None = None) -> Record:
    result: dict[str, Any] = {
        "schema": "rs9.instance-result.v1alpha1",
        "operation": operation,
        "instance_id": manifest["instance_id"],
        "engine": manifest["engine"],
        "template": manifest["template"],
        "adapter": manifest["adapter"],
        "outcome": outcome,
        "files": files,
        "remoteState": "unknown",
        "publicationAuthority": False,
        "qualified": False,
        "publicationEnabled": False,
    }
    if extra:
        result.update(extra)
    return Record(snapshot(result))


def _pending_transaction_record(marker: Mapping[str, Any] | None) -> dict[str, Any] | None:
    """Return only safe, relative transaction target information for results."""

    if marker is None:
        return None
    pending: dict[str, Any] = {"operation": marker["operation"]}
    if marker["operation"] == "register":
        pending.update({
            "consumer_id": marker["pending_consumer_id"],
            "path": marker["pending_path"],
        })
    return pending


def _resolve_engine_version(engine_version: str | None, version_provider: Callable[[], str] | None) -> str:
    if engine_version is not None and version_provider is not None:
        raise ContractError("INVALID_CONFIG", "Choose an engine version or provider, not both")
    if engine_version is None:
        if version_provider is None:
            from rs9.cli import distribution_version
            version_provider = distribution_version
        if not callable(version_provider):
            raise ContractError("INVALID_CONFIG", "Engine version provider must be callable")
        try:
            engine_version = version_provider()
        except Exception:  # noqa: BLE001 - version provider is a closed boundary
            raise ContractError("ENGINE_VERSION", "Installed engine version is unavailable") from None
    return _safe_version(engine_version)


def init_instance(
    publisher_root: str | os.PathLike[str],
    *,
    instance_id: str,
    publisher_repository: str,
    publisher_branch: str,
    engine_version: str | None = None,
    version_provider: Callable[[], str] | None = None,
    template_id: str = "github-homebrew-projection",
    template_version: str = "v1alpha1",
    runner: str = "ubuntu-24.04",
    environment: str = "rs9-publish",
    operator_binding: str = "github-actions-oidc",
) -> Record:
    """Create or inspect an inert publisher-root instance configuration."""

    root = _validate_root(publisher_root)
    template = _template(template_id, template_version)
    manifest = _manifest_record(instance_id=instance_id, engine_version=_resolve_engine_version(engine_version, version_provider),
                                template=template, publisher_repository=publisher_repository, publisher_branch=publisher_branch,
                                runner=runner, environment=environment, operator_binding=operator_binding)
    manifest_bytes = _render_manifest(manifest)
    root_fd = _open_root(root)
    try:
        existing_manifest = _inspect_file(root_fd, INSTANCE_FILE)
        if existing_manifest["state"] == "present" and existing_manifest["data"] != manifest_bytes:
            return _instance_result(operation="init", manifest=manifest, outcome="drift", files=[
                {"path": INSTANCE_FILE, "state": "drift", "desired_sha256": _sha256(manifest_bytes),
                 "observed_sha256": existing_manifest["sha256"]}
            ])
        registrations = _list_registrations(root_fd)
        desired = _desired_files(manifest_bytes, template, registrations)
        state_bytes = _render_state(manifest_bytes, template["sha256"], desired)
        current = _current_files(root_fd, desired)
        marker = _load_transaction(root_fd)
        outcome = _local_outcome(current, marker is not None)
        state_info = _inspect_file(root_fd, STATE_FILE)
        state_window = _state_matches_transaction_window(
            marker, state_info, manifest_bytes=manifest_bytes, template=template,
            desired=desired, registrations=registrations)
        if state_info["state"] in {"unsafe", "unreadable"}:
            outcome = "unsafe"
        elif (state_info["state"] == "present"
              and (state_info["sha256"] != _sha256(state_bytes) or state_info["mode"] != 0o644)):
            outcome = "interrupted" if state_window else "drift"
        if outcome in {"drift", "unsafe"}:
            return _instance_result(operation="init", manifest=manifest, outcome=outcome, files=current)
    finally:
        os.close(root_fd)
    contents = {INSTANCE_FILE: manifest_bytes}
    contents.update({path: template["resources"][name] for name, (path, _) in SCAFFOLD_OUTPUTS.items()})
    outcome = _commit(root, desired, contents, state_bytes, allow_state_replace=False, operation="init")
    result_fd = _open_root(root)
    try:
        current = _current_files(result_fd, desired)
        final_marker = _load_transaction(result_fd)
    finally:
        os.close(result_fd)
    pending = _pending_transaction_record(final_marker) if outcome == "interrupted" else None
    extra = {"pendingTransaction": pending} if pending is not None else None
    return _instance_result(operation="init", manifest=manifest, outcome=outcome, files=current, extra=extra)


def register_consumer(
    publisher_root: str | os.PathLike[str],
    *,
    consumer_id: str,
    project: str | os.PathLike[str],
    destinations: str | os.PathLike[str],
    destination_id: str,
    package_id: str,
    version_provider: Callable[[], str] | None = None,
) -> Record:
    """Register one validated Homebrew projection consumer locally."""

    root = _validate_root(publisher_root)
    root_fd = _open_root(root)
    try:
        manifest, manifest_bytes = _load_manifest(root, root_fd)
        runtime_version = _resolve_engine_version(None, version_provider)
        if manifest["engine"]["version"] != runtime_version:
            raise ContractError("ENGINE_VERSION_MISMATCH", "Instance engine version does not match runtime")
        template = _template(manifest["template"]["id"], manifest["template"]["version"])
        if manifest["template"]["sha256"] != template["sha256"]:
            raise ContractError("TEMPLATE_MISMATCH", "Pinned instance template differs from installed template")
        consumer = _load_consumer(project, destinations)
        target = consumer["target"]
        if target["destination"] != destination_id or target["package"] != package_id:
            raise ContractError("INSTANCE_TARGET", "Selected consumer target does not match registration")
        registration = {
            "schema": SCHEMA_CONSUMER,
            "id": consumer_id,
            "project_id": consumer["project_id"],
            "repository": consumer["repository"],
            "destination_id": destination_id,
            "package_id": package_id,
            "package_name": target["name"],
            "project_inputs": consumer["project_inputs"],
            "project_inputs_sha256": consumer["project_inputs_sha256"],
            "destinations_sha256": consumer["destinations_sha256"],
        }
        registration_bytes = _render_registration(registration)
        path = _registration_path(consumer_id)
        existing = _inspect_file(root_fd, path)
        if existing["state"] == "present" and existing["data"] != registration_bytes:
            return _instance_result(operation="register", manifest=manifest, outcome="drift", files=[
                {"path": path, "state": "drift", "desired_sha256": _sha256(registration_bytes),
                 "observed_sha256": existing["sha256"]}
            ], extra={"consumer_id": consumer_id})
        registrations = _list_registrations(root_fd)
        old_desired = _desired_files(manifest_bytes, template, registrations)
        old_state_bytes = _render_state(manifest_bytes, template["sha256"], old_desired)
        old_state_info = _inspect_file(root_fd, STATE_FILE)
        marker = _load_transaction(root_fd)
        state_window = _state_matches_transaction_window(
            marker, old_state_info, manifest_bytes=manifest_bytes, template=template,
            desired=old_desired, registrations=registrations)
        if old_state_info["state"] in {"unsafe", "unreadable"}:
            return _instance_result(operation="register", manifest=manifest, outcome="unsafe",
                                    files=_current_files(root_fd, old_desired),
                                    extra={"consumer_id": consumer_id})
        if (old_state_info["state"] == "present"
                and (old_state_info["sha256"] != _sha256(old_state_bytes)
                     or old_state_info["mode"] != 0o644)) and not state_window:
            return _instance_result(operation="register", manifest=manifest, outcome="drift",
                                    files=_current_files(root_fd, old_desired),
                                    extra={"consumer_id": consumer_id})
        predecessor_sha256 = None
        if old_state_info["state"] == "present":
            predecessor_sha256 = _validate_sha(old_state_info["sha256"], "predecessor state")
        registrations[consumer_id] = (registration, registration_bytes)
        desired = _desired_files(manifest_bytes, template, registrations)
        state_bytes = _render_state(manifest_bytes, template["sha256"], desired)
        current = _current_files(root_fd, desired)
        marker = _load_transaction(root_fd)
        outcome = _local_outcome(current, marker is not None)
        if outcome in {"drift", "unsafe"}:
            return _instance_result(operation="register", manifest=manifest, outcome=outcome, files=current,
                                    extra={"consumer_id": consumer_id})
    finally:
        os.close(root_fd)
    contents = {INSTANCE_FILE: manifest_bytes}
    contents.update({path: template["resources"][name] for name, (path, _) in SCAFFOLD_OUTPUTS.items()})
    contents[path] = registration_bytes
    outcome = _commit(
        root, desired, contents, state_bytes, allow_state_replace=True, operation="register",
        expected_predecessor_sha256=predecessor_sha256, pending_consumer_id=consumer_id)
    result_fd = _open_root(root)
    try:
        current = _current_files(result_fd, desired)
        final_marker = _load_transaction(result_fd)
    finally:
        os.close(result_fd)
    pending = _pending_transaction_record(final_marker) if outcome == "interrupted" else None
    extra = {"consumer_id": consumer_id}
    if pending is not None:
        extra["pendingTransaction"] = pending
    return _instance_result(operation="register", manifest=manifest, outcome=outcome, files=current,
                            extra=extra)


def _observation_reason(observation: Mapping[str, Any] | None, evaluated_at: str | None) -> str:
    if observation is None:
        return "not-observed"
    if not isinstance(observation, Mapping):
        raise ContractError("INVALID_OBSERVATION", "Observation must be a mapping")
    if evaluated_at is None:
        return "offline-plan"
    observed_at = observation.get("observed_at")
    try:
        evaluated = parse_rfc3339_utc(evaluated_at)
        observed = parse_rfc3339_utc(observed_at)
    except ContractError:
        return "invalid-observation"
    if observed > evaluated or (evaluated - observed).total_seconds() > MAX_OBSERVATION_AGE_SECONDS:
        return "stale-observation"
    if observation.get("authenticated") is not True or observation.get("transport") != "ok":
        return "untrusted-observation"
    return "remote-readback-requires-authorized-observer"


def plan_instance(
    publisher_root: str | os.PathLike[str],
    *,
    consumer_id: str,
    project: str | os.PathLike[str],
    destinations: str | os.PathLike[str],
    version: str,
    evaluated_at: str | None = None,
    observation: Mapping[str, Any] | None = None,
) -> Record:
    """Return a canonical offline desired-state snapshot with remote unknown."""

    validate_version_string(version)
    if evaluated_at is not None:
        parse_rfc3339_utc(evaluated_at)
    root = _validate_root(publisher_root)
    root_fd = _open_root(root)
    try:
        manifest, manifest_bytes = _load_manifest(root, root_fd)
        template = _template(manifest["template"]["id"], manifest["template"]["version"])
        if manifest["template"]["sha256"] != template["sha256"]:
            raise ContractError("TEMPLATE_MISMATCH", "Pinned instance template differs from installed template")
        registrations = _list_registrations(root_fd)
        if consumer_id not in registrations:
            raise ContractError("MISSING_REQUIRED_FILE", "Consumer registration is missing")
        registration, _ = registrations[consumer_id]
        consumer = _load_consumer(project, destinations, version=version)
        selected_inputs = consumer["project_inputs"]
        if (registration["project_id"] != consumer["project_id"] or registration["repository"] != consumer["repository"]
                or registration["destination_id"] != consumer["target"]["destination"]
                or registration["package_id"] != consumer["target"]["package"]
                or registration["package_name"] != consumer["target"]["name"]
                or registration["project_inputs"] != selected_inputs
                or registration["destinations_sha256"] != consumer["destinations_sha256"]):
            input_state = "drift"
        else:
            input_state = "exact"
        desired = _desired_files(manifest_bytes, template, registrations)
        current = _current_files(root_fd, desired)
        marker = _load_transaction(root_fd)
        local_state = _local_outcome(current, marker is not None)
        state_bytes = _render_state(manifest_bytes, template["sha256"], desired)
        state_info = _inspect_file(root_fd, STATE_FILE)
        state_window = _state_matches_transaction_window(
            marker, state_info, manifest_bytes=manifest_bytes, template=template,
            desired=desired, registrations=registrations)
        if state_info["state"] in {"unsafe", "unreadable"}:
            local_state = "unsafe"
        elif (state_info["state"] == "present"
              and (state_info["sha256"] != _sha256(state_bytes) or state_info["mode"] != 0o644)):
            local_state = "interrupted" if state_window else "drift"
        elif state_info["state"] == "missing" and local_state == "noop":
            local_state = "create"
        normalized = consumer["normalized"]
        target = consumer["target"]
        selected_names = set(selected_inputs) | {"destinations.toml"}
        normalized_for_plan = copy.deepcopy(normalized)
        normalized_targets = [row for row in normalized_for_plan.get("targets", [])
                              if all(row.get(key) == target.get(key)
                                     for key in ("adapter", "mode", "destination", "package", "name"))]
        if len(normalized_targets) != 1:
            raise ContractError("NORMALIZATION_OUTPUT", "Normalized selected target is unavailable")
        normalized_for_plan["targets"] = normalized_targets
        normalized_evidence = dict(normalized_for_plan.get("evidence", {}))
        normalized_evidence["inputs"] = [row for row in normalized_evidence.get("inputs", [])
                                          if row.get("filename") in selected_names]
        normalized_for_plan["evidence"] = normalized_evidence
        embedded_normalized_sha256 = record_sha256(normalized_for_plan)
        result = {
            "schema": SCHEMA_PLAN,
            "instance_id": manifest["instance_id"],
            "consumer_id": consumer_id,
            "engine": manifest["engine"],
            "template": manifest["template"],
            "adapter": {"name": "homebrew", "mode": "projection", "destination": target["destination"],
                         "package": target["package"], "package_name": target["name"]},
            "inputs": {"project": selected_inputs, "destinations_sha256": consumer["destinations_sha256"],
                       "normalized_sha256": embedded_normalized_sha256,
                       "normalized_engine_sha256": consumer["normalized_sha256"],
                       "normalized_engine_sha256_scope": "full-engine-output-including-unselected-inputs"},
            "local": {"state": local_state if input_state == "exact" else "drift", "input_state": input_state,
                      "files": current},
            "remoteState": "unknown",
            "remoteReason": _observation_reason(observation, evaluated_at),
            "publicationAuthority": False,
            "qualified": False,
            "publicationEnabled": False,
            "actions": {"writes": [], "deletes": []},
            "normalizedIntent": normalized_for_plan,
        }
        pending = _pending_transaction_record(marker)
        if pending is not None:
            result["pendingTransaction"] = pending
        return Record(snapshot(result))
    finally:
        os.close(root_fd)


__all__ = ["init_instance", "plan_instance", "register_consumer"]
