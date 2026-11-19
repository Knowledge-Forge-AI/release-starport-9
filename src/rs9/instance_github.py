"""Offline, fake-transport GitHub instance reconciliation.

This prototype intentionally contains no subprocess or network implementation.
It binds a validated local ``rs9.instance`` snapshot to a bounded remote
observation, plans create-only managed-file changes, and drives a caller-owned
transport through Git blob/tree/commit/ref operations.  Existing files are
never replaced and no path is deleted.

The imports from :mod:`rs9.instance` are a deliberately narrow internal
boundary.  The local instance module remains the owner of its v1alpha1
manifest, template, registration, and descriptor-relative state machinery.
"""

from __future__ import annotations

import hashlib
import re
from collections.abc import Mapping
from datetime import datetime, timezone
from typing import Any, Protocol

from rs9 import instance as _instance
from rs9.errors import ContractError
from rs9.security import (
    scan_for_credentials,
    validate_repository,
    validate_safe_relative_posix_path,
    validate_slug,
)


PROTOCOL_ID = "github-instance-transport"
PROTOCOL_VERSION = "v1alpha1"
SCHEMA_OBSERVATION = "rs9.instance-github-observation.v1alpha2"
SCHEMA_PLAN = "rs9.instance-github-plan.v1alpha1"
SCHEMA_RESULT = "rs9.instance-github-result.v1alpha1"

MANAGED_NAMESPACE = ".rs9-instance"
EXPECTED_MODE = "100644"
MAX_MANAGED_PATHS = 64
MAX_NAMESPACE_ENTRIES = 256
MAX_TOTAL_BYTES = 4 * 1024 * 1024
MAX_DIAGNOSTICS = 16
MAX_OBSERVATION_AGE_SECONDS = getattr(_instance, "MAX_OBSERVATION_AGE_SECONDS", 300)
COMMIT_MESSAGE = "RS9 instance managed files"

_HEX40 = re.compile(r"[0-9a-f]{40}")
_HEX64 = re.compile(r"[0-9a-f]{64}")
_MODE = re.compile(r"[0-7]{6}")
_TOKEN = re.compile(r"[a-z][a-z0-9-]{0,63}")


class GitHubInstanceTransport(Protocol):
    """The injected read/write boundary used by this offline prototype."""

    def read_branch(self, repository: str, branch: str) -> Mapping[str, Any]: ...

    def read_file(self, repository: str, path: str, commit: str) -> Mapping[str, Any]: ...

    def read_parent(self, repository: str, path: str, commit: str) -> Mapping[str, Any]: ...

    def read_namespace(self, repository: str, tree: str, prefix: str) -> Mapping[str, Any]: ...

    def create_blob(self, repository: str, data: bytes) -> Any: ...

    def create_tree(self, repository: str, base_tree: str, entries: list[dict[str, str]]) -> Any: ...

    def create_commit(self, repository: str, message: str, tree: str, parent: str) -> Any: ...

    def update_ref(
        self,
        repository: str,
        branch: str,
        commit: str,
        *,
        force: bool = False,
        expected_parent: str | None = None,
    ) -> Any: ...


class _TransportFailure(Exception):
    """Private marker for a failed injected boundary."""


def _record(value: Mapping[str, Any]) -> _instance.Record:
    return _instance.Record(_instance.snapshot(dict(value)))


def _closed(value: Any, allowed: set[str], required: set[str], context: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping) or set(value) - allowed or required - set(value):
        raise ContractError("RECORD_SCHEMA", f"Invalid {context} record")
    return value


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _git_blob_sha(data: bytes) -> str:
    header = b"blob " + str(len(data)).encode("ascii") + b"\0"
    return hashlib.sha1(header + data).hexdigest()


def _validate_sha(value: Any, *, length: int, context: str) -> str:
    pattern = _HEX40 if length == 40 else _HEX64
    if not isinstance(value, str) or pattern.fullmatch(value) is None:
        raise ContractError("INVALID_HASH", f"A lowercase hash is required for {context}")
    return value


def _validate_mode(value: Any, context: str = "mode") -> str:
    if not isinstance(value, str) or _MODE.fullmatch(value) is None:
        raise ContractError("REMOTE_SCHEMA", f"A six-digit Git mode is required for {context}")
    return value


def _validate_timestamp(value: Any) -> str:
    parsed = _instance.parse_rfc3339_utc(value)
    timespec = "microseconds" if isinstance(value, str) and "." in value else "seconds"
    return parsed.isoformat(timespec=timespec).replace("+00:00", "Z")


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def _safe_reason(value: Any) -> str:
    if not isinstance(value, str) or _TOKEN.fullmatch(value) is None:
        raise ContractError("RECORD_SCHEMA", "Diagnostic token is invalid")
    return value


def _diagnostics(rows: Any) -> list[dict[str, str]]:
    if rows is None:
        return []
    if not isinstance(rows, list) or len(rows) > MAX_DIAGNOSTICS:
        raise ContractError("RECORD_LIMIT", "Diagnostic bound exceeded")
    result = []
    for row in rows:
        _closed(row, {"code", "message"}, {"code", "message"}, "diagnostic")
        code = _safe_reason(row["code"])
        message = row["message"]
        if not isinstance(message, str) or not message or len(message) > 256:
            raise ContractError("RECORD_SCHEMA", "Diagnostic message is invalid")
        scan_for_credentials(message)
        result.append({"code": code, "message": message})
    return sorted(result, key=lambda row: (row["code"], row["message"]))


def _validate_protocol(value: Any) -> dict[str, str]:
    _closed(value, {"id", "version"}, {"id", "version"}, "protocol")
    if value["id"] != PROTOCOL_ID or value["version"] != PROTOCOL_VERSION:
        raise ContractError("PROTOCOL_MISMATCH", "Unsupported GitHub instance protocol")
    return {"id": PROTOCOL_ID, "version": PROTOCOL_VERSION}


def _validate_instance_identity(value: Any) -> dict[str, str]:
    _closed(value, {"id", "repository", "branch"}, {"id", "repository", "branch"}, "instance identity")
    validate_slug(value["id"], "instance.id")
    validate_repository(value["repository"])
    if not isinstance(value["branch"], str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._/-]{0,127}", value["branch"]):
        raise ContractError("INVALID_CONFIG", "Invalid GitHub branch")
    if ".." in value["branch"] or value["branch"].endswith(("/", ".")):
        raise ContractError("INVALID_CONFIG", "Invalid GitHub branch")
    scan_for_credentials(value["branch"])
    return {"id": value["id"], "repository": value["repository"], "branch": value["branch"]}


def _validate_local_identity(value: Any) -> dict[str, Any]:
    _closed(
        value,
        {"instance_id", "engine", "template", "adapter", "manifest_sha256", "desired_state_sha256", "registrations", "managed_files"},
        {"instance_id", "engine", "template", "adapter", "manifest_sha256", "desired_state_sha256", "registrations", "managed_files"},
        "local identity",
    )
    validate_slug(value["instance_id"], "local.instance_id")
    _closed(value["engine"], {"distribution", "version"}, {"distribution", "version"}, "engine")
    if value["engine"]["distribution"] != "release-starport-9":
        raise ContractError("INVALID_CONFIG", "Unsupported instance engine")
    if not isinstance(value["engine"]["version"], str) or not value["engine"]["version"]:
        raise ContractError("RECORD_SCHEMA", "Engine version is required")
    _closed(value["template"], {"id", "version", "sha256"}, {"id", "version", "sha256"}, "template")
    validate_slug(value["template"]["id"], "template.id")
    if not isinstance(value["template"]["version"], str) or not value["template"]["version"]:
        raise ContractError("RECORD_SCHEMA", "Template version is required")
    _validate_sha(value["template"]["sha256"], length=64, context="template.sha256")
    _closed(value["adapter"], {"name", "mode"}, {"name", "mode"}, "adapter")
    if value["adapter"] != {"name": "homebrew", "mode": "projection"}:
        raise ContractError("INVALID_CONFIG", "Unsupported instance adapter")
    _validate_sha(value["manifest_sha256"], length=64, context="manifest.sha256")
    _validate_sha(value["desired_state_sha256"], length=64, context="desired-state.sha256")
    registrations = value["registrations"]
    if not isinstance(registrations, Mapping) or len(registrations) > MAX_MANAGED_PATHS:
        raise ContractError("RECORD_LIMIT", "Registration bound exceeded")
    registration_result = {}
    for consumer_id, row in sorted(registrations.items()):
        validate_slug(consumer_id, "registration.id")
        _closed(row, {"sha256", "project_inputs_sha256", "destinations_sha256"},
                {"sha256", "project_inputs_sha256", "destinations_sha256"}, "registration digest")
        registration_result[consumer_id] = {
            "sha256": _validate_sha(row["sha256"], length=64, context="registration.sha256"),
            "project_inputs_sha256": _validate_sha(row["project_inputs_sha256"], length=64, context="project inputs"),
            "destinations_sha256": _validate_sha(row["destinations_sha256"], length=64, context="destinations"),
        }
    managed = value["managed_files"]
    if not isinstance(managed, Mapping) or not managed or len(managed) > MAX_MANAGED_PATHS:
        raise ContractError("RECORD_LIMIT", "Managed path bound exceeded")
    managed_result = {}
    for path, row in sorted(managed.items()):
        validate_safe_relative_posix_path(path, "managed path")
        _closed(row, {"sha256", "mode", "role"}, {"sha256", "mode", "role"}, "managed file")
        managed_result[path] = {
            "sha256": _validate_sha(row["sha256"], length=64, context="managed file"),
            "mode": _validate_mode(row["mode"], "managed file mode"),
            "role": row["role"],
        }
        if not isinstance(row["role"], str) or not row["role"]:
            raise ContractError("RECORD_SCHEMA", "Managed file role is required")
        scan_for_credentials(row["role"])
    return {
        "instance_id": value["instance_id"],
        "engine": dict(value["engine"]),
        "template": dict(value["template"]),
        "adapter": dict(value["adapter"]),
        "manifest_sha256": value["manifest_sha256"],
        "desired_state_sha256": value["desired_state_sha256"],
        "registrations": registration_result,
        "managed_files": managed_result,
    }


def _validate_file_record(value: Any, *, allow_unknown: bool = False) -> dict[str, Any]:
    _closed(value, {"state", "sha256", "git_blob_sha", "type", "mode", "size"},
            {"state", "sha256", "git_blob_sha", "type", "mode", "size"},
            "managed file observation")
    state = value["state"]
    if not isinstance(state, str) or state not in ({"present", "missing"} | ({"unknown"} if allow_unknown else set())):
        raise ContractError("REMOTE_SCHEMA", "Unknown managed file state")
    if state == "missing":
        if value["type"] != "missing" or value["mode"] is not None or value["sha256"] is not None or value["git_blob_sha"] is not None or value["size"] is not None:
            raise ContractError("REMOTE_SCHEMA", "Missing file carries content identity")
        return {"state": "missing", "sha256": None, "git_blob_sha": None, "type": "missing", "mode": None, "size": None}
    if state == "unknown":
        if value["type"] != "unknown" or value["mode"] is not None or value["sha256"] is not None or value["git_blob_sha"] is not None or value["size"] is not None:
            raise ContractError("REMOTE_SCHEMA", "Unknown file carries content identity")
        return {"state": "unknown", "sha256": None, "git_blob_sha": None, "type": "unknown", "mode": None, "size": None}
    _validate_sha(value["sha256"], length=64, context="remote file")
    _validate_sha(value["git_blob_sha"], length=40, context="Git blob")
    if not isinstance(value["type"], str) or value["type"] not in {"blob", "symlink", "tree"}:
        raise ContractError("REMOTE_SCHEMA", "Unknown Git file type")
    _validate_mode(value["mode"], "remote file mode")
    if type(value["size"]) is not int or not 0 <= value["size"] <= _instance.MAX_FILE_BYTES:
        raise ContractError("REMOTE_LIMIT", "Remote file size exceeds bound")
    return {
        "state": "present",
        "sha256": value["sha256"],
        "git_blob_sha": value["git_blob_sha"],
        "type": value["type"],
        "mode": value["mode"],
        "size": value["size"],
    }


def _parent_paths(path: str) -> list[str]:
    """Return every remote directory prefix needed to create ``path``."""

    parts = path.split("/")
    return ["/".join(parts[:index]) for index in range(1, len(parts))]


def _validate_parent_record(value: Any) -> dict[str, Any]:
    _closed(value, {"state", "type", "mode"}, {"state", "type", "mode"}, "managed parent")
    if value["state"] == "absent":
        if value["type"] != "missing" or value["mode"] is not None:
            raise ContractError("REMOTE_SCHEMA", "Absent parent carries content identity")
        return {"state": "absent", "type": "missing", "mode": None}
    if value["state"] != "present" or not isinstance(value["type"], str) or value["type"] not in {"tree", "blob", "symlink"}:
        raise ContractError("REMOTE_SCHEMA", "Unknown managed parent state")
    _validate_mode(value["mode"], "managed parent mode")
    return {"state": "present", "type": value["type"], "mode": value["mode"]}


def _validate_parent_map(value: Any, managed_files: Mapping[str, Any]) -> dict[str, dict[str, Any]]:
    if not isinstance(value, Mapping) or len(value) > MAX_MANAGED_PATHS * 2:
        raise ContractError("REMOTE_LIMIT", "Managed parent bound exceeded")
    expected = {
        parent
        for path, row in managed_files.items()
        if row["state"] == "missing"
        for parent in _parent_paths(path)
    }
    if set(value) != expected:
        raise ContractError("OBSERVATION_BINDING", "Managed parent proof does not match missing paths")
    result: dict[str, dict[str, Any]] = {}
    for path, row in sorted(value.items()):
        validate_safe_relative_posix_path(path, "managed parent path")
        result[path] = _validate_parent_record(row)
    return result


def _validate_namespace(value: Any) -> dict[str, Any] | None:
    if value is None:
        return None
    _closed(value, {"prefix", "state", "entries"}, {"prefix", "state", "entries"}, "namespace inventory")
    if value["prefix"] != MANAGED_NAMESPACE or not isinstance(value["state"], str) or value["state"] not in {"empty", "contains"}:
        raise ContractError("REMOTE_SCHEMA", "Invalid managed namespace inventory")
    entries = value["entries"]
    if not isinstance(entries, list) or len(entries) > MAX_NAMESPACE_ENTRIES:
        raise ContractError("REMOTE_LIMIT", "Namespace entry bound exceeded")
    output = []
    seen = set()
    for entry in entries:
        _closed(entry, {"path", "type", "mode", "sha256"}, {"path", "type", "mode"}, "namespace entry")
        path = entry["path"]
        if not isinstance(path, str):
            raise ContractError("REMOTE_SCHEMA", "Namespace path must be text")
        validate_safe_relative_posix_path(path, "namespace path")
        if path == MANAGED_NAMESPACE or not path.startswith(MANAGED_NAMESPACE + "/") or path in seen:
            raise ContractError("REMOTE_SCHEMA", "Namespace entry is outside the managed namespace")
        seen.add(path)
        if not isinstance(entry["type"], str) or entry["type"] not in {"blob", "symlink", "tree"}:
            raise ContractError("REMOTE_SCHEMA", "Unknown namespace entry type")
        _validate_mode(entry["mode"], "namespace mode")
        row = {"path": path, "type": entry["type"], "mode": entry["mode"]}
        if "sha256" in entry and entry["sha256"] is not None:
            row["sha256"] = _validate_sha(entry["sha256"], length=64, context="namespace entry")
        else:
            row["sha256"] = None
        output.append(row)
    if (value["state"] == "empty") != (not output):
        raise ContractError("REMOTE_SCHEMA", "Namespace state disagrees with entries")
    return {"prefix": MANAGED_NAMESPACE, "state": value["state"], "entries": sorted(output, key=lambda row: row["path"])}


def _validate_observation_shape(value: Any) -> Mapping[str, Any]:
    allowed = {"schema", "protocol", "instance", "local", "observed_at", "transport", "authenticated", "state",
               "commit", "tree", "protected", "managed_files", "parents", "namespace", "bootstrap_requested", "diagnostics"}
    required = allowed
    _closed(value, allowed, required, "GitHub observation")
    if value["schema"] != SCHEMA_OBSERVATION:
        raise ContractError("OBSERVATION_SCHEMA", "Unsupported GitHub observation schema")
    _validate_protocol(value["protocol"])
    _validate_instance_identity(value["instance"])
    local = _validate_local_identity(value["local"])
    _validate_timestamp(value["observed_at"])
    if not isinstance(value["transport"], str) or value["transport"] not in {"ok", "unknown"} or type(value["authenticated"]) is not bool:
        raise ContractError("OBSERVATION_SCHEMA", "Explicit transport and authentication status required")
    if not isinstance(value["state"], str) or value["state"] not in {"observed", "unknown"} or type(value["bootstrap_requested"]) is not bool:
        raise ContractError("OBSERVATION_SCHEMA", "Unknown observation state")
    files = value["managed_files"]
    if not isinstance(files, Mapping) or len(files) > MAX_MANAGED_PATHS:
        raise ContractError("REMOTE_LIMIT", "Managed file observation bound exceeded")
    expected_paths = set(local["managed_files"])
    if set(files) != expected_paths:
        raise ContractError("OBSERVATION_BINDING", "Managed file set does not match local snapshot")
    normalized_files = {}
    for path, row in sorted(files.items()):
        validate_safe_relative_posix_path(path, "managed path")
        normalized_files[path] = _validate_file_record(row, allow_unknown=True)
    parents = _validate_parent_map(value["parents"], normalized_files)
    namespace = _validate_namespace(value["namespace"])
    _diagnostics(value["diagnostics"])
    if value["state"] == "unknown":
        if value["transport"] != "unknown" or value["authenticated"] is not False or value["commit"] is not None or value["tree"] is not None or value["protected"] is not None:
            raise ContractError("OBSERVATION_SCHEMA", "Unknown observation carries remote proof")
        if any(row["state"] != "unknown" for row in normalized_files.values()) or parents:
            raise ContractError("OBSERVATION_SCHEMA", "Unknown observation carries file proof")
    else:
        if value["transport"] != "ok" or value["authenticated"] is not True:
            raise ContractError("OBSERVATION_SCHEMA", "Observed state requires authenticated transport")
        _validate_sha(value["commit"], length=40, context="branch commit")
        _validate_sha(value["tree"], length=40, context="branch tree")
        if type(value["protected"]) is not bool:
            raise ContractError("OBSERVATION_SCHEMA", "Branch protection status is required")
        if any(row["state"] == "unknown" for row in normalized_files.values()):
            raise ContractError("OBSERVATION_SCHEMA", "Observed state carries an unknown file")
    return {
        "schema": SCHEMA_OBSERVATION,
        "protocol": {"id": PROTOCOL_ID, "version": PROTOCOL_VERSION},
        "instance": dict(value["instance"]),
        "local": local,
        "observed_at": value["observed_at"],
        "transport": value["transport"],
        "authenticated": value["authenticated"],
        "state": value["state"],
        "commit": value["commit"],
        "tree": value["tree"],
        "protected": value["protected"],
        "managed_files": normalized_files,
        "parents": parents,
        "namespace": namespace,
        "bootstrap_requested": value["bootstrap_requested"],
        "diagnostics": _diagnostics(value["diagnostics"]),
    }


def validate_observation(value: Mapping[str, Any]) -> _instance.Record:
    """Validate and canonicalize a persisted observation record."""

    normalized = _validate_observation_shape(value)
    return _record(normalized)


def _plan_observation_projection(value: Mapping[str, Any]) -> dict[str, Any]:
    """Reconstruct the observation fields carried by a plan.

    Plan records intentionally retain hashes/statuses rather than a second
    nested observation record.  The projection is the closed canonical input
    for ``observation_sha256``; it excludes the observer's diagnostic prose,
    which is not carried by the plan.
    """

    remote_unknown = value["commit"] is None
    return {
        "schema": SCHEMA_OBSERVATION,
        "protocol": value["protocol"],
        "instance": value["instance"],
        "local": value["local"],
        "observed_at": value["observed_at"],
        "transport": "unknown" if remote_unknown else "ok",
        "authenticated": not remote_unknown,
        "state": "unknown" if remote_unknown else "observed",
        "commit": None if remote_unknown else value["commit"],
        "tree": None if remote_unknown else value["tree"],
        "protected": None if remote_unknown else value["protected"],
        "managed_files": {
            row["path"]: row["observed"] for row in value["files"]
        },
        "parents": value["parents"],
        "namespace": value["namespace"],
        "bootstrap_requested": value["bootstrap"],
        "diagnostics": [],
    }


def _validate_plan_shape(value: Any) -> Mapping[str, Any]:
    allowed = {"schema", "protocol", "instance", "local", "evaluated_at", "observation_sha256", "observed_at",
               "commit", "tree", "protected", "parents", "namespace", "bootstrap", "remoteState", "outcome", "reason", "files", "actions",
               "publicationAuthority", "qualified", "publicationEnabled"}
    _closed(value, allowed, allowed, "GitHub plan")
    if value["schema"] != SCHEMA_PLAN:
        raise ContractError("PLAN_SCHEMA", "Unsupported GitHub instance plan schema")
    _validate_protocol(value["protocol"])
    _validate_instance_identity(value["instance"])
    _validate_local_identity(value["local"])
    _validate_timestamp(value["evaluated_at"])
    _validate_sha(value["observation_sha256"], length=64, context="observation")
    _validate_timestamp(value["observed_at"])
    if value["commit"] is not None:
        _validate_sha(value["commit"], length=40, context="plan commit")
    if value["tree"] is not None:
        _validate_sha(value["tree"], length=40, context="plan tree")
    if type(value["protected"]) is not bool and value["protected"] is not None:
        raise ContractError("PLAN_SCHEMA", "Plan branch protection status is invalid")
    _validate_namespace(value["namespace"])
    if type(value["bootstrap"]) is not bool:
        raise ContractError("PLAN_SCHEMA", "Bootstrap flag is required")
    if value["remoteState"] not in {"unknown", "observed", "drift"}:
        raise ContractError("PLAN_SCHEMA", "Unknown remote plan state")
    if value["outcome"] not in {"unknown", "blocked", "noop", "create", "drift", "bootstrap-required"}:
        raise ContractError("PLAN_SCHEMA", "Unknown remote plan outcome")
    if value["reason"] is not None:
        _safe_reason(value["reason"])
    if value["publicationAuthority"] is not False or value["qualified"] is not False or value["publicationEnabled"] is not False:
        raise ContractError("PLAN_AUTHORITY", "Prototype plan cannot claim publication authority")
    files = value["files"]
    if not isinstance(files, list) or not files or len(files) > MAX_MANAGED_PATHS:
        raise ContractError("PLAN_LIMIT", "Plan file bound exceeded")
    expected_paths = set(value["local"]["managed_files"])
    seen = set()
    for row in files:
        _closed(row, {"path", "role", "desired_sha256", "desired_mode", "observed", "action"},
                {"path", "role", "desired_sha256", "desired_mode", "observed", "action"}, "plan file")
        path = row["path"]
        validate_safe_relative_posix_path(path, "plan path")
        if path in seen:
            raise ContractError("PLAN_SCHEMA", "Duplicate plan path")
        seen.add(path)
        if path not in expected_paths:
            raise ContractError("PLAN_BINDING", "Plan file path is absent from local snapshot")
        local_file = value["local"]["managed_files"][path]
        if row["role"] != local_file["role"]:
            raise ContractError("PLAN_BINDING", "Plan role disagrees with local snapshot")
        if row["desired_sha256"] != local_file["sha256"]:
            raise ContractError("PLAN_BINDING", "Plan desired digest disagrees with local snapshot")
        _validate_sha(row["desired_sha256"], length=64, context="desired file")
        if row["desired_mode"] != EXPECTED_MODE:
            raise ContractError("PLAN_SCHEMA", "Unsupported desired file mode")
        _validate_file_record(row["observed"], allow_unknown=True)
        if row["action"] not in {"noop", "create", "drift", "unknown", "blocked"}:
            raise ContractError("PLAN_SCHEMA", "Unknown managed-file action")
    if seen != expected_paths:
        raise ContractError("PLAN_BINDING", "Plan file set does not match local snapshot")
    observed_files = {row["path"]: row["observed"] for row in files}
    parents = _validate_parent_map(value["parents"], observed_files)
    create_paths = {row["path"] for row in files if row["action"] == "create"}
    for path in create_paths:
        for parent in _parent_paths(path):
            parent_row = parents.get(parent)
            if parent_row is None or (parent_row["state"] == "present" and parent_row["type"] != "tree"):
                raise ContractError("PLAN_BINDING", "Create action lacks absent-or-tree parent proof")
    actions = value["actions"]
    _closed(actions, {"writes", "deletes"}, {"writes", "deletes"}, "plan actions")
    if actions["deletes"] != []:
        raise ContractError("PLAN_AUTHORITY", "Prototype plans cannot delete remote paths")
    if not isinstance(actions["writes"], list) or len(actions["writes"]) > MAX_MANAGED_PATHS:
        raise ContractError("PLAN_LIMIT", "Plan write bound exceeded")
    write_paths = set()
    action_by_path = {row["path"]: row["action"] for row in files}
    for row in files:
        observed = row["observed"]
        action = row["action"]
        if observed["state"] == "unknown":
            allowed_actions = {"unknown"}
        elif observed["state"] == "missing":
            allowed_actions = {"create", "blocked", "drift", "unknown"}
        elif (
            observed["type"] == "blob"
            and observed["mode"] == EXPECTED_MODE
            and observed["sha256"] == row["desired_sha256"]
        ):
            allowed_actions = {"noop", "drift", "unknown"}
        else:
            allowed_actions = {"drift", "blocked", "unknown"}
        if action not in allowed_actions:
            raise ContractError("PLAN_BINDING", "Plan action disagrees with observed path state")
    for row in actions["writes"]:
        _closed(row, {"path", "sha256", "mode"}, {"path", "sha256", "mode"}, "plan write")
        validate_safe_relative_posix_path(row["path"], "plan write path")
        if row["path"] in write_paths or row["path"] not in expected_paths or action_by_path[row["path"]] != "create":
            raise ContractError("PLAN_BINDING", "Plan write set disagrees with file actions")
        write_paths.add(row["path"])
        _validate_sha(row["sha256"], length=64, context="plan write")
        if row["mode"] != EXPECTED_MODE:
            raise ContractError("PLAN_SCHEMA", "Unsupported plan write mode")
        if row["sha256"] != value["local"]["managed_files"][row["path"]]["sha256"]:
            raise ContractError("PLAN_BINDING", "Plan write digest disagrees with local snapshot")
    expected_writes = {row["path"] for row in files if row["action"] == "create"}
    if write_paths != expected_writes:
        raise ContractError("PLAN_BINDING", "Plan write set is incomplete")
    if value["outcome"] in {"noop", "drift", "unknown", "blocked", "bootstrap-required"} and write_paths:
        raise ContractError("PLAN_BINDING", "Non-create plan contains writes")
    projection = _plan_observation_projection(value)
    if _instance.record_sha256(projection) != value["observation_sha256"]:
        raise ContractError("PLAN_BINDING", "Plan observation provenance disagrees with carried observation")
    observation_unknown = value["commit"] is None
    if observation_unknown:
        if value["tree"] is not None or value["protected"] is not None:
            raise ContractError("PLAN_BINDING", "Unknown plan carries remote branch proof")
        if value["namespace"] is not None or value["parents"] or any(row["observed"]["state"] != "unknown" for row in files):
            raise ContractError("PLAN_BINDING", "Unknown plan carries remote path proof")
        if value["remoteState"] != "unknown" or value["outcome"] != "blocked" or value["reason"] != "observation-unknown":
            raise ContractError("PLAN_BINDING", "Unknown plan state is incoherent")
    elif value["remoteState"] == "unknown":
        if value["outcome"] != "blocked" or value["reason"] != "stale-observation":
            raise ContractError("PLAN_BINDING", "Stale plan state is incoherent")
        if any(row["observed"]["state"] == "unknown" for row in files):
            raise ContractError("PLAN_BINDING", "Stale plan carries an unknown path")
        if any(row["action"] != "unknown" for row in files):
            raise ContractError("PLAN_BINDING", "Unknown plan carries actionable path state")
    elif value["remoteState"] == "observed":
        if any(row["observed"]["state"] == "unknown" for row in files):
            raise ContractError("PLAN_BINDING", "Observed plan carries an unknown path")
        if value["outcome"] == "drift":
            raise ContractError("PLAN_BINDING", "Observed plan cannot claim drift outcome")
        if value["outcome"] == "noop" and any(row["action"] != "noop" for row in files):
            raise ContractError("PLAN_BINDING", "No-op plan carries a non-no-op action")
        if value["outcome"] == "create":
            if value["protected"] is not False or not any(row["action"] == "create" for row in files):
                raise ContractError("PLAN_BINDING", "Create plan carries incoherent protection or actions")
            if any(row["action"] not in {"create", "noop"} for row in files):
                raise ContractError("PLAN_BINDING", "Create plan carries a blocking or drift action")
        if value["outcome"] == "bootstrap-required":
            sentinel = next(row for row in files if row["path"] == _instance.INSTANCE_FILE)
            if (value["reason"] != "bootstrap-required" or sentinel["observed"]["state"] != "missing"
                    or any(row["action"] != "unknown" for row in files)):
                raise ContractError("PLAN_BINDING", "Bootstrap-required plan state is incoherent")
        if value["outcome"] == "unknown":
            raise ContractError("PLAN_BINDING", "Observed plan cannot claim unknown outcome")
        if value["outcome"] == "blocked" and value["reason"] not in {
            "protected-branch", "bootstrap-namespace-not-empty"
        }:
            raise ContractError("PLAN_BINDING", "Blocked observed plan reason is incoherent")
        if value["outcome"] == "blocked" and value["reason"] == "protected-branch" and value["protected"] is not True:
            raise ContractError("PLAN_BINDING", "Protected-branch block lacks protection proof")
    elif value["remoteState"] == "drift":
        if any(row["observed"]["state"] == "unknown" for row in files):
            raise ContractError("PLAN_BINDING", "Drift plan carries an unknown path")
        if value["outcome"] != "drift" or not any(row["action"] == "drift" for row in files):
            raise ContractError("PLAN_BINDING", "Drift plan state is incoherent")
    return value


def validate_plan(value: Mapping[str, Any]) -> _instance.Record:
    """Validate and canonicalize a remote plan."""

    return _record(_validate_plan_shape(value))


def _validate_result_shape(value: Any) -> Mapping[str, Any]:
    allowed = {"schema", "protocol", "plan_sha256", "status", "remoteState", "reason", "effects",
               "observation_sha256", "publicationAuthority", "qualified", "publicationEnabled"}
    _closed(value, allowed, allowed, "GitHub result")
    if value["schema"] != SCHEMA_RESULT:
        raise ContractError("RESULT_SCHEMA", "Unsupported GitHub result schema")
    _validate_protocol(value["protocol"])
    _validate_sha(value["plan_sha256"], length=64, context="plan")
    if value["status"] not in {"completed", "pending", "failed", "uncertain"}:
        raise ContractError("RESULT_SCHEMA", "Unknown result status")
    if value["remoteState"] not in {"unknown", "observed", "drift"}:
        raise ContractError("RESULT_SCHEMA", "Unknown result remote state")
    if value["reason"] is not None:
        _safe_reason(value["reason"])
    if value["observation_sha256"] is not None:
        _validate_sha(value["observation_sha256"], length=64, context="result observation")
    if value["publicationAuthority"] is not False or value["qualified"] is not False or value["publicationEnabled"] is not False:
        raise ContractError("RESULT_AUTHORITY", "Prototype result cannot claim publication authority")
    effects = value["effects"]
    if not isinstance(effects, list) or len(effects) > MAX_MANAGED_PATHS * 4 + 8:
        raise ContractError("RESULT_LIMIT", "Result effect bound exceeded")
    for row in effects:
        _closed(row, {"step", "status", "path", "sha1", "basis", "reason"}, {"step", "status"}, "result effect")
        if not isinstance(row["step"], str) or not row["step"] or len(row["step"]) > 160:
            raise ContractError("RESULT_SCHEMA", "Result step is invalid")
        scan_for_credentials(row["step"])
        if row["status"] not in {"completed", "pending", "failed", "uncertain"}:
            raise ContractError("RESULT_SCHEMA", "Unknown effect status")
        if "path" in row:
            validate_safe_relative_posix_path(row["path"], "result path")
        if "sha1" in row:
            _validate_sha(row["sha1"], length=40, context="result object")
        if "basis" in row:
            _safe_reason(row["basis"])
        if "reason" in row:
            _safe_reason(row["reason"])
    return value


def validate_result(value: Mapping[str, Any]) -> _instance.Record:
    """Validate and canonicalize a result snapshot."""

    return _record(_validate_result_shape(value))


def _local_snapshot(publisher_root: str) -> dict[str, Any]:
    root = _instance._validate_root(publisher_root)
    root_fd = _instance._open_root(root)
    try:
        transaction_info = _instance._inspect_file(root_fd, _instance.TRANSACTION_FILE)
        if transaction_info["state"] != "missing":
            raise ContractError("INSTANCE_STATE", "Local instance has a pending or unsafe transaction marker")
        manifest, manifest_bytes = _instance._load_manifest(root, root_fd)
        template = _instance._template(manifest["template"]["id"], manifest["template"]["version"])
        if manifest["template"]["sha256"] != template["sha256"]:
            raise ContractError("TEMPLATE_MISMATCH", "Pinned instance template differs from installed template")
        repository = manifest["hosting"]["publisher_repository"]
        if manifest["hosting"]["scope"] != repository.split("/", 1)[0]:
            raise ContractError("INVALID_CONFIG", "GitHub scope disagrees with repository owner")
        registrations = _instance._list_registrations(root_fd)
        desired = _instance._desired_files(manifest_bytes, template, registrations)
        if not desired or len(desired) > MAX_MANAGED_PATHS:
            raise ContractError("RECORD_LIMIT", "Managed path bound exceeded")
        contents: dict[str, bytes] = { _instance.INSTANCE_FILE: manifest_bytes }
        contents.update({
            path: template["resources"][resource_name]
            for resource_name, (path, _role) in _instance.SCAFFOLD_OUTPUTS.items()
        })
        for consumer_id, (_registration, raw) in registrations.items():
            contents[_instance._registration_path(consumer_id)] = raw
        managed_files: dict[str, dict[str, Any]] = {}
        total = 0
        for row in desired:
            path = row["path"]
            data = contents.get(path)
            if not isinstance(data, bytes) or len(data) > _instance.MAX_FILE_BYTES:
                raise ContractError("RECORD_LIMIT", "Managed file bytes exceed bound")
            total += len(data)
            if total > MAX_TOTAL_BYTES:
                raise ContractError("RECORD_LIMIT", "Managed byte bound exceeded")
            digest = _sha256(data)
            if digest != row["sha256"] or row["mode"] != 0o644:
                raise ContractError("INSTANCE_STATE", "Local managed file snapshot is inconsistent")
            actual = _instance._inspect_file(root_fd, path)
            if (actual["state"] != "present" or actual["sha256"] != digest
                    or actual["mode"] != 0o644):
                raise ContractError("INSTANCE_STATE", "Local managed file snapshot is inconsistent")
            managed_files[path] = {"sha256": digest, "mode": EXPECTED_MODE, "role": row["role"]}
        state_bytes = _instance._render_state(manifest_bytes, template["sha256"], desired)
        state_info = _instance._inspect_file(root_fd, _instance.STATE_FILE)
        if (state_info["state"] != "present" or state_info["sha256"] != _sha256(state_bytes)
                or state_info["mode"] != 0o644):
            raise ContractError("INSTANCE_STATE", "Local desired state is not exact")
        registration_digests = {}
        for consumer_id, (registration, raw) in sorted(registrations.items()):
            registration_digests[consumer_id] = {
                "sha256": _sha256(raw),
                "project_inputs_sha256": registration["project_inputs_sha256"],
                "destinations_sha256": registration["destinations_sha256"],
            }
        identity = {
            "instance_id": manifest["instance_id"],
            "engine": dict(manifest["engine"]),
            "template": dict(manifest["template"]),
            "adapter": dict(manifest["adapter"]),
            "manifest_sha256": _sha256(manifest_bytes),
            "desired_state_sha256": _sha256(state_bytes),
            "registrations": registration_digests,
            "managed_files": managed_files,
        }
        return {
            "root": root,
            "manifest": manifest,
            "identity": _validate_local_identity(identity),
            "desired": desired,
            "contents": contents,
            "repository": repository,
            "branch": manifest["hosting"]["publisher_branch"],
        }
    finally:
        import os
        os.close(root_fd)


def _base_observation(local: Mapping[str, Any], observed_at: str, *, bootstrap: bool) -> dict[str, Any]:
    manifest = local["manifest"]
    return {
        "schema": SCHEMA_OBSERVATION,
        "protocol": {"id": PROTOCOL_ID, "version": PROTOCOL_VERSION},
        "instance": {"id": manifest["instance_id"], "repository": local["repository"], "branch": local["branch"]},
        "local": local["identity"],
        "observed_at": observed_at,
        "transport": "unknown",
        "authenticated": False,
        "state": "unknown",
        "commit": None,
        "tree": None,
        "protected": None,
        "managed_files": {
            path: {"state": "unknown", "sha256": None, "git_blob_sha": None, "type": "unknown", "mode": None, "size": None}
            for path in sorted(local["identity"]["managed_files"])
        },
        "parents": {},
        "namespace": None,
        "bootstrap_requested": bootstrap,
        "diagnostics": [],
    }


def _unknown_observation(local: Mapping[str, Any], observed_at: str, bootstrap: bool, reason: str) -> _instance.Record:
    result = _base_observation(local, observed_at, bootstrap=bootstrap)
    result["diagnostics"] = [{"code": _safe_reason(reason), "message": "Authenticated bounded remote readback is unavailable."}]
    return validate_observation(_record(result))


def _call_read(transport: Any, method_name: str, *args: Any) -> Mapping[str, Any]:
    method = getattr(transport, method_name, None)
    if not callable(method):
        raise _TransportFailure("missing-read-boundary")
    try:
        value = method(*args)
    except Exception as error:  # noqa: BLE001 - injected transport is a closed boundary
        raise _TransportFailure("transport-read-failed") from error
    if not isinstance(value, Mapping):
        raise _TransportFailure("transport-schema-failed")
    return value


def _branch_read(value: Mapping[str, Any]) -> dict[str, Any]:
    status = value.get("status", 200)
    if type(status) is not int or status != 200 or value.get("transport") != "ok" or value.get("authenticated") is not True:
        raise _TransportFailure("branch-read-unknown")
    commit = _validate_sha(value.get("commit"), length=40, context="branch commit")
    tree = _validate_sha(value.get("tree"), length=40, context="branch tree")
    if type(value.get("protected")) is not bool:
        raise _TransportFailure("branch-read-schema")
    return {"commit": commit, "tree": tree, "protected": value["protected"]}


def _file_read(path: str, value: Mapping[str, Any]) -> tuple[dict[str, Any], int]:
    status = value.get("status", 200)
    transport = value.get("transport")
    authenticated = value.get("authenticated")
    if status == 404 and transport == "ok" and authenticated is True:
        return ({"state": "missing", "sha256": None, "git_blob_sha": None, "type": "missing", "mode": None, "size": None}, 0)
    if type(status) is not int or status != 200 or transport != "ok" or authenticated is not True:
        raise _TransportFailure("managed-file-read-unknown")
    if value.get("state", "present") != "present":
        raise _TransportFailure("managed-file-read-schema")
    data = value.get("data")
    if not isinstance(data, bytes) or len(data) > _instance.MAX_FILE_BYTES:
        raise _TransportFailure("managed-file-limit")
    digest = _sha256(data)
    if value.get("sha256", digest) != digest:
        raise _TransportFailure("managed-file-hash")
    blob = _git_blob_sha(data)
    if value.get("git_blob_sha", blob) != blob:
        raise _TransportFailure("managed-file-blob")
    file_type = value.get("type", "blob")
    mode = value.get("mode")
    if not isinstance(file_type, str) or file_type not in {"blob", "symlink", "tree"} or not isinstance(mode, str) or _MODE.fullmatch(mode) is None:
        raise _TransportFailure("managed-file-mode")
    return ({"state": "present", "sha256": digest, "git_blob_sha": blob, "type": file_type, "mode": mode, "size": len(data)}, len(data))


def _parent_read(path: str, value: Mapping[str, Any]) -> dict[str, Any]:
    status = value.get("status", 200)
    transport = value.get("transport")
    authenticated = value.get("authenticated")
    if status == 404 and transport == "ok" and authenticated is True:
        return {"state": "absent", "type": "missing", "mode": None}
    if type(status) is not int or status != 200 or transport != "ok" or authenticated is not True:
        raise _TransportFailure("managed-parent-read-unknown")
    parent_type = value.get("type")
    if not isinstance(parent_type, str) or parent_type not in {"tree", "blob", "symlink"}:
        raise _TransportFailure("managed-parent-read-schema")
    mode = value.get("mode")
    _validate_mode(mode, "managed parent mode")
    return {"state": "present", "type": parent_type, "mode": mode}


def _namespace_read(value: Mapping[str, Any]) -> dict[str, Any]:
    status = value.get("status", 200)
    if type(status) is not int or status != 200 or value.get("transport") != "ok" or value.get("authenticated") is not True:
        raise _TransportFailure("namespace-read-unknown")
    entries = value.get("entries")
    if not isinstance(entries, list) or len(entries) > MAX_NAMESPACE_ENTRIES:
        raise _TransportFailure("namespace-read-limit")
    normalized = []
    for entry in entries:
        if not isinstance(entry, Mapping):
            raise _TransportFailure("namespace-read-schema")
        row = dict(entry)
        try:
            _validate_namespace({"prefix": MANAGED_NAMESPACE, "state": "contains" if entries else "empty", "entries": [row] if entries else []})
        except ContractError as error:
            raise _TransportFailure("namespace-read-schema") from error
        normalized.append(row)
    result = {"prefix": MANAGED_NAMESPACE, "state": "contains" if normalized else "empty", "entries": normalized}
    return _validate_namespace(result) or result


def observe_instance(
    publisher_root: str,
    transport: GitHubInstanceTransport,
    *,
    observed_at: str | None = None,
    bootstrap: bool = False,
) -> _instance.Record:
    """Read a bounded authenticated branch through an injected transport."""

    local = _local_snapshot(publisher_root)
    timestamp = _validate_timestamp(observed_at or _now())
    result = _base_observation(local, timestamp, bootstrap=bootstrap)
    try:
        branch = _branch_read(_call_read(transport, "read_branch", local["repository"], local["branch"]))
        result.update(transport="ok", authenticated=True, state="observed", commit=branch["commit"],
                      tree=branch["tree"], protected=branch["protected"])
        total = 0
        for path in sorted(local["identity"]["managed_files"]):
            row, size = _file_read(path, _call_read(transport, "read_file", local["repository"], path, branch["commit"]))
            result["managed_files"][path] = row
            total += size
            if total > MAX_TOTAL_BYTES:
                raise _TransportFailure("managed-file-limit")
        missing_paths = [
            path for path, row in result["managed_files"].items()
            if row["state"] == "missing"
        ]
        parent_paths = sorted({parent for path in missing_paths for parent in _parent_paths(path)})
        for path in parent_paths:
            result["parents"][path] = _parent_read(
                path,
                _call_read(transport, "read_parent", local["repository"], path, branch["commit"]),
            )
        sentinel = result["managed_files"][_instance.INSTANCE_FILE]
        if bootstrap and sentinel["state"] == "missing":
            result["namespace"] = _namespace_read(_call_read(transport, "read_namespace", local["repository"], branch["tree"], MANAGED_NAMESPACE))
        return validate_observation(_record(result))
    except (_TransportFailure, ContractError) as error:
        reason = error.args[0] if isinstance(error, _TransportFailure) and error.args else "remote-readback-unknown"
        return _unknown_observation(local, timestamp, bootstrap, reason if _TOKEN.fullmatch(reason) else "remote-readback-unknown")


def _observation_binding(observation: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "protocol": observation["protocol"],
        "instance": observation["instance"],
        "local": observation["local"],
        "transport": observation["transport"],
        "authenticated": observation["authenticated"],
        "state": observation["state"],
        "commit": observation["commit"],
        "tree": observation["tree"],
        "protected": observation["protected"],
        "managed_files": observation["managed_files"],
        "parents": observation["parents"],
        "namespace": observation["namespace"],
        "bootstrap_requested": observation["bootstrap_requested"],
    }


def _same_observation(left: Mapping[str, Any], right: Mapping[str, Any]) -> bool:
    return _observation_binding(left) == _observation_binding(right)


def _age_reason(observation: Mapping[str, Any], evaluated_at: str) -> str | None:
    if observation["state"] != "observed":
        return "observation-unknown"
    evaluated = _instance.parse_rfc3339_utc(evaluated_at)
    observed = _instance.parse_rfc3339_utc(observation["observed_at"])
    age = (evaluated - observed).total_seconds()
    if age < 0 or age > MAX_OBSERVATION_AGE_SECONDS:
        return "stale-observation"
    return None


def _file_plan_rows(local: Mapping[str, Any], observation: Mapping[str, Any], actions: Mapping[str, str]) -> list[dict[str, Any]]:
    rows = []
    for path, desired in sorted(local["identity"]["managed_files"].items()):
        rows.append({
            "path": path,
            "role": desired["role"],
            "desired_sha256": desired["sha256"],
            "desired_mode": EXPECTED_MODE,
            "observed": observation["managed_files"][path],
            "action": actions[path],
        })
    return rows


def plan_instance_github(
    publisher_root: str,
    observation: Mapping[str, Any],
    *,
    evaluated_at: str | None = None,
    bootstrap: bool = False,
) -> _instance.Record:
    """Bind a fresh observation to the local managed snapshot without writing."""

    local = _local_snapshot(publisher_root)
    obs = validate_observation(observation)
    expected_instance = {"id": local["manifest"]["instance_id"], "repository": local["repository"], "branch": local["branch"]}
    if obs["instance"] != expected_instance or obs["local"] != local["identity"]:
        raise ContractError("PLAN_BINDING", "Observation does not bind the current local instance")
    if obs["bootstrap_requested"] != bootstrap:
        raise ContractError("BOOTSTRAP_BINDING", "Observation bootstrap mode differs from plan")
    evaluated = _validate_timestamp(evaluated_at or _now())
    reason = _age_reason(obs, evaluated)
    actions = {path: "unknown" for path in local["identity"]["managed_files"]}
    remote_state = "unknown"
    outcome = "blocked"
    if reason is None:
        remote_state = "observed"
        sentinel = obs["managed_files"][_instance.INSTANCE_FILE]
        sentinel_exact = (
            sentinel["state"] == "present" and sentinel["type"] == "blob"
            and sentinel["mode"] == EXPECTED_MODE
            and sentinel["sha256"] == local["identity"]["managed_files"][_instance.INSTANCE_FILE]["sha256"]
        )
        if sentinel["state"] == "missing":
            if not bootstrap:
                outcome, reason = "bootstrap-required", "bootstrap-required"
            elif obs["namespace"] is None or obs["namespace"]["state"] != "empty":
                outcome, reason = "blocked", "bootstrap-namespace-not-empty"
            elif any(row["state"] == "present" and row["type"] == "tree" for row in obs["parents"].values()):
                outcome, reason = "blocked", "bootstrap-namespace-not-empty"
            elif any(row["state"] != "missing" for row in obs["managed_files"].values()):
                actions = {
                    path: "drift" if row["state"] != "missing" else "unknown"
                    for path, row in obs["managed_files"].items()
                }
                outcome, remote_state, reason = "drift", "drift", "bootstrap-path-present"
            else:
                for path in actions:
                    actions[path] = "create"
                outcome = "create"
        elif not sentinel_exact:
            actions[_instance.INSTANCE_FILE] = "drift"
            outcome, remote_state, reason = "drift", "drift", "sentinel-drift"
        elif obs["protected"]:
            for path, row in obs["managed_files"].items():
                desired = local["identity"]["managed_files"][path]
                if row["state"] == "present" and row["sha256"] == desired["sha256"] and row["type"] == "blob" and row["mode"] == EXPECTED_MODE:
                    actions[path] = "noop"
                elif row["state"] == "missing":
                    actions[path] = "blocked"
                else:
                    actions[path] = "drift"
            if any(action == "drift" for action in actions.values()):
                outcome, remote_state, reason = "drift", "drift", "protected-branch-drift"
            elif all(action == "noop" for action in actions.values()):
                outcome = "noop"
            else:
                outcome, reason = "blocked", "protected-branch"
        else:
            for path, row in obs["managed_files"].items():
                desired = local["identity"]["managed_files"][path]
                if row["state"] == "missing":
                    actions[path] = "create"
                elif row["state"] == "present" and row["type"] == "blob" and row["mode"] == EXPECTED_MODE and row["sha256"] == desired["sha256"]:
                    actions[path] = "noop"
                else:
                    actions[path] = "drift"
            if any(action == "drift" for action in actions.values()):
                outcome, remote_state, reason = "drift", "drift", "managed-file-drift"
            elif any(action == "create" for action in actions.values()):
                outcome = "create"
            else:
                outcome = "noop"
    if outcome == "create":
        bad_parent = any(
            obs["parents"][parent]["state"] == "present" and obs["parents"][parent]["type"] != "tree"
            for path, action in actions.items() if action == "create"
            for parent in _parent_paths(path)
        )
        if bad_parent:
            outcome, remote_state, reason = "drift", "drift", "managed-parent-drift"
            actions = {
                path: "drift" if action == "create" else action
                for path, action in actions.items()
            }
    if obs["protected"] and outcome in {"blocked", "noop"}:
        bad_parent = any(
            obs["parents"][parent]["state"] == "present" and obs["parents"][parent]["type"] != "tree"
            for path, row in obs["managed_files"].items() if row["state"] == "missing"
            for parent in _parent_paths(path)
        )
        if bad_parent:
            outcome, remote_state, reason = "drift", "drift", "managed-parent-drift"
            actions = {
                path: "drift" if obs["managed_files"][path]["state"] == "missing" else action
                for path, action in actions.items()
            }
    if obs["protected"] and outcome == "create":
        outcome, reason = "blocked", "protected-branch"
        actions = {
            path: "blocked" if action == "create" else action
            for path, action in actions.items()
        }
    writes = [
        {"path": path, "sha256": local["identity"]["managed_files"][path]["sha256"], "mode": EXPECTED_MODE}
        for path, action in actions.items() if action == "create"
    ]
    plan = {
        "schema": SCHEMA_PLAN,
        "protocol": {"id": PROTOCOL_ID, "version": PROTOCOL_VERSION},
        "instance": expected_instance,
        "local": local["identity"],
        "evaluated_at": evaluated,
        "observation_sha256": _instance.record_sha256({
            "schema": SCHEMA_OBSERVATION,
            "protocol": obs["protocol"],
            "instance": obs["instance"],
            "local": obs["local"],
            "observed_at": obs["observed_at"],
            "transport": obs["transport"],
            "authenticated": obs["authenticated"],
            "state": obs["state"],
            "commit": obs["commit"],
            "tree": obs["tree"],
            "protected": obs["protected"],
            "managed_files": obs["managed_files"],
            "parents": obs["parents"],
            "namespace": obs["namespace"],
            "bootstrap_requested": obs["bootstrap_requested"],
            "diagnostics": [],
        }),
        "observed_at": obs["observed_at"],
        "commit": obs["commit"],
        "tree": obs["tree"],
        "protected": obs["protected"],
        "parents": obs["parents"],
        "namespace": obs["namespace"],
        "bootstrap": bootstrap,
        "remoteState": remote_state,
        "outcome": outcome if reason is None or outcome != "blocked" else outcome,
        "reason": reason,
        "files": _file_plan_rows(local, obs, actions),
        "actions": {"writes": writes, "deletes": []},
        "publicationAuthority": False,
        "qualified": False,
        "publicationEnabled": False,
    }
    return validate_plan(_record(plan))


def _mutation_value(value: Any, key: str, length: int) -> str:
    try:
        if isinstance(value, str):
            return _validate_sha(value, length=length, context=key)
        if isinstance(value, Mapping):
            return _validate_sha(value.get(key) or value.get("sha"), length=length, context=key)
    except ContractError as error:
        raise _TransportFailure("mutation-response-schema") from error
    raise _TransportFailure("mutation-response-schema")


def _call_mutation(transport: Any, method_name: str, *args: Any, **kwargs: Any) -> Any:
    method = getattr(transport, method_name, None)
    if not callable(method):
        raise _TransportFailure("missing-write-boundary")
    try:
        return method(*args, **kwargs)
    except Exception as error:  # noqa: BLE001 - injected transport is a closed boundary
        raise _TransportFailure("transport-write-uncertain") from error


def _effect(step: str, status: str, *, path: str | None = None, sha1: str | None = None,
            basis: str | None = None, reason: str | None = None) -> dict[str, Any]:
    row: dict[str, Any] = {"step": step, "status": status}
    if path is not None:
        row["path"] = path
    if sha1 is not None:
        row["sha1"] = sha1
    if basis is not None:
        row["basis"] = basis
    if reason is not None:
        row["reason"] = reason
    return row


def _result(plan: Mapping[str, Any], *, status: str, remote_state: str, effects: list[dict[str, Any]],
            observation: Mapping[str, Any] | None = None, reason: str | None = None) -> _instance.Record:
    result = {
        "schema": SCHEMA_RESULT,
        "protocol": {"id": PROTOCOL_ID, "version": PROTOCOL_VERSION},
        "plan_sha256": _instance.record_sha256(plan),
        "status": status,
        "remoteState": remote_state,
        "reason": reason,
        "effects": effects,
        "observation_sha256": _instance.record_sha256(observation) if observation is not None else None,
        "publicationAuthority": False,
        "qualified": False,
        "publicationEnabled": False,
    }
    return validate_result(_record(result))


def _remote_exact(local: Mapping[str, Any], observation: Mapping[str, Any]) -> bool:
    if observation["state"] != "observed":
        return False
    for path, desired in local["identity"]["managed_files"].items():
        actual = observation["managed_files"][path]
        if not (actual["state"] == "present" and actual["type"] == "blob" and actual["mode"] == EXPECTED_MODE
                and actual["sha256"] == desired["sha256"]):
            return False
    return True


def _reconcile_after_mutation(
    plan: Mapping[str, Any],
    local: Mapping[str, Any],
    transport: GitHubInstanceTransport,
    effects: list[dict[str, Any]],
    *,
    bootstrap: bool,
    expected_commit: str | None,
    expected_tree: str | None,
    ref_acknowledged: bool = False,
) -> _instance.Record:
    try:
        current = observe_instance(local["root"], transport, observed_at=_now(), bootstrap=bootstrap)
    except ContractError:
        return _result(plan, status="uncertain", remote_state="unknown", effects=effects, reason="reobserve-failed")
    except Exception:  # noqa: BLE001 - post-mutation readback is a fail-closed boundary
        return _result(plan, status="uncertain", remote_state="unknown", effects=effects, reason="reobserve-failed")
    if current["local"] != plan["local"]:
        effects.append(_effect("post-readback", "uncertain", reason="local-state-changed"))
        return _result(plan, status="uncertain", remote_state="unknown", effects=effects, observation=current, reason="local-state-changed")
    if current["state"] == "unknown":
        effects.append(_effect("post-readback", "uncertain", reason="remote-unknown"))
        return _result(plan, status="uncertain", remote_state="unknown", effects=effects, observation=current, reason="remote-unknown")
    old_position = current["commit"] == plan["commit"] and current["tree"] == plan["tree"]
    new_position = (
        expected_commit is not None and expected_tree is not None
        and current["commit"] == expected_commit and current["tree"] == expected_tree
    )
    if old_position:
        # Object creation may have succeeded while the ref stayed at the
        # planned parent.  The objects are then orphan candidates, not proof
        # of remote drift; retain that distinction for safe fresh resumption.
        for path, desired in local["identity"]["managed_files"].items():
            actual = current["managed_files"][path]
            if actual["state"] == "missing":
                effects.append(_effect(
                    "readback",
                    "uncertain" if ref_acknowledged else "pending",
                    path=path,
                    reason="ref-acknowledged-readback-stale" if ref_acknowledged else None,
                ))
            elif actual["state"] == "present" and actual["type"] == "blob" and actual["mode"] == EXPECTED_MODE and actual["sha256"] == desired["sha256"]:
                effects.append(_effect("readback", "completed", path=path, basis="pre-existing"))
            else:
                effects.append(_effect("readback", "uncertain", path=path,
                                       reason="ref-acknowledged-readback-stale" if ref_acknowledged else "ref-not-advanced"))
        if ref_acknowledged:
            effects.append(_effect("post-readback", "uncertain", reason="ref-acknowledged-readback-stale"))
            return _result(plan, status="uncertain", remote_state="observed", effects=effects, observation=current,
                           reason="ref-acknowledged-readback-stale")
        effects.append(_effect("post-readback", "pending", reason="ref-not-advanced"))
        return _result(plan, status="pending", remote_state="observed", effects=effects, observation=current, reason="ref-not-advanced")
    if not new_position:
        effects.append(_effect("post-readback", "failed", reason="remote-changed"))
        return _result(plan, status="failed", remote_state="drift", effects=effects, observation=current, reason="remote-changed")
    if _remote_exact(local, current):
        effects.append(_effect("post-readback", "completed", basis="exact-readback"))
        return _result(plan, status="completed", remote_state="observed", effects=effects, observation=current)
    drift = False
    pending = False
    readback_status = "pending"
    for path, desired in local["identity"]["managed_files"].items():
        actual = current["managed_files"][path]
        if actual["state"] == "missing":
            pending = True
            effects.append(_effect("readback", "pending", path=path))
        elif actual["state"] == "present" and actual["type"] == "blob" and actual["mode"] == EXPECTED_MODE and actual["sha256"] == desired["sha256"]:
            effects.append(_effect("readback", "completed", path=path, basis="exact-readback"))
        else:
            drift = True
            effects.append(_effect("readback", "failed", path=path, reason="managed-file-drift"))
    if drift:
        readback_status = "failed"
    effects.append(_effect("post-readback", readback_status,
                           reason="managed-file-drift" if drift else "partial-remote-state"))
    if drift:
        return _result(plan, status="failed", remote_state="drift", effects=effects, observation=current, reason="managed-file-drift")
    if pending:
        return _result(plan, status="pending", remote_state="observed", effects=effects, observation=current, reason="partial-remote-state")
    return _result(plan, status="uncertain", remote_state="observed", effects=effects, observation=current, reason="remote-readback-incomplete")


def apply_instance_github(
    publisher_root: str,
    plan: Mapping[str, Any],
    transport: GitHubInstanceTransport,
) -> _instance.Record:
    """Apply a create-only plan through a fake/injected Git transport.

    A persisted plan is evidence only. This function reconstructs and verifies
    the current local snapshot and performs a fresh remote observation before
    any object or ref mutation.
    """

    validated_plan = validate_plan(plan)
    local = _local_snapshot(publisher_root)
    if validated_plan["local"] != local["identity"]:
        raise ContractError("PLAN_BINDING", "Current local instance differs from plan")
    if validated_plan["instance"] != {"id": local["manifest"]["instance_id"], "repository": local["repository"], "branch": local["branch"]}:
        raise ContractError("PLAN_BINDING", "Current public instance identity differs from plan")
    if validated_plan["outcome"] not in {"noop", "create"}:
        return _result(validated_plan, status="failed", remote_state=validated_plan["remoteState"],
                       effects=[_effect("precondition", "failed", reason="plan-not-applicable")], reason="plan-not-applicable")
    expected_commit: str | None = None
    expected_tree: str | None = None
    ref_acknowledged = False
    try:
        current = observe_instance(local["root"], transport, observed_at=_now(), bootstrap=validated_plan["bootstrap"])
    except ContractError:
        return _result(validated_plan, status="uncertain", remote_state="unknown",
                       effects=[_effect("precondition", "uncertain", reason="reobserve-failed")], reason="reobserve-failed")
    if current["state"] == "unknown":
        return _result(validated_plan, status="failed", remote_state="unknown",
                       effects=[_effect("precondition", "failed", reason="remote-unknown")], observation=current, reason="remote-unknown")
    expected_observation = {**current, "observed_at": validated_plan["observed_at"],
                                       "commit": validated_plan["commit"], "tree": validated_plan["tree"],
                                       "managed_files": {row["path"]: row["observed"] for row in validated_plan["files"]},
                                       "local": validated_plan["local"], "instance": validated_plan["instance"],
                                       "protocol": validated_plan["protocol"], "transport": "ok", "authenticated": True,
                                       "state": "observed", "protected": validated_plan["protected"],
                                       "parents": validated_plan["parents"],
                                       "namespace": validated_plan["namespace"], "bootstrap_requested": validated_plan["bootstrap"]}
    if not _same_observation(current, expected_observation):
        return _result(validated_plan, status="failed", remote_state="drift",
                       effects=[_effect("precondition", "failed", reason="remote-changed")], observation=current, reason="remote-changed")
    # Recompute the action set from the fresh observation.  A persisted plan
    # is evidence, not authority: tampering a missing row into an existing
    # row must never turn a create-only operation into an overwrite.
    try:
        fresh_plan = plan_instance_github(
            local["root"], current, evaluated_at=_now(), bootstrap=validated_plan["bootstrap"]
        )
    except ContractError:
        return _result(validated_plan, status="failed", remote_state="drift",
                       effects=[_effect("precondition", "failed", reason="plan-recompute-failed")],
                       observation=current, reason="plan-recompute-failed")
    for key in ("instance", "local", "commit", "tree", "protected", "namespace", "bootstrap",
                "remoteState", "outcome", "reason", "files", "actions"):
        if fresh_plan[key] != validated_plan[key]:
            return _result(validated_plan, status="failed", remote_state="drift",
                           effects=[_effect("precondition", "failed", reason="plan-stale")],
                           observation=current, reason="plan-stale")
    if validated_plan["outcome"] == "noop":
        effects = [_effect("noop", "completed", path=row["path"], basis="exact-readback") for row in validated_plan["files"]]
        return _result(validated_plan, status="completed", remote_state="observed", effects=effects, observation=current)
    if current["protected"]:
        return _result(validated_plan, status="failed", remote_state="observed",
                       effects=[_effect("precondition", "failed", reason="protected-branch")], observation=current, reason="protected-branch")
    writes = [row for row in validated_plan["actions"]["writes"]]
    effects: list[dict[str, Any]] = []
    blobs: dict[str, str] = {}
    try:
        for row in writes:
            path = row["path"]
            data = local["contents"][path]
            blob = _mutation_value(_call_mutation(transport, "create_blob", local["repository"], data), "sha", 40)
            if blob != _git_blob_sha(data):
                raise _TransportFailure("mutation-response-identity")
            blobs[path] = blob
            effects.append(_effect("blob", "completed", path=path, sha1=blob))
        entries = [{"path": path, "mode": EXPECTED_MODE, "type": "blob", "sha": blobs[path]} for path in sorted(blobs)]
        tree = _mutation_value(_call_mutation(transport, "create_tree", local["repository"], validated_plan["tree"], entries), "sha", 40)
        expected_tree = tree
        effects.append(_effect("tree", "completed", sha1=tree))
        commit = _mutation_value(_call_mutation(transport, "create_commit", local["repository"], COMMIT_MESSAGE, tree, validated_plan["commit"]), "sha", 40)
        expected_commit = commit
        effects.append(_effect("commit", "completed", sha1=commit))
        ref_result = _call_mutation(transport, "update_ref", local["repository"], local["branch"], commit,
                                    force=False, expected_parent=validated_plan["commit"])
        if not isinstance(ref_result, Mapping) or ref_result.get("ok") is not True:
            raise _TransportFailure("ref-response-schema")
        ref_acknowledged = True
        effects.append(_effect("ref", "completed", sha1=commit, basis="force-false"))
    except _TransportFailure as error:
        effects.append(_effect("mutation", "uncertain", reason=error.args[0] if error.args and _TOKEN.fullmatch(error.args[0]) else "transport-write-uncertain"))
        return _reconcile_after_mutation(validated_plan, local, transport, effects,
                                         bootstrap=validated_plan["bootstrap"], expected_commit=expected_commit,
                                         expected_tree=expected_tree, ref_acknowledged=ref_acknowledged)
    return _reconcile_after_mutation(validated_plan, local, transport, effects,
                                     bootstrap=validated_plan["bootstrap"], expected_commit=expected_commit,
                                     expected_tree=expected_tree, ref_acknowledged=ref_acknowledged)


__all__ = [
    "GitHubInstanceTransport",
    "COMMIT_MESSAGE",
    "EXPECTED_MODE",
    "MANAGED_NAMESPACE",
    "MAX_MANAGED_PATHS",
    "MAX_NAMESPACE_ENTRIES",
    "MAX_TOTAL_BYTES",
    "PROTOCOL_ID",
    "PROTOCOL_VERSION",
    "SCHEMA_OBSERVATION",
    "SCHEMA_PLAN",
    "SCHEMA_RESULT",
    "apply_instance_github",
    "observe_instance",
    "plan_instance_github",
    "validate_observation",
    "validate_plan",
    "validate_result",
]
