"""Unexposed, journaled existing-repository GitHub instance composition.

The accepted rs9.instance_github state machine remains the owner of the
offline plan and create-only policy. This module is the narrow composition
boundary for a future caller that supplies the real read and write transports:
it binds an installed engine identity and reader-owned repository observation,
persists a write-ahead journal before every mutation, and closes only from
exact readback. It intentionally has no CLI, package export, repository
provisioning, publication, or automatic replay path.
"""

from __future__ import annotations

import hashlib
import re
import time
from collections.abc import Mapping
from typing import Any, Protocol

from rs9 import instance as _instance
from rs9 import instance_github as _github
from rs9 import remote_journal
from rs9.errors import ContractError
from rs9.security import scan_for_credentials, validate_repository


SCHEMA_CONFIG = "rs9.instance-github-coordinator-config.v1alpha1"
SCHEMA_RESULT = "rs9.instance-github-coordinator-result.v1alpha1"
_ENGINE_DISTRIBUTION = "release-starport-9"
_POLICY = {
    "managed_namespace": _github.MANAGED_NAMESPACE,
    "transport": f"{_github.PROTOCOL_ID}/{_github.PROTOCOL_VERSION}",
    "journal": remote_journal.SCHEMA,
}
_PERMISSION_FIELDS = ("admin", "maintain", "push", "triage", "pull")
_HEX40 = re.compile(r"[0-9a-f]{40}")
_HEX64 = re.compile(r"[0-9a-f]{64}")
_VERSION = re.compile(r"[A-Za-z0-9][A-Za-z0-9.+-]{0,63}")
_TOKEN = re.compile(r"[a-z][a-z0-9-]{0,63}")
_NODE_ID = re.compile(r"[!-~]{1,256}")
_OPERATION = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,62}[a-z0-9])?")
_ZERO_SHA = "0" * 40


class ReaderPort(Protocol):
    """Read boundary required by the journaled composition."""

    def read_repository_node(self, repository: str) -> Mapping[str, Any]: ...

    def read_branch(self, repository: str, branch: str) -> Mapping[str, Any]: ...

    def read_file(self, repository: str, path: str, commit: str) -> Mapping[str, Any]: ...

    def read_parent(self, repository: str, path: str, commit: str) -> Mapping[str, Any]: ...

    def read_namespace(self, repository: str, tree: str, prefix: str) -> Mapping[str, Any]: ...


class WriterPort(Protocol):
    """Mutation boundary required by the journaled composition."""

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

    def repository_node_binding(self) -> Mapping[str, Any]: ...


def _closed(value: Any, allowed: set[str], required: set[str], code: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping) or set(value) != allowed or required - set(value):
        raise ContractError(code, "Coordinator record shape is invalid")
    return value


def _safe_string(value: Any, pattern: re.Pattern[str], code: str) -> str:
    if not isinstance(value, str) or pattern.fullmatch(value) is None:
        raise ContractError(code, "Coordinator string is invalid")
    scan_for_credentials(value)
    return value


def _sha(value: Any, *, length: int, code: str = "COORDINATOR_SCHEMA", nonzero: bool = False) -> str:
    pattern = _HEX40 if length == 40 else _HEX64
    if not isinstance(value, str) or pattern.fullmatch(value) is None:
        raise ContractError(code, "Coordinator hash is invalid")
    if nonzero and value == _ZERO_SHA:
        raise ContractError("COORDINATOR_ZERO_OID", "A zero Git object ID is forbidden")
    return value


def _validate_installed_engine(value: Any) -> dict[str, str]:
    """Validate a caller-declared engine identity; do not infer installation."""

    row = _closed(value, {"distribution", "version", "artifact_sha256"},
                  {"distribution", "version", "artifact_sha256"}, "COORDINATOR_ENGINE")
    if row["distribution"] != _ENGINE_DISTRIBUTION:
        raise ContractError("COORDINATOR_ENGINE", "Installed engine distribution is unsupported")
    version = _safe_string(row["version"], _VERSION, "COORDINATOR_ENGINE")
    if version == "unreleased":
        raise ContractError("COORDINATOR_ENGINE", "The unreleased engine placeholder is not installed proof")
    artifact_sha256 = _sha(row["artifact_sha256"], length=64, code="COORDINATOR_ENGINE")
    return {
        "distribution": _ENGINE_DISTRIBUTION,
        "version": version,
        "artifact_sha256": artifact_sha256,
    }


def _validate_node_observation(value: Any, repository: str) -> tuple[dict[str, str], str]:
    if not isinstance(value, Mapping):
        raise ContractError("COORDINATOR_NODE", "Repository node observation is invalid")
    if value.get("status") != 200 or value.get("transport") != "ok":
        raise ContractError("COORDINATOR_NODE", "Repository node observation is unavailable")
    if value.get("authenticated") is not True or value.get("permission_proof") != "repository-permissions":
        raise ContractError("COORDINATOR_PERMISSION", "Repository permission proof is unavailable")
    authority = value.get("authority")
    if authority != {"read": True, "write": False, "publication": False}:
        raise ContractError("COORDINATOR_NODE", "Reader authority record is invalid")
    metadata = value.get("repository")
    full_name = metadata.get("full_name") if isinstance(metadata, Mapping) else None
    if not isinstance(full_name, str) or full_name.casefold() != repository.casefold():
        raise ContractError("COORDINATOR_NODE", "Repository node observation identity mismatches")
    permissions = value.get("permissions")
    if (not isinstance(permissions, Mapping)
            or set(permissions) != set(_PERMISSION_FIELDS)
            or any(type(permissions.get(key)) is not bool for key in _PERMISSION_FIELDS)):
        raise ContractError("COORDINATOR_PERMISSION", "Repository permission fields are invalid")
    if not any(permissions[key] for key in ("admin", "maintain", "push")):
        raise ContractError("COORDINATOR_PERMISSION", "Repository write permission proof is unavailable")
    node = _closed(value.get("node"), {"repository", "value", "metadata_sha256"},
                   {"repository", "value", "metadata_sha256"}, "COORDINATOR_NODE")
    node_repository = node["repository"]
    validate_repository(node_repository)
    if node_repository.casefold() != repository.casefold():
        raise ContractError("COORDINATOR_NODE", "Repository node binding mismatches")
    node_value = _safe_string(node["value"], _NODE_ID, "COORDINATOR_NODE")
    metadata_sha256 = _sha(node["metadata_sha256"], length=64, code="COORDINATOR_NODE")
    return {
        "repository": node_repository,
        "value": node_value,
        "metadata_sha256": metadata_sha256,
    }, metadata_sha256


def _call_node(reader: Any, repository: str) -> tuple[dict[str, str], str]:
    method = getattr(reader, "read_repository_node", None)
    if not callable(method):
        raise ContractError("COORDINATOR_NODE", "A reader-owned repository node boundary is required")
    try:
        value = method(repository)
    except ContractError:
        raise
    except Exception:
        raise ContractError("COORDINATOR_NODE", "Repository node read failed") from None
    return _validate_node_observation(value, repository)


def _call_branch_probe(reader: Any, repository: str, branch: str, metadata_sha256: str) -> None:
    """Require a repository-bound, permission-authenticated branch probe."""

    method = getattr(reader, "read_branch", None)
    if not callable(method):
        raise ContractError("COORDINATOR_READ", "A branch read boundary is required")
    try:
        value = method(repository, branch)
    except ContractError:
        raise
    except Exception:
        raise ContractError("COORDINATOR_READ", "Fresh branch read failed") from None
    if not isinstance(value, Mapping) or value.get("status") != 200 or value.get("transport") != "ok":
        raise ContractError("COORDINATOR_READ", "Fresh branch read is unavailable")
    if value.get("authenticated") is not True:
        raise ContractError("COORDINATOR_PERMISSION", "Fresh branch permission proof is unavailable")
    branch_repository = value.get("repository")
    full_name = branch_repository.get("full_name") if isinstance(branch_repository, Mapping) else None
    if not isinstance(full_name, str) or full_name.casefold() != repository.casefold():
        raise ContractError("COORDINATOR_NODE", "Fresh branch repository identity mismatches")
    observed_metadata_sha256 = value.get("metadata_sha256")
    if (not isinstance(observed_metadata_sha256, str)
            or _HEX64.fullmatch(observed_metadata_sha256) is None):
        raise ContractError("COORDINATOR_NODE", "Fresh branch node metadata binding is unavailable")
    if observed_metadata_sha256 != metadata_sha256:
        raise ContractError("COORDINATOR_NODE", "Repository node metadata changed during preflight")


def _config(
    local: Mapping[str, Any],
    installed_engine: Mapping[str, str],
    node_metadata_sha256: str,
) -> dict[str, Any]:
    config = {
        "schema": SCHEMA_CONFIG,
        "repository": local["repository"],
        "branch": local["branch"],
        "bootstrap": False,
        "force": False,
        "engine": dict(installed_engine),
        "template": dict(local["identity"]["template"]),
        "adapter": dict(local["identity"]["adapter"]),
        "policy": dict(_POLICY),
        "local_identity": local["identity"],
        "node_metadata_sha256": node_metadata_sha256,
    }
    _instance.canonical(config, validate=True)
    return config


def _compare_plan(expected: Mapping[str, Any], actual: Mapping[str, Any]) -> bool:
    keys = (
        "instance", "local", "commit", "tree", "protected", "namespace",
        "bootstrap", "remoteState", "outcome", "reason", "files", "actions",
    )
    return all(expected[key] == actual[key] for key in keys)


def _fresh_preflight(
    publisher_root: str,
    plan: Mapping[str, Any],
    reader: ReaderPort,
    installed_engine: Mapping[str, Any],
) -> tuple[dict[str, Any], _instance.Record, dict[str, Any], str, dict[str, str]]:
    validated_plan = _github.validate_plan(plan)
    local = _github._local_snapshot(publisher_root)
    if validated_plan["local"] != local["identity"]:
        raise ContractError("COORDINATOR_PLAN", "Current local instance differs from plan")
    expected_instance = {
        "id": local["manifest"]["instance_id"],
        "repository": local["repository"],
        "branch": local["branch"],
    }
    if validated_plan["instance"] != expected_instance:
        raise ContractError("COORDINATOR_PLAN", "Current instance identity differs from plan")
    if validated_plan["bootstrap"] is not False:
        raise ContractError("COORDINATOR_BOOTSTRAP", "Existing-repository apply forbids bootstrap")
    if validated_plan["outcome"] not in {"create", "noop"}:
        raise ContractError("COORDINATOR_PLAN", "Plan outcome is not applicable")
    if validated_plan["commit"] is None or validated_plan["tree"] is None:
        raise ContractError("COORDINATOR_PLAN", "Existing-repository plan lacks a remote parent")
    _sha(validated_plan["commit"], length=40, code="COORDINATOR_PLAN", nonzero=True)
    _sha(validated_plan["tree"], length=40, code="COORDINATOR_PLAN", nonzero=True)

    engine = _validate_installed_engine(installed_engine)
    if local["identity"]["engine"] != {
        "distribution": engine["distribution"],
        "version": engine["version"],
    }:
        raise ContractError("COORDINATOR_ENGINE", "Installed engine identity differs from the instance")
    node, metadata_sha256 = _call_node(reader, local["repository"])
    _call_branch_probe(reader, local["repository"], local["branch"], metadata_sha256)

    observation = _github.observe_instance(
        publisher_root,
        reader,  # type: ignore[arg-type]
        observed_at=_github._now(),
        bootstrap=False,
    )
    if observation["state"] != "observed" or observation["authenticated"] is not True:
        raise ContractError("COORDINATOR_READ", "Fresh authenticated remote observation is unavailable")
    if observation["instance"] != expected_instance or observation["local"] != local["identity"]:
        raise ContractError("COORDINATOR_READ", "Fresh remote observation is not bound to the instance")
    fresh_plan = _github.plan_instance_github(
        publisher_root,
        observation,
        evaluated_at=_github._now(),
        bootstrap=False,
    )
    if not _compare_plan(validated_plan, fresh_plan):
        raise ContractError("COORDINATOR_PLAN", "Persisted plan is stale")
    config = _config(local, engine, metadata_sha256)
    config_sha256 = _instance.record_sha256(config)
    return local, validated_plan, config, config_sha256, node


def _operation_id(plan_sha256: str, config_sha256: str) -> str:
    material = f"{plan_sha256}\0{config_sha256}\0{time.time_ns()}".encode("ascii")
    return "apply-" + hashlib.sha256(material).hexdigest()[:32]


def _journal_inventory(publisher_root: str) -> list[dict[str, str]]:
    try:
        snapshot = remote_journal.inventory(publisher_root)
    except ContractError:
        raise ContractError("COORDINATOR_JOURNAL", "Remote apply journal inventory is unavailable") from None
    return [
        {"operation_id": row["operation_id"], "phase": row["phase"]}
        for row in snapshot["entries"]
    ]


def _ensure_no_incomplete_journals(publisher_root: str) -> None:
    for row in _journal_inventory(publisher_root):
        if row["phase"] != "completed":
            raise ContractError("COORDINATOR_JOURNAL", "An incomplete remote apply journal requires explicit recovery")


def _sha_from_response(value: Any, context: str) -> str:
    del context
    candidate = value
    if isinstance(value, Mapping):
        candidate = value.get("sha") or value.get("sha1")
    return _sha(candidate, length=40, code="COORDINATOR_RESPONSE", nonzero=True)


def _journal_reason(error: BaseException) -> str:
    code = getattr(error, "code", None)
    if code == "GITHUB_TIMEOUT":
        return "transport-timeout"
    if code in {"GITHUB_RESPONSE", "GITHUB_HASH", "COORDINATOR_RESPONSE",
                "COORDINATOR_BLOB", "COORDINATOR_QUEUE", "COORDINATOR_TREE",
                "COORDINATOR_COMMIT", "COORDINATOR_REF"}:
        return "malformed-response"
    if code == "GITHUB_CAS":
        return "stale-parent"
    if code in {"GITHUB_MUTATION_DISABLED", "GITHUB_NODE_ID"}:
        return "permission-denied"
    if code in {"GITHUB_HTTP", "GITHUB_GRAPHQL", "GITHUB_PROCESS", "GITHUB_EXECUTABLE"}:
        return "transport-lost"
    return "transport-lost"


class _JournaledTransport:
    """Adapter preserving the fake apply state machine and adding journaling."""

    def __init__(
        self,
        reader: ReaderPort,
        writer: WriterPort,
        journal: remote_journal.RemoteApplyJournal,
        plan: Mapping[str, Any],
        local: Mapping[str, Any],
    ) -> None:
        self._reader = reader
        self._writer = writer
        self._journal = journal
        self._blob_queue = [
            dict(row) for row in sorted(plan["actions"]["writes"], key=lambda row: row["path"])
        ]
        self._blob_index = 0
        self._blob_sha_by_path: dict[str, str] = {}

    def read_branch(self, repository: str, branch: str) -> Mapping[str, Any]:
        return self._reader.read_branch(repository, branch)

    def read_file(self, repository: str, path: str, commit: str) -> Mapping[str, Any]:
        return self._reader.read_file(repository, path, commit)

    def read_parent(self, repository: str, path: str, commit: str) -> Mapping[str, Any]:
        return self._reader.read_parent(repository, path, commit)

    def read_namespace(self, repository: str, tree: str, prefix: str) -> Mapping[str, Any]:
        return self._reader.read_namespace(repository, tree, prefix)

    def _begin(self, step: str, *, path: str | None = None, sha1: str | None = None) -> None:
        self._journal.begin_submission(
            step,
            path=path,
            sha1=sha1,
            predecessor_sha256=self._journal.digest,
        )

    def _uncertain(self, step: str, error: BaseException, *, path: str | None = None) -> None:
        reason = _journal_reason(error)
        self._journal.mark_uncertain(
            step,
            path=path,
            reason=reason,
            predecessor_sha256=self._journal.digest,
        )
        raise _github._TransportFailure("transport-write-uncertain") from None

    def create_blob(self, repository: str, data: bytes) -> Any:
        if self._blob_index >= len(self._blob_queue):
            raise ContractError("COORDINATOR_QUEUE", "The mutation supplied more blobs than the bound plan")
        journal_record = self._journal.record
        if repository != journal_record["repository"]:
            raise ContractError("COORDINATOR_BLOB", "Blob repository differs from the journal binding")
        row = self._blob_queue[self._blob_index]
        path = row["path"]
        if hashlib.sha256(data).hexdigest() != row["sha256"]:
            raise ContractError("COORDINATOR_BLOB", "Blob bytes differ from the bound managed path")
        expected = _github._git_blob_sha(data)
        self._begin("blob", path=path, sha1=expected)
        self._blob_index += 1
        try:
            response = self._writer.create_blob(repository, data)
            actual = _sha_from_response(response, "blob")
            if actual != expected:
                raise ContractError("COORDINATOR_RESPONSE", "Blob identity differs from request")
        except Exception as error:  # noqa: BLE001 - closed mutation boundary
            self._uncertain("blob", error, path=path)
        self._journal.acknowledge(
            "blob",
            path=path,
            sha1=expected,
            predecessor_sha256=self._journal.digest,
        )
        self._blob_sha_by_path[path] = expected
        return response

    def create_tree(self, repository: str, base_tree: str, entries: list[dict[str, str]]) -> Any:
        journal_record = self._journal.record
        if repository != journal_record["repository"]:
            raise ContractError("COORDINATOR_TREE", "Tree repository differs from the journal binding")
        if self._blob_index != len(self._blob_queue):
            raise ContractError("COORDINATOR_QUEUE", "Tree submission omitted a bound blob")
        if base_tree != journal_record["expected_tree"]:
            raise ContractError("COORDINATOR_TREE", "Tree base differs from the journal binding")
        expected_entries = [
            {"path": row["path"], "mode": row["mode"], "type": "blob", "sha": self._blob_sha_by_path[row["path"]]}
            for row in self._blob_queue
        ]
        actual_entries: list[dict[str, str]] = []
        for entry in entries:
            if not isinstance(entry, Mapping) or set(entry) != {"path", "mode", "type", "sha"}:
                raise ContractError("COORDINATOR_TREE", "Tree entry shape differs from the bound plan")
            actual_entries.append({key: entry[key] for key in ("path", "mode", "type", "sha")})
        if sorted(actual_entries, key=lambda row: row["path"]) != sorted(expected_entries, key=lambda row: row["path"]):
            raise ContractError("COORDINATOR_TREE", "Tree entries differ from the acknowledged blobs")
        self._begin("tree")
        try:
            response = self._writer.create_tree(repository, base_tree, entries)
            tree = _sha_from_response(response, "tree")
        except Exception as error:  # noqa: BLE001 - closed mutation boundary
            self._uncertain("tree", error)
        self._journal.acknowledge(
            "tree",
            sha1=tree,
            predecessor_sha256=self._journal.digest,
        )
        return response

    def create_commit(self, repository: str, message: str, tree: str, parent: str) -> Any:
        journal_record = self._journal.record
        if repository != journal_record["repository"]:
            raise ContractError("COORDINATOR_COMMIT", "Commit repository differs from the journal binding")
        if tree != journal_record["target_tree"] or parent != journal_record["expected_parent"]:
            raise ContractError("COORDINATOR_COMMIT", "Commit tree or parent differs from the journal binding")
        if message != _github.COMMIT_MESSAGE:
            raise ContractError("COORDINATOR_COMMIT", "Commit message differs from the bound protocol")
        self._begin("commit")
        try:
            response = self._writer.create_commit(repository, message, tree, parent)
            commit = _sha_from_response(response, "commit")
        except Exception as error:  # noqa: BLE001 - closed mutation boundary
            self._uncertain("commit", error)
        self._journal.acknowledge(
            "commit",
            sha1=commit,
            predecessor_sha256=self._journal.digest,
        )
        return response

    def update_ref(
        self,
        repository: str,
        branch: str,
        commit: str,
        *,
        force: bool = False,
        expected_parent: str | None = None,
    ) -> Any:
        journal_record = self._journal.record
        if repository != journal_record["repository"] or branch != journal_record["branch"]:
            raise ContractError("COORDINATOR_REF", "Ref identity differs from the journal binding")
        if type(force) is not bool or force is not False:
            raise ContractError("COORDINATOR_REF", "Force ref updates are forbidden")
        if expected_parent != journal_record["expected_parent"] or commit != journal_record["target_commit"]:
            raise ContractError("COORDINATOR_REF", "Ref parent or commit differs from the journal binding")
        self._begin("ref")
        try:
            response = self._writer.update_ref(
                repository,
                branch,
                commit,
                force=force,
                expected_parent=expected_parent,
            )
            if not isinstance(response, Mapping) or response.get("ok") is not True:
                raise ContractError("COORDINATOR_RESPONSE", "Ref response is invalid")
        except Exception as error:  # noqa: BLE001 - closed mutation boundary
            self._uncertain("ref", error)
        self._journal.acknowledge(
            "ref",
            sha1=commit,
            predecessor_sha256=self._journal.digest,
        )
        return response


def _exact_readback(
    publisher_root: str,
    reader: ReaderPort,
    plan: Mapping[str, Any],
    journal: remote_journal.RemoteApplyJournal,
) -> tuple[bool, str, str | None]:
    try:
        local = _github._local_snapshot(publisher_root)
        if local["identity"] != plan["local"]:
            return False, "local-state-changed", None
        observation = _github.observe_instance(
            publisher_root,
            reader,  # type: ignore[arg-type]
            observed_at=_github._now(),
            bootstrap=False,
        )
    except Exception:
        return False, "readback-failed", None
    observation_sha256 = _instance.record_sha256(observation)
    record = journal.record
    target_commit = record["target_commit"]
    target_tree = record["target_tree"]
    if (observation["state"] != "observed" or observation["authenticated"] is not True
            or target_commit is None or target_tree is None):
        return False, "readback-failed", observation_sha256
    if observation["commit"] != target_commit or observation["tree"] != target_tree:
        return False, "target-not-observed", observation_sha256
    if observation["protected"] != plan["protected"]:
        return False, "remote-policy-changed", observation_sha256
    if not _github._remote_exact(local, observation):
        return False, "managed-file-readback", observation_sha256
    return True, "exact-readback", observation_sha256


def _coordinator_result(
    *,
    operation_id: str | None,
    decision: str,
    base_result: Mapping[str, Any],
    plan_sha256: str,
    config_sha256: str,
    journal: remote_journal.RemoteApplyJournal | None,
    readback: Mapping[str, Any] | None = None,
) -> _instance.Record:
    base = dict(_github.validate_result(base_result))
    journal_view = None
    if journal is not None:
        journal_view = {"phase": journal.record["phase"], "digest": journal.digest}
    result = {
        "schema": SCHEMA_RESULT,
        "operation_id": operation_id,
        "decision": decision,
        "status": _wrapper_status(decision, journal_view),
        "plan_sha256": plan_sha256,
        "config_sha256": config_sha256,
        "journal": journal_view,
        "readback": dict(readback) if readback is not None else None,
        "base_result": base,
        "publicationAuthority": False,
        "qualified": False,
        "publicationEnabled": False,
    }
    _validate_coordinator_result(result)
    _instance.canonical(result, validate=True)
    return _instance.Record(_instance.snapshot(result))


def _wrapper_status(decision: str, journal: Mapping[str, Any] | None) -> str:
    """Derive wrapper status without rewriting the base classification."""

    phase = journal.get("phase") if journal is not None else None
    if decision == "noop" and journal is None:
        return "completed"
    if decision == "completed" and phase == "completed":
        return "completed"
    if decision == "fresh-plan-required" and phase == "prepared":
        return "pending"
    return "uncertain"


def _validate_coordinator_result(value: Mapping[str, Any]) -> Mapping[str, Any]:
    allowed = {
        "schema", "operation_id", "decision", "status", "plan_sha256", "config_sha256",
        "journal", "readback", "base_result", "publicationAuthority", "qualified", "publicationEnabled",
    }
    _closed(value, allowed, allowed, "COORDINATOR_RESULT")
    if value["schema"] != SCHEMA_RESULT:
        raise ContractError("COORDINATOR_RESULT", "Coordinator result schema is unsupported")
    operation_id = value["operation_id"]
    if operation_id is not None:
        _safe_string(operation_id, _OPERATION, "COORDINATOR_OPERATION")
    decision = value["decision"]
    status = value["status"]
    if decision not in {"noop", "completed", "fresh-plan-required", "readback-required", "hold"}:
        raise ContractError("COORDINATOR_RESULT", "Coordinator decision is invalid")
    if status not in {"completed", "pending", "failed", "uncertain"}:
        raise ContractError("COORDINATOR_RESULT", "Coordinator status is invalid")
    _sha(value["plan_sha256"], length=64, code="COORDINATOR_RESULT")
    _sha(value["config_sha256"], length=64, code="COORDINATOR_RESULT")
    if value["publicationAuthority"] is not False or value["qualified"] is not False or value["publicationEnabled"] is not False:
        raise ContractError("COORDINATOR_AUTHORITY", "Coordinator result cannot claim publication authority")
    journal = value["journal"]
    phase = None
    if journal is not None:
        _closed(journal, {"phase", "digest"}, {"phase", "digest"}, "COORDINATOR_RESULT")
        phase = journal["phase"]
        if phase not in {
            "prepared", "blob-submitting", "blob-created", "tree-submitting", "tree-created",
            "commit-submitting", "commit-created", "ref-submitting", "readback-pending",
            "uncertain", "failed", "completed",
        }:
            raise ContractError("COORDINATOR_RESULT", "Coordinator journal phase is invalid")
        _sha(journal["digest"], length=64, code="COORDINATOR_RESULT")
    readback = value["readback"]
    if readback is not None:
        _closed(readback, {"reason", "observation_sha256"}, {"reason", "observation_sha256"}, "COORDINATOR_RESULT")
        _safe_string(readback["reason"], _TOKEN, "COORDINATOR_RESULT")
        if readback["observation_sha256"] is not None:
            _sha(readback["observation_sha256"], length=64, code="COORDINATOR_RESULT")
    if decision == "noop":
        if operation_id is not None or journal is not None or status != "completed":
            raise ContractError("COORDINATOR_RESULT", "Noop result binding is inconsistent")
    elif decision == "completed":
        if operation_id is None or journal is None or phase != "completed" or status != "completed":
            raise ContractError("COORDINATOR_RESULT", "Completed result binding is inconsistent")
    elif decision == "fresh-plan-required":
        if operation_id is None or journal is None or phase != "prepared" or status not in {"pending", "uncertain"}:
            raise ContractError("COORDINATOR_RESULT", "Fresh-plan result binding is inconsistent")
    elif decision == "readback-required":
        if operation_id is None or journal is None or phase != "readback-pending" or status != "uncertain":
            raise ContractError("COORDINATOR_RESULT", "Readback result binding is inconsistent")
    elif decision == "hold":
        if (operation_id is None or journal is None
                or phase in {None, "prepared", "readback-pending", "completed"}
                or status != "uncertain"):
            raise ContractError("COORDINATOR_RESULT", "Held result binding is inconsistent")
    _github.validate_result(value["base_result"])
    return value


def _ensure_writer_binding(writer: Any, node: Mapping[str, str], repository: str) -> None:
    accessor = getattr(writer, "repository_node_binding", None)
    if not callable(accessor):
        raise ContractError("COORDINATOR_WRITER", "Writer lacks a public repository-node binding accessor")
    try:
        binding = accessor()
    except ContractError:
        raise
    except Exception:
        raise ContractError("COORDINATOR_WRITER", "Writer binding read failed") from None
    _closed(binding, {"repository", "node_id", "allow_mutation"},
            {"repository", "node_id", "allow_mutation"}, "COORDINATOR_WRITER")
    if type(binding["allow_mutation"]) is not bool or binding["allow_mutation"] is not True:
        raise ContractError("COORDINATOR_WRITER", "Explicit writer mutation opt-in is required")
    writer_repository = binding["repository"]
    validate_repository(writer_repository)
    writer_node = _safe_string(binding["node_id"], _NODE_ID, "COORDINATOR_NODE")
    if (writer_repository.casefold() != repository.casefold()
            or writer_node != node["value"]):
        raise ContractError("COORDINATOR_NODE", "Writer node binding differs from reader observation")


def apply_existing_repository(
    publisher_root: str,
    plan: Mapping[str, Any],
    *,
    reader: ReaderPort,
    writer: WriterPort,
    installed_engine: Mapping[str, Any],
    operation_id: str | None = None,
) -> _instance.Record:
    """Apply one existing-repository create/no-op plan without replay.

    A noop performs no journal or writer mutation. A create operation writes
    through the existing fake apply state machine via a journaling adapter;
    this preserves its fresh-plan and create-only checks while making every
    object/ref boundary durable before the call.
    """

    local, validated_plan, _config_record, config_sha256, node = _fresh_preflight(
        publisher_root, plan, reader, installed_engine
    )
    plan_sha256 = _instance.record_sha256(validated_plan)
    if validated_plan["outcome"] == "noop":
        base = _github.apply_instance_github(publisher_root, validated_plan, reader)  # type: ignore[arg-type]
        return _coordinator_result(
            operation_id=None,
            decision="noop",
            base_result=base,
            plan_sha256=plan_sha256,
            config_sha256=config_sha256,
            journal=None,
        )

    _ensure_writer_binding(writer, node, local["repository"])
    if not all(callable(getattr(writer, method, None))
               for method in ("create_blob", "create_tree", "create_commit", "update_ref")):
        raise ContractError("COORDINATOR_WRITER", "Writer mutation boundary is incomplete")
    _ensure_no_incomplete_journals(publisher_root)
    operation_id = operation_id or _operation_id(plan_sha256, config_sha256)
    if not isinstance(operation_id, str) or _OPERATION.fullmatch(operation_id) is None:
        raise ContractError("COORDINATOR_OPERATION", "Operation ID is invalid")
    scan_for_credentials(operation_id)
    journal = remote_journal.prepare(
        publisher_root,
        operation_id,
        repository=local["repository"],
        branch=local["branch"],
        plan_sha256=plan_sha256,
        config_sha256=config_sha256,
        expected_parent=_sha(validated_plan["commit"], length=40, code="COORDINATOR_PLAN", nonzero=True),
        expected_tree=_sha(validated_plan["tree"], length=40, code="COORDINATOR_PLAN", nonzero=True),
    )
    transport = _JournaledTransport(reader, writer, journal, validated_plan, local)
    base = _github.apply_instance_github(publisher_root, validated_plan, transport)

    record = journal.record
    if record["phase"] == "readback-pending":
        exact, reason, observation_sha256 = _exact_readback(
            publisher_root, reader, validated_plan, journal
        )
        readback = {"reason": reason, "observation_sha256": observation_sha256}
        if exact:
            try:
                journal.mark_readback_complete(
                    commit=record["target_commit"],
                    tree=record["target_tree"],
                    predecessor_sha256=journal.digest,
                )
            except Exception:
                return _coordinator_result(
                    operation_id=operation_id,
                    decision="readback-required",
                    base_result=base,
                    plan_sha256=plan_sha256,
                    config_sha256=config_sha256,
                    journal=journal,
                    readback=readback,
                )
            return _coordinator_result(
                operation_id=operation_id,
                decision="completed",
                base_result=base,
                plan_sha256=plan_sha256,
                config_sha256=config_sha256,
                journal=journal,
                readback=readback,
            )
        return _coordinator_result(
            operation_id=operation_id,
            decision="readback-required",
            base_result=base,
            plan_sha256=plan_sha256,
            config_sha256=config_sha256,
            journal=journal,
            readback=readback,
        )
    if record["phase"] == "uncertain":
        return _coordinator_result(
            operation_id=operation_id,
            decision="hold",
            base_result=base,
            plan_sha256=plan_sha256,
            config_sha256=config_sha256,
            journal=journal,
        )
    if record["phase"] == "completed":
        return _coordinator_result(
            operation_id=operation_id,
            decision="completed",
            base_result=base,
            plan_sha256=plan_sha256,
            config_sha256=config_sha256,
            journal=journal,
        )
    decision = "fresh-plan-required" if record["phase"] == "prepared" else "hold"
    return _coordinator_result(
        operation_id=operation_id,
        decision=decision,
        base_result=base,
        plan_sha256=plan_sha256,
        config_sha256=config_sha256,
        journal=journal,
    )


__all__ = [
    "SCHEMA_CONFIG",
    "SCHEMA_RESULT",
    "ReaderPort",
    "WriterPort",
    "apply_existing_repository",
]
