"""Thin CLI composition for existing-repository RS9 GitHub operations.

This module owns argument-independent orchestration only.  The reader, writer,
coordinator, journal, and resume modules remain the owners of their respective
protocols.  It never creates repositories, dispatches workflows, publishes, or
replays an uncertain operation.
"""

from __future__ import annotations

import json
import hashlib
import fcntl
import os
import re
import secrets
import shutil
import stat
from collections.abc import Mapping
from pathlib import Path
from typing import Any, Callable

from rs9 import instance_github
from rs9 import instance_github_apply as coordinator
from rs9 import instance_github_resume as resume
from rs9.engine_binding import DIST_NAME, SCHEMA as ENGINE_SCHEMA, verify_engine_wheel
from rs9.errors import ContractError
from rs9.github_reader import GITHUB_HOST, GitHubReadTransport
from rs9.github_writer import GitHubWriteTransport, RepositoryNodeId


SCHEMA_PLAN = "rs9.instance-github-cli-plan.v1alpha1"
SCHEMA_RESULT = "rs9.instance-github-cli-result.v1alpha1"
SCHEMA_RESUME_RESULT = "rs9.instance-github-cli-resume-result.v1alpha1"
SCHEMA_OPERATION_FAILURE = "rs9.instance-github-cli-operation-failure.v1alpha1"
CLI_SCHEMA = "rs9.cli.v1alpha1"
MAX_PLAN_BYTES = 8 * 1024 * 1024
_OPERATION = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,62}[a-z0-9])?")
_HEX64 = re.compile(r"[0-9a-f]{64}")
_VERSION = re.compile(r"[A-Za-z0-9][A-Za-z0-9.+-]{0,63}")


def _mint_operation_id() -> str:
    """Mint one bounded ID before entering the journaled create call."""

    operation_id = "apply-" + secrets.token_hex(16)
    if _OPERATION.fullmatch(operation_id) is None:
        _reject("CLI_OPERATION")
    return operation_id


def _operation_failure_result(operation_id: str) -> dict[str, Any]:
    return {
        "schema": SCHEMA_OPERATION_FAILURE,
        "operation_id": operation_id,
        "reason": "coordinator-call-escaped",
        "publicationAuthority": False,
        "qualified": False,
        "publicationEnabled": False,
    }


class _OperationFailure(ContractError):
    """Closed carrier for a create call that escaped before yielding a result."""

    def __init__(self, operation_id: str) -> None:
        super().__init__("GITHUB_OPERATION", "GitHub operation requires review.")
        self.operation_id = operation_id
        self.result = _operation_failure_result(operation_id)


def _reject(code: str, message: str = "GitHub CLI contract rejected") -> None:
    raise ContractError(code, message)


def _json_bytes(value: Any) -> bytes:
    try:
        return json.dumps(value, ensure_ascii=True, sort_keys=True, indent=2).encode("ascii") + b"\n"
    except (TypeError, ValueError, UnicodeError, RecursionError):
        _reject("CLI_RESULT")


def _strict_pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in items:
        if key in result:
            raise ValueError("duplicate JSON object key")
        result[key] = value
    return result


def _reject_constant(_value: str) -> None:
    raise ValueError("non-finite JSON number")


def _safe_read_json(
    path_value: str | os.PathLike[str],
    *,
    error_code: str = "CLI_PLAN",
) -> Mapping[str, Any]:
    if not isinstance(path_value, (str, os.PathLike)):
        _reject(error_code)
    fd: int | None = None
    try:
        path = Path(os.fspath(path_value))
        before = path.lstat()
        if not stat.S_ISREG(before.st_mode) or stat.S_ISLNK(before.st_mode) or before.st_size > MAX_PLAN_BYTES:
            _reject(error_code)
        fd = os.open(
            os.fspath(path),
            os.O_RDONLY | os.O_NONBLOCK | getattr(os, "O_NOFOLLOW", 0),
        )
        info = os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode)
                or info.st_size > MAX_PLAN_BYTES
                or (info.st_dev, info.st_ino, info.st_size) != (before.st_dev, before.st_ino, before.st_size)):
            _reject(error_code)
        flags = fcntl.fcntl(fd, fcntl.F_GETFL)
        fcntl.fcntl(fd, fcntl.F_SETFL, flags & ~os.O_NONBLOCK)
        chunks: list[bytes] = []
        remaining = info.st_size
        while remaining:
            chunk = os.read(fd, min(1024 * 1024, remaining))
            if not chunk:
                _reject(error_code)
            chunks.append(chunk)
            remaining -= len(chunk)
        raw = b"".join(chunks)
    except ContractError:
        raise
    except (OSError, TypeError, ValueError):
        _reject(error_code)
    finally:
        try:
            if fd is not None:
                os.close(fd)
        except (UnboundLocalError, OSError):
            pass
    if len(raw) != info.st_size:
        _reject(error_code)
    try:
        value = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_strict_pairs,
            parse_constant=_reject_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError, ValueError):
        _reject(error_code)
    if not isinstance(value, Mapping):
        _reject(error_code)
    return value


def _prior_coordinator_result(value: Mapping[str, Any], binding: Mapping[str, Any]) -> dict[str, Any]:
    """Accept only the documented apply-result forms for explicit resume.

    The resume protocol owns the raw coordinator schema.  This adapter also
    accepts the exact successful or closed-error CLI envelope/result emitted
    by this module so a saved apply response can be supplied directly without
    asking callers to edit or extract a private nested object.
    """

    if not isinstance(value, Mapping):
        _reject("RESUME_BASE")
    candidate: Mapping[str, Any] = value
    if value.get("schema") == CLI_SCHEMA:
        if value.get("command") != "instance.github.apply" or not isinstance(value.get("result"), Mapping):
            _reject("RESUME_BASE")
        if value.get("ok") is True:
            if set(value) != {"schema", "command", "ok", "result"}:
                _reject("RESUME_BASE")
        elif value.get("ok") is False:
            if set(value) != {"schema", "command", "ok", "result", "error"}:
                _reject("RESUME_BASE")
            error = value.get("error")
            if (not isinstance(error, Mapping) or set(error) != {"code", "message"}
                    or error.get("code") != "GITHUB_RESULT"
                    or error.get("message") != "GitHub operation requires review."):
                _reject("RESUME_BASE")
        else:
            _reject("RESUME_BASE")
        candidate = value["result"]
    if candidate.get("schema") == SCHEMA_RESULT:
        allowed_result = {
            "schema", "engine", "coordinator", "plan_sha256", "config_sha256",
            "decision", "status", "publicationAuthority", "qualified", "publicationEnabled",
        }
        if set(candidate) != allowed_result:
            _reject("RESUME_BASE")
        if (candidate["publicationAuthority"] is not False
                or candidate["qualified"] is not False
                or candidate["publicationEnabled"] is not False):
            _reject("RESUME_BASE")
        if _engine_view(candidate["engine"]) != _engine_view(binding):
            _reject("ENGINE_ARTIFACT_MISMATCH")
        nested = candidate["coordinator"]
        if not isinstance(nested, Mapping):
            _reject("RESUME_BASE")
        if (candidate["plan_sha256"] != nested.get("plan_sha256")
                or candidate["config_sha256"] != nested.get("config_sha256")
                or candidate["decision"] != nested.get("decision")
                or candidate["status"] != nested.get("status")):
            _reject("RESUME_BASE")
        candidate = nested
    if candidate.get("schema") != coordinator.SCHEMA_RESULT:
        _reject("RESUME_BASE")
    try:
        coordinator._validate_coordinator_result(candidate)
    except ContractError:
        _reject("RESUME_BASE")
    return dict(candidate)


def _validate_output_parent(path_value: str | os.PathLike[str]) -> Path:
    if not isinstance(path_value, (str, os.PathLike)):
        _reject("CLI_OUTPUT")
    absolute = Path(os.path.abspath(os.fspath(path_value)))
    current = absolute.parent
    while True:
        try:
            info = current.lstat()
        except OSError:
            _reject("CLI_OUTPUT")
        if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
            _reject("CLI_OUTPUT")
        if current.parent == current:
            break
        current = current.parent
    return absolute


def _reserve_plan_output(path_value: str | os.PathLike[str]) -> tuple[Path, int, tuple[int, int]]:
    path = _validate_output_parent(path_value)
    try:
        fd = os.open(
            os.fspath(path),
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
            0o600,
        )
    except FileExistsError:
        _reject("CLI_PLAN_EXISTS")
    except (OSError, TypeError, ValueError):
        _reject("CLI_OUTPUT")
    try:
        info = os.fstat(fd)
        return path, fd, (info.st_dev, info.st_ino)
    except OSError:
        try:
            os.close(fd)
        except OSError:
            pass
        _reject("CLI_OUTPUT")


def _fsync_parent(path: Path) -> None:
    parent_fd: int | None = None
    try:
        parent_fd = os.open(
            os.fspath(path.parent),
            os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0),
        )
        os.fsync(parent_fd)
    except OSError:
        pass
    finally:
        if parent_fd is not None:
            try:
                os.close(parent_fd)
            except OSError:
                pass


def _discard_reserved(path: Path, fd: int, identity: tuple[int, int]) -> None:
    if fd >= 0:
        try:
            os.close(fd)
        except OSError:
            pass
    try:
        info = path.lstat()
        if (stat.S_ISREG(info.st_mode)
                and (info.st_dev, info.st_ino) == identity):
            path.unlink()
            _fsync_parent(path)
    except OSError:
        pass


def _write_reserved(path: Path, fd: int, value: Mapping[str, Any]) -> None:
    try:
        raw = _json_bytes(value)
        offset = 0
        while offset < len(raw):
            written = os.write(fd, raw[offset:])
            if written <= 0:
                _reject("CLI_OUTPUT")
            offset += written
        os.fsync(fd)
    except OSError:
        _reject("CLI_OUTPUT")
    finally:
        try:
            os.close(fd)
        except OSError:
            pass


def write_plan_exclusive(path_value: str | os.PathLike[str], value: Mapping[str, Any]) -> None:
    """Write one new private plan without replacing an existing path."""

    path, fd, identity = _reserve_plan_output(path_value)
    try:
        _write_reserved(path, fd, value)
    except BaseException:
        # _write_reserved owns and closes fd, even when serialization fails.
        _discard_reserved(path, -1, identity)
        raise
    _fsync_parent(path)


def _engine_view(binding: Mapping[str, Any]) -> dict[str, Any]:
    full = {"schema", "distribution", "version", "artifact_sha256", "member_binding_sha256", "member_count"}
    full_with_members = full | {"members"}
    view = {"distribution", "version", "artifact_sha256", "member_binding_sha256", "member_count"}
    if not isinstance(binding, Mapping) or set(binding) not in (full, full_with_members, view):
        _reject("ENGINE_ARTIFACT")
    if "schema" in binding and binding["schema"] != ENGINE_SCHEMA:
        _reject("ENGINE_ARTIFACT")
    if binding["distribution"] != DIST_NAME:
        _reject("ENGINE_ARTIFACT")
    if (not isinstance(binding["version"], str)
            or _VERSION.fullmatch(binding["version"]) is None
            or not isinstance(binding["artifact_sha256"], str)
            or not isinstance(binding["member_binding_sha256"], str)
            or _HEX64.fullmatch(binding["artifact_sha256"]) is None
            or _HEX64.fullmatch(binding["member_binding_sha256"]) is None
            or type(binding["member_count"]) is not int
            or not 1 <= binding["member_count"] <= 4096):
        _reject("ENGINE_ARTIFACT")
    return {
        "distribution": binding["distribution"],
        "version": binding["version"],
        "artifact_sha256": binding["artifact_sha256"],
        "member_binding_sha256": binding["member_binding_sha256"],
        "member_count": binding["member_count"],
    }


def _validate_local_engine(plan: Mapping[str, Any], binding: Mapping[str, Any]) -> None:
    local = plan.get("local")
    configured = local.get("engine") if isinstance(local, Mapping) else None
    expected = {"distribution": DIST_NAME, "version": binding["version"]}
    if configured != expected:
        _reject("ENGINE_VERSION_MISMATCH")


def _validate_local_engine_snapshot(publisher_root: str, binding: Mapping[str, Any]) -> None:
    try:
        local = instance_github._local_snapshot(publisher_root)
    except ContractError:
        raise
    except Exception:
        _reject("CLI_INPUT")
    identity = local.get("identity") if isinstance(local, Mapping) else None
    configured = identity.get("engine") if isinstance(identity, Mapping) else None
    expected = {"distribution": DIST_NAME, "version": binding["version"]}
    if configured != expected:
        _reject("ENGINE_VERSION_MISMATCH")


def _wrap_plan(plan: Mapping[str, Any], binding: Mapping[str, Any]) -> dict[str, Any]:
    validated = dict(instance_github.validate_plan(plan))
    _validate_local_engine(validated, binding)
    return {
        "schema": SCHEMA_PLAN,
        "engine": _engine_view(binding),
        "reader": {
            "host": GITHUB_HOST,
            "transport": f"{instance_github.PROTOCOL_ID}/{instance_github.PROTOCOL_VERSION}",
        },
        "plan_sha256": instance_github._instance.record_sha256(validated),
        "plan": validated,
        "publicationAuthority": False,
        "qualified": False,
        "publicationEnabled": False,
    }


def validate_plan_wrapper(value: Mapping[str, Any]) -> dict[str, Any]:
    allowed = {
        "schema", "engine", "reader", "plan_sha256", "plan",
        "publicationAuthority", "qualified", "publicationEnabled",
    }
    if not isinstance(value, Mapping) or set(value) != allowed or value["schema"] != SCHEMA_PLAN:
        _reject("CLI_PLAN")
    engine = _engine_view(value["engine"])
    reader = value["reader"]
    if reader != {
        "host": GITHUB_HOST,
        "transport": f"{instance_github.PROTOCOL_ID}/{instance_github.PROTOCOL_VERSION}",
    }:
        _reject("CLI_PLAN")
    if value["publicationAuthority"] is not False or value["qualified"] is not False \
            or value["publicationEnabled"] is not False:
        _reject("CLI_AUTHORITY")
    plan = dict(instance_github.validate_plan(value["plan"]))
    plan_sha256 = value["plan_sha256"]
    if (not isinstance(plan_sha256, str)
            or plan_sha256 != instance_github._instance.record_sha256(plan)):
        _reject("CLI_PLAN")
    return {
        "schema": SCHEMA_PLAN,
        "engine": engine,
        "reader": dict(reader),
        "plan_sha256": plan_sha256,
        "plan": plan,
        "publicationAuthority": False,
        "qualified": False,
        "publicationEnabled": False,
    }


def _binding_for(path_value: str | os.PathLike[str], supplied: Mapping[str, Any] | None) -> dict[str, Any]:
    if supplied is not None:
        return _engine_view(supplied)
    return _engine_view(verify_engine_wheel(path_value))


def _read_instance_plan(
    publisher_root: str, binding: Mapping[str, Any], reader: Any | None,
) -> dict[str, Any]:
    _validate_local_engine_snapshot(publisher_root, binding)
    observed_at = instance_github._now()
    observation = instance_github.observe_instance(
        publisher_root, reader if reader is not None else GitHubReadTransport(),
        observed_at=observed_at, bootstrap=False,
    )
    return dict(instance_github.plan_instance_github(
        publisher_root, observation, evaluated_at=observed_at, bootstrap=False,
    ))


def plan_instance_github_cli(
    publisher_root: str,
    *,
    engine_wheel: str | os.PathLike[str],
    output: str | os.PathLike[str],
    _reader: Any | None = None,
    _binding: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    binding = _binding_for(engine_wheel, _binding)
    reserved = _reserve_plan_output(output)
    try:
        plan = _read_instance_plan(publisher_root, binding, _reader)
        wrapper = _wrap_plan(plan, binding)
        path, fd, identity = reserved
        try:
            _write_reserved(path, fd, wrapper)
        except BaseException:
            # _write_reserved owns and closes fd, even when serialization fails.
            _discard_reserved(path, -1, identity)
            raise
        _fsync_parent(path)
    except BaseException:
        # The nested write block has already handled descriptor ownership.
        # This outer guard only cleans failures before that hand-off.
        if "path" not in locals():
            _discard_reserved(*reserved)
        raise
    return {
        "schema": SCHEMA_PLAN,
        "outcome": wrapper["plan"]["outcome"],
        "remoteState": wrapper["plan"]["remoteState"],
        "reason": wrapper["plan"]["reason"],
        "plan_sha256": wrapper["plan_sha256"],
        "artifact_sha256": binding["artifact_sha256"],
        "publicationAuthority": False,
        "qualified": False,
        "publicationEnabled": False,
    }


def inspect_homebrew_projection(
    plan: Mapping[str, Any],
    branch: str,
    *,
    _reader: GitHubReadTransport | None = None,
) -> dict[str, Any]:
    """Observe the exact formula for evidence verified by this invocation."""
    from rs9.homebrew_renderer import render_python_wheel_formula
    from rs9.instance import record_sha256

    path, desired, template = render_python_wheel_formula(plan)
    target, = plan["normalizedIntent"]["targets"]
    repository = target.get("repository")
    if not isinstance(repository, str):
        _reject("HOMEBREW_DESTINATION_REPOSITORY", "The registered tap must name its GitHub repository")

    reader = _reader if _reader is not None else GitHubReadTransport()
    initial = reader.read_branch(repository, branch)
    commit, tree = initial["commit"], initial["tree"]
    parent_path = path.rsplit("/", 1)[0]
    parent = reader.read_parent(repository, parent_path, commit)
    remote: dict[str, Any] = {"commit": commit, "tree": tree, "state": "unsafe"}

    def same_snapshot(row: Mapping[str, Any], expected_path: str) -> bool:
        return (
            row.get("path") == expected_path
            and row.get("commit") == commit
            and row.get("tree") == tree
            and row.get("repository") == initial.get("repository")
            and row.get("metadata_sha256") == initial.get("metadata_sha256")
        )

    if not same_snapshot(parent, parent_path):
        _reject("HOMEBREW_OBSERVATION_MISMATCH", "The tap response does not match its branch snapshot")
    if parent["state"] == "absent":
        remote["state"] = "missing"
    elif parent["state"] == "present" and parent["type"] == "tree" and parent["mode"] == "040000":
        entry = reader.read_file(repository, path, commit)
        if not same_snapshot(entry, path):
            _reject("HOMEBREW_OBSERVATION_MISMATCH", "The formula response does not match its branch snapshot")
        if entry["state"] == "missing":
            remote["state"] = "missing"
        elif entry["state"] == "present" and entry["type"] == "blob":
            byte_data = entry.get("data")
            if not isinstance(byte_data, bytes):
                _reject("HOMEBREW_OBSERVATION_MISMATCH", "The formula blob has no verified bytes")
            actual_sha256 = hashlib.sha256(byte_data).hexdigest()
            if entry.get("size") != len(byte_data) or entry.get("sha256") != actual_sha256:
                _reject("HOMEBREW_OBSERVATION_MISMATCH", "The formula blob does not match its verified digest")
            same = entry["mode"] == "100644" and byte_data == desired
            remote.update(
                state="match" if same else "drift",
                mode=entry["mode"],
                sha256=actual_sha256,
                size=len(byte_data),
            )

    latest = reader.read_branch(repository, branch)
    if any(latest.get(key) != initial.get(key) for key in ("commit", "tree", "repository", "metadata_sha256")):
        remote = {"state": "unknown", "reason": "branch-changed"}
    return {
        "schema": "rs9.homebrew-projection-observation.v1alpha1",
        "instanceId": plan["instance_id"],
        "consumerId": plan["consumer_id"],
        "instancePlanSha256": record_sha256(plan),
        "taggedConsumerContractVerified": plan["releaseEvidence"]["taggedConsumerContractVerified"],
        "destination": {"repository": repository, "branch": branch, "path": path},
        "desired": {"sha256": hashlib.sha256(desired).hexdigest(), "size": len(desired),
                    "mode": "100644", "template": template},
        "remote": remote,
        "publicationAuthority": False,
        "publicationEnabled": False,
    }


class _NoMutationWriter:
    """Writer placeholder for a coordinator no-op; every mutation is fatal."""

    def _reject(self) -> None:
        _reject("CLI_WRITER")

    def repository_node_binding(self) -> Mapping[str, Any]:
        self._reject()
        return {}

    def create_blob(self, *args: Any, **kwargs: Any) -> Any:
        self._reject()

    def create_tree(self, *args: Any, **kwargs: Any) -> Any:
        self._reject()

    def create_commit(self, *args: Any, **kwargs: Any) -> Any:
        self._reject()

    def update_ref(self, *args: Any, **kwargs: Any) -> Any:
        self._reject()


def _node_id(reader: Any, repository: str) -> RepositoryNodeId:
    try:
        observed = reader.read_repository_node(repository)
    except ContractError:
        raise
    except Exception:
        _reject("GITHUB_NODE")
    if not isinstance(observed, Mapping) or observed.get("authenticated") is not True:
        _reject("GITHUB_PERMISSION")
    node = observed.get("node")
    if (not isinstance(node, Mapping)
            or not isinstance(node.get("repository"), str)
            or node["repository"].casefold() != repository.casefold()):
        _reject("GITHUB_NODE")
    return RepositoryNodeId(repository, node.get("value"))


def apply_instance_github_cli(
    publisher_root: str,
    *,
    plan_path: str | os.PathLike[str],
    engine_wheel: str | os.PathLike[str],
    operation_id: str | None = None,
    _reader: Any | None = None,
    _binding: Mapping[str, Any] | None = None,
    _writer_factory: Callable[..., Any] | None = None,
) -> dict[str, Any]:
    wrapper = validate_plan_wrapper(_safe_read_json(plan_path))
    binding = _binding_for(engine_wheel, _binding)
    if wrapper["engine"] != _engine_view(binding):
        _reject("ENGINE_ARTIFACT_MISMATCH")
    plan = wrapper["plan"]
    _validate_local_engine(plan, binding)
    if operation_id is not None and (
            not isinstance(operation_id, str) or _OPERATION.fullmatch(operation_id) is None):
        _reject("CLI_OPERATION")
    if plan["outcome"] not in {"create", "noop"}:
        _reject("CLI_PLAN_NOT_APPLICABLE")
    if plan["outcome"] == "create" and operation_id is None:
        operation_id = _mint_operation_id()
    reader = _reader or GitHubReadTransport()
    if plan["outcome"] == "create":
        repository = plan["instance"]["repository"]
        node = _node_id(reader, repository)
        writer = (_writer_factory or GitHubWriteTransport)(
            repository_node_id=node,
            allow_mutation=True,
        )
    else:
        writer = _NoMutationWriter()
    kwargs: dict[str, Any] = {
        "reader": reader,
        "writer": writer,
        "installed_engine": {
            "distribution": DIST_NAME,
            "version": binding["version"],
            "artifact_sha256": binding["artifact_sha256"],
        },
    }
    if operation_id is not None:
        kwargs["operation_id"] = operation_id
    try:
        result = dict(coordinator.apply_existing_repository(publisher_root, plan, **kwargs))
        coordinator._validate_coordinator_result(result)
    except BaseException:
        if plan["outcome"] == "create" and operation_id is not None:
            raise _OperationFailure(operation_id) from None
        raise
    return {
        "schema": SCHEMA_RESULT,
        "engine": _engine_view(binding),
        "coordinator": result,
        "plan_sha256": result["plan_sha256"],
        "config_sha256": result["config_sha256"],
        "decision": result["decision"],
        "status": result["status"],
        "publicationAuthority": False,
        "qualified": False,
        "publicationEnabled": False,
    }


def resume_instance_github_cli(
    publisher_root: str,
    *,
    operation_id: str,
    engine_wheel: str | os.PathLike[str],
    prior_result: str | os.PathLike[str] | None = None,
    _reader: Any | None = None,
    _binding: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    if not isinstance(operation_id, str) or _OPERATION.fullmatch(operation_id) is None:
        _reject("CLI_OPERATION")
    binding = _binding_for(engine_wheel, _binding)
    prior = None if prior_result is None else _prior_coordinator_result(
        _safe_read_json(prior_result, error_code="RESUME_BASE"), binding,
    )
    reader = _reader or GitHubReadTransport()
    result = dict(resume.resume_existing_repository(
        publisher_root,
        operation_id=operation_id,
        reader=reader,
        current_engine={
            "distribution": DIST_NAME,
            "version": binding["version"],
            "artifact_sha256": binding["artifact_sha256"],
        },
        prior_coordinator_result=prior,
    ))
    return {
        "schema": SCHEMA_RESUME_RESULT,
        "engine": _engine_view(binding),
        "resume": result,
        "decision": result["decision"],
        "status": result["status"],
        "publicationAuthority": False,
        "qualified": False,
        "publicationEnabled": False,
    }


def doctor_instance_github_cli(
    *,
    publisher_root: str | None = None,
    engine_wheel: str | os.PathLike[str] | None = None,
    _binding: Mapping[str, Any] | None = None,
    _reader: Any | None = None,
) -> dict[str, Any]:
    binding = None
    if engine_wheel is not None or _binding is not None:
        binding = _binding_for(engine_wheel, _binding)
    report = {
        "schema": "rs9.instance-github-cli-doctor.v1alpha1",
        "engine": binding,
        "gh": {"available": shutil.which("gh") is not None},
        "remote_reads": False,
        "remote_writes": False,
        "auth_inspected": False,
        "publicationAuthority": False,
        "qualified": False,
        "publicationEnabled": False,
    }
    if publisher_root is None:
        return report
    if binding is None:
        _reject("CLI_INPUT", "A bound engine wheel is required for remote observation.")
    plan = _read_instance_plan(publisher_root, binding, _reader)
    return {
        **report,
        "schema": "rs9.instance-github-cli-remote-doctor.v1alpha1",
        "remote_reads": True,
        "instance": plan["instance"],
        "outcome": plan["outcome"],
        "remoteState": plan["remoteState"],
        "reason": plan["reason"],
        "commit": plan["commit"],
        "observedAt": plan["observed_at"],
        "managedFiles": [
            {"path": row["path"], "comparison": row["action"]} for row in plan["files"]
        ],
    }


__all__ = [
    "SCHEMA_PLAN",
    "SCHEMA_RESULT",
    "SCHEMA_RESUME_RESULT",
    "SCHEMA_OPERATION_FAILURE",
    "apply_instance_github_cli",
    "doctor_instance_github_cli",
    "plan_instance_github_cli",
    "resume_instance_github_cli",
    "validate_plan_wrapper",
    "write_plan_exclusive",
]
