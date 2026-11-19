"""Read-only recovery for an existing-repository GitHub apply journal.

This module never accepts a writer and never submits a remote mutation.  It
loads one explicitly named journal, binds eligible ref/readback states to a
fresh local and reader observation, and uses only the journal owner's
already-accepted readback-close transitions.  Object uncertainty and prepared
zero-effect records remain held for separate operator disposition.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from typing import Any, Protocol

from rs9 import instance as _instance
from rs9 import instance_github as _github
from rs9 import instance_github_apply as _coordinator
from rs9 import remote_journal
from rs9.errors import ContractError
from rs9.security import scan_for_credentials


SCHEMA_RESULT = "rs9.instance-github-resume-result.v1alpha1"
_HEX40 = re.compile(r"[0-9a-f]{40}")
_HEX64 = re.compile(r"[0-9a-f]{64}")
_OPERATION = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,62}[a-z0-9])?")
_TOKEN = re.compile(r"[a-z][a-z0-9-]{0,63}")
_PHASES = {
    "prepared", "blob-submitting", "blob-created", "tree-submitting",
    "tree-created", "commit-submitting", "commit-created", "ref-submitting",
    "readback-pending", "completed", "failed", "uncertain",
}
_BINDINGS = {"not-checked", "matched", "mismatch", "historical"}
_DECISIONS = {"missing", "closed", "completed", "hold", "prepared-disposition-required"}


class ReaderPort(Protocol):
    """Read-only boundary required for eligible journal recovery."""

    def read_repository_node(self, repository: str) -> Mapping[str, Any]: ...

    def read_branch(self, repository: str, branch: str) -> Mapping[str, Any]: ...

    def read_file(self, repository: str, path: str, commit: str) -> Mapping[str, Any]: ...

    def read_parent(self, repository: str, path: str, commit: str) -> Mapping[str, Any]: ...

    def read_namespace(self, repository: str, tree: str, prefix: str) -> Mapping[str, Any]: ...


def _safe_operation(value: Any) -> str:
    if not isinstance(value, str) or _OPERATION.fullmatch(value) is None:
        raise ContractError("RESUME_OPERATION", "Resume operation ID is invalid")
    scan_for_credentials(value)
    return value


def _sha(value: Any, *, length: int, code: str = "RESUME_SCHEMA") -> str:
    pattern = _HEX40 if length == 40 else _HEX64
    if not isinstance(value, str) or pattern.fullmatch(value) is None:
        raise ContractError(code, "Resume hash is invalid")
    scan_for_credentials(value)
    return value


def _token(value: Any, code: str = "RESUME_SCHEMA") -> str:
    if not isinstance(value, str) or _TOKEN.fullmatch(value) is None:
        raise ContractError(code, "Resume reason is invalid")
    scan_for_credentials(value)
    return value


def _journal_summary(journal: remote_journal.RemoteApplyJournal) -> dict[str, str]:
    record = journal.record
    return {
        "phase": record["phase"],
        "digest": journal.digest,
        "plan_sha256": record["plan_sha256"],
        "config_sha256": record["config_sha256"],
    }


def _binding(status: str, *, current_config_sha256: str | None = None,
             reason: str | None = None) -> dict[str, Any]:
    return {
        "status": status,
        "current_config_sha256": current_config_sha256,
        "reason": reason,
    }


def _readback(reason: str, observation_sha256: str | None) -> dict[str, Any]:
    return {"reason": _token(reason), "observation_sha256": observation_sha256}


def _preserved_base(
    prior_coordinator_result: Mapping[str, Any] | None,
    operation_id: str,
    journal: remote_journal.RemoteApplyJournal,
) -> tuple[dict[str, Any] | None, str]:
    if prior_coordinator_result is None:
        return None, "not-persisted"
    try:
        _coordinator._validate_coordinator_result(prior_coordinator_result)
    except ContractError:
        raise ContractError("RESUME_BASE", "Prior coordinator result is invalid") from None
    if (prior_coordinator_result["operation_id"] != operation_id
            or prior_coordinator_result["plan_sha256"] != journal.record["plan_sha256"]
            or prior_coordinator_result["config_sha256"] != journal.record["config_sha256"]):
        raise ContractError("RESUME_BASE", "Prior coordinator result does not bind to the journal")
    try:
        base = _github.validate_result(prior_coordinator_result["base_result"])
        return _instance.snapshot(base), "preserved"
    except ContractError:
        raise ContractError("RESUME_BASE", "Prior base result is invalid") from None


def _resume_result(
    *,
    operation_id: str,
    decision: str,
    status: str,
    reason: str | None,
    journal: dict[str, str] | None,
    binding: Mapping[str, Any],
    readback: Mapping[str, Any] | None,
    base_result: Mapping[str, Any] | None,
    base_evidence: str,
) -> dict[str, Any]:
    value: dict[str, Any] = {
        "schema": SCHEMA_RESULT,
        "operation_id": operation_id,
        "decision": decision,
        "status": status,
        "reason": reason,
        "journal": dict(journal) if journal is not None else None,
        "binding": dict(binding),
        "readback": dict(readback) if readback is not None else None,
        "base_result": _instance.snapshot(base_result) if base_result is not None else None,
        "base_evidence": base_evidence,
        "replay": False,
        "publicationAuthority": False,
        "qualified": False,
        "publicationEnabled": False,
    }
    return _validate_resume_result(_instance.snapshot(value))


def _validate_resume_result(value: Mapping[str, Any]) -> dict[str, Any]:
    allowed = {
        "schema", "operation_id", "decision", "status", "reason", "journal",
        "binding", "readback", "base_result", "base_evidence", "replay",
        "publicationAuthority", "qualified", "publicationEnabled",
    }
    if not isinstance(value, Mapping) or set(value) != allowed:
        raise ContractError("RESUME_SCHEMA", "Resume result shape is invalid")
    if value["schema"] != SCHEMA_RESULT:
        raise ContractError("RESUME_SCHEMA", "Resume result schema is unsupported")
    operation_id = _safe_operation(value["operation_id"])
    decision = value["decision"]
    if decision not in _DECISIONS:
        raise ContractError("RESUME_SCHEMA", "Resume decision is invalid")
    status = value["status"]
    if status not in {"closed", "completed", "pending", "uncertain"}:
        raise ContractError("RESUME_SCHEMA", "Resume status is invalid")
    reason = value["reason"]
    if reason is not None:
        _token(reason)
    journal = value["journal"]
    phase = None
    if journal is not None:
        if not isinstance(journal, Mapping) or set(journal) != {
                "phase", "digest", "plan_sha256", "config_sha256"}:
            raise ContractError("RESUME_SCHEMA", "Resume journal summary is invalid")
        phase = journal["phase"]
        if phase not in _PHASES:
            raise ContractError("RESUME_SCHEMA", "Resume journal phase is invalid")
        _sha(journal["digest"], length=64)
        _sha(journal["plan_sha256"], length=64)
        _sha(journal["config_sha256"], length=64)
    binding = value["binding"]
    if not isinstance(binding, Mapping) or set(binding) != {
            "status", "current_config_sha256", "reason"}:
        raise ContractError("RESUME_SCHEMA", "Resume binding is invalid")
    if binding["status"] not in _BINDINGS:
        raise ContractError("RESUME_SCHEMA", "Resume binding status is invalid")
    current_config_sha256 = binding["current_config_sha256"]
    if current_config_sha256 is not None:
        _sha(current_config_sha256, length=64)
    if binding["reason"] is not None:
        _token(binding["reason"])
    readback = value["readback"]
    if readback is not None:
        if not isinstance(readback, Mapping) or set(readback) != {"reason", "observation_sha256"}:
            raise ContractError("RESUME_SCHEMA", "Resume readback is invalid")
        _token(readback["reason"])
        if readback["observation_sha256"] is not None:
            _sha(readback["observation_sha256"], length=64)
    base_result = value["base_result"]
    if base_result is not None:
        try:
            _github.validate_result(base_result)
        except ContractError:
            raise ContractError("RESUME_SCHEMA", "Resume base result is invalid") from None
    if value["base_evidence"] not in {"preserved", "not-persisted"}:
        raise ContractError("RESUME_SCHEMA", "Resume base evidence state is invalid")
    if (value["base_evidence"] == "preserved") != (base_result is not None):
        raise ContractError("RESUME_SCHEMA", "Resume base evidence binding is inconsistent")
    if value["replay"] is not False or value["publicationAuthority"] is not False \
            or value["qualified"] is not False or value["publicationEnabled"] is not False:
        raise ContractError("RESUME_AUTHORITY", "Resume result cannot claim replay or publication authority")
    if decision == "missing":
        if journal is not None or status != "uncertain" or reason != "journal-missing":
            raise ContractError("RESUME_SCHEMA", "Missing resume result binding is inconsistent")
    elif decision == "closed":
        if phase != "completed" or status != "closed" or binding["status"] not in {"historical", "not-checked"}:
            raise ContractError("RESUME_SCHEMA", "Closed resume result binding is inconsistent")
    elif decision == "completed":
        if phase != "completed" or status != "completed" or binding["status"] != "matched" \
                or readback is None or readback["reason"] != "exact-readback":
            raise ContractError("RESUME_SCHEMA", "Completed resume result binding is inconsistent")
    elif decision == "prepared-disposition-required":
        if phase != "prepared" or status != "pending":
            raise ContractError("RESUME_SCHEMA", "Prepared resume result binding is inconsistent")
    elif decision == "hold":
        if journal is None or phase == "completed" or status != "uncertain":
            raise ContractError("RESUME_SCHEMA", "Held resume result binding is inconsistent")
    return dict(value)


def _reason_for_binding(error: BaseException) -> str:
    code = getattr(error, "code", None)
    if code in {"COORDINATOR_ENGINE", "RESUME_ENGINE"}:
        return "engine-binding-changed"
    if code in {"COORDINATOR_NODE", "COORDINATOR_PERMISSION", "COORDINATOR_READ"}:
        return "binding-unavailable"
    if code in {"INSTANCE_STATE", "TEMPLATE_MISMATCH", "INVALID_CONFIG"}:
        return "local-state-changed"
    return "binding-unavailable"


def _reason_for_journal(error: BaseException) -> str:
    code = getattr(error, "code", None)
    if code in {"JOURNAL_STALE", "JOURNAL_SCHEMA", "JOURNAL_INVENTORY"}:
        return "journal-stale"
    if code in {"JOURNAL_IO", "JOURNAL_UNCERTAIN", "JOURNAL_UNSAFE"}:
        return "journal-persistence-uncertain"
    return "journal-close-failed"


def _eligible_phase(record: Mapping[str, Any]) -> str | None:
    phase = record["phase"]
    if phase == "readback-pending":
        return "readback"
    if phase == "ref-submitting":
        return "ref"
    if phase == "uncertain":
        uncertain = [row for row in record["effects"] if row["status"] == "uncertain"]
        if len(uncertain) == 1 and uncertain[0]["step"] == "ref":
            return "ref"
    return None


def _hold_reason(record: Mapping[str, Any]) -> str:
    phase = record["phase"]
    if phase == "prepared":
        return "prepared-zero-effect"
    if phase == "uncertain":
        uncertain = [row for row in record["effects"] if row["status"] == "uncertain"]
        if uncertain and uncertain[0]["step"] != "ref":
            return "object-uncertain"
        return "journal-uncertain"
    if phase.endswith("-submitting"):
        return "submission-in-flight"
    if phase.endswith("-created"):
        return "acknowledged-object"
    if phase == "failed":
        return "journal-failed"
    return "journal-hold"


def _current_binding(
    publisher_root: str,
    reader: ReaderPort,
    current_engine: Mapping[str, Any],
) -> tuple[dict[str, Any], str]:
    local = _github._local_snapshot(publisher_root)
    engine = _coordinator._validate_installed_engine(current_engine)
    if local["identity"]["engine"] != {
        "distribution": engine["distribution"],
        "version": engine["version"],
    }:
        raise ContractError("RESUME_ENGINE", "Current engine identity differs from local instance")
    node, metadata_sha256 = _coordinator._call_node(reader, local["repository"])
    _coordinator._call_branch_probe(reader, local["repository"], local["branch"], metadata_sha256)
    config = _coordinator._config(local, engine, metadata_sha256)
    return local, _instance.record_sha256(config)


def _fresh_target_readback(
    publisher_root: str,
    reader: ReaderPort,
    local: Mapping[str, Any],
    journal: remote_journal.RemoteApplyJournal,
) -> tuple[bool, str, str | None]:
    try:
        observation = _github.observe_instance(
            publisher_root,
            reader,  # type: ignore[arg-type]
            observed_at=_github._now(),
            bootstrap=False,
        )
        observation_sha256 = _instance.record_sha256(observation)
    except Exception:  # noqa: BLE001 - the reader is an injected closed boundary
        return False, "readback-failed", None
    record = journal.record
    if observation["state"] != "observed" or observation["authenticated"] is not True:
        return False, "readback-failed", observation_sha256
    instance = observation["instance"]
    if (instance["repository"].casefold() != record["repository"].casefold()
            or instance["branch"] != record["branch"]
            or observation["local"] != local["identity"]):
        return False, "binding-changed", observation_sha256
    target_commit = record["target_commit"]
    target_tree = record["target_tree"]
    if (target_commit is None or target_tree is None
            or _HEX40.fullmatch(target_commit) is None
            or _HEX40.fullmatch(target_tree) is None
            or observation["commit"] != target_commit
            or observation["tree"] != target_tree):
        return False, "target-not-observed", observation_sha256
    if observation["protected"] is not False:
        return False, "branch-policy-changed", observation_sha256
    if not _github._remote_exact(local, observation):
        return False, "managed-file-readback", observation_sha256
    return True, "exact-readback", observation_sha256


def resume_existing_repository(
    publisher_root: str,
    *,
    operation_id: str,
    reader: ReaderPort,
    current_engine: Mapping[str, Any],
    prior_coordinator_result: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Close only a reader-proven ref/readback state; never replay or write."""

    operation_id = _safe_operation(operation_id)
    _coordinator._validate_installed_engine(current_engine)
    inventory_before = remote_journal.inventory(publisher_root)
    entries = inventory_before["entries"]
    selected = next((row for row in entries if row["operation_id"] == operation_id), None)
    if selected is None:
        if prior_coordinator_result is not None:
            raise ContractError("RESUME_BASE", "A prior result cannot bind to a missing journal")
        return _resume_result(
            operation_id=operation_id,
            decision="missing",
            status="uncertain",
            reason="journal-missing",
            journal=None,
            binding=_binding("not-checked", reason="journal-missing"),
            readback=None,
            base_result=None,
            base_evidence="not-persisted",
        )
    try:
        journal = remote_journal.load(publisher_root, operation_id)
    except ContractError:
        raise ContractError("RESUME_JOURNAL", "Selected journal could not be loaded") from None
    if journal.digest != selected["digest"]:
        raise ContractError("RESUME_JOURNAL", "Selected journal changed during inventory")
    base_result, base_evidence = _preserved_base(prior_coordinator_result, operation_id, journal)
    record = journal.record
    summary = _journal_summary(journal)
    if (record["phase"] != "completed"
            and any(row["operation_id"] != operation_id and row["phase"] != "completed"
                    for row in entries)):
        return _resume_result(
            operation_id=operation_id,
            decision="hold",
            status="uncertain",
            reason="other-incomplete-journal",
            journal=summary,
            binding=_binding("not-checked", reason="other-incomplete-journal"),
            readback=None,
            base_result=base_result,
            base_evidence=base_evidence,
        )
    if record["phase"] == "completed":
        return _resume_result(
            operation_id=operation_id,
            decision="closed",
            status="closed",
            reason=None,
            journal=summary,
            binding=_binding("historical", reason="historical-closed"),
            readback=None,
            base_result=base_result,
            base_evidence=base_evidence,
        )
    if record["phase"] == "prepared":
        return _resume_result(
            operation_id=operation_id,
            decision="prepared-disposition-required",
            status="pending",
            reason="prepared-zero-effect",
            journal=summary,
            binding=_binding("not-checked", reason="prepared-zero-effect"),
            readback=None,
            base_result=base_result,
            base_evidence=base_evidence,
        )
    eligible = _eligible_phase(record)
    if eligible is None:
        return _resume_result(
            operation_id=operation_id,
            decision="hold",
            status="uncertain",
            reason=_hold_reason(record),
            journal=summary,
            binding=_binding("not-checked", reason=_hold_reason(record)),
            readback=None,
            base_result=base_result,
            base_evidence=base_evidence,
        )

    try:
        local, current_config_sha256 = _current_binding(
            publisher_root, reader, current_engine
        )
    except ContractError as error:
        reason = _reason_for_binding(error)
        return _resume_result(
            operation_id=operation_id,
            decision="hold",
            status="uncertain",
            reason=reason,
            journal=summary,
            binding=_binding("mismatch" if reason != "binding-unavailable" else "not-checked",
                             reason=reason),
            readback=None,
            base_result=base_result,
            base_evidence=base_evidence,
        )
    if current_config_sha256 != record["config_sha256"]:
        return _resume_result(
            operation_id=operation_id,
            decision="hold",
            status="uncertain",
            reason="config-binding-changed",
            journal=summary,
            binding=_binding("mismatch", current_config_sha256=current_config_sha256,
                             reason="config-binding-changed"),
            readback=None,
            base_result=base_result,
            base_evidence=base_evidence,
        )
    exact, readback_reason, observation_sha256 = _fresh_target_readback(
        publisher_root, reader, local, journal
    )
    readback = _readback(readback_reason, observation_sha256)
    binding = _binding("matched", current_config_sha256=current_config_sha256)
    if not exact:
        return _resume_result(
            operation_id=operation_id,
            decision="hold",
            status="uncertain",
            reason=readback_reason,
            journal=summary,
            binding=binding,
            readback=readback,
            base_result=base_result,
            base_evidence=base_evidence,
        )
    try:
        inventory_after = remote_journal.inventory(publisher_root)
    except Exception:  # noqa: BLE001 - preserve the fresh proof but sanitize custody errors
        return _resume_result(
            operation_id=operation_id,
            decision="hold",
            status="uncertain",
            reason="journal-inventory-changed",
            journal=summary,
            binding=binding,
            readback=readback,
            base_result=base_result,
            base_evidence=base_evidence,
        )
    after_entry = next((row for row in inventory_after["entries"] if row["operation_id"] == operation_id), None)
    if (inventory_after["inventory_sha256"] != inventory_before["inventory_sha256"]
            or after_entry is None or after_entry["digest"] != journal.digest):
        return _resume_result(
            operation_id=operation_id,
            decision="hold",
            status="uncertain",
            reason="journal-inventory-changed",
            journal=summary,
            binding=binding,
            readback=readback,
            base_result=base_result,
            base_evidence=base_evidence,
        )
    try:
        if eligible == "readback":
            remote_journal.mark_readback_complete(
                journal,
                commit=record["target_commit"],
                tree=record["target_tree"],
                predecessor_sha256=journal.digest,
            )
        else:
            remote_journal.mark_ref_readback_complete(
                journal,
                commit=record["target_commit"],
                tree=record["target_tree"],
                predecessor_sha256=journal.digest,
            )
        closed = remote_journal.load(publisher_root, operation_id)
        if closed.record["phase"] != "completed":
            raise ContractError("JOURNAL_UNCERTAIN", "Journal close did not produce a completed record")
    except ContractError as error:
        return _resume_result(
            operation_id=operation_id,
            decision="hold",
            status="uncertain",
            reason=_reason_for_journal(error),
            journal=summary,
            binding=binding,
            readback=readback,
            base_result=base_result,
            base_evidence=base_evidence,
        )
    return _resume_result(
        operation_id=operation_id,
        decision="completed",
        status="completed",
        reason=None,
        journal=_journal_summary(closed),
        binding=binding,
        readback=readback,
        base_result=base_result,
        base_evidence=base_evidence,
    )


__all__ = ["SCHEMA_RESULT", "resume_existing_repository"]
