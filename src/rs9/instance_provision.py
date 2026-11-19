"""Closed-state orchestration for the RS9 GitHub provisioning boundary.

The module is an unexposed candidate seam.  It composes a source-owned plan,
a read-only observation port, fixed provisioning mutations, and the durable
provision journal.  Existing instance and coordinator modules remain owners
of their schemas; this module never edits or widens them.
"""

from __future__ import annotations

import copy
import hashlib
import re
from collections.abc import Mapping
from datetime import datetime, timezone
from typing import Any, Callable, Protocol

from rs9 import instance as _instance
from rs9 import provision_journal
from rs9 import remote_journal
from rs9.errors import ContractError
from rs9.github_provision import (
    APPROVED_OWNER,
    DEFAULT_BRANCH,
    README_BYTES,
    README_MESSAGE,
    README_PATH,
    README_SHA256,
    classify_repository_response,
)
from rs9.security import scan_for_credentials, validate_repository, validate_slug

SCHEMA_PROTOCOL = "rs9.instance-github-provision.v1alpha3"
SCHEMA_OBSERVATION = "rs9.instance-github-provision-observation.v1alpha3"
SCHEMA_PLAN = "rs9.instance-github-provision-plan.v1alpha3"
SCHEMA_RESULT = "rs9.instance-github-provision-result.v1alpha3"
ZERO_OID = "0" * 40
_HEX40 = re.compile(r"[0-9a-f]{40}\Z")
_HEX64 = re.compile(r"[0-9a-f]{64}\Z")
_BRANCH = re.compile(r"[A-Za-z0-9][A-Za-z0-9._/-]{0,127}\Z")
_TOKEN = re.compile(r"[a-z][a-z0-9-]{0,95}\Z")
_NO_EFFECT_DECISIONS = {"adoption-required", "existing-apply-required", "noop"}
_MUTATION_EFFECTS = {"created", "completed"}
_DEFAULT_AUTHORITY = {
    "ambient_read": False,
    "ambient_write": False,
    "publication": False,
    "explicit_apply_required": True,
}


class ReaderPort(Protocol):
    """Bounded read-only port used by observe and readback."""

    def read_repository(self, repository: str) -> Mapping[str, Any]: ...
    def read_branch_inventory(self, repository: str, page_size: int) -> Mapping[str, Any]: ...
    def read_branch(self, repository: str, branch: str) -> Mapping[str, Any]: ...
    def read_anchor(self, repository: str) -> Mapping[str, Any]: ...
    def read_target_ref(self, repository: str, branch: str) -> Mapping[str, Any]: ...


class WriterPort(Protocol):
    """Fixed mutation port supplied only by an explicit apply caller."""

    def create_repository(self, name: str) -> Mapping[str, Any]: ...
    def put_bootstrap_readme(self, repository: str) -> Mapping[str, Any]: ...
    def create_target_ref(
        self, repository: str, *, node_id: str, branch: str, anchor_commit: str
    ) -> Mapping[str, Any]: ...


Coordinator = Callable[[Mapping[str, Any], str, Mapping[str, Any]], Mapping[str, Any]]


class _MutationUncertain(Exception):
    pass


class _IdentityConflict(_MutationUncertain):
    """A fresh remote identity does not match the exact plan binding."""


class _TransitionReloaded(Exception):
    """A failed transition was reconciled against the durable journal."""

    def __init__(self, current: provision_journal.ProvisionJournal, *, committed: bool) -> None:
        super().__init__("Provision journal transition was reconciled after persistence failure")
        self.current = current
        self.committed = committed


def _closed(value: Any, keys: set[str], context: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping) or set(value) != keys:
        raise ContractError("PROVISION_SCHEMA", f"{context} record is not closed")
    return value


def _sha(value: Any, length: int, context: str) -> str:
    pattern = _HEX40 if length == 40 else _HEX64
    if not isinstance(value, str) or pattern.fullmatch(value) is None:
        raise ContractError("PROVISION_SCHEMA", f"{context} hash is invalid")
    scan_for_credentials(value)
    return value


def _token(value: Any, context: str = "enum") -> str:
    if not isinstance(value, str) or _TOKEN.fullmatch(value) is None:
        raise ContractError("PROVISION_SCHEMA", f"{context} is invalid")
    scan_for_credentials(value)
    return value


def _branch(value: Any, context: str = "branch") -> str:
    if not isinstance(value, str) or _BRANCH.fullmatch(value) is None:
        raise ContractError("PROVISION_SCHEMA", f"{context} is invalid")
    if ".." in value or value.endswith(("/", ".")) or any(part in {"", ".", ".."} for part in value.split("/")):
        raise ContractError("PROVISION_SCHEMA", f"{context} is invalid")
    scan_for_credentials(value)
    return value


def _timestamp(value: Any) -> str:
    if value is None:
        return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
    try:
        parsed = _instance.parse_rfc3339_utc(value)
    except ContractError:
        raise ContractError("PROVISION_SCHEMA", "Provision timestamp is invalid") from None
    return parsed.isoformat(timespec="microseconds" if "." in value else "seconds").replace("+00:00", "Z")


def _source(value: Any) -> dict[str, Any]:
    keys = {
        "instance_id", "repository", "branch", "engine", "template", "adapter",
        "manifest_sha256", "desired_state_sha256",
    }
    value = _closed(value, keys, "source")
    validate_slug(value["instance_id"], "source.instance_id")
    validate_repository(value["repository"])
    if value["repository"].split("/", 1)[0].casefold() != APPROVED_OWNER.casefold():
        raise ContractError("PROVISION_OWNER", "Source repository owner is outside the approved organization")
    _branch(value["branch"], "source.branch")
    engine = _closed(value["engine"], {"distribution", "version", "artifact_sha256"}, "source.engine")
    if engine["distribution"] != "release-starport-9" or not isinstance(engine["version"], str) or not engine["version"]:
        raise ContractError("PROVISION_ENGINE", "Source engine identity is unsupported")
    _sha(engine["artifact_sha256"], 64, "source.engine")
    template = _closed(value["template"], {"id", "version", "sha256"}, "source.template")
    if not isinstance(template["id"], str) or not template["id"] or not isinstance(template["version"], str) or not template["version"]:
        raise ContractError("PROVISION_TEMPLATE", "Source template identity is invalid")
    _sha(template["sha256"], 64, "source.template")
    adapter = _closed(value["adapter"], {"name", "mode"}, "source.adapter")
    if adapter != {"name": "homebrew", "mode": "projection"}:
        raise ContractError("PROVISION_ADAPTER", "Source adapter is unsupported")
    result = {
        "instance_id": value["instance_id"],
        "repository": value["repository"],
        "branch": value["branch"],
        "engine": dict(engine),
        "template": dict(template),
        "adapter": dict(adapter),
        "manifest_sha256": _sha(value["manifest_sha256"], 64, "source.manifest"),
        "desired_state_sha256": _sha(value["desired_state_sha256"], 64, "source.desired"),
    }
    scan_for_credentials(result["instance_id"])
    return result


def _validate_authority(value: Any, *, explicit_apply: bool | None = None) -> dict[str, bool]:
    expected = set(_DEFAULT_AUTHORITY)
    if not isinstance(value, Mapping) or set(value) != expected or any(type(item) is not bool for item in value.values()):
        raise ContractError("PROVISION_AUTHORITY", "Provision authority record is invalid")
    result = dict(value)
    if explicit_apply is not None and result["explicit_apply_required"] is not True:
        raise ContractError("PROVISION_AUTHORITY", "Explicit apply remains required")
    return result


def _repository_meta(value: Any, *, expected: str | None = None) -> dict[str, Any]:
    keys = {"full_name", "private", "node_id", "default_branch"}
    value = _closed(value, keys, "repository")
    full_name = value["full_name"]
    validate_repository(full_name)
    if not isinstance(value["private"], bool) or value["private"] is not True:
        raise ContractError("PROVISION_REPOSITORY", "Repository is not private")
    node_id = value["node_id"]
    if not isinstance(node_id, str) or not 1 <= len(node_id) <= 256 or any(ord(char) <= 32 or ord(char) >= 127 for char in node_id):
        raise ContractError("PROVISION_NODE", "Repository node identity is invalid")
    default_branch = value["default_branch"]
    if default_branch is not None:
        _branch(default_branch, "repository.default_branch")
    if expected is not None and full_name.casefold() != expected.casefold():
        raise ContractError("PROVISION_NODE", "Repository identity does not match the source")
    return {
        "full_name": full_name,
        "private": True,
        "node_id": node_id,
        "default_branch": default_branch,
    }


def _observation(value: Any) -> dict[str, Any]:
    keys = {
        "schema", "protocol", "operation_id", "observed_at", "instance",
        "source_sha256", "repository", "branches", "refs", "bootstrap",
        "authority",
    }
    value = _closed(value, keys, "observation")
    if value["schema"] != SCHEMA_OBSERVATION or value["protocol"] != SCHEMA_PROTOCOL:
        raise ContractError("PROVISION_SCHEMA", "Observation schema is unsupported")
    operation_id = _token(value["operation_id"], "observation.operation_id")
    observed_at = _timestamp(value["observed_at"])
    instance = _closed(value["instance"], {"id", "repository", "branch"}, "observation.instance")
    validate_slug(instance["id"], "observation.instance.id")
    validate_repository(instance["repository"])
    _branch(instance["branch"], "observation.instance.branch")
    source_sha = _sha(value["source_sha256"], 64, "observation.source")
    repository = value["repository"]
    repository = _closed(repository, {"state", "metadata", "reason"}, "observation.repository")
    if repository["state"] not in {"present", "not-observed-404", "unknown"}:
        raise ContractError("PROVISION_SCHEMA", "Observation repository state is invalid")
    if repository["state"] == "present":
        metadata = _repository_meta(repository["metadata"], expected=instance["repository"])
    elif repository["metadata"] is not None:
        raise ContractError("PROVISION_SCHEMA", "Non-present repository carries metadata")
    else:
        metadata = None
    if repository["reason"] is not None:
        _token(repository["reason"], "observation.repository.reason")
    branches = _closed(value["branches"], {"state", "names", "has_next", "pagination_class"}, "observation.branches")
    if branches["state"] not in {"empty", "nonempty", "inventory-unknown", "not-queried"}:
        raise ContractError("PROVISION_SCHEMA", "Observation branch state is invalid")
    if not isinstance(branches["names"], list) or len(branches["names"]) > 2:
        raise ContractError("PROVISION_SCHEMA", "Observation branch inventory is outside its bound")
    names = []
    for name in branches["names"]:
        names.append(_branch(name, "observation.branch"))
    if names != sorted(set(names)):
        raise ContractError("PROVISION_SCHEMA", "Observation branch inventory is not sorted and unique")
    if type(branches["has_next"]) is not bool:
        raise ContractError("PROVISION_SCHEMA", "Observation branch pagination flag is invalid")
    if branches["pagination_class"] not in {"complete", "truncated", "unknown", "not-queried"}:
        raise ContractError("PROVISION_SCHEMA", "Observation pagination class is invalid")
    refs = _closed(value["refs"], {"main_state", "main_commit", "target_state", "target_commit"}, "observation.refs")
    if refs["main_state"] not in {"not-queried", "empty-repository", "present", "absent-unexpected", "unknown"}:
        raise ContractError("PROVISION_SCHEMA", "Observation main ref state is invalid")
    if refs["target_state"] not in {"not-queried", "absent", "present", "unknown"}:
        raise ContractError("PROVISION_SCHEMA", "Observation target ref state is invalid")
    for key in ("main_commit", "target_commit"):
        if refs[key] is not None:
            _sha(refs[key], 40, f"observation.refs.{key}")
    bootstrap = _closed(
        value["bootstrap"],
        {"readme_state", "anchor_commit", "anchor_tree", "anchor_metadata_sha256"},
        "observation.bootstrap",
    )
    if bootstrap["readme_state"] not in {"not-checked", "absent", "exact", "drifted", "unknown"}:
        raise ContractError("PROVISION_SCHEMA", "Observation README state is invalid")
    if bootstrap["anchor_commit"] is not None:
        _sha(bootstrap["anchor_commit"], 40, "observation.anchor.commit")
    if bootstrap["anchor_tree"] is not None:
        _sha(bootstrap["anchor_tree"], 40, "observation.anchor.tree")
    if bootstrap["anchor_metadata_sha256"] is not None:
        _sha(bootstrap["anchor_metadata_sha256"], 64, "observation.anchor.metadata")
    _validate_authority(value["authority"])
    return {
        "schema": value["schema"], "protocol": value["protocol"], "operation_id": operation_id,
        "observed_at": observed_at, "instance": dict(instance), "source_sha256": source_sha,
        "repository": {"state": repository["state"], "metadata": metadata, "reason": repository["reason"]},
        "branches": {"state": branches["state"], "names": names, "has_next": branches["has_next"], "pagination_class": branches["pagination_class"]},
        "refs": dict(refs),
        "bootstrap": dict(bootstrap),
        "authority": dict(value["authority"]),
    }


def validate_observation(value: Mapping[str, Any]) -> dict[str, Any]:
    return _observation(value)


def _plan(value: Any) -> dict[str, Any]:
    keys = {
        "schema", "protocol", "operation_id", "instance", "source", "repository",
        "bootstrap", "observation_sha256", "decision", "reason", "actions",
        "authority",
    }
    value = _closed(value, keys, "plan")
    if value["schema"] != SCHEMA_PLAN or value["protocol"] != SCHEMA_PROTOCOL:
        raise ContractError("PROVISION_SCHEMA", "Plan schema is unsupported")
    operation_id = _token(value["operation_id"], "plan.operation_id")
    instance = _closed(value["instance"], {"id", "repository", "branch"}, "plan.instance")
    validate_slug(instance["id"], "plan.instance.id")
    validate_repository(instance["repository"])
    _branch(instance["branch"], "plan.instance.branch")
    source = _source(value["source"])
    if (source["instance_id"], source["repository"], source["branch"]) != (
        instance["id"], instance["repository"], instance["branch"]
    ):
        raise ContractError("PROVISION_BINDING", "Plan source and instance differ")
    repository = _closed(value["repository"], {"visibility", "create_policy", "adoption"}, "plan.repository")
    if repository["visibility"] != "private" or repository["create_policy"] not in {"create-once", "adopt-exact"}:
        raise ContractError("PROVISION_REPOSITORY", "Plan repository policy is invalid")
    adoption = _closed(
        repository["adoption"],
        {"mode", "prior_observation_sha256", "prior_observation_operation_id", "expected_node_id_sha256", "expected_anchor_metadata_sha256"},
        "plan.adoption",
    )
    if adoption["mode"] not in {"none", "prior-observation"}:
        raise ContractError("PROVISION_REPOSITORY", "Plan adoption mode is invalid")
    for key in ("prior_observation_sha256", "expected_node_id_sha256", "expected_anchor_metadata_sha256"):
        if adoption[key] is not None:
            _sha(adoption[key], 64, "plan.adoption")
    if adoption["prior_observation_operation_id"] is not None:
        _token(adoption["prior_observation_operation_id"], "plan.adoption.operation")
    if adoption["mode"] == "none" and any(adoption[key] is not None for key in adoption if key != "mode"):
        raise ContractError("PROVISION_REPOSITORY", "Non-adoption plan carries adoption identity")
    if adoption["mode"] == "prior-observation" and (
        adoption["prior_observation_sha256"] is None
        or adoption["prior_observation_operation_id"] is None
        or adoption["expected_node_id_sha256"] is None
        or adoption["expected_anchor_metadata_sha256"] is None
    ):
        raise ContractError("PROVISION_REPOSITORY", "Adoption plan lacks exact prior observation identity")
    bootstrap = _closed(value["bootstrap"], {"default_branch", "readme_path", "readme_sha256", "target_branch"}, "plan.bootstrap")
    if bootstrap["default_branch"] != DEFAULT_BRANCH or bootstrap["readme_path"] != README_PATH:
        raise ContractError("PROVISION_BOOTSTRAP", "Plan bootstrap fixture is unsupported")
    _sha(bootstrap["readme_sha256"], 64, "plan.bootstrap.readme")
    if bootstrap["readme_sha256"] != README_SHA256:
        raise ContractError("PROVISION_BOOTSTRAP", "Plan bootstrap fixture differs from the fixed source")
    _branch(bootstrap["target_branch"], "plan.bootstrap.target_branch")
    if bootstrap["target_branch"] == DEFAULT_BRANCH:
        raise ContractError("PROVISION_BRANCH", "Plan target branch must be non-default")
    if bootstrap["target_branch"] != instance["branch"]:
        raise ContractError("PROVISION_BINDING", "Plan target branch differs from instance branch")
    observation_sha = _sha(value["observation_sha256"], 64, "plan.observation")
    if adoption["mode"] == "prior-observation" and adoption["prior_observation_sha256"] != observation_sha:
        raise ContractError("PROVISION_BINDING", "Adoption observation digest differs from the bound observation")
    decision = _token(value["decision"], "plan.decision")
    reason = _token(value["reason"], "plan.reason")
    if decision not in {"create", "adopt-exact", "noop", "adoption-required", "existing-apply-required", "held"}:
        raise ContractError("PROVISION_PLAN", "Plan decision is unsupported")
    actions = _closed(value["actions"], {"repository", "main_anchor", "target_ref", "handoff"}, "plan.actions")
    for key, allowed in {
        "repository": {"create", "existing", "not-attempted"},
        "main_anchor": {"create", "existing", "not-attempted"},
        "target_ref": {"create", "noop", "not-attempted"},
        "handoff": {"required", "not-requested"},
    }.items():
        if actions[key] not in allowed:
            raise ContractError("PROVISION_PLAN", "Plan action is invalid")
    action_tuple = tuple(actions[key] for key in ("repository", "main_anchor", "target_ref", "handoff"))
    exact_shapes = {
        ("create", "create-once", "none", ("create", "create", "create", "required")),
        ("adopt-exact", "adopt-exact", "prior-observation", ("existing", "existing", "create", "required")),
        ("noop", "adopt-exact", "prior-observation", ("existing", "existing", "noop", "not-requested")),
        ("existing-apply-required", "adopt-exact", "prior-observation", ("existing", "existing", "not-attempted", "not-requested")),
        ("adoption-required", "adopt-exact", "none", ("existing", "not-attempted", "not-attempted", "not-requested")),
        ("held", "adopt-exact", "none", ("existing", "not-attempted", "not-attempted", "not-requested")),
        ("held", "adopt-exact", "prior-observation", ("existing", "existing", "not-attempted", "not-requested")),
        ("held", "create-once", "none", ("not-attempted", "not-attempted", "not-attempted", "not-requested")),
    }
    if (decision, repository["create_policy"], adoption["mode"], action_tuple) not in exact_shapes:
        raise ContractError("PROVISION_PLAN", "Decision, actions, policy, and adoption do not form a closed plan")
    _validate_authority(value["authority"])
    return {
        "schema": value["schema"], "protocol": value["protocol"], "operation_id": operation_id,
        "instance": dict(instance), "source": source, "repository": {
            "visibility": repository["visibility"], "create_policy": repository["create_policy"], "adoption": dict(adoption)
        }, "bootstrap": dict(bootstrap), "observation_sha256": observation_sha,
        "decision": decision, "reason": reason, "actions": dict(actions), "authority": dict(value["authority"]),
    }


def validate_plan(value: Mapping[str, Any]) -> dict[str, Any]:
    return _plan(value)


def _result_from_record(
    record: Mapping[str, Any],
    *,
    journal_sha256: str | None,
    decision: str,
    reason: str,
    observation_sha256: str | None = None,
) -> dict[str, Any]:
    terminal = dict(record["terminal"])
    effects = dict(record["effects"])
    repository = {
        "not-created": "not-created",
        "created": "created",
        "created-unknown": "created-unknown",
        "existing": "existing",
        "unknown": "created-unknown",
    }.get(effects["repository"], "not-created")
    target = {
        "not-attempted": "not-attempted",
        "created": "anchor-created",
        "existing-foreign": "existing-foreign",
        "unknown": "unknown",
    }[effects["target_ref"]]
    inner = dict(record["inner"])
    status = "completed" if terminal["state"] == "completed" else "closed" if terminal["state"] != "nonterminal" else "held"
    return {
        "schema": SCHEMA_RESULT,
        "protocol": SCHEMA_PROTOCOL,
        "operation_id": record["operation_id"],
        "decision": decision,
        "status": status,
        "terminal": terminal,
        "outcome_class": terminal["outcome_class"],
        "reason": reason,
        "effects": effects,
        "repository": repository,
        "target": target,
        "inner_coordinator": inner,
        "observation_sha256": observation_sha256,
        "journal_sha256": journal_sha256,
        "explicit_apply_used": status != "held" or journal_sha256 is not None,
        "authority": dict(_DEFAULT_AUTHORITY),
    }


def _validate_result(value: Any) -> dict[str, Any]:
    keys = {
        "schema", "protocol", "operation_id", "decision", "status", "terminal",
        "outcome_class", "reason", "effects", "repository", "target",
        "inner_coordinator", "observation_sha256", "journal_sha256",
        "explicit_apply_used", "authority",
    }
    value = _closed(value, keys, "result")
    if value["schema"] != SCHEMA_RESULT or value["protocol"] != SCHEMA_PROTOCOL:
        raise ContractError("PROVISION_SCHEMA", "Result schema is unsupported")
    _token(value["operation_id"], "result.operation_id")
    _token(value["decision"], "result.decision")
    if value["status"] not in {"completed", "closed", "held"}:
        raise ContractError("PROVISION_RESULT", "Result status is invalid")
    terminal = _closed(value["terminal"], {"state", "outcome_class", "reason"}, "result.terminal")
    if terminal["state"] not in {"nonterminal", "completed", "no-effect-closed", "partial-closed", "orphan-closed", "superseded"}:
        raise ContractError("PROVISION_RESULT", "Result terminal state is invalid")
    if terminal["outcome_class"] not in {"applied", "definite-no-effect", "partial", "orphan", "uncertain"}:
        raise ContractError("PROVISION_RESULT", "Result outcome is invalid")
    _token(value["reason"], "result.reason")
    if not isinstance(value["effects"], Mapping) or set(value["effects"]) != {"repository", "main_anchor", "target_ref", "inner_coordinator"}:
        raise ContractError("PROVISION_RESULT", "Result effects are not closed")
    for item in value["effects"].values():
        _token(item, "result.effect")
    if value["repository"] not in {"not-created", "created", "created-unknown", "adopted", "existing"}:
        raise ContractError("PROVISION_RESULT", "Result repository disposition is invalid")
    if value["target"] not in {"not-attempted", "anchor-created", "existing-complete", "existing-incomplete", "existing-foreign", "unknown"}:
        raise ContractError("PROVISION_RESULT", "Result target disposition is invalid")
    if value["observation_sha256"] is not None:
        _sha(value["observation_sha256"], 64, "result.observation")
    if value["journal_sha256"] is not None:
        _sha(value["journal_sha256"], 64, "result.journal")
    if type(value["explicit_apply_used"]) is not bool:
        raise ContractError("PROVISION_AUTHORITY", "Result apply authority is invalid")
    _validate_authority(value["authority"])
    return dict(value)


def validate_result(value: Mapping[str, Any]) -> dict[str, Any]:
    return _validate_result(value)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def _call(reader: Any, method: str, *args: Any) -> Mapping[str, Any]:
    function = getattr(reader, method, None)
    if not callable(function):
        raise ContractError("PROVISION_READER", "Required provisioning read port is missing")
    try:
        value = function(*args)
    except ContractError:
        raise
    except Exception:
        raise ContractError("PROVISION_READER", "Provisioning read port failed") from None
    if not isinstance(value, Mapping):
        raise ContractError("PROVISION_READER", "Provisioning read port returned an invalid record")
    return value


def _empty_observation(source: Mapping[str, Any], operation_id: str, observed_at: str, reason: str) -> dict[str, Any]:
    return {
        "schema": SCHEMA_OBSERVATION,
        "protocol": SCHEMA_PROTOCOL,
        "operation_id": operation_id,
        "observed_at": observed_at,
        "instance": {"id": source["instance_id"], "repository": source["repository"], "branch": source["branch"]},
        "source_sha256": provision_journal.record_sha256(source),
        "repository": {"state": "unknown", "metadata": None, "reason": reason},
        "branches": {"state": "not-queried", "names": [], "has_next": False, "pagination_class": "not-queried"},
        "refs": {"main_state": "not-queried", "main_commit": None, "target_state": "not-queried", "target_commit": None},
        "bootstrap": {"readme_state": "not-checked", "anchor_commit": None, "anchor_tree": None, "anchor_metadata_sha256": None},
        "authority": {"ambient_read": False, "ambient_write": False, "publication": False, "explicit_apply_required": True},
    }


def _branch_state(value: Mapping[str, Any], *, expected_commit: str | None = None) -> tuple[str, str | None]:
    status = value.get("status")
    if status == 404:
        return "absent", None
    if status != 200:
        return "unknown", None
    payload = value.get("payload")
    if not isinstance(payload, Mapping):
        return "unknown", None
    commit = payload.get("commit")
    if not isinstance(commit, str) or _HEX40.fullmatch(commit) is None:
        return "unknown", None
    if expected_commit is not None and commit != expected_commit:
        return "present", commit
    return "present", commit


def _inventory(value: Mapping[str, Any]) -> dict[str, Any]:
    status = value.get("status")
    if status != 200:
        return {"state": "inventory-unknown", "names": [], "has_next": False, "pagination_class": "unknown"}
    payload = value.get("payload")
    if not isinstance(payload, Mapping):
        return {"state": "inventory-unknown", "names": [], "has_next": False, "pagination_class": "unknown"}
    names = payload.get("names")
    has_next = payload.get("has_next")
    if not isinstance(names, list) or type(has_next) is not bool:
        return {"state": "inventory-unknown", "names": [], "has_next": False, "pagination_class": "unknown"}
    # Check element types before deduplication/hashability.  A malformed
    # response must become an honest inventory uncertainty, never leak a
    # TypeError from ``set`` for an unhashable JSON value.
    if any(not isinstance(name, str) for name in names):
        return {"state": "inventory-unknown", "names": [], "has_next": False, "pagination_class": "unknown"}
    if len(names) > 2 or len(set(names)) != len(names):
        return {"state": "inventory-unknown", "names": [], "has_next": False, "pagination_class": "truncated"}
    normalized = sorted(_branch(name, "branch inventory") for name in names)
    if has_next:
        return {"state": "inventory-unknown", "names": normalized[:2], "has_next": has_next, "pagination_class": "truncated"}
    return {
        "state": "empty" if not normalized else "nonempty",
        "names": normalized,
        "has_next": False,
        "pagination_class": "complete",
    }


def _anchor(value: Mapping[str, Any], *, expected_commit: str | None = None) -> dict[str, Any]:
    if value.get("status") != 200 or not isinstance(value.get("payload"), Mapping):
        return {"readme_state": "unknown", "anchor_commit": None, "anchor_tree": None, "anchor_metadata_sha256": None}
    payload = value["payload"]
    commit = payload.get("commit")
    tree = payload.get("tree")
    readme_sha = payload.get("readme_sha256")
    metadata = payload.get("metadata_sha256")
    readme_state = payload.get("readme_state")
    if payload.get("branch") != DEFAULT_BRANCH or payload.get("path") != README_PATH:
        return {"readme_state": "unknown", "anchor_commit": None, "anchor_tree": None, "anchor_metadata_sha256": None}
    if not all(isinstance(item, str) and _HEX40.fullmatch(item) for item in (commit, tree)):
        return {"readme_state": "unknown", "anchor_commit": None, "anchor_tree": None, "anchor_metadata_sha256": None}
    if not isinstance(readme_sha, str) or not _HEX64.fullmatch(readme_sha) or not isinstance(metadata, str) or not _HEX64.fullmatch(metadata):
        return {"readme_state": "unknown", "anchor_commit": commit, "anchor_tree": tree, "anchor_metadata_sha256": None}
    if readme_state not in {"exact", "drifted"} or (readme_state == "exact" and readme_sha != README_SHA256):
        return {"readme_state": "unknown", "anchor_commit": commit, "anchor_tree": tree, "anchor_metadata_sha256": None}
    if expected_commit is not None and commit != expected_commit:
        return {"readme_state": "unknown", "anchor_commit": commit, "anchor_tree": tree, "anchor_metadata_sha256": None}
    return {
        "readme_state": readme_state,
        "anchor_commit": commit,
        "anchor_tree": tree,
        "anchor_metadata_sha256": metadata,
    }


def observe(
    source: Mapping[str, Any],
    reader: ReaderPort,
    *,
    operation_id: str,
    observed_at: str | None = None,
) -> dict[str, Any]:
    """Collect a bounded observation; never mutates the repository."""

    source = _source(source)
    operation_id = _token(operation_id, "observation.operation_id")
    timestamp = _timestamp(observed_at)
    base = _empty_observation(source, operation_id, timestamp, "repository-read-unknown")
    try:
        repository_response = _call(reader, "read_repository", source["repository"])
        classification = classify_repository_response(repository_response)
    except ContractError:
        return validate_observation(base)
    if classification["state"] != "present":
        base["repository"] = {
            "state": classification["state"],
            "metadata": None,
            "reason": classification["reason"],
        }
        return validate_observation(base)
    try:
        repository_metadata = _repository_meta(classification["repository"], expected=source["repository"])
    except ContractError:
        base["repository"] = {
            "state": "unknown",
            "metadata": None,
            "reason": "repository-identity-conflict",
        }
        return validate_observation(base)
    base["repository"] = {
        "state": "present",
        "metadata": repository_metadata,
        "reason": classification["reason"],
    }
    try:
        branches = _inventory(_call(reader, "read_branch_inventory", source["repository"], 3))
        base["branches"] = branches
        main_status, main_commit = _branch_state(_call(reader, "read_branch", source["repository"], DEFAULT_BRANCH))
        target_status, target_commit = _branch_state(_call(reader, "read_target_ref", source["repository"], source["branch"]))
        main_state = (
            "present" if main_status == "present"
            else "empty-repository"
            if main_status == "absent"
            and branches["state"] == "empty"
            and branches["pagination_class"] == "complete"
            else "absent-unexpected"
            if main_status == "absent"
            else main_status
        )
        base["refs"] = {
            "main_state": main_state,
            "main_commit": main_commit,
            "target_state": target_status,
            "target_commit": target_commit,
        }
        if main_status == "present":
            base["bootstrap"] = _anchor(
                _call(reader, "read_anchor", source["repository"]),
                expected_commit=main_commit,
            )
    except ContractError:
        base["repository"]["reason"] = "remote-read-unknown"
    if (base["branches"]["state"] in {"inventory-unknown", "not-queried"}
            or base["refs"]["main_state"] in {"unknown", "absent-unexpected", "not-queried"}
            or base["refs"]["target_state"] in {"unknown", "not-queried"}
            or (base["bootstrap"]["readme_state"] in {"unknown", "not-checked"}
                and base["refs"]["main_state"] != "empty-repository")):
        base["repository"]["reason"] = "remote-read-unknown"
    return validate_observation(base)


def _plan_reason(observation: Mapping[str, Any]) -> tuple[str, str, dict[str, str], dict[str, Any]]:
    repository = observation["repository"]
    actions = {"repository": "not-attempted", "main_anchor": "not-attempted", "target_ref": "not-attempted", "handoff": "not-requested"}
    adoption = {
        "mode": "none",
        "prior_observation_sha256": None,
        "prior_observation_operation_id": None,
        "expected_node_id_sha256": None,
        "expected_anchor_metadata_sha256": None,
    }
    if repository["state"] == "not-observed-404":
        actions.update(repository="create", main_anchor="create", target_ref="create", handoff="required")
        return "create", "repository-404-not-observed", actions, adoption
    if repository["state"] != "present":
        return "held", "repository-read-unknown", actions, adoption
    actions["repository"] = "existing"
    if repository["reason"] != "repository-present":
        return "held", "remote-read-unknown", actions, adoption
    metadata = repository["metadata"]
    if metadata["default_branch"] != DEFAULT_BRANCH:
        return "adoption-required", "default-branch-not-main", actions, adoption
    if observation["branches"]["state"] in {"inventory-unknown", "not-queried"}:
        return "held", "branch-inventory-unknown", actions, adoption
    bootstrap = observation["bootstrap"]
    if bootstrap["readme_state"] != "exact" or observation["refs"]["main_state"] != "present":
        return "adoption-required", "main-anchor-nonconforming", actions, adoption
    adoption.update({
        "mode": "prior-observation",
        "prior_observation_sha256": None,
        "prior_observation_operation_id": observation["operation_id"],
        "expected_node_id_sha256": hashlib.sha256(metadata["node_id"].encode("utf-8")).hexdigest(),
        "expected_anchor_metadata_sha256": observation["bootstrap"]["anchor_metadata_sha256"],
    })
    actions["main_anchor"] = "existing"
    if observation["refs"]["target_state"] == "absent":
        actions.update(target_ref="create", handoff="required")
        return "adopt-exact", "exact-main-anchor-target-absent", actions, adoption
    if observation["refs"]["target_state"] == "present":
        if observation["refs"]["target_commit"] == bootstrap["anchor_commit"]:
            actions.update(target_ref="noop", handoff="not-requested")
            return "noop", "noop-exact", actions, adoption
        return "existing-apply-required", "target-existing-incomplete", actions, adoption
    return "held", "target-read-unknown", actions, adoption


def plan(
    source: Mapping[str, Any],
    observation: Mapping[str, Any],
    *,
    operation_id: str,
) -> dict[str, Any]:
    """Bind a source snapshot to one exact observation and choose one action."""

    source = _source(source)
    observation = _observation(observation)
    if observation["source_sha256"] != provision_journal.record_sha256(source):
        raise ContractError("PROVISION_BINDING", "Observation source digest differs")
    expected = {"id": source["instance_id"], "repository": source["repository"], "branch": source["branch"]}
    if observation["instance"] != expected:
        raise ContractError("PROVISION_BINDING", "Observation instance differs")
    operation_id = _token(operation_id, "plan.operation_id")
    decision, reason, actions, adoption = _plan_reason(observation)
    if adoption["mode"] == "prior-observation":
        adoption["prior_observation_sha256"] = provision_journal.record_sha256(observation)
        if adoption["prior_observation_operation_id"] == operation_id:
            raise ContractError("PROVISION_BINDING", "Adoption observation and plan operation IDs must differ")
    repository_policy = "create-once" if observation["repository"]["state"] != "present" else "adopt-exact"
    result = {
        "schema": SCHEMA_PLAN,
        "protocol": SCHEMA_PROTOCOL,
        "operation_id": operation_id,
        "instance": expected,
        "source": source,
        "repository": {"visibility": "private", "create_policy": repository_policy, "adoption": adoption},
        "bootstrap": {
            "default_branch": DEFAULT_BRANCH,
            "readme_path": README_PATH,
            "readme_sha256": README_SHA256,
            "target_branch": source["branch"],
        },
        "observation_sha256": provision_journal.record_sha256(observation),
        "decision": decision,
        "reason": reason,
        "actions": actions,
        "authority": dict(_DEFAULT_AUTHORITY),
    }
    return _plan(result)


def _request_digest(step: str, repository: str, payload: Mapping[str, Any]) -> str:
    return provision_journal.record_sha256({"step": step, "repository": repository, "payload": dict(payload)})


def _effects(
    *,
    repository: str = "not-attempted",
    main_anchor: str = "not-attempted",
    target_ref: str = "not-attempted",
    inner_coordinator: str = "not-attempted",
) -> dict[str, str]:
    return {
        "repository": repository,
        "main_anchor": main_anchor,
        "target_ref": target_ref,
        "inner_coordinator": inner_coordinator,
    }


def _known_mutation(effects: Mapping[str, str]) -> bool:
    return any(value in _MUTATION_EFFECTS for value in effects.values())


def _journal_result(
    journal: provision_journal.ProvisionJournal,
    *,
    decision: str,
    reason: str,
    observation_sha256: str | None = None,
) -> dict[str, Any]:
    record = journal.record
    result = _result_from_record(
        record,
        journal_sha256=journal.digest,
        decision=decision,
        reason=reason,
        observation_sha256=observation_sha256,
    )
    return _validate_result(result)


def _plan_result(plan_record: Mapping[str, Any], *, decision: str, reason: str) -> dict[str, Any]:
    effects = _effects(
        repository="existing" if plan_record["actions"]["repository"] == "existing" else "not-attempted",
        main_anchor="existing" if plan_record["actions"]["main_anchor"] == "existing" else "not-attempted",
        target_ref="existing-foreign" if plan_record["decision"] == "existing-apply-required" else "not-attempted",
    )
    terminal = {
        "state": "no-effect-closed",
        "outcome_class": "definite-no-effect",
        "reason": reason,
    }
    terminal_value = (
        {"state": "completed", "outcome_class": "applied", "reason": reason}
        if decision == "noop"
        else {"state": "nonterminal", "outcome_class": "uncertain", "reason": reason}
        if decision == "held"
        else terminal
    )
    result = {
        "schema": SCHEMA_RESULT,
        "protocol": SCHEMA_PROTOCOL,
        "operation_id": plan_record["operation_id"],
        "decision": decision,
        "status": "completed" if decision == "noop" else "held" if decision == "held" else "closed",
        "terminal": terminal_value,
        "outcome_class": terminal_value["outcome_class"],
        "reason": reason,
        "effects": effects,
        "repository": "existing" if effects["repository"] == "existing" else "not-created",
        "target": "existing-complete" if decision == "noop" else "existing-incomplete" if decision == "existing-apply-required" else "not-attempted",
        "inner_coordinator": {"operation_id": None, "plan_sha256": None, "config_sha256": None, "result_sha256": None, "result": None},
        "observation_sha256": plan_record["observation_sha256"],
        "journal_sha256": None,
        "explicit_apply_used": False,
        "authority": dict(_DEFAULT_AUTHORITY),
    }
    return _validate_result(result)


def _fresh_repository(reader: ReaderPort, repository: str) -> dict[str, Any]:
    classification = classify_repository_response(_call(reader, "read_repository", repository))
    if classification["state"] != "present":
        if classification["reason"] == "repository-identity-conflict":
            raise _IdentityConflict()
        raise _MutationUncertain()
    try:
        return _repository_meta(classification["repository"], expected=repository)
    except ContractError:
        raise _IdentityConflict() from None


def _fresh_anchor(reader: ReaderPort, repository: str, *, expected_metadata: str | None = None) -> dict[str, Any]:
    anchor = _anchor(_call(reader, "read_anchor", repository))
    if anchor["readme_state"] == "drifted":
        raise _IdentityConflict()
    if anchor["readme_state"] != "exact" or anchor["anchor_commit"] is None or anchor["anchor_tree"] is None or anchor["anchor_metadata_sha256"] is None:
        raise _MutationUncertain()
    if expected_metadata is not None and anchor["anchor_metadata_sha256"] != expected_metadata:
        raise _IdentityConflict()
    return anchor


def _fresh_target(reader: ReaderPort, repository: str, branch: str) -> tuple[str, str | None]:
    value = _call(reader, "read_target_ref", repository, branch)
    status = value.get("status")
    if status == 404:
        return "absent", None
    if status != 200 or not isinstance(value.get("payload"), Mapping):
        return "unknown", None
    commit = value["payload"].get("commit")
    if not isinstance(commit, str) or _HEX40.fullmatch(commit) is None:
        return "unknown", None
    return "present", commit


def _response_status(value: Any) -> tuple[int, Mapping[str, Any]]:
    if not isinstance(value, Mapping) or type(value.get("status")) is not int or not isinstance(value.get("payload"), Mapping):
        raise _MutationUncertain()
    return value["status"], value["payload"]


def _created_repository(value: Any, expected_repository: str) -> dict[str, Any]:
    status, payload = _response_status(value)
    if status != 201:
        raise _MutationUncertain()
    return _repository_meta({
        "full_name": payload.get("full_name"),
        "private": payload.get("private"),
        "node_id": payload.get("node_id"),
        "default_branch": payload.get("default_branch"),
    }, expected=expected_repository)


def _duplicate_response(value: Any) -> bool:
    if not isinstance(value, Mapping) or value.get("status") not in {409, 422}:
        return False
    payload = value.get("payload")
    if not isinstance(payload, Mapping):
        return False
    error = payload.get("error")
    if not isinstance(error, Mapping):
        return False
    return error == {"resource": "Repository", "field": "name", "code": "already_exists"}


def _terminal_for_failure(
    effects: Mapping[str, str],
    reason: str,
    *,
    definite_no_effect: bool,
    readback_uncertain: bool = False,
) -> dict[str, str]:
    if readback_uncertain:
        return {"state": "nonterminal", "outcome_class": "uncertain", "reason": reason}
    if any(value == "unknown" for value in effects.values()):
        return {"state": "nonterminal", "outcome_class": "uncertain", "reason": reason}
    if definite_no_effect and not _known_mutation(effects):
        return {"state": "no-effect-closed", "outcome_class": "definite-no-effect", "reason": reason}
    if _known_mutation(effects):
        return {"state": "partial-closed", "outcome_class": "partial", "reason": reason}
    return {"state": "nonterminal", "outcome_class": "uncertain", "reason": reason}


def _transition_failure(
    journal: provision_journal.ProvisionJournal,
    *,
    effects: Mapping[str, str],
    reason: str,
    definite_no_effect: bool = False,
    readback_uncertain: bool = False,
    inner: Mapping[str, Any] | None = None,
) -> provision_journal.ProvisionJournal:
    terminal = _terminal_for_failure(
        effects,
        reason,
        definite_no_effect=definite_no_effect,
        readback_uncertain=readback_uncertain,
    )
    phase = terminal["state"] if terminal["state"] != "nonterminal" else "held"
    return journal.transition(
        phase=phase,
        updated_at=_now(),
        terminal=terminal,
        effects=effects,
        pending=journal.record["pending"] if terminal["state"] == "nonterminal" else {"kind": None, "request_sha256": None},
        inner=inner,
    )


def _transition_after_install(
    journal: provision_journal.ProvisionJournal,
    publisher_root: str,
    *,
    phase: str,
    updated_at: str,
    terminal: Mapping[str, Any],
    effects: Mapping[str, str],
    inner: Mapping[str, Any],
) -> provision_journal.ProvisionJournal:
    """Reconcile a post-mutation transition before entering response-loss.

    ``ProvisionJournal.transition`` may fail after replacing the control file
    (for example, while syncing its parent directory).  Reloading the exact
    operation lets the caller report the durable completed record instead of
    retrying through a mutated in-memory object or misclassifying a finished
    handoff as uncertain.
    """

    try:
        return journal.transition(
            phase=phase,
            updated_at=updated_at,
            terminal=terminal,
            effects=effects,
            inner=inner,
            pending={"kind": None, "request_sha256": None},
        )
    except Exception as error:
        try:
            current = provision_journal.load(publisher_root, journal.operation_id)
        except Exception:
            raise error
        committed = (
            current.record["phase"] == phase
            and current.record["terminal"]["state"] == terminal["state"]
        )
        raise _TransitionReloaded(current, committed=committed) from error


def _decision_for_terminal(journal: provision_journal.ProvisionJournal) -> str:
    state = journal.record["terminal"]["state"]
    return {
        "partial-closed": "closed-partial",
        "no-effect-closed": "closed-no-effect",
        "orphan-closed": "closed-orphan",
    }.get(state, "held")


def _inner_config(plan_record: Mapping[str, Any], node_id: str) -> dict[str, Any]:
    source = plan_record["source"]
    return {
        "schema": "rs9.instance-github-provision-inner-config.v1alpha3",
        "repository": plan_record["instance"]["repository"],
        "branch": plan_record["instance"]["branch"],
        "node_id_sha256": hashlib.sha256(node_id.encode("utf-8")).hexdigest(),
        "source_sha256": provision_journal.record_sha256(source),
        "engine": dict(source["engine"]),
        "template": dict(source["template"]),
        "adapter": dict(source["adapter"]),
    }


def _inner_operation_id(operation_id: str, plan_sha256: str, config_sha256: str) -> str:
    material = "\0".join((operation_id, plan_sha256, config_sha256)).encode("utf-8")
    return "inner-" + hashlib.sha256(material).hexdigest()[:32]


def _normalize_handoff(
    value: Any,
    *,
    expected_inner_operation_id: str | None = None,
    expected_outer_plan_sha256: str | None = None,
    expected_outer_config_sha256: str | None = None,
) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise ContractError("PROVISION_HANDOFF", "Coordinator result is not a normalized record")
    try:
        result = provision_journal._validate_nested(copy.deepcopy(dict(value)))
    except ContractError as error:
        raise ContractError("PROVISION_HANDOFF", "Coordinator result exceeds the bounded nested schema") from error
    if not isinstance(result, dict):
        raise ContractError("PROVISION_HANDOFF", "Coordinator result is not a normalized record")
    if not isinstance(result.get("schema"), str) or not isinstance(result.get("status"), str):
        raise ContractError("PROVISION_HANDOFF", "Coordinator result is missing normalized identity")
    if expected_inner_operation_id is not None and result.get("operation_id") != expected_inner_operation_id:
        raise ContractError("PROVISION_HANDOFF", "Coordinator result inner operation differs")
    if expected_outer_plan_sha256 is not None and result.get("provision_plan_sha256") != expected_outer_plan_sha256:
        raise ContractError("PROVISION_HANDOFF", "Coordinator result outer plan differs")
    if expected_outer_config_sha256 is not None and result.get("provision_config_sha256") != expected_outer_config_sha256:
        raise ContractError("PROVISION_HANDOFF", "Coordinator result outer configuration differs")
    if result.get("publicationAuthority") is not False or result.get("qualified") is not False or result.get("publicationEnabled") is not False:
        raise ContractError("PROVISION_HANDOFF", "Coordinator result claims an unauthorized outcome")
    try:
        if len(provision_journal.canonical_bytes(result)) > provision_journal.MAX_JOURNAL_BYTES:
            raise ContractError("PROVISION_LIMIT", "Coordinator result exceeds the journal byte bound")
    except (TypeError, ValueError, UnicodeError):
        raise ContractError("PROVISION_HANDOFF", "Coordinator result is not canonical metadata") from None
    return result


def _block_reason(
    entries: list[Mapping[str, Any]],
    *,
    operation_id: str,
    instance_id: str,
    repository: str,
) -> str | None:
    for entry in entries:
        if entry["terminal_state"] != "nonterminal":
            continue
        if entry["operation_id"] == operation_id:
            return "operation-blocked"
        if entry["instance_id"].casefold() == instance_id.casefold() or entry["repository"].casefold() == repository.casefold():
            return "operation-blocked"
    return None


def _foreign_inner_journal(root: str) -> bool:
    """Detect an unfinished accepted coordinator journal before handoff/noop."""

    try:
        inventory = remote_journal.inventory(root)
    except ContractError:
        return True
    return any(row["phase"] != "completed" for row in inventory["entries"])


def _noop_readback(reader: ReaderPort, plan_record: Mapping[str, Any]) -> str | None:
    """Freshly cross-check an exact noop without creating a provision journal."""

    try:
        metadata = _fresh_repository(reader, plan_record["instance"]["repository"])
        if hashlib.sha256(metadata["node_id"].encode("utf-8")).hexdigest() != plan_record["repository"]["adoption"]["expected_node_id_sha256"]:
            return "repository-identity-conflict"
        inventory = _inventory(_call(reader, "read_branch_inventory", plan_record["instance"]["repository"], 3))
        expected_names = {DEFAULT_BRANCH, plan_record["bootstrap"]["target_branch"]}
        if inventory["state"] != "nonempty" or set(inventory["names"]) != expected_names:
            return "branch-inventory-conflict"
        anchor = _fresh_anchor(reader, plan_record["instance"]["repository"])
        if anchor["anchor_metadata_sha256"] != plan_record["repository"]["adoption"]["expected_anchor_metadata_sha256"]:
            return "anchor-readback-mismatch"
        state, commit = _fresh_target(reader, plan_record["instance"]["repository"], plan_record["bootstrap"]["target_branch"])
        if state != "present" or commit != anchor["anchor_commit"]:
            return "target-advanced-foreign"
    except Exception:
        return "noop-readback-unknown"
    return None


def apply(
    publisher_root: str,
    plan: Mapping[str, Any],
    *,
    reader: ReaderPort,
    writer: WriterPort,
    handoff: Coordinator | None = None,
) -> dict[str, Any]:
    """Apply one explicit plan with journal-before-mutation boundaries."""

    plan_record = _plan(plan)
    if plan_record["decision"] in _NO_EFFECT_DECISIONS:
        with provision_journal.exclusive_lock(publisher_root):
            inventory = provision_journal.inventory(publisher_root)
            blocked = _block_reason(
                inventory["entries"],
                operation_id=plan_record["operation_id"],
                instance_id=plan_record["instance"]["id"],
                repository=plan_record["instance"]["repository"],
            )
            if blocked is not None:
                return _plan_result(plan_record, decision="held", reason=blocked)
            if _foreign_inner_journal(publisher_root):
                return _plan_result(plan_record, decision="held", reason="foreign-inner-journal")
            if plan_record["decision"] == "noop":
                drift = _noop_readback(reader, plan_record)
                if drift is not None:
                    return _plan_result(plan_record, decision="held", reason=drift)
        return _plan_result(plan_record, decision=plan_record["decision"], reason=plan_record["reason"])
    if plan_record["decision"] == "held":
        with provision_journal.exclusive_lock(publisher_root):
            inventory = provision_journal.inventory(publisher_root)
            blocked = _block_reason(
                inventory["entries"],
                operation_id=plan_record["operation_id"],
                instance_id=plan_record["instance"]["id"],
                repository=plan_record["instance"]["repository"],
            )
            if blocked is not None:
                return _plan_result(plan_record, decision="held", reason=blocked)
            if _foreign_inner_journal(publisher_root):
                return _plan_result(plan_record, decision="held", reason="foreign-inner-journal")
        return _plan_result(plan_record, decision="held", reason=plan_record["reason"])
    operation_id = plan_record["operation_id"]
    plan_sha = provision_journal.record_sha256(plan_record)
    engine_sha = provision_journal.record_sha256(plan_record["source"]["engine"])
    with provision_journal.exclusive_lock(publisher_root):
        inventory = provision_journal.inventory(publisher_root)
        existing = next((row for row in inventory["entries"] if row["operation_id"] == operation_id), None)
        if existing is not None:
            historical = provision_journal.load(publisher_root, operation_id)
            if historical.record["plan_sha256"] != plan_sha:
                raise ContractError("PROVISION_BINDING", "Operation ID is already bound to a different plan")
            if existing["terminal_state"] != "nonterminal":
                return _journal_result(historical, decision="closed", reason=historical.record["terminal"]["reason"] or "historical-closed")
            return _journal_result(historical, decision="held", reason="operation-blocked")
        # A fresh mutating operation must have a callable continuation before
        # any foreign-journal check, journal creation, or writer boundary.  A
        # persisted same-ID record above intentionally wins this preflight so
        # replay/reporting remains available after a caller loses its handoff.
        if not callable(handoff):
            return _plan_result(plan_record, decision="held", reason="handoff-required")
        if _foreign_inner_journal(publisher_root):
            return _plan_result(plan_record, decision="held", reason="foreign-inner-journal")
        blocked = _block_reason(
            inventory["entries"],
            operation_id=operation_id,
            instance_id=plan_record["instance"]["id"],
            repository=plan_record["instance"]["repository"],
        )
        if blocked is not None:
            return _plan_result(plan_record, decision="held", reason=blocked)
        journal = provision_journal.prepare(
            publisher_root,
            operation_id=operation_id,
            instance_id=plan_record["instance"]["id"],
            repository=plan_record["instance"]["repository"],
            branch=plan_record["instance"]["branch"],
            plan_sha256=plan_sha,
            engine_sha256=engine_sha,
            updated_at=_now(),
        )
        effects = _effects(
            repository="not-attempted" if plan_record["actions"]["repository"] == "create" else "existing",
            main_anchor="not-attempted" if plan_record["actions"]["main_anchor"] == "create" else "existing",
        )
        repository = plan_record["instance"]["repository"]
        name = repository.split("/", 1)[1]
        metadata: dict[str, Any] | None = None
        created_metadata: dict[str, Any] | None = None
        if plan_record["actions"]["repository"] == "create":
            request = {"name": name, "private": True, "auto_init": False}
            effects["repository"] = "unknown"
            journal = journal.transition(
                phase="repository-create-prepared",
                updated_at=_now(),
                effects=effects,
                pending={"kind": "repository-create", "request_sha256": _request_digest("repository-create", repository, request)},
            )
            response: Mapping[str, Any] | None = None
            try:
                response = writer.create_repository(name)
                created_metadata = _created_repository(response, repository)
                metadata = created_metadata
            except Exception:
                if response is not None and _duplicate_response(response):
                    effects["repository"] = "not-attempted"
                    journal = _transition_failure(journal, effects=effects, reason="repository-name-conflict", definite_no_effect=True)
                    return _journal_result(journal, decision="closed-no-effect", reason="repository-name-conflict")
                effects["repository"] = "unknown"
                journal = _transition_failure(journal, effects=effects, reason="repository-create-response-lost")
                return _journal_result(journal, decision="held", reason="repository-create-response-lost")
            effects["repository"] = "created"
            journal = journal.transition(
                phase="repository-created", updated_at=_now(), effects=effects,
                pending={"kind": None, "request_sha256": None},
            )
            try:
                metadata = _fresh_repository(reader, repository)
                if created_metadata is None or metadata["node_id"] != created_metadata["node_id"]:
                    raise _IdentityConflict()
            except _IdentityConflict:
                journal = _transition_failure(
                    journal,
                    effects=effects,
                    reason="repository-identity-conflict",
                    readback_uncertain=True,
                )
                return _journal_result(journal, decision="held", reason="repository-identity-conflict")
            except Exception:
                journal = _transition_failure(
                    journal,
                    effects=effects,
                    reason="repository-read-unknown",
                    readback_uncertain=True,
                )
                return _journal_result(journal, decision="held", reason="repository-read-unknown")
        else:
            try:
                metadata = _fresh_repository(reader, repository)
            except _IdentityConflict:
                journal = _transition_failure(
                    journal,
                    effects=effects,
                    reason="repository-identity-conflict",
                    definite_no_effect=True,
                )
                return _journal_result(journal, decision="closed-no-effect", reason="repository-identity-conflict")
            except Exception:
                journal = _transition_failure(
                    journal,
                    effects=effects,
                    reason="repository-read-unknown",
                    readback_uncertain=True,
                )
                return _journal_result(journal, decision="held", reason="repository-read-unknown")
        assert metadata is not None
        if (plan_record["actions"]["repository"] == "existing"
                and hashlib.sha256(metadata["node_id"].encode("utf-8")).hexdigest()
                != plan_record["repository"]["adoption"]["expected_node_id_sha256"]):
            journal = _transition_failure(
                journal,
                effects=effects,
                reason="repository-identity-conflict",
                definite_no_effect=True,
            )
            return _journal_result(journal, decision="closed-no-effect", reason="repository-identity-conflict")
        if metadata["default_branch"] != DEFAULT_BRANCH:
            if plan_record["actions"]["repository"] == "existing":
                journal = _transition_failure(
                    journal,
                    effects=effects,
                    reason="default-branch-not-main",
                    definite_no_effect=True,
                )
                return _journal_result(
                    journal,
                    decision=_decision_for_terminal(journal),
                    reason="default-branch-not-main",
                )
            journal = journal.transition(
                phase="orphan-closed", updated_at=_now(),
                terminal={"state": "orphan-closed", "outcome_class": "orphan", "reason": "default-branch-not-main"},
                effects=effects, pending={"kind": None, "request_sha256": None},
            )
            return _journal_result(journal, decision="closed-orphan", reason="default-branch-not-main")
        try:
            inventory_read = _inventory(_call(reader, "read_branch_inventory", repository, 3))
        except Exception:
            journal = _transition_failure(
                journal,
                effects=effects,
                reason="branch-inventory-unknown",
                readback_uncertain=True,
            )
            return _journal_result(journal, decision="held", reason="branch-inventory-unknown")
        expected_inventory = plan_record["actions"]["main_anchor"] == "create"
        if inventory_read["state"] == "inventory-unknown" and not (
            expected_inventory and inventory_read["has_next"] is True
        ):
            journal = _transition_failure(
                journal,
                effects=effects,
                reason="branch-inventory-unknown",
                readback_uncertain=True,
            )
            return _journal_result(journal, decision="held", reason="branch-inventory-unknown")
        if (expected_inventory and inventory_read["state"] != "empty") or (
            not expected_inventory
            and (inventory_read["state"] != "nonempty" or "main" not in inventory_read["names"])
        ):
            definite_no_effect = plan_record["actions"]["repository"] == "existing"
            journal = _transition_failure(
                journal,
                effects=effects,
                reason="branch-inventory-conflict",
                definite_no_effect=definite_no_effect,
            )
            return _journal_result(
                journal,
                decision=_decision_for_terminal(journal),
                reason="branch-inventory-conflict",
            )
        if plan_record["actions"]["main_anchor"] == "create":
            request = {"path": README_PATH, "message": README_MESSAGE, "branch": DEFAULT_BRANCH, "sha256": README_SHA256}
            effects["main_anchor"] = "unknown"
            journal = journal.transition(
                phase="first-readme-prepared", updated_at=_now(), effects=effects,
                pending={"kind": "first-readme", "request_sha256": _request_digest("first-readme", repository, request)},
            )
            try:
                response = writer.put_bootstrap_readme(repository)
                status, _payload = _response_status(response)
                if status not in {200, 201}:
                    raise _MutationUncertain()
            except _MutationUncertain:
                effects["main_anchor"] = "unknown"
                journal = _transition_failure(journal, effects=effects, reason="contents-response-lost")
                return _journal_result(journal, decision="held", reason="contents-response-lost")
            except Exception:
                effects["main_anchor"] = "unknown"
                journal = _transition_failure(journal, effects=effects, reason="contents-response-lost")
                return _journal_result(journal, decision="held", reason="contents-response-lost")
            effects["main_anchor"] = "created"
            try:
                anchor = _fresh_anchor(reader, repository)
            except Exception:
                journal = _transition_failure(
                    journal,
                    effects=effects,
                    reason="contents-readback-unknown",
                    readback_uncertain=True,
                )
                return _journal_result(journal, decision="held", reason="contents-readback-unknown")
        else:
            try:
                anchor = _fresh_anchor(
                    reader,
                    repository,
                    expected_metadata=plan_record["repository"]["adoption"]["expected_anchor_metadata_sha256"],
                )
            except _IdentityConflict:
                journal = _transition_failure(
                    journal,
                    effects=effects,
                    reason="anchor-readback-mismatch",
                    definite_no_effect=True,
                )
                return _journal_result(journal, decision="closed-no-effect", reason="anchor-readback-mismatch")
            except Exception:
                journal = _transition_failure(
                    journal,
                    effects=effects,
                    reason="anchor-readback-mismatch",
                    readback_uncertain=True,
                )
                return _journal_result(journal, decision="held", reason="anchor-readback-mismatch")
        journal = journal.transition(
            phase="main-anchor-read", updated_at=_now(), effects=effects,
            anchor={
                "commit": anchor["anchor_commit"],
                "tree": anchor["anchor_tree"],
                "metadata_sha256": anchor["anchor_metadata_sha256"],
            },
            pending={"kind": None, "request_sha256": None},
        )
        try:
            target_state, target_commit = _fresh_target(reader, repository, plan_record["bootstrap"]["target_branch"])
        except Exception:
            target_state, target_commit = "unknown", None
        if target_state == "unknown":
            journal = _transition_failure(
                journal,
                effects=effects,
                reason="target-ref-read-unknown",
                readback_uncertain=True,
            )
            return _journal_result(journal, decision="held", reason="target-ref-read-unknown")
        if target_state == "present":
            effects["target_ref"] = "existing-foreign"
            definite_no_effect = plan_record["actions"]["repository"] == "existing"
            journal = _transition_failure(
                journal,
                effects=effects,
                reason="target-branch-already-exists",
                definite_no_effect=definite_no_effect,
            )
            return _journal_result(
                journal,
                decision=_decision_for_terminal(journal),
                reason="target-branch-already-exists",
            )
        request = {"branch": plan_record["bootstrap"]["target_branch"], "before_oid": ZERO_OID, "after_oid": anchor["anchor_commit"], "force": False}
        effects["target_ref"] = "unknown"
        journal = journal.transition(
            phase="target-ref-prepared", updated_at=_now(), effects=effects,
            pending={"kind": "target-ref", "request_sha256": _request_digest("target-ref", repository, request)},
        )
        try:
            response = writer.create_target_ref(
                repository,
                node_id=metadata["node_id"],
                branch=plan_record["bootstrap"]["target_branch"],
                anchor_commit=anchor["anchor_commit"],
            )
            status, payload = _response_status(response)
            if status != 200 or not isinstance(payload.get("data"), Mapping):
                raise _MutationUncertain()
            target_state, target_commit = _fresh_target(reader, repository, plan_record["bootstrap"]["target_branch"])
            if target_state != "present" or target_commit != anchor["anchor_commit"]:
                raise _MutationUncertain()
        except Exception:
            effects["target_ref"] = "unknown"
            journal = _transition_failure(journal, effects=effects, reason="target-ref-response-lost")
            return _journal_result(journal, decision="held", reason="target-ref-response-lost")
        effects["target_ref"] = "created"
        journal = journal.transition(
            phase="target-ref-created", updated_at=_now(), effects=effects,
            pending={"kind": None, "request_sha256": None},
        )
        if handoff is None:
            journal = _transition_failure(journal, effects=effects, reason="handoff-required", readback_uncertain=True)
            return _journal_result(journal, decision="held", reason="handoff-required")
        config = _inner_config(plan_record, metadata["node_id"])
        config_sha = provision_journal.record_sha256(config)
        inner_id = _inner_operation_id(operation_id, plan_sha, config_sha)
        inner = {
            "operation_id": inner_id,
            "plan_sha256": plan_sha,
            "config_sha256": config_sha,
            "result_sha256": None,
            "result": None,
        }
        effects["inner_coordinator"] = "unknown"
        journal = journal.transition(
            phase="handoff-prepared", updated_at=_now(), effects=effects, inner=inner,
            pending={"kind": None, "request_sha256": None},
        )
        try:
            normalized = _normalize_handoff(
                handoff(plan_record, inner_id, config),
                expected_inner_operation_id=inner_id,
                expected_outer_plan_sha256=plan_sha,
                expected_outer_config_sha256=config_sha,
            )
            inner["result"] = normalized
            inner["result_sha256"] = provision_journal.record_sha256(normalized)
            if normalized["status"] != "completed":
                journal = _transition_failure(
                    journal,
                    effects=effects,
                    reason="inner-coordinator-not-completed",
                    inner=inner,
                )
                return _journal_result(journal, decision="held", reason="inner-coordinator-not-completed")
            completed_effects = dict(effects)
            completed_effects["inner_coordinator"] = "completed"
            try:
                journal = _transition_after_install(
                    journal,
                    publisher_root,
                    phase="handoff-completed",
                    updated_at=_now(),
                    terminal={"state": "completed", "outcome_class": "applied", "reason": "exact-readback"},
                    effects=completed_effects,
                    inner=inner,
                )
            except _TransitionReloaded as reconciled:
                journal = reconciled.current
                if reconciled.committed:
                    return _journal_result(journal, decision="completed", reason="exact-readback")
                raise
        except Exception:
            effects["inner_coordinator"] = "unknown"
            journal = _transition_failure(journal, effects=effects, reason="inner-coordinator-response-lost")
            return _journal_result(journal, decision="held", reason="inner-coordinator-response-lost")
        return _journal_result(journal, decision="completed", reason="exact-readback")


def resume(
    publisher_root: str,
    *,
    operation_id: str,
    reader: ReaderPort,
) -> dict[str, Any]:
    """Perform read-only closure checks; never retries a mutation or handoff."""

    operation_id = _token(operation_id, "resume.operation_id")
    with provision_journal.exclusive_lock(publisher_root):
        journal = provision_journal.load(publisher_root, operation_id)
        record = journal.record
        if record["terminal"]["state"] != "nonterminal":
            return _journal_result(journal, decision="closed", reason=record["terminal"]["reason"] or "historical-closed")
        effects = dict(record["effects"])
        if record["pending"]["kind"] == "target-ref":
            try:
                target_state, target_commit = _fresh_target(reader, record["repository"], record["branch"])
            except Exception:
                target_state, target_commit = "unknown", None
            expected_commit = record["anchor"]["commit"]
            if target_state == "present" and target_commit == expected_commit and expected_commit is not None:
                effects["target_ref"] = "created"
                journal = journal.transition(
                    phase="target-ref-created", updated_at=_now(), effects=effects,
                    pending={"kind": None, "request_sha256": None},
                )
                return _journal_result(journal, decision="held", reason="handoff-required")
            effects["target_ref"] = "unknown"
            reason = (
                "target-advanced-foreign" if target_state == "present"
                else "target-ref-absent" if target_state == "absent"
                else "target-ref-read-unknown"
            )
            journal = _transition_failure(
                journal,
                effects=effects,
                reason=reason,
                readback_uncertain=True,
            )
            return _journal_result(journal, decision="held", reason=reason)
        reason = "response-loss-held" if record["phase"].endswith("prepared") else "nonterminal-held"
        return _journal_result(journal, decision="held", reason=reason)


__all__ = [
    "Coordinator",
    "ReaderPort",
    "SCHEMA_OBSERVATION",
    "SCHEMA_PLAN",
    "SCHEMA_PROTOCOL",
    "SCHEMA_RESULT",
    "WriterPort",
    "apply",
    "observe",
    "plan",
    "resume",
    "validate_observation",
    "validate_plan",
    "validate_result",
]

