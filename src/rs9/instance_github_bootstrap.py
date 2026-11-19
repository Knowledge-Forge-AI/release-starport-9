"""Anchored-bootstrap handoff for the RS9 GitHub instance protocol.

This module is intentionally a new, unexposed seam.  It composes the
accepted ``instance_github`` bootstrap planner with the accepted journaled
object/ref transport, but does not change the existing coordinator's
bootstrap=False contract.  The provisioning owner may call the returned
handoff callback after it has created the non-zero README anchor and target
ref; the outer provision journal is never closed here.

Only normalized records and digests cross the durable boundary.  The reader
composition at the bottom of this module combines the accepted coordinator
reader with the separately-owned provisioning reader.  The latter's closed
``read_anchor`` envelope is normalized here; no raw response, README bytes,
or unknown state is synthesized.
"""

from __future__ import annotations

import copy
import hashlib
import re
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Any, Protocol

from rs9 import bootstrap_binding
from rs9 import instance as _instance
from rs9 import instance_github as _github
from rs9 import instance_github_apply as _coordinator
from rs9 import provision_journal
from rs9 import remote_journal
from rs9.errors import ContractError
from rs9.github_provision import (
    DEFAULT_BRANCH,
    README_BYTES,
    README_MESSAGE,
    README_PATH,
    README_SHA256,
)
from rs9.github_writer import COMMIT_AUTHOR_EMAIL, COMMIT_AUTHOR_NAME, RepositoryNodeId
from rs9.github_provision_reader import (
    SCHEMA_ANCHOR as PROVISION_ANCHOR_SCHEMA,
    SCHEMA_PROOF as PROVISION_READER_SCHEMA,
    GitHubProvisionReadTransport,
)
from rs9.github_reader import GitHubReadTransport
from rs9.security import scan_for_credentials, validate_repository, validate_safe_relative_posix_path


SCHEMA_CONFIG = "rs9.instance-github-anchored-bootstrap-config.v1alpha1"
SCHEMA_RESULT = "rs9.instance-github-anchored-bootstrap-result.v1alpha1"
SCHEMA_ANCHOR = "rs9.instance-github-anchored-bootstrap-anchor.v1alpha1"
ANCHOR_FACTS_SCHEMA = "rs9.instance-github-anchored-bootstrap-anchor-facts.v1alpha1"
_HEX40 = re.compile(r"[0-9a-f]{40}\Z")
_HEX64 = re.compile(r"[0-9a-f]{64}\Z")
_TOKEN = re.compile(r"[a-z][a-z0-9-]{0,63}\Z")
_OPERATION = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,62}[a-z0-9])?\Z")
_NODE_ID = re.compile(r"[!-~]{1,256}\Z")
_POLICY = {
    "managed_namespace": _github.MANAGED_NAMESPACE,
    "transport": f"{_github.PROTOCOL_ID}/{_github.PROTOCOL_VERSION}",
    "journal": remote_journal.SCHEMA,
}


class ReaderPort(_coordinator.ReaderPort, Protocol):
    """Accepted coordinator reader plus normalized authenticated anchor facts."""

    def read_anchor_facts(
        self, repository: str, commit: str, tree: str
    ) -> Mapping[str, Any]: ...


class WriterPort(_coordinator.WriterPort, Protocol):
    """Writer boundary supplied by an explicit apply caller."""


@dataclass(frozen=True)
class PreparedAnchoredBootstrap:
    """In-process accepted handoff; no raw node value is persisted."""

    publisher_root: str
    provision_operation_id: str
    provision_inner_id: str
    provision_plan: Mapping[str, Any]
    provision_config: Mapping[str, Any]
    plan: Mapping[str, Any]
    config: Mapping[str, Any]
    plan_sha256: str
    config_sha256: str
    node: Mapping[str, str]
    anchor: Mapping[str, Any]
    journal: remote_journal.RemoteApplyJournal | None


def _closed(value: Any, keys: set[str], context: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping) or set(value) != keys:
        raise ContractError("BOOTSTRAP_SCHEMA", f"{context} record is not closed")
    return value


def _sha(value: Any, length: int, context: str, *, nonzero: bool = False) -> str:
    pattern = _HEX40 if length == 40 else _HEX64
    if not isinstance(value, str) or pattern.fullmatch(value) is None:
        raise ContractError("BOOTSTRAP_SCHEMA", f"{context} digest is invalid")
    if nonzero and value == "0" * length:
        raise ContractError("BOOTSTRAP_SCHEMA", f"{context} cannot be zero")
    scan_for_credentials(value)
    return value


def _operation(value: Any, context: str = "operation") -> str:
    if not isinstance(value, str) or _OPERATION.fullmatch(value) is None:
        raise ContractError("BOOTSTRAP_SCHEMA", f"{context} is invalid")
    scan_for_credentials(value)
    return value


def _token(value: Any, context: str) -> str:
    if not isinstance(value, str) or _TOKEN.fullmatch(value) is None:
        raise ContractError("BOOTSTRAP_SCHEMA", f"{context} is invalid")
    scan_for_credentials(value)
    return value


def _record(value: Mapping[str, Any], context: str) -> dict[str, Any]:
    try:
        normalized = _instance.snapshot(dict(value))
        _instance.canonical(normalized, validate=True)
    except ContractError:
        raise
    except (TypeError, ValueError, UnicodeError, RecursionError):
        raise ContractError("BOOTSTRAP_SCHEMA", f"{context} is not canonical") from None
    return normalized


def _git_blob_sha(data: bytes) -> str:
    return hashlib.sha1(b"blob " + str(len(data)).encode("ascii") + b"\0" + data).hexdigest()


def _node_id_sha256(node_id: str) -> str:
    return hashlib.sha256(node_id.encode("utf-8")).hexdigest()


def _validate_engine(value: Any) -> dict[str, str]:
    return dict(_coordinator._validate_installed_engine(value))


def _validate_provision_config(value: Any, repository: str, branch: str) -> dict[str, Any]:
    keys = {"schema", "repository", "branch", "node_id_sha256", "source_sha256", "engine", "template", "adapter"}
    row = _closed(value, keys, "Provision inner configuration")
    if row["schema"] != "rs9.instance-github-provision-inner-config.v1alpha3":
        raise ContractError("BOOTSTRAP_BINDING", "Provision inner configuration schema is unsupported")
    if row["repository"] != repository or row["branch"] != branch:
        raise ContractError("BOOTSTRAP_BINDING", "Provision inner configuration identity differs")
    _sha(row["node_id_sha256"], 64, "Provision node")
    _sha(row["source_sha256"], 64, "Provision source")
    if not isinstance(row["engine"], Mapping) or not isinstance(row["template"], Mapping) or not isinstance(row["adapter"], Mapping):
        raise ContractError("BOOTSTRAP_BINDING", "Provision inner configuration identity is invalid")
    normalized = _record(row, "Provision inner configuration")
    return normalized


def _validate_provision_plan(value: Any, *, allow_outer_create: bool = False) -> dict[str, Any]:
    try:
        plan = dict(provision_journal._validate_nested(copy.deepcopy(dict(value))))
    except (TypeError, ValueError, ContractError):
        try:
            from rs9 import instance_provision
            plan = dict(instance_provision.validate_plan(value))
        except Exception:
            raise ContractError("BOOTSTRAP_BINDING", "Provision plan is not a validated record") from None
    # The candidate validator is the owner of the full provisioning schema;
    # call it explicitly when available so a nested-looking impostor cannot
    # authorize a handoff.
    try:
        from rs9 import instance_provision
        plan = dict(instance_provision.validate_plan(plan))
    except Exception:
        raise ContractError("BOOTSTRAP_BINDING", "Provision plan is not a validated record") from None
    actions = plan["actions"]
    if plan["decision"] == "create" and allow_outer_create:
        # A create plan is accepted only as the already-journaled outer
        # operation.  This seam never creates the repository, README, or
        # target ref itself.
        if actions != {
            "repository": "create",
            "main_anchor": "create",
            "target_ref": "create",
            "handoff": "required",
        }:
            raise ContractError("BOOTSTRAP_BINDING", "Outer create plan is not the fixed anchored handoff shape")
        return plan
    if plan["decision"] not in {"adopt-exact", "noop"}:
        raise ContractError("BOOTSTRAP_BINDING", "Provision decision is not an anchored handoff")
    if plan["decision"] == "noop":
        if actions != {
            "repository": "existing",
            "main_anchor": "existing",
            "target_ref": "noop",
            "handoff": "not-requested",
        }:
            raise ContractError("BOOTSTRAP_BINDING", "Provision noop is not a no-write handoff")
    else:
        if actions != {
            "repository": "existing",
            "main_anchor": "existing",
            "target_ref": "create",
            "handoff": "required",
        }:
            raise ContractError("BOOTSTRAP_BINDING", "Provision adopt plan is not an anchored handoff")
    return plan


def _validate_anchor_facts(
    value: Any,
    *,
    repository: str,
    commit: str,
    tree: str,
    node_metadata_sha256: str,
    node_id_sha256: str | None = None,
) -> dict[str, Any]:
    keys = {
        "schema", "status", "transport", "authenticated", "repository", "branch", "commit", "tree",
        "node_id_sha256", "repository_metadata_sha256", "anchor_metadata_sha256", "readme",
        "message", "author", "committer", "parents",
    }
    facts = _closed(value, keys, "Anchor facts")
    if facts["schema"] != ANCHOR_FACTS_SCHEMA or facts["status"] != 200 or facts["transport"] != "ok" or facts["authenticated"] is not True:
        raise ContractError("BOOTSTRAP_ANCHOR", "Anchor facts are not authenticated")
    if (facts["repository"] != repository or facts["branch"] != DEFAULT_BRANCH
            or facts["commit"] != commit or facts["tree"] != tree):
        raise ContractError("BOOTSTRAP_ANCHOR", "Anchor facts do not bind the authenticated branch")
    observed_node_id_sha256 = _sha(facts["node_id_sha256"], 64, "Anchor node identity")
    if node_id_sha256 is not None and observed_node_id_sha256 != node_id_sha256:
        raise ContractError("BOOTSTRAP_ANCHOR", "Anchor node identity differs from node custody")
    repository_metadata_sha256 = _sha(facts["repository_metadata_sha256"], 64, "Repository metadata")
    if repository_metadata_sha256 != node_metadata_sha256:
        raise ContractError("BOOTSTRAP_ANCHOR", "Anchor permission metadata differs from the node proof")
    anchor_metadata_sha256 = _sha(facts["anchor_metadata_sha256"], 64, "Anchor metadata")
    readme = _closed(
        facts["readme"],
        {"path", "state", "bytes_sha256", "git_blob_sha", "mode", "size"},
        "Anchor README",
    )
    if (
        readme["path"] != README_PATH
        or readme["state"] != "exact"
        or _sha(readme["bytes_sha256"], 64, "Anchor README bytes") != README_SHA256
        or _sha(readme["git_blob_sha"], 40, "Anchor README Git blob") != _git_blob_sha(README_BYTES)
        or readme["mode"] != _github.EXPECTED_MODE
        or type(readme["size"]) is not int
        or readme["size"] != len(README_BYTES)
    ):
        raise ContractError("BOOTSTRAP_ANCHOR", "Anchor README digest or mode are not exact")
    author = _closed(facts["author"], {"name", "email", "date"}, "Anchor author")
    committer = _closed(facts["committer"], {"name", "email", "date"}, "Anchor committer")
    if (author["name"] != COMMIT_AUTHOR_NAME or author["email"] != COMMIT_AUTHOR_EMAIL
            or committer["name"] != COMMIT_AUTHOR_NAME or committer["email"] != COMMIT_AUTHOR_EMAIL):
        raise ContractError("BOOTSTRAP_ANCHOR", "Anchor author or committer is not the fixed protocol identity")
    if facts["message"] != README_MESSAGE:
        raise ContractError("BOOTSTRAP_ANCHOR", "Anchor commit message is not the fixed protocol message")
    author = {"name": author["name"], "email": author["email"], "date": _github._validate_timestamp(author["date"])}
    committer = {"name": committer["name"], "email": committer["email"], "date": _github._validate_timestamp(committer["date"])}
    parents = facts["parents"]
    if not isinstance(parents, list) or len(parents) > 16:
        raise ContractError("BOOTSTRAP_ANCHOR", "Anchor parent facts are malformed")
    normalized_parents: list[str] = []
    for parent in parents:
        normalized_parents.append(_sha(parent, 40, "Anchor parent"))
    readme_digest = hashlib.sha256(README_BYTES).hexdigest()
    if readme_digest != README_SHA256:
        raise ContractError("BOOTSTRAP_ANCHOR", "Fixed README digest is internally inconsistent")
    projection = {
        "schema": SCHEMA_ANCHOR,
        "repository": repository,
        "branch": DEFAULT_BRANCH,
        "commit": commit,
        "tree": tree,
        "readme": {
            "path": README_PATH,
            "bytes_sha256": readme_digest,
            "git_blob_sha": _git_blob_sha(README_BYTES),
            "state": "exact",
            "mode": _github.EXPECTED_MODE,
            "size": len(README_BYTES),
        },
        "commit_facts": {
            "message": README_MESSAGE,
            "author": dict(author),
            "committer": dict(committer),
            "parents": normalized_parents,
        },
        "node_id_sha256": observed_node_id_sha256,
        "repository_metadata_sha256": repository_metadata_sha256,
        "anchor_metadata_sha256": anchor_metadata_sha256,
    }
    projection = _record(projection, "Anchor projection")
    return {
        "projection": projection,
        "projection_sha256": _instance.record_sha256(projection),
        "node_id_sha256": observed_node_id_sha256,
        "repository_metadata_sha256": repository_metadata_sha256,
        "anchor_metadata_sha256": anchor_metadata_sha256,
        "readme_sha256": readme_digest,
    }


def _validate_config(value: Any, *, local: Mapping[str, Any], provision_operation_id: str) -> dict[str, Any]:
    keys = {
        "schema", "repository", "branch", "bootstrap", "force", "engine", "template", "adapter", "policy",
        "local_identity", "node_metadata_sha256", "node_id_sha256", "anchor", "provision_operation_id",
        "provision_plan_sha256", "provision_config_sha256",
    }
    config = _closed(value, keys, "Anchored-bootstrap configuration")
    if config["schema"] != SCHEMA_CONFIG or config["repository"] != local["repository"] or config["branch"] != local["branch"]:
        raise ContractError("BOOTSTRAP_CONFIG", "Anchored-bootstrap configuration identity differs")
    if config["bootstrap"] is not True or config["force"] is not False or config["provision_operation_id"] != provision_operation_id:
        raise ContractError("BOOTSTRAP_CONFIG", "Anchored-bootstrap policy is invalid")
    engine = _validate_engine(config["engine"])
    if local["identity"]["engine"] != {"distribution": engine["distribution"], "version": engine["version"]}:
        raise ContractError("BOOTSTRAP_ENGINE", "Installed engine identity differs from local instance")
    if config["template"] != local["identity"]["template"] or config["adapter"] != local["identity"]["adapter"]:
        raise ContractError("BOOTSTRAP_CONFIG", "Template or adapter identity differs from local instance")
    if config["policy"] != _POLICY:
        raise ContractError("BOOTSTRAP_CONFIG", "Anchored-bootstrap policy is not the fixed policy")
    if config["local_identity"] != local["identity"]:
        raise ContractError("BOOTSTRAP_CONFIG", "Anchored-bootstrap local identity differs")
    _sha(config["node_metadata_sha256"], 64, "Node metadata")
    _sha(config["node_id_sha256"], 64, "Node identity")
    _sha(config["provision_plan_sha256"], 64, "Provision plan")
    _sha(config["provision_config_sha256"], 64, "Provision config")
    anchor = _closed(config["anchor"], {
        "commit", "tree", "readme_sha256", "projection_sha256", "provision_metadata_sha256",
        "repository_metadata_sha256", "anchor_metadata_sha256", "node_id_sha256", "projection",
    }, "Anchored-bootstrap anchor")
    _sha(anchor["commit"], 40, "Anchor commit", nonzero=True)
    _sha(anchor["tree"], 40, "Anchor tree", nonzero=True)
    _sha(anchor["readme_sha256"], 64, "Anchor README")
    _sha(anchor["projection_sha256"], 64, "Anchor projection")
    _sha(anchor["provision_metadata_sha256"], 64, "Provision anchor metadata")
    _sha(anchor["repository_metadata_sha256"], 64, "Repository metadata")
    _sha(anchor["anchor_metadata_sha256"], 64, "Anchor metadata")
    _sha(anchor["node_id_sha256"], 64, "Anchor node identity")
    projection = _record(anchor["projection"], "Anchor projection")
    if _instance.record_sha256(projection) != anchor["projection_sha256"]:
        raise ContractError("BOOTSTRAP_CONFIG", "Anchor projection digest differs")
    if projection["commit"] != anchor["commit"] or projection["tree"] != anchor["tree"]:
        raise ContractError("BOOTSTRAP_CONFIG", "Anchor projection identity differs")
    if anchor["readme_sha256"] != README_SHA256 or projection["readme"]["bytes_sha256"] != README_SHA256:
        raise ContractError("BOOTSTRAP_CONFIG", "Fixed README digest differs")
    if projection["repository_metadata_sha256"] != anchor["repository_metadata_sha256"]:
        raise ContractError("BOOTSTRAP_CONFIG", "Repository metadata digest differs")
    if projection["anchor_metadata_sha256"] != anchor["anchor_metadata_sha256"]:
        raise ContractError("BOOTSTRAP_CONFIG", "Anchor metadata digest differs")
    if projection["node_id_sha256"] != anchor["node_id_sha256"] or anchor["node_id_sha256"] != config["node_id_sha256"]:
        raise ContractError("BOOTSTRAP_CONFIG", "Anchor node identity differs from node custody")
    if anchor["repository_metadata_sha256"] != config["node_metadata_sha256"]:
        raise ContractError("BOOTSTRAP_CONFIG", "Anchor permission metadata differs from node custody")
    return dict(config)


def _validate_handoff_boundary(
    publisher_root: str,
    provision_plan: Mapping[str, Any],
    provision_inner_id: str,
    provision_config: Mapping[str, Any] | None = None,
) -> provision_journal.ProvisionJournal | None:
    """Validate the exact outer journal boundary before any inner write.

    The outer coordinator owns repository/README/ref mutation and invokes the
    handoff only while its journal is at ``handoff-prepared``.  This check is
    deliberately read-only: ``ProvisionJournal.load`` does not acquire the
    outer flock, so it is safe while the coordinator still owns that lock.
    Both create and adopt-exact plans use the same custody boundary; noop has
    no handoff and is intentionally rejected here.
    """

    try:
        from rs9 import instance_provision
        plan = dict(instance_provision.validate_plan(provision_plan))
    except Exception:
        raise ContractError("BOOTSTRAP_OUTER", "Outer provision plan is not a validated record") from None
    expected_effects = {
        "create": {
            "repository": "created",
            "main_anchor": "created",
            "target_ref": "created",
            "inner_coordinator": "unknown",
        },
        "adopt-exact": {
            "repository": "existing",
            "main_anchor": "existing",
            "target_ref": "created",
            "inner_coordinator": "unknown",
        },
    }
    if plan["decision"] not in expected_effects or plan["actions"] != {
        "repository": "create" if plan["decision"] == "create" else "existing",
        "main_anchor": "create" if plan["decision"] == "create" else "existing",
        "target_ref": "create",
        "handoff": "required",
    }:
        return None
    try:
        outer = provision_journal.load(publisher_root, plan["operation_id"])
    except ContractError:
        raise ContractError("BOOTSTRAP_OUTER", "Outer provision journal is required before handoff") from None
    record = outer.record
    outer_plan_sha256 = provision_journal.record_sha256(plan)
    outer_config_sha256 = None if provision_config is None else provision_journal.record_sha256(provision_config)
    if record["operation_id"] != plan["operation_id"]:
        raise ContractError("BOOTSTRAP_OUTER", "Outer operation identity differs")
    if record["plan_sha256"] != outer_plan_sha256:
        raise ContractError("BOOTSTRAP_OUTER", "Outer plan digest differs")
    inner = record["inner"]
    if inner["operation_id"] != provision_inner_id:
        raise ContractError("BOOTSTRAP_OUTER", "Outer inner operation identity differs")
    if inner["plan_sha256"] != outer_plan_sha256:
        raise ContractError("BOOTSTRAP_OUTER", "Outer inner plan identity differs")
    if outer_config_sha256 is not None and inner["config_sha256"] != outer_config_sha256:
        raise ContractError("BOOTSTRAP_OUTER", "Outer inner config identity differs")
    if record["phase"] != "handoff-prepared" or record["terminal"] != {
        "state": "nonterminal",
        "outcome_class": "uncertain",
        "reason": None,
    }:
        raise ContractError("BOOTSTRAP_OUTER", "Outer journal is not at the handoff boundary")
    if record["instance_id"] != plan["instance"]["id"] or record["repository"] != plan["instance"]["repository"]:
        raise ContractError("BOOTSTRAP_OUTER", "Outer instance identity differs")
    if record["branch"] != plan["instance"]["branch"]:
        raise ContractError("BOOTSTRAP_OUTER", "Outer branch identity differs")
    if record["engine_sha256"] != provision_journal.record_sha256(plan["source"]["engine"]):
        raise ContractError("BOOTSTRAP_OUTER", "Outer engine identity differs")
    if record["effects"] != expected_effects[plan["decision"]]:
        raise ContractError("BOOTSTRAP_OUTER", "Outer effects are not the exact pre-handoff boundary")
    if record["pending"] != {"kind": None, "request_sha256": None}:
        raise ContractError("BOOTSTRAP_OUTER", "Outer journal has a pending mutation")
    if inner["result_sha256"] is not None or inner["result"] is not None:
        raise ContractError("BOOTSTRAP_OUTER", "Outer journal already contains an inner result")
    anchor = record["anchor"]
    _sha(anchor["commit"], 40, "Outer anchor commit", nonzero=True)
    _sha(anchor["tree"], 40, "Outer anchor tree", nonzero=True)
    _sha(anchor["metadata_sha256"], 64, "Outer anchor metadata", nonzero=True)
    return outer


def _validated_outer_create(
    publisher_root: str,
    provision_plan: Mapping[str, Any],
    provision_inner_id: str,
    provision_config: Mapping[str, Any] | None = None,
) -> provision_journal.ProvisionJournal | None:
    """Retain the create-only compatibility name over the shared boundary."""

    try:
        from rs9 import instance_provision
        plan = dict(instance_provision.validate_plan(provision_plan))
    except Exception:
        raise ContractError("BOOTSTRAP_OUTER", "Outer provision plan is not a validated record") from None
    if plan["decision"] != "create":
        return None
    return _validate_handoff_boundary(
        publisher_root,
        plan,
        provision_inner_id,
        provision_config,
    )


def _outer_anchor(
    publisher_root: str,
    provision_plan: Mapping[str, Any],
    provision_inner_id: str,
    *,
    provision_config: Mapping[str, Any] | None = None,
) -> tuple[str, str, str, provision_journal.ProvisionJournal | None]:
    outer = _validate_handoff_boundary(
        publisher_root,
        provision_plan,
        provision_inner_id,
        provision_config,
    )
    if outer is None:
        raise ContractError("BOOTSTRAP_OUTER", "Provision decision does not authorize a handoff")
    record = outer.record
    _sha(record["anchor"]["commit"], 40, "Provision anchor commit", nonzero=True)
    _sha(record["anchor"]["tree"], 40, "Provision anchor tree", nonzero=True)
    _sha(record["anchor"]["metadata_sha256"], 64, "Provision anchor metadata", nonzero=True)
    return record["anchor"]["commit"], record["anchor"]["tree"], record["anchor"]["metadata_sha256"], outer


def _call(reader: Any, method: str, *args: Any) -> Mapping[str, Any]:
    function = getattr(reader, method, None)
    if not callable(function):
        raise ContractError("BOOTSTRAP_READER", f"Reader {method} boundary is unavailable")
    try:
        value = function(*args)
    except ContractError:
        raise
    except Exception:
        raise ContractError("BOOTSTRAP_READER", f"Reader {method} boundary failed") from None
    if not isinstance(value, Mapping):
        raise ContractError("BOOTSTRAP_READER", f"Reader {method} boundary returned an invalid record")
    return value


def _normalize_provision_anchor(
    value: Mapping[str, Any], *, repository: str, commit: str, tree: str
) -> dict[str, Any]:
    """Normalize one closed provisioning anchor envelope into ``ReaderPort`` facts."""

    envelope = _closed(value, {"status", "payload", "proof"}, "Provision anchor envelope")
    if envelope["status"] != 200:
        # A 404/403/other status is not an absence proof.  Keep it outside the
        # strict facts shape so callers cannot accidentally treat it as exact.
        raise ContractError("BOOTSTRAP_ANCHOR", "Provision anchor is not an authenticated success")
    payload = _closed(
        envelope["payload"],
        {
            "schema", "state", "repository", "branch", "path", "commit", "tree", "readme_state",
            "readme_sha256", "readme_git_sha", "readme_size", "readme_mode", "message", "author",
            "committer", "parents", "metadata_sha256", "repository_metadata_sha256",
        },
        "Provision anchor payload",
    )
    proof = _closed(
        envelope["proof"],
        {
            "schema", "repository", "authenticated", "permission_proof", "permission_pull", "metadata_sha256",
            "node_id_sha256", "authority",
        },
        "Provision reader proof",
    )
    if (
        payload["schema"] != PROVISION_ANCHOR_SCHEMA
        or payload["state"] != "exact"
        or payload["repository"] != repository
        or payload["branch"] != DEFAULT_BRANCH
        or payload["path"] != README_PATH
        or payload["commit"] != commit
        or payload["tree"] != tree
        or payload["readme_state"] != "exact"
    ):
        raise ContractError("BOOTSTRAP_ANCHOR", "Provision anchor identity or state is not exact")
    if (
        proof["schema"] != PROVISION_READER_SCHEMA
        or proof["repository"] != repository
        or proof["authenticated"] is not True
        or proof["permission_proof"] != "repository-permissions"
        or proof["permission_pull"] is not True
        or proof["authority"] != {"read": True, "write": False, "publication": False}
    ):
        raise ContractError("BOOTSTRAP_ANCHOR", "Provision reader proof is not authenticated")
    anchor_metadata_sha256 = _sha(payload["metadata_sha256"], 64, "Anchor metadata")
    repository_metadata_sha256 = _sha(payload["repository_metadata_sha256"], 64, "Repository metadata")
    if proof["metadata_sha256"] != repository_metadata_sha256:
        raise ContractError("BOOTSTRAP_ANCHOR", "Provision permission digest differs from anchor proof")
    node_id_sha256 = _sha(proof["node_id_sha256"], 64, "Anchor node identity")
    readme_sha256 = _sha(payload["readme_sha256"], 64, "Anchor README bytes")
    readme_git_sha = _sha(payload["readme_git_sha"], 40, "Anchor README Git blob")
    if type(payload["readme_size"]) is not int or payload["readme_size"] < 0:
        raise ContractError("BOOTSTRAP_ANCHOR", "Provision README size is malformed")
    if payload["readme_mode"] != _github.EXPECTED_MODE:
        raise ContractError("BOOTSTRAP_ANCHOR", "Provision README mode is not exact")
    author = _closed(payload["author"], {"name", "email", "date"}, "Provision anchor author")
    committer = _closed(payload["committer"], {"name", "email", "date"}, "Provision anchor committer")
    parents = payload["parents"]
    if not isinstance(parents, list) or len(parents) > 16:
        raise ContractError("BOOTSTRAP_ANCHOR", "Provision anchor parents are malformed")
    normalized_parents = [_sha(parent, 40, "Anchor parent") for parent in parents]
    return {
        "schema": ANCHOR_FACTS_SCHEMA,
        "status": 200,
        "transport": "ok",
        "authenticated": True,
        "repository": repository,
        "branch": DEFAULT_BRANCH,
        "commit": commit,
        "tree": tree,
        "node_id_sha256": node_id_sha256,
        "repository_metadata_sha256": repository_metadata_sha256,
        "anchor_metadata_sha256": anchor_metadata_sha256,
        "readme": {
            "path": README_PATH,
            "state": "exact",
            "bytes_sha256": readme_sha256,
            "git_blob_sha": readme_git_sha,
            "mode": payload["readme_mode"],
            "size": payload["readme_size"],
        },
        "message": payload["message"],
        "author": dict(author),
        "committer": dict(committer),
        "parents": normalized_parents,
    }


class GitHubAnchoredBootstrapReader:
    """Compose the accepted coordinator and provisioning readers.

    ``GitHubProvisionReadTransport`` wraps a ``GitHubReadTransport`` but is
    deliberately not a subtype.  Requiring object identity here prevents the
    node/permission reads and the anchor read from silently using different
    runners or authentication observations.
    """

    def __init__(
        self,
        coordinator_reader: GitHubReadTransport,
        provisioning_reader: GitHubProvisionReadTransport,
    ) -> None:
        if type(coordinator_reader) is not GitHubReadTransport or type(provisioning_reader) is not GitHubProvisionReadTransport:
            raise ContractError("BOOTSTRAP_READER", "Accepted GitHub reader composition is required")
        if getattr(provisioning_reader, "_reader", None) is not coordinator_reader:
            raise ContractError("BOOTSTRAP_READER", "Provisioning reader is bound to a different coordinator reader")
        self._coordinator = coordinator_reader
        self._provisioning = provisioning_reader

    def read_repository_node(self, repository: str) -> Mapping[str, Any]:
        return self._coordinator.read_repository_node(repository)

    def read_branch(self, repository: str, branch: str) -> Mapping[str, Any]:
        return self._coordinator.read_branch(repository, branch)

    def read_file(self, repository: str, path: str, commit: str) -> Mapping[str, Any]:
        return self._coordinator.read_file(repository, path, commit)

    def read_parent(self, repository: str, path: str, commit: str) -> Mapping[str, Any]:
        return self._coordinator.read_parent(repository, path, commit)

    def read_namespace(self, repository: str, tree: str, prefix: str) -> Mapping[str, Any]:
        return self._coordinator.read_namespace(repository, tree, prefix)

    def read_anchor_facts(self, repository: str, commit: str, tree: str) -> Mapping[str, Any]:
        envelope = self._provisioning.read_anchor(repository, expected_commit=commit)
        return _normalize_provision_anchor(envelope, repository=repository, commit=commit, tree=tree)


def _branch(value: Mapping[str, Any], repository: str, metadata_sha256: str) -> dict[str, Any]:
    if value.get("status") != 200 or value.get("transport") != "ok" or value.get("authenticated") is not True:
        raise ContractError("BOOTSTRAP_READ", "Authenticated branch observation is unavailable")
    repository_row = value.get("repository")
    if not isinstance(repository_row, Mapping) or repository_row.get("full_name", "").casefold() != repository.casefold():
        raise ContractError("BOOTSTRAP_NODE", "Branch repository identity differs")
    if value.get("metadata_sha256") != metadata_sha256:
        raise ContractError("BOOTSTRAP_NODE", "Branch permission metadata differs")
    if type(value.get("protected")) is not bool:
        raise ContractError("BOOTSTRAP_READ", "Branch protection state is invalid")
    return {
        "commit": _sha(value.get("commit"), 40, "Branch commit", nonzero=True),
        "tree": _sha(value.get("tree"), 40, "Branch tree", nonzero=True),
        "protected": value.get("protected"),
    }


def _node(reader: Any, repository: str, provision_config: Mapping[str, Any]) -> tuple[dict[str, str], str]:
    node, metadata_sha256 = _coordinator._call_node(reader, repository)
    if _node_id_sha256(node["value"]) != provision_config["node_id_sha256"]:
        raise ContractError("BOOTSTRAP_NODE", "Reader node differs from provision custody")
    return node, metadata_sha256


class _BoundReader:
    """Reader wrapper preserving repository/node custody on every read."""

    def __init__(self, reader: ReaderPort, repository: str, metadata_sha256: str) -> None:
        self._reader = reader
        self._repository = repository
        self._metadata_sha256 = metadata_sha256

    def _checked(self, method: str, value: Mapping[str, Any], *, allow_missing: bool = False) -> Mapping[str, Any]:
        if value.get("transport") != "ok" or value.get("authenticated") is not True:
            raise ContractError("BOOTSTRAP_READ", "Authenticated remote read is unavailable")
        if value.get("status") == 404 and allow_missing:
            return value
        repository = value.get("repository")
        if repository is not None and (not isinstance(repository, Mapping) or repository.get("full_name", "").casefold() != self._repository.casefold()):
            raise ContractError("BOOTSTRAP_NODE", "Remote read repository identity differs")
        metadata = value.get("metadata_sha256")
        if metadata is not None and metadata != self._metadata_sha256:
            raise ContractError("BOOTSTRAP_NODE", "Remote read permission metadata differs")
        return value

    def read_branch(self, repository: str, branch: str) -> Mapping[str, Any]:
        if repository != self._repository:
            raise ContractError("BOOTSTRAP_NODE", "Branch repository differs")
        return self._checked("branch", _call(self._reader, "read_branch", repository, branch))

    def read_file(self, repository: str, path: str, commit: str) -> Mapping[str, Any]:
        return self._checked("file", _call(self._reader, "read_file", repository, path, commit), allow_missing=True)

    def read_parent(self, repository: str, path: str, commit: str) -> Mapping[str, Any]:
        return self._checked("parent", _call(self._reader, "read_parent", repository, path, commit), allow_missing=True)

    def read_namespace(self, repository: str, tree: str, prefix: str) -> Mapping[str, Any]:
        return self._checked("namespace", _call(self._reader, "read_namespace", repository, tree, prefix))


def _anchor_record(
    *,
    commit: str,
    tree: str,
    provision_metadata_sha256: str,
    anchor_facts: Mapping[str, Any],
    node_metadata_sha256: str,
    repository: str,
    node_id_sha256: str | None = None,
) -> dict[str, Any]:
    checked = _validate_anchor_facts(
        anchor_facts,
        repository=repository,
        commit=commit,
        tree=tree,
        node_metadata_sha256=node_metadata_sha256,
        node_id_sha256=node_id_sha256,
    )
    return {
        "commit": commit,
        "tree": tree,
        "readme_sha256": checked["readme_sha256"],
        "projection_sha256": checked["projection_sha256"],
        "provision_metadata_sha256": _sha(provision_metadata_sha256, 64, "Provision anchor metadata"),
        "anchor_metadata_sha256": checked["anchor_metadata_sha256"],
        "node_id_sha256": checked["node_id_sha256"],
        "repository_metadata_sha256": checked["repository_metadata_sha256"],
        "projection": checked["projection"],
    }


def _fresh_observation(
    publisher_root: str,
    reader: ReaderPort,
    *,
    repository: str,
    metadata_sha256: str,
    anchor: Mapping[str, Any],
    expected_commit: str | None = None,
    expected_tree: str | None = None,
) -> tuple[dict[str, Any], dict[str, Any]]:
    branch = _branch(_call(reader, "read_branch", repository, _github._local_snapshot(publisher_root)["branch"]), repository, metadata_sha256)
    expected_commit = anchor["commit"] if expected_commit is None else expected_commit
    expected_tree = anchor["tree"] if expected_tree is None else expected_tree
    if branch["commit"] != expected_commit or branch["tree"] != expected_tree:
        raise ContractError("BOOTSTRAP_DRIFT", "Target branch moved from the anchored position")
    bound = _BoundReader(reader, repository, metadata_sha256)
    observation = dict(_github.observe_instance(
        publisher_root,
        bound,  # type: ignore[arg-type]
        observed_at=_github._now(),
        bootstrap=True,
    ))
    if observation["state"] != "observed" or observation["authenticated"] is not True:
        raise ContractError("BOOTSTRAP_READ", "Fresh authenticated bootstrap observation is unavailable")
    if observation["commit"] != expected_commit or observation["tree"] != expected_tree:
        raise ContractError("BOOTSTRAP_DRIFT", "Bootstrap observation moved from the anchor")
    facts = _call(reader, "read_anchor_facts", repository, anchor["commit"], anchor["tree"])
    observed_anchor = _anchor_record(
        commit=anchor["commit"],
        tree=anchor["tree"],
        provision_metadata_sha256=anchor["provision_metadata_sha256"],
        anchor_facts=facts,
        node_metadata_sha256=metadata_sha256,
        repository=repository,
        node_id_sha256=anchor["node_id_sha256"],
    )
    if observed_anchor != dict(anchor):
        raise ContractError("BOOTSTRAP_DRIFT", "Authenticated anchor facts changed")
    return observation, observed_anchor


def _plan_matches_observation(plan: Mapping[str, Any], observation: Mapping[str, Any]) -> bool:
    if plan["bootstrap"] is not True or observation["bootstrap_requested"] is not True:
        return False
    if plan["instance"] != observation["instance"] or plan["local"] != observation["local"]:
        return False
    if plan["commit"] != observation["commit"] or plan["tree"] != observation["tree"] or plan["protected"] != observation["protected"]:
        return False
    if plan["parents"] != observation["parents"] or plan["namespace"] != observation["namespace"]:
        return False
    files = {row["path"]: row for row in plan["files"]}
    return all(files[path]["observed"] == row for path, row in observation["managed_files"].items())


def _validate_accepted_plan(plan: Mapping[str, Any], observation: Mapping[str, Any], anchor: Mapping[str, Any]) -> dict[str, Any]:
    validated = dict(_github.validate_plan(plan))
    if validated["bootstrap"] is not True or validated["outcome"] not in {"create", "noop", "blocked", "drift"}:
        raise ContractError("BOOTSTRAP_PLAN", "Anchored bootstrap plan is not an accepted no-write or create state")
    if validated["commit"] != anchor["commit"] or validated["tree"] != anchor["tree"] or validated["actions"]["deletes"]:
        raise ContractError("BOOTSTRAP_PLAN", "Anchored bootstrap plan does not retain the anchor")
    if not _plan_matches_observation(validated, observation):
        raise ContractError("BOOTSTRAP_PLAN", "Anchored bootstrap plan does not bind the observation")
    if validated["outcome"] in {"create", "noop"}:
        allowed_actions = {"create", "noop"}
    else:
        allowed_actions = {"create", "noop", "blocked", "drift", "unknown"}
        if validated["actions"]["writes"]:
            raise ContractError("BOOTSTRAP_PLAN", "Blocked or drifted bootstrap plan carries writes")
    for row in validated["files"]:
        if row["action"] not in allowed_actions:
            raise ContractError("BOOTSTRAP_PLAN", "Anchored bootstrap plan carries an unsupported action")
    return validated


def _build_config(
    local: Mapping[str, Any],
    *,
    provision_plan: Mapping[str, Any],
    provision_config: Mapping[str, Any],
    provision_operation_id: str,
    node_metadata_sha256: str,
    node_id_sha256: str,
    anchor: Mapping[str, Any],
    installed_engine: Mapping[str, Any],
) -> dict[str, Any]:
    config = {
        "schema": SCHEMA_CONFIG,
        "repository": local["repository"],
        "branch": local["branch"],
        "bootstrap": True,
        "force": False,
        "engine": _validate_engine(installed_engine),
        "template": dict(local["identity"]["template"]),
        "adapter": dict(local["identity"]["adapter"]),
        "policy": dict(_POLICY),
        "local_identity": copy.deepcopy(local["identity"]),
        "node_metadata_sha256": node_metadata_sha256,
        "node_id_sha256": node_id_sha256,
        "anchor": copy.deepcopy(dict(anchor)),
        "provision_operation_id": provision_operation_id,
        "provision_plan_sha256": provision_journal.record_sha256(provision_plan),
        "provision_config_sha256": provision_journal.record_sha256(provision_config),
    }
    return _validate_config(config, local=local, provision_operation_id=provision_operation_id)


def _journal_for_plan(
    publisher_root: str,
    *,
    operation_id: str,
    repository: str,
    branch: str,
    plan_sha256: str,
    config_sha256: str,
    anchor: Mapping[str, Any],
) -> remote_journal.RemoteApplyJournal:
    try:
        historical = remote_journal.load(publisher_root, operation_id)
    except ContractError as error:
        if getattr(error, "code", None) != "JOURNAL_MISSING":
            raise
        return remote_journal.prepare(
            publisher_root,
            operation_id,
            repository=repository,
            branch=branch,
            plan_sha256=plan_sha256,
            config_sha256=config_sha256,
            expected_parent=anchor["commit"],
            expected_tree=anchor["tree"],
        )
    record = historical.record
    if (
        record["repository"] != repository or record["branch"] != branch
        or record["plan_sha256"] != plan_sha256 or record["config_sha256"] != config_sha256
        or record["expected_parent"] != anchor["commit"] or record["expected_tree"] != anchor["tree"]
    ):
        raise ContractError("BOOTSTRAP_JOURNAL", "Existing remote journal differs from the binding")
    return historical


def _ensure_no_foreign_journals(publisher_root: str, operation_id: str) -> None:
    try:
        inventory = remote_journal.inventory(publisher_root)
    except ContractError as error:
        if getattr(error, "code", None) == "JOURNAL_MISSING":
            return
        raise
    for row in inventory["entries"]:
        if row["operation_id"] != operation_id and row["phase"] != "completed":
            raise ContractError("BOOTSTRAP_JOURNAL", "Another remote operation requires explicit recovery")


def _load_existing_binding(
    publisher_root: str, operation_id: str
) -> dict[str, Any] | None:
    """Load an existing immutable binding without converting custody errors to absence."""

    try:
        return bootstrap_binding.load_binding(publisher_root, operation_id)
    except ContractError as error:
        if getattr(error, "code", None) == "BOOTSTRAP_BINDING_MISSING":
            return None
        raise


def _journal_view(journal: remote_journal.RemoteApplyJournal | None) -> dict[str, Any] | None:
    if journal is None:
        return None
    return {"operation_id": journal.operation_id, "phase": journal.record["phase"], "digest": journal.digest}


def _base_result(plan: Mapping[str, Any], *, status: str, remote_state: str, reason: str, observation: Mapping[str, Any] | None = None) -> Mapping[str, Any]:
    return _github._result(
        plan,
        status=status,
        remote_state=remote_state,
        effects=[{"step": "precondition", "status": "failed", "reason": reason}],
        observation=observation,
        reason=reason,
    )


def _reconstruct_base_result(
    plan: Mapping[str, Any], journal: remote_journal.RemoteApplyJournal, observation: Mapping[str, Any]
) -> Mapping[str, Any]:
    record = journal.record
    if record["phase"] != "completed" or not all(effect["status"] == "completed" for effect in record["effects"]):
        raise ContractError("BOOTSTRAP_JOURNAL", "Remote journal is not readback-closed")
    if record["target_commit"] is None or record["target_tree"] is None:
        raise ContractError("BOOTSTRAP_JOURNAL", "Closed remote journal lacks target identity")
    if observation["commit"] != record["target_commit"] or observation["tree"] != record["target_tree"]:
        raise ContractError("BOOTSTRAP_READBACK", "Closed remote journal target is not observed")
    effects: list[dict[str, Any]] = []
    for effect in record["effects"]:
        row = {"step": effect["step"], "status": effect["status"]}
        if effect["path"] is not None:
            row["path"] = effect["path"]
        if effect["sha1"] is not None:
            row["sha1"] = effect["sha1"]
        if effect["step"] == "ref":
            row["basis"] = "force-false"
        effects.append(row)
    effects.append({"step": "post-readback", "status": "completed", "basis": "exact-readback"})
    return _github._result(plan, status="completed", remote_state="observed", effects=effects, observation=observation)


def _wrapper_result(
    *,
    operation_id: str,
    decision: str,
    status: str,
    plan_sha256: str,
    config_sha256: str,
    anchor: Mapping[str, Any],
    base_result: Mapping[str, Any],
    journal: remote_journal.RemoteApplyJournal | None,
    readback: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    result = {
        "schema": SCHEMA_RESULT,
        "operation_id": operation_id,
        "decision": decision,
        "status": status,
        "bootstrap": True,
        "plan_sha256": plan_sha256,
        "config_sha256": config_sha256,
        "journal": _journal_view(journal),
        "readback": dict(readback) if readback is not None else None,
        "anchor": {
            "commit": anchor["commit"],
            "tree": anchor["tree"],
            "readme_sha256": anchor["readme_sha256"],
            "projection_sha256": anchor["projection_sha256"],
            "provision_metadata_sha256": anchor["provision_metadata_sha256"],
            "anchor_metadata_sha256": anchor["anchor_metadata_sha256"],
            "node_id_sha256": anchor["node_id_sha256"],
            "repository_metadata_sha256": anchor["repository_metadata_sha256"],
        },
        "base_result": dict(_github.validate_result(base_result)),
        "publicationAuthority": False,
        "qualified": False,
        "publicationEnabled": False,
    }
    return validate_result(result)


def validate_result(value: Mapping[str, Any]) -> dict[str, Any]:
    required = {
        "schema", "operation_id", "decision", "status", "bootstrap", "plan_sha256", "config_sha256",
        "journal", "readback", "anchor", "base_result", "publicationAuthority", "qualified", "publicationEnabled",
    }
    optional = {"provision_plan_sha256", "provision_config_sha256"}
    if not isinstance(value, Mapping) or not required <= set(value) or not set(value) <= required | optional:
        raise ContractError("BOOTSTRAP_SCHEMA", "Anchored-bootstrap result record is not closed")
    row = value
    if row["schema"] != SCHEMA_RESULT or row["bootstrap"] is not True:
        raise ContractError("BOOTSTRAP_RESULT", "Anchored-bootstrap result schema is unsupported")
    operation_id = _operation(row["operation_id"], "Result operation")
    if row["decision"] not in {"noop", "completed", "readback-required", "hold", "fresh-plan-required"}:
        raise ContractError("BOOTSTRAP_RESULT", "Anchored-bootstrap decision is invalid")
    if row["status"] not in {"completed", "pending", "uncertain", "failed"}:
        raise ContractError("BOOTSTRAP_RESULT", "Anchored-bootstrap status is invalid")
    _sha(row["plan_sha256"], 64, "Result plan")
    _sha(row["config_sha256"], 64, "Result config")
    if "provision_plan_sha256" in row:
        _sha(row["provision_plan_sha256"], 64, "Outer provision plan")
    if "provision_config_sha256" in row:
        _sha(row["provision_config_sha256"], 64, "Outer provision config")
    if row["publicationAuthority"] is not False or row["qualified"] is not False or row["publicationEnabled"] is not False:
        raise ContractError("BOOTSTRAP_AUTHORITY", "Anchored-bootstrap result cannot claim publication authority")
    journal = row["journal"]
    if journal is not None:
        _closed(journal, {"operation_id", "phase", "digest"}, "Result journal")
        _operation(journal["operation_id"], "Result journal operation")
        if journal["operation_id"] != operation_id:
            raise ContractError("BOOTSTRAP_RESULT", "Result journal operation differs")
        if journal["phase"] not in {"prepared", "blob-submitting", "blob-created", "tree-submitting", "tree-created", "commit-submitting", "commit-created", "ref-submitting", "readback-pending", "completed", "failed", "uncertain"}:
            raise ContractError("BOOTSTRAP_RESULT", "Result journal phase is invalid")
        _sha(journal["digest"], 64, "Result journal")
    readback = row["readback"]
    if readback is not None:
        _closed(readback, {"reason", "observation_sha256"}, "Result readback")
        _token(readback["reason"], "Result readback reason")
        if readback["observation_sha256"] is not None:
            _sha(readback["observation_sha256"], 64, "Result observation")
    anchor = _closed(
        row["anchor"],
        {
            "commit", "tree", "readme_sha256", "projection_sha256", "provision_metadata_sha256",
            "anchor_metadata_sha256", "node_id_sha256", "repository_metadata_sha256",
        },
        "Result anchor",
    )
    _sha(anchor["commit"], 40, "Result anchor commit", nonzero=True)
    _sha(anchor["tree"], 40, "Result anchor tree", nonzero=True)
    for key in (
        "readme_sha256", "projection_sha256", "provision_metadata_sha256", "anchor_metadata_sha256",
        "node_id_sha256", "repository_metadata_sha256",
    ):
        _sha(anchor[key], 64, f"Result anchor {key}")
    if anchor["readme_sha256"] != README_SHA256:
        raise ContractError("BOOTSTRAP_RESULT", "Result README digest is not fixed")
    _github.validate_result(row["base_result"])
    if row["decision"] == "noop" and (journal is not None or row["status"] != "completed"):
        raise ContractError("BOOTSTRAP_RESULT", "No-op result binding is inconsistent")
    if row["decision"] == "completed" and (journal is None or journal["phase"] != "completed" or row["status"] != "completed"):
        raise ContractError("BOOTSTRAP_RESULT", "Completed result binding is inconsistent")
    if row["decision"] == "readback-required" and (journal is None or journal["phase"] != "readback-pending" or row["status"] != "uncertain"):
        raise ContractError("BOOTSTRAP_RESULT", "Readback-required result binding is inconsistent")
    if row["decision"] == "fresh-plan-required" and (journal is None or journal["phase"] != "prepared" or row["status"] != "pending"):
        raise ContractError("BOOTSTRAP_RESULT", "Fresh-plan result binding is inconsistent")
    if row["decision"] == "hold" and row["status"] not in {"uncertain", "failed"}:
        raise ContractError("BOOTSTRAP_RESULT", "Held result binding is inconsistent")
    return dict(row)


def prepare_anchored_bootstrap(
    publisher_root: str,
    provision_plan: Mapping[str, Any],
    *,
    provision_inner_id: str,
    provision_config: Mapping[str, Any],
    reader: ReaderPort,
    installed_engine: Mapping[str, Any],
) -> PreparedAnchoredBootstrap:
    """Read/plan/bind an anchored bootstrap before any remote writer call."""

    provision_inner_id = _operation(provision_inner_id, "Provision inner operation")
    local = _github._local_snapshot(publisher_root)
    provision_config_norm = _validate_provision_config(provision_config, local["repository"], local["branch"])
    if provision_config_norm["engine"] != installed_engine:
        raise ContractError("BOOTSTRAP_ENGINE", "Provision inner engine differs from installed engine")
    if provision_config_norm["template"] != local["identity"]["template"] or provision_config_norm["adapter"] != local["identity"]["adapter"]:
        raise ContractError("BOOTSTRAP_CONFIG", "Provision inner template or adapter differs from local identity")
    outer_create = _validated_outer_create(
        publisher_root,
        provision_plan,
        provision_inner_id,
        provision_config_norm,
    )
    plan_outer = _validate_provision_plan(
        provision_plan,
        allow_outer_create=outer_create is not None,
    )
    if plan_outer["instance"] != {"id": local["manifest"]["instance_id"], "repository": local["repository"], "branch": local["branch"]}:
        raise ContractError("BOOTSTRAP_BINDING", "Provision instance identity differs from local instance")
    outer_commit, outer_tree, outer_metadata, _outer = _outer_anchor(
        publisher_root,
        plan_outer,
        provision_inner_id,
        provision_config=provision_config_norm,
    )
    node, node_metadata_sha256 = _node(reader, local["repository"], provision_config_norm)
    branch = _branch(_call(reader, "read_branch", local["repository"], local["branch"]), local["repository"], node_metadata_sha256)
    if branch["commit"] != outer_commit or branch["tree"] != outer_tree:
        raise ContractError("BOOTSTRAP_DRIFT", "Target branch does not equal the provision anchor")
    facts = _call(reader, "read_anchor_facts", local["repository"], outer_commit, outer_tree)
    anchor = _anchor_record(
        commit=outer_commit,
        tree=outer_tree,
        provision_metadata_sha256=outer_metadata,
        anchor_facts=facts,
        node_metadata_sha256=node_metadata_sha256,
        repository=local["repository"],
        node_id_sha256=_node_id_sha256(node["value"]),
    )
    observation, anchor = _fresh_observation(
        publisher_root,
        reader,
        repository=local["repository"],
        metadata_sha256=node_metadata_sha256,
        anchor=anchor,
    )
    existing_binding = _load_existing_binding(publisher_root, provision_inner_id)
    if existing_binding is not None:
        # A crash after binding installation must resume the exact accepted
        # timestamped plan.  Re-observe and validate it, but never call the
        # planner again and never mint a replacement evaluated_at timestamp.
        if existing_binding["provision_operation_id"] != plan_outer["operation_id"]:
            raise ContractError("BOOTSTRAP_BINDING", "Persisted provision operation differs")
        expected_outer_plan = provision_journal.record_sha256(plan_outer)
        expected_outer_config = provision_journal.record_sha256(provision_config_norm)
        persisted_config = existing_binding["config"]
        if (persisted_config["provision_plan_sha256"] != expected_outer_plan
                or persisted_config["provision_config_sha256"] != expected_outer_config):
            raise ContractError("BOOTSTRAP_BINDING", "Persisted outer plan/config identity differs")
        accepted = _validate_accepted_plan(existing_binding["plan"], observation, anchor)
        config = _validate_config(
            persisted_config,
            local=local,
            provision_operation_id=plan_outer["operation_id"],
        )
        plan_sha256 = _instance.record_sha256(accepted)
        config_sha256 = _instance.record_sha256(config)
        if existing_binding["plan_sha256"] != plan_sha256 or existing_binding["config_sha256"] != config_sha256:
            raise ContractError("BOOTSTRAP_BINDING", "Persisted accepted digest differs")
    else:
        accepted = _validate_accepted_plan(
            _github.plan_instance_github(
                publisher_root,
                observation,
                evaluated_at=_github._now(),
                bootstrap=True,
            ),
            observation,
            anchor,
        )
        config = _build_config(
            local,
            provision_plan=plan_outer,
            provision_config=provision_config_norm,
            provision_operation_id=plan_outer["operation_id"],
            node_metadata_sha256=node_metadata_sha256,
            node_id_sha256=provision_config_norm["node_id_sha256"],
            anchor=anchor,
            installed_engine=installed_engine,
        )
        plan_sha256 = _instance.record_sha256(accepted)
        config_sha256 = _instance.record_sha256(config)
        binding = {
            "schema": bootstrap_binding.SCHEMA,
            "operation_id": provision_inner_id,
            "provision_operation_id": plan_outer["operation_id"],
            "plan": accepted,
            "config": config,
            "plan_sha256": plan_sha256,
            "config_sha256": config_sha256,
        }
        # The foreign-journal check precedes binding installation.  A binding
        # without a recoverable remote journal is a defined no-write hold, not
        # permission to silently overwrite a different in-flight operation.
        if accepted["outcome"] == "create":
            _ensure_no_foreign_journals(publisher_root, provision_inner_id)
        bootstrap_binding.write_binding(publisher_root, binding)
    journal = None
    if accepted["outcome"] == "create":
        _ensure_no_foreign_journals(publisher_root, provision_inner_id)
        journal = _journal_for_plan(
            publisher_root,
            operation_id=provision_inner_id,
            repository=local["repository"],
            branch=local["branch"],
            plan_sha256=plan_sha256,
            config_sha256=config_sha256,
            anchor=anchor,
        )
    return PreparedAnchoredBootstrap(
        publisher_root=str(publisher_root),
        provision_operation_id=plan_outer["operation_id"],
        provision_inner_id=provision_inner_id,
        provision_plan=plan_outer,
        provision_config=provision_config_norm,
        plan=accepted,
        config=config,
        plan_sha256=plan_sha256,
        config_sha256=config_sha256,
        node=node,
        anchor=anchor,
        journal=journal,
    )


def _prepared_binding(prepared: PreparedAnchoredBootstrap) -> dict[str, Any]:
    if prepared.provision_plan.get("decision") in {"create", "adopt-exact"}:
        _validate_handoff_boundary(
            prepared.publisher_root,
            prepared.provision_plan,
            prepared.provision_inner_id,
            prepared.provision_config,
        )
    binding = bootstrap_binding.load_binding(prepared.publisher_root, prepared.provision_inner_id)
    if binding["provision_operation_id"] != prepared.provision_operation_id:
        raise ContractError("BOOTSTRAP_BINDING", "Persisted provision operation differs")
    if binding["plan_sha256"] != prepared.plan_sha256 or binding["config_sha256"] != prepared.config_sha256:
        raise ContractError("BOOTSTRAP_BINDING", "Persisted accepted digests differ")
    if binding["plan"] != dict(prepared.plan) or binding["config"] != dict(prepared.config):
        raise ContractError("BOOTSTRAP_BINDING", "Persisted accepted records differ")
    return binding


def _fresh_for_prepared(
    prepared: PreparedAnchoredBootstrap,
    reader: ReaderPort,
    *,
    expected_commit: str | None = None,
    expected_tree: str | None = None,
    require_plan_match: bool = True,
) -> tuple[dict[str, Any], dict[str, Any], dict[str, str]]:
    local = _github._local_snapshot(prepared.publisher_root)
    _validate_config(prepared.config, local=local, provision_operation_id=prepared.provision_operation_id)
    if local["identity"] != prepared.plan["local"]:
        raise ContractError("BOOTSTRAP_BINDING", "Local instance differs from accepted plan")
    node, metadata = _node(reader, local["repository"], prepared.provision_config)
    if metadata != prepared.config["node_metadata_sha256"] or _node_id_sha256(node["value"]) != prepared.config["node_id_sha256"]:
        raise ContractError("BOOTSTRAP_NODE", "Fresh node custody differs from accepted config")
    observation, anchor = _fresh_observation(
        prepared.publisher_root,
        reader,
        repository=local["repository"],
        metadata_sha256=metadata,
        anchor=prepared.anchor,
        expected_commit=expected_commit,
        expected_tree=expected_tree,
    )
    if require_plan_match and not _plan_matches_observation(prepared.plan, observation):
        raise ContractError("BOOTSTRAP_DRIFT", "Fresh observation differs from accepted plan")
    return observation, anchor, node


def _readback(
    prepared: PreparedAnchoredBootstrap,
    reader: ReaderPort,
    journal: remote_journal.RemoteApplyJournal,
) -> tuple[bool, str, str | None, dict[str, Any] | None]:
    try:
        record = journal.record
        target_commit = record["target_commit"]
        target_tree = record["target_tree"]
        observation, _anchor, _node_value = _fresh_for_prepared(
            prepared,
            reader,
            expected_commit=target_commit if target_commit is not None else prepared.anchor["commit"],
            expected_tree=target_tree if target_tree is not None else prepared.anchor["tree"],
            require_plan_match=False,
        )
    except ContractError:
        return False, "readback-failed", None, None
    observation_sha256 = _instance.record_sha256(observation)
    record = journal.record
    target_commit, target_tree = record["target_commit"], record["target_tree"]
    if target_commit is None or target_tree is None:
        return False, "target-not-observed", observation_sha256, observation
    if observation["commit"] != target_commit or observation["tree"] != target_tree:
        return False, "target-not-observed", observation_sha256, observation
    if observation["protected"] is not False:
        return False, "remote-policy-changed", observation_sha256, observation
    if not _github._remote_exact(_github._local_snapshot(prepared.publisher_root), observation):
        return False, "managed-file-readback", observation_sha256, observation
    return True, "exact-readback", observation_sha256, observation


def _finalize_apply(
    prepared: PreparedAnchoredBootstrap,
    reader: ReaderPort,
    base: Mapping[str, Any],
    journal: remote_journal.RemoteApplyJournal,
) -> dict[str, Any]:
    record = journal.record
    phase = record["phase"]
    if phase == "readback-pending":
        exact, reason, observation_sha256, observation = _readback(prepared, reader, journal)
        readback = {"reason": reason, "observation_sha256": observation_sha256}
        if exact:
            try:
                journal.mark_readback_complete(
                    commit=record["target_commit"], tree=record["target_tree"], predecessor_sha256=journal.digest
                )
            except ContractError:
                return _wrapper_result(
                    operation_id=prepared.provision_inner_id,
                    decision="readback-required",
                    status="uncertain",
                    plan_sha256=prepared.plan_sha256,
                    config_sha256=prepared.config_sha256,
                    anchor=prepared.anchor,
                    base_result=base,
                    journal=journal,
                    readback=readback,
                )
            base = _github._result(
                prepared.plan,
                status="completed",
                remote_state="observed",
                effects=list(base["effects"]),
                observation=observation,
            )
            return _wrapper_result(
                operation_id=prepared.provision_inner_id,
                decision="completed",
                status="completed",
                plan_sha256=prepared.plan_sha256,
                config_sha256=prepared.config_sha256,
                anchor=prepared.anchor,
                base_result=base,
                journal=journal,
                readback=readback,
            )
        return _wrapper_result(
            operation_id=prepared.provision_inner_id,
            decision="readback-required",
            status="uncertain",
            plan_sha256=prepared.plan_sha256,
            config_sha256=prepared.config_sha256,
            anchor=prepared.anchor,
            base_result=base,
            journal=journal,
            readback=readback,
        )
    if phase == "completed":
        exact, reason, observation_sha256, observation = _readback(prepared, reader, journal)
        if not exact or observation is None:
            return _wrapper_result(
                operation_id=prepared.provision_inner_id,
                decision="hold",
                status="uncertain",
                plan_sha256=prepared.plan_sha256,
                config_sha256=prepared.config_sha256,
                anchor=prepared.anchor,
                base_result=base,
                journal=journal,
                readback={"reason": reason, "observation_sha256": observation_sha256},
            )
        reconstructed = _reconstruct_base_result_checked(prepared, journal, observation)
        return _wrapper_result(
            operation_id=prepared.provision_inner_id,
            decision="completed",
            status="completed",
            plan_sha256=prepared.plan_sha256,
            config_sha256=prepared.config_sha256,
            anchor=prepared.anchor,
            base_result=reconstructed,
            journal=journal,
            readback={"reason": reason, "observation_sha256": observation_sha256},
        )
    decision = "fresh-plan-required" if phase == "prepared" else "hold"
    status = "pending" if decision == "fresh-plan-required" else "uncertain"
    return _wrapper_result(
        operation_id=prepared.provision_inner_id,
        decision=decision,
        status=status,
        plan_sha256=prepared.plan_sha256,
        config_sha256=prepared.config_sha256,
        anchor=prepared.anchor,
        base_result=base,
        journal=journal,
    )


def _reconstruct_base_result_checked(
    prepared: PreparedAnchoredBootstrap,
    journal: remote_journal.RemoteApplyJournal,
    observation: Mapping[str, Any],
) -> Mapping[str, Any]:
    if not _github._remote_exact(_github._local_snapshot(prepared.publisher_root), observation):
        raise ContractError("BOOTSTRAP_READBACK", "Managed files are not exact")
    return _reconstruct_base_result(prepared.plan, journal, observation)


def apply_anchored_bootstrap(
    prepared: PreparedAnchoredBootstrap,
    *,
    reader: ReaderPort,
    writer_factory: Callable[[RepositoryNodeId], WriterPort],
) -> Mapping[str, Any]:
    """Apply only the persisted accepted plan, then close by exact readback."""

    _prepared_binding(prepared)
    observation, _anchor, node = _fresh_for_prepared(prepared, reader)
    if prepared.plan["outcome"] == "noop":
        base = _github._result(
            prepared.plan,
            status="completed",
            remote_state="observed",
            effects=[{"step": "noop", "status": "completed", "path": row["path"], "basis": "exact-readback"} for row in prepared.plan["files"]],
            observation=observation,
        )
        return _wrapper_result(
            operation_id=prepared.provision_inner_id,
            decision="noop",
            status="completed",
            plan_sha256=prepared.plan_sha256,
            config_sha256=prepared.config_sha256,
            anchor=prepared.anchor,
            base_result=base,
            journal=None,
        )
    if prepared.plan["outcome"] != "create":
        reason = prepared.plan["reason"] or "plan-not-applicable"
        base = _base_result(
            prepared.plan,
            status="failed",
            remote_state=prepared.plan["remoteState"],
            reason=reason,
            observation=observation,
        )
        return _wrapper_result(
            operation_id=prepared.provision_inner_id,
            decision="hold",
            status="failed",
            plan_sha256=prepared.plan_sha256,
            config_sha256=prepared.config_sha256,
            anchor=prepared.anchor,
            base_result=base,
            journal=None,
        )
    if prepared.journal is None:
        raise ContractError("BOOTSTRAP_JOURNAL", "Create plan lacks a prepared remote journal")
    try:
        writer = writer_factory(RepositoryNodeId(prepared.node["repository"], prepared.node["value"]))
    except ContractError:
        raise
    except Exception:
        raise ContractError("BOOTSTRAP_WRITER", "Writer factory failed before mutation") from None
    _coordinator._ensure_writer_binding(writer, node, prepared.plan["instance"]["repository"])
    if not all(callable(getattr(writer, name, None)) for name in ("create_blob", "create_tree", "create_commit", "update_ref")):
        raise ContractError("BOOTSTRAP_WRITER", "Writer mutation boundary is incomplete")
    transport = _coordinator._JournaledTransport(
        _BoundReader(reader, prepared.plan["instance"]["repository"], prepared.config["node_metadata_sha256"]),
        writer,
        prepared.journal,
        prepared.plan,
        _github._local_snapshot(prepared.publisher_root),
    )
    base = _github.apply_instance_github(prepared.publisher_root, prepared.plan, transport)
    return _finalize_apply(prepared, reader, base, prepared.journal)


def _resume_prepared(
    publisher_root: str,
    *,
    provision_operation_id: str,
    reader: ReaderPort,
    installed_engine: Mapping[str, Any],
) -> tuple[PreparedAnchoredBootstrap, remote_journal.RemoteApplyJournal | None]:
    outer = provision_journal.load(publisher_root, provision_operation_id)
    inner_id = outer.record["inner"]["operation_id"]
    if inner_id is None:
        raise ContractError("BOOTSTRAP_OUTER", "Provision journal has no persisted inner operation")
    binding = bootstrap_binding.load_binding(publisher_root, inner_id)
    plan = dict(_github.validate_plan(binding["plan"]))
    local = _github._local_snapshot(publisher_root)
    config = _validate_config(binding["config"], local=local, provision_operation_id=provision_operation_id)
    _validate_engine(installed_engine)
    if config["engine"] != _validate_engine(installed_engine):
        raise ContractError("BOOTSTRAP_ENGINE", "Installed engine differs from persisted config")
    if config["local_identity"] != local["identity"] or plan["local"] != local["identity"]:
        raise ContractError("BOOTSTRAP_BINDING", "Local instance differs from persisted bootstrap binding")
    inner = outer.record["inner"]
    if outer.record["plan_sha256"] != config["provision_plan_sha256"]:
        raise ContractError("BOOTSTRAP_OUTER", "Outer provision plan digest differs from persisted config")
    if inner["plan_sha256"] != outer.record["plan_sha256"]:
        raise ContractError("BOOTSTRAP_OUTER", "Outer provision inner plan digest differs")
    if inner["config_sha256"] != config["provision_config_sha256"]:
        raise ContractError("BOOTSTRAP_OUTER", "Outer provision config digest differs")
    if (outer.record["anchor"]["commit"] != config["anchor"]["commit"]
            or outer.record["anchor"]["tree"] != config["anchor"]["tree"]):
        raise ContractError("BOOTSTRAP_OUTER", "Outer provision anchor differs from persisted bootstrap binding")
    node, metadata = _node(reader, local["repository"], {"node_id_sha256": config["node_id_sha256"]})
    if metadata != config["node_metadata_sha256"]:
        raise ContractError("BOOTSTRAP_NODE", "Fresh node metadata differs from persisted config")
    journal = None
    if plan["outcome"] == "create":
        try:
            journal = remote_journal.load(publisher_root, inner_id)
        except ContractError as error:
            if getattr(error, "code", None) != "JOURNAL_MISSING":
                raise
            # Binding installation is durable before remote-journal prepare.
            # A crash in that interval is a no-write hold; it is never a reason
            # to regenerate the timestamped plan or retry a remote mutation.
            journal = None
        if journal is not None:
            record = journal.record
            if (record["plan_sha256"] != binding["plan_sha256"] or record["config_sha256"] != binding["config_sha256"]
                    or record["expected_parent"] != config["anchor"]["commit"] or record["expected_tree"] != config["anchor"]["tree"]):
                raise ContractError("BOOTSTRAP_JOURNAL", "Remote journal differs from persisted bootstrap binding")
    prepared = PreparedAnchoredBootstrap(
        publisher_root=str(publisher_root),
        provision_operation_id=provision_operation_id,
        provision_inner_id=inner_id,
        provision_plan=outer.record,
        provision_config={"node_id_sha256": config["node_id_sha256"]},
        plan=plan,
        config=config,
        plan_sha256=binding["plan_sha256"],
        config_sha256=binding["config_sha256"],
        node=node,
        anchor=config["anchor"],
        journal=journal,
    )
    return prepared, journal


def resume_anchored_bootstrap(
    publisher_root: str,
    *,
    provision_operation_id: str,
    reader: ReaderPort,
    installed_engine: Mapping[str, Any],
) -> Mapping[str, Any]:
    """Close only from fresh exact observations; never replay a writer call."""

    prepared, journal = _resume_prepared(
        publisher_root,
        provision_operation_id=provision_operation_id,
        reader=reader,
        installed_engine=installed_engine,
    )
    if prepared.plan["outcome"] == "noop":
        observation, _anchor, _node_value = _fresh_for_prepared(prepared, reader)
        base = _github._result(
            prepared.plan,
            status="completed",
            remote_state="observed",
            effects=[{"step": "noop", "status": "completed", "path": row["path"], "basis": "exact-readback"} for row in prepared.plan["files"]],
            observation=observation,
        )
        return _wrapper_result(
            operation_id=prepared.provision_inner_id,
            decision="noop",
            status="completed",
            plan_sha256=prepared.plan_sha256,
            config_sha256=prepared.config_sha256,
            anchor=prepared.anchor,
            base_result=base,
            journal=None,
        )
    if prepared.plan["outcome"] != "create":
        observation, _anchor, _node_value = _fresh_for_prepared(prepared, reader)
        reason = prepared.plan["reason"] or "plan-not-applicable"
        base = _base_result(
            prepared.plan,
            status="failed",
            remote_state=prepared.plan["remoteState"],
            reason=reason,
            observation=observation,
        )
        return _wrapper_result(
            operation_id=prepared.provision_inner_id,
            decision="hold",
            status="failed",
            plan_sha256=prepared.plan_sha256,
            config_sha256=prepared.config_sha256,
            anchor=prepared.anchor,
            base_result=base,
            journal=None,
        )
    if journal is None:
        try:
            observation, _anchor, _node_value = _fresh_for_prepared(prepared, reader)
        except ContractError:
            observation = None
        base = _base_result(
            prepared.plan,
            status="uncertain",
            remote_state="unknown" if observation is None else "observed",
            reason="binding-without-journal",
            observation=observation,
        )
        return _wrapper_result(
            operation_id=prepared.provision_inner_id,
            decision="hold",
            status="uncertain",
            plan_sha256=prepared.plan_sha256,
            config_sha256=prepared.config_sha256,
            anchor=prepared.anchor,
            base_result=base,
            journal=None,
            readback={"reason": "binding-without-journal", "observation_sha256": None if observation is None else _instance.record_sha256(observation)},
        )
    record = journal.record
    if record["phase"] in {"prepared", "blob-submitting", "blob-created", "tree-submitting", "tree-created", "commit-submitting", "commit-created"}:
        observation, _anchor, _node_value = _fresh_for_prepared(prepared, reader)
    else:
        observation = None
    if record["phase"] == "readback-pending":
        exact, reason, observation_sha256, observation = _readback(prepared, reader, journal)
        if exact and observation is not None:
            journal.mark_readback_complete(
                commit=record["target_commit"], tree=record["target_tree"], predecessor_sha256=journal.digest
            )
            base = _reconstruct_base_result_checked(prepared, journal, observation)
            return _wrapper_result(
                operation_id=prepared.provision_inner_id,
                decision="completed",
                status="completed",
                plan_sha256=prepared.plan_sha256,
                config_sha256=prepared.config_sha256,
                anchor=prepared.anchor,
                base_result=base,
                journal=journal,
                readback={"reason": reason, "observation_sha256": observation_sha256},
            )
        base = _base_result(prepared.plan, status="uncertain", remote_state="unknown", reason=reason, observation=observation)
        return _wrapper_result(
            operation_id=prepared.provision_inner_id,
            decision="readback-required",
            status="uncertain",
            plan_sha256=prepared.plan_sha256,
            config_sha256=prepared.config_sha256,
            anchor=prepared.anchor,
            base_result=base,
            journal=journal,
            readback={"reason": reason, "observation_sha256": observation_sha256},
        )
    if record["phase"] == "completed":
        exact, reason, observation_sha256, observation = _readback(prepared, reader, journal)
        if not exact or observation is None:
            base = _base_result(prepared.plan, status="uncertain", remote_state="unknown", reason=reason, observation=observation)
            return _wrapper_result(
                operation_id=prepared.provision_inner_id,
                decision="hold",
                status="uncertain",
                plan_sha256=prepared.plan_sha256,
                config_sha256=prepared.config_sha256,
                anchor=prepared.anchor,
                base_result=base,
                journal=journal,
                readback={"reason": reason, "observation_sha256": observation_sha256},
            )
        base = _reconstruct_base_result_checked(prepared, journal, observation)
        return _wrapper_result(
            operation_id=prepared.provision_inner_id,
            decision="completed",
            status="completed",
            plan_sha256=prepared.plan_sha256,
            config_sha256=prepared.config_sha256,
            anchor=prepared.anchor,
            base_result=base,
            journal=journal,
            readback={"reason": reason, "observation_sha256": observation_sha256},
        )
    if record["phase"] in {"ref-submitting", "uncertain"}:
        ref_effect = next((effect for effect in record["effects"] if effect["step"] == "ref"), None)
        if ref_effect is not None and ref_effect["status"] in {"submitting", "uncertain"} and record["target_commit"] and record["target_tree"]:
            exact, reason, observation_sha256, observed = _readback(prepared, reader, journal)
            if exact and observed is not None:
                journal.mark_ref_readback_complete(
                    commit=record["target_commit"], tree=record["target_tree"], predecessor_sha256=journal.digest
                )
                base = _reconstruct_base_result_checked(prepared, journal, observed)
                return _wrapper_result(
                    operation_id=prepared.provision_inner_id,
                    decision="completed",
                    status="completed",
                    plan_sha256=prepared.plan_sha256,
                    config_sha256=prepared.config_sha256,
                    anchor=prepared.anchor,
                    base_result=base,
                    journal=journal,
                    readback={"reason": reason, "observation_sha256": observation_sha256},
                )
    if observation is None:
        try:
            observation, _anchor, _node_value = _fresh_for_prepared(prepared, reader)
        except ContractError:
            observation = None
    base = _base_result(prepared.plan, status="uncertain", remote_state="unknown" if observation is None else "observed", reason="journal-recovery-held", observation=observation)
    return _wrapper_result(
        operation_id=prepared.provision_inner_id,
        decision="hold",
        status="uncertain",
        plan_sha256=prepared.plan_sha256,
        config_sha256=prepared.config_sha256,
        anchor=prepared.anchor,
        base_result=base,
        journal=journal,
    )


def make_anchored_bootstrap_handoff(
    publisher_root: str,
    *,
    reader: ReaderPort,
    writer_factory: Callable[[RepositoryNodeId], WriterPort],
    installed_engine: Mapping[str, Any],
) -> Callable[[Mapping[str, Any], str, Mapping[str, Any]], Mapping[str, Any]]:
    """Return the existing three-argument provisioning handoff callback."""

    root = str(publisher_root)

    def handoff(
        provision_plan: Mapping[str, Any],
        provision_inner_id: str,
        provision_config: Mapping[str, Any],
    ) -> Mapping[str, Any]:
        prepared = prepare_anchored_bootstrap(
            root,
            provision_plan,
            provision_inner_id=provision_inner_id,
            provision_config=provision_config,
            reader=reader,
            installed_engine=installed_engine,
        )
        result = dict(apply_anchored_bootstrap(prepared, reader=reader, writer_factory=writer_factory))
        # Keep outer provisioning identity distinct from the inner bootstrap
        # plan/config fields.  These values are derived from the exact caller
        # records and are never compared to the inner digests by field name.
        result["provision_plan_sha256"] = provision_journal.record_sha256(prepared.provision_plan)
        result["provision_config_sha256"] = provision_journal.record_sha256(prepared.provision_config)
        return validate_result(result)

    return handoff


__all__ = [
    "ANCHOR_FACTS_SCHEMA",
    "GitHubAnchoredBootstrapReader",
    "PreparedAnchoredBootstrap",
    "ReaderPort",
    "SCHEMA_ANCHOR",
    "SCHEMA_CONFIG",
    "SCHEMA_RESULT",
    "WriterPort",
    "apply_anchored_bootstrap",
    "make_anchored_bootstrap_handoff",
    "prepare_anchored_bootstrap",
    "resume_anchored_bootstrap",
    "validate_result",
]
