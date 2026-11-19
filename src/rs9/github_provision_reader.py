"""Read-only GitHub.com observations for the bounded provisioning boundary.

This adapter is deliberately narrower than a general GitHub client.  It uses
the accepted :class:`rs9.github_reader.GitHubReadTransport` as its sole
subprocess/parser boundary and projects only the fixed repository, branch,
ref, and bootstrap-README facts required by ``instance_provision``.  It has
no mutation, journal, retry, publication, or raw-response surface.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping
from typing import Any

from rs9.errors import ContractError
from rs9.github_provision import (
    APPROVED_OWNER,
    DEFAULT_BRANCH,
    README_BYTES,
    README_MESSAGE,
    README_PATH,
    README_SHA256,
    _validate_approved_repository,
)
from rs9.github_reader import (
    GITHUB_HOST,
    GitHubReadTransport,
    MAX_TREE_ENTRIES,
    _git_blob_sha,
    _metadata_sha256,
    _validate_branch,
    _validate_node_id,
    _validate_path,
    _validate_sha,
)
from rs9.github_writer import COMMIT_AUTHOR_EMAIL, COMMIT_AUTHOR_NAME
from rs9.instance import parse_rfc3339_utc
from rs9.security import scan_for_credentials


SCHEMA_ANCHOR = "rs9.github-provision-anchor.v1alpha1"
SCHEMA_PROOF = "rs9.github-provision-reader.v1alpha1"
BRANCH_PAGE_SIZE = 3
MAX_BRANCHES = BRANCH_PAGE_SIZE
MAX_PARENTS = 16
MAX_TEXT_BYTES = 4096
_PERMISSION_FIELDS = ("admin", "maintain", "push", "triage", "pull")
_CONTROL = re.compile(r"[\x00-\x1f\x7f]")


def _reject(code: str) -> None:
    raise ContractError(code, "GitHub provisioning read rejected")


def _repository(value: Any) -> str:
    try:
        result = _validate_approved_repository(value)
    except ContractError:
        raise ContractError("PROVISION_INPUT", "GitHub provisioning repository is invalid") from None
    scan_for_credentials(result)
    return result


def _branch(value: Any) -> str:
    try:
        result = _validate_branch(value)
    except ContractError:
        raise ContractError("PROVISION_INPUT", "GitHub provisioning branch is invalid") from None
    return result


def _text(
    value: Any,
    context: str,
    *,
    limit: int = MAX_TEXT_BYTES,
    allow_line_breaks: bool = False,
) -> str:
    controls = _CONTROL if not allow_line_breaks else re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
    if (not isinstance(value, str) or not value or len(value.encode("utf-8")) > limit
            or controls.search(value) is not None):
        raise ContractError("PROVISION_RESPONSE", f"GitHub {context} is malformed")
    scan_for_credentials(value)
    return value


def _timestamp(value: Any) -> str:
    raw = _text(value, "commit timestamp")
    try:
        parsed = parse_rfc3339_utc(raw)
    except ContractError:
        raise ContractError("PROVISION_RESPONSE", "GitHub commit timestamp is malformed") from None
    precision = "microseconds" if "." in raw else "seconds"
    return parsed.isoformat(timespec=precision).replace("+00:00", "Z")


def _canonical_json(value: Mapping[str, Any]) -> bytes:
    try:
        return json.dumps(
            value,
            ensure_ascii=True,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("ascii")
    except (TypeError, ValueError, UnicodeError, RecursionError):
        raise ContractError("PROVISION_RESPONSE", "GitHub projection is not canonical") from None


def _sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _single_blob_tree_sha(entries: list[Mapping[str, Any]]) -> str:
    """Compute a Git tree identity for exactly one flat blob row."""

    material = bytearray()
    try:
        if len(entries) != 1:
            raise ContractError("PROVISION_RESPONSE", "GitHub anchor tree is not a single blob")
        ordered = entries
        for entry in ordered:
            if not isinstance(entry, Mapping):
                raise ContractError("PROVISION_RESPONSE", "GitHub anchor tree row is malformed")
            mode = entry["mode"]
            path = entry["path"]
            sha = entry["sha"]
            if (entry.get("type") != "blob" or not isinstance(mode, str) or not isinstance(path, str)
                    or not isinstance(sha, str) or not re.fullmatch(r"[0-7]{6}", mode)
                    or mode not in {"100644", "100755"} or "/" in path
                    or not re.fullmatch(r"[0-9a-f]{40}", sha)):
                raise ContractError("PROVISION_RESPONSE", "GitHub anchor tree row is malformed")
            material.extend(mode.encode("ascii"))
            material.extend(b" ")
            material.extend(path.encode("utf-8"))
            material.extend(b"\0")
            material.extend(bytes.fromhex(sha))
    except (KeyError, TypeError, UnicodeEncodeError, ValueError):
        raise ContractError("PROVISION_RESPONSE", "GitHub anchor tree rows are malformed") from None
    encoded = bytes(material)
    return hashlib.sha1(b"tree " + str(len(encoded)).encode("ascii") + b"\0" + encoded).hexdigest()


EXPECTED_BOOTSTRAP_TREE_SHA = _single_blob_tree_sha([
    {"path": README_PATH, "type": "blob", "mode": "100644", "sha": _git_blob_sha(README_BYTES)},
])


def _unknown_payload(*, repository: str, state: str = "unknown", branch: str | None = None) -> dict[str, Any]:
    result: dict[str, Any] = {"state": state, "repository": repository}
    if branch is not None:
        result["branch"] = branch
    return result


def _safe_status(value: Any) -> int:
    if type(value) is not int or not 100 <= value <= 599:
        raise ContractError("PROVISION_READER", "GitHub read status is malformed")
    return value


class GitHubProvisionReadTransport:
    """Project fixed provisioning reads through one accepted reader instance.

    The constructor requires the exact accepted ``GitHubReadTransport`` class;
    tests inject its runner, never a second command executor.  The adapter
    calls only the reader's pinned private ``_request``, ``_endpoint``,
    ``_commit_tree``, and ``_tree_entries`` contracts plus the public
    ``read_file`` contract for the additional fixed endpoints that the public
    reader does not expose.
    """

    def __init__(self, reader: GitHubReadTransport) -> None:
        if type(reader) is not GitHubReadTransport:
            _reject("PROVISION_READER")
        if GITHUB_HOST != "github.com":
            _reject("PROVISION_READER")
        self._reader = reader

    def _endpoint(self, repository: str, *segments: str, query: str | None = None) -> str:
        try:
            endpoint = self._reader._endpoint(repository, *segments, query=query)
        except Exception:
            raise ContractError("PROVISION_READER", "GitHub endpoint contract is unavailable") from None
        if not isinstance(endpoint, str) or not endpoint.startswith("repos/"):
            raise ContractError("PROVISION_READER", "GitHub endpoint contract is malformed")
        return endpoint

    def _get(self, endpoint: str) -> tuple[int, Any]:
        try:
            response = self._reader._request(endpoint)
            status = _safe_status(getattr(response, "status", None))
            payload = getattr(response, "payload", None)
        except ContractError:
            raise ContractError("PROVISION_READER", "GitHub provisioning read failed") from None
        except Exception:
            raise ContractError("PROVISION_READER", "GitHub provisioning read failed") from None
        if status == 204:
            return status, None
        if payload is not None and not isinstance(payload, (Mapping, list)):
            raise ContractError("PROVISION_RESPONSE", "GitHub provisioning response is malformed")
        return status, payload

    def _tree_entries(self, repository: str, tree: str) -> list[dict[str, str]]:
        try:
            entries = self._reader._tree_entries(repository, tree, expected_tree_sha=tree)
        except ContractError:
            raise ContractError("PROVISION_READER", "GitHub anchor tree read failed") from None
        if not isinstance(entries, list) or len(entries) > MAX_TREE_ENTRIES:
            raise ContractError("PROVISION_RESPONSE", "GitHub anchor tree rows are malformed")
        projected: list[dict[str, str]] = []
        for row in entries:
            if not isinstance(row, Mapping):
                raise ContractError("PROVISION_RESPONSE", "GitHub anchor tree row is malformed")
            path = row.get("path")
            entry_type = row.get("type")
            mode = row.get("mode")
            try:
                path = _validate_path(path, "anchor tree path")
                sha = _validate_sha(row.get("sha"), "anchor tree row")
            except ContractError:
                raise ContractError("PROVISION_RESPONSE", "GitHub anchor tree row is malformed") from None
            if (not isinstance(entry_type, str) or entry_type not in {"blob", "tree", "commit"}
                    or not isinstance(mode, str) or re.fullmatch(r"[0-7]{6}", mode) is None):
                raise ContractError("PROVISION_RESPONSE", "GitHub anchor tree row is malformed")
            projected.append({"path": path, "type": entry_type, "mode": mode, "sha": sha})
        return projected

    @staticmethod
    def _proof(metadata: Mapping[str, Any]) -> dict[str, Any]:
        node_id = metadata["node_id"]
        permissions = metadata["permissions"]
        return {
            "schema": SCHEMA_PROOF,
            "repository": metadata.get("canonical_repository", metadata["repository"]["full_name"]),
            "authenticated": metadata["authenticated"],
            "permission_proof": metadata["permission_proof"],
            "permission_pull": permissions.get("pull") if isinstance(permissions, Mapping) else None,
            "metadata_sha256": metadata["metadata_sha256"],
            "node_id_sha256": _sha256(node_id.encode("utf-8")),
            "authority": {"read": True, "write": False, "publication": False},
        }

    def _repository_document(self, repository: str) -> tuple[dict[str, Any], dict[str, Any] | None]:
        repository = _repository(repository)
        status, payload = self._get(self._endpoint(repository))
        if status == 404:
            return {
                "status": status,
                "payload": {"state": "not-observed-404", "repository": repository},
            }, None
        if status != 200:
            return {
                "status": status,
                "payload": _unknown_payload(repository=repository),
            }, None
        if not isinstance(payload, Mapping):
            raise ContractError("PROVISION_RESPONSE", "GitHub repository response is malformed")
        full_name = payload.get("full_name")
        try:
            observed_name = _validate_approved_repository(full_name)
        except ContractError:
            raise ContractError("PROVISION_IDENTITY", "GitHub repository identity does not match") from None
        if observed_name.casefold() != repository.casefold():
            raise ContractError("PROVISION_IDENTITY", "GitHub repository identity does not match")
        private = payload.get("private")
        if type(private) is not bool:
            raise ContractError("PROVISION_RESPONSE", "GitHub repository privacy metadata is malformed")
        try:
            node_id = _validate_node_id(payload.get("node_id"))
        except ContractError:
            raise ContractError("PROVISION_IDENTITY", "GitHub repository node identity is malformed") from None
        try:
            default_branch = _validate_branch(payload.get("default_branch"))
        except ContractError:
            raise ContractError("PROVISION_RESPONSE", "GitHub default branch is malformed") from None
        permissions_value = payload.get("permissions")
        permissions: dict[str, bool] | None = None
        authenticated = False
        permission_proof = "public-read-without-permission-proof"
        if isinstance(permissions_value, Mapping) and all(
                type(permissions_value.get(key)) is bool for key in _PERMISSION_FIELDS):
            permissions = {key: bool(permissions_value[key]) for key in _PERMISSION_FIELDS}
            authenticated = True
            permission_proof = "repository-permissions"
        metadata = {
            # Keep the accepted reader's response spelling in the digest; the
            # canonical spelling remains the closed ReaderPort payload/proof.
            "repository": {"full_name": full_name, "private": private},
            "canonical_repository": observed_name,
            "permissions": permissions,
            "authenticated": authenticated,
            "permission_proof": permission_proof,
            "node_id": node_id,
        }
        metadata["metadata_sha256"] = _metadata_sha256(metadata)
        result = {
            "status": 200,
            "payload": {
                "full_name": observed_name,
                "private": private,
                "node_id": node_id,
                "default_branch": default_branch,
            },
            "proof": self._proof(metadata),
        }
        return result, metadata

    @staticmethod
    def _status_payload(status: int, payload: Any, *, repository: str, branch: str | None = None) -> dict[str, Any]:
        # A 404 is safe to preserve only for a proven authenticated absence.
        # Other 404s are normalized so instance_provision._branch_state cannot
        # turn a permission or repository race into absence.
        result_status = 500 if status == 404 else status
        return {
            "status": result_status,
            "payload": _unknown_payload(repository=repository, branch=branch),
        }

    def read_repository(self, repository: str) -> dict[str, Any]:
        """Return raw-to-closed repository metadata for ``ReaderPort``."""

        result, _metadata = self._repository_document(repository)
        return result

    def read_branch_inventory(self, repository: str, page_size: int) -> dict[str, Any]:
        """Read only page one of a fixed three-entry branch inventory."""

        if type(page_size) is not int or page_size != BRANCH_PAGE_SIZE:
            _reject("PROVISION_INPUT")
        repository = _repository(repository)
        repository_result, metadata = self._repository_document(repository)
        if metadata is None:
            return {
                "status": 500 if repository_result["status"] == 404 else repository_result["status"],
                "payload": {"names": [], "has_next": False, "pagination_class": "unknown"},
            }
        status, payload = self._get(
            self._endpoint(repository, "branches", query=f"per_page={BRANCH_PAGE_SIZE}&page=1")
        )
        proof = self._proof(metadata)
        if status != 200:
            return {**self._status_payload(status, payload, repository=repository), "proof": proof}
        if not isinstance(payload, list) or len(payload) > MAX_BRANCHES:
            raise ContractError("PROVISION_RESPONSE", "GitHub branch inventory is malformed or truncated")
        names: list[str] = []
        for row in payload:
            if not isinstance(row, Mapping):
                raise ContractError("PROVISION_RESPONSE", "GitHub branch inventory row is malformed")
            try:
                name = _branch(row.get("name"))
            except ContractError:
                raise ContractError("PROVISION_RESPONSE", "GitHub branch inventory name is malformed") from None
            commit = row.get("commit")
            if not isinstance(commit, Mapping):
                raise ContractError("PROVISION_RESPONSE", "GitHub branch inventory commit is malformed")
            try:
                _validate_sha(commit.get("sha"), "branch inventory commit")
            except ContractError:
                raise ContractError("PROVISION_RESPONSE", "GitHub branch inventory commit is malformed") from None
            if name in names:
                raise ContractError("PROVISION_RESPONSE", "GitHub branch inventory contains duplicates")
            names.append(name)
        names.sort()
        has_next = len(names) == BRANCH_PAGE_SIZE
        return {
            "status": 200,
            "payload": {
                "names": names,
                "has_next": has_next,
                "page_size": BRANCH_PAGE_SIZE,
                "pagination_class": "truncated" if has_next else "complete",
            },
            "proof": proof,
        }

    def _branch_result(self, repository: str, branch: str) -> dict[str, Any]:
        repository = _repository(repository)
        branch = _branch(branch)
        repository_result, metadata = self._repository_document(repository)
        if metadata is None:
            return {
                "status": 500,
                "payload": _unknown_payload(repository=repository, branch=branch),
            }
        status, payload = self._get(self._endpoint(repository, "branches", branch))
        proof = self._proof(metadata)
        if status == 404:
            if (proof["authenticated"] is not True or proof["permission_pull"] is not True
                    or not self._inventory_proves_absence(repository, branch, proof)):
                return {
                    "status": 500,
                    "payload": _unknown_payload(repository=repository, branch=branch),
                    "proof": proof,
                }
            return {
                "status": status,
                "payload": {"state": "absent", "repository": repository, "branch": branch, "commit": None, "tree": None},
                "proof": proof,
            }
        if status != 200:
            return {**self._status_payload(status, payload, repository=repository, branch=branch), "proof": proof}
        if not isinstance(payload, Mapping) or payload.get("name") != branch:
            raise ContractError("PROVISION_IDENTITY", "GitHub branch identity does not match")
        commit_doc = payload.get("commit")
        if not isinstance(commit_doc, Mapping):
            raise ContractError("PROVISION_RESPONSE", "GitHub branch commit is malformed")
        try:
            commit = _validate_sha(commit_doc.get("sha"), "branch commit")
            tree = self._reader._commit_tree(repository, commit)
        except ContractError:
            raise ContractError("PROVISION_READER", "GitHub branch commit binding failed") from None
        protected = payload.get("protected")
        if type(protected) is not bool:
            raise ContractError("PROVISION_RESPONSE", "GitHub branch protection metadata is malformed")
        return {
            "status": 200,
            "payload": {
                "repository": repository,
                "branch": branch,
                "commit": commit,
                "tree": tree,
                "protected": protected,
            },
            "proof": proof,
        }

    def read_branch(self, repository: str, branch: str) -> dict[str, Any]:
        return self._branch_result(repository, branch)

    def _inventory_proves_absence(
        self, repository: str, branch: str, proof: Mapping[str, Any]
    ) -> bool:
        try:
            inventory = self.read_branch_inventory(repository, BRANCH_PAGE_SIZE)
        except ContractError:
            return False
        inventory_proof = inventory.get("proof")
        payload = inventory.get("payload")
        if (inventory.get("status") != 200 or not isinstance(inventory_proof, Mapping)
                or inventory_proof.get("metadata_sha256") != proof.get("metadata_sha256")
                or not isinstance(payload, Mapping)
                or payload.get("has_next") is not False
                or payload.get("pagination_class") != "complete"):
            return False
        names = payload.get("names")
        return isinstance(names, list) and branch not in names

    def read_target_ref(self, repository: str, branch: str) -> dict[str, Any]:
        repository = _repository(repository)
        branch = _branch(branch)
        repository_result, metadata = self._repository_document(repository)
        if metadata is None:
            return {
                "status": 500,
                "payload": _unknown_payload(repository=repository, branch=branch),
            }
        status, payload = self._get(self._endpoint(repository, "git", "ref", "heads", branch))
        proof = self._proof(metadata)
        if status == 404:
            if (proof["authenticated"] is not True or proof["permission_pull"] is not True
                    or not self._inventory_proves_absence(repository, branch, proof)):
                return {
                    "status": 500,
                    "payload": _unknown_payload(repository=repository, branch=branch),
                    "proof": proof,
                }
            return {
                "status": status,
                "payload": {"state": "absent", "repository": repository, "branch": branch, "commit": None, "tree": None},
                "proof": proof,
            }
        if status != 200:
            return {**self._status_payload(status, payload, repository=repository, branch=branch), "proof": proof}
        if not isinstance(payload, Mapping) or payload.get("ref") != "refs/heads/" + branch:
            raise ContractError("PROVISION_IDENTITY", "GitHub target ref identity does not match")
        object_doc = payload.get("object")
        if not isinstance(object_doc, Mapping) or object_doc.get("type") != "commit":
            raise ContractError("PROVISION_RESPONSE", "GitHub target ref object is malformed")
        try:
            commit = _validate_sha(object_doc.get("sha"), "target ref commit")
            tree = self._reader._commit_tree(repository, commit)
        except ContractError:
            raise ContractError("PROVISION_READER", "GitHub target ref binding failed") from None
        return {
            "status": 200,
            "payload": {"repository": repository, "branch": branch, "ref": payload["ref"], "commit": commit, "tree": tree},
            "proof": proof,
        }

    def _commit_facts(self, repository: str, commit: str, tree: str) -> dict[str, Any]:
        status, payload = self._get(self._endpoint(repository, "git", "commits", commit))
        if status != 200 or not isinstance(payload, Mapping):
            raise ContractError("PROVISION_READER", "GitHub anchor commit read failed")
        if payload.get("sha") != commit:
            raise ContractError("PROVISION_IDENTITY", "GitHub anchor commit identity does not match")
        top_tree = payload.get("tree")
        if not isinstance(top_tree, Mapping):
            raise ContractError("PROVISION_RESPONSE", "GitHub anchor commit facts are malformed")
        try:
            if _validate_sha(top_tree.get("sha"), "anchor tree") != tree:
                raise ContractError("PROVISION_IDENTITY", "GitHub anchor tree identity does not match")
        except ContractError:
            raise
        message = _text(payload.get("message"), "commit message", allow_line_breaks=True)
        authors: dict[str, dict[str, str]] = {}
        for role in ("author", "committer"):
            person = payload.get(role)
            if not isinstance(person, Mapping):
                raise ContractError("PROVISION_RESPONSE", "GitHub anchor person facts are malformed")
            name = _text(person.get("name"), f"{role} name", limit=256)
            email = _text(person.get("email"), f"{role} email", limit=512)
            date = _timestamp(person.get("date"))
            authors[role] = {"name": name, "email": email, "date": date}
        parents_value = payload.get("parents")
        if not isinstance(parents_value, list) or len(parents_value) > MAX_PARENTS:
            raise ContractError("PROVISION_RESPONSE", "GitHub anchor parents are malformed")
        parents: list[str] = []
        for parent in parents_value:
            if not isinstance(parent, Mapping):
                raise ContractError("PROVISION_RESPONSE", "GitHub anchor parent is malformed")
            try:
                parent_sha = _validate_sha(parent.get("sha"), "anchor parent")
            except ContractError:
                raise ContractError("PROVISION_RESPONSE", "GitHub anchor parent is malformed") from None
            parents.append(parent_sha)
        return {
            "message": message,
            "author": authors["author"],
            "committer": authors["committer"],
            "parents": parents,
        }

    def read_anchor(self, repository: str, *, expected_commit: str | None = None) -> dict[str, Any]:
        """Read the fixed main README anchor and its canonical commit facts."""

        repository = _repository(repository)
        if expected_commit is not None:
            expected_commit = _validate_sha(expected_commit, "expected anchor commit")
        repository_result, metadata = self._repository_document(repository)
        if metadata is None:
            return {
                "status": 500 if repository_result["status"] == 404 else repository_result["status"],
                "payload": _unknown_payload(repository=repository),
            }
        branch = self._branch_result(repository, DEFAULT_BRANCH)
        if branch["status"] != 200 or not isinstance(branch.get("payload"), Mapping):
            return {
                "status": 500 if branch["status"] == 404 else branch["status"],
                "payload": _unknown_payload(repository=repository, branch=DEFAULT_BRANCH),
                "proof": self._proof(metadata),
            }
        branch_proof = branch.get("proof")
        if (not isinstance(branch_proof, Mapping)
                or branch_proof.get("metadata_sha256") != metadata["metadata_sha256"]):
            return {
                "status": 500,
                "payload": _unknown_payload(repository=repository, branch=DEFAULT_BRANCH),
                "proof": self._proof(metadata),
            }
        branch_payload = branch["payload"]
        commit = branch_payload["commit"]
        tree = branch_payload["tree"]
        if expected_commit is not None and commit != expected_commit:
            raise ContractError("PROVISION_IDENTITY", "GitHub anchor commit does not match the observed branch")
        try:
            facts = self._commit_facts(repository, commit, tree)
            tree_entries = self._tree_entries(repository, tree)
            file_result = self._reader.read_file(repository, README_PATH, commit)
        except ContractError:
            raise ContractError("PROVISION_READER", "GitHub anchor read failed") from None
        if not isinstance(file_result, Mapping):
            raise ContractError("PROVISION_RESPONSE", "GitHub anchor file result is malformed")
        if file_result.get("metadata_sha256") != metadata["metadata_sha256"]:
            return {
                "status": 500,
                "payload": _unknown_payload(repository=repository, branch=DEFAULT_BRANCH),
                "proof": self._proof(metadata),
            }
        file_status = _safe_status(file_result.get("status"))
        if file_status != 200:
            return {
                "status": file_status,
                "payload": {
                    "state": "missing" if file_status == 404 else "unknown",
                    "repository": repository,
                    "branch": DEFAULT_BRANCH,
                    "commit": commit,
                    "tree": tree,
                },
                "proof": self._proof(metadata),
            }
        data = file_result.get("data")
        if type(data) is not bytes:
            raise ContractError("PROVISION_RESPONSE", "GitHub anchor README bytes are malformed")
        readme_sha256 = _sha256(data)
        git_blob_sha = file_result.get("git_blob_sha")
        try:
            git_blob_sha = _validate_sha(git_blob_sha, "anchor README blob")
        except ContractError:
            raise ContractError("PROVISION_RESPONSE", "GitHub anchor README blob is malformed") from None
        mode = file_result.get("mode")
        file_type = file_result.get("type")
        if not isinstance(mode, str) or not re.fullmatch(r"[0-7]{6}", mode) or not isinstance(file_type, str):
            raise ContractError("PROVISION_RESPONSE", "GitHub anchor README file facts are malformed")
        readme_facts = {
            "path": README_PATH,
            "type": file_type,
            "mode": mode,
            "size": len(data),
            "git_sha": git_blob_sha,
            "sha256": readme_sha256,
        }
        projection = {
            "schema": SCHEMA_ANCHOR,
            "repository": repository,
            "branch": DEFAULT_BRANCH,
            "commit": commit,
            "tree": tree,
            "readme": readme_facts,
            "commit_facts": facts,
        }
        metadata_sha256 = _sha256(_canonical_json(projection))
        expected_tree_entry = {
            "path": README_PATH,
            "type": "blob",
            "mode": "100644",
            "sha": _git_blob_sha(README_BYTES),
        }
        tree_exact = (
            len(tree_entries) == 1
            and dict(tree_entries[0]) == expected_tree_entry
            and _single_blob_tree_sha(tree_entries) == tree == EXPECTED_BOOTSTRAP_TREE_SHA
        )
        exact = (
            data == README_BYTES
            and readme_sha256 == README_SHA256
            and git_blob_sha == _git_blob_sha(README_BYTES)
            and file_type == "blob"
            and mode == "100644"
            and facts["message"] == README_MESSAGE
            and facts["parents"] == []
            and tree_exact
            and facts["author"] == {"name": COMMIT_AUTHOR_NAME, "email": COMMIT_AUTHOR_EMAIL, "date": facts["author"]["date"]}
            and facts["committer"] == {"name": COMMIT_AUTHOR_NAME, "email": COMMIT_AUTHOR_EMAIL, "date": facts["committer"]["date"]}
        )
        payload = {
            "schema": SCHEMA_ANCHOR,
            "state": "exact" if exact else "drifted",
            "repository": repository,
            "branch": DEFAULT_BRANCH,
            "path": README_PATH,
            "commit": commit,
            "tree": tree,
            "readme_state": "exact" if exact else "drifted",
            "readme_sha256": readme_sha256,
            "readme_git_sha": git_blob_sha,
            "readme_size": len(data),
            "readme_mode": mode,
            "message": facts["message"],
            "author": facts["author"],
            "committer": facts["committer"],
            "parents": facts["parents"],
            "metadata_sha256": metadata_sha256,
            "repository_metadata_sha256": metadata["metadata_sha256"],
        }
        return {"status": 200, "payload": payload, "proof": self._proof(metadata)}


GitHubProvisionReader = GitHubProvisionReadTransport


__all__ = [
    "BRANCH_PAGE_SIZE",
    "EXPECTED_BOOTSTRAP_TREE_SHA",
    "GitHubProvisionReadTransport",
    "GitHubProvisionReader",
    "SCHEMA_ANCHOR",
    "SCHEMA_PROOF",
]
