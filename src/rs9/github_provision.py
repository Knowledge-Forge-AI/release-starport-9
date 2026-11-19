"""Fixed GitHub provisioning transport for the v1alpha3 bootstrap boundary.

The transport owns only the approved GitHub host/organization endpoints used
by repository provisioning.  It does not own local state, journals, retries,
or publication.  The runner is injectable for tests; the default runner is
available only after explicit mutation opt-in.
"""

from __future__ import annotations

import base64
import hashlib
import json
import math
import subprocess
from collections.abc import Mapping
from typing import Any, Protocol
from urllib.parse import quote

from rs9.errors import ContractError
from rs9.github_reader import (
    API_ACCEPT,
    DEFAULT_TIMEOUT_SECONDS,
    GH_EXECUTABLE,
    GITHUB_HOST,
    MAX_OUTPUT_BYTES,
    _json_bytes,
    _json_document,
    _parse_output,
    _validate_branch,
    _validate_repository_name,
    _validate_sha,
)
from rs9.github_writer import COMMIT_AUTHOR_EMAIL, COMMIT_AUTHOR_NAME, _bounded_subprocess_run

APPROVED_OWNER = "Knowledge-Forge-AI"
DEFAULT_BRANCH = "main"
README_PATH = "README.md"
README_BYTES = b"unmanaged\n"
README_MESSAGE = "RS9 bootstrap README"
README_SHA256 = "2dc316e0f76f7005f7eb27803fe78f59ca49bcea0f69099d2eacc6640db564ff"
ZERO_OID = "0" * 40
MAX_REQUEST_BYTES = 8 * 1024 * 1024
MAX_NODE_ID_BYTES = 256
_GRAPHQL_ENDPOINT = "graphql"
_UPDATE_REFS_QUERY = """mutation UpdateRefs($input: UpdateRefsInput!) {
  updateRefs(input: $input) {
    clientMutationId
  }
}"""


class ProvisionRunner(Protocol):
    def __call__(self, argv: list[str], **kwargs: Any) -> Any: ...


def _validate_approved_repository(value: Any) -> str:
    _validate_repository_name(value)
    owner, name = value.split("/", 1)
    if owner.casefold() != APPROVED_OWNER.casefold():
        raise ContractError("PROVISION_OWNER", "Repository owner is outside the approved organization")
    if name != name.casefold() or name.startswith(("-", ".")) or name.endswith(("-", ".")):
        raise ContractError("PROVISION_REPOSITORY", "Repository name must be lower-case")
    if "--" in name:
        raise ContractError("PROVISION_REPOSITORY", "Repository name contains an invalid separator")
    return f"{APPROVED_OWNER}/{name}"


def _validate_node(value: Any) -> str:
    if (not isinstance(value, str) or not 1 <= len(value) <= MAX_NODE_ID_BYTES
            or any(ord(char) <= 32 or ord(char) >= 127 for char in value)):
        raise ContractError("PROVISION_NODE", "Repository node identity is invalid")
    # Keep node identifiers out of diagnostics and persisted raw payloads.
    from rs9.security import scan_for_credentials
    scan_for_credentials(value)
    return value


def _nonzero_sha(value: Any, context: str) -> str:
    result = _validate_sha(value, context)
    if result == ZERO_OID:
        raise ContractError("PROVISION_OID", "A nonzero Git object identity is required")
    return result


def _response_shape(value: Any) -> tuple[int, Mapping[str, Any]]:
    if not isinstance(value, Mapping) or type(value.get("status")) is not int:
        raise ContractError("PROVISION_RESPONSE", "Provision transport response is malformed")
    payload = value.get("payload")
    if not isinstance(payload, Mapping):
        raise ContractError("PROVISION_RESPONSE", "Provision transport response payload is malformed")
    return value["status"], payload


def _fixed_endpoint(repository: str, *segments: str) -> str:
    owner, name = _validate_approved_repository(repository).split("/", 1)
    encoded = [quote(owner, safe=""), quote(name, safe="")]
    encoded.extend(quote(segment, safe="") for segment in segments)
    return "repos/" + "/".join(encoded)


def classify_repository_response(value: Any) -> dict[str, Any]:
    """Classify one bounded repository GET response without inferring ownership."""

    status, payload = _response_shape(value)
    if status == 404:
        return {"state": "not-observed-404", "repository": None, "reason": "repository-404-not-observed"}
    if status != 200:
        return {"state": "unknown", "repository": None, "reason": "repository-read-unknown"}
    full_name = payload.get("full_name")
    private = payload.get("private")
    node_id = payload.get("node_id")
    if not isinstance(full_name, str) or not isinstance(private, bool) or not isinstance(node_id, str):
        return {"state": "unknown", "repository": None, "reason": "repository-response-malformed"}
    try:
        requested = _validate_approved_repository(full_name)
        node_id = _validate_node(node_id)
    except ContractError:
        return {"state": "unknown", "repository": None, "reason": "repository-identity-conflict"}
    if private is not True:
        return {"state": "unknown", "repository": None, "reason": "repository-visibility-conflict"}
    default_branch = payload.get("default_branch")
    if default_branch is not None and not isinstance(default_branch, str):
        return {"state": "unknown", "repository": None, "reason": "repository-response-malformed"}
    return {
        "state": "present",
        "repository": {
            "full_name": requested,
            "private": True,
            "node_id": node_id,
            "default_branch": default_branch,
        },
        "reason": "repository-present",
    }


def _client_mutation_id(repository: str, branch: str, anchor: str) -> str:
    material = "\0".join((repository, branch, anchor)).encode("utf-8")
    return "rs9-" + hashlib.sha256(material).hexdigest()[:32]


class GitHubProvisionTransport:
    """Fixed mutation transport; no mutation is enabled by default."""

    def __init__(
        self,
        runner: ProvisionRunner | None = None,
        *,
        allow_mutation: bool = False,
        timeout: float = DEFAULT_TIMEOUT_SECONDS,
        output_limit: int = MAX_OUTPUT_BYTES,
    ) -> None:
        if runner is not None and not callable(runner):
            raise ContractError("PROVISION_INPUT", "Provision runner must be callable")
        if type(allow_mutation) is not bool:
            raise ContractError("PROVISION_INPUT", "Provision mutation opt-in must be boolean")
        if type(timeout) not in (int, float) or not math.isfinite(timeout) or not 0 < timeout <= 300:
            raise ContractError("PROVISION_INPUT", "Provision timeout is outside the bounded range")
        if type(output_limit) is not int or not 1 <= output_limit <= MAX_OUTPUT_BYTES:
            raise ContractError("PROVISION_INPUT", "Provision output limit is outside the bounded range")
        self._runner = _bounded_subprocess_run if runner is None else runner
        self._allow_mutation = allow_mutation
        self._timeout = float(timeout)
        self._output_limit = output_limit

    @property
    def mutation_enabled(self) -> bool:
        return self._allow_mutation

    @staticmethod
    def _command(method: str, endpoint: str, *, has_body: bool) -> list[str]:
        command = [
            GH_EXECUTABLE, "api", "--hostname", GITHUB_HOST, "--method", method,
            "--include", "--header", "Accept: " + API_ACCEPT,
        ]
        if has_body:
            command.extend(["--header", "Content-Type: application/json", "--input", "-"])
        command.append(endpoint)
        return command

    def _request(
        self,
        method: str,
        endpoint: str,
        payload: Mapping[str, Any],
        *,
        accepted_statuses: frozenset[int],
        graphql: bool = False,
    ) -> dict[str, Any]:
        if self._allow_mutation is not True:
            raise ContractError("PROVISION_MUTATION_DISABLED", "Explicit provision mutation opt-in is required")
        try:
            body = json.dumps(payload, ensure_ascii=False, allow_nan=False, separators=(",", ":")).encode("utf-8")
        except (TypeError, ValueError, UnicodeError):
            raise ContractError("PROVISION_INPUT", "Provision request body is not serializable") from None
        if len(body) > MAX_REQUEST_BYTES:
            raise ContractError("PROVISION_INPUT_LIMIT", "Provision request body exceeds the bounded limit")
        try:
            completed = self._runner(
                self._command(method, endpoint, has_body=True),
                input=body,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
                shell=False,
                timeout=self._timeout,
            )
        except ContractError:
            raise
        except subprocess.TimeoutExpired:
            raise ContractError("PROVISION_TIMEOUT", "Provision transport timed out") from None
        except OSError:
            raise ContractError("PROVISION_EXECUTABLE", "Provision transport executable is unavailable") from None
        except Exception:
            raise ContractError("PROVISION_PROCESS", "Provision transport failed") from None
        returncode = getattr(completed, "returncode", None)
        stdout = getattr(completed, "stdout", None)
        stderr = getattr(completed, "stderr", b"")
        if type(returncode) is not int:
            raise ContractError("PROVISION_PROCESS", "Provision transport result is malformed")
        raw = _json_bytes(stdout, limit=self._output_limit)
        _json_bytes(stderr, limit=self._output_limit)
        try:
            status, response_body = _parse_output(raw)
            document = _json_document(response_body)
        except ContractError:
            raise
        if not isinstance(document, Mapping):
            raise ContractError("PROVISION_RESPONSE", "Provision transport response is not an object")
        if returncode != 0:
            raise ContractError("PROVISION_PROCESS", "Provision transport process failed")
        if status not in accepted_statuses:
            raise ContractError("PROVISION_HTTP", "Provision transport returned an unexpected status",
                                details={"http_status": status})
        if graphql and "errors" in document:
            raise ContractError("PROVISION_GRAPHQL", "Provision GraphQL response contains errors")
        return {"status": status, "payload": dict(document)}

    def create_repository(self, name: str) -> dict[str, Any]:
        if not isinstance(name, str) or name != name.casefold():
            raise ContractError("PROVISION_REPOSITORY", "Repository name must be lower-case")
        if _validate_approved_repository(APPROVED_OWNER + "/" + name).split("/", 1)[1] != name:
            raise ContractError("PROVISION_REPOSITORY", "Repository name is not canonical")
        return self._request(
            "POST",
            "orgs/" + quote(APPROVED_OWNER, safe="") + "/repos",
            {"name": name, "private": True, "auto_init": False},
            accepted_statuses=frozenset({201}),
        )

    def put_bootstrap_readme(self, repository: str) -> dict[str, Any]:
        repository = _validate_approved_repository(repository)
        author = {"name": COMMIT_AUTHOR_NAME, "email": COMMIT_AUTHOR_EMAIL}
        return self._request(
            "PUT",
            _fixed_endpoint(repository, "contents", README_PATH),
            {
                "message": README_MESSAGE,
                "content": base64.b64encode(README_BYTES).decode("ascii"),
                "branch": DEFAULT_BRANCH,
                "author": author,
                "committer": author,
            },
            accepted_statuses=frozenset({200, 201}),
        )

    def create_target_ref(
        self,
        repository: str,
        *,
        node_id: str,
        branch: str,
        anchor_commit: str,
    ) -> dict[str, Any]:
        repository = _validate_approved_repository(repository)
        node_id = _validate_node(node_id)
        branch = _validate_branch(branch)
        if branch == DEFAULT_BRANCH:
            raise ContractError("PROVISION_BRANCH", "Provision target branch must be non-default")
        anchor_commit = _nonzero_sha(anchor_commit, "anchor commit")
        mutation_id = _client_mutation_id(repository, branch, anchor_commit)
        response = self._request(
            "POST",
            _GRAPHQL_ENDPOINT,
            {
                "query": _UPDATE_REFS_QUERY,
                "variables": {
                    "input": {
                        "repositoryId": node_id,
                        "refUpdates": [{
                            "name": "refs/heads/" + branch,
                            "beforeOid": ZERO_OID,
                            "afterOid": anchor_commit,
                            "force": False,
                        }],
                        "clientMutationId": mutation_id,
                    },
                },
            },
            accepted_statuses=frozenset({200}),
            graphql=True,
        )
        payload = response["payload"]
        data = payload.get("data")
        update = data.get("updateRefs") if isinstance(data, Mapping) else None
        if not isinstance(update, Mapping) or update.get("clientMutationId") != mutation_id:
            raise ContractError("PROVISION_GRAPHQL", "Provision GraphQL mutation payload is malformed")
        return response


__all__ = [
    "APPROVED_OWNER",
    "DEFAULT_BRANCH",
    "GitHubProvisionTransport",
    "README_BYTES",
    "README_MESSAGE",
    "README_PATH",
    "README_SHA256",
    "ZERO_OID",
    "classify_repository_response",
]

