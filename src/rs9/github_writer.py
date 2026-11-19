"""Fixed, explicitly enabled GitHub.com write transport for RS9.

This module is only the remote object/ref transport.  It does not load a local
instance, create an apply journal, invoke the CLI, provision a repository, or
claim that a mutation was read back successfully.  The caller-owned
``rs9.instance_github`` state machine remains the owner of those boundaries.

Every endpoint and request shape is fixed in this module.  The subprocess
runner is injectable for contract tests; the default runner is available only
after a caller explicitly enables mutation on the transport constructor.
"""

from __future__ import annotations

import base64
import hashlib
import json
import math
import os
import re
import selectors
import signal
import subprocess
import time
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any, Protocol
from urllib.parse import quote

from rs9.errors import ContractError
from rs9.github_reader import (
    API_ACCEPT,
    DEFAULT_TIMEOUT_SECONDS,
    GITHUB_HOST,
    GH_EXECUTABLE,
    MAX_FILE_BYTES,
    MAX_OUTPUT_BYTES,
    MAX_TREE_ENTRIES,
    _git_blob_sha,
    _json_bytes,
    _json_document,
    _parse_output,
    _validate_branch,
    _validate_path,
    _validate_repository_name,
    _validate_sha,
)
from rs9.instance_github import COMMIT_MESSAGE, EXPECTED_MODE, MAX_MANAGED_PATHS


GRAPHQL_ENDPOINT = "graphql"
MAX_REQUEST_BYTES = 8 * 1024 * 1024
MAX_NODE_ID_BYTES = 256
MAX_CLIENT_MUTATION_ID_BYTES = 64
COMMIT_AUTHOR_NAME = "Samuel Leighton Lair"
COMMIT_AUTHOR_EMAIL = "sam.lair@knowledge-forge.ai"
UPDATE_REFS_QUERY = """mutation UpdateRefs($input: UpdateRefsInput!) {
  updateRefs(input: $input) {
    clientMutationId
  }
}"""

_HEX40 = re.compile(r"[0-9a-f]{40}")
_ZERO_SHA = "0" * 40
_TREE_TYPES = {"blob", "tree", "commit"}
_TREE_MODES = {"040000", "100644", "100755", "120000", "160000"}
_MUTATION_ID = re.compile(r"rs9-[0-9a-f]{32}")
_REST_WRITE_ENDPOINT = re.compile(r"repos/[^/]+/[^/]+/git/(?:blobs|trees|commits)")
MAX_RESPONSE_PATH_CHARS = 4096


class GitHubWriterRunner(Protocol):
    """The bounded subprocess seam used by :class:`GitHubWriteTransport`."""

    def __call__(self, argv: list[str], **kwargs: Any) -> Any: ...


@dataclass(frozen=True)
class RepositoryNodeId:
    """A shape-validated, declared-repository GraphQL node ID supplied by the caller.

    The repository binding prevents a caller from pairing a node ID declared
    for one repository with a mutation method naming another.  It proves only
    that the declaration and value have bounded shapes; it does not prove
    remote identity, permission, or write authority.  Those proofs remain
    owned by the reader/qualification boundary.
    """

    repository: str
    value: str

    def __post_init__(self) -> None:
        object.__setattr__(self, "repository", _validate_repository_name(self.repository))
        object.__setattr__(self, "value", _validate_node_id(self.value))


RepositoryNodeID = RepositoryNodeId


def _validate_node_id(value: Any) -> str:
    if (not isinstance(value, str) or not 1 <= len(value) <= MAX_NODE_ID_BYTES
            or any(ord(char) <= 32 or ord(char) >= 127 for char in value)):
        raise ContractError("GITHUB_NODE_ID", "A bounded repository node ID is required")
    return value


def _validate_nonzero_sha(value: Any, context: str, *, error_code: str = "GITHUB_INPUT") -> str:
    validated = _validate_sha(value, context)
    if validated == _ZERO_SHA:
        raise ContractError(error_code, "The zero Git object ID is forbidden for this operation")
    return validated


def _kill_bounded_process(child: subprocess.Popen[bytes]) -> None:
    try:
        os.killpg(child.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    except OSError:
        try:
            child.kill()
        except (ProcessLookupError, OSError):
            pass
    try:
        child.wait(timeout=5)
    except (subprocess.TimeoutExpired, OSError):
        pass


def _bounded_subprocess_run(
    argv: list[str],
    *,
    input: bytes,
    stdin: Any,
    stdout: Any,
    stderr: Any,
    check: bool,
    shell: bool,
    timeout: float,
) -> subprocess.CompletedProcess[bytes]:
    """Run one fixed command with bounded stdin/stdout/stderr custody."""

    if (stdin is not subprocess.PIPE or stdout is not subprocess.PIPE
            or stderr is not subprocess.PIPE or check is not False or shell is not False):
        raise ContractError("GITHUB_PROCESS", "GitHub command runner options are not bounded")
    if not isinstance(input, bytes) or len(input) > MAX_REQUEST_BYTES:
        raise ContractError("GITHUB_INPUT_LIMIT", "GitHub request body exceeds the bounded limit")

    child = subprocess.Popen(
        argv,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        shell=False,
        start_new_session=True,
    )
    if child.stdin is None or child.stdout is None or child.stderr is None:
        raise ContractError("GITHUB_PROCESS", "GitHub command pipes are unavailable")
    captures = {child.stdout: bytearray(), child.stderr: bytearray()}
    input_offset = 0
    reaped = False
    deadline = time.monotonic() + timeout
    try:
        with selectors.DefaultSelector() as selector:
            for pipe in captures:
                os.set_blocking(pipe.fileno(), False)
                selector.register(pipe, selectors.EVENT_READ, "output")
            os.set_blocking(child.stdin.fileno(), False)
            if input:
                selector.register(child.stdin, selectors.EVENT_WRITE, "input")
            else:
                child.stdin.close()
            while selector.get_map():
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise subprocess.TimeoutExpired(argv, timeout)
                for key, mask in selector.select(remaining):
                    if key.data == "input":
                        try:
                            written = os.write(child.stdin.fileno(), input[input_offset:])
                        except (BlockingIOError, InterruptedError):
                            continue
                        except BrokenPipeError:
                            raise ContractError("GITHUB_PROCESS", "GitHub command input pipe closed") from None
                        except OSError:
                            raise ContractError("GITHUB_PROCESS", "GitHub command input write failed") from None
                        input_offset += written
                        if input_offset == len(input):
                            selector.unregister(key.fileobj)
                            child.stdin.close()
                        continue
                    try:
                        chunk = os.read(key.fd, 65536)
                    except (BlockingIOError, InterruptedError):
                        continue
                    if not chunk:
                        selector.unregister(key.fileobj)
                        continue
                    captures[key.fileobj].extend(chunk)
                    if sum(len(value) for value in captures.values()) > MAX_OUTPUT_BYTES:
                        raise ContractError("GITHUB_OUTPUT_LIMIT", "GitHub command output exceeds the bounded limit")
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise subprocess.TimeoutExpired(argv, timeout)
        returncode = child.wait(timeout=remaining)
        reaped = True
        return subprocess.CompletedProcess(
            argv,
            returncode,
            bytes(captures[child.stdout]),
            bytes(captures[child.stderr]),
        )
    except OSError:
        raise ContractError("GITHUB_PROCESS", "GitHub command process failed") from None
    finally:
        if not reaped:
            _kill_bounded_process(child)
        for pipe in (child.stdin, child.stdout, child.stderr):
            if pipe is not None and not pipe.closed:
                pipe.close()


def _rest_endpoint(repository: str, *segments: str) -> str:
    repository = _validate_repository_name(repository)
    owner, name = repository.split("/", 1)
    encoded = [quote(owner, safe=""), quote(name, safe="")]
    encoded.extend(quote(segment, safe="") for segment in segments)
    return "repos/" + "/".join(encoded)


def _json_body(value: Mapping[str, Any]) -> bytes:
    try:
        body = json.dumps(
            value,
            ensure_ascii=False,
            allow_nan=False,
            separators=(",", ":"),
        ).encode("utf-8")
    except (TypeError, UnicodeError, ValueError):
        raise ContractError("GITHUB_INPUT", "GitHub request body is not serializable") from None
    if len(body) > MAX_REQUEST_BYTES:
        raise ContractError("GITHUB_INPUT_LIMIT", "GitHub request body exceeds the bounded limit")
    return body


def _response_sha(value: Any, context: str) -> str:
    if not isinstance(value, Mapping):
        raise ContractError("GITHUB_RESPONSE", "GitHub mutation response is malformed")
    try:
        return _validate_sha(value.get("sha"), context)
    except ContractError:
        raise ContractError("GITHUB_RESPONSE", "GitHub mutation response has an invalid object identity") from None


def _validate_response_tree_path(value: Any) -> str:
    """Validate only bounded response-path shape, not managed-path policy."""

    if not isinstance(value, str) or not 1 <= len(value) <= MAX_RESPONSE_PATH_CHARS:
        raise ContractError("GITHUB_RESPONSE", "GitHub tree response path shape is invalid")
    return value


def _validate_tree_entries(value: Any, *, response: bool = False) -> list[dict[str, str]]:
    if not isinstance(value, list) or len(value) > (MAX_TREE_ENTRIES if response else MAX_MANAGED_PATHS):
        raise ContractError("GITHUB_INPUT" if not response else "GITHUB_RESPONSE", "GitHub tree entry bound exceeded")
    normalized: list[dict[str, str]] = []
    for row in value:
        if not isinstance(row, Mapping):
            raise ContractError("GITHUB_INPUT" if not response else "GITHUB_RESPONSE", "GitHub tree entry is malformed")
        try:
            keys = set(row)
        except TypeError:
            raise ContractError("GITHUB_INPUT" if not response else "GITHUB_RESPONSE", "GitHub tree entry is malformed") from None
        required = {"path", "mode", "type", "sha"}
        if (keys != required and not response) or (not required <= keys and response):
            raise ContractError("GITHUB_INPUT" if not response else "GITHUB_RESPONSE", "GitHub tree entry fields are invalid")
        path = row.get("path")
        path = _validate_response_tree_path(path) if response else _validate_path(path, "GitHub tree path")
        mode = row.get("mode")
        entry_type = row.get("type")
        if not isinstance(mode, str) or mode not in _TREE_MODES:
            raise ContractError("GITHUB_INPUT" if not response else "GITHUB_RESPONSE", "GitHub tree entry mode is invalid")
        if not isinstance(entry_type, str) or entry_type not in _TREE_TYPES:
            raise ContractError("GITHUB_INPUT" if not response else "GITHUB_RESPONSE", "GitHub tree entry type is invalid")
        try:
            sha = _validate_sha(row.get("sha"), "GitHub tree object")
        except ContractError:
            raise ContractError("GITHUB_INPUT" if not response else "GITHUB_RESPONSE", "GitHub tree object identity is invalid") from None
        normalized.append({"path": path, "mode": mode, "type": entry_type, "sha": sha})
    if not response:
        paths = [row["path"] for row in normalized]
        if paths != sorted(paths) or len(set(paths)) != len(paths):
            raise ContractError("GITHUB_INPUT", "GitHub tree entries must be sorted and unique")
        if any(row["mode"] != EXPECTED_MODE or row["type"] != "blob" for row in normalized):
            raise ContractError("GITHUB_INPUT", "Only regular managed blob entries are writable")
    return normalized


def _validate_commit_identity(payload: Mapping[str, Any], *, tree: str, parent: str) -> str:
    commit_sha = _response_sha(payload, "created commit")
    for tree_value in (payload.get("tree"),):
        if tree_value is not None and _response_sha(tree_value, "commit tree") != tree:
            raise ContractError("GITHUB_HASH", "Created commit tree identity does not match the request")
    for field in ("author", "committer"):
        if field in payload:
            _validate_commit_author(payload[field])
    commit = payload.get("commit")
    if commit is not None:
        if not isinstance(commit, Mapping):
            raise ContractError("GITHUB_RESPONSE", "Created commit metadata is malformed")
        nested_tree = commit.get("tree")
        if nested_tree is not None and _response_sha(nested_tree, "commit tree") != tree:
            raise ContractError("GITHUB_HASH", "Created commit tree identity does not match the request")
        for field in ("author", "committer"):
            if field in commit:
                _validate_commit_author(commit[field])
        nested_parents = commit.get("parents")
        if nested_parents is not None:
            _validate_commit_parents(nested_parents, parent)
    top_parents = payload.get("parents")
    if top_parents is not None:
        _validate_commit_parents(top_parents, parent)
    return commit_sha


def _validate_commit_author(value: Any) -> None:
    if (not isinstance(value, Mapping) or value.get("name") != COMMIT_AUTHOR_NAME
            or value.get("email") != COMMIT_AUTHOR_EMAIL):
        raise ContractError("GITHUB_IDENTITY", "Created commit author identity is not canonical")


def _validate_commit_parents(value: Any, expected_parent: str) -> None:
    if not isinstance(value, list) or len(value) != 1 or not isinstance(value[0], Mapping):
        raise ContractError("GITHUB_RESPONSE", "Created commit parent metadata is malformed")
    try:
        observed = _validate_sha(value[0].get("sha"), "created commit parent")
    except ContractError:
        raise ContractError("GITHUB_RESPONSE", "Created commit parent metadata is malformed") from None
    if observed != expected_parent:
        raise ContractError("GITHUB_HASH", "Created commit parent identity does not match the request")


class GitHubWriteTransport:
    """Fixed GitHub object/ref writer matching ``GitHubInstanceTransport``.

    ``allow_mutation=True`` is an explicit constructor opt-in.  The opt-in is
    a local capability switch, not repository permission proof; the caller
    must supply a shape-validated :class:`RepositoryNodeId` for ref updates.
    The writer never performs readback, so a successful response is not an
    apply/completion claim.
    """

    def __init__(
        self,
        runner: GitHubWriterRunner | None = None,
        *,
        repository_node_id: str | RepositoryNodeId | None = None,
        allow_mutation: bool = False,
        timeout: float = DEFAULT_TIMEOUT_SECONDS,
        output_limit: int = MAX_OUTPUT_BYTES,
    ) -> None:
        if runner is not None and not callable(runner):
            raise ContractError("GITHUB_INPUT", "A callable GitHub runner is required")
        if type(allow_mutation) is not bool:
            raise ContractError("GITHUB_INPUT", "Mutation permission must be an explicit boolean")
        if type(timeout) not in (int, float) or not math.isfinite(timeout) or not 0 < timeout <= 300:
            raise ContractError("GITHUB_INPUT", "GitHub timeout is outside the bounded range")
        if type(output_limit) is not int or not 1 <= output_limit <= MAX_OUTPUT_BYTES:
            raise ContractError("GITHUB_INPUT", "GitHub output limit is outside the bounded range")
        if isinstance(repository_node_id, RepositoryNodeId):
            node_id = repository_node_id
        elif repository_node_id is None:
            node_id = None
        else:
            raise ContractError("GITHUB_NODE_ID", "A repository-bound node ID record is required")
        if allow_mutation is True and node_id is None:
            raise ContractError("GITHUB_NODE_ID", "A repository-bound node ID record is required")
        self._runner = _bounded_subprocess_run if runner is None else runner
        self._repository_node_id = node_id
        self._allow_mutation = allow_mutation
        self._timeout = float(timeout)
        self._output_limit = output_limit

    def repository_node_binding(self) -> dict[str, str | bool | None]:
        """Return a detached local capability declaration without remote I/O.

        This reports constructor configuration, not authenticated permission
        proof. Coordinators must compare it with their fresh reader-owned
        repository/node observation before permitting a mutation.
        """

        binding = self._repository_node_id
        return {
            "repository": None if binding is None else binding.repository,
            "node_id": None if binding is None else binding.value,
            "allow_mutation": self._allow_mutation,
        }

    def _mutation_repository(self, repository: str) -> str:
        repository = _validate_repository_name(repository)
        if self._repository_node_id is None:
            raise ContractError("GITHUB_NODE_ID", "A repository-bound node ID record is required")
        if self._repository_node_id.repository.casefold() != repository.casefold():
            raise ContractError("GITHUB_NODE_ID", "The repository node ID does not match the mutation repository")
        return repository

    def _require_mutation(self) -> None:
        if self._allow_mutation is not True:
            raise ContractError("GITHUB_MUTATION_DISABLED", "Explicit GitHub mutation opt-in is required")

    @staticmethod
    def _command(endpoint: str) -> list[str]:
        if endpoint != GRAPHQL_ENDPOINT and _REST_WRITE_ENDPOINT.fullmatch(endpoint) is None:
            raise ContractError("GITHUB_ENDPOINT", "GitHub write endpoint is not allowlisted")
        return [
            GH_EXECUTABLE,
            "api",
            "--hostname",
            GITHUB_HOST,
            "--method",
            "POST",
            "--include",
            "--header",
            "Accept: " + API_ACCEPT,
            "--header",
            "Content-Type: application/json",
            "--input",
            "-",
            endpoint,
        ]

    def _post(self, endpoint: str, payload: Mapping[str, Any], *, graphql: bool = False) -> Mapping[str, Any]:
        body = _json_body(payload)
        try:
            completed = self._runner(
                self._command(endpoint),
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
            raise ContractError("GITHUB_TIMEOUT", "GitHub write command timed out") from None
        except OSError:
            raise ContractError("GITHUB_EXECUTABLE", "GitHub write executable is unavailable") from None
        except Exception:
            raise ContractError("GITHUB_PROCESS", "GitHub write command failed") from None

        returncode = getattr(completed, "returncode", None)
        stdout = getattr(completed, "stdout", None)
        stderr = getattr(completed, "stderr", b"")
        if type(returncode) is not int:
            raise ContractError("GITHUB_PROCESS", "GitHub command result is malformed")
        raw = _json_bytes(stdout, limit=self._output_limit)
        stderr_bytes = _json_bytes(stderr, limit=self._output_limit)
        if len(raw) + len(stderr_bytes) > self._output_limit:
            raise ContractError("GITHUB_OUTPUT_LIMIT", "GitHub command output exceeds the bounded limit")
        if returncode != 0 and not raw.strip():
            raise ContractError("GITHUB_PROCESS", "GitHub write command failed")
        try:
            status, response_body = _parse_output(raw)
        except ContractError:
            if returncode != 0:
                raise ContractError("GITHUB_PROCESS", "GitHub write command failed") from None
            raise
        if status < 100 or status > 599:
            raise ContractError("GITHUB_RESPONSE", "GitHub response status is invalid")
        if status >= 400:
            raise ContractError("GITHUB_HTTP", "GitHub write returned a non-success HTTP status",
                                details={"http_status": status})
        if not response_body.strip():
            if returncode != 0:
                raise ContractError("GITHUB_PROCESS", "GitHub write command failed")
            raise ContractError("GITHUB_RESPONSE", "GitHub write response has no JSON body")
        try:
            document = _json_document(response_body)
        except ContractError:
            if returncode != 0:
                raise ContractError("GITHUB_PROCESS", "GitHub write command failed") from None
            raise
        if not isinstance(document, Mapping):
            raise ContractError("GITHUB_RESPONSE", "GitHub write response JSON must be an object")
        if graphql and status == 200 and "errors" in document:
            errors = document["errors"]
            if not isinstance(errors, list) or not errors:
                raise ContractError("GITHUB_GRAPHQL", "GitHub GraphQL mutation response is malformed")
            raise ContractError("GITHUB_GRAPHQL", "GitHub GraphQL mutation was rejected")
        if returncode != 0:
            raise ContractError("GITHUB_PROCESS", "GitHub write command failed")
        expected_statuses = {200} if graphql else {200, 201}
        if status not in expected_statuses:
            raise ContractError("GITHUB_HTTP", "GitHub write returned an unexpected HTTP status",
                                details={"http_status": status})
        return document

    def create_blob(self, repository: str, data: bytes) -> dict[str, str]:
        """Create one blob and verify its returned Git object identity."""

        self._require_mutation()
        repository = self._mutation_repository(repository)
        if not isinstance(data, bytes) or len(data) > MAX_FILE_BYTES:
            raise ContractError("GITHUB_INPUT_LIMIT", "GitHub blob bytes exceed the bounded file limit")
        response = self._post(
            _rest_endpoint(repository, "git", "blobs"),
            {"content": base64.b64encode(data).decode("ascii"), "encoding": "base64"},
        )
        sha = _response_sha(response, "created blob")
        expected = _git_blob_sha(data)
        if sha != expected:
            raise ContractError("GITHUB_HASH", "Created blob identity does not match the request")
        return {"sha": sha}

    def create_tree(self, repository: str, base_tree: str, entries: list[dict[str, str]]) -> dict[str, str]:
        """Create a tree against one observed base tree and validate its shape."""

        self._require_mutation()
        repository = self._mutation_repository(repository)
        base_tree = _validate_nonzero_sha(base_tree, "base tree")
        normalized = _validate_tree_entries(entries)
        response = self._post(
            _rest_endpoint(repository, "git", "trees"),
            {"base_tree": base_tree, "tree": normalized},
        )
        sha = _response_sha(response, "created tree")
        truncated = response.get("truncated")
        if truncated is True:
            raise ContractError("GITHUB_RESPONSE", "Created tree response is truncated")
        if truncated is not None and type(truncated) is not bool:
            raise ContractError("GITHUB_RESPONSE", "Created tree truncation metadata is malformed")
        if "tree" in response:
            _validate_tree_entries(response["tree"], response=True)
        return {"sha": sha}

    def create_commit(self, repository: str, message: str, tree: str, parent: str) -> dict[str, str]:
        """Create one canonical-authored commit with exactly one parent."""

        self._require_mutation()
        repository = self._mutation_repository(repository)
        if message != COMMIT_MESSAGE:
            raise ContractError("GITHUB_INPUT", "GitHub commit message is implementation-owned")
        tree = _validate_nonzero_sha(tree, "commit tree")
        parent = _validate_nonzero_sha(parent, "commit parent")
        author = {"name": COMMIT_AUTHOR_NAME, "email": COMMIT_AUTHOR_EMAIL}
        response = self._post(
            _rest_endpoint(repository, "git", "commits"),
            {
                "message": COMMIT_MESSAGE,
                "tree": tree,
                "parents": [parent],
                "author": author,
                "committer": author,
            },
        )
        return {"sha": _validate_commit_identity(response, tree=tree, parent=parent)}

    @staticmethod
    def _client_mutation_id(repository: str, branch: str, parent: str, commit: str) -> str:
        material = "\0".join((repository, branch, parent, commit)).encode("utf-8")
        return "rs9-" + hashlib.sha256(material).hexdigest()[:32]

    def update_ref(
        self,
        repository: str,
        branch: str,
        commit: str,
        *,
        force: bool = False,
        expected_parent: str | None = None,
    ) -> dict[str, Any]:
        """Move one branch through GraphQL ``updateRefs`` parent CAS."""

        self._require_mutation()
        repository = self._mutation_repository(repository)
        branch = _validate_branch(branch)
        commit = _validate_nonzero_sha(commit, "ref target", error_code="GITHUB_CAS")
        if type(force) is not bool or force is not False:
            raise ContractError("GITHUB_CAS", "Forced GitHub ref updates are forbidden")
        if expected_parent is None:
            raise ContractError("GITHUB_CAS", "An expected GitHub ref parent is required")
        expected_parent = _validate_nonzero_sha(expected_parent, "expected ref parent", error_code="GITHUB_CAS")
        if self._repository_node_id is None:
            raise ContractError("GITHUB_NODE_ID", "A validated repository node ID is required for ref updates")
        client_mutation_id = self._client_mutation_id(repository, branch, expected_parent, commit)
        if _MUTATION_ID.fullmatch(client_mutation_id) is None or len(client_mutation_id) > MAX_CLIENT_MUTATION_ID_BYTES:
            raise ContractError("GITHUB_INPUT", "GitHub client mutation ID is malformed")
        response = self._post(
            GRAPHQL_ENDPOINT,
            {
                "query": UPDATE_REFS_QUERY,
                "variables": {
                    "input": {
                        "repositoryId": self._repository_node_id.value,
                        "refUpdates": [{
                            "name": "refs/heads/" + branch,
                            "beforeOid": expected_parent,
                            "afterOid": commit,
                            "force": False,
                        }],
                        "clientMutationId": client_mutation_id,
                    },
                },
            },
            graphql=True,
        )
        errors = response.get("errors")
        if errors is not None:
            if not isinstance(errors, list) or not errors:
                raise ContractError("GITHUB_GRAPHQL", "GitHub GraphQL mutation response is malformed")
            raise ContractError("GITHUB_GRAPHQL", "GitHub GraphQL mutation was rejected")
        data = response.get("data")
        if not isinstance(data, Mapping) or not isinstance(data.get("updateRefs"), Mapping):
            raise ContractError("GITHUB_GRAPHQL", "GitHub GraphQL mutation payload is malformed")
        payload = data["updateRefs"]
        if payload.get("clientMutationId") != client_mutation_id:
            raise ContractError("GITHUB_GRAPHQL", "GitHub GraphQL mutation identity is malformed")
        return {"ok": True, "clientMutationId": client_mutation_id}


GitHubWriter = GitHubWriteTransport
RealGitHubWriter = GitHubWriteTransport


__all__ = [
    "COMMIT_AUTHOR_EMAIL",
    "COMMIT_AUTHOR_NAME",
    "COMMIT_MESSAGE",
    "GRAPHQL_ENDPOINT",
    "GitHubWriteTransport",
    "GitHubWriter",
    "GitHubWriterRunner",
    "MAX_REQUEST_BYTES",
    "RealGitHubWriter",
    "RepositoryNodeID",
    "RepositoryNodeId",
    "UPDATE_REFS_QUERY",
]
