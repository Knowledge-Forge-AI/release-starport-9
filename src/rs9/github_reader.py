"""Bounded, read-only GitHub.com reader for the RS9 instance protocol.

The reader is deliberately separate from ``rs9.instance_github``'s fake
transport.  It invokes a fixed ``gh api`` GET command through an injectable
runner, validates the repository/branch/path before every request, and binds
content to immutable Git object IDs.  It contains no mutation operation.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import os
import re
import selectors
import signal
import subprocess
import time
from collections.abc import Callable, Mapping
from typing import Any, Protocol
from urllib.parse import quote

from rs9.errors import ContractError
from rs9.security import (
    scan_for_credentials,
    validate_repository,
    validate_safe_relative_posix_path,
)


GITHUB_HOST = "github.com"
GH_EXECUTABLE = "gh"
API_ACCEPT = "application/vnd.github+json"
DEFAULT_TIMEOUT_SECONDS = 30.0
MAX_OUTPUT_BYTES = 8 * 1024 * 1024
MAX_TREE_ENTRIES = 4096
MAX_NAMESPACE_ENTRIES = 256
MAX_FILE_BYTES = 1024 * 1024
MAX_NODE_ID_BYTES = 256

_HEX40 = re.compile(r"[0-9a-f]{40}")
_BRANCH = re.compile(r"[A-Za-z0-9][A-Za-z0-9._/-]{0,127}")
_BASE64 = re.compile(r"[A-Za-z0-9+/]*={0,2}")
_HTTP_STATUS = re.compile(rb"^HTTP/[^\s]+\s+(\d{3})(?:\s.*)?$")
_PERMISSION_FIELDS = ("admin", "maintain", "push", "triage", "pull")
_TREE_TYPES = {"blob", "tree", "commit"}


class GitHubReaderRunner(Protocol):
    """The narrow subprocess boundary used by :class:`GitHubReadTransport`."""

    def __call__(self, argv: list[str], **kwargs: Any) -> Any: ...


class _Response:
    __slots__ = ("status", "payload")

    def __init__(self, status: int, payload: Any) -> None:
        self.status = status
        self.payload = payload


def _kill_bounded_process(child: subprocess.Popen[bytes]) -> None:
    """Stop the exact default child and reap it without exposing diagnostics."""

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
    stdin: Any,
    stdout: Any,
    stderr: Any,
    check: bool,
    shell: bool,
    timeout: float,
) -> subprocess.CompletedProcess[bytes]:
    """Run the fixed command with concurrent, combined output custody."""

    if shell is not False or check is not False or stdout is not subprocess.PIPE or stderr is not subprocess.PIPE:
        raise ContractError("GITHUB_PROCESS", "GitHub command runner options are not bounded")
    child = subprocess.Popen(
        argv,
        stdin=stdin,
        stdout=stdout,
        stderr=stderr,
        shell=False,
        start_new_session=True,
    )
    captures = {child.stdout: bytearray(), child.stderr: bytearray()}
    reaped = False
    deadline = time.monotonic() + timeout
    try:
        with selectors.DefaultSelector() as selector:
            for pipe in captures:
                if pipe is None:
                    raise ContractError("GITHUB_PROCESS", "GitHub command pipes are unavailable")
                os.set_blocking(pipe.fileno(), False)
                selector.register(pipe, selectors.EVENT_READ)
            while selector.get_map():
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise subprocess.TimeoutExpired(argv, timeout)
                for key, _ in selector.select(remaining):
                    try:
                        total = sum(len(value) for value in captures.values())
                        chunk = os.read(key.fd, min(65536, MAX_OUTPUT_BYTES - total + 1))
                    except BlockingIOError:
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
    finally:
        if not reaped:
            _kill_bounded_process(child)
        for pipe in (child.stdout, child.stderr):
            if pipe is not None:
                pipe.close()


def _validate_sha(value: Any, context: str) -> str:
    if not isinstance(value, str) or _HEX40.fullmatch(value) is None:
        raise ContractError("GITHUB_INPUT", f"A lowercase Git SHA is required for {context}")
    return value


def _validate_branch(value: Any) -> str:
    if not isinstance(value, str) or _BRANCH.fullmatch(value) is None:
        raise ContractError("GITHUB_INPUT", "Invalid GitHub branch")
    if (".." in value or value.endswith(("/", ".")) or value.startswith(("/", "."))
            or any(part in {"", ".", ".."} for part in value.split("/"))):
        raise ContractError("GITHUB_INPUT", "Invalid GitHub branch")
    scan_for_credentials(value)
    return value


def _validate_repository_name(value: Any) -> str:
    validate_repository(value)
    scan_for_credentials(value)
    return value


def _validate_node_id(value: Any) -> str:
    if (not isinstance(value, str) or not 1 <= len(value) <= MAX_NODE_ID_BYTES
            or any(ord(char) <= 32 or ord(char) >= 127 for char in value)):
        raise ContractError("GITHUB_NODE_ID", "A bounded repository node ID is required")
    scan_for_credentials(value)
    return value


def _validate_path(value: Any, context: str = "path") -> str:
    validate_safe_relative_posix_path(value, context)
    scan_for_credentials(value)
    return value


def _git_blob_sha(data: bytes) -> str:
    return hashlib.sha1(b"blob " + str(len(data)).encode("ascii") + b"\0" + data).hexdigest()


def _json_bytes(value: bytes | str, *, limit: int) -> bytes:
    if isinstance(value, str):
        value = value.encode("utf-8")
    if not isinstance(value, bytes):
        raise ContractError("GITHUB_PROCESS", "GitHub command output has an invalid byte type")
    if len(value) > limit:
        raise ContractError("GITHUB_OUTPUT_LIMIT", "GitHub command output exceeds the bounded limit")
    return value


def _parse_output(value: bytes) -> tuple[int, bytes]:
    """Parse ``gh api --include`` output without retaining response headers."""

    raw = value
    first_line = raw.splitlines()[0] if raw.splitlines() else b""
    match = _HTTP_STATUS.fullmatch(first_line.strip())
    if match is None:
        # An injected runner may provide the body-only form.  The production
        # command always asks gh for headers, but accepting body-only 200
        # responses keeps the boundary easy to test without weakening errors.
        if not raw.lstrip().startswith((b"{", b"[")):
            raise ContractError("GITHUB_RESPONSE", "GitHub command output lacks a valid HTTP response")
        return 200, raw
    separator = b"\r\n\r\n"
    if separator not in raw:
        separator = b"\n\n"
    if separator not in raw:
        raise ContractError("GITHUB_RESPONSE", "GitHub command output has incomplete HTTP headers")
    _headers, body = raw.split(separator, 1)
    if re.search(rb"(?:^|\r?\n)HTTP/", body):
        raise ContractError("GITHUB_RESPONSE", "GitHub command returned an unexpected redirect chain")
    return int(match.group(1)), body


def _json_document(body: bytes) -> Mapping[str, Any] | list[Any]:
    try:
        value = json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError, TypeError, ValueError, RecursionError):
        raise ContractError("GITHUB_RESPONSE", "GitHub response is not valid JSON") from None
    if not isinstance(value, (Mapping, list)):
        raise ContractError("GITHUB_RESPONSE", "GitHub response JSON must be an object or array")
    return value


def _metadata_sha256(metadata: Mapping[str, Any]) -> str:
    material = {
        "repository": metadata["repository"],
        "permissions": metadata["permissions"],
        "authenticated": metadata["authenticated"],
        "permission_proof": metadata["permission_proof"],
        "node_id": metadata["node_id"],
    }
    encoded = json.dumps(material, ensure_ascii=True, sort_keys=True, separators=(",", ":")).encode("ascii")
    return hashlib.sha256(encoded).hexdigest()


class GitHubReadTransport:
    """Read-only GitHub.com transport matching the fake reader's read shape.

    ``runner`` receives a complete argument list and bounded subprocess
    keyword arguments.  It must return a ``subprocess.CompletedProcess``-like
    object with ``returncode``, ``stdout``, and ``stderr`` attributes.  The
    default runner drains both pipes concurrently and stops at the combined
    output bound; no shell is used and child stderr is never copied into an
    exception or result.
    """

    def __init__(
        self,
        runner: GitHubReaderRunner | None = None,
        *,
        timeout: float = DEFAULT_TIMEOUT_SECONDS,
        output_limit: int = MAX_OUTPUT_BYTES,
    ) -> None:
        if runner is not None and not callable(runner):
            raise ContractError("GITHUB_INPUT", "A callable GitHub runner is required")
        if type(timeout) not in (int, float) or not 0 < timeout <= 300:
            raise ContractError("GITHUB_INPUT", "GitHub timeout is outside the bounded range")
        if type(output_limit) is not int or not 1 <= output_limit <= MAX_OUTPUT_BYTES:
            raise ContractError("GITHUB_INPUT", "GitHub output limit is outside the bounded range")
        self._runner = _bounded_subprocess_run if runner is None else runner
        self._timeout = float(timeout)
        self._output_limit = output_limit

    @staticmethod
    def _endpoint(repository: str, *segments: str, query: str | None = None) -> str:
        owner, name = repository.split("/", 1)
        encoded = [quote(owner, safe=""), quote(name, safe="")]
        encoded.extend(quote(segment, safe="") for segment in segments)
        endpoint = "repos/" + "/".join(encoded)
        return endpoint if query is None else endpoint + "?" + query

    @staticmethod
    def _common(metadata: Mapping[str, Any], status: int = 200) -> dict[str, Any]:
        permissions = metadata["permissions"]
        return {
            "status": status,
            "transport": "ok",
            "authenticated": metadata["authenticated"],
            "repository": metadata["repository"],
            "permissions": permissions,
            "permission_proof": metadata["permission_proof"],
            "metadata_sha256": metadata["metadata_sha256"],
            # Read identity is not write/publication authority.
            "authority": {"read": True, "write": False, "publication": False},
        }

    def _command(self, endpoint: str) -> list[str]:
        return [
            GH_EXECUTABLE,
            "api",
            "--hostname",
            GITHUB_HOST,
            "--method",
            "GET",
            "--include",
            "--header",
            "Accept: " + API_ACCEPT,
            endpoint,
        ]

    def _request(self, endpoint: str) -> _Response:
        try:
            completed = self._runner(
                self._command(endpoint),
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
                shell=False,
                timeout=self._timeout,
            )
        except ContractError:
            raise
        except subprocess.TimeoutExpired:
            raise ContractError("GITHUB_TIMEOUT", "GitHub read command timed out") from None
        except OSError:
            raise ContractError("GITHUB_EXECUTABLE", "GitHub read executable is unavailable") from None
        except Exception:
            # The injected runner is an external boundary.  Do not expose its
            # exception text, which may contain command paths or credentials.
            raise ContractError("GITHUB_PROCESS", "GitHub read command failed") from None

        returncode = getattr(completed, "returncode", None)
        stdout = getattr(completed, "stdout", None)
        stderr = getattr(completed, "stderr", b"")
        if type(returncode) is not int:
            raise ContractError("GITHUB_PROCESS", "GitHub command result is malformed")
        raw = _json_bytes(stdout, limit=self._output_limit)
        _json_bytes(stderr, limit=self._output_limit)
        if len(raw) + len(stderr.encode("utf-8") if isinstance(stderr, str) else stderr) > self._output_limit:
            raise ContractError("GITHUB_OUTPUT_LIMIT", "GitHub command output exceeds the bounded limit")
        if returncode != 0 and not raw.strip():
            raise ContractError("GITHUB_PROCESS", "GitHub read command failed")
        status, body = _parse_output(raw)
        if returncode != 0 and status < 400:
            raise ContractError("GITHUB_PROCESS", "GitHub read command failed")
        if status < 100 or status > 599:
            raise ContractError("GITHUB_RESPONSE", "GitHub response status is invalid")
        if status == 204 or not body.strip():
            return _Response(status, None)
        return _Response(status, _json_document(body))

    def _request_json(
        self,
        endpoint: str,
        *,
        allow: frozenset[int] = frozenset({200}),
        allow_array: bool = False,
    ) -> _Response:
        response = self._request(endpoint)
        if response.status not in allow:
            raise ContractError("GITHUB_HTTP", "GitHub read returned a non-success HTTP status",
                                details={"http_status": response.status})
        if response.status == 200 and response.payload is None:
            raise ContractError("GITHUB_RESPONSE", "GitHub success response has no JSON body")
        allowed_types: type | tuple[type, ...] = (Mapping, list) if allow_array else Mapping
        if response.payload is not None and not isinstance(response.payload, allowed_types):
            raise ContractError("GITHUB_RESPONSE", "GitHub response JSON must be an object")
        return response

    def _metadata(self, repository: str, *, require_node_id: bool = False) -> dict[str, Any]:
        repository = _validate_repository_name(repository)
        response = self._request_json(self._endpoint(repository), allow=frozenset({200}))
        payload = response.payload
        if payload is None:
            raise ContractError("GITHUB_RESPONSE", "GitHub repository metadata is empty")
        full_name = payload.get("full_name")
        if not isinstance(full_name, str) or full_name.casefold() != repository.casefold():
            raise ContractError("GITHUB_IDENTITY", "GitHub repository identity does not match the declared repository")
        private = payload.get("private")
        if type(private) is not bool:
            raise ContractError("GITHUB_RESPONSE", "GitHub repository privacy metadata is malformed")
        permissions_value = payload.get("permissions")
        permissions: dict[str, bool] | None = None
        authenticated = False
        proof = "public-read-without-permission-proof"
        if isinstance(permissions_value, Mapping):
            if all(type(permissions_value.get(key)) is bool for key in _PERMISSION_FIELDS):
                permissions = {key: bool(permissions_value[key]) for key in _PERMISSION_FIELDS}
                authenticated = True
                proof = "repository-permissions"
        node_id = payload.get("node_id")
        if node_id is not None:
            node_id = _validate_node_id(node_id)
        if require_node_id and node_id is None:
            raise ContractError("GITHUB_NODE_ID", "GitHub repository metadata lacks a node ID")
        result = {
            "repository": {
                "full_name": full_name,
                "private": private,
            },
            "permissions": permissions,
            "authenticated": authenticated,
            "permission_proof": proof,
            "node_id": node_id,
        }
        result["metadata_sha256"] = _metadata_sha256(result)
        return result

    def read_repository(self, repository: str) -> dict[str, Any]:
        """Return fixed repository metadata without claiming write authority."""

        metadata = self._metadata(repository)
        return self._common(metadata)

    read_repository_metadata = read_repository

    def read_repository_node(self, repository: str) -> dict[str, Any]:
        """Read a repository-bound GraphQL node ID and permission metadata.

        The node record is an observation binding, not mutation authority. The
        coordinator must pair it with a fresh branch/tree read and separately
        construct the writer's shape-validated RepositoryNodeId.
        """

        metadata = self._metadata(repository, require_node_id=True)
        common = self._common(metadata)
        return {
            **common,
            "node": {
                "repository": metadata["repository"]["full_name"],
                "value": metadata["node_id"],
                "metadata_sha256": metadata["metadata_sha256"],
            },
        }

    read_repository_identity = read_repository_node
    read_repository_node_id = read_repository_node

    def _commit_tree(self, repository: str, commit: str) -> str:
        """Resolve and bind a commit SHA to its server-reported root tree."""

        commit = _validate_sha(commit, "commit")
        response = self._request_json(
            self._endpoint(repository, "git", "commits", commit),
            allow=frozenset({200}),
        )
        payload = response.payload
        if payload is None or payload.get("sha") != commit:
            raise ContractError("GITHUB_RESPONSE", "GitHub commit identity is malformed")
        tree_doc = payload.get("tree")
        if not isinstance(tree_doc, Mapping):
            raise ContractError("GITHUB_RESPONSE", "GitHub commit tree metadata is malformed")
        return _validate_sha(tree_doc.get("sha"), "commit tree")

    def read_branch(self, repository: str, branch: str) -> dict[str, Any]:
        repository = _validate_repository_name(repository)
        branch = _validate_branch(branch)
        metadata = self._metadata(repository)
        response = self._request_json(
            self._endpoint(repository, "branches", branch),
            allow=frozenset({200}),
        )
        payload = response.payload
        if payload is None or payload.get("name") != branch:
            raise ContractError("GITHUB_RESPONSE", "GitHub branch response identity is malformed")
        commit_doc = payload.get("commit")
        if not isinstance(commit_doc, Mapping):
            raise ContractError("GITHUB_RESPONSE", "GitHub branch commit metadata is malformed")
        commit = _validate_sha(commit_doc.get("sha"), "branch commit")
        tree = self._commit_tree(repository, commit)
        protected = payload.get("protected")
        if type(protected) is not bool:
            raise ContractError("GITHUB_RESPONSE", "GitHub branch protection metadata is malformed")
        return {
            **self._common(metadata),
            "branch": branch,
            "commit": commit,
            "tree": tree,
            "protected": protected,
        }

    def _tree_entries(
        self,
        repository: str,
        tree: str,
        *,
        expected_tree_sha: str | None = None,
    ) -> list[dict[str, Any]]:
        repository = _validate_repository_name(repository)
        tree = _validate_sha(tree, "tree")
        response = self._request_json(
            self._endpoint(repository, "git", "trees", tree, query="recursive=1"),
            allow=frozenset({200}),
        )
        payload = response.payload
        if payload is None:
            raise ContractError("GITHUB_RESPONSE", "GitHub tree response is empty")
        response_sha = _validate_sha(payload.get("sha"), "GitHub tree response")
        if expected_tree_sha is not None and response_sha != expected_tree_sha:
            raise ContractError("GITHUB_HASH", "GitHub tree identity does not match the declared tree")
        truncated = payload.get("truncated")
        if type(truncated) is not bool:
            raise ContractError("GITHUB_RESPONSE", "GitHub tree truncation metadata is malformed")
        if truncated:
            raise ContractError("GITHUB_TREE_LIMIT", "GitHub tree response was truncated")
        entries = payload.get("tree")
        if not isinstance(entries, list) or len(entries) > MAX_TREE_ENTRIES:
            raise ContractError("GITHUB_TREE_LIMIT", "GitHub tree entry bound exceeded")
        normalized: list[dict[str, Any]] = []
        seen: set[str] = set()
        for entry in entries:
            if not isinstance(entry, Mapping):
                raise ContractError("GITHUB_RESPONSE", "GitHub tree entry is malformed")
            path = entry.get("path")
            if not isinstance(path, str):
                raise ContractError("GITHUB_RESPONSE", "GitHub tree entry path is malformed")
            _validate_path(path, "Git tree path")
            if path in seen:
                raise ContractError("GITHUB_RESPONSE", "GitHub tree contains duplicate paths")
            seen.add(path)
            entry_type = entry.get("type")
            mode = entry.get("mode")
            sha = _validate_sha(entry.get("sha"), "Git tree object")
            if (not isinstance(entry_type, str) or entry_type not in _TREE_TYPES
                    or not isinstance(mode, str) or not re.fullmatch(r"[0-7]{6}", mode)):
                raise ContractError("GITHUB_RESPONSE", "GitHub tree entry type or mode is malformed")
            normalized.append({"path": path, "type": entry_type, "mode": mode, "sha": sha})
        return normalized

    @staticmethod
    def _kind(entry: Mapping[str, Any]) -> str:
        mode = entry["mode"]
        entry_type = entry["type"]
        if mode == "040000" and entry_type == "tree":
            return "tree"
        if mode == "120000" and entry_type == "blob":
            return "symlink"
        if mode in {"100644", "100755"} and entry_type == "blob":
            return "blob"
        if mode == "160000" and entry_type == "commit":
            return "commit"
        raise ContractError("GITHUB_RESPONSE", "GitHub tree entry mode is unsupported")

    def _contents_entry(
        self,
        repository: str,
        path: str,
        commit: str,
        *,
        verify_identity: bool = True,
        allow_array: bool = True,
    ) -> _Response:
        response = self._request_json(
            self._endpoint(
                repository,
                "contents",
                path,
                query="ref=" + quote(commit, safe=""),
            ),
            allow=frozenset({200, 404}),
            allow_array=allow_array,
        )
        if response.status == 404:
            return response
        payload = response.payload
        if isinstance(payload, list):
            if len(payload) > MAX_TREE_ENTRIES:
                raise ContractError("GITHUB_TREE_LIMIT", "GitHub directory entry bound exceeded")
            for row in payload:
                if not isinstance(row, Mapping) or not isinstance(row.get("path"), str) or not isinstance(row.get("type"), str):
                    raise ContractError("GITHUB_RESPONSE", "GitHub directory entry is malformed")
                _validate_path(row["path"], "GitHub directory path")
                if row["type"] not in {"file", "dir", "symlink", "submodule"}:
                    raise ContractError("GITHUB_RESPONSE", "GitHub directory entry type is malformed")
                _validate_sha(row.get("sha"), "directory entry")
            return response
        if payload is None or not isinstance(payload, Mapping):
            raise ContractError("GITHUB_RESPONSE", "GitHub content response is malformed")
        if not verify_identity:
            content_type = payload.get("type")
            if (not isinstance(content_type, str)
                    or content_type not in {"file", "symlink", "dir", "directory", "submodule"}):
                raise ContractError("GITHUB_RESPONSE", "GitHub content type is malformed")
            return response
        if payload.get("path") != path:
            raise ContractError("GITHUB_RESPONSE", "GitHub content path identity is malformed")
        _validate_sha(payload.get("sha"), "content blob")
        if not isinstance(payload.get("type"), str):
            raise ContractError("GITHUB_RESPONSE", "GitHub content type is malformed")
        return response

    def _blob(self, repository: str, blob_sha: str) -> bytes:
        response = self._request_json(self._endpoint(repository, "git", "blobs", blob_sha), allow=frozenset({200}))
        payload = response.payload
        if payload is None or payload.get("sha") != blob_sha or payload.get("encoding") != "base64":
            raise ContractError("GITHUB_RESPONSE", "GitHub blob identity or encoding is malformed")
        content = payload.get("content")
        if not isinstance(content, str):
            raise ContractError("GITHUB_RESPONSE", "GitHub blob content is malformed")
        compact = "".join(content.split())
        if len(compact) > ((MAX_FILE_BYTES + 2) // 3) * 4 + 4 or len(compact) % 4:
            raise ContractError("GITHUB_FILE_LIMIT", "GitHub blob content exceeds the bounded limit")
        if _BASE64.fullmatch(compact) is None:
            raise ContractError("GITHUB_RESPONSE", "GitHub blob content is not valid base64")
        try:
            data = base64.b64decode(compact.encode("ascii"), validate=True)
        except (UnicodeEncodeError, ValueError, binascii.Error):
            raise ContractError("GITHUB_RESPONSE", "GitHub blob content is not valid base64") from None
        if len(data) > MAX_FILE_BYTES:
            raise ContractError("GITHUB_FILE_LIMIT", "GitHub blob exceeds the bounded file limit")
        size = payload.get("size")
        if type(size) is not int or size != len(data):
            raise ContractError("GITHUB_RESPONSE", "GitHub blob size does not match decoded content")
        if _git_blob_sha(data) != blob_sha:
            raise ContractError("GITHUB_HASH", "GitHub blob SHA does not match decoded content")
        return data

    def read_file(self, repository: str, path: str, commit: str) -> dict[str, Any]:
        repository = _validate_repository_name(repository)
        path = _validate_path(path)
        commit = _validate_sha(commit, "commit")
        metadata = self._metadata(repository)
        tree = self._commit_tree(repository, commit)
        entries = self._tree_entries(repository, tree, expected_tree_sha=tree)
        entry = next((row for row in entries if row["path"] == path), None)
        if entry is None:
            common = self._common(metadata, 404)
            return {**common, "path": path, "commit": commit, "tree": tree,
                    "state": "missing", "type": "missing", "mode": None, "data": None, "size": None,
                    "sha256": None, "git_blob_sha": None, "git_sha": None}
        kind = self._kind(entry)
        contents = self._contents_entry(
            repository,
            path,
            commit,
            verify_identity=kind not in {"symlink", "tree"},
            allow_array=kind == "tree",
        )
        if contents.status != 200:
            raise ContractError("GITHUB_HASH", "GitHub content response disagrees with immutable tree")
        common = self._common(metadata)
        common["path"] = path
        common["commit"] = commit
        common["tree"] = tree
        payload = contents.payload
        if payload is None:
            raise ContractError("GITHUB_RESPONSE", "GitHub content response is empty")
        if isinstance(payload, list):
            if kind != "tree":
                raise ContractError("GITHUB_RESPONSE", "GitHub directory response and tree type disagree")
            return {
                **common,
                "status": 200,
                "state": "present",
                "type": kind,
                "mode": entry["mode"],
                "git_sha": entry["sha"],
                "data": None,
                "size": None,
                "sha256": None,
                "git_blob_sha": None,
            }
        if not isinstance(payload, Mapping):
            raise ContractError("GITHUB_RESPONSE", "GitHub content response is malformed")
        # Contents may follow a symlink and report its target identity.  The
        # immutable tree entry remains authoritative for the 120000 object.
        if kind not in {"symlink", "tree"} and entry["sha"] != payload["sha"]:
            raise ContractError("GITHUB_HASH", "GitHub content and immutable tree identities disagree")
        expected_content_type = {
            "blob": "file",
            "symlink": "symlink",
            "tree": "dir",
            "commit": "submodule",
        }[kind]
        accepted_content_types = {expected_content_type}
        if kind == "symlink":
            accepted_content_types.add("file")
        if expected_content_type == "dir":
            accepted_content_types.add("directory")
        if payload.get("type") not in accepted_content_types:
            raise ContractError("GITHUB_RESPONSE", "GitHub content and tree types disagree")
        result = {
            **common,
            "status": 200,
            "state": "present",
            "type": kind,
            "mode": entry["mode"],
            "git_sha": entry["sha"],
            "data": None,
            "size": None,
            "sha256": None,
            "git_blob_sha": None,
        }
        if kind in {"blob", "symlink"}:
            data = self._blob(repository, entry["sha"])
            result.update(
                data=data,
                size=len(data),
                sha256=hashlib.sha256(data).hexdigest(),
                git_blob_sha=_git_blob_sha(data),
            )
        return result

    def read_parent(self, repository: str, path: str, commit: str) -> dict[str, Any]:
        repository = _validate_repository_name(repository)
        path = _validate_path(path, "parent path")
        commit = _validate_sha(commit, "commit")
        metadata = self._metadata(repository)
        tree = self._commit_tree(repository, commit)
        entries = self._tree_entries(repository, tree, expected_tree_sha=tree)
        entry = next((row for row in entries if row["path"] == path), None)
        if entry is None:
            return {**self._common(metadata, 404), "path": path, "commit": commit, "tree": tree,
                    "state": "absent", "type": "missing", "mode": None, "git_sha": None}
        return {**self._common(metadata), "path": path, "commit": commit, "tree": tree,
                "state": "present", "type": self._kind(entry), "mode": entry["mode"], "git_sha": entry["sha"]}

    def read_namespace(self, repository: str, tree: str, prefix: str) -> dict[str, Any]:
        repository = _validate_repository_name(repository)
        tree = _validate_sha(tree, "tree")
        prefix = _validate_path(prefix, "namespace prefix")
        metadata = self._metadata(repository)
        entries = []
        for entry in self._tree_entries(repository, tree, expected_tree_sha=tree):
            path = entry["path"]
            if path == prefix or not path.startswith(prefix + "/"):
                continue
            if len(entries) >= MAX_NAMESPACE_ENTRIES:
                raise ContractError("GITHUB_TREE_LIMIT", "GitHub namespace entry bound exceeded")
            entries.append({"path": path, "type": self._kind(entry), "mode": entry["mode"], "sha256": None})
        entries.sort(key=lambda row: row["path"])
        return {
            **self._common(metadata),
            "tree": tree,
            "prefix": prefix,
            "state": "contains" if entries else "empty",
            "entries": entries,
        }


# Names that make the additive boundary discoverable without coupling callers
# to a prototype-specific class spelling.
GitHubReader = GitHubReadTransport
RealGitHubReader = GitHubReadTransport


__all__ = [
    "API_ACCEPT",
    "DEFAULT_TIMEOUT_SECONDS",
    "GH_EXECUTABLE",
    "GITHUB_HOST",
    "GitHubReadTransport",
    "GitHubReader",
    "RealGitHubReader",
    "MAX_FILE_BYTES",
    "MAX_NAMESPACE_ENTRIES",
    "MAX_NODE_ID_BYTES",
    "MAX_OUTPUT_BYTES",
    "MAX_TREE_ENTRIES",
]
