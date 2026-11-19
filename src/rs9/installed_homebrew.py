"""Offline installed-CLI composition for one Homebrew formula candidate.

The pure renderer owns the normalized contract and formula bytes.  This
module owns only strict local input custody, a review receipt, and exclusive
output files.  It never fetches, executes, installs, or publishes anything.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import sys
from collections.abc import Mapping
from pathlib import Path
from typing import Any, BinaryIO

from rs9.errors import ContractError
from rs9.homebrew_renderer import (
    SCHEMA_RENDER,
    VARIANT_CLI,
    render_homebrew_formula,
)


SCHEMA_RESULT = "rs9.homebrew-cli-render-result.v1alpha1"
MAX_NORMALIZED_BYTES = 512 * 1024
MAX_PAYLOAD_FACTS_BYTES = 64 * 1024
MAX_FORMULA_BYTES = 64 * 1024
MAX_RESULT_BYTES = 256 * 1024
_PAYLOAD_KEYS = frozenset({"name", "url", "sha256", "version", "platform", "license"})
_FORMULA_NAME = re.compile(r"[a-z0-9]+(?:-[a-z0-9]+)*\.rb\Z")
_ENGINE_VERSION = re.compile(r"[A-Za-z0-9][A-Za-z0-9.+-]{0,63}\Z")
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")


class _DuplicateKey(ValueError):
    """Private parser signal kept separate from malformed JSON."""


def _reject(code: str) -> None:
    raise ContractError(code, "Homebrew CLI contract rejected")


def _identity(info: os.stat_result) -> tuple[int, int, int, int, int, int]:
    return (
        info.st_dev,
        info.st_ino,
        info.st_size,
        info.st_mode,
        info.st_mtime_ns,
        info.st_ctime_ns,
    )


def _as_path(value: str | os.PathLike[str], *, code: str) -> Path:
    if not isinstance(value, (str, os.PathLike)):
        _reject(code)
    try:
        raw = os.fspath(value)
    except (OSError, TypeError, ValueError):
        _reject(code)
    if isinstance(raw, bytes) or not raw or "\x00" in raw:
        _reject(code)
    try:
        path = Path(os.path.abspath(raw))
    except (OSError, TypeError, ValueError):
        _reject(code)
    return path


def _check_physical_ancestors(path: Path, *, code: str) -> None:
    current = path.parent
    while True:
        try:
            info = current.lstat()
        except OSError:
            _reject(code)
        if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
            _reject(code)
        if current.parent == current:
            return
        current = current.parent


def _read_fd(fd: int, limit: int, *, code: str) -> bytes:
    chunks: list[bytes] = []
    total = 0
    while True:
        try:
            chunk = os.read(fd, min(64 * 1024, limit + 1 - total))
        except OSError:
            _reject(code)
        if not chunk:
            break
        chunks.append(chunk)
        total += len(chunk)
        if total > limit:
            _reject("HOMEBREW_INPUT_LIMIT")
    return b"".join(chunks)


def _read_file(path_value: str | os.PathLike[str], *, limit: int) -> bytes:
    path = _as_path(path_value, code="HOMEBREW_INPUT_READ")
    _check_physical_ancestors(path, code="HOMEBREW_CUSTODY")
    fd: int | None = None
    try:
        before = path.lstat()
        if (stat.S_ISLNK(before.st_mode) or not stat.S_ISREG(before.st_mode)
                or before.st_size > limit):
            _reject("HOMEBREW_CUSTODY" if stat.S_ISLNK(before.st_mode)
                    or not stat.S_ISREG(before.st_mode) else "HOMEBREW_INPUT_LIMIT")
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
        fd = os.open(os.fspath(path), flags)
        opened = os.fstat(fd)
        if _identity(opened) != _identity(before):
            _reject("HOMEBREW_INPUT_CHANGED")
        raw = _read_fd(fd, limit, code="HOMEBREW_INPUT_READ")
        after = os.fstat(fd)
        current = path.lstat()
        if (_identity(after) != _identity(before)
                or _identity(current) != _identity(before)
                or len(raw) != before.st_size):
            _reject("HOMEBREW_INPUT_CHANGED")
        return raw
    except ContractError:
        raise
    except (OSError, TypeError, ValueError):
        _reject("HOMEBREW_INPUT_READ")
    finally:
        if fd is not None:
            try:
                os.close(fd)
            except OSError:
                pass


def _read_stdin(stream: BinaryIO, *, limit: int) -> bytes:
    reader = getattr(stream, "read", None)
    if not callable(reader):
        _reject("HOMEBREW_INPUT_READ")
    try:
        raw = reader(limit + 1)
    except (OSError, TypeError, ValueError):
        _reject("HOMEBREW_INPUT_READ")
    if not isinstance(raw, bytes):
        _reject("HOMEBREW_INPUT_READ")
    if len(raw) > limit:
        _reject("HOMEBREW_INPUT_LIMIT")
    return raw


def _read_source(
    value: str | os.PathLike[str],
    *,
    limit: int,
    stdin: BinaryIO,
) -> tuple[bytes, str]:
    if isinstance(value, str) and value == "-":
        return _read_stdin(stdin, limit=limit), "stdin"
    return _read_file(value, limit=limit), "file"


def _strict_pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in items:
        if key in result:
            raise _DuplicateKey
        result[key] = value
    return result


def _reject_constant(_value: str) -> None:
    raise ValueError("non-finite JSON number")


def _json_document(raw: bytes, *, duplicate_code: str, json_code: str) -> Mapping[str, Any]:
    try:
        value = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_strict_pairs,
            parse_constant=_reject_constant,
        )
    except _DuplicateKey:
        _reject(duplicate_code)
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError, ValueError):
        _reject(json_code)
    if not isinstance(value, Mapping):
        _reject(json_code)
    return value


def _sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _canonical_json(value: Mapping[str, Any]) -> bytes:
    try:
        raw = json.dumps(
            value,
            ensure_ascii=True,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("ascii") + b"\n"
    except (TypeError, ValueError, UnicodeError, RecursionError):
        _reject("HOMEBREW_OUTPUT_RESULT")
    if len(raw) > MAX_RESULT_BYTES:
        _reject("HOMEBREW_OUTPUT_LIMIT")
    return raw


def _canonical_input(value: Mapping[str, Any]) -> bytes:
    try:
        return json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError, UnicodeError, RecursionError):
        _reject("HOMEBREW_INPUT_JSON")


def _validate_engine(engine: Mapping[str, str]) -> dict[str, str]:
    if not isinstance(engine, Mapping) or set(engine) != {"distribution", "version"}:
        _reject("HOMEBREW_ENGINE")
    distribution = engine["distribution"]
    version = engine["version"]
    if distribution != "release-starport-9" or not isinstance(version, str) or not _ENGINE_VERSION.fullmatch(version):
        _reject("HOMEBREW_ENGINE")
    return {"distribution": distribution, "version": version}


def _validate_renderer_result(rendered: Mapping[str, Any]) -> tuple[dict[str, Any], str, bytes]:
    if not isinstance(rendered, Mapping):
        _reject("HOMEBREW_RENDER_RESULT")
    manifest = rendered.get("manifest")
    files = rendered.get("files")
    if not isinstance(manifest, Mapping) or not isinstance(files, Mapping):
        _reject("HOMEBREW_RENDER_RESULT")
    if manifest.get("schema") != SCHEMA_RENDER:
        _reject("HOMEBREW_RENDER_RESULT")
    if (manifest.get("status") != "unsigned-candidate"
            or manifest.get("publication_enabled") is not False
            or manifest.get("qualified") is not False):
        _reject("HOMEBREW_RENDER_RESULT")
    manifest_inputs = manifest.get("inputs")
    manifest_template = manifest.get("template")
    if (not isinstance(manifest_inputs, Mapping)
            or not {"normalized_sha256", "payload_facts_sha256"} <= set(manifest_inputs)
            or not isinstance(manifest_template, Mapping)
            or not {"id", "version", "sha256"} <= set(manifest_template)):
        _reject("HOMEBREW_RENDER_RESULT")
    if any(not isinstance(manifest_inputs[key], str) or not _SHA256.fullmatch(manifest_inputs[key])
           for key in ("normalized_sha256", "payload_facts_sha256")):
        _reject("HOMEBREW_RENDER_RESULT")
    if (any(not isinstance(manifest_template[key], str) or not manifest_template[key]
            for key in ("id", "version"))
            or not isinstance(manifest_template["sha256"], str)
            or not _SHA256.fullmatch(manifest_template["sha256"])):
        _reject("HOMEBREW_RENDER_RESULT")
    blockers = manifest.get("blockers", [])
    if (not isinstance(blockers, list)
            or any(not isinstance(item, str) or not item for item in blockers)):
        _reject("HOMEBREW_RENDER_RESULT")
    manifest_files = manifest.get("files")
    if not isinstance(manifest_files, list) or len(manifest_files) != 1:
        _reject("HOMEBREW_RENDER_RESULT")
    row = manifest_files[0]
    if not isinstance(row, Mapping) or set(row) != {"path", "size", "sha256", "mode"}:
        _reject("HOMEBREW_RENDER_RESULT")
    path = row["path"]
    if (not isinstance(path, str) or not path.startswith("Formula/")
            or path.count("/") != 1 or not _FORMULA_NAME.fullmatch(path[8:])):
        _reject("HOMEBREW_RENDER_RESULT")
    formula = files.get(path)
    if (not isinstance(formula, bytes) or len(formula) > MAX_FORMULA_BYTES
            or type(row["size"]) is not int or row["size"] != len(formula)
            or not isinstance(row["sha256"], str) or not _SHA256.fullmatch(row["sha256"])
            or row["sha256"] != _sha256(formula)
            or row["mode"] != "100644"):
        _reject("HOMEBREW_RENDER_RESULT")
    if set(files) != {path}:
        _reject("HOMEBREW_RENDER_RESULT")
    return dict(manifest), path, formula


def _write_new_file(directory_fd: int, name: str, data: bytes) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    fd: int | None = None
    try:
        fd = os.open(name, flags, 0o644, dir_fd=directory_fd)
        offset = 0
        while offset < len(data):
            written = os.write(fd, data[offset:])
            if written <= 0:
                raise OSError("short write")
            offset += written
        # This is our newly-created inode, never an existing path.  Set the
        # documented receipt mode despite a restrictive process umask.
        os.fchmod(fd, 0o644)
        info = os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o644
                or info.st_nlink != 1 or info.st_size != len(data)):
            raise OSError("output custody changed")
    finally:
        if fd is not None:
            os.close(fd)


def _write_output(output_value: str | os.PathLike[str], formula_path: str, formula: bytes, result: bytes) -> None:
    output = _as_path(output_value, code="HOMEBREW_CUSTODY")
    _check_physical_ancestors(output, code="HOMEBREW_CUSTODY")
    try:
        output.lstat()
    except FileNotFoundError:
        pass
    except OSError:
        _reject("HOMEBREW_CUSTODY")
    else:
        try:
            existing = output.lstat()
        except OSError:
            _reject("HOMEBREW_CUSTODY")
        if stat.S_ISLNK(existing.st_mode):
            _reject("HOMEBREW_CUSTODY")
        _reject("HOMEBREW_OUTPUT_EXISTS")

    output_fd: int | None = None
    formula_fd: int | None = None
    try:
        try:
            os.mkdir(os.fspath(output), 0o755)
        except FileExistsError:
            _reject("HOMEBREW_OUTPUT_EXISTS")
        except OSError:
            _reject("HOMEBREW_CUSTODY")
        output_fd = os.open(
            os.fspath(output),
            os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0),
        )
        os.mkdir("Formula", 0o755, dir_fd=output_fd)
        formula_fd = os.open(
            "Formula",
            os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0),
            dir_fd=output_fd,
        )
        _write_new_file(formula_fd, formula_path[8:], formula)
        _write_new_file(output_fd, "render-result.json", result)
    finally:
        if formula_fd is not None:
            os.close(formula_fd)
        if output_fd is not None:
            os.close(output_fd)


def render_homebrew_output(
    *,
    normalized_source: str | os.PathLike[str],
    payload_facts_source: str | os.PathLike[str],
    variant: str,
    output_dir: str | os.PathLike[str],
    engine: Mapping[str, str],
    stdin: BinaryIO | None = None,
) -> dict[str, Any]:
    """Read, render, and exclusively write one reviewable formula result."""
    if variant != VARIANT_CLI:
        _reject("HOMEBREW_INPUT_VARIANT")
    if normalized_source == "-" and payload_facts_source == "-":
        _reject("HOMEBREW_INPUT_STREAMS")
    if stdin is None:
        stdin = getattr(sys.stdin, "buffer", sys.stdin)
    engine_view = _validate_engine(engine)
    normalized_raw, normalized_mode = _read_source(
        normalized_source,
        limit=MAX_NORMALIZED_BYTES,
        stdin=stdin,
    )
    payload_raw, payload_mode = _read_source(
        payload_facts_source,
        limit=MAX_PAYLOAD_FACTS_BYTES,
        stdin=stdin,
    )
    normalized = _json_document(
        normalized_raw,
        duplicate_code="HOMEBREW_INPUT_DUPLICATE",
        json_code="HOMEBREW_INPUT_JSON",
    )
    payload = _json_document(
        payload_raw,
        duplicate_code="HOMEBREW_INPUT_DUPLICATE",
        json_code="HOMEBREW_INPUT_JSON",
    )
    if set(payload) != _PAYLOAD_KEYS:
        _reject("HOMEBREW_INPUT_PAYLOAD")

    rendered = render_homebrew_formula(normalized, payload, variant=VARIANT_CLI)
    manifest, formula_path, formula = _validate_renderer_result(rendered)
    canonical_payload = {
        "license": payload["license"],
        "name": payload["name"],
        "platform": payload["platform"],
        "sha256": payload["sha256"],
        "url": payload["url"],
        "version": payload["version"],
    }
    if (manifest["inputs"]["normalized_sha256"] != _sha256(_canonical_input(normalized))
            or manifest["inputs"]["payload_facts_sha256"] != _sha256(_canonical_input(canonical_payload))):
        _reject("HOMEBREW_RENDER_PROVENANCE")
    result: dict[str, Any] = {
        "schema": SCHEMA_RESULT,
        "status": "rendered",
        "publication_enabled": False,
        "qualified": False,
        "remote_state": "unknown",
        "variant": VARIANT_CLI,
        "blockers": list(manifest.get("blockers", [])),
        "engine": {
            **engine_view,
            "renderer_schema": SCHEMA_RENDER,
            "template_version": manifest["template"]["version"],
            "binding": "external-wheel-receipt-required",
        },
        "inputs": {
            "normalized_source_sha256": _sha256(normalized_raw),
            "normalized_canonical_sha256": manifest["inputs"]["normalized_sha256"],
            "payload_facts_source_sha256": _sha256(payload_raw),
            "payload_facts_canonical_sha256": manifest["inputs"]["payload_facts_sha256"],
            "normalized_source_mode": normalized_mode,
            "payload_facts_source_mode": payload_mode,
        },
        "template": dict(manifest["template"]),
        "manifest_sha256": _sha256(_canonical_json(manifest)),
        "files": [dict(manifest["files"][0])],
    }
    result_raw = _canonical_json(result)
    _write_output(output_dir, formula_path, formula, result_raw)
    return result


__all__ = ["SCHEMA_RESULT", "render_homebrew_output"]
