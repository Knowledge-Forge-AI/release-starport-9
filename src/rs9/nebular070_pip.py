"""Authenticated offline pip input and command seams for Nebular 0.7.0.

The consumer imports these helpers only for the explicit Linux floor-consumer
bootstrap.  Keeping the source authentication contract here leaves the
historical consumer lifecycle and its default ``-m pip`` path unchanged.
"""
from __future__ import annotations

import os
import re
import stat
from pathlib import Path
from typing import Any, Mapping, Sequence

from rs9.tf_pypi_archive import fail, physical_bytes, sha256
from rs9.tf_pypi_model import strict_json


_NEBULAR_HEX64 = re.compile(r"[0-9a-f]{64}")
_NEBULAR_PIP_ROOT = "/inputs/consumer-tools/pip"
_NEBULAR_PIP_MANIFEST = "/inputs/consumer-tools/pip-source.json"
_NEBULAR_PIP_SCHEMA = "triad.existing-pip-source.v1"
_NEBULAR_PIP_VERSION = "25.0.1"
_NEBULAR_PIP_MANIFEST_BYTES = 148305
_NEBULAR_PIP_MANIFEST_SHA256 = "747d67c414904ef1969601125e5566c55df59f0fe87634da028ead6384c9c071"
_NEBULAR_PIP_RECORD_COUNT = 438
_NEBULAR_PIP_REGULAR_BYTES = 4958315
_NEBULAR_PIP_MAX_FILES = 5000
_NEBULAR_PIP_MAX_BYTES = 50 * 1024 * 1024


def _pip_safe_rel(value: Any) -> str:
    if (not isinstance(value, str) or not value or not value.isascii()
            or value.startswith("/") or "\\" in value or ":" in value
            or "\x00" in value):
        fail("NEBULAR_CAPTURE_PATH")
    parts = value.split("/")
    if any(part in ("", ".", "..") for part in parts):
        fail("NEBULAR_CAPTURE_PATH")
    return value


def _nebular_pip_inventory(root: Path) -> dict[str, dict[str, Any]]:
    """Inventory the immutable pip source without following links or specials."""
    if root.is_symlink() or not root.is_dir():
        fail("NEBULAR_PIP_BOOTSTRAP")
    records: dict[str, dict[str, Any]] = {}

    def visit(directory: Path, relative: str, depth: int) -> None:
        if depth > 32:
            fail("NEBULAR_PIP_BOOTSTRAP")
        try:
            entries = sorted(os.scandir(directory), key=lambda entry: entry.name)
        except OSError:
            fail("NEBULAR_PIP_BOOTSTRAP")
        for entry in entries:
            name = _pip_safe_rel(entry.name)
            path = relative + "/" + name if relative else name
            _pip_safe_rel(path)
            try:
                info = entry.stat(follow_symlinks=False)
            except OSError:
                fail("NEBULAR_PIP_BOOTSTRAP")
            if stat.S_ISLNK(info.st_mode) or stat.S_ISCHR(info.st_mode) or stat.S_ISBLK(info.st_mode):
                fail("NEBULAR_PIP_BOOTSTRAP")
            if stat.S_ISDIR(info.st_mode):
                visit(Path(entry.path), path, depth + 1)
                continue
            if not stat.S_ISREG(info.st_mode) or len(records) >= _NEBULAR_PIP_MAX_FILES:
                fail("NEBULAR_PIP_BOOTSTRAP")
            data = physical_bytes(Path(entry.path), limit=_NEBULAR_PIP_MAX_BYTES)
            if sum(row["bytes"] for row in records.values()) + len(data) > _NEBULAR_PIP_MAX_BYTES:
                fail("NEBULAR_PIP_BOOTSTRAP")
            records[path] = {
                "bytes": len(data),
                "sha256": sha256(data),
                "mode": stat.S_IMODE(info.st_mode),
            }

    visit(root, "", 0)
    return records


def _nebular_validate_pip_source(root: Path, manifest_path: Path) -> dict[str, Any]:
    """Join the retained pip manifest to actual regular bytes before use."""
    try:
        manifest_bytes = physical_bytes(manifest_path, limit=_NEBULAR_PIP_MANIFEST_BYTES)
    except Exception:
        fail("NEBULAR_PIP_BOOTSTRAP")
    if (len(manifest_bytes) != _NEBULAR_PIP_MANIFEST_BYTES
            or sha256(manifest_bytes) != _NEBULAR_PIP_MANIFEST_SHA256):
        fail("NEBULAR_PIP_BOOTSTRAP")
    try:
        manifest = strict_json(manifest_bytes)
    except Exception:
        fail("NEBULAR_PIP_BOOTSTRAP")
    if (not isinstance(manifest, Mapping)
            or manifest.get("schema") != _NEBULAR_PIP_SCHEMA
            or manifest.get("version") != _NEBULAR_PIP_VERSION
            or manifest.get("regularBytes") != _NEBULAR_PIP_REGULAR_BYTES
            or manifest.get("copied") is not False
            or not isinstance(manifest.get("records"), list)
            or len(manifest["records"]) != _NEBULAR_PIP_RECORD_COUNT):
        fail("NEBULAR_PIP_BOOTSTRAP")
    expected: dict[str, dict[str, Any]] = {}
    for row in manifest["records"]:
        if (not isinstance(row, Mapping) or "path" not in row
                or not isinstance(row.get("full9"), list) or len(row["full9"]) != 9
                or type(row["full9"][3]) is not int
                or type(row.get("bytes")) is not int or row["bytes"] < 0
                or not _NEBULAR_HEX64.fullmatch(str(row.get("sha256")))):
            fail("NEBULAR_PIP_BOOTSTRAP")
        path = _pip_safe_rel(row["path"])
        if path in expected or stat.S_IFMT(row["full9"][3]) != stat.S_IFREG:
            fail("NEBULAR_PIP_BOOTSTRAP")
        expected[path] = {
            "bytes": row["bytes"],
            "sha256": row["sha256"],
            "mode": stat.S_IMODE(row["full9"][3]),
        }
    actual = _nebular_pip_inventory(root)
    if actual != expected or sum(row["bytes"] for row in actual.values()) != _NEBULAR_PIP_REGULAR_BYTES:
        fail("NEBULAR_PIP_BOOTSTRAP")
    init = physical_bytes(root / "__init__.py", limit=4096)
    versions = re.findall(rb"(?m)^__version__\s*=\s*['\"]([^'\"]+)['\"]\s*$", init)
    if versions != [_NEBULAR_PIP_VERSION.encode()]:
        fail("NEBULAR_PIP_BOOTSTRAP")
    runner = root / "__pip-runner__.py"
    if runner.as_posix().split("/")[-1] not in actual:
        fail("NEBULAR_PIP_BOOTSTRAP")
    return {
        "root": root,
        "runner": runner,
        "manifest_sha256": _NEBULAR_PIP_MANIFEST_SHA256,
        "manifest_bytes": _NEBULAR_PIP_MANIFEST_BYTES,
        "version": _NEBULAR_PIP_VERSION,
        "regular_files": len(actual),
        "regular_bytes": _NEBULAR_PIP_REGULAR_BYTES,
    }


def _nebular_offline_pip_input(value: Mapping[str, Any] | None, target: str) -> dict[str, Any] | None:
    """Validate the explicit Linux-only mounted pip role; None preserves legacy behavior."""
    if value is None:
        return None
    if (not target.startswith("linux") or not isinstance(value, Mapping)
            or set(value) != {"root", "manifest"}
            or value.get("root") != _NEBULAR_PIP_ROOT
            or value.get("manifest") != _NEBULAR_PIP_MANIFEST):
        fail("NEBULAR_PIP_BOOTSTRAP")
    return _nebular_validate_pip_source(Path(_NEBULAR_PIP_ROOT), Path(_NEBULAR_PIP_MANIFEST))


def _nebular_pip_command(python: Path, args: Sequence[Any], pip_source: Mapping[str, Any] | None) -> list[Any]:
    if pip_source is None:
        return [python, "-I", "-B", "-m", "pip", *args]
    return [python, "-I", "-B", pip_source["runner"], *args]


def _nebular_require_pip_bootstrap(result: Mapping[str, Any]) -> None:
    line = result.get("stdout_token", "").strip()
    if (result.get("exit_code") != 0 or result.get("timed_out")
            or result.get("output_limit_exceeded") or not result.get("cleanup_known")
            or not result.get("output_complete")
            or not re.fullmatch(r"pip 25\.0\.1 from .+ \(python [0-9]+\.[0-9]+\)", line)):
        fail("NEBULAR_PIP_BOOTSTRAP")
