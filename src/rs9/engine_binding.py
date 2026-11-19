"""Bounded local binding between an engine wheel and the running ``rs9``.

The binding is deliberately independent of package installation and network
state.  It hashes the wheel archive itself and compares every packaged
``rs9`` member with the bytes exposed by the installed distribution.  Version
metadata and ``direct_url`` files are descriptive only; neither is an
artifact identity.
"""

from __future__ import annotations

import hashlib
import fcntl
import importlib
import importlib.metadata
import io
import json
import os
import re
import stat
import zipfile
from collections.abc import Mapping
from email.parser import Parser
from pathlib import Path
from typing import Any

from rs9.errors import ContractError


SCHEMA = "rs9.engine-artifact-binding.v1alpha1"
DIST_NAME = "release-starport-9"
PACKAGE_NAME = "rs9"
MAX_WHEEL_BYTES = 64 * 1024 * 1024
MAX_MEMBER_BYTES = 4 * 1024 * 1024
MAX_TOTAL_MEMBER_BYTES = 32 * 1024 * 1024
MAX_MEMBERS = 4096
MAX_METADATA_BYTES = 256 * 1024
_VERSION = re.compile(r"[A-Za-z0-9][A-Za-z0-9.+-]{0,63}")


def _reject(code: str) -> None:
    raise ContractError(code, "Engine artifact binding rejected")


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _safe_member(name: Any) -> str:
    if not isinstance(name, str) or not name or len(name) > 4096:
        _reject("ENGINE_ARCHIVE")
    if "\\" in name or "\x00" in name or name.startswith("/"):
        _reject("ENGINE_ARCHIVE")
    parts = name.split("/")
    if any(part in {".", ".."} for part in parts) or any(part == "" for part in parts[:-1]):
        _reject("ENGINE_ARCHIVE")
    return name


def _generated_bytecode(name: str) -> bool:
    parts = name.split("/")
    return "__pycache__" in parts or name.endswith((".pyc", ".pyo"))


def _regular_zip_member(info: zipfile.ZipInfo) -> None:
    if info.is_dir() or info.filename.endswith("/"):
        return
    mode = (info.external_attr >> 16) & 0xFFFF
    mode_type = stat.S_IFMT(mode)
    if mode_type not in {0, stat.S_IFREG}:
        _reject("ENGINE_ARCHIVE")
    if info.file_size > MAX_MEMBER_BYTES:
        _reject("ENGINE_ARCHIVE_LIMIT")


def _open_wheel(path_value: str | os.PathLike[str]) -> tuple[int, int]:
    if not isinstance(path_value, (str, os.PathLike)):
        _reject("ENGINE_INPUT")
    fd: int | None = None
    try:
        path = Path(os.fspath(path_value))
        before = path.lstat()
        if not stat.S_ISREG(before.st_mode) or stat.S_ISLNK(before.st_mode):
            _reject("ENGINE_INPUT")
        fd = os.open(
            os.fspath(path),
            os.O_RDONLY | os.O_NONBLOCK | getattr(os, "O_NOFOLLOW", 0),
        )
        info = os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode)
                or (info.st_dev, info.st_ino, info.st_size)
                != (before.st_dev, before.st_ino, before.st_size)):
            _reject("ENGINE_INPUT")
        flags = fcntl.fcntl(fd, fcntl.F_GETFL)
        fcntl.fcntl(fd, fcntl.F_SETFL, flags & ~os.O_NONBLOCK)
    except ContractError:
        if fd is not None:
            try:
                os.close(fd)
            except OSError:
                pass
        raise
    except (OSError, TypeError, ValueError):
        if fd is not None:
            try:
                os.close(fd)
            except OSError:
                pass
        _reject("ENGINE_INPUT")
    if not stat.S_ISREG(info.st_mode) or info.st_size <= 0 or info.st_size > MAX_WHEEL_BYTES:
        os.close(fd)
        _reject("ENGINE_ARCHIVE_LIMIT")
    return fd, info.st_size


def _read_fd(fd: int, size: int) -> bytes:
    chunks: list[bytes] = []
    remaining = size
    while remaining:
        try:
            chunk = os.read(fd, min(1024 * 1024, remaining))
        except OSError:
            _reject("ENGINE_INPUT")
        if not chunk:
            _reject("ENGINE_INPUT")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def _wheel_members(raw: bytes) -> tuple[dict[str, bytes], str]:
    try:
        archive = zipfile.ZipFile(io.BytesIO(raw), "r")
    except (OSError, ValueError, zipfile.BadZipFile, zipfile.LargeZipFile):
        _reject("ENGINE_ARCHIVE")
    members: dict[str, bytes] = {}
    seen_names: set[str] = set()
    total = 0
    metadata_name: str | None = None
    try:
        infos = archive.infolist()
        if len(infos) > MAX_MEMBERS:
            _reject("ENGINE_ARCHIVE_LIMIT")
        for info in infos:
            name = _safe_member(info.filename)
            if name in seen_names:
                _reject("ENGINE_ARCHIVE")
            seen_names.add(name)
            if name.endswith("/"):
                continue
            _regular_zip_member(info)
            if not name.startswith(PACKAGE_NAME + "/") and not name.endswith("/METADATA"):
                continue
            if info.file_size > MAX_MEMBER_BYTES:
                _reject("ENGINE_ARCHIVE_LIMIT")
            try:
                data = archive.read(info)
            except (OSError, RuntimeError, ValueError, zipfile.BadZipFile):
                _reject("ENGINE_ARCHIVE")
            if len(data) != info.file_size:
                _reject("ENGINE_ARCHIVE")
            total += len(data)
            if total > MAX_TOTAL_MEMBER_BYTES:
                _reject("ENGINE_ARCHIVE_LIMIT")
            members[name] = data
            if name.endswith("/METADATA"):
                if metadata_name is not None:
                    _reject("ENGINE_ARCHIVE")
                metadata_name = name
    finally:
        archive.close()
    if metadata_name is None:
        _reject("ENGINE_ARCHIVE")
    return members, metadata_name


def _metadata_version(members: Mapping[str, bytes], metadata_name: str) -> str:
    raw = members[metadata_name]
    if len(raw) > MAX_METADATA_BYTES:
        _reject("ENGINE_ARCHIVE_LIMIT")
    try:
        document = Parser().parsestr(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        _reject("ENGINE_ARCHIVE")
    name = document.get("Name")
    version = document.get("Version")
    if name != DIST_NAME or not isinstance(version, str) or _VERSION.fullmatch(version) is None:
        _reject("ENGINE_ARCHIVE")
    return version


def _read_installed(path: Path) -> bytes:
    try:
        info = path.lstat()
    except OSError:
        _reject("ENGINE_INSTALLED_MISMATCH")
    if not stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode) or info.st_size > MAX_MEMBER_BYTES:
        _reject("ENGINE_INSTALLED_MISMATCH")
    fd: int | None = None
    try:
        fd = os.open(
            os.fspath(path),
            os.O_RDONLY | os.O_NONBLOCK | getattr(os, "O_NOFOLLOW", 0),
        )
        opened = os.fstat(fd)
        if (not stat.S_ISREG(opened.st_mode) or stat.S_ISLNK(opened.st_mode)
                or (opened.st_dev, opened.st_ino, opened.st_size)
                != (info.st_dev, info.st_ino, info.st_size)):
            _reject("ENGINE_INSTALLED_MISMATCH")
        flags = fcntl.fcntl(fd, fcntl.F_GETFL)
        fcntl.fcntl(fd, fcntl.F_SETFL, flags & ~os.O_NONBLOCK)
        data = _read_fd(fd, info.st_size)
        after = os.fstat(fd)
        if (not stat.S_ISREG(after.st_mode)
                or (after.st_dev, after.st_ino, after.st_size)
                != (info.st_dev, info.st_ino, info.st_size)):
            _reject("ENGINE_INSTALLED_MISMATCH")
    except (OSError, TypeError, ValueError):
        _reject("ENGINE_INSTALLED_MISMATCH")
    finally:
        try:
            if fd is not None:
                os.close(fd)
        except (UnboundLocalError, OSError):
            pass
    return data


def _installed_members(
    members: Mapping[str, bytes],
    *,
    distribution: Any,
    package: Any,
) -> list[dict[str, Any]]:
    package_file = getattr(package, "__file__", None)
    if not isinstance(package_file, str):
        _reject("ENGINE_INSTALLED_MISMATCH")
    init_member = f"{PACKAGE_NAME}/__init__.py"
    try:
        init_path = Path(distribution.locate_file(init_member))
    except (AttributeError, OSError, TypeError, ValueError):
        _reject("ENGINE_INSTALLED_MISMATCH")
    if os.path.abspath(os.fspath(init_path)) != os.path.abspath(package_file):
        _reject("ENGINE_INSTALLED_MISMATCH")
    selected = sorted(
        name for name in members
        if name.startswith(PACKAGE_NAME + "/") and not _generated_bytecode(name)
    )
    if not selected:
        _reject("ENGINE_ARCHIVE")
    distribution_files = getattr(distribution, "files", None)
    if distribution_files is None or not isinstance(distribution_files, (list, tuple)):
        _reject("ENGINE_INSTALLED_MISMATCH")
    expected: set[str] = set()
    for entry in distribution_files:
        if not isinstance(entry, (str, os.PathLike)):
            _reject("ENGINE_INSTALLED_MISMATCH")
        try:
            name = os.fspath(entry)
        except (TypeError, ValueError):
            _reject("ENGINE_INSTALLED_MISMATCH")
        if isinstance(name, bytes):
            _reject("ENGINE_INSTALLED_MISMATCH")
        if not name.startswith(PACKAGE_NAME + "/") or _generated_bytecode(name):
            continue
        name = _safe_member(name)
        if name in expected:
            _reject("ENGINE_INSTALLED_MISMATCH")
        expected.add(name)
    if set(selected) != expected:
        _reject("ENGINE_INSTALLED_MISMATCH")
    package_path = os.path.dirname(os.path.abspath(package_file))
    package_paths = getattr(package, "__path__", None)
    if package_paths is not None:
        if not isinstance(package_paths, (list, tuple)) or not package_paths:
            _reject("ENGINE_INSTALLED_MISMATCH")
        for path_value in package_paths:
            try:
                if os.path.abspath(os.fspath(path_value)) != package_path:
                    _reject("ENGINE_INSTALLED_MISMATCH")
            except (TypeError, ValueError, OSError):
                _reject("ENGINE_INSTALLED_MISMATCH")
    bound: list[dict[str, Any]] = []
    for name in selected:
        try:
            installed_path = Path(distribution.locate_file(name))
        except (AttributeError, OSError, TypeError, ValueError):
            _reject("ENGINE_INSTALLED_MISMATCH")
        installed = _read_installed(installed_path)
        if installed != members[name]:
            _reject("ENGINE_INSTALLED_MISMATCH")
        bound.append({"member": name, "bytes": len(installed), "sha256": _sha256(installed)})
    return bound


def _binding_digest(members: list[dict[str, Any]]) -> str:
    encoded = json.dumps(members, ensure_ascii=True, sort_keys=True, separators=(",", ":")).encode("ascii")
    return _sha256(encoded)


def verify_engine_wheel(
    path_value: str | os.PathLike[str],
    *,
    _distribution: Any | None = None,
    _package: Any | None = None,
) -> dict[str, Any]:
    """Verify a wheel against the imported, installed ``rs9`` bytes.

    The private dependency hooks exist only for bounded archive tests. Normal
    callers always use the running distribution and imported package.
    """

    fd, size = _open_wheel(path_value)
    try:
        raw = _read_fd(fd, size)
    finally:
        os.close(fd)
    artifact_sha256 = _sha256(raw)
    members, metadata_name = _wheel_members(raw)
    version = _metadata_version(members, metadata_name)
    try:
        distribution = _distribution or importlib.metadata.distribution(DIST_NAME)
        package = _package or importlib.import_module(PACKAGE_NAME)
        installed_version = distribution.version
        installed_name = distribution.metadata.get("Name")
    except (ImportError, AttributeError, KeyError, TypeError, ValueError):
        _reject("ENGINE_INSTALLED_MISMATCH")
    if installed_name != DIST_NAME or installed_version != version:
        _reject("ENGINE_VERSION_MISMATCH")
    bound_members = _installed_members(members, distribution=distribution, package=package)
    return {
        "schema": SCHEMA,
        "distribution": DIST_NAME,
        "version": version,
        "artifact_sha256": artifact_sha256,
        "member_binding_sha256": _binding_digest(bound_members),
        "member_count": len(bound_members),
        "members": bound_members,
    }


__all__ = [
    "DIST_NAME",
    "MAX_MEMBER_BYTES",
    "MAX_MEMBERS",
    "MAX_TOTAL_MEMBER_BYTES",
    "MAX_WHEEL_BYTES",
    "PACKAGE_NAME",
    "SCHEMA",
    "verify_engine_wheel",
]
