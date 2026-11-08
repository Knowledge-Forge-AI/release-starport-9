"""Bounded mechanics shared by the isolated universal release route."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
from collections.abc import Callable, Mapping, Sequence
from typing import Any

from rs9.tf_pypi_archive import AdmissionError, canonical, physical_bytes, sha256


MAX_DECLARED_FILE_BYTES = 2 * 1024 * 1024 * 1024
MAX_SNAPSHOT_ENTRIES = 5000
MAX_SNAPSHOT_DEPTH = 32
MAX_SNAPSHOT_FILE_BYTES = 16 * 1024 * 1024
MAX_SNAPSHOT_TOTAL_BYTES = 128 * 1024 * 1024

DARWIN_QUALIFY_SANDBOX_PROFILE = "(version 1)(allow default)(deny network*)"
LINUX_SANDBOX_PRESERVE_ENV = (
    "PATH,HOME,TMPDIR,TEMP,TMP,LANG,LC_ALL,"
    "PIP_CONFIG_FILE,PIP_NO_INDEX,PIP_NO_CACHE_DIR,PIP_DISABLE_PIP_VERSION_CHECK,"
    "PYTHONDONTWRITEBYTECODE,XDG_CACHE_HOME,XDG_CONFIG_HOME,XDG_DATA_HOME,XDG_STATE_HOME"
)

_HEX40 = set("0123456789abcdef")
_HEX64 = _HEX40
_STATE_NAMES = (
    "ai.knowledgeforge.themeforge.nebularfusion",
    "Theme Forge Nebular Fusion",
    "theme-forge-nebular-fusion",
)
_DARWIN_STATE_BASES = (
    "Library/Caches",
    "Library/Application Support",
    "Library/WebKit",
    "Library/Logs",
    "Library/HTTPStorages",
    "Library/Saved Application State",
    "Library/Preferences",
)
_UNIX_STATE_BASES = (".cache", ".config", ".local/share", ".local/state")
_STATE_SUFFIXES = ("", ".plist", ".savedState")


def fail(code: str) -> None:
    """Raise a stable, path-free admission code."""
    raise AdmissionError("TF_PYPI_NEBULAR080_" + str(code).strip()) from None


def _is_hex(value: Any, length: int) -> bool:
    return isinstance(value, str) and len(value) == length and set(value) <= _HEX40


def repo_root(repository: str | Path | None = None) -> Path:
    root = Path(repository) if repository is not None else Path(__file__).resolve().parents[2]
    check_no_symlinks(root, "REPO_SYMLINK")
    try:
        return root.resolve(strict=True)
    except (OSError, RuntimeError):
        fail("REPO_ROOT")
    raise AssertionError("unreachable")


def check_no_symlinks(path: str | Path, code: str = "SYMLINK") -> None:
    candidate = Path(path)
    try:
        chain = (candidate, *candidate.parents)
        if any(item.is_symlink() for item in chain):
            fail(code)
    except OSError:
        fail(code)


_check_no_symlinks = check_no_symlinks


def git_output(
    repository: str | Path,
    args: Sequence[str],
    error_code: str = "SOURCE_LINEAGE",
) -> str:
    """Capture one bounded source-control query without exposing diagnostics."""
    root = Path(repository)
    check_no_symlinks(root, error_code)
    if not root.is_dir() or any(not isinstance(item, str) or not item for item in args):
        fail(error_code)
    try:
        completed = subprocess.run(
            ["git", "-C", str(root), *args],
            check=False,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=30,
        )
    except (OSError, subprocess.SubprocessError):
        fail(error_code)
    if completed.returncode != 0:
        fail(error_code)
    return completed.stdout.strip()


_git_output = git_output


def validate_file_digest_entry(
    entry: Any,
    *,
    code: str = "FILE_DIGEST",
    max_size: int = MAX_DECLARED_FILE_BYTES,
) -> dict[str, Any]:
    if not isinstance(entry, Mapping):
        fail(code)
    rel_path = entry.get("path")
    name = entry.get("name")
    size = entry.get("size")
    digest_hex = entry.get("sha256")
    if (
        not isinstance(rel_path, str)
        or not rel_path
        or rel_path.startswith("/")
        or "\\" in rel_path
        or any(part in ("", ".", "..") for part in Path(rel_path).parts)
    ):
        fail(code)
    if name is not None and (
        not isinstance(name, str)
        or not name
        or "/" in name
        or "\\" in name
        or name in (".", "..")
        or name != Path(rel_path).name
    ):
        fail(code)
    if (
        type(size) is not int
        or size <= 0
        or size > max_size
        or not _is_hex(digest_hex, 64)
    ):
        fail(code)
    return dict(entry)


_validate_file_digest_entry = validate_file_digest_entry


def validate_repo_relative_dir_spec(raw_rel: Any, *, code: str = "PATH") -> str:
    if (
        not isinstance(raw_rel, str)
        or not raw_rel.strip()
        or raw_rel.startswith("/")
        or "\\" in raw_rel
        or any(part in ("", ".", "..") for part in Path(raw_rel).parts)
    ):
        fail(code)
    return raw_rel


_validate_repo_relative_dir_spec = validate_repo_relative_dir_spec


def resolve_repo_contained_dir(
    root: str | Path,
    relative_dir: str,
    *,
    symlink_code: str = "SYMLINK",
    missing_code: str = "MISSING_DIR",
    containment_code: str = "CONTAINMENT",
) -> Path:
    base = Path(root)
    validate_repo_relative_dir_spec(relative_dir, code=containment_code)
    check_no_symlinks(base, containment_code)
    candidate = base / relative_dir
    check_no_symlinks(candidate, symlink_code)
    try:
        base_real = base.resolve(strict=True)
        candidate_real = candidate.resolve(strict=True)
        candidate_real.relative_to(base_real)
    except (OSError, RuntimeError, ValueError):
        fail(containment_code)
    if not candidate.is_dir():
        fail(missing_code)
    return candidate_real


_resolve_repo_contained_dir = resolve_repo_contained_dir


def _valid_profile_spec(value: Any, *, label: str) -> bool:
    if not isinstance(value, Mapping):
        return False
    schema = value.get("schema")
    origin = value.get("origin_kind")
    return (
        isinstance(schema, str)
        and schema.startswith("rs9.tf-pypi-nebular080-")
        and origin == "public-in-run"
    )


def resolve_inrun_artifact_root(
    repository_root: str | Path,
    manylinux_spec: Mapping[str, Any] | None,
    inrun_root: str | Path | None,
    *,
    system_webkit_spec: Mapping[str, Any] | None = None,
) -> Path:
    """Resolve a private run root while retaining profile XOR and ownership checks."""
    base = Path(repository_root)
    if inrun_root is None:
        return base
    has_manylinux = _valid_profile_spec(manylinux_spec, label="manylinux")
    has_system = _valid_profile_spec(system_webkit_spec, label="system_webkit")
    if manylinux_spec is not None and not has_manylinux:
        fail("QUALIFICATION_INPUTS_ROOT")
    if system_webkit_spec is not None and not has_system:
        fail("QUALIFICATION_INPUTS_ROOT")
    if has_manylinux == has_system:
        fail("QUALIFICATION_INPUTS_ROOT")
    candidate = Path(inrun_root)
    if not candidate.is_absolute():
        fail("QUALIFICATION_INPUTS_ROOT")
    check_no_symlinks(candidate, "QUALIFICATION_INPUTS_ROOT")
    try:
        info = candidate.stat()
        base_real = base.resolve(strict=True)
        candidate_real = candidate.resolve(strict=True)
    except (OSError, RuntimeError):
        fail("QUALIFICATION_INPUTS_ROOT")
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o022:
        fail("QUALIFICATION_INPUTS_ROOT")
    try:
        candidate_real.relative_to(base_real)
    except ValueError:
        try:
            base_real.relative_to(candidate_real)
        except ValueError:
            return candidate_real
        fail("QUALIFICATION_INPUTS_ROOT")
    fail("QUALIFICATION_INPUTS_ROOT")
    raise AssertionError("unreachable")


_resolve_inrun_artifact_root = resolve_inrun_artifact_root


def read_regular_file(path: str | Path, *, limit: int, code: str = "FILE") -> bytes:
    candidate = Path(path)
    check_no_symlinks(candidate, code)
    if limit <= 0:
        fail(code)
    try:
        fd = os.open(candidate, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except OSError:
        fail(code)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_size <= 0 or info.st_size > limit:
            fail(code)
        chunks: list[bytes] = []
        remaining = info.st_size + 1
        while remaining > 0:
            chunk = os.read(fd, min(1024 * 1024, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        data = b"".join(chunks)
        if len(data) != info.st_size:
            fail(code)
        return data
    except OSError:
        fail(code)
    finally:
        os.close(fd)


def write_exclusive(path: str | Path, data: bytes, *, mode: int = 0o600, code: str = "OUTPUT") -> None:
    candidate = Path(path)
    check_no_symlinks(candidate.parent, code)
    if candidate.exists() or candidate.is_symlink() or not isinstance(data, bytes):
        fail(code)
    try:
        fd = os.open(candidate, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    except OSError:
        fail(code)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
    except OSError:
        fail(code)


def default_sandbox_prefix(target: str) -> tuple[str, ...]:
    if target == "darwin-arm64":
        return ("/usr/bin/sandbox-exec", "-p", DARWIN_QUALIFY_SANDBOX_PROFILE)
    if target in ("linux-arm64-gnu", "linux-x64-gnu"):
        uid, gid = os.getuid(), os.getgid()
        return (
            "sudo", "-n", f"--preserve-env={LINUX_SANDBOX_PRESERVE_ENV}",
            "unshare", "--net", "--", "setpriv", f"--reuid={uid}",
            f"--regid={gid}", "--clear-groups", "--",
        )
    fail("WHEEL_TARGET")
    raise AssertionError("unreachable")


def _state_targets(target: str) -> tuple[str, ...]:
    if target == "darwin-arm64":
        bases = _DARWIN_STATE_BASES
    elif target in ("linux-arm64-gnu", "linux-x64-gnu"):
        bases = _UNIX_STATE_BASES
    else:
        fail("WHEEL_TARGET")
    return tuple(f"{base}/{name}{suffix}" for base in bases for name in _STATE_NAMES for suffix in _STATE_SUFFIXES)


def _snapshot_state(root: Path, relatives: Sequence[str]) -> tuple[dict[str, Any], str]:
    rows: dict[str, Any] = {}
    total = 0
    seen = 0

    def visit(path: Path, key: str, depth: int) -> None:
        nonlocal total, seen
        if depth > MAX_SNAPSHOT_DEPTH or seen >= MAX_SNAPSHOT_ENTRIES:
            fail("NEBULAR_USER_STATE_GUARD")
        try:
            info = os.lstat(path)
        except FileNotFoundError:
            return
        except OSError:
            fail("NEBULAR_USER_STATE_GUARD")
        seen += 1
        row: dict[str, Any] = {
            "mode": stat.S_IMODE(info.st_mode),
            "uid": info.st_uid,
            "gid": info.st_gid,
            "mtime_ns": info.st_mtime_ns,
            "flags": getattr(info, "st_flags", 0),
        }
        if stat.S_ISLNK(info.st_mode):
            try:
                row.update(kind="symlink", link_target_sha256=sha256(os.fsencode(os.readlink(path))))
            except OSError:
                fail("NEBULAR_USER_STATE_GUARD")
            rows[key] = row
            return
        if stat.S_ISDIR(info.st_mode):
            row["kind"] = "directory"
            rows[key] = row
            try:
                with os.scandir(path) as scan:
                    children = sorted(scan, key=lambda item: item.name)
            except OSError:
                fail("NEBULAR_USER_STATE_GUARD")
            for child in children:
                visit(child.path, key + "/" + hashlib.sha256(child.name.encode()).hexdigest(), depth + 1)
            return
        if stat.S_ISREG(info.st_mode):
            if info.st_size > MAX_SNAPSHOT_FILE_BYTES or total + info.st_size > MAX_SNAPSHOT_TOTAL_BYTES:
                fail("NEBULAR_USER_STATE_GUARD")
            try:
                data = read_regular_file(path, limit=MAX_SNAPSHOT_FILE_BYTES, code="NEBULAR_USER_STATE_GUARD")
            except AdmissionError:
                fail("NEBULAR_USER_STATE_GUARD")
            total += len(data)
            row.update(kind="file", size=len(data), sha256=sha256(data))
            rows[key] = row
            return
        row["kind"] = "other"
        rows[key] = row

    for relative in relatives:
        visit(root / relative, relative, 0)
    digest = sha256(canonical(rows))
    return rows, digest


def make_real_user_state_snapshotter(
    target: str,
    *,
    home_dir: str | Path | None = None,
) -> Callable[[str, str], dict[str, Any]]:
    if target not in ("darwin-arm64", "linux-arm64-gnu", "linux-x64-gnu"):
        fail("WHEEL_TARGET")
    root = Path(home_dir) if home_dir is not None else Path.home()
    check_no_symlinks(root, "USER_STATE_HOME")
    if not root.is_dir():
        fail("USER_STATE_HOME")
    relatives = _state_targets(target)
    before: dict[str, Any] | None = None

    def snapshot(phase: str, observed_target: str) -> dict[str, Any]:
        nonlocal before
        if phase not in ("before", "after") or observed_target != target:
            fail("NEBULAR_USER_STATE_GUARD")
        rows, digest = _snapshot_state(root, relatives)
        changed = [] if phase == "before" else sorted(
            key for key, row in rows.items() if before is None or before.get(key) != row
        )
        if phase == "before":
            before = rows
        elif before is None:
            fail("NEBULAR_USER_STATE_GUARD")
        return {
            "schema": "nebular.native-rc-persistent-user-state-v1",
            "method": "native-rc-smoke.persistentStateLocations+snapshotLocations",
            "scope": "real-user-state",
            "target": observed_target,
            "phase": phase,
            "locations": len(rows),
            "snapshot_sha256": digest,
            "changed": changed,
        }

    return snapshot

