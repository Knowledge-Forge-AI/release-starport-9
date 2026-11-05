"""Untrusted probe-output ingestion: quiesced writers, held no-follow fds, declared schemas.

The root-capable client can reach the probe-output bind, so everything there is
untrusted. Ingestion is only allowed after the owning client container was
stopped and read back as exited. Each entry is lstat-ed, opened with
``O_NOFOLLOW`` relative to its held parent descriptor, compared against the
pre-open identity (device/inode/mode/owner/size/times/links) before and after
the read, and must be a plain directory or single-link regular file owned by
the verified runner UID/GID without set-id/sticky/world-write bits. Only
declared relative paths are accepted, each through its caller-supplied existing
schema validator. Symlinks, devices, FIFOs, sockets, undeclared or unstable
entries fail the whole ingestion. The result never confers authority.
"""
from __future__ import annotations

import hashlib
import os
import re
import stat
from types import MappingProxyType
from typing import Any, Callable, Mapping

from rs9._archarm_support.refusal import SdkRefusal, require

REL_RE = re.compile(r"[A-Za-z0-9._-]{1,128}(?:/[A-Za-z0-9._-]{1,128}){0,7}")
MAX_FILE_BYTES = 4 * 1024 * 1024
MAX_TOTAL_BYTES = 32 * 1024 * 1024
MAX_ENTRIES = 4096
MAX_DEPTH = 8
_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)
_CLOEXEC = getattr(os, "O_CLOEXEC", 0)
_NONBLOCK = getattr(os, "O_NONBLOCK", 0)
_DIRECTORY = getattr(os, "O_DIRECTORY", 0)


def _identity(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid, info.st_size,
            info.st_mtime_ns, info.st_ctime_ns, info.st_nlink)


def _dir_identity(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid)


def _owned(info, uid, gid, label):
    require(info.st_uid == uid and info.st_gid == gid, label)
    require(info.st_mode & 0o7002 == 0, label)


def validate_declarations(declared, required):
    require(isinstance(declared, Mapping) and 0 < len(declared) <= MAX_ENTRIES, "EVIDENCE_SCHEMA")
    for rel, validator in declared.items():
        require(isinstance(rel, str) and REL_RE.fullmatch(rel) is not None
                and all(p not in (".", "..") for p in rel.split("/")), "EVIDENCE_SCHEMA")
        require(callable(validator), "EVIDENCE_SCHEMA")
    required = tuple(required)
    require(all(rel in declared for rel in required), "EVIDENCE_SCHEMA")
    return dict(declared), frozenset(required)


class UntrustedEvidence:
    """Schema-validated bytes from the probe-output tree; never qualification authority."""

    authority = False

    def __init__(self, rows):
        self._rows = MappingProxyType(dict(rows))

    @property
    def files(self) -> Mapping[str, Mapping[str, Any]]:
        return self._rows

    def record(self):
        """Closed public projection: declared relative names, sizes and digests only."""
        return {"schema": "rs9.archarm-untrusted-probe-output.v1", "authority": False,
                "files": [{"path": rel, "bytes": row["bytes"], "sha256": row["sha256"]}
                          for rel, row in sorted(self._rows.items())]}


def ingest_tree(root, *, uid, gid, declared: Mapping[str, Callable[[bytes], Any]],
                required=()):
    declared, required = validate_declarations(declared, required)
    rows, total, count = {}, 0, 0
    try:
        before = os.lstat(root)
    except OSError:
        raise SdkRefusal("EVIDENCE_UNSAFE") from None
    require(stat.S_ISDIR(before.st_mode), "EVIDENCE_UNSAFE")
    _owned(before, uid, gid, "EVIDENCE_OWNER")
    root_fd = os.open(root, os.O_RDONLY | _DIRECTORY | _NOFOLLOW | _CLOEXEC)
    try:
        require(_dir_identity(os.fstat(root_fd)) == _dir_identity(before), "EVIDENCE_UNSTABLE")

        def walk(dir_fd, prefix, depth):
            nonlocal total, count
            require(depth <= MAX_DEPTH, "EVIDENCE_UNSAFE")
            for name in sorted(os.listdir(dir_fd)):
                count += 1
                require(count <= MAX_ENTRIES, "EVIDENCE_LIMIT")
                rel = name if not prefix else prefix + "/" + name
                require(REL_RE.fullmatch(rel) is not None, "EVIDENCE_UNSAFE")
                info = os.stat(name, dir_fd=dir_fd, follow_symlinks=False)
                mode = info.st_mode
                require(not stat.S_ISLNK(mode), "EVIDENCE_UNSAFE")
                _owned(info, uid, gid, "EVIDENCE_OWNER")
                if stat.S_ISDIR(mode):
                    require(any(key.startswith(rel + "/") for key in declared), "EVIDENCE_UNDECLARED")
                    child = os.open(name, os.O_RDONLY | _DIRECTORY | _NOFOLLOW | _CLOEXEC,
                                    dir_fd=dir_fd)
                    try:
                        require(_dir_identity(os.fstat(child)) == _dir_identity(info),
                                "EVIDENCE_UNSTABLE")
                        walk(child, rel, depth + 1)
                        require(_dir_identity(os.fstat(child)) == _dir_identity(info),
                                "EVIDENCE_UNSTABLE")
                    finally:
                        os.close(child)
                    continue
                require(stat.S_ISREG(mode), "EVIDENCE_UNSAFE")
                require(rel in declared, "EVIDENCE_UNDECLARED")
                require(info.st_nlink == 1 and 0 <= info.st_size <= MAX_FILE_BYTES,
                        "EVIDENCE_UNSAFE")
                fd = os.open(name, os.O_RDONLY | _NOFOLLOW | _NONBLOCK | _CLOEXEC, dir_fd=dir_fd)
                try:
                    opened = os.fstat(fd)
                    require(_identity(opened) == _identity(info), "EVIDENCE_UNSTABLE")
                    chunks, size = [], 0
                    while True:
                        chunk = os.read(fd, 65536)
                        if not chunk:
                            break
                        size += len(chunk)
                        require(size <= info.st_size, "EVIDENCE_UNSTABLE")
                        chunks.append(chunk)
                    require(size == info.st_size
                            and _identity(os.fstat(fd)) == _identity(info), "EVIDENCE_UNSTABLE")
                finally:
                    os.close(fd)
                after = os.stat(name, dir_fd=dir_fd, follow_symlinks=False)
                require(_identity(after) == _identity(info), "EVIDENCE_UNSTABLE")
                data = b"".join(chunks)
                total += len(data)
                require(total <= MAX_TOTAL_BYTES, "EVIDENCE_LIMIT")
                try:
                    value = declared[rel](data)
                except SdkRefusal:
                    raise
                except Exception:
                    raise SdkRefusal("EVIDENCE_SCHEMA") from None
                rows[rel] = MappingProxyType({"bytes": len(data),
                                              "sha256": hashlib.sha256(data).hexdigest(),
                                              "value": value})

        walk(root_fd, "", 0)
        require(_dir_identity(os.fstat(root_fd)) == _dir_identity(before), "EVIDENCE_UNSTABLE")
    finally:
        os.close(root_fd)
    require(required <= set(rows), "EVIDENCE_MISSING")
    return UntrustedEvidence(rows)
