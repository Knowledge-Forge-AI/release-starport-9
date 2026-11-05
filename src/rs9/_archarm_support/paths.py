"""Host path admission for worker binds: physical, closed charset, no private material."""
from __future__ import annotations

import os
from pathlib import Path
import re
import stat

from rs9._archarm_support.refusal import SdkRefusal, require

SAFE_PATH_RE = re.compile(r"/[A-Za-z0-9._/+@-]{1,1000}")
GUEST_TARGET_RE = re.compile(r"/srv/rs9/[A-Za-z0-9._-]{1,64}(?:/[A-Za-z0-9._-]{1,64}){0,3}")
REFUSED_SEGMENTS = frozenset({".git", ".serena", ".ssh", ".gnupg", ".docker", ".netrc",
                              ".npmrc", ".pypirc", ".aws", ".kube"})
MAX_SOURCE_ENTRIES = 500_000


def _text(value, label):
    require(isinstance(value, (str, os.PathLike)), label)
    text = os.fspath(value)
    require(isinstance(text, str) and SAFE_PATH_RE.fullmatch(text) is not None
            and "//" not in text and not text.endswith("/"), label)
    parts = text.split("/")[1:]
    require(all(p not in ("", ".", "..") and p.casefold() not in REFUSED_SEGMENTS
                for p in parts), label)
    return text


def physical(value, label, *, kind):
    """An existing, non-symlink, physical absolute path of the requested kind."""
    text = _text(value, label)
    try:
        info = os.lstat(text)
    except OSError:
        raise SdkRefusal(label) from None
    require(not stat.S_ISLNK(info.st_mode), label)
    if kind == "dir":
        require(stat.S_ISDIR(info.st_mode), label)
    elif kind == "file":
        require(stat.S_ISREG(info.st_mode), label)
    else:
        require(stat.S_ISDIR(info.st_mode) or stat.S_ISREG(info.st_mode), label)
    require(os.path.realpath(text) == text, label)
    return Path(text)


def fresh(value, label):
    """A not-yet-existing path whose parent is a physical directory."""
    text = _text(value, label)
    require(not os.path.lexists(text), label)
    parent = os.path.dirname(text)
    try:
        info = os.lstat(parent)
    except OSError:
        raise SdkRefusal(label) from None
    require(stat.S_ISDIR(info.st_mode) and os.path.realpath(parent) == parent, label)
    return Path(text)


def overlaps(a, b):
    a, b = Path(a), Path(b)
    return a == b or a in b.parents or b in a.parents


def require_disjoint(paths, private_roots, label):
    paths = list(paths)
    for index, path in enumerate(paths):
        for other in paths[index + 1:]:
            require(not overlaps(path, other), label)
        for private in private_roots:
            require(not overlaps(path, private), "PRIVATE_MOUNT")


def owned_directory(path, uid, gid, label, *, empty):
    info = os.lstat(path)
    require(stat.S_ISDIR(info.st_mode) and info.st_uid == uid and info.st_gid == gid, label)
    require(info.st_mode & 0o7002 == 0, label)
    if empty:
        require(not os.listdir(path), label)


def scan_public_tree(root, label):
    """Bounded no-follow scan: no refused names, special files or set-id files."""
    root = Path(root)
    info = os.lstat(root)
    if stat.S_ISREG(info.st_mode):
        require(info.st_mode & 0o6000 == 0, label)
        return 1
    count = 0
    for parent, dirs, names in os.walk(root, followlinks=False):
        for name in [*dirs, *names]:
            count += 1
            require(count <= MAX_SOURCE_ENTRIES, label)
            require(name.casefold() not in REFUSED_SEGMENTS, label)
            entry = os.lstat(os.path.join(parent, name))
            mode = entry.st_mode
            require(stat.S_ISDIR(mode) or stat.S_ISREG(mode) or stat.S_ISLNK(mode), label)
            require(stat.S_ISLNK(mode) or mode & 0o6000 == 0, label)
    return count


def guest_target(value, label):
    require(isinstance(value, str) and GUEST_TARGET_RE.fullmatch(value) is not None, label)
    return value
