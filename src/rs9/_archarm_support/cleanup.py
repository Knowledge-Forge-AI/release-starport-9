"""Identity-bound cleanup (ported): stop without force, rm without -f, tag rm --no-prune.

An owned name whose identity is unknown or differs is retained (returns False)
for disposable VM teardown; it is never removed by name alone, forced or pruned.
The Docker CLI absence convention (``inspect`` exit 1 with ``[]``) is the only
absence evidence, as in the qualified probe; nothing stronger is claimed.
"""
from __future__ import annotations

import os
from pathlib import Path
import re
import stat

from rs9._archarm_support.docker import container_doc, image_identity, presence
from rs9._archarm_support.refusal import require

CERT_NAME = "archlinuxarm-builder-public.gpg"


class Record:
    """One owned Docker object: exact name, labels and (once known) immutable id."""

    def __init__(self, kind, name, labels=None):
        self.kind = kind
        self.name = name
        self.labels = labels
        self.requested = False
        self.id = None
        self.removed = False


def cleanup_container(docker, record):
    if not record.requested or record.removed:
        return True
    if not presence(docker, "container", record.name):
        clean = record.id is None or not presence(docker, "container", record.id)
        record.removed = clean
        return clean
    if record.id is None:
        return False  # exists but identity unknown: preserve for VM teardown
    doc = container_doc(docker, record.name, "DOCKER_READBACK")
    if (doc.get("Id") != record.id or doc.get("Name") != "/" + record.name
            or doc.get("Labels") != record.labels):
        return False
    if doc.get("Running") is not False:
        code, _ = docker(["container", "stop", "--time", "10", record.id], timeout=60)
        if code != 0:
            return False
        doc = container_doc(docker, record.id, "DOCKER_READBACK")
        if doc.get("Id") != record.id or doc.get("Running") is not False:
            return False
    code, _ = docker(["container", "rm", record.id], timeout=120)
    if code != 0:
        return False
    clean = (not presence(docker, "container", record.name)
             and not presence(docker, "container", record.id))
    record.removed = clean
    return clean


def cleanup_image(docker, record):
    if not record.requested or record.removed:
        return True
    if not presence(docker, "image", record.name):
        clean = record.id is None or not presence(docker, "image", record.id)
        record.removed = clean
        return clean
    if record.id is None:
        return False
    if image_identity(docker, record.name, "DOCKER_READBACK") != record.id:
        return False
    code, _ = docker(["image", "rm", "--no-prune", record.name], timeout=300)
    if code != 0:
        return False
    clean = not presence(docker, "image", record.name) and not presence(docker, "image", record.id)
    record.removed = clean
    return clean


def remove_fresh_docker_home(root):
    """Remove only bounded opaque client metadata in this fresh owned directory."""
    root = Path(root)
    require(stat.S_ISDIR(root.lstat().st_mode) and not root.is_symlink(), "DOCKER_HOME_CHANGED")
    files, directories = [], []
    total = 0
    for parent, dirs, names in os.walk(root, followlinks=False):
        for name in [*dirs, *names]:
            path = Path(parent) / name
            relative = path.relative_to(root)
            require(len(relative.parts) <= 5 and name.casefold() not in {"db", "raw", ".serena"}
                    and not re.search(r"(?:\.db|\.sqlite)(?:$|[.-])", name, re.I),
                    "DOCKER_HOME_CHANGED")
            s = path.lstat()
            require(not stat.S_ISLNK(s.st_mode), "DOCKER_HOME_CHANGED")
            if stat.S_ISDIR(s.st_mode):
                directories.append(path)
            else:
                require(stat.S_ISREG(s.st_mode) and path.suffix == ".json", "DOCKER_HOME_CHANGED")
                files.append(path)
                total += s.st_size
            require(len(files) + len(directories) <= 64 and total <= 256 * 1024,
                    "DOCKER_HOME_CHANGED")
    for path in files:
        path.unlink()
    for path in sorted(directories, key=lambda p: len(p.parts), reverse=True):
        path.rmdir()
    root.rmdir()


class Layout:
    def __init__(self, work, count):
        self.work = Path(work)
        self.count = count
        self.home = self.work / "public-home"
        self.docker_home = self.work / "docker-home"
        self.rootfs_dir = self.work / "rootfs"
        self.rootfs = self.rootfs_dir / "rootfs.tar.gz"
        self.rootfs_sig = self.rootfs_dir / "rootfs.tar.gz.sig"
        self.inputs = self.work / "inputs"
        self.pkg_dir = self.inputs / "pkg"
        self.key_dir = self.inputs / "key"
        self.cert_copy = self.key_dir / CERT_NAME
        self.pacman_conf = self.inputs / "pacman.conf"

    def package(self, index):
        return self.pkg_dir / f"{index:03d}.pkg.tar.xz"

    def signature(self, index):
        return self.pkg_dir / f"{index:03d}.pkg.tar.xz.sig"

    def package_names(self):
        names = set()
        for index in range(self.count):
            names.add(self.package(index).name)
            names.add(self.signature(index).name)
        return names


def remove_workspace(layout):
    """Two-phase: scan the closed layout, refuse anything unexpected, then delete."""
    files, directories = [], []

    def scan(directory, allowed_files, allowed_dirs):
        info = directory.lstat()
        require(stat.S_ISDIR(info.st_mode), "WORKSPACE_CHANGED")
        names = set(os.listdir(directory))
        require(names <= set(allowed_files) | set(allowed_dirs), "WORKSPACE_CHANGED")
        for name in names:
            entry = (directory / name).lstat()
            if name in allowed_dirs:
                require(stat.S_ISDIR(entry.st_mode), "WORKSPACE_CHANGED")
            else:
                require(stat.S_ISREG(entry.st_mode), "WORKSPACE_CHANGED")
                files.append(directory / name)
        return names

    top = scan(layout.work, (), ("public-home", "rootfs", "inputs"))
    if "public-home" in top:
        scan(layout.home, ("common.conf",), ())
        directories.append(layout.home)
    if "rootfs" in top:
        scan(layout.rootfs_dir, ("rootfs.tar.gz", "rootfs.tar.gz.sig"), ())
        directories.append(layout.rootfs_dir)
    if "inputs" in top:
        sub = scan(layout.inputs, ("pacman.conf",), ("pkg", "key"))
        if "pkg" in sub:
            scan(layout.pkg_dir, tuple(layout.package_names()), ())
            directories.append(layout.pkg_dir)
        if "key" in sub:
            scan(layout.key_dir, (CERT_NAME,), ())
            directories.append(layout.key_dir)
        directories.append(layout.inputs)
    for path in files:
        path.unlink()
    for path in directories:
        path.rmdir()
    layout.work.rmdir()
