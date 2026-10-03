"""Authenticate a runtime npm closure from tagged lockfile bytes, without npm."""
import base64
import hashlib
import json
import re
import tarfile
from urllib.parse import urlsplit
from pathlib import Path

from rs9.errors import ContractError
from rs9.records import record_sha256, snapshot
from rs9.release_core import authenticated_record_hash, digest
from rs9.archives import inspect_archive
from rs9.security import validate_safe_relative_posix_path


def _resolve(packages, parent, name):
    prefix = parent
    while True:
        path = (prefix + "/" if prefix else "") + "node_modules/" + name
        if path in packages:
            return path
        if not prefix:
            raise ContractError("NPM_CLOSURE", "Lockfile lacks a required runtime dependency")
        prefix = prefix.rsplit("/node_modules/", 1)[0] if "/node_modules/" in prefix else ""


def runtime_closure(package, lock):
    if lock.get("lockfileVersion") not in {2, 3} or not isinstance(lock.get("packages"), dict):
        raise ContractError("NPM_LOCK", "A complete package lock is required")
    packages = lock["packages"]
    roots = package.get("dependencies", {})
    if packages.get("", {}).get("dependencies", {}) != roots:
        raise ContractError("NPM_LOCK", "Tagged package and lockfile runtime requirements disagree")
    if any(not re.fullmatch(r"\d+\.\d+\.\d+", version) for version in roots.values()):
        raise ContractError("NPM_PIN", "LIVE1 requires exact direct runtime versions")
    pending = [_resolve(packages, "", name) for name in sorted(roots)]
    selected = {}
    while pending:
        path = pending.pop()
        if path in selected:
            continue
        validate_safe_relative_posix_path(path)
        row = packages[path]
        if row.get("link") or row.get("dev") or row.get("peerDependencies") or row.get("optionalDependencies"):
            raise ContractError("NPM_CLOSURE", "Unsupported linked, peer or optional runtime closure")
        parsed = urlsplit(row.get("resolved", ""))
        if (parsed.scheme != "https" or parsed.hostname != "registry.npmjs.org"
                or parsed.port not in (None, 443) or parsed.username or parsed.password
                or parsed.query or parsed.fragment):
            raise ContractError("NPM_PIN", "Only lock-pinned public registry tarballs are supported")
        if not re.fullmatch(r"sha512-[A-Za-z0-9+/]+={0,2}", row.get("integrity", "")):
            raise ContractError("NPM_INTEGRITY", "Strong lockfile integrity is required")
        name = path.rsplit("node_modules/", 1)[1]
        if name in roots and roots[name] != row.get("version"):
            raise ContractError("NPM_PIN", "Direct runtime pin differs from locked version")
        selected[path] = {"path": path, "name": name, "version": row["version"],
                          "url": row["resolved"], "integrity": row["integrity"]}
        pending.extend(_resolve(packages, path, name) for name in row.get("dependencies", {}))
    return sorted(selected.values(), key=lambda row: row["path"])


def closure_for_capture(capture):
    authenticated_record_hash(capture)
    try:
        package = json.loads(capture.source["package.json"])
        lock = json.loads(capture.source["package-lock.json"])
    except (KeyError, ValueError):
        raise ContractError("NPM_LOCK", "Authenticated tagged package lock is mandatory") from None
    return runtime_closure(package, lock)


def authenticate_dependencies(capture, archives):
    """archives maps exact node_modules paths to physical staged archive paths."""
    closure = closure_for_capture(capture)
    if set(archives) != {row["path"] for row in closure}:
        raise ContractError("NPM_CLOSURE", "Staged dependency set differs from runtime closure")
    records = []
    for row in closure:
        path = Path(archives[row["path"]])
        if any(p.is_symlink() for p in (path, *path.parents)) or not path.is_file() or path.stat().st_size > 32 * 1024 ** 2:
            raise ContractError("NPM_ARCHIVE", "Bounded physical dependency archive required")
        data = path.read_bytes()
        integrity = "sha512-" + base64.b64encode(hashlib.sha512(data).digest()).decode("ascii")
        if integrity != row["integrity"]:
            raise ContractError("NPM_INTEGRITY", "Staged dependency bytes differ from tagged integrity")
        metadata = {}
        def visitor(name, content, mode):
            if name == "package/package.json":
                metadata.update(json.loads(content))
        manifest = inspect_archive(path, {}, on_file=visitor, max_members=20000,
            max_member_bytes=4 * 1024 ** 2, max_total_bytes=64 * 1024 ** 2)
        if digest(path.read_bytes()) != digest(data):
            raise ContractError("NPM_ARCHIVE", "Staged dependency changed during authentication")
        if metadata.get("name") != row["name"] or metadata.get("version") != row["version"]:
            raise ContractError("NPM_IDENTITY", "Dependency archive identity differs from tagged lock")
        legal = [m["path"] for m in manifest["members"] if m["type"] == "file"
                 and m["path"].rsplit("/", 1)[-1].lower().startswith(("license", "licence", "notice"))]
        if not legal or not metadata.get("license"):
            raise ContractError("NPM_LICENSE", "Dependency licence files and metadata are required")
        records.append({**row, "sha256": digest(data), "size": len(data),
                        "payload_manifest_sha256": manifest["manifest_sha256"],
                        "license": metadata["license"], "legal_files": legal})
    return snapshot({"schema": "rs9.pinned-npm-dependencies.v1alpha1",
        "release_record_sha256": authenticated_record_hash(capture),
        "lock_sha256": digest(capture.source["package-lock.json"]), "dependencies": records})
