"""Read-only candidate inventories and Git tree calculation without an index."""
import hashlib
import os
from pathlib import Path
import subprocess

from rs9.errors import ContractError
from rs9.security import scan_for_credentials, validate_safe_relative_posix_path
from rs9.scratch import physical_directory

MANIFEST = "operators/live1/candidate-manifest.json"
DIRECTORIES = ("src", "tests", "docs", "examples", "bootstrap", "nix", "operators", "evidence", ".github")


def git_oid(kind, data):
    return hashlib.sha1(kind.encode() + b" " + str(len(data)).encode() + b"\0" + data).hexdigest()


def candidate_paths(root):
    root = physical_directory(root)
    tracked = subprocess.check_output(["git", "-C", str(root), "ls-files", "-z"]).decode().split("\0")
    paths = {p for p in tracked if p and (root / p).exists()}
    for directory in DIRECTORIES:
        paths.update(p.relative_to(root).as_posix() for p in (root / directory).rglob("*")
                     if (p.is_file() or p.is_symlink()) and "__pycache__" not in p.parts)
    paths.update(p.name for p in root.glob("flake.*") if p.is_file())
    return sorted(paths)


def file_inventory(root, paths):
    root = physical_directory(root)
    rows = []
    if len(set(paths)) != len(paths):
        raise ContractError("CANDIDATE_INVENTORY", "Duplicate paths")
    for relative in sorted(paths):
        validate_safe_relative_posix_path(relative)
        path = root / relative
        if any(p.is_symlink() for p in (path, *path.parents)) or not path.is_file():
            raise ContractError("CANDIDATE_INVENTORY", "Physical source file required")
        data = path.read_bytes()
        if len(data) > 512 * 1024:
            raise ContractError("CANDIDATE_LIMIT", "Only bounded source/evidence files may be adopted")
        text = data.decode("utf-8")
        scan_for_credentials(text)
        rows.append({"path": relative, "size": len(data), "sha256": hashlib.sha256(data).hexdigest(),
                     "git_blob": git_oid("blob", data), "mode": "100755" if os.access(path, os.X_OK) else "100644"})
    return rows


def source_tree(rows):
    """Compute Git tree IDs from complete inventory, with Git directory ordering."""
    root = {}
    for row in rows:
        validate_safe_relative_posix_path(row["path"])
        current = root
        parts = row["path"].split("/")
        for part in parts[:-1]:
            current = current.setdefault(part, {})
            if not isinstance(current, dict):
                raise ContractError("CANDIDATE_INVENTORY", "Conflicting tree paths")
        if parts[-1] in current:
            raise ContractError("CANDIDATE_INVENTORY", "Duplicate tree path")
        current[parts[-1]] = (row["mode"], row["git_blob"])
    def tree(directory):
        entries = []
        for name, value in directory.items():
            is_dir = isinstance(value, dict)
            mode, oid = ("40000", tree(value)) if is_dir else value
            entries.append((name.encode() + (b"/" if is_dir else b""),
                            mode.encode() + b" " + name.encode() + b"\0" + bytes.fromhex(oid)))
        return git_oid("tree", b"".join(data for _, data in sorted(entries)))
    return tree(root)


def verify_inventory(root, manifest):
    expected = manifest["files"]
    if file_inventory(root, [r["path"] for r in expected]) != expected:
        raise ContractError("CANDIDATE_CHANGED", "Reviewed inventory differs from source bytes or modes")
    if set(candidate_paths(root)) != {r["path"] for r in expected} | {MANIFEST}:
        raise ContractError("CANDIDATE_CHANGED", "Candidate inventory is incomplete")
    return source_tree(file_inventory(root, [r["path"] for r in expected] + [MANIFEST]))
