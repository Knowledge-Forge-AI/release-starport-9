"""Safe runtime materializer for RS9 payloads away from read-only Nix store."""

from __future__ import annotations

import argparse
import fcntl
import gzip
import hashlib
import json
import os
from pathlib import Path
import posixpath
import shutil
import stat
import sys
import tarfile
from typing import Any, Dict, List, Optional, Set, Tuple
import unicodedata

from rs9.archives import inspect_archive
from rs9.errors import ContractError
from rs9.scratch import canonical
from rs9.security import validate_safe_relative_posix_path


def validate_ancestry_not_symlink(target_path: Path | str) -> Path:
    """Validate that path and every ancestor contains no symlinks."""
    raw_path = Path(target_path).absolute()
    for parent in (raw_path, *raw_path.parents):
        if parent.is_symlink():
            raise ContractError("SYMLINK_REJECTED", "Directory ancestry contains a forbidden symlink")
    return raw_path


def validate_symlink_target(target: str, source_path: str, root_name: str) -> None:
    """Ensure symlink target is safe, normalized, and remains strictly within the root."""
    if not target or target.startswith("/") or "\\" in target or unicodedata.normalize("NFC", target) != target or any(ord(c) < 32 or ord(c) == 127 for c in target):
        raise ContractError("UNSAFE_LINK", "Unsafe or non-normalized symlink target")
    combined = posixpath.normpath(posixpath.join(posixpath.dirname(source_path), target))
    if not combined.startswith(root_name + "/") and combined != root_name:
        raise ContractError("UNSAFE_LINK", "Symlink target escapes payload root")


def safe_rmtree(target: Path | str, confinement_root: Optional[Path | str] = None) -> None:
    """Remove only a confined cache tree; report cleanup failures explicitly."""
    path = Path(target).absolute()
    validate_ancestry_not_symlink(path.parent)
    if confinement_root is not None:
        conf = validate_ancestry_not_symlink(confinement_root)
        if path == conf or not path.is_relative_to(conf):
            raise ContractError("UNSAFE_PATH", "Target path escapes confinement root")
    if not path.exists() and not path.is_symlink():
        return
    try:
        if path.is_symlink():
            path.unlink()
            return
        os.chmod(path, 0o700, follow_symlinks=False)
        for current, directories, _ in os.walk(path, topdown=True, followlinks=False):
            for name in directories:
                child = Path(current) / name
                if not child.is_symlink():
                    os.chmod(child, 0o700, follow_symlinks=False)
        shutil.rmtree(path)
    except OSError:
        raise ContractError("CACHE_CLEANUP_FAILED", "Failed cache cleanup requires operator recovery") from None


def ensure_safe_parent_dir(base: Path, rel_path: str) -> Path:
    """Ensure all parent directories of rel_path under base exist and contain NO symlinks."""
    parts = rel_path.split("/")[:-1]
    curr = base
    for part in parts:
        curr = curr / part
        if os.path.islink(curr):
            raise ContractError("UNSAFE_LINK", "Symlink encountered in path ancestry")
        if not curr.is_dir():
            curr.mkdir(mode=0o700)
        elif os.path.islink(curr):
            raise ContractError("UNSAFE_LINK", "Symlink encountered in path ancestry")
    return curr


def parse_manifest_members(manifest_or_members: Any) -> Tuple[List[Dict[str, Any]], str, str]:
    """Parse, validate, and normalize manifest members into sorted canonical inventory."""
    if isinstance(manifest_or_members, dict):
        members, expected_hash = manifest_or_members.get("members", []), manifest_or_members.get("manifest_sha256")
    elif isinstance(manifest_or_members, list):
        members, expected_hash = manifest_or_members, None
    else:
        raise ContractError("INVALID_MANIFEST", "Manifest must be a dict or list of member objects")
    if not members:
        raise ContractError("INVALID_MANIFEST", "Manifest members list cannot be empty")

    root_name: Optional[str] = None
    seen_paths: Set[str] = set()

    for item in members:
        if not isinstance(item, dict):
            raise ContractError("INVALID_MANIFEST", "Manifest member must be an object")
        if not isinstance(path := item.get("path"), str):
            raise ContractError("INVALID_MANIFEST", "Manifest member missing path")
        validate_safe_relative_posix_path(path)
        m_root = path.split("/")[0]
        if root_name is None: root_name = m_root
        elif m_root != root_name:
            raise ContractError("ARCHIVE_ROOT", "Member root does not match expected payload root")
        if path in seen_paths:
            raise ContractError("DUPLICATE_MEMBER", "Duplicate path in manifest")
        seen_paths.add(path)

        m_type, mode = item.get("type"), item.get("mode")
        if m_type not in ("file", "directory", "symlink"):
            raise ContractError("UNSAFE_MEMBER", "Unsupported manifest member type")
        if type(mode) is not int or isinstance(mode, bool) or mode < 0 or mode > 0o777:
            raise ContractError("UNSAFE_MODE", "Invalid file mode outside 0..0777")

        if m_type == "file":
            sha256, size = item.get("sha256"), item.get("size")
            if not isinstance(sha256, str) or len(sha256) != 64 or any(c not in "0123456789abcdef" for c in sha256):
                raise ContractError("INVALID_MANIFEST", "Invalid file sha256 digest")
            if type(size) is not int or isinstance(size, bool) or size < 0:
                raise ContractError("INVALID_MANIFEST", "Invalid file size")
        elif m_type == "symlink":
            if not isinstance(target := item.get("target"), str):
                raise ContractError("INVALID_MANIFEST", "Symlink member missing target")
            validate_symlink_target(target, path, root_name)

    if root_name not in seen_paths:
        raise ContractError("INVALID_MANIFEST", "Manifest must include root directory entry")

    symlinks = {m["path"]: m for m in members if m["type"] == "symlink"}
    for m in members:
        path = m["path"]
        is_sidecar = any("sidecar" in part for part in path.split("/"))
        if is_sidecar and m["type"] == "symlink":
            raise ContractError("UNSAFE_LINK", "Symlinks forbidden in sidecar ancestry")
        parent = posixpath.dirname(path)
        while parent:
            if parent in symlinks:
                if is_sidecar:
                    raise ContractError("UNSAFE_LINK", "Symlinks forbidden in sidecar ancestry")
                raise ContractError("UNSAFE_LINK", "Member has a non-directory ancestor")
            parent = posixpath.dirname(parent)

    def resolve_chain(name: str, seen: Tuple[str, ...] = ()) -> str:
        parts, resolved = name.split("/"), []
        while parts:
            part = parts.pop(0)
            if part in ("", "."):
                continue
            if part == "..":
                if len(resolved) <= 1:
                    raise ContractError("UNSAFE_LINK", "Symlink target escapes payload root")
                resolved.pop(); continue
            resolved.append(part)
            cur = "/".join(resolved)
            if cur in symlinks:
                if cur in seen or len(seen) > 64:
                    raise ContractError("UNSAFE_LINK", "Symlink loop or excessive chain detected")
                target = posixpath.dirname(cur) + "/" + symlinks[cur]["target"]
                return resolve_chain(target + ("/" + "/".join(parts) if parts else ""), (*seen, cur))
        return "/".join(resolved)

    for s_path in symlinks: resolve_chain(s_path)
    sorted_members = sorted(members, key=lambda x: x["path"])
    computed_sha256 = hashlib.sha256(canonical(sorted_members)).hexdigest()
    if expected_hash is not None:
        if (
            not isinstance(expected_hash, str)
            or len(expected_hash) != 64
            or any(c not in "0123456789abcdef" for c in expected_hash)
        ):
            raise ContractError("INVALID_DIGEST", "Manifest SHA256 must be a 64-character lowercase hex digest")
        if expected_hash != computed_sha256:
            raise ContractError("MANIFEST_TAMPERED", "Manifest SHA256 does not match canonical member digest")
    return sorted_members, root_name, computed_sha256


def verify_payload_directory(payload_root: Path, members: List[Dict[str, Any]]) -> None:
    """Verify materialized payload directory strictly against complete manifest inventory."""
    if not payload_root.is_dir():
        raise ContractError("PAYLOAD_TAMPERED", "Payload root directory does not exist")
    expected_by_path = {m["path"]: m for m in members}
    actual_seen: Set[str] = set()
    root_name = members[0]["path"].split("/")[0]
    expected_root_dir = payload_root / root_name
    if not expected_root_dir.is_dir() or expected_root_dir.is_symlink():
        raise ContractError("PAYLOAD_TAMPERED", "Root payload directory not found or is a symlink")

    for dirpath, dirnames, filenames in os.walk(expected_root_dir, followlinks=False):
        rel_dir = os.path.relpath(dirpath, payload_root)
        actual_seen.add(rel_dir)
        expected = expected_by_path.get(rel_dir)
        if expected is None or expected["type"] != "directory":
            raise ContractError("EXTRA_PAYLOAD_ENTRY", "Unexpected directory in payload")
        if os.lstat(dirpath).st_mode & 0o777 != expected["mode"]:
            raise ContractError("PAYLOAD_TAMPERED", "Directory mode mismatch")

        for d in list(dirnames):
            p = os.path.join(dirpath, d)
            if os.path.islink(p):
                rel_link = os.path.relpath(p, payload_root)
                actual_seen.add(rel_link); exp_link = expected_by_path.get(rel_link)
                if exp_link is None or exp_link["type"] != "symlink":
                    raise ContractError("EXTRA_PAYLOAD_ENTRY", "Unexpected symlink in payload")
                if os.readlink(p) != exp_link["target"]:
                    raise ContractError("PAYLOAD_TAMPERED", "Symlink target mismatch")
                dirnames.remove(d)

        for f in filenames:
            file_path = os.path.join(dirpath, f)
            rel_file = os.path.relpath(file_path, payload_root)
            actual_seen.add(rel_file)
            if (exp := expected_by_path.get(rel_file)) is None:
                raise ContractError("EXTRA_PAYLOAD_ENTRY", "Unexpected entry in payload")
            st = os.lstat(file_path)
            if stat.S_ISLNK(st.st_mode):
                if exp["type"] != "symlink" or os.readlink(file_path) != exp["target"]:
                    raise ContractError("PAYLOAD_TAMPERED", "Symlink mismatch")
            elif stat.S_ISREG(st.st_mode):
                if exp["type"] != "file" or st.st_size != exp["size"] or (st.st_mode & 0o777 != exp["mode"]):
                    raise ContractError("PAYLOAD_TAMPERED", "File metadata mismatch")
                hasher = hashlib.sha256()
                try:
                    fd = os.open(file_path, os.O_RDONLY | os.O_NOFOLLOW)
                    with open(fd, "rb", closefd=True) as fp:
                        while chunk := fp.read(1024 * 1024): hasher.update(chunk)
                except OSError:
                    raise ContractError("PAYLOAD_TAMPERED", "Cannot read payload file safely")
                if hasher.hexdigest() != exp["sha256"]:
                    raise ContractError("PAYLOAD_TAMPERED", "File hash mismatch")
            else:
                raise ContractError("UNSAFE_MEMBER", "Special non-regular member in payload")

    if actual_seen != set(expected_by_path.keys()):
        if set(expected_by_path.keys()) - actual_seen:
            raise ContractError("PAYLOAD_TAMPERED", "Missing expected payload members")
        raise ContractError("EXTRA_PAYLOAD_ENTRY", "Unexpected entry in payload")


def extract_archive_to_payload(archive_path: Path | str, target_payload_dir: Path, members: List[Dict[str, Any]]) -> None:
    """Extract archive into target_payload_dir applying exact archive modes and verifying bytes."""
    path = Path(archive_path).resolve()
    validate_ancestry_not_symlink(path)
    if not path.is_file():
        raise ContractError("INVALID_ARCHIVE", "Archive file does not exist")
    expected_by_path = {m["path"]: m for m in members}
    root_name = members[0]["path"].split("/")[0]
    dirs_to_chmod: List[Tuple[Path, int]] = []
    seen_in_archive: Set[str] = set()

    try:
        raw_fd = os.open(str(path), os.O_RDONLY | os.O_NOFOLLOW)
        with open(raw_fd, "rb", closefd=True) as raw:
            # Pass 1: Validate entire archive layout against manifest before any disk writes
            with gzip.GzipFile(fileobj=raw) as decomp, tarfile.open(fileobj=decomp, mode="r|") as archive:
                for item in archive:
                    name = item.name.rstrip("/") if item.isdir() else item.name
                    validate_safe_relative_posix_path(name)
                    expected = expected_by_path.get(name)
                    if expected is None:
                        raise ContractError("EXTRA_PAYLOAD_ENTRY", "Archive member not in manifest")
                    if name in seen_in_archive:
                        raise ContractError("DUPLICATE_MEMBER", "Duplicate archive path")
                    seen_in_archive.add(name)

                    if item.isdir():
                        if expected["type"] != "directory":
                            raise ContractError("PAYLOAD_TAMPERED", "Archive member type mismatch")
                    elif item.isfile():
                        if expected["type"] != "file":
                            raise ContractError("PAYLOAD_TAMPERED", "Archive member type mismatch")
                        if item.size != expected["size"]:
                            raise ContractError("PAYLOAD_TAMPERED", "Archive member size mismatch")
                    elif item.issym():
                        if expected["type"] != "symlink":
                            raise ContractError("PAYLOAD_TAMPERED", "Archive member type mismatch")
                        if item.linkname != expected.get("target"):
                            raise ContractError("PAYLOAD_TAMPERED", "Archive symlink target mismatch")
                        validate_symlink_target(item.linkname, name, root_name)
                    else:
                        raise ContractError("UNSAFE_MEMBER", "Unsupported archive member")

            if seen_in_archive != set(expected_by_path.keys()):
                raise ContractError("INVALID_ARCHIVE", "Archive did not contain all manifest members")

            # Validate ancestry layout across all members before writes
            for name in seen_in_archive:
                is_sidecar = any("sidecar" in part for part in name.split("/"))
                if is_sidecar and expected_by_path[name]["type"] == "symlink":
                    raise ContractError("UNSAFE_LINK", "Symlinks forbidden in sidecar ancestry")
                parent = posixpath.dirname(name)
                while parent:
                    parent_exp = expected_by_path.get(parent)
                    if parent_exp is None or parent_exp["type"] != "directory":
                        raise ContractError("UNSAFE_LINK", "Archive member has a non-directory ancestor")
                    parent = posixpath.dirname(parent)

            # Pass 2: Extract to disk with safe no-follow directory and file operations
            raw.seek(0)
            with gzip.GzipFile(fileobj=raw) as decomp, tarfile.open(fileobj=decomp, mode="r|") as archive:
                for item in archive:
                    name = item.name.rstrip("/") if item.isdir() else item.name
                    expected = expected_by_path[name]
                    dest = target_payload_dir / name

                    if item.isdir():
                        ensure_safe_parent_dir(target_payload_dir, name)
                        if os.path.islink(dest):
                            raise ContractError("UNSAFE_LINK", "Symlink encountered where directory expected")
                        dest.mkdir(mode=0o700, exist_ok=True)
                        dirs_to_chmod.append((dest, expected["mode"]))
                    elif item.isfile():
                        ensure_safe_parent_dir(target_payload_dir, name)
                        if os.path.islink(dest):
                            raise ContractError("UNSAFE_LINK", "Symlink encountered where file expected")
                        if (stream := archive.extractfile(item)) is None:
                            raise ContractError("INVALID_ARCHIVE", "Could not read archive file member")
                        out_fd = os.open(str(dest), os.O_CREAT | os.O_WRONLY | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
                        hasher = hashlib.sha256()
                        with open(out_fd, "wb", closefd=True) as out_fp:
                            while chunk := stream.read(1024 * 1024):
                                hasher.update(chunk)
                                out_fp.write(chunk)
                        if hasher.hexdigest() != expected["sha256"]:
                            raise ContractError("PAYLOAD_TAMPERED", "Extracted file hash mismatch")
                        os.chmod(dest, expected["mode"])
                    elif item.issym():
                        ensure_safe_parent_dir(target_payload_dir, name)
                        if os.path.islink(dest) or dest.exists():
                            dest.unlink()
                        os.symlink(item.linkname, dest)

            for d_path, mode in reversed(dirs_to_chmod):
                os.chmod(d_path, mode)
    except (OSError, tarfile.TarError, EOFError) as exc:
        if isinstance(exc, ContractError):
            raise
        raise ContractError("INVALID_ARCHIVE", "Archive extraction failed") from None


def copy_store_to_payload(store_path: Path | str, target_payload_dir: Path, members: List[Dict[str, Any]]) -> None:
    """Copy from read-only Nix store path to target_payload_dir, restoring original archive modes."""
    src_root = Path(store_path).resolve()
    validate_ancestry_not_symlink(src_root)
    if not src_root.exists():
        raise ContractError("INVALID_STORE_PATH", "Store path does not exist")
    root_name = members[0]["path"].split("/")[0]
    base_src = src_root.parent if src_root.name == root_name else src_root
    for candidate in [src_root, src_root / "Applications", src_root / "lib"]:
        if (candidate / root_name).is_dir():
            base_src = candidate
            break
    dirs_to_chmod: List[Tuple[Path, int]] = []
    for item in members:
        rel = item["path"]
        src_item, dest_item = base_src / rel, target_payload_dir / rel
        if item["type"] == "directory":
            ensure_safe_parent_dir(target_payload_dir, rel)
            if os.path.islink(dest_item):
                raise ContractError("UNSAFE_LINK", "Symlink encountered where directory expected")
            dest_item.mkdir(mode=0o700, exist_ok=True)
            dirs_to_chmod.append((dest_item, item["mode"]))
        elif item["type"] == "symlink":
            ensure_safe_parent_dir(target_payload_dir, rel)
            if dest_item.is_symlink() or dest_item.exists():
                dest_item.unlink()
            os.symlink(item["target"], dest_item)
        elif item["type"] == "file":
            ensure_safe_parent_dir(target_payload_dir, rel)
            if os.path.islink(dest_item):
                raise ContractError("UNSAFE_LINK", "Symlink encountered where file expected")
            if not src_item.is_file():
                raise ContractError("INVALID_STORE_PATH", "Store file not found")
            hasher = hashlib.sha256()
            src_fd = os.open(str(src_item), os.O_RDONLY | os.O_NOFOLLOW)
            dest_fd = os.open(str(dest_item), os.O_CREAT | os.O_WRONLY | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
            with open(src_fd, "rb", closefd=True) as s_fp, open(dest_fd, "wb", closefd=True) as d_fp:
                while chunk := s_fp.read(1024 * 1024):
                    hasher.update(chunk)
                    d_fp.write(chunk)
            if hasher.hexdigest() != item["sha256"]:
                raise ContractError("PAYLOAD_TAMPERED", "Store file hash mismatch")
            os.chmod(dest_item, item["mode"])
    for d_path, mode in reversed(dirs_to_chmod):
        os.chmod(d_path, mode)


class MaterializeLock:
    """Process-level lock using fcntl.flock with predictable directory mode and privacy."""

    def __init__(self, lock_file: Path) -> None:
        self.lock_file, self.fd = lock_file, None

    def __enter__(self) -> MaterializeLock:
        lock_dir = self.lock_file.parent
        lock_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
        os.chmod(lock_dir, 0o700)
        self.fd = os.open(str(self.lock_file), os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        try:
            fcntl.flock(self.fd, fcntl.LOCK_EX)
        except OSError as exc:
            os.close(self.fd)
            self.fd = None
            raise ContractError("LOCK_FAILED", "Failed to acquire materialize lock") from exc
        return self

    def __exit__(self, exc_type: Any, *args: Any) -> None:
        if self.fd is not None:
            try:
                try:
                    fcntl.flock(self.fd, fcntl.LOCK_UN)
                except OSError as exc:
                    if exc_type is None:
                        raise ContractError("LOCK_FAILED", "Failed to release materialize lock") from exc
            finally:
                os.close(self.fd)
                self.fd = None


def materialize_payload(
    source: Path | str,
    cache_root: Path | str,
    manifest: Any = None,
    *,
    source_is_store: bool = False,
    expected_manifest_sha256: Optional[str] = None,
) -> Path:
    """Safely materialize a payload into an atomic, validated cache outside the Nix store."""
    cache_dir = validate_ancestry_not_symlink(cache_root)
    cache_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(cache_dir, 0o700)

    if manifest is None and not source_is_store:
        inspected = inspect_archive(source, commands={})
        members, root_name, manifest_sha256 = inspected["members"], inspected["root"], inspected["manifest_sha256"]
    else:
        members, root_name, manifest_sha256 = parse_manifest_members(manifest)

    if expected_manifest_sha256 is not None:
        if (
            not isinstance(expected_manifest_sha256, str)
            or len(expected_manifest_sha256) != 64
            or any(c not in "0123456789abcdef" for c in expected_manifest_sha256)
        ):
            raise ContractError("INVALID_DIGEST", "Expected manifest SHA256 must be a 64-character lowercase hex digest")
        if expected_manifest_sha256 != manifest_sha256:
            raise ContractError("MANIFEST_TAMPERED", "Expected manifest SHA256 mismatch")

    cache_key = manifest_sha256
    entry_dir, payload_dir = cache_dir / "entries" / cache_key, cache_dir / "entries" / cache_key / "payload"
    lock_file = cache_dir / ".locks" / f"{cache_key}.lock"

    with MaterializeLock(lock_file):
        if entry_dir.is_dir() and payload_dir.is_dir():
            try:
                verify_payload_directory(payload_dir, members)
                return payload_dir / root_name
            except ContractError:
                safe_rmtree(entry_dir, confinement_root=cache_dir)

        staging_dir = cache_dir / ".staging" / f"{cache_key}.{os.getpid()}"
        staging_payload = staging_dir / "payload"
        if staging_dir.exists():
            safe_rmtree(staging_dir, confinement_root=cache_dir)
        staging_payload.mkdir(mode=0o700, parents=True, exist_ok=True)
        os.chmod(staging_dir, 0o700)

        try:
            if source_is_store:
                copy_store_to_payload(source, staging_payload, members)
            else:
                extract_archive_to_payload(source, staging_payload, members)
            verify_payload_directory(staging_payload, members)
            meta = {
                "manifest_sha256": manifest_sha256,
                "root_name": root_name,
                "member_count": len(members),
                "source_is_store": source_is_store,
            }
            (staging_dir / "meta.json").write_bytes(canonical(meta))
            (staging_dir / "manifest.json").write_bytes(canonical(members))
            entry_dir.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            if entry_dir.exists():
                safe_rmtree(entry_dir, confinement_root=cache_dir)
            os.replace(str(staging_dir), str(entry_dir))
        finally:
            if staging_dir.exists():
                safe_rmtree(staging_dir, confinement_root=cache_dir)
        return payload_dir / root_name


def resolve_launcher(materialized_root: Path, launcher_relpath: str) -> Path:
    """Validate and resolve launcher binary path relative to materialized root."""
    validate_safe_relative_posix_path(launcher_relpath)
    launcher_path = materialized_root / launcher_relpath
    curr = launcher_path
    while curr != materialized_root.parent:
        if curr.is_symlink():
            raise ContractError("UNSAFE_LINK", "Symlinks forbidden in launch ancestry")
        curr = curr.parent
    if not launcher_path.is_file():
        raise ContractError("COMMAND_PATH", "Launcher not found")
    if not (launcher_path.stat().st_mode & 0o111):
        raise ContractError("COMMAND_PATH", "Launcher is not executable")
    return launcher_path


def main(argv: Optional[List[str]] = None) -> int:
    """CLI entrypoint for Nix wrappers and external invocations."""
    parser = argparse.ArgumentParser(description="RS9 Safe Runtime Materializer")
    for opt, kwargs in [("--archive", {}), ("--store-path", {}), ("--manifest", {"default": ""}),
                        ("--expected-manifest-sha256", {}), ("--cache-dir", {"required": True}),
                        ("--launcher", {}), ("--verify-only", {"action": "store_true"})]:
        parser.add_argument(opt, **kwargs)
    parser.add_argument("cmd_args", nargs="*")
    args = parser.parse_args(argv)
    if not args.archive and not args.store_path:
        sys.stderr.write("Error: either --archive or --store-path required\n"); return 2
    m_data = json.loads(Path(args.manifest).read_bytes()) if args.manifest and Path(args.manifest).is_file() else None
    root = materialize_payload(args.store_path or args.archive, Path(args.cache_dir), m_data,
                               source_is_store=bool(args.store_path), expected_manifest_sha256=args.expected_manifest_sha256)
    if args.verify_only:
        sys.stdout.write("OK: Verified\n"); return 0
    if args.launcher:
        exe = resolve_launcher(root, args.launcher); os.execv(str(exe), [str(exe), *args.cmd_args])
    sys.stdout.write(f"{root}\n"); return 0


if __name__ == "__main__":
    sys.exit(main())
