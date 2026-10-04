"""Authenticated, closed extraction policy for the official Nix binary installer."""
import hashlib
import io
import json
import lzma
import os
from pathlib import Path
import platform
import re
import stat
import subprocess
import tarfile
import zlib

from rs9.errors import ContractError, safe_details
from rs9.github import PublicClient
from rs9.release_core import digest
from rs9.scratch import canonical, physical_directory

INSTALLER_SYSTEMS = ("aarch64-darwin", "x86_64-linux", "aarch64-linux")
MAX_ARCHIVE = 256 * 1024 ** 2
MAX_MEMBERS = 50000
MAX_UNCOMPRESSED = 2 * 1024 ** 3
STORE_PATH = re.compile(r"[0-9a-df-np-sv-z]{32}-[A-Za-z0-9+._?=-]+\Z")


def get_current_system():
    arch = {"arm64": "aarch64", "aarch64": "aarch64", "x86_64": "x86_64"}.get(platform.machine())
    host = {"Darwin": "darwin", "Linux": "linux"}.get(platform.system())
    system = str(arch) + "-" + str(host)
    if system not in INSTALLER_SYSTEMS:
        raise ContractError("NIX_SYSTEM", "Unsupported official Nix installer system")
    return system


def get_installer_pin(targets, system):
    if system not in INSTALLER_SYSTEMS:
        raise ContractError("NIX_SYSTEM", "Unsupported official Nix installer system")
    pins = targets.get("installer_sha256_by_system")
    if (not isinstance(pins, dict) or set(pins) != set(INSTALLER_SYSTEMS)
            or any(not isinstance(v, str) or not re.fullmatch(r"[0-9a-f]{64}", v) for v in pins.values())):
        raise ContractError("NIX_PIN", "Exactly three source-pinned installer SHA-256 identities required")
    return pins[system]


def _unsafe(reason):
    raise ContractError("NIX_INSTALLER_UNSAFE", "Official installer archive violates its closed extraction policy",
                        details={"substage": "installer-archive-validation", "reason": reason})


def validate_archive_members(members, expected_top):
    """Validate the complete inventory, including forward ancestors, before any write."""
    if not members or len(members) > MAX_MEMBERS:
        _unsafe("member-count")
    entries, directories, total = {}, set(), 0
    for entry in members:
        name = entry.name[:-1] if entry.isdir() and entry.name.endswith("/") else entry.name
        parts = name.split("/")
        if (not name or "\\" in name or "\x00" in name or any(p in {"", ".", ".."} for p in parts)
                or parts[0] != expected_top):
            _unsafe("member-path")
        if name in entries:
            _unsafe("duplicate-member")
        if entry.type not in {tarfile.DIRTYPE, tarfile.REGTYPE, tarfile.AREGTYPE, tarfile.SYMTYPE} or entry.sparse is not None:
            _unsafe("member-type")
        if (entry.mode < 0 or entry.mode & 0o7000 or entry.size < 0
                or (not entry.isreg() and entry.size != 0)):
            _unsafe("member-metadata")
        if name == expected_top and not entry.isdir():
            _unsafe("top-level-directory")
        entries[name] = entry
        if entry.isreg():
            total += entry.size
            if total > MAX_UNCOMPRESSED:
                _unsafe("uncompressed-size")
        if entry.isdir():
            directories.add(name)
        for i in range(1, len(parts)):
            directories.add("/".join(parts[:i]))
    for name in directories:
        if name in entries and not entries[name].isdir():
            _unsafe("non-directory-ancestor")
    for name, entry in entries.items():
        if not entry.issym():
            continue
        target = entry.linkname
        if not target or "\\" in target or "\x00" in target:
            _unsafe("symlink-target")
        if target.startswith("/"):
            parts = target.split("/")
            if (len(parts) < 4 or parts[:3] != ["", "nix", "store"]
                    or not STORE_PATH.fullmatch(parts[3])
                    or any(p in {"", ".", ".."} or not re.fullmatch(r"[A-Za-z0-9+._?=-]+", p) for p in parts[3:])):
                _unsafe("absolute-symlink-target")
            archived = expected_top + "/store/" + "/".join(parts[3:])
            if archived not in entries and archived not in directories:
                _unsafe("store-target-not-archived")
    # Resolve link components in order, rather than cancelling '..' lexically.
    # Absolute links use a virtual projection of the authenticated /nix/store inventory.
    def resolve_link(name, target, require_archived=False):
        pending = target.split("/")
        stack = name.split("/")[:-1]
        if target.startswith("/"):
            stack, pending = [], (expected_top + "/store/" + "/".join(pending[3:])).split("/")
        hops = 0
        while pending:
            part, pending = pending[0], pending[1:]
            if part in ("", "."):
                continue
            if part == "..":
                if require_archived:
                    _unsafe("ambiguous-upward-traversal")
                if len(stack) <= 1:
                    _unsafe("relative-symlink-escape")
                stack.pop()
                continue
            candidate = "/".join([*stack, part])
            node = entries.get(candidate)
            if node is not None and node.issym():
                hops += 1
                if hops > 64:
                    _unsafe("symlink-loop")
                link = node.linkname
                if link.startswith("/"):
                    stack = []
                    link = expected_top + "/store/" + "/".join(link.split("/")[3:])
                    require_archived = True
                pending = link.split("/") + pending
            else:
                stack.append(part)
                if node is not None and not node.isdir() and pending:
                    _unsafe("symlink-nondirectory")
        resolved = "/".join(stack)
        if not stack or stack[0] != expected_top:
            _unsafe("relative-symlink-escape")
        if require_archived and resolved not in entries and resolved not in directories:
            _unsafe("store-target-not-archived")
    for name, entry in entries.items():
        if entry.issym():
            resolve_link(name, entry.linkname, entry.linkname.startswith("/"))
    rows = [{"path": name, "type": "directory" if e.isdir() else "file" if e.isreg() else "symlink",
             "mode": e.mode, "size": e.size, **({"target": e.linkname} if e.issym() else {})}
            for name, e in sorted(entries.items())]
    return entries, directories, {"member_count": len(rows), "uncompressed_bytes": total,
        "regular_files": sum(e.isreg() for e in entries.values()),
        "directories": sum(e.isdir() for e in entries.values()),
        "symlinks": sum(e.issym() for e in entries.values()),
        "absolute_store_symlinks": sum(e.issym() and e.linkname.startswith("/") for e in entries.values()),
        "extraction_manifest_sha256": digest(canonical(rows))}


def _open_directory(root_fd, parts):
    current = os.dup(root_fd)
    try:
        for part in parts:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=current)
            os.close(current)
            current = child
        return current
    except BaseException:
        os.close(current)
        raise


def _cleanup_directory(fd):
    """Remove partial output without following links; writable directory modes come first."""
    os.fchmod(fd, 0o700)
    for name in os.listdir(fd):
        info = os.stat(name, dir_fd=fd, follow_symlinks=False)
        if stat.S_ISDIR(info.st_mode):
            child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            try:
                _cleanup_directory(child)
            finally:
                os.close(child)
            os.rmdir(name, dir_fd=fd)
        else:
            os.unlink(name, dir_fd=fd)


def verify_physical_inventory(root_fd, expected):
    """Read back physical types, bytes, modes and link targets through no-follow descriptors."""
    rows = []
    def walk(fd, prefix):
        for name in sorted(os.listdir(fd)):
            relative = prefix + name
            info = os.stat(name, dir_fd=fd, follow_symlinks=False)
            if stat.S_ISDIR(info.st_mode):
                row = {"path": relative, "type": "directory", "mode": stat.S_IMODE(info.st_mode) & 0o755}
                child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
                try:
                    walk(child, relative + "/")
                finally:
                    os.close(child)
            elif stat.S_ISREG(info.st_mode):
                file_fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=fd)
                hasher, size = hashlib.sha256(), 0
                with os.fdopen(file_fd, "rb") as stream:
                    for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                        size += len(chunk)
                        hasher.update(chunk)
                row = {"path": relative, "type": "file", "mode": stat.S_IMODE(info.st_mode) & 0o755,
                       "size": size, "sha256": hasher.hexdigest()}
            elif stat.S_ISLNK(info.st_mode):
                row = {"path": relative, "type": "symlink", "target": os.readlink(name, dir_fd=fd)}
            else:
                _unsafe("physical-special-member")
            rows.append(row)
    walk(root_fd, "")
    rows.sort(key=lambda r: r["path"])
    if rows != sorted(expected.values(), key=lambda r: r["path"]):
        _unsafe("physical-inventory-mismatch")
    return digest(canonical(rows))


def extract_installer_archive(archive_path, target_dir, *, expected_sha256, version, system):
    """Authenticate an immutable in-memory snapshot, then perform confined writes and readback."""
    if (system not in INSTALLER_SYSTEMS or not isinstance(version, str)
            or not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", version)
            or not isinstance(expected_sha256, str) or not re.fullmatch(r"[0-9a-f]{64}", expected_sha256)):
        raise ContractError("NIX_PIN", "Exact official installer version, system and SHA-256 required")
    archive_path = Path(archive_path)
    physical_directory(archive_path.parent)
    fd = os.open(archive_path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(fd, "rb") as stream:
        if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
            _unsafe("archive-type")
        raw = stream.read(MAX_ARCHIVE + 1)
    if len(raw) > MAX_ARCHIVE or digest(raw) != expected_sha256:
        raise ContractError("NIX_INSTALLER_CHECKSUM", "Installer archive differs from its exact source pin")
    target = physical_directory(target_dir)
    if any(target.iterdir()):
        raise ContractError("OUTPUT_NOT_EMPTY", "Empty physical installer extraction root required")
    expected_top = "nix-" + version + "-" + system
    root_fd, wrote = None, False
    try:
        with tarfile.open(fileobj=io.BytesIO(raw), mode="r:*") as tar:
            members, total = [], 0
            for entry in tar:
                members.append(entry)
                total += max(0, entry.size)
                if len(members) > MAX_MEMBERS or total > MAX_UNCOMPRESSED:
                    _unsafe("archive-limit")
            entries, directories, evidence = validate_archive_members(members, expected_top)
            if (not all(call in os.supports_dir_fd for call in (os.open, os.mkdir, os.symlink, os.stat, os.readlink, os.unlink, os.rmdir))
                    or os.listdir not in os.supports_fd):
                raise ContractError("NIX_INSTALLER_CONFINEMENT", "Descriptor-relative extraction is unavailable")
            root_fd = os.open(target, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            target_mode = stat.S_IMODE(os.fstat(root_fd).st_mode)
            if os.listdir(root_fd):
                raise ContractError("OUTPUT_NOT_EMPTY", "Installer root changed before extraction")
            physical = {}
            for name in sorted(directories, key=lambda p: (p.count("/"), p)):
                parts = name.split("/")
                parent_fd = _open_directory(root_fd, parts[:-1])
                try:
                    wrote = True
                    os.mkdir(parts[-1], 0o755, dir_fd=parent_fd)
                    physical[name] = {"path": name, "type": "directory",
                                      "mode": (entries[name].mode if name in entries else 0o755) & 0o755}
                finally:
                    os.close(parent_fd)
            for name, entry in entries.items():
                if not entry.isreg():
                    continue
                source = tar.extractfile(entry)
                if source is None:
                    _unsafe("member-data")
                parts = name.split("/")
                parent_fd = _open_directory(root_fd, parts[:-1])
                try:
                    with source:
                        out_fd = os.open(parts[-1], os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600, dir_fd=parent_fd)
                        with os.fdopen(out_fd, "wb") as output:
                            copied, hasher = 0, hashlib.sha256()
                            for chunk in iter(lambda: source.read(1024 * 1024), b""):
                                copied += len(chunk)
                                if copied > entry.size:
                                    _unsafe("member-size")
                                hasher.update(chunk)
                                output.write(chunk)
                            if copied != entry.size:
                                _unsafe("member-size")
                            os.fchmod(output.fileno(), entry.mode & 0o755)
                    physical[name] = {"path": name, "type": "file", "mode": entry.mode & 0o755,
                                      "size": copied, "sha256": hasher.hexdigest()}
                finally:
                    os.close(parent_fd)
            for name, entry in entries.items():
                if entry.issym():
                    parts = name.split("/")
                    parent_fd = _open_directory(root_fd, parts[:-1])
                    try:
                        os.symlink(entry.linkname, parts[-1], dir_fd=parent_fd)
                        physical[name] = {"path": name, "type": "symlink", "target": entry.linkname}
                    finally:
                        os.close(parent_fd)
            for name in sorted(directories, key=lambda p: (-p.count("/"), p)):
                directory_fd = _open_directory(root_fd, name.split("/"))
                try:
                    os.fchmod(directory_fd, physical[name]["mode"])
                finally:
                    os.close(directory_fd)
            evidence["physical_manifest_sha256"] = verify_physical_inventory(root_fd, physical)
            installer = physical.get(expected_top + "/install", {})
            if installer.get("type") != "file" or not installer.get("mode", 0) & 0o111:
                raise ContractError("NIX_INSTALLER", "Physical executable installer required")
            verify_physical_executable(target / expected_top / "install")
            evidence["install_sha256"] = installer["sha256"]
            return evidence
    except BaseException as error:
        cleanup = "not-needed"
        root_mode_restored = True
        if wrote and root_fd is not None:
            try:
                _cleanup_directory(root_fd)
                cleanup = "complete"
            except OSError:
                cleanup = "failed"
            finally:
                try:
                    os.fchmod(root_fd, target_mode)
                except OSError:
                    root_mode_restored = False
                    cleanup = "failed"
        if isinstance(error, ContractError):
            raise ContractError(error.code, error.message, details={**error.details, "cleanup": cleanup,
                                                                  "root_mode_restored": root_mode_restored}) from None
        if isinstance(error, (tarfile.TarError, EOFError, OSError, lzma.LZMAError, zlib.error, ValueError)):
            raise ContractError("NIX_INSTALLER_EXTRACTION", "Authenticated installer extraction failed safely",
                                details={"cleanup": cleanup, "root_mode_restored": root_mode_restored}) from None
        raise
    finally:
        if root_fd is not None:
            os.close(root_fd)


def verify_physical_executable(installer):
    path = Path(installer)
    physical_directory(path.parent)
    try:
        info = path.lstat()
    except OSError:
        raise ContractError("NIX_INSTALLER", "Physical installer executable is missing") from None
    if not stat.S_ISREG(info.st_mode) or not info.st_mode & 0o111:
        raise ContractError("NIX_INSTALLER", "Installer must be a physical executable regular file")


def retain_installer_identity(scratch, version, system, sha256, *, status="pass", error=None, **identity):
    doc = {"version": version, "system": system, "sha256": sha256,
           "archive_sha256": sha256, "pin_provenance": "source-pinned", "status": status, **identity}
    if error is not None:
        doc["error"] = error.code if isinstance(error, ContractError) else "NIX_INSTALLER_INTERNAL"
        doc["error_detail"] = error.details if isinstance(error, ContractError) else safe_details({"exception_type": type(error).__name__})
    path = scratch / "installer-identity.json"
    path.write_bytes(canonical(doc))
    if status == "fail":
        (scratch / "installer-failure.json").write_bytes(canonical(doc))
    return path


def install(repository, scratch, *, client=None, runner=subprocess.run):
    scratch = Path(scratch).absolute()
    physical_directory(scratch.parent)
    scratch.mkdir(exist_ok=False)
    system, version, expected = None, None, None
    try:
        targets = json.loads((repository / "operators/live1/targets.json").read_bytes())["nix"]
        system, version = get_current_system(), targets["installer_version"]
        expected = get_installer_pin(targets, system)
        filename = "nix-" + version + "-" + system + ".tar.xz"
        url = "https://releases.nixos.org/nix/nix-" + version + "/" + filename
        client = client or PublicClient()
        data = client.get(url, request_class="nix-installer", limit=MAX_ARCHIVE)
        if digest(data) != expected:
            raise ContractError("NIX_INSTALLER_CHECKSUM", "Official installer archive differs from source pin")
        archive = scratch / filename
        archive.write_bytes(data)
        extract_root = scratch / "extracted"
        extract_root.mkdir()
        extraction = extract_installer_archive(archive, extract_root, expected_sha256=expected, version=version, system=system)
        installer = extract_root / ("nix-" + version + "-" + system) / "install"
        verify_physical_executable(installer)
        result = runner(["sh", str(installer), "--daemon", "--yes"], capture_output=True, check=False, timeout=1200)
        if result.returncode:
            raise ContractError("NIX_INSTALLER_EXECUTION", "Official authenticated installer returned failure",
                details={"tool": "sh", "substage": "installer-execution", "exit_code": result.returncode,
                         "stdout_sha256": digest(result.stdout), "stderr_sha256": digest(result.stderr)})
        retain_installer_identity(scratch, version, system, expected, url=url, extraction=extraction)
        return {"version": version, "system": system, "sha256": expected, "status": "pass", "extraction": extraction}
    except Exception as error:
        retain_installer_identity(scratch, version, system, expected, status="fail", error=error)
        if isinstance(error, ContractError):
            raise
        raise ContractError("NIX_INSTALLER_INTERNAL", "Official installer preparation failed",
            details=safe_details({"substage": "installer-preparation", "exception_type": type(error).__name__})) from None
