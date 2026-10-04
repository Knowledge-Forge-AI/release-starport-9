"""Bounded tar.gz inspection without extracting untrusted members."""
import hashlib
import os
import posixpath
import tarfile
import unicodedata
import gzip
import stat
from pathlib import Path

from rs9.errors import ContractError
from rs9.scratch import canonical
from rs9.security import validate_safe_relative_posix_path


class _DecompressionLimit:
    def __init__(self, stream, limit):
        self.stream, self.limit, self.count = stream, limit, 0

    def read(self, size=-1):
        if size < 0 or size > self.limit - self.count:
            size = self.limit - self.count + 1
        data = self.stream.read(size)
        self.count += len(data)
        if self.count > self.limit:
            raise ContractError("ARCHIVE_LIMIT", "Decompressed archive including metadata exceeds bound")
        return data


def inspect_archive(path, commands, *, command_policy="native-executable", on_file=None, max_members=20000,
                    max_member_bytes=256 * 1024 ** 2, max_total_bytes=1024 ** 3,
                    max_ratio=1000):
    """Check the complete structure before handing any bytes to a visitor."""
    if command_policy not in {"native-executable", "npm-package-bin"}:
        raise ContractError("INVALID_SELECTION", "Unknown command execution policy")
    path = Path(path)
    if any(p.is_symlink() for p in (path, *path.parents)):
        raise ContractError("SYMLINK_REJECTED", "Archive input cannot traverse symlinks")
    roots = {p.split("/")[0] for p in commands.values()}
    for command in commands.values():
        validate_safe_relative_posix_path(command)
    entries, root, total = {}, None, 0
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
        with os.fdopen(descriptor, "rb") as raw:
            info = os.fstat(raw.fileno())
            if not stat.S_ISREG(info.st_mode):
                raise ContractError("INVALID_ARCHIVE", "Regular archive input required")
            compressed_size = info.st_size
            decompressed_limit = min(max_total_bytes + max_members * 1024, max(1, compressed_size) * max_ratio)
            with gzip.GzipFile(fileobj=raw) as decoded, tarfile.open(fileobj=_DecompressionLimit(decoded, decompressed_limit), mode="r|") as archive:
                for member in archive:
                    if len(entries) >= max_members:
                        raise ContractError("ARCHIVE_LIMIT", "Archive member count exceeds limit")
                    name = member.name.rstrip("/") if member.isdir() else member.name
                    validate_safe_relative_posix_path(name)
                    current_root = name.split("/")[0]
                    root = root or current_root
                    if current_root != root or (roots and roots != {root}):
                        raise ContractError("ARCHIVE_ROOT", "Archive must have the declared single root")
                    if name in entries:
                        raise ContractError("DUPLICATE_MEMBER", "Duplicate archive path")
                    if member.mode & 0o6000:
                        raise ContractError("UNSAFE_MODE", "Privileged archive mode forbidden")
                    if member.islnk() or member.type in (tarfile.LNKTYPE, "1", b"1"):
                        raise ContractError("UNSAFE_LINK", "Archive hard links forbidden")
                    if member.size < 0 or member.size > max_member_bytes:
                        raise ContractError("ARCHIVE_LIMIT", "Archive member size exceeds limit")
                    total += member.size
                    if total > max_total_bytes or total > max(1, compressed_size) * max_ratio:
                        raise ContractError("ARCHIVE_LIMIT", "Archive total or compression ratio exceeds limit")
                    entry = {"path": name, "mode": member.mode & 0o777, "size": member.size}
                    if member.isfile():
                        entry["type"] = "file"
                        stream = archive.extractfile(member)
                        hasher, count = hashlib.sha256(), 0
                        while True:
                            chunk = stream.read(1024 * 1024)
                            if not chunk:
                                break
                            count += len(chunk)
                            hasher.update(chunk)
                        if count != member.size:
                            raise ContractError("INVALID_ARCHIVE", "Truncated regular archive member")
                        entry["sha256"] = hasher.hexdigest()
                    elif member.isdir():
                        entry["type"] = "directory"
                    elif member.issym():
                        entry["type"] = "symlink"
                        target = member.linkname
                        if (not target or target.startswith("/") or "\\" in target
                                or unicodedata.normalize("NFC", target) != target
                                or any(ord(c) < 32 or ord(c) == 127 for c in target)):
                            raise ContractError("UNSAFE_LINK", "Unsafe archive link target")
                        entry["target"] = target
                    else:
                        raise ContractError("UNSAFE_MEMBER", "Archive special member forbidden")
                    entries[name] = entry
            if not entries:
                raise ContractError("ARCHIVE_ROOT", "Empty archive")

            def resolve(name, seen=()):
                parts, resolved = name.split("/"), []
                while parts:
                    part = parts.pop(0)
                    if part in ("", "."):
                        continue
                    if part == "..":
                        if len(resolved) <= 1:
                            raise ContractError("UNSAFE_LINK", "Link leaves archive root")
                        resolved.pop()
                        continue
                    resolved.append(part)
                    if resolved[0] != root:
                        raise ContractError("UNSAFE_LINK", "Link leaves archive root")
                    current = "/".join(resolved)
                    entry = entries.get(current, {})
                    if entry.get("type") == "symlink":
                        if current in seen or len(seen) > 64:
                            raise ContractError("UNSAFE_LINK", "Archive link cycle or excessive chain")
                        target = posixpath.dirname(current) + "/" + entry["target"]
                        suffix = "/".join(parts)
                        return resolve(target + ("/" + suffix if suffix else ""), (*seen, current))
                return "/".join(resolved)

            for name, entry in entries.items():
                parent = posixpath.dirname(name)
                while parent:
                    if entries.get(parent, {}).get("type", "directory") != "directory":
                        raise ContractError("UNSAFE_LINK", "Archive member has a non-directory ancestor")
                    parent = posixpath.dirname(parent)
                if entry["type"] == "symlink":
                    target = resolve(name)
            command_records = {}
            for command, name in commands.items():
                entry = entries.get(name, {})
                reason = ("missing" if not entry else "not-regular" if entry.get("type") != "file"
                          else "not-executable" if command_policy == "native-executable" and not entry["mode"] & 0o111 else None)
                if reason:
                    launcher = command.startswith("launcher:")
                    raise ContractError("COMMAND_PATH", "Command member violates its execution policy", details={
                        "command": command[9:] if launcher else command, "archive_path": name,
                        "command_kind": "launcher" if launcher else "command",
                        "member_type": entry.get("type", "missing"), "mode": entry.get("mode", 0), "reason": reason})
                command_records[command] = {k: entry[k] for k in ("path", "sha256", "size", "mode")}
            if on_file is not None:
                raw.seek(0)
                with gzip.GzipFile(fileobj=raw) as decoded, tarfile.open(fileobj=_DecompressionLimit(decoded, decompressed_limit), mode="r|") as archive:
                    for member in archive:
                        if member.isfile():
                            data = archive.extractfile(member).read(max_member_bytes + 1)
                            if (member.name not in entries or len(data) != member.size
                                    or member.mode & 0o777 != entries[member.name]["mode"]
                                    or hashlib.sha256(data).hexdigest() != entries[member.name].get("sha256")):
                                raise ContractError("INPUT_CHANGED", "Archive changed during inspection")
                            on_file(member.name, data, member.mode & 0o777)
    except (OSError, tarfile.TarError, EOFError):
        raise ContractError("INVALID_ARCHIVE", "Unreadable or malformed tar.gz") from None
    members = [entries[n] for n in sorted(entries)]
    return {"root": root, "members": members, "commands": command_records,
            "manifest_sha256": hashlib.sha256(canonical(members)).hexdigest()}
