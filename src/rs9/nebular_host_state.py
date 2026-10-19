"""Bounded read-only snapshots of the exact 63 Nebular Darwin state names without parent directory scans."""
from __future__ import annotations

import errno
import hashlib
import json
import os
from pathlib import Path
import pwd
import re
import stat
from typing import Any, Mapping

from rs9.tf_pypi_archive import AdmissionError, fail, physical_bytes

APPLICATION_IDENTIFIER = "ai.knowledgeforge.themeforge.nebularfusion"
NAMES = (
    APPLICATION_IDENTIFIER,
    "Theme Forge Nebular Fusion",
    "theme-forge-nebular-fusion",
)
BASES = (
    "Library/Caches",
    "Library/Application Support",
    "Library/WebKit",
    "Library/Logs",
    "Library/HTTPStorages",
    "Library/Saved Application State",
    "Library/Preferences",
)
SUFFIXES = ("", ".plist", ".savedState")
MAX_DEPTH = 32
MAX_ENTRIES = 5000
MAX_FILE_BYTES = 16 * 1024 * 1024
MAX_TOTAL_BYTES = 128 * 1024 * 1024
SCOPE_DESCRIPTION = (
    "63 exact Nebular names beneath actual operator home; "
    "only their directory descendants, no parent directory enumeration"
)


class HostStateError(AdmissionError):
    """Privacy-safe host-state observation failure recording only error code, target index, and errno."""

    def __init__(self, code: str, *, target_index: int | None = None, err_no: int | None = None):
        c = str(code).strip()
        if not c.startswith("TF_PYPI_"):
            c = f"TF_PYPI_{c}"
        super().__init__(c)
        self.target_index = target_index if isinstance(target_index, int) else None
        self.errno = err_no if isinstance(err_no, int) else None

    def public_details(self) -> dict[str, Any]:
        details: dict[str, Any] = {"code": self.code}
        if self.target_index is not None:
            details["target_index"] = self.target_index
        if self.errno is not None:
            details["errno"] = self.errno
            details["errno_name"] = errno.errorcode.get(self.errno, "UNKNOWN")
        return details


def operator_home() -> Path:
    """Resolve the real operator home directory from the account database, never $HOME."""
    pw_dir = pwd.getpwuid(os.getuid()).pw_dir
    if not pw_dir or not os.path.isabs(pw_dir):
        raise HostStateError("HOST_STATE_HOME_INVALID")
    return Path(pw_dir)


def target_relatives() -> tuple[str, ...]:
    """Return the exact 63 Darwin persistent-state relative paths in deterministic order."""
    return tuple(
        f"{base}/{name}{suffix}"
        for base in BASES
        for name in NAMES
        for suffix in SUFFIXES
    )


def verify_harness_targets(smoke_mjs_path: str | Path) -> dict[str, Any]:
    """Verify the authenticated native-rc-smoke.mjs defines the exact same 63 Darwin state targets."""
    raw = physical_bytes(Path(smoke_mjs_path), limit=512 * 1024)
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        fail("HOST_STATE_HARNESS_MISMATCH")

    app_match = re.search(
        r'export\s+const\s+APPLICATION_IDENTIFIER\s*=\s*"([^"]+)"\s*;',
        text,
    )
    fn_match = re.search(
        r"export\s+function\s+persistentStateLocations\s*\(.*?\)\s*\{(.*?)\n\}",
        text,
        re.DOTALL,
    )
    if not app_match or not fn_match:
        fail("HOST_STATE_HARNESS_MISMATCH")

    app_id = app_match.group(1)
    body = fn_match.group(1)
    names_match = re.search(
        r'const\s+names\s*=\s*\[\s*APPLICATION_IDENTIFIER\s*,\s*"([^"]+)"\s*,\s*"([^"]+)"\s*\]\s*;',
        body,
    )
    bases_match = re.search(
        r'platform\.startsWith\(\s*"darwin"\s*\)\s*\?\s*\[(.*?)\]\s*:',
        body,
        re.DOTALL,
    )
    if not names_match or not bases_match:
        fail("HOST_STATE_HARNESS_MISMATCH")

    parsed_names = (app_id, names_match.group(1), names_match.group(2))
    parsed_bases = tuple(re.findall(r'"([^"]+)"', bases_match.group(1)))
    has_suffixes = (
        "join(home, base, name)" in body
        and "join(home, base, `${name}.plist`)" in body
        and "join(home, base, `${name}.savedState`)" in body
    )
    if parsed_names != NAMES or parsed_bases != BASES or not has_suffixes:
        fail("HOST_STATE_HARNESS_MISMATCH")

    derived = tuple(
        f"{base}/{name}{suffix}"
        for base in parsed_bases
        for name in parsed_names
        for suffix in SUFFIXES
    )
    expected = target_relatives()
    if derived != expected or len(derived) != 63:
        fail("HOST_STATE_HARNESS_MISMATCH")

    return {
        "verified": True,
        "target_count": len(derived),
        "application_identifier": app_id,
        "targets_sha256": hashlib.sha256(
            json.dumps(derived, separators=(",", ":")).encode("utf-8")
        ).hexdigest(),
    }


def _check_ancestors_no_symlink(home: Path, target: Path, target_index: int) -> None:
    try:
        home_stat = os.lstat(home)
    except OSError as exc:
        raise HostStateError("HOST_STATE_IO", target_index=target_index, err_no=exc.errno) from None
    if stat.S_ISLNK(home_stat.st_mode) or not stat.S_ISDIR(home_stat.st_mode):
        raise HostStateError("HOST_STATE_SYMLINK_ANCESTOR", target_index=target_index)

    rel_parts = target.relative_to(home).parts[:-1]
    current = home
    for part in rel_parts:
        current = current / part
        try:
            st = os.lstat(current)
        except FileNotFoundError:
            return
        except OSError as exc:
            raise HostStateError("HOST_STATE_IO", target_index=target_index, err_no=exc.errno) from None
        if stat.S_ISLNK(st.st_mode):
            raise HostStateError("HOST_STATE_SYMLINK_ANCESTOR", target_index=target_index)
        if not stat.S_ISDIR(st.st_mode):
            raise HostStateError("HOST_STATE_ANCESTOR_NOT_DIR", target_index=target_index)


def snapshot(home: str | Path | None = None) -> dict[str, Any]:
    """Take a bounded, read-only metadata/digest snapshot of the 63 exact Nebular state paths."""
    root = operator_home() if home is None else Path(home)
    if not root.is_absolute():
        raise HostStateError("HOST_STATE_HOME_INVALID")

    entries: dict[str, dict[str, Any]] = {}
    total_bytes = 0
    existing_targets = 0
    relatives = target_relatives()

    def visit(path: Path, target_rel: str, sub_rel: str, depth: int, target_index: int) -> None:
        nonlocal total_bytes
        if depth > MAX_DEPTH:
            raise HostStateError("HOST_STATE_DEPTH_BOUND", target_index=target_index)
        if len(entries) >= MAX_ENTRIES:
            raise HostStateError("HOST_STATE_ENTRY_BOUND", target_index=target_index)
        key = (
            target_rel
            if not sub_rel
            else f"{target_rel}/sha256:{hashlib.sha256(sub_rel.encode('utf-8')).hexdigest()}"
        )
        try:
            info = os.lstat(path)
        except OSError as exc:
            raise HostStateError("HOST_STATE_IO", target_index=target_index, err_no=exc.errno) from None

        entry: dict[str, Any] = {
            "mode": stat.S_IMODE(info.st_mode),
            "uid": info.st_uid,
            "gid": info.st_gid,
            "mtime_ns": info.st_mtime_ns,
            "flags": getattr(info, "st_flags", 0),
        }
        if stat.S_ISLNK(info.st_mode):
            try:
                raw_target = os.fsencode(os.readlink(path))
            except OSError as exc:
                raise HostStateError("HOST_STATE_IO", target_index=target_index, err_no=exc.errno) from None
            entry.update(
                kind="symlink",
                link_target_sha256=hashlib.sha256(raw_target).hexdigest(),
            )
            entries[key] = entry
            return

        if stat.S_ISDIR(info.st_mode):
            entry["kind"] = "directory"
            entries[key] = entry
            try:
                with os.scandir(path) as it:
                    children = sorted(it, key=lambda e: e.name)
            except OSError as exc:
                raise HostStateError("HOST_STATE_IO", target_index=target_index, err_no=exc.errno) from None
            for child in children:
                child_sub = f"{sub_rel}/{child.name}" if sub_rel else child.name
                visit(Path(child.path), target_rel, child_sub, depth + 1, target_index)
            try:
                after_dir = os.lstat(path)
            except OSError as exc:
                raise HostStateError("HOST_STATE_IO", target_index=target_index, err_no=exc.errno) from None
            if (after_dir.st_dev, after_dir.st_ino, after_dir.st_mtime_ns) != (
                info.st_dev,
                info.st_ino,
                info.st_mtime_ns,
            ):
                raise HostStateError("HOST_STATE_CONCURRENT_MUTATION", target_index=target_index)
            return

        if stat.S_ISREG(info.st_mode):
            if info.st_size < 0 or info.st_size > MAX_FILE_BYTES or total_bytes + info.st_size > MAX_TOTAL_BYTES:
                raise HostStateError("HOST_STATE_BYTE_BOUND", target_index=target_index)
            flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
            try:
                fd = os.open(path, flags)
            except OSError as exc:
                raise HostStateError("HOST_STATE_IO", target_index=target_index, err_no=exc.errno) from None
            try:
                with os.fdopen(fd, "rb") as stream:
                    before = os.fstat(stream.fileno())
                    if not stat.S_ISREG(before.st_mode) or (
                        before.st_dev,
                        before.st_ino,
                        before.st_size,
                        before.st_mtime_ns,
                    ) != (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns):
                        raise HostStateError("HOST_STATE_CONCURRENT_MUTATION", target_index=target_index)
                    digest = hashlib.sha256()
                    size = 0
                    while True:
                        chunk = stream.read(min(1024 * 1024, info.st_size - size + 1))
                        if not chunk:
                            break
                        size += len(chunk)
                        if size > info.st_size or size > MAX_FILE_BYTES or total_bytes + size > MAX_TOTAL_BYTES:
                            raise HostStateError("HOST_STATE_BYTE_BOUND", target_index=target_index)
                        digest.update(chunk)
                    after = os.fstat(stream.fileno())
                    if (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns) != (
                        before.st_dev,
                        before.st_ino,
                        before.st_size,
                        before.st_mtime_ns,
                    ):
                        raise HostStateError("HOST_STATE_CONCURRENT_MUTATION", target_index=target_index)
            except HostStateError:
                raise
            except OSError as exc:
                raise HostStateError("HOST_STATE_IO", target_index=target_index, err_no=exc.errno) from None

            try:
                post = os.lstat(path)
            except OSError as exc:
                raise HostStateError("HOST_STATE_IO", target_index=target_index, err_no=exc.errno) from None
            if post.st_ino != info.st_ino or post.st_dev != info.st_dev or size != info.st_size:
                raise HostStateError("HOST_STATE_CONCURRENT_MUTATION", target_index=target_index)

            entry.update(kind="file", size=size, sha256=digest.hexdigest())
            total_bytes += size
            entries[key] = entry
            return

        raise HostStateError("HOST_STATE_SPECIAL_MEMBER", target_index=target_index)

    for idx, relative in enumerate(relatives):
        target = root / relative
        _check_ancestors_no_symlink(root, target, idx)
        try:
            os.lstat(target)
        except FileNotFoundError:
            if len(entries) >= MAX_ENTRIES:
                raise HostStateError("HOST_STATE_ENTRY_BOUND", target_index=idx) from None
            entries[relative] = {"kind": "absent"}
            continue
        except OSError as exc:
            raise HostStateError("HOST_STATE_IO", target_index=idx, err_no=exc.errno) from None
        existing_targets += 1
        visit(target, relative, "", 0, idx)

    raw = json.dumps(entries, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return {
        "scope": SCOPE_DESCRIPTION,
        "target_count": len(relatives),
        "existing_targets": existing_targets,
        "inventory_entries": len(entries),
        "file_bytes_hashed": total_bytes,
        "sha256": hashlib.sha256(raw).hexdigest(),
        "entries": entries,
    }


def public_summary(snap: Mapping[str, Any]) -> dict[str, Any]:
    """Return privacy-safe aggregate summary without retaining raw target entries or paths."""
    return {
        "scope": snap["scope"],
        "target_count": snap["target_count"],
        "existing_targets": snap["existing_targets"],
        "inventory_entries": snap["inventory_entries"],
        "file_bytes_hashed": snap["file_bytes_hashed"],
        "sha256": snap["sha256"],
    }


def compare_snapshots(before: Mapping[str, Any], after: Mapping[str, Any]) -> dict[str, Any]:
    """Compare before/after snapshots and report privacy-safe target indices if any drifted."""
    relatives = target_relatives()
    before_entries = before.get("entries", {})
    after_entries = after.get("entries", {})
    changed_indices: list[int] = []
    for idx, rel in enumerate(relatives):
        prefix = rel + "/"
        b_sub = {k: v for k, v in before_entries.items() if k == rel or k.startswith(prefix)}
        a_sub = {k: v for k, v in after_entries.items() if k == rel or k.startswith(prefix)}
        if b_sub != a_sub:
            changed_indices.append(idx)
    unchanged = (
        before.get("sha256") == after.get("sha256")
        and before_entries == after_entries
        and not changed_indices
    )
    if not unchanged:
        raise HostStateError(
            "HOST_STATE_DRIFT",
            target_index=changed_indices[0] if changed_indices else None,
        )
    return {
        **public_summary(before),
        "after_sha256": after["sha256"],
        "unchanged": True,
        "changed_target_indices": [],
    }
