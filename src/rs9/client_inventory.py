"""Lossless stdlib client inventory scanner, framed parser, and comparator integration.

Provides:
- scanner_argv(root="/"): CLI argument list to invoke standalone scanner subprocess.
- parse_inventory(stdout, exclusion=None, *, with_modes=False): Parse framed JSON output
  into a lossless surrogateescape-keyed mapping compatible with compare_inventories.
- run_and_parse(runner=None, root="/", exclusion=None, *, with_modes=False): Convenient
  subprocess invocation and parsing pipeline.
- compare_inventories: Re-exported from rs9.hosted_native (or compatible implementation)
  with support for symmetric mode comparisons.

Symmetric Mode Comparison:
By default, parse_inventory produces mappings of {path: sha256 | 'dir' | 'symlink:<target>' | ...}.
When with_modes=True is passed to parse_inventory, each value is suffixed with its octal permissions mode
(e.g. '{sha256}:0644' or 'dir:0755'). When before and after snapshots are both captured with with_modes=True,
standard compare_inventories(before, after) automatically and symmetrically identifies any permission changes
as modifications (in modified keys) alongside file content modifications, preserving full backward compatibility.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import stat
import subprocess
import sys
from pathlib import Path
from typing import Any, Callable, Mapping, Sequence

from rs9.errors import ContractError

FRAME_BEGIN = b"=== RS9 CLIENT INVENTORY FRAME BEGIN V2 ==="
FRAME_END = b"=== RS9 CLIENT INVENTORY FRAME END V2 ==="
FRAME_SCHEMA = "rs9.client-inventory.v2"
FRAME_VERSION = 2

MAX_ENTRIES = 200_000
MAX_SINGLE_FILE_BYTES = 512 * 1024 * 1024         # 512 MiB
MAX_TOTAL_HASHED_BYTES = 4 * 1024 * 1024 * 1024    # 4 GiB
MAX_STDOUT_BYTES = 32 * 1024 * 1024                # 32 MiB
MAX_PATH_BYTES = 4096
MAX_SYMLINK_TARGET_BYTES = 4096
MAX_DEPTH = 128

PRUNES = (b"proc", b"sys", b"dev", b"run", b"tmp", b"srv/rs9")

# --------------------------------------------------------------------------- Standalone Scanner

SCANNER_SCRIPT = f"""# RS9 Standalone Client Inventory Scanner
import sys
import os
import stat
import hashlib
import base64
import json
import re

FRAME_BEGIN = {repr(FRAME_BEGIN)}
FRAME_END = {repr(FRAME_END)}
FRAME_SCHEMA = {repr(FRAME_SCHEMA)}
FRAME_VERSION = {FRAME_VERSION}

MAX_ENTRIES = {MAX_ENTRIES}
MAX_SINGLE_FILE_BYTES = {MAX_SINGLE_FILE_BYTES}
MAX_TOTAL_HASHED_BYTES = {MAX_TOTAL_HASHED_BYTES}
MAX_STDOUT_BYTES = {MAX_STDOUT_BYTES}
MAX_PATH_BYTES = {MAX_PATH_BYTES}
MAX_SYMLINK_TARGET_BYTES = {MAX_SYMLINK_TARGET_BYTES}
MAX_DEPTH = {MAX_DEPTH}

PRUNES = {repr(PRUNES)}

def main():
    root = sys.argv[1] if len(sys.argv) > 1 else "/"
    # The exact maintained regex predicates arrive as bounded JSON argv. No
    # subtree pruning: dot does not match embedded newline filename bytes.
    raw_patterns = json.loads(sys.argv[2]) if len(sys.argv) > 2 else []
    if (not isinstance(raw_patterns, list) or len(raw_patterns) > 32
            or any(not isinstance(p, str) or not p.isascii() or len(p) > 256 for p in raw_patterns)):
        sys.exit(1)
    compiled_excludes = [re.compile(p) for p in raw_patterns]
    entries = []
    hardlink_cache = {{}}
    total_hashed_bytes = 0
    output_estimate = 512
    file_count = dir_count = symlink_count = special_count = hardlink_count = 0
    scanned_entries = excluded_files = 0
    max_depth_observed = max_file_bytes_observed = max_path_bytes_observed = max_symlink_bytes_observed = 0
    max_directory_entries = 0

    def diagnostics():
        return {{"counters": {{"dir_count": dir_count, "entries": len(entries),
            "file_count": file_count, "hardlink_count": hardlink_count,
            "special_count": special_count, "symlink_count": symlink_count,
            "total_hashed_bytes": total_hashed_bytes, "scanned_entries": scanned_entries,
            "excluded_files": excluded_files}},
            "max": {{"depth": max_depth_observed, "file_bytes": max_file_bytes_observed,
                "path_bytes": max_path_bytes_observed, "symlink_bytes": max_symlink_bytes_observed,
                "directory_entries": max_directory_entries}}}}

    def fail(cause, observed=0, maximum=0):
        record = {{"schema": "rs9.inventory-failure.v1", "cause": cause,
            "observed": observed, "maximum": maximum, "diagnostics": diagnostics()}}
        sys.stderr.write(json.dumps(record, sort_keys=True, separators=(",", ":")) + "\\n")
        raise SystemExit(1)

    try:
        root_fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    except Exception as e:
        fail("scanner-error-opening-root")

    try:
        root_st = os.fstat(root_fd)
        root_dev = root_st.st_dev
    except Exception as e:
        os.close(root_fd)
        fail("scanner-error-stating-root")

    def signature(st):
        return (st.st_dev, st.st_ino, st.st_mode, st.st_size, st.st_mtime_ns, st.st_ctime_ns)

    def scan_dir(dir_fd, rel_path_bytes, depth):
        nonlocal total_hashed_bytes, output_estimate
        nonlocal file_count, dir_count, symlink_count, special_count, hardlink_count, scanned_entries, excluded_files, max_directory_entries
        nonlocal max_depth_observed, max_file_bytes_observed, max_path_bytes_observed, max_symlink_bytes_observed

        dir_before = os.fstat(dir_fd)
        if depth > MAX_DEPTH:
            fail("depth", depth, MAX_DEPTH)
        if depth > max_depth_observed:
            max_depth_observed = depth

        try:
            raw_names = []
            with os.scandir(dir_fd) as iterator:
                for child in iterator:
                    raw_names.append(child.name)
                    max_directory_entries = max(max_directory_entries, len(raw_names))
                    if len(raw_names) > MAX_ENTRIES:
                        fail("directory-entries", len(raw_names), MAX_ENTRIES)
        except Exception as e:
            fail("scanner-error-listing-dir")

        raw_names.sort(key=lambda s: os.fsencode(s))

        for name in raw_names:
            scanned_entries += 1
            if scanned_entries > MAX_ENTRIES:
                fail("entries", scanned_entries, MAX_ENTRIES)
            name_bytes = os.fsencode(name)
            child_rel_bytes = (rel_path_bytes + b"/" + name_bytes) if rel_path_bytes else name_bytes
            if len(child_rel_bytes) > MAX_PATH_BYTES:
                fail("path-bytes", len(child_rel_bytes), MAX_PATH_BYTES)
            if len(child_rel_bytes) > max_path_bytes_observed:
                max_path_bytes_observed = len(child_rel_bytes)

            if any(child_rel_bytes == p or child_rel_bytes.startswith(p + b"/") for p in PRUNES):
                continue

            try:
                st_before = os.stat(name, dir_fd=dir_fd, follow_symlinks=False)
            except Exception as e:
                fail("scanner-error-stating-entry")

            mode = stat.S_IMODE(st_before.st_mode)
            b64_path = base64.b64encode(child_rel_bytes).decode("ascii")

            if stat.S_ISLNK(st_before.st_mode):
                try:
                    target = os.readlink(name, dir_fd=dir_fd)
                    target_bytes = os.fsencode(target) if isinstance(target, str) else target
                except Exception as e:
                    fail("scanner-error-readlink")
                if len(target_bytes) > MAX_SYMLINK_TARGET_BYTES:
                    fail("symlink-bytes", len(target_bytes), MAX_SYMLINK_TARGET_BYTES)
                if len(target_bytes) > max_symlink_bytes_observed:
                    max_symlink_bytes_observed = len(target_bytes)
                if signature(os.stat(name, dir_fd=dir_fd, follow_symlinks=False)) != signature(st_before):
                    fail("scanner-symlink-changed")
                entry = {{
                    "kind": "symlink",
                    "mode": mode,
                    "path": b64_path,
                    "target": base64.b64encode(target_bytes).decode("ascii"),
                }}
                entries.append((child_rel_bytes, entry))
                symlink_count += 1

            elif stat.S_ISDIR(st_before.st_mode):
                dir_count += 1
                if st_before.st_dev != root_dev:
                    entry = {{
                        "kind": "mount",
                        "mode": mode,
                        "path": b64_path,
                    }}
                    entries.append((child_rel_bytes, entry))
                else:
                    entry = {{
                        "kind": "dir",
                        "mode": mode,
                        "path": b64_path,
                    }}
                    entries.append((child_rel_bytes, entry))
                    dir_flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
                    try:
                        child_fd = os.open(name, dir_flags, dir_fd=dir_fd)
                    except Exception as e:
                        fail("scanner-error-opening-directory")
                    try:
                        if signature(os.fstat(child_fd)) != signature(st_before):
                            fail("scanner-directory-changed")
                        scan_dir(child_fd, child_rel_bytes, depth + 1)
                        if signature(os.stat(name, dir_fd=dir_fd, follow_symlinks=False)) != signature(st_before):
                            fail("scanner-directory-changed")
                    finally:
                        os.close(child_fd)

            elif stat.S_ISFIFO(st_before.st_mode):
                entry = {{"kind": "fifo", "mode": mode, "path": b64_path}}
                entries.append((child_rel_bytes, entry))
                special_count += 1

            elif stat.S_ISSOCK(st_before.st_mode):
                entry = {{"kind": "socket", "mode": mode, "path": b64_path}}
                entries.append((child_rel_bytes, entry))
                special_count += 1

            elif stat.S_ISCHR(st_before.st_mode):
                entry = {{"kind": "char", "mode": mode, "path": b64_path, "rdev": st_before.st_rdev}}
                entries.append((child_rel_bytes, entry))
                special_count += 1

            elif stat.S_ISBLK(st_before.st_mode):
                entry = {{"kind": "block", "mode": mode, "path": b64_path, "rdev": st_before.st_rdev}}
                entries.append((child_rel_bytes, entry))
                special_count += 1

            elif stat.S_ISREG(st_before.st_mode):
                rel_str = child_rel_bytes.decode("utf-8", errors="surrogateescape")
                if any(p.search(rel_str) is not None for p in compiled_excludes):
                    excluded_files += 1
                    continue

                if st_before.st_size > MAX_SINGLE_FILE_BYTES:
                    fail("file-bytes", st_before.st_size, MAX_SINGLE_FILE_BYTES)

                file_key = (st_before.st_dev, st_before.st_ino)
                if file_key in hardlink_cache:
                    cached_signature, file_sha256 = hardlink_cache[file_key]
                    if signature(st_before) != cached_signature:
                        fail("scanner-hardlink-changed")
                    file_size = st_before.st_size
                    if total_hashed_bytes + file_size > MAX_TOTAL_HASHED_BYTES:
                        fail("hashed-bytes", total_hashed_bytes + st_before.st_size, MAX_TOTAL_HASHED_BYTES)
                    total_hashed_bytes += file_size
                    hardlink_count += 1
                else:
                    if total_hashed_bytes + st_before.st_size > MAX_TOTAL_HASHED_BYTES:
                        fail("hashed-bytes", total_hashed_bytes + st_before.st_size, MAX_TOTAL_HASHED_BYTES)

                    file_flags = os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_CLOEXEC", 0)
                    try:
                        file_fd = os.open(name, file_flags, dir_fd=dir_fd)
                    except Exception as e:
                        fail("scanner-error-opening-file")

                    try:
                        st_after = os.fstat(file_fd)
                        if signature(st_before) != signature(st_after):
                            fail("scanner-stat-consistency-mismatch")
                        if not stat.S_ISREG(st_after.st_mode):
                            fail("scanner-stat-consistency-mismatch")
                        if st_after.st_size != st_before.st_size:
                            fail("scanner-stat-consistency-mismatch")

                        h = hashlib.sha256()
                        bytes_read = 0
                        while True:
                            chunk = os.read(file_fd, 65536)
                            if not chunk:
                                break
                            bytes_read += len(chunk)
                            if bytes_read > MAX_SINGLE_FILE_BYTES:
                                fail("file-bytes", bytes_read, MAX_SINGLE_FILE_BYTES)
                            if total_hashed_bytes + bytes_read > MAX_TOTAL_HASHED_BYTES:
                                fail("hashed-bytes", total_hashed_bytes + bytes_read, MAX_TOTAL_HASHED_BYTES)
                            h.update(chunk)

                        if bytes_read != st_after.st_size:
                            fail("scanner-file-size-read-mismatch-with-stat")
                        if (signature(os.fstat(file_fd)) != signature(st_after)
                                or signature(os.stat(name, dir_fd=dir_fd, follow_symlinks=False)) != signature(st_after)):
                            fail("scanner-file-changed-while-hashing")

                        file_sha256 = h.hexdigest()
                        file_size = bytes_read
                        total_hashed_bytes += bytes_read

                        if st_before.st_nlink > 1:
                            hardlink_cache[file_key] = (signature(st_after), file_sha256)
                    finally:
                        os.close(file_fd)

                if file_size > max_file_bytes_observed:
                    max_file_bytes_observed = file_size

                entry = {{
                    "kind": "file",
                    "mode": mode,
                    "path": b64_path,
                    "sha256": file_sha256,
                    "size": file_size,
                }}
                entries.append((child_rel_bytes, entry))
                file_count += 1

            else:
                fail("scanner-encountered-unknown-file-mode")

            if len(entries) > MAX_ENTRIES:
                fail("entries", len(entries), MAX_ENTRIES)
            output_estimate += len(json.dumps(entry, separators=(",", ":"), sort_keys=True).encode()) + 1
            if output_estimate > MAX_STDOUT_BYTES:
                fail("output-bytes", output_estimate, MAX_STDOUT_BYTES)
        if signature(os.fstat(dir_fd)) != signature(dir_before):
            fail("scanner-directory-changed-during-traversal")

    try:
        scan_dir(root_fd, b"", 0)
    finally:
        os.close(root_fd)

    entries.sort(key=lambda item: item[0])
    sorted_entries = [item[1] for item in entries]

    payload = {{
        "diagnostics": diagnostics(),
        "entries": sorted_entries,
        "entry_count": len(sorted_entries),
        "schema": FRAME_SCHEMA,
        "total_hashed_bytes": total_hashed_bytes,
        "version": FRAME_VERSION,
    }}

    try:
        json_bytes = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
    except Exception as e:
        fail("scanner-json-serialization-error")

    header = FRAME_BEGIN + b" " + str(len(json_bytes)).encode() + b" " + hashlib.sha256(json_bytes).hexdigest().encode()
    total_stdout_len = len(header) + 1 + len(json_bytes) + 1 + len(FRAME_END) + 1
    if total_stdout_len > MAX_STDOUT_BYTES:
        fail("output-bytes", total_stdout_len, MAX_STDOUT_BYTES)

    out = header + b"\\n" + json_bytes + b"\\n" + FRAME_END + b"\\n"
    sys.stdout.buffer.write(out)
    sys.stdout.buffer.flush()

if __name__ == "__main__":
    main()
""".strip()

# Verify standalone scanner script size bound (< 128 KiB)
if len(SCANNER_SCRIPT.encode("utf-8")) >= 128 * 1024:
    raise RuntimeError("SCANNER_SCRIPT source code size exceeds 128 KiB limit")


def scanner_argv(root: str | Path = "/", family: str | None = None) -> list[str]:
    """Return argv to invoke the standalone isolated client scanner via python3."""
    cmd = ["python3", "-I", "-S", "-B", "-c", SCANNER_SCRIPT, str(root)]
    if family:
        from rs9.hosted_native import EXCLUDED_INVENTORY_PATTERNS
        from rs9.hosted_deb import INVENTORY_EXCLUDES
        if family not in INVENTORY_EXCLUDES:
            raise ContractError("INVENTORY_SCHEMA", "Unknown scanner family")
        patterns = [*EXCLUDED_INVENTORY_PATTERNS, *(p.pattern for p in INVENTORY_EXCLUDES[family])]
        cmd.append(json.dumps(patterns, separators=(",", ":")))
    return cmd


# --------------------------------------------------------------------------- Exclusions

def make_family_exclusion(family: str) -> Callable[[str], bool]:
    """Reuse the maintained shared family policy; never widen exclusions here."""
    from rs9.hosted_deb import INVENTORY_EXCLUDES, inventory_excluded
    if family not in INVENTORY_EXCLUDES:
        raise ContractError("INVENTORY_SCHEMA", "Unknown package manager family")
    return lambda path: inventory_excluded(family, path)


def _resolve_exclusion(exclusion: str | Callable[[str], bool] | None) -> Callable[[str], bool]:
    if exclusion is None:
        return lambda _: False
    if callable(exclusion):
        return exclusion
    if isinstance(exclusion, str):
        return make_family_exclusion(exclusion)
    raise ContractError("INVENTORY_SCHEMA", "Exclusion must be a callable, family name string, or None")


# --------------------------------------------------------------------------- Validation Helpers

REQUIRED_TOP_KEYS = frozenset({"schema", "version", "entry_count", "total_hashed_bytes", "entries", "diagnostics"})
ALLOWED_TOP_KEYS = REQUIRED_TOP_KEYS
ALLOWED_KINDS = frozenset({"dir", "file", "symlink", "fifo", "socket", "char", "block", "mount"})
FILE_KEYS = frozenset({"kind", "mode", "path", "sha256", "size"})
SYMLINK_KEYS = frozenset({"kind", "mode", "path", "target"})
SPECIAL_KEYS = frozenset({"kind", "mode", "path"})
DEVICE_KEYS = SPECIAL_KEYS | {"rdev"}
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


def inventory_limit(limit, observed, maximum):
    return ContractError("INVENTORY_LIMIT", "Inventory capacity exceeded",
                         details={"cause": "capacity", "limit": limit,
                                  "observed": observed, "maximum": maximum})


def decode_canonical_b64(b64_str: Any, field_name: str = "path") -> bytes:
    """Decode base64 string, failing closed if non-canonical, invalid padding, or invalid chars."""
    if not isinstance(b64_str, str):
        raise ContractError("INVENTORY_SCHEMA", f"Field '{field_name}' must be a string")
    if not b64_str and field_name == "path":
        raise ContractError("INVENTORY_PATH_TRAVERSAL", "Path base64 string must not be empty")
    try:
        raw = base64.b64decode(b64_str, validate=True)
    except Exception:
        raise ContractError("INVENTORY_BASE64", f"Invalid base64 encoding in '{field_name}'")
    if base64.b64encode(raw).decode("ascii") != b64_str:
        raise ContractError("INVENTORY_BASE64", f"Noncanonical base64 encoding in '{field_name}'")
    return raw


def validate_relative_path_bytes(raw_path: bytes, max_path_bytes: int = MAX_PATH_BYTES) -> None:
    """Validate relative POSIX path bytes for traversal, empty segments, or NUL bytes."""
    if not raw_path:
        raise ContractError("INVENTORY_PATH_TRAVERSAL", "Path must not be empty")
    if raw_path.startswith(b"/"):
        raise ContractError("INVENTORY_PATH_TRAVERSAL", "Path must be a relative path")
    if b"\0" in raw_path:
        raise ContractError("INVENTORY_PATH_TRAVERSAL", "Path must not contain NUL bytes")
    if len(raw_path) > max_path_bytes:
        raise inventory_limit("path-bytes", len(raw_path), max_path_bytes)
    segments = raw_path.split(b"/")
    for seg in segments:
        if seg in (b"", b".", b".."):
            raise ContractError("INVENTORY_PATH_TRAVERSAL", "Invalid path segment or directory traversal")


def validate_symlink_target_bytes(target_bytes: bytes, max_symlink_bytes: int = MAX_SYMLINK_TARGET_BYTES) -> None:
    """Validate symlink target bytes."""
    if not target_bytes:
        raise ContractError("INVENTORY_PARSE", "Symlink target must not be empty")
    if b"\0" in target_bytes:
        raise ContractError("INVENTORY_PARSE", "Symlink target must not contain NUL bytes")
    if len(target_bytes) > max_symlink_bytes:
        raise inventory_limit("symlink-bytes", len(target_bytes), max_symlink_bytes)


def extract_frame_body(stdout: bytes, max_stdout_bytes: int = MAX_STDOUT_BYTES) -> bytes:
    """Extract and validate framing envelope, failing closed on bounds, chatter, or truncation."""
    if not isinstance(stdout, (bytes, bytearray)):
        raise ContractError("INVENTORY_PARSE", "Inventory stdout must be bytes")
    if len(stdout) > max_stdout_bytes:
        raise inventory_limit("output-bytes", len(stdout), max_stdout_bytes)

    header, sep, rest = stdout.partition(b"\n")
    match = re.fullmatch(re.escape(FRAME_BEGIN) + rb" ([1-9][0-9]{0,8}) ([0-9a-f]{64})", header)
    if not sep or match is None:
        raise ContractError("INVENTORY_PARSE", "Missing or malformed inventory frame header")
    length = int(match[1])
    body = rest[:length]
    if rest[length:] != b"\n" + FRAME_END + b"\n" or hashlib.sha256(body).hexdigest().encode() != match[2]:
        raise ContractError("INVENTORY_PARSE", "Truncated, changed or trailing inventory data")
    return body


def frame_payload(payload):
    """Canonical frame for explicit scanner fixtures and protocol readback."""
    body = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
    return (FRAME_BEGIN + b" " + str(len(body)).encode() + b" " + hashlib.sha256(body).hexdigest().encode()
            + b"\n" + body + b"\n" + FRAME_END + b"\n")


def _reject_duplicate_json_keys(pairs: Sequence[tuple[str, Any]]) -> dict[str, Any]:
    res = {}
    for k, v in pairs:
        if k in res:
            raise ContractError("INVENTORY_SCHEMA", f"Duplicate key in JSON object: {k}")
        res[k] = v
    return res


def parse_framed_json(body_bytes: bytes) -> dict[str, Any]:
    try:
        text = body_bytes.decode("utf-8")
    except UnicodeDecodeError:
        raise ContractError("INVENTORY_PARSE", "Inventory frame body is not valid UTF-8")
    try:
        data = json.loads(text, object_pairs_hook=_reject_duplicate_json_keys)
    except ContractError:
        raise
    except Exception as e:
        raise ContractError("INVENTORY_PARSE", "Malformed JSON in inventory frame") from None
    if not isinstance(data, dict):
        raise ContractError("INVENTORY_SCHEMA", "Inventory payload must be a JSON object")
    return data


# --------------------------------------------------------------------------- Parser Implementation

def parse_inventory(
    stdout: bytes,
    exclusion: str | Callable[[str], bool] | None = None,
    *,
    with_modes: bool = False,
    return_diagnostics: bool = False,
    max_stdout_bytes: int = MAX_STDOUT_BYTES,
    max_entries: int = MAX_ENTRIES,
    max_single_file_bytes: int = MAX_SINGLE_FILE_BYTES,
    max_total_hashed_bytes: int = MAX_TOTAL_HASHED_BYTES,
    max_path_bytes: int = MAX_PATH_BYTES,
    max_symlink_bytes: int = MAX_SYMLINK_TARGET_BYTES,
    max_depth: int = MAX_DEPTH,
) -> dict[str, str] | tuple[dict[str, str], dict[str, Any]]:
    """Parse framed JSON scanner output into a bytes-lossless surrogateescape-keyed mapping.

    Args:
        stdout: Raw output bytes from the scanner process.
        exclusion: Package manager family string ('apt', 'dnf', 'pacman'), external callable
            accepting exact decoded path string, or None. Evaluated without backslash folding.
        with_modes: When True, suffix values with ':mode' (e.g. 'sha256:0644' or 'dir:0755')
            for symmetric before/after comparison of permissions in compare_inventories.
        return_diagnostics: When True, return (inventory, diagnostics).
        max_stdout_bytes: Upper bound on accepted stdout length.
        max_entries: Upper bound on total entries in inventory.
        max_single_file_bytes: Upper bound on any single file size.
        max_total_hashed_bytes: Upper bound on total hashed file bytes.
        max_path_bytes: Upper bound on relative path bytes.
        max_symlink_bytes: Upper bound on symlink target bytes.
        max_depth: Upper bound on directory depth.

    Returns:
        Mapping of relative path (surrogateescape str) to inventory value:
            - Regular files: sha256 hex string (or sha256:mode)
            - Directories: 'dir' (or dir:mode)
            - Symlinks: 'symlink:<target>' (or symlink:<target>:mode)
            - Special entries: 'fifo', 'socket', 'char', 'block', 'mount' (or kind:mode)
    """
    body_bytes = extract_frame_body(stdout, max_stdout_bytes=max_stdout_bytes)
    data = parse_framed_json(body_bytes)
    if json.dumps(data, separators=(",", ":"), sort_keys=True).encode("utf-8") != body_bytes:
        raise ContractError("INVENTORY_PARSE", "Noncanonical inventory JSON")

    # Validate top-level schema and fields
    keys = set(data.keys())
    missing = REQUIRED_TOP_KEYS - keys
    if missing:
        raise ContractError("INVENTORY_SCHEMA", "Missing top-level field")
    unknown = keys - ALLOWED_TOP_KEYS
    if unknown:
        raise ContractError("INVENTORY_SCHEMA", "Unknown top-level field")

    if data["schema"] != FRAME_SCHEMA:
        raise ContractError("INVENTORY_SCHEMA", "Unsupported inventory schema")
    if type(data["version"]) is not int or data["version"] != FRAME_VERSION:
        raise ContractError("INVENTORY_SCHEMA", "Unsupported inventory version")

    entry_count = data["entry_count"]
    if not isinstance(entry_count, int) or isinstance(entry_count, bool) or entry_count < 0:
        raise ContractError("INVENTORY_SCHEMA", "entry_count must be non-negative integer")
    if entry_count > max_entries:
        raise inventory_limit("entries", entry_count, max_entries)

    total_hashed_bytes = data["total_hashed_bytes"]
    if not isinstance(total_hashed_bytes, int) or isinstance(total_hashed_bytes, bool) or total_hashed_bytes < 0:
        raise ContractError("INVENTORY_SCHEMA", "total_hashed_bytes must be non-negative integer")
    if total_hashed_bytes > max_total_hashed_bytes:
        raise inventory_limit("hashed-bytes", total_hashed_bytes, max_total_hashed_bytes)

    parsed_diagnostics: dict[str, Any] = {}
    if "diagnostics" in data:
        diag = data["diagnostics"]
        if not isinstance(diag, dict) or isinstance(diag, bool):
            raise ContractError("INVENTORY_SCHEMA", "diagnostics must be a JSON object")
        if set(diag.keys()) != {"counters", "max"}:
            raise ContractError("INVENTORY_SCHEMA", "diagnostics must contain exactly 'counters' and 'max'")

        counters = diag["counters"]
        if not isinstance(counters, dict) or isinstance(counters, bool):
            raise ContractError("INVENTORY_SCHEMA", "counters must be a JSON object")
        expected_counter_keys = {"dir_count", "entries", "file_count", "hardlink_count", "special_count", "symlink_count", "total_hashed_bytes", "scanned_entries", "excluded_files"}
        if set(counters.keys()) != expected_counter_keys:
            raise ContractError("INVENTORY_SCHEMA", "Invalid keys in diagnostics counters")
        for ck, cv in counters.items():
            if type(cv) is not int or isinstance(cv, bool) or cv < 0:
                raise ContractError("INVENTORY_SCHEMA", f"Counter '{ck}' must be a non-negative integer")
        if (not 0 <= counters["scanned_entries"] <= max_entries
                or counters["excluded_files"] > counters["scanned_entries"]
                or counters["hardlink_count"] > counters["file_count"]):
            raise ContractError("INVENTORY_SCHEMA", "Invalid scanner work counters")
        if counters["entries"] != entry_count:
            raise ContractError("INVENTORY_PARSE", "diagnostics counter entries mismatch with entry_count")
        if counters["total_hashed_bytes"] != total_hashed_bytes:
            raise ContractError("INVENTORY_PARSE", "diagnostics counter total_hashed_bytes mismatch")

        max_diag = diag["max"]
        if not isinstance(max_diag, dict) or isinstance(max_diag, bool):
            raise ContractError("INVENTORY_SCHEMA", "max diagnostics must be a JSON object")
        expected_max_keys = {"depth", "file_bytes", "path_bytes", "symlink_bytes", "directory_entries"}
        if set(max_diag.keys()) != expected_max_keys:
            raise ContractError("INVENTORY_SCHEMA", "Invalid keys in max diagnostics")
        for mk, mv in max_diag.items():
            if type(mv) is not int or isinstance(mv, bool) or mv < 0:
                raise ContractError("INVENTORY_SCHEMA", f"Max diagnostic '{mk}' must be a non-negative integer")
        if max_diag["directory_entries"] > max_entries:
            raise inventory_limit("directory-entries", max_diag["directory_entries"], max_entries)
        if max_diag["depth"] > max_depth:
            raise inventory_limit("depth", max_diag["depth"], max_depth)
        if max_diag["file_bytes"] > max_single_file_bytes:
            raise inventory_limit("file-bytes", max_diag["file_bytes"], max_single_file_bytes)
        if max_diag["path_bytes"] > max_path_bytes:
            raise inventory_limit("path-bytes", max_diag["path_bytes"], max_path_bytes)
        if max_diag["symlink_bytes"] > max_symlink_bytes:
            raise inventory_limit("symlink-bytes", max_diag["symlink_bytes"], max_symlink_bytes)
        parsed_diagnostics = diag

    entries = data["entries"]
    if not isinstance(entries, list):
        raise ContractError("INVENTORY_SCHEMA", "entries must be a list")
    if len(entries) != entry_count:
        raise ContractError("INVENTORY_PARSE", f"Entry count mismatch: declared {entry_count}, actual {len(entries)}")

    exclusion_cb = _resolve_exclusion(exclusion)

    inventory: dict[str, str] = {}
    prev_path_bytes: bytes | None = None
    accumulated_hashed_bytes = 0
    observed_file_count = 0
    observed_dir_count = 0
    observed_symlink_count = 0
    observed_special_count = 0
    observed_path_bytes = observed_file_bytes = observed_symlink_bytes = 0

    for entry in entries:
        if not isinstance(entry, dict):
            raise ContractError("INVENTORY_SCHEMA", "Entry must be a JSON object")

        kind = entry.get("kind")
        if not isinstance(kind, str) or kind not in ALLOWED_KINDS:
            raise ContractError("INVENTORY_SCHEMA", "Invalid or unknown entry kind")

        mode = entry.get("mode")
        if not isinstance(mode, int) or isinstance(mode, bool) or mode < 0 or mode > 0o7777:
            raise ContractError("INVENTORY_SCHEMA", "Invalid entry mode")

        # Check required fields per kind
        if kind == "file":
            expected_keys = FILE_KEYS
            observed_file_count += 1
        elif kind == "symlink":
            expected_keys = SYMLINK_KEYS
            observed_symlink_count += 1
        elif kind in {"dir", "mount"}:
            expected_keys = SPECIAL_KEYS
            observed_dir_count += 1
        elif kind in {"char", "block"}:
            expected_keys = DEVICE_KEYS
            observed_special_count += 1
        elif kind in {"fifo", "socket"}:
            expected_keys = SPECIAL_KEYS
            observed_special_count += 1
        else:
            expected_keys = SPECIAL_KEYS

        if set(entry.keys()) != expected_keys:
            unknown = set(entry.keys()) - expected_keys
            if unknown:
                raise ContractError("INVENTORY_SCHEMA", "Unknown field in entry")
            missing = expected_keys - set(entry.keys())
            raise ContractError("INVENTORY_SCHEMA", "Missing field in entry")

        path_bytes = decode_canonical_b64(entry["path"], "path")
        validate_relative_path_bytes(path_bytes, max_path_bytes=max_path_bytes)
        observed_path_bytes = max(observed_path_bytes, len(path_bytes))

        # Enforce deterministic bytes ordering & duplicate checks on raw bytes
        if prev_path_bytes is not None:
            if path_bytes == prev_path_bytes:
                raise ContractError("INVENTORY_DUPLICATE", "Duplicate path in inventory entries")
            if path_bytes < prev_path_bytes:
                raise ContractError("INVENTORY_ORDERING", "Inventory entries out of order")
        prev_path_bytes = path_bytes

        if kind == "file":
            sha256 = entry["sha256"]
            if not isinstance(sha256, str) or not SHA256_RE.fullmatch(sha256):
                raise ContractError("INVENTORY_SCHEMA", "Invalid sha256 in file entry")
            size = entry["size"]
            if not isinstance(size, int) or isinstance(size, bool) or size < 0:
                raise ContractError("INVENTORY_SCHEMA", "File size must be non-negative integer")
            if size > max_single_file_bytes:
                raise inventory_limit("file-bytes", size, max_single_file_bytes)
            observed_file_bytes = max(observed_file_bytes, size)
            accumulated_hashed_bytes += size
            if accumulated_hashed_bytes > max_total_hashed_bytes:
                raise inventory_limit("hashed-bytes", accumulated_hashed_bytes, max_total_hashed_bytes)
            val = sha256

        elif kind == "dir":
            val = "dir"

        elif kind == "symlink":
            target_bytes = decode_canonical_b64(entry["target"], "target")
            validate_symlink_target_bytes(target_bytes, max_symlink_bytes=max_symlink_bytes)
            observed_symlink_bytes = max(observed_symlink_bytes, len(target_bytes))
            target_str = target_bytes.decode("utf-8", errors="surrogateescape")
            val = f"symlink:{target_str}"
        elif kind in {"char", "block"}:
            rdev = entry["rdev"]
            if type(rdev) is not int or not 0 <= rdev < 2 ** 64:
                raise ContractError("INVENTORY_SCHEMA", "Invalid device identity")
            val = f"{kind}:{rdev}"
        else:
            val = kind

        decoded_path = path_bytes.decode("utf-8", errors="surrogateescape")
        if decoded_path in inventory:
            raise ContractError("INVENTORY_COLLISION", f"Path collision in inventory mapping: {decoded_path}")

        # Evaluate exclusion on EXACT decoded path without backslash folding
        if exclusion_cb(decoded_path):
            continue

        inventory[decoded_path] = f"{val}:{mode:04o}" if with_modes else val

    if accumulated_hashed_bytes != total_hashed_bytes:
        raise ContractError(
            "INVENTORY_PARSE",
            f"Total hashed bytes mismatch: declared {total_hashed_bytes}, computed {accumulated_hashed_bytes}",
        )

    if "diagnostics" in data:
        if counters["file_count"] != observed_file_count:
            raise ContractError("INVENTORY_PARSE", "file_count mismatch in diagnostics")
        if counters["dir_count"] != observed_dir_count:
            raise ContractError("INVENTORY_PARSE", "dir_count mismatch in diagnostics")
        if counters["symlink_count"] != observed_symlink_count:
            raise ContractError("INVENTORY_PARSE", "symlink_count mismatch in diagnostics")
        if counters["special_count"] != observed_special_count:
            raise ContractError("INVENTORY_PARSE", "special_count mismatch in diagnostics")
        if counters["entries"] != (observed_file_count + observed_dir_count + observed_symlink_count + observed_special_count):
            raise ContractError("INVENTORY_PARSE", "entries sum mismatch in diagnostics")

    if (counters["scanned_entries"] < entry_count + counters["excluded_files"]
            or max_diag["path_bytes"] < observed_path_bytes
            or max_diag["file_bytes"] < observed_file_bytes
            or max_diag["symlink_bytes"] < observed_symlink_bytes):
        raise ContractError("INVENTORY_PARSE", "Scanner diagnostics underreport retained records")
    if return_diagnostics:
        return inventory, parsed_diagnostics
    return inventory


# --------------------------------------------------------------------------- Subprocess Pipeline

def run_and_parse(
    runner: Any = None,
    root: str | Path = "/",
    exclusion: str | Callable[[str], bool] | None = None,
    *,
    with_modes: bool = False,
    timeout: float | None = None,
    stage: str | None = None,
    family: str | None = None,
    return_diagnostics: bool = False,
) -> dict[str, str] | tuple[dict[str, str], dict[str, Any]]:
    """Execute scanner subprocess and parse its inventory output.

    If runner is None, invokes python3 subprocess directly.
    If runner is provided (e.g. host runner, container client), invokes runner.exec or runner.run.
    Fails closed if the scanner exits with a non-zero exit code.
    """
    if family is None and isinstance(exclusion, str):
        family = exclusion
    context = {"family": family or "unspecified", "stage": stage or "unspecified",
               "counters": {}, "max": {}}
    argv = scanner_argv(root=root, family=family)
    try:
        if runner is None:
            receipt = subprocess.run(argv, capture_output=True, timeout=timeout or 120)
        elif hasattr(runner, "exec"):
            receipt = runner.exec(argv)
        elif hasattr(runner, "run"):
            receipt = runner.run(argv)
        elif callable(runner):
            receipt = runner(argv)
        else:
            raise ContractError("INVENTORY_SCHEMA", "Unsupported scanner runner")
    except (OSError, subprocess.TimeoutExpired):
        raise ContractError("INVENTORY_FAILED", "Scanner unavailable or timed out",
                            details={**context, "cause": "unavailable-or-timeout"}) from None
    exit_code = getattr(receipt, "exit_code", getattr(receipt, "returncode", None))
    stdout = getattr(receipt, "stdout_bytes", getattr(receipt, "stdout", None))
    stderr = getattr(receipt, "stderr_bytes", getattr(receipt, "stderr", None))
    if not isinstance(stdout, bytes):
        raise ContractError("INVENTORY_FAILED", "Scanner receipt lacks stdout bytes",
                            details={**context, "cause": "malformed-receipt"})
    if not isinstance(stderr, bytes):
        raise ContractError("INVENTORY_FAILED", "Scanner receipt lacks stderr bytes",
                            details={**context, "cause": "malformed-receipt"})
    if type(exit_code) is not int or exit_code != 0 or stderr:
        details = {**context, "cause": "scanner-error",
            "substage": "client-inventory-scan", "tool": "python3",
            "exit_code": exit_code if type(exit_code) is int else -1,
            "stdout_sha256": hashlib.sha256(stdout).hexdigest(),
            "stderr_sha256": hashlib.sha256(stderr).hexdigest(),
        }
        # Only this closed, bounded grammar can contribute failure diagnostics.
        try:
            failure = json.loads(stderr) if len(stderr) <= 4096 else None
            if (type(failure) is dict and set(failure) == {"schema", "cause", "observed", "maximum", "diagnostics"}
                    and failure["schema"] == "rs9.inventory-failure.v1"
                    and isinstance(failure["cause"], str)
                    and re.fullmatch(r"[a-z][a-z0-9-]{0,63}", failure["cause"])
                    and all(type(failure[k]) is int and 0 <= failure[k] < 2**64 for k in ("observed", "maximum"))):
                diag = failure["diagnostics"]
                if (type(diag) is dict and set(diag) == {"counters", "max"}
                        and set(diag["counters"]) == {"dir_count", "entries", "file_count", "hardlink_count", "special_count", "symlink_count", "total_hashed_bytes", "scanned_entries", "excluded_files"}
                        and set(diag["max"]) == {"depth", "file_bytes", "path_bytes", "symlink_bytes", "directory_entries"}
                        and all(type(v) is int and 0 <= v < 2**64 for values in diag.values() for v in values.values())):
                    details.update(cause=failure["cause"], observed=failure["observed"], maximum=failure["maximum"],
                                   counters=diag["counters"], max=diag["max"])
        except (ValueError, TypeError, KeyError, AttributeError):
            pass
        if family:
            details["family"] = family
        if stage:
            details["stage"] = stage
        raise ContractError("INVENTORY_FAILED", "Client inventory scanner failed", details=details)
    try:
        return parse_inventory(
            stdout,
            exclusion=exclusion,
            with_modes=with_modes,
            return_diagnostics=return_diagnostics,
        )
    except ContractError as err:
        if stage or family:
            details = {**context, "cause": "parser-error", **(err.details or {})}
            if stage and "stage" not in details:
                details["stage"] = stage
            if family and "family" not in details:
                details["family"] = family
            raise err.with_details(**details) from None
        raise


# --------------------------------------------------------------------------- Compare Integration

from rs9.hosted_native import compare_inventories
