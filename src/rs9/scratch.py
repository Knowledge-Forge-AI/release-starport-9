"""Descriptor-relative, exclusive writes into a caller-owned empty directory."""
import json
import math
import os
from pathlib import Path
import re
import stat

from rs9.errors import ContractError
from rs9.security import validate_safe_relative_posix_path


def validate_safe_json(value, *, lane=None, product=None, field=None, path="root", max_depth=32, max_nodes=100000):
    """Reject non-JSON values with bounded logical identity, never arbitrary values."""
    import hashlib
    from rs9.security import scan_for_credentials
    count, active = 0, set()

    def component(key):
        if isinstance(key, str) and re.fullmatch(r"[A-Za-z_][A-Za-z0-9_-]{0,63}", key):
            try:
                scan_for_credentials(key)
                return key
            except ContractError:
                pass
        # Hash only strings; do not invoke arbitrary user methods for other keys.
        return "key-sha256-" + hashlib.sha256(key.encode()).hexdigest()[:16] if isinstance(key, str) else "non-string-key"

    def fail(val, location, reason):
        name = type(val).__name__
        safe_type = name if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,63}", name) else "unknown_type"
        details = {"origin": location, "exception_type": safe_type, "reason": reason}
        if product:
            details["product"] = product
        if lane:
            details["substage"] = lane
        raise ContractError("INVALID_JSON", f"Non-JSON value of type {safe_type} at {location}", details=details)

    def walk(val, location, depth):
        nonlocal count
        count += 1
        if len(location) > 240:
            location = "logical-path-sha256-" + hashlib.sha256(location.encode()).hexdigest()
        if count > max_nodes:
            fail(val, location, "max-nodes-exceeded")
        if depth > min(max_depth, 64):
            fail(val, location, "max-depth-exceeded")
        if type(val) in (str, bool, int) or val is None:
            return
        if type(val) is float:
            if not math.isfinite(val):
                fail(val, location, "non-finite-float")
            return
        if type(val) not in (dict, list):
            fail(val, location, "non-json-value")
        if id(val) in active:
            fail(val, location, "circular-reference")
        active.add(id(val))
        try:
            if type(val) is dict:
                for key, item in val.items():
                    if type(key) is not str:
                        fail(key, location, "non-string-dict-key")
                    walk(item, location + "." + component(key), depth + 1)
            else:
                for index, item in enumerate(val):
                    walk(item, location + "." + str(index), depth + 1)
        finally:
            active.remove(id(val))
    walk(value, component(field or path), 0)
    return value


def canonical(value, *, validate=False, lane=None, product=None):
    if validate:
        validate_safe_json(value, lane=lane, product=product)
    return (json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False) + "\n").encode("utf-8")


def physical_directory(root):
    path = Path(root).absolute()
    if any(parent.is_symlink() for parent in (path, *path.parents)):
        raise ContractError("SYMLINK_REJECTED", "Directory ancestry contains a symlink")
    if not path.is_dir():
        raise ContractError("INVALID_DIRECTORY", "An existing physical directory is required")
    return path


class ConfinedWriter:
    """Never overwrite existing output or follow a directory/link component."""

    def __init__(self, root, *, file_mode: int | None = None, dir_mode: int | None = None):
        path = physical_directory(root)
        self.file_mode = file_mode
        self.dir_mode = dir_mode
        self.fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        if os.listdir(self.fd):
            self.close()
            raise ContractError("OUTPUT_NOT_EMPTY", "Output root must be empty")

    def close(self):
        if self.fd is not None:
            os.close(self.fd)
            self.fd = None

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()

    def write(self, relative, content):
        validate_safe_relative_posix_path(relative)
        if not isinstance(content, bytes):
            raise ContractError("INVALID_TYPE", "Output content must be bytes")
        current = os.dup(self.fd)
        try:
            parts = relative.split("/")
            for part in parts[:-1]:
                try:
                    os.mkdir(part, self.dir_mode if self.dir_mode is not None else 0o755, dir_fd=current)
                except FileExistsError:
                    pass
                child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=current)
                try:
                    if self.dir_mode is not None:
                        os.fchmod(child, self.dir_mode)
                except OSError:
                    os.close(child)
                    raise
                os.close(current)
                current = child
            descriptor = os.open(parts[-1], os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                                 self.file_mode if self.file_mode is not None else 0o644, dir_fd=current)
            try:
                if self.file_mode is not None:
                    os.fchmod(descriptor, self.file_mode)
                stream = os.fdopen(descriptor, "wb")
                descriptor = None
                with stream:
                    stream.write(content)
            finally:
                if descriptor is not None:
                    os.close(descriptor)
        except OSError:
            raise ContractError("OUTPUT_CONFINEMENT", "Confined output write failed") from None
        finally:
            os.close(current)


def verify_public_tree_modes(root, *, expected_file_mode=0o644, expected_dir_mode=0o755,
                             raise_on_error=False):
    """Descriptor-relative public mode readback; bounded samples and no host paths."""
    kinds = ("file_mode", "directory_mode", "symlink", "special")
    counts = {k: 0 for k in kinds}
    counts.update(total_files=0, total_directories=0)
    samples = {k: [] for k in kinds}
    def mismatch(kind, path, **fields):
        counts[kind] += 1
        if len(samples[kind]) < 10:
            samples[kind].append({"path": path[:256], **fields})
    def visit(fd, relative, depth=0):
        counts["total_directories"] += 1
        mode = stat.S_IMODE(os.fstat(fd).st_mode)
        if mode != expected_dir_mode:
            mismatch("directory_mode", relative or ".", expected_mode=expected_dir_mode, actual_mode=mode)
        if depth >= 128:
            mismatch("special", relative, type="depth-limit")
            return
        with os.scandir(fd) as entries:
            for entry in entries:
                name = f"{relative}/{entry.name}" if relative else entry.name
                st = entry.stat(follow_symlinks=False)
                if stat.S_ISLNK(st.st_mode):
                    mismatch("symlink", name, type="symlink")
                elif stat.S_ISDIR(st.st_mode):
                    child = os.open(entry.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
                    try:
                        visit(child, name, depth + 1)
                    finally:
                        os.close(child)
                elif stat.S_ISREG(st.st_mode):
                    counts["total_files"] += 1
                    mode = stat.S_IMODE(st.st_mode)
                    if mode != expected_file_mode:
                        mismatch("file_mode", name, expected_mode=expected_file_mode, actual_mode=mode)
                else:
                    mismatch("special", name, type="fifo" if stat.S_ISFIFO(st.st_mode) else "special")
    try:
        path = physical_directory(root)
        fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            visit(fd, "")
        finally:
            os.close(fd)
    except ContractError as error:
        mismatch("symlink" if error.code == "SYMLINK_REJECTED" else "special", ".", type=error.code)
    except OSError:
        mismatch("special", ".", type="io-error")
    passed = not any(counts[k] for k in kinds)
    if raise_on_error and not passed:
        code = "SYMLINK_REJECTED" if counts["symlink"] else "INVALID_FILE" if counts["special"] else "MODE_MISMATCH"
        raise ContractError(code, "Public repository mode readback failed")
    counts.update(dir_mode=counts["directory_mode"], file_mode_mismatches=counts["file_mode"],
                  dir_mode_mismatches=counts["directory_mode"],
                  special_or_symlink_objects=counts["symlink"] + counts["special"])
    samples["dir_mode"] = samples["directory_mode"]
    samples["all"] = [row for k in kinds for row in samples[k]][:10]
    return {"status": "pass" if passed else "fail", "counts": counts,
            "mismatch_counts": dict(counts), "mismatch_samples": samples, "samples": samples}
