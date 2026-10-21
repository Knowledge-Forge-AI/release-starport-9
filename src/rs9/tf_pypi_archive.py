"""Hostile tar.gz archive admission reader and physical file inspector."""

import errno
import gzip
import hashlib
import io
import json
import os
import posixpath
import stat
import tarfile
import typing
import unicodedata
import zlib
from pathlib import Path


class AdmissionError(ValueError):
    """Hostile archive admission failure with sanitized error code."""

    def __init__(self, code: str):
        sanitized = "".join(
            c for c in str(code).strip() if c.isascii() and (c.isalnum() or c in ("_", "-"))
        )
        self.code = sanitized
        super().__init__(self.code)

    def __str__(self) -> str:
        return self.code

    def __repr__(self) -> str:
        return f"AdmissionError({self.code!r})"


def fail(code: str) -> typing.NoReturn:
    """Raise AdmissionError prefixed with TF_PYPI_."""
    c = str(code).strip()
    if not c.startswith("TF_PYPI_"):
        c = f"TF_PYPI_{c}"
    raise AdmissionError(c)


def sha256(data: bytes) -> str:
    """Return SHA-256 hex digest of data bytes."""
    return hashlib.sha256(data).hexdigest()


def canonical(value: typing.Any) -> bytes:
    """Return canonical sorted compact JSON plus newline."""
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8") + b"\n"


def _validate_safe_path(path: str, *, is_dir: bool = False) -> None:
    if not isinstance(path, str) or not path or unicodedata.normalize("NFC", path) != path:
        fail("PATH")
    if not path.isascii() or ":" in path or "\\" in path or "\x00" in path or path.startswith("/"):
        fail("PATH")
    if any(ord(c) < 32 or ord(c) == 127 for c in path):
        fail("PATH")
    parts = path.split("/")
    if is_dir and parts and parts[-1] == "":
        parts = parts[:-1]
    if not parts or any(p in ("", ".", "..") for p in parts):
        fail("PATH")


def _check_gzip_header(data: bytes, max_header_bytes: int = 4096) -> None:
    if len(data) < 10 or data[:2] != b"\x1f\x8b" or data[2] != 8:
        fail("ARCHIVE")
    flg, pos = data[3], 10
    if flg & 0xe0:
        fail("ARCHIVE")
    if flg & 0x04:
        if pos + 2 > len(data):
            fail("ARCHIVE")
        pos += 2 + int.from_bytes(data[pos : pos + 2], "little")
    if flg & 0x08:
        nul = data.find(b"\x00", pos, min(len(data), max_header_bytes))
        if nul < 0:
            fail("ARCHIVE")
        pos = nul + 1
    if flg & 0x10:
        nul = data.find(b"\x00", pos, min(len(data), max_header_bytes))
        if nul < 0:
            fail("ARCHIVE")
        pos = nul + 1
    if flg & 0x02:
        pos += 2
    if pos > max_header_bytes or pos > len(data):
        fail("ARCHIVE")


class SafeTarInfo(tarfile.TarInfo):
    @classmethod
    def frombuf(cls, buf: bytes, encoding: str, errors: str) -> "SafeTarInfo":
        obj = super().frombuf(buf, encoding, errors)
        obj.raw_name = obj.name
        return obj

    def _proc_member(self, tar):
        # Newer readers bypass frombuf; record this header's own name before PAX/GNU names apply.
        self.raw_name = self.name
        return super()._proc_member(tar)


def _member_path(member, root):
    if not (member.isfile() or member.isdir()) or member.linkname or member.sparse is not None:
        fail("LINK")
    raw_name = getattr(member, "raw_name", None)
    if not isinstance(raw_name, str):
        fail("ARCHIVE")
    pax_path = member.pax_headers.get("path") if member.pax_headers else None
    for name in (member.name, raw_name):
        _validate_safe_path(name, is_dir=member.isdir())
    if pax_path is not None:
        _validate_safe_path(pax_path, is_dir=member.isdir())
        if pax_path.rstrip("/") != member.name.rstrip("/"):
            fail("ARCHIVE")
    if raw_name.rstrip("/") != member.name.rstrip("/"):
        if len(raw_name) < 100 or not member.name.startswith(raw_name):
            fail("ARCHIVE")
    name = member.name.rstrip("/") if member.isdir() else member.name
    if not (name == root and member.isdir()) and not name.startswith(root + "/"):
        fail("ROOT")
    return name


class _Index:
    def __init__(self):
        self.seen, self.dirs, self.files, self.casing = set(), set(), set(), {}

    def add(self, name, directory):
        folded = name.casefold()
        if folded in self.seen:
            fail("DUPLICATE")
        self.seen.add(folded)
        parent = posixpath.dirname(name)
        while parent:
            cf_parent = parent.casefold()
            if cf_parent in self.casing and self.casing[cf_parent] != parent:
                fail("DUPLICATE")
            self.casing[cf_parent] = parent
            if cf_parent in self.files:
                fail("ANCESTOR")
            self.dirs.add(cf_parent)
            parent = posixpath.dirname(parent)
        if directory:
            if folded in self.casing and self.casing[folded] != name:
                fail("DUPLICATE")
            self.casing[folded] = name
            self.dirs.add(folded)
        else:
            if folded in self.dirs:
                fail("ANCESTOR")
            self.files.add(folded)


def _content(archive, member, maximum):
    mode = member.mode
    if mode not in ({0o755} if member.isdir() else {0o644, 0o755}):
        fail("MODE")
    if member.size < 0 or member.size > maximum or (member.isdir() and member.size):
        fail("ARCHIVE")
    if member.isdir():
        return None
    with archive.extractfile(member) as stream:
        content = stream.read(maximum + 1)
    if len(content) != member.size:
        fail("ARCHIVE")
    return content, mode


def read_tar(
    data: bytes,
    root: str = "package",
    *,
    max_members: int = 20000,
    max_member_bytes: int = 8 * 1024**2,
    max_total_bytes: int = 64 * 1024**2,
) -> dict[str, tuple[bytes, int]]:
    """Read a gzip tar archive validating safety constraints without extracting."""
    if not isinstance(data, (bytes, bytearray)) or len(data) > 32 * 1024**2:
        fail("ARCHIVE")
    _check_gzip_header(data)

    clean_root = root.rstrip("/")
    _validate_safe_path(clean_root, is_dir=True)
    decompression_limit = max_total_bytes + (max_members + 2) * 2048

    result, index, total_bytes = {}, _Index(), 0
    try:
        # Consume to gzip EOF before accepting tar end markers, validating CRC/ISIZE.
        decoder = zlib.decompressobj(16 + zlib.MAX_WBITS)
        decoded = decoder.decompress(data, decompression_limit + 1)
        if not decoder.eof or decoder.unused_data or decoder.unconsumed_tail:
            fail("ARCHIVE")
        if len(decoded) > decompression_limit or len(decoded) % 512:
            fail("ARCHIVE")
        with tarfile.open(fileobj=io.BytesIO(decoded), mode="r:", tarinfo=SafeTarInfo) as archive:
            for count, member in enumerate(archive, 1):
                if count > max_members:
                    fail("ARCHIVE")
                name = _member_path(member, clean_root)
                index.add(name, member.isdir())
                value = _content(archive, member, max_member_bytes)
                if value is not None:
                    result[name] = value
                    total_bytes += len(value[0])
                    if total_bytes > max_total_bytes:
                        fail("ARCHIVE")
            # Reject concatenated/hidden tar members after the first end marker.
            if len(decoded) - archive.offset < 1024 or any(decoded[archive.offset:]):
                fail("ARCHIVE")
        if not result:
            fail("ARCHIVE")
    except AdmissionError:
        raise
    except (tarfile.TarError, gzip.BadGzipFile, EOFError, OSError, zlib.error, ValueError):
        fail("ARCHIVE")

    return dict(sorted(result.items()))


def _open_physical(path):
    # Hold directory descriptors so a replaced ancestor cannot redirect the read.
    if os.name != "posix":
        fail("UNSUPPORTED_HOST")
    parts = Path(os.path.abspath(path)).parts
    directory_flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    descriptor = os.open(parts[0], directory_flags)
    try:
        for part in parts[1:-1]:
            child = os.open(part, directory_flags, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = child
        flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK
        return os.open(parts[-1], flags, dir_fd=descriptor)
    finally:
        os.close(descriptor)


def _fingerprint(info):
    return info.st_size, info.st_mtime_ns, info.st_ctime_ns, info.st_ino, info.st_dev


def _stable_read(fd, limit):
    before = os.fstat(fd)
    if not stat.S_ISREG(before.st_mode):
        fail("FILE")
    if before.st_size < 0 or before.st_size > limit:
        fail("LIMIT")
    chunks, count = [], 0
    while True:
        chunk = os.read(fd, min(65536, limit - count + 1))
        if not chunk:
            break
        count += len(chunk)
        if count > limit:
            fail("LIMIT")
        chunks.append(chunk)
    data = b"".join(chunks)
    if len(data) != before.st_size or _fingerprint(os.fstat(fd)) != _fingerprint(before):
        fail("MUTATED")
    return data


def physical_bytes(path: typing.Union[str, os.PathLike], *, limit: int = 32 * 1024**2) -> bytes:
    """Read a regular physical file rejecting symlinks with stable fstat."""
    if limit < 0:
        fail("LIMIT")
    try:
        p = Path(path)
        if any(part.is_symlink() for part in (p, *p.parents)):
            fail("SYMLINK")
        fd = _open_physical(p)
    except FileNotFoundError:
        fail("ASSET_ABSENT")
    except OSError as err:
        if err.errno == errno.ELOOP:
            fail("SYMLINK")
        fail("FILE")
    except (TypeError, ValueError) as err:
        if isinstance(err, AdmissionError):
            raise
        fail("FILE")
    try:
        return _stable_read(fd, limit)
    finally:
        os.close(fd)
