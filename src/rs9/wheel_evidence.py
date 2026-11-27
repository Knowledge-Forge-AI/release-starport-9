"""Bounded wheel and RECORD readers shared by Python release profiles."""
import base64
import csv
import hashlib
import io
from pathlib import PurePosixPath
import stat
import zipfile

from rs9.tf_pypi_archive import fail


def _wheel_path(member):
    path = member.filename
    if (member.orig_filename != path or not path.isascii() or "\\" in path
            or "\x00" in path or ":" in path or str(PurePosixPath(path)) != path):
        fail("WHEEL")
    if any(ord(c) < 32 or ord(c) == 127 for c in path):
        fail("WHEEL")
    if any(p in {"", ".", ".."} for p in path.split("/")):
        fail("WHEEL")
    return path


def _wheel_mode(member, *, max_member_bytes=8 * 1024**2):
    if type(max_member_bytes) is not int or max_member_bytes <= 0:
        fail("WHEEL")
    mode = member.external_attr >> 16
    if stat.S_IFMT(mode) != stat.S_IFREG or stat.S_IMODE(mode) not in {0o644, 0o755}:
        fail("WHEEL")
    if (member.flag_bits & 1 or member.file_size > max_member_bytes
            or member.compress_type not in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED)):
        fail("WHEEL")
    return stat.S_IMODE(mode)


def read_wheel(data, *, max_total_bytes=64 * 1024**2, max_member_bytes=8 * 1024**2):
    if (type(max_total_bytes) is not int or max_total_bytes <= 0
            or type(max_member_bytes) is not int or max_member_bytes <= 0
            or max_member_bytes > max_total_bytes):
        fail("WHEEL")
    result, folded, total = {}, set(), 0
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            if len(archive.infolist()) > 20000:
                fail("WHEEL")
            for member in archive.infolist():
                path, mode = _wheel_path(member), _wheel_mode(
                    member, max_member_bytes=max_member_bytes,
                )
                if path.casefold() in folded:
                    fail("WHEEL")
                total += member.file_size
                if total > max_total_bytes:
                    fail("WHEEL")
                folded.add(path.casefold())
                # Bound actual decompression before CRC/declared-size validation.
                # An attacker can forge file_size smaller than the DEFLATE body.
                with archive.open(member) as stream:
                    body = stream.read(member.file_size + 1)
                if len(body) != member.file_size:
                    fail("WHEEL")
                result[path] = (body, mode)
    except (zipfile.BadZipFile, OSError, ValueError, RuntimeError):
        fail("WHEEL")
    for path in result:
        if any(parent.as_posix() in result for parent in PurePosixPath(path).parents if parent.as_posix() != "."):
            fail("WHEEL")
    return result


def verify_record(files, info):
    path = info + "/RECORD"
    if path not in files:
        fail("RECORD")
    try:
        rows = list(csv.reader(io.StringIO(files[path][0].decode(), newline=""), strict=True))
    except (UnicodeError, csv.Error):
        fail("RECORD")
    seen = set()
    for row in rows:
        if len(row) != 3 or row[0] in seen or row[0] not in files:
            fail("RECORD")
        seen.add(row[0])
        if row[0] == path:
            if row[1:] != ["", ""]:
                fail("RECORD")
            continue
        body = files[row[0]][0]
        digest = base64.urlsafe_b64encode(hashlib.sha256(body).digest()).decode().rstrip("=")
        if row[1:] != ["sha256=" + digest, str(len(body))]:
            fail("RECORD")
    if seen != set(files):
        fail("RECORD")
