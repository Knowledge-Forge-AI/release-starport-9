"""Exact wheel/sdist admission, independent RECORD checks and byte custody."""
import base64
import csv
import hashlib
import io
from pathlib import Path, PurePosixPath
import stat
import zipfile

from rs9.tf_pypi_archive import canonical, fail, physical_bytes, read_tar, sha256
from rs9.tf_pypi_backend import names, sdist_entries, wheel_entries
from rs9.tf_pypi_closure import DEPENDENCIES
from rs9.tf_pypi_backend import payload
from rs9.tf_pypi_model import logical_identity


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


def _wheel_mode(member):
    mode = member.external_attr >> 16
    if stat.S_IFMT(mode) != stat.S_IFREG or stat.S_IMODE(mode) not in {0o644, 0o755}:
        fail("WHEEL")
    if (member.flag_bits & 1 or member.file_size > 8 * 1024**2
            or member.compress_type not in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED)):
        fail("WHEEL")
    return stat.S_IMODE(mode)


def read_wheel(data):
    result, folded, total = {}, set(), 0
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            if len(archive.infolist()) > 20000:
                fail("WHEEL")
            for member in archive.infolist():
                path, mode = _wheel_path(member), _wheel_mode(member)
                if path.casefold() in folded:
                    fail("WHEEL")
                total += member.file_size
                if total > 64 * 1024**2:
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


def verify_pair(pin, directory, target=None):
    directory = Path(directory)
    _, stem, info = names(pin)
    sdist_name = stem + ".tar.gz"
    if directory.is_symlink():
        fail("FILE_SET")
    sdist_body = physical_bytes(directory / sdist_name)
    sdist = read_tar(sdist_body, stem)
    sdist = {p[len(stem) + 1:]: value for p, value in sdist.items()}
    asset = sdist.get("upstream/" + pin["asset"])
    if asset is None:
        fail("SDIST")
    dependencies = {p["asset"]: sdist["upstream/" + p["asset"]][0]
                    for p in DEPENDENCIES} if pin["project"] == "theme-forge-stellar-burst" else {}
    _, tag, _ = payload(pin, asset[0], dependencies, target)
    wheel_name = stem + "-py3-none-" + tag + ".whl"
    if set(p.name for p in directory.iterdir()) != {wheel_name, sdist_name}:
        fail("FILE_SET")
    bodies = {wheel_name: physical_bytes(directory / wheel_name), sdist_name: sdist_body}
    expected_sdist = sdist_entries(pin, asset[0], dependencies, target)
    if sdist != expected_sdist:
        fail("SDIST_MATCH")
    wheel = read_wheel(bodies[wheel_name])
    verify_record(wheel, info)
    if wheel.get(info + "/METADATA") != sdist.get("PKG-INFO"):
        fail("METADATA")
    if wheel != wheel_entries(pin, asset[0], dependencies, target):
        fail("WHEEL_MATCH")
    records = [{"filename": name, "size": len(body), "sha256": sha256(body),
                "logical_sha256": logical_identity(wheel if name == wheel_name else sdist)}
               for name, body in sorted(bodies.items())]
    return {"schema": "rs9.tf-pypi-candidate-set.v1", "project": pin["project"],
            "version": pin["version"], "publication_admitted": False,
            "files": records, "set_sha256": sha256(canonical(records))}


def verify_manifest(pin, directory, manifest):
    actual = verify_pair(pin, directory)
    if actual != manifest:
        fail("SET_DIGEST")
    return actual
