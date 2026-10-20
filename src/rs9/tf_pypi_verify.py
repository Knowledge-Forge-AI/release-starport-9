"""Exact wheel/sdist admission, independent RECORD checks and byte custody."""
import base64
import csv
import hashlib
import io
from pathlib import Path, PurePosixPath
import stat
import zipfile

from rs9.tf_pypi_archive import canonical, fail, physical_bytes, read_tar, sha256
from rs9.tf_pypi_backend import names, payload, sdist_entries, wheel_entries
from rs9.tf_pypi_closure import DEPENDENCIES
from rs9.tf_pypi_model import logical_identity, strict_json, validate_pin


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


def _sdist_dependencies(pin, sdist):
    if pin["project"] != "theme-forge-stellar-burst":
        return {}
    dependencies = {}
    for dep in DEPENDENCIES:
        entry = sdist.get("upstream/" + dep["asset"])
        if entry is None:
            fail("SDIST")
        dependencies[dep["asset"]] = entry[0]
    return dependencies


def verify_pair(pin, directory, target=None):
    validate_pin(pin)
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
    dependencies = _sdist_dependencies(pin, sdist)
    _, tag, _ = payload(pin, asset[0], dependencies, target)
    wheel_name = stem + "-py3-none-" + tag + ".whl"
    try:
        actual_names = {p.name for p in directory.iterdir()}
    except OSError:
        fail("FILE_SET")
    if actual_names != {wheel_name, sdist_name}:
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
            "version": pin["distribution_version"], "upstream_version": pin["version"],
            "publication_admitted": False,
            "files": records, "set_sha256": sha256(canonical(records))}


def verify_aggregate(pin, directory):
    validate_pin(pin)
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
    dependencies = _sdist_dependencies(pin, sdist)
    targets = list(pin["candidate_platforms"])
    wheel_by_target = {}
    for target in targets:
        _, tag, _ = payload(pin, asset[0], dependencies, target)
        wheel_by_target[target] = stem + "-py3-none-" + tag + ".whl"
    if len(set(wheel_by_target.values())) != len(targets):
        fail("FILE_SET")
    try:
        actual_names = {p.name for p in directory.iterdir()}
    except OSError:
        fail("FILE_SET")
    if actual_names != {sdist_name, *wheel_by_target.values()}:
        fail("FILE_SET")
    sdist_sets = [sdist_entries(pin, asset[0], dependencies, target) for target in targets]
    if any(entries != sdist_sets[0] for entries in sdist_sets[1:]):
        fail("SDIST_DIVERGENT")
    if sdist != sdist_sets[0]:
        fail("SDIST_MATCH")
    records = [{
        "filename": sdist_name,
        "size": len(sdist_body),
        "sha256": sha256(sdist_body),
        "logical_sha256": logical_identity(sdist),
        "target": None,
    }]
    for target, wheel_name in wheel_by_target.items():
        wheel_body = physical_bytes(directory / wheel_name)
        wheel = read_wheel(wheel_body)
        verify_record(wheel, info)
        if wheel.get(info + "/METADATA") != sdist.get("PKG-INFO"):
            fail("METADATA")
        if wheel != wheel_entries(pin, asset[0], dependencies, target):
            fail("WHEEL_MATCH")
        transform_entry = wheel.get(info + "/rs9-tf-transform.json")
        if not transform_entry or strict_json(transform_entry[0]).get("target_key") != target:
            fail("WHEEL_MATCH")
        records.append({
            "filename": wheel_name,
            "size": len(wheel_body),
            "sha256": sha256(wheel_body),
            "logical_sha256": logical_identity(wheel),
            "target": target,
        })
    records.sort(key=lambda row: row["filename"])
    return {
        "schema": "rs9.tf-pypi-candidate-aggregate.v1",
        "project": pin["project"],
        "version": pin["distribution_version"],
        "upstream_version": pin["version"],
        "targets": targets,
        "publication_admitted": False,
        "files": records,
        "set_sha256": sha256(canonical(records)),
    }


def host_view(pin, aggregate_dir, target, output_dir):
    aggregate = verify_aggregate(pin, aggregate_dir)
    if target not in pin["candidate_platforms"]:
        fail("UNSUPPORTED_PLATFORM")
    wheel_record = next((row for row in aggregate["files"] if row["target"] == target), None)
    sdist_record = next((row for row in aggregate["files"] if row["target"] is None), None)
    if wheel_record is None or sdist_record is None:
        fail("VIEW")
    output = Path(output_dir)
    if output.exists() or output.is_symlink():
        fail("VIEW")
    output.mkdir(parents=True, exist_ok=False)
    for record in (wheel_record, sdist_record):
        body = physical_bytes(Path(aggregate_dir) / record["filename"])
        with (output / record["filename"]).open("xb") as stream:
            stream.write(body)
    pair = verify_pair(pin, output, target=target)
    expected_files = sorted(
        [{k: v for k, v in row.items() if k != "target"} for row in (wheel_record, sdist_record)],
        key=lambda row: row["filename"],
    )
    if pair["files"] != expected_files:
        fail("VIEW")
    return pair


def verify_manifest(pin, directory, manifest):
    actual = verify_pair(pin, directory)
    if actual != manifest:
        fail("SET_DIGEST")
    return actual
