"""Bounded transport of the generic Nebular 0.7 public-CI input bundle.

The tracked manifest is the authority for release asset identity.  This module
only downloads those exact public bytes and materializes the checkout-local
``.scratch/nebular070-inputs`` layout; the maintained qualification validator
remains responsible for authenticating the descriptor's release and source
joins.
"""

from __future__ import annotations

import argparse
import gzip
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import stat
import tarfile
from urllib.parse import quote

from rs9.errors import ContractError
from rs9.github import PublicClient
from rs9.scratch import ConfinedWriter, canonical, physical_directory
from rs9.security import (
    scan_bytes_for_credentials,
    validate_repository,
    validate_safe_basename,
    validate_safe_relative_posix_path,
    validate_version_string,
)


SCHEMA = "rs9.nebular070-public-input-manifest.v1"
REPOSITORY = "Knowledge-Forge-AI/theme-forge-nebular-fusion"
VERSION = "0.7.0"
TAG = "v0.7.0"
DESCRIPTOR_SCHEMA = "rs9.tf-pypi-nebular070-qualification-inputs.v1"
DESCRIPTOR_NAME = "qualification-inputs.json"
# The npm wrapper has one historical consumer path in addition to the
# canonical release-asset path.  This is deliberately a fixed compatibility
# view, not a general alias facility.
COMPATIBILITY_WRAPPER_PATH = "npm/package.tgz"
MAX_METADATA_BYTES = 32 * 1024 * 1024
MAX_METADATA_MEMBERS = 512
MAX_METADATA_MEMBER_BYTES = 8 * 1024 * 1024
# A regular tar member needs one 512-byte header plus up to 511 bytes of
# padding.  This bound also leaves two end-of-archive blocks; gzip expansion
# is stopped before tarfile interprets PAX/GNU extension headers.
MAX_TAR_BYTES = MAX_METADATA_BYTES + MAX_METADATA_MEMBERS * 1024 + 2048
MAX_PAYLOAD_BYTES = 300 * 1024 * 1024
MAX_PAYLOAD_TOTAL = 1024 * 1024 * 1024
SHA256_RE = re.compile(r"[0-9a-f]{64}\Z")
PROTECTED_COMPONENTS = frozenset({".git", ".serena", "DB", "RAW", ".ninja_deps", ".ninja_log"})
ARCHIVE_SUFFIXES = (".tgz", ".tar", ".tar.gz", ".zip", ".whl", ".deb", ".dylib", ".dll", ".so")
# These are opaque, authenticated release evidence members, not payload
# inputs.  They are admitted only at these exact paths and only after their
# regular-member bytes match the independently pinned size and digest.  The
# contents are never unpacked or executed by this transport.
OPAQUE_METADATA_ARCHIVES = (
    ("evidence/public-release/assets/nebular-v0.7.0-third-party-notices.tar.gz",
     30212, "c8ab80d6601947a505eb68e482985672dd4c4a697ff57ecb1bacb9ca9935dbde"),
    ("evidence/public-release/assets/theme-forge-nebular-fusion-v0.7.0-source.tar.gz",
     4453031, "183f99f5af7228eb6498ab990fa514bb501586e8a0ff31a93a7bc05c736a805a"),
)
TOP_KEYS = frozenset({"schema", "repository", "version", "release_id", "metadata", "payloads"})
ASSET_KEYS = frozenset({"asset_id", "name", "url", "bytes", "sha256"})
PAYLOAD_KEYS = ASSET_KEYS | {"path"}


def _fail(code: str, message: str) -> None:
    raise ContractError(code, message)


def _positive_int(value, field: str) -> None:
    if type(value) is not int or not 0 < value <= 2**63 - 1:
        _fail("INVALID_MANIFEST", f"{field} must be a positive bounded integer")


def _sha(value, field: str) -> None:
    if not isinstance(value, str) or SHA256_RE.fullmatch(value) is None:
        _fail("INVALID_MANIFEST", f"{field} must be a lowercase SHA-256")


def _asset_url(repository: str, name: str) -> str:
    return "https://github.com/" + repository + "/releases/download/" + TAG + "/" + quote(name, safe="")


def _validate_asset(row, *, field: str, payload: bool) -> dict:
    expected = PAYLOAD_KEYS if payload else ASSET_KEYS
    if type(row) is not dict or set(row) != expected:
        _fail("INVALID_MANIFEST", f"{field} has an unexpected closed shape")
    _positive_int(row["asset_id"], field + ".asset_id")
    validate_safe_basename(row["name"], field + ".name")
    if type(row["bytes"]) is not int or row["bytes"] <= 0:
        _fail("INVALID_MANIFEST", f"{field}.bytes must be positive")
    _sha(row["sha256"], field + ".sha256")
    if not isinstance(row["url"], str) or row["url"] != _asset_url(REPOSITORY, row["name"]):
        _fail("ASSET_AUTHORITY", f"{field}.url is not the pinned release download URL")
    if payload:
        validate_safe_relative_posix_path(row["path"], field + ".path")
        parts = row["path"].split("/")
        if any(part in PROTECTED_COMPONENTS for part in parts):
            _fail("PROTECTED_PATH", f"{field}.path is outside the public source layout")
    return dict(row)


def validate_manifest(value) -> dict:
    """Validate the closed, release-pinned manifest before any network request."""
    if type(value) is not dict or set(value) != TOP_KEYS:
        _fail("INVALID_MANIFEST", "Manifest has an unexpected closed shape")
    if value["schema"] != SCHEMA or value["repository"] != REPOSITORY or value["version"] != VERSION:
        _fail("MANIFEST_IDENTITY", "Manifest repository, schema, or version is not Nebular 0.7")
    validate_repository(value["repository"])
    validate_version_string(value["version"])
    _positive_int(value["release_id"], "release_id")
    metadata = _validate_asset(value["metadata"], field="metadata", payload=False)
    if not metadata["name"].endswith(".tar.gz") or metadata["bytes"] > MAX_METADATA_BYTES:
        _fail("METADATA_LIMIT", "Metadata asset must be a bounded tar.gz")
    payloads = value["payloads"]
    if type(payloads) is not list or len(payloads) != 4:
        _fail("PAYLOAD_SHAPE", "Exactly three raw archives and one npm wrapper are required")
    seen_ids = {metadata["asset_id"]}
    seen_names = {metadata["name"]}
    seen_paths = set()
    raw, wrappers = [], []
    total = 0
    for index, item in enumerate(payloads):
        row = _validate_asset(item, field=f"payloads[{index}]", payload=True)
        if row["asset_id"] in seen_ids or row["name"] in seen_names or row["path"] in seen_paths:
            _fail("DUPLICATE_ASSET", "Asset identities and output paths must be unique")
        seen_ids.add(row["asset_id"])
        seen_names.add(row["name"])
        seen_paths.add(row["path"])
        if row["bytes"] > MAX_PAYLOAD_BYTES:
            _fail("PAYLOAD_LIMIT", "Payload exceeds the per-asset limit")
        total += row["bytes"]
        if total > MAX_PAYLOAD_TOTAL:
            _fail("PAYLOAD_LIMIT", "Payload aggregate exceeds the bounded limit")
        if row["name"].endswith(".tgz"):
            wrappers.append(row)
        elif row["name"].endswith(".tar.gz"):
            raw.append(row)
        else:
            _fail("PAYLOAD_SHAPE", "Payload must be a tar.gz raw archive or tgz npm wrapper")
    if len(raw) != 3 or len(wrappers) != 1:
        _fail("PAYLOAD_SHAPE", "Exactly three .tar.gz payloads and one .tgz wrapper are required")
    result = {"schema": SCHEMA, "repository": REPOSITORY, "version": VERSION,
              "release_id": value["release_id"], "metadata": metadata,
              "payloads": [dict(row) for row in payloads]}
    return result


def _safe_member_name(name: str) -> str:
    if name.endswith("/"):
        name = name[:-1]
    validate_safe_relative_posix_path(name, "archive member")
    parts = name.split("/")
    if any(part in PROTECTED_COMPONENTS for part in parts):
        _fail("PROTECTED_PATH", "Metadata archive contains a protected path component")
    opaque = any(name == path for path, _size, _sha256 in OPAQUE_METADATA_ARCHIVES)
    if name == "fetch-receipt.json" or (name.endswith(ARCHIVE_SUFFIXES) and not opaque):
        _fail("UNSAFE_MEMBER", "Metadata archive contains a payload-like member")
    return name


def _archive_members(data: bytes) -> tuple[dict, ...]:
    if len(data) > MAX_METADATA_BYTES:
        _fail("METADATA_LIMIT", "Metadata response exceeds the compressed byte limit")
    entries, total = {}, 0
    try:
        with gzip.GzipFile(fileobj=io.BytesIO(data), mode="rb") as decoded:
            expanded = decoded.read(MAX_TAR_BYTES + 1)
        if len(expanded) > MAX_TAR_BYTES:
            _fail("METADATA_LIMIT", "Expanded metadata tar exceeds the bounded byte limit")
        with tarfile.open(fileobj=io.BytesIO(expanded), mode="r:") as archive:
            for member in archive:
                if len(entries) >= MAX_METADATA_MEMBERS:
                    _fail("METADATA_LIMIT", "Metadata member count exceeds the bound")
                name = _safe_member_name(member.name)
                expected_opaque = next((entry[1:] for entry in OPAQUE_METADATA_ARCHIVES
                                       if entry[0] == name), None)
                if expected_opaque is not None and not member.isfile():
                    _fail("UNSAFE_MEMBER", "Approved opaque member must be a regular file")
                if name in entries:
                    _fail("DUPLICATE_MEMBER", "Metadata archive contains a duplicate member")
                if member.pax_headers:
                    _fail("UNSAFE_MEMBER", "PAX metadata is not accepted in the metadata archive")
                if member.mode & 0o7000:
                    _fail("UNSAFE_MODE", "Metadata archive contains privileged mode bits")
                if member.isdir():
                    if member.size != 0:
                        _fail("UNSAFE_MEMBER", "Metadata directory declares a nonzero body")
                    entries[name] = {"path": name, "type": "directory", "mode": member.mode & 0o777}
                    continue
                if not member.isfile() or member.size < 0 or member.size > MAX_METADATA_MEMBER_BYTES:
                    _fail("UNSAFE_MEMBER", "Metadata archive contains a non-regular member")
                if member.mode & 0o111:
                    _fail("UNSAFE_MODE", "Metadata files must not be executable")
                total += member.size
                if total > MAX_METADATA_BYTES:
                    _fail("METADATA_LIMIT", "Metadata members exceed the uncompressed byte limit")
                source = archive.extractfile(member)
                if source is None:
                    _fail("INVALID_ARCHIVE", "Metadata regular member has no body")
                body = source.read(member.size + 1)
                if len(body) != member.size:
                    _fail("INVALID_ARCHIVE", "Metadata regular member is truncated")
                if expected_opaque is not None:
                    expected_size, expected_sha256 = expected_opaque
                    if member.size != expected_size:
                        _fail("OPAQUE_MEMBER_MISMATCH", "Approved opaque member has an unexpected size")
                    if hashlib.sha256(body).hexdigest() != expected_sha256:
                        _fail("OPAQUE_MEMBER_MISMATCH", "Approved opaque member has an unexpected digest")
                scan_bytes_for_credentials(body)
                entries[name] = {"path": name, "type": "file", "mode": member.mode & 0o777, "body": body}
    except ContractError:
        raise
    except (OSError, EOFError, tarfile.TarError, ValueError):
        _fail("INVALID_ARCHIVE", "Metadata tar.gz is malformed or unreadable")
    if DESCRIPTOR_NAME not in entries or entries[DESCRIPTOR_NAME]["type"] != "file":
        _fail("DESCRIPTOR_MISSING", "Metadata archive must contain qualification-inputs.json at its root")
    for path, entry in entries.items():
        if entry["type"] == "file":
            parent = PurePosixPath(path).parent
            while str(parent) not in ("", "."):
                parent_entry = entries.get(str(parent))
                if parent_entry is not None and parent_entry["type"] != "directory":
                    _fail("UNSAFE_MEMBER", "Metadata file has a non-directory archive ancestor")
                parent = parent.parent
    return tuple(entries[path] for path in sorted(entries))


def _descriptor_from_entries(entries: tuple[dict, ...]) -> tuple[dict, str, str, str]:
    body = next(entry["body"] for entry in entries if entry["path"] == DESCRIPTOR_NAME)
    try:
        descriptor = json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        _fail("DESCRIPTOR_INVALID", "Qualification descriptor is not bounded UTF-8 JSON")
    if type(descriptor) is not dict or descriptor.get("schema") != DESCRIPTOR_SCHEMA:
        _fail("DESCRIPTOR_INVALID", "Qualification descriptor schema is not the maintained v1 schema")
    if descriptor.get("project") != "theme-forge-nebular-fusion" or descriptor.get("version") != VERSION:
        _fail("DESCRIPTOR_IDENTITY", "Qualification descriptor project/version disagrees")
    roots = {}
    for section in ("evidence", "raw_release"):
        item = descriptor.get(section)
        if type(item) is not dict or not isinstance(item.get("source_root"), str):
            _fail("DESCRIPTOR_ROOT", "Qualification descriptor is missing a source root")
        root = item["source_root"]
        validate_safe_relative_posix_path(root, section + ".source_root")
        if root == "." or any(part in PROTECTED_COMPONENTS for part in root.split("/")):
            _fail("PROTECTED_PATH", "Qualification descriptor source root is protected")
        roots[section] = root
    return descriptor, roots["evidence"], roots["raw_release"], hashlib.sha256(body).hexdigest()


def _compatibility_wrapper_alias(descriptor: dict, evidence_root: str, wrapper_row: dict,
                                 metadata_entries: tuple[dict, ...], payload_paths: set[str]) -> str | None:
    """Validate the one declared npm wrapper compatibility view.

    Older manifests do not declare ``evidence.files`` and therefore retain
    their existing single-path behavior.  A newer descriptor may declare the
    exact fixed ``npm/package.tgz`` record; only then do we materialize the
    second view.  The declaration is checked against the already pinned
    wrapper row before any metadata or payload bytes are written.
    """
    evidence = descriptor.get("evidence")
    if type(evidence) is not dict or "files" not in evidence:
        return None
    files = evidence["files"]
    if type(files) is not dict:
        _fail("DESCRIPTOR_JOIN", "Qualification evidence.files must be a closed mapping")
    declared = files.get(COMPATIBILITY_WRAPPER_PATH)
    if declared is None:
        return None
    if type(declared) is not dict or set(declared) != {"path", "size", "sha256"}:
        _fail("DESCRIPTOR_JOIN", "npm wrapper compatibility record has an unexpected shape")
    if declared["path"] != COMPATIBILITY_WRAPPER_PATH:
        _fail("DESCRIPTOR_JOIN", "npm wrapper compatibility record has an unexpected path")
    _positive_int(declared["size"], "evidence.files.npm/package.tgz.size")
    _sha(declared["sha256"], "evidence.files.npm/package.tgz.sha256")
    if declared["size"] != wrapper_row["bytes"] or declared["sha256"] != wrapper_row["sha256"]:
        _fail("COMPATIBILITY_ALIAS_MISMATCH", "npm wrapper compatibility record disagrees with the pinned asset")
    alias_path = evidence_root.rstrip("/") + "/" + COMPATIBILITY_WRAPPER_PATH
    validate_safe_relative_posix_path(alias_path, "compatibility output path")
    for entry in metadata_entries:
        metadata_path = entry["path"]
        if (metadata_path == alias_path or metadata_path.startswith(alias_path + "/")
                or (alias_path.startswith(metadata_path + "/") and entry["type"] != "directory")):
            _fail("OUTPUT_COLLISION", "npm wrapper compatibility path collides with metadata")
    for payload_path in payload_paths:
        if payload_path == wrapper_row["path"]:
            continue
        if (payload_path == alias_path or payload_path.startswith(alias_path + "/")
                or alias_path.startswith(payload_path + "/")):
            _fail("OUTPUT_COLLISION", "npm wrapper compatibility path collides with a payload")
    # A legacy manifest may already use the compatibility path as the
    # canonical wrapper output.  It still receives all declaration checks,
    # but must not be written twice through the exclusive writer.
    return None if alias_path == wrapper_row["path"] else alias_path


def _strings(value, *, limit=20000):
    found, seen = [], 0
    def visit(item):
        nonlocal seen
        seen += 1
        if seen > limit:
            _fail("DESCRIPTOR_LIMIT", "Qualification descriptor is too large")
        if isinstance(item, str):
            found.append(item)
        elif isinstance(item, dict):
            for key, child in item.items():
                if isinstance(key, str):
                    found.append(key)
                visit(child)
        elif isinstance(item, list):
            for child in item:
                visit(child)
    visit(value)
    return set(found)


def _write_metadata(writer: ConfinedWriter, entries: tuple[dict, ...]) -> None:
    for entry in entries:
        if entry["type"] == "file":
            writer.write(entry["path"], entry["body"])


def _read_owned(path: Path, limit: int) -> bytes:
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
        try:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or info.st_size > limit:
                _fail("DESCRIPTOR_INVALID", "Owned descriptor is not a bounded regular file")
            chunks, remaining = [], limit + 1
            while remaining:
                chunk = os.read(fd, remaining)
                if not chunk:
                    break
                chunks.append(chunk)
                remaining -= len(chunk)
            body = b"".join(chunks)
            if len(body) != info.st_size:
                _fail("DESCRIPTOR_INVALID", "Owned descriptor changed during read")
            return body
        finally:
            os.close(fd)
    except ContractError:
        raise
    except OSError:
        _fail("DESCRIPTOR_INVALID", "Owned descriptor could not be read")


def _create_output(path: Path) -> tuple[Path, tuple[int, int, int]]:
    if path.is_absolute() is False:
        path = Path.cwd() / path
    path = path.absolute()
    parent = physical_directory(path.parent)
    if path.exists() or path.is_symlink():
        _fail("OUTPUT_EXISTS", "Output root must not already exist")
    path.mkdir(mode=0o700)
    info = os.lstat(path)
    if not stat.S_ISDIR(info.st_mode):
        _fail("OUTPUT_CUSTODY", "Output root is not a directory")
    return path, (info.st_dev, info.st_ino, info.st_uid)


def _cleanup_output(path: Path, identity: tuple[int, int, int]) -> bool:
    try:
        info = os.lstat(path)
        if (not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode)
                or (info.st_dev, info.st_ino, info.st_uid) != identity):
            return False
        shutil.rmtree(path)
        return not path.exists()
    except OSError:
        return False


def _load_manifest(path: Path, repository_root: Path | None) -> dict:
    root = physical_directory(repository_root or Path.cwd())
    if not path.is_absolute():
        validate_safe_relative_posix_path(path.as_posix(), "manifest")
    target = path if path.is_absolute() else root / path
    physical_directory(target.parent)
    try:
        data = _read_owned(target.absolute(), 2 * 1024 * 1024)
        value = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        _fail("INVALID_MANIFEST", "Manifest is not bounded UTF-8 JSON")
    return validate_manifest(value)


def materialize_public_inputs(manifest, output, *, client=None, repository_root=None) -> dict:
    """Fetch and materialize a fresh, digest-bound generic input root."""
    value = validate_manifest(manifest) if isinstance(manifest, dict) else _load_manifest(Path(manifest), repository_root)
    client = client or PublicClient()
    output_path, identity = _create_output(Path(output))
    try:
        with ConfinedWriter(output_path, file_mode=0o644, dir_mode=0o755) as writer:
            metadata_bytes = client.get(value["metadata"]["url"], request_class="github-asset",
                                        limit=MAX_METADATA_BYTES, expected_size=value["metadata"]["bytes"])
            if hashlib.sha256(metadata_bytes).hexdigest() != value["metadata"]["sha256"]:
                _fail("DIGEST_MISMATCH", "Metadata asset digest differs from the manifest")
            entries = _archive_members(metadata_bytes)
            descriptor, evidence_root, raw_root, descriptor_sha = _descriptor_from_entries(entries)
            metadata_paths = {entry["path"] for entry in entries}
            strings = _strings(descriptor)
            for row in value["payloads"]:
                expected_root = evidence_root if row["name"].endswith(".tgz") else raw_root
                prefix = expected_root.rstrip("/") + "/"
                relative = row["path"][len(prefix):] if row["path"].startswith(prefix) else ""
                if not relative or (row["path"] not in strings and relative not in strings):
                    _fail("DESCRIPTOR_JOIN", "Payload output path is not bound by the descriptor")
                if row["path"] in metadata_paths:
                    _fail("OUTPUT_COLLISION", "Payload output path collides with metadata")
            wrapper_row = next(row for row in value["payloads"] if row["name"].endswith(".tgz"))
            compatibility_alias = _compatibility_wrapper_alias(
                descriptor, evidence_root, wrapper_row, entries,
                {row["path"] for row in value["payloads"]})
            _write_metadata(writer, entries)
            payload_records = []
            for row in value["payloads"]:
                body = client.get(row["url"], request_class="github-asset", limit=MAX_PAYLOAD_BYTES,
                                  expected_size=row["bytes"])
                actual_sha = hashlib.sha256(body).hexdigest()
                if actual_sha != row["sha256"]:
                    _fail("DIGEST_MISMATCH", "Payload asset digest differs from the manifest")
                writer.write(row["path"], body)
                if compatibility_alias is not None and row["name"].endswith(".tgz"):
                    writer.write(compatibility_alias, body)
                payload_records.append({"asset_id": row["asset_id"], "name": row["name"],
                                        "path": row["path"], "bytes": len(body), "sha256": actual_sha})
            receipt = {"schema": "rs9.nebular070-public-input-receipt.v1", "manifest_sha256": hashlib.sha256(canonical(value)).hexdigest(),
                       "repository": REPOSITORY, "version": VERSION, "release_id": value["release_id"],
                       "metadata": {"asset_id": value["metadata"]["asset_id"], "name": value["metadata"]["name"],
                                    "bytes": len(metadata_bytes), "sha256": hashlib.sha256(metadata_bytes).hexdigest(),
                                    "descriptor_sha256": descriptor_sha}, "payloads": payload_records,
                       "descriptor": {"schema": descriptor["schema"], "path": DESCRIPTOR_NAME,
                                      "source_roots": {"evidence": evidence_root, "raw_release": raw_root}}}
            writer.write("fetch-receipt.json", canonical(receipt, validate=True))
        return receipt
    except Exception as error:
        if not _cleanup_output(output_path, identity):
            _fail("CLEANUP_UNCERTAIN", "Owned partial output could not be safely removed")
        raise error


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Materialize pinned Nebular 0.7 public inputs")
    parser.add_argument("--manifest", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--repository-root", default=".")
    return parser


def main(argv=None) -> int:
    try:
        args = build_parser().parse_args(argv)
        receipt = materialize_public_inputs(Path(args.manifest), Path(args.output), repository_root=Path(args.repository_root))
        print(json.dumps(receipt, sort_keys=True, separators=(",", ":")))
        return 0
    except ContractError as error:
        print("nebular070 public input transport failed: " + error.code)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
