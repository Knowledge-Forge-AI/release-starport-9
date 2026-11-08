"""Bounded 0.8 public-input acquisition from authenticated public evidence.

The producer accepts a source-bound manifest, an injected read-only product
transport, and a separately authenticated NativeRC evidence transport.  It
materializes a fresh in-run root, authenticates the product capture, stages
only the fixed NativeRC rows, and writes the descriptor receipt last.  The
transport boundary is deliberately small so a future release asset client
can replace the local fixture without changing descriptor semantics.
"""

from __future__ import annotations

from collections.abc import Mapping
import hashlib
import io
import json
import os
from pathlib import Path
import shutil
import stat
import tarfile
import tempfile
from types import MappingProxyType
from typing import Any

from rs9.errors import ContractError
from rs9.materialize import validate_ancestry_not_symlink
from rs9.tf_pypi_archive import AdmissionError, canonical, sha256


PRODUCT_REPOSITORY = "Knowledge-Forge-AI/theme-forge-nebular-fusion"
PRODUCT_TAG = "v0.8.0"
PRODUCT_VERSION = "0.8.0"
SOURCE_SCHEMA = "rs9.nebular080-public-input-acquisition.v1"
EVIDENCE_SCHEMA = "nebular080-native-evidence-release-inventory.v1"
EVIDENCE_ARCHIVE_NAME = "nebular-v0.8.0-native-evidence-run-42418673472-attempt-1.tar.gz"
EVIDENCE_INVENTORY_NAME = "nebular-v0.8.0-native-evidence-run-42418673472-attempt-1-inventory.json"
EVIDENCE_ARCHIVE_SHA256 = "20f5aaf0dacad5437185981ab95448fb2f13f26001b19ac31fd83ac324795640"
EVIDENCE_ARCHIVE_SHA512 = "ceb0f288efc67eed64768094ea1ce9704506cfbb2828ce8e1d7032c8638740d6ac3ecd56917db47a672518e43bcb064edaccbc099d7e9b729b58279272ad4c37"
EVIDENCE_ARCHIVE_BYTES = 216591
EVIDENCE_INVENTORY_SHA256 = "89067774cbdf7b4ce931e3df6b08029bdee97873b8083460fd5b249ee4f5ec72"
EVIDENCE_INVENTORY_BYTES = 17681
EVIDENCE_SOURCE_BYTES = 1514913
EVIDENCE_RELAY_ASSET_IDS = {"archive": 722806135, "inventory": 722806134}
EVIDENCE_RELAY_TAG = "nebular-v0.8.0-native-evidence-run-42418673472-attempt-1"
EVIDENCE_RELAY_RELEASE_ID = 438017969
TARGETS = ("darwin-arm64", "linux-arm64-gnu", "linux-x64-gnu")
_LANE_BY_TARGET = {
    "darwin-arm64": "macos-arm64",
    "linux-arm64-gnu": "linux-arm64",
    "linux-x64-gnu": "linux-x64",
}
_SOURCE_FIXTURES = frozenset({
    "docs/examples/v0.4/brand-system/core-minimal/.tfsb/assets/fixture-mark-on-dark.toml",
    "docs/examples/v0.4/brand-system/core-minimal/.tfsb/assets/fixture-mark-on-light.toml",
    "docs/examples/v0.4/brand-system/core-minimal/.tfsb/brand-package.toml",
    "docs/examples/v0.4/brand-system/core-minimal/.tfsb/brand.toml",
    "docs/examples/v0.4/brand-system/core-minimal/.tfsb/companions/GUIDANCE.md",
    "docs/examples/v0.4/brand-system/core-minimal/.tfsb/project.toml",
    "docs/examples/v0.4/brand-system/core-minimal/GUIDANCE.md",
    "docs/examples/v0.4/brand-system/core-minimal/bundle/assets/fixture-mark-on-dark.svg",
    "docs/examples/v0.4/brand-system/core-minimal/bundle/assets/fixture-mark-on-light.svg",
    "docs/examples/v0.4/brand-system/core-minimal/bundle/brand/brand-package.toml",
    "docs/examples/v0.4/brand-system/core-minimal/bundle/brand/brand.toml",
    "docs/examples/v0.4/brand-system/core-minimal/bundle/companions/GUIDANCE.md",
    "docs/examples/v0.4/brand-system/core-minimal/bundle/tfsb-brand-manifest.json",
    "docs/examples/v0.4/brand-system/core-minimal/bundle/tfsb-manifest.json",
})
_SOURCE_TOOLS = frozenset({
    "native-rc-smoke.mjs", "sidecar-common.mjs", "sidecar-verify.mjs",
    "native-rc-package.mjs", "native-runtime.mjs", "native-launcher.mjs",
    "fs-snapshot.mjs", "platform-targets.mjs", "build-inputs.mjs",
    "build-settings.mjs", "candidate-provenance.mjs",
    "darwin-linkage-validator.mjs", "node-runtime-authority.mjs",
})
_HEX64 = set("0123456789abcdef")


def _fail(reason: str = "Public input acquisition contract failed") -> None:
    raise ContractError("NEBULAR080_PUBLIC_INPUT_ACQUISITION", reason)


def _hex(value: Any, width: int = 64) -> bool:
    return isinstance(value, str) and len(value) == width and set(value) <= _HEX64


def _positive(value: Any) -> bool:
    return type(value) is int and value > 0


def _safe_rel(value: Any) -> str:
    if (
        not isinstance(value, str)
        or not value
        or value.startswith("/")
        or "\\" in value
        or "\x00" in value
        or any(part in ("", ".", "..") for part in Path(value).parts)
    ):
        _fail("unsafe relative path")
    return value


def _regular(path: Path, *, limit: int) -> bytes:
    validate_ancestry_not_symlink(path)
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except OSError:
        _fail("required evidence is unavailable")
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_size <= 0 or info.st_size > limit:
            _fail("required evidence is not a bounded regular file")
        data = os.read(fd, info.st_size + 1)
        if len(data) != info.st_size:
            _fail("required evidence changed while reading")
        return data
    except OSError:
        _fail("required evidence changed while reading")
    finally:
        os.close(fd)


def _mkdir(path: Path) -> None:
    validate_ancestry_not_symlink(path.parent)
    try:
        path.mkdir(parents=True, mode=0o700, exist_ok=True)
    except OSError:
        _fail("acquisition output cannot be created")
    validate_ancestry_not_symlink(path)
    if not path.is_dir():
        _fail("acquisition output is not a directory")


def _write(path: Path, data: bytes) -> None:
    _mkdir(path.parent)
    validate_ancestry_not_symlink(path)
    if path.exists() or path.is_symlink():
        _fail("acquisition output collision")
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
    except OSError:
        _fail("acquisition output write failed")


def _copy_file(source: Path, destination: Path, *, expected_size: int, expected_sha256: str) -> None:
    validate_ancestry_not_symlink(source)
    _mkdir(destination.parent)
    if destination.exists() or destination.is_symlink():
        _fail("acquisition output collision")
    try:
        source_fd = os.open(source, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        destination_fd = os.open(
            destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600,
        )
    except OSError:
        _fail("acquisition source is unavailable")
    digest = hashlib.sha256()
    size = 0
    try:
        source_info = os.fstat(source_fd)
        if not stat.S_ISREG(source_info.st_mode) or source_info.st_size != expected_size:
            _fail("product asset metadata disagrees")
        while True:
            chunk = os.read(source_fd, 1024 * 1024)
            if not chunk:
                break
            size += len(chunk)
            if size > expected_size:
                _fail("product asset grew while copying")
            digest.update(chunk)
            os.write(destination_fd, chunk)
        os.fsync(destination_fd)
    except OSError:
        _fail("product asset copy failed")
    finally:
        os.close(source_fd)
        os.close(destination_fd)
    if size != expected_size or digest.hexdigest() != expected_sha256:
        try:
            destination.unlink()
        except OSError:
            pass
        _fail("product asset digest disagrees")


def _file_entry(path: str, data: bytes) -> dict[str, Any]:
    return {"path": _safe_rel(path), "size": len(data), "sha256": sha256(data)}


def _asset_rows(release_document: Mapping[str, Any]) -> dict[str, Mapping[str, Any]]:
    assets = release_document.get("assets")
    if not isinstance(assets, list):
        _fail("product release assets are malformed")
    rows: dict[str, Mapping[str, Any]] = {}
    for row in assets:
        if not isinstance(row, Mapping) or not isinstance(row.get("name"), str):
            _fail("product release assets are malformed")
        if row["name"] in rows:
            _fail("product release assets are duplicated")
        rows[row["name"]] = row
    return rows


def _validate_source_manifest(value: Mapping[str, Any]) -> dict[str, Any]:
    required = {"schema", "status", "product", "native_evidence"}
    if not isinstance(value, Mapping) or set(value) != required:
        _fail("source manifest shape is not closed")
    if value.get("schema") != SOURCE_SCHEMA or value.get("status") != "source-only; relay-public":
        _fail("source manifest status is not public-relay bound")
    product = value.get("product")
    if not isinstance(product, Mapping):
        _fail("source manifest product binding is malformed")
    product_keys = {
        "repository", "tag", "version", "repository_id", "release_id", "commit", "tree", "asset_ids",
    }
    if set(product) != product_keys or product.get("repository") != PRODUCT_REPOSITORY:
        _fail("source manifest product binding is malformed")
    if product.get("tag") != PRODUCT_TAG or product.get("version") != PRODUCT_VERSION:
        _fail("source manifest product binding is malformed")
    if not _positive(product.get("repository_id")) or not _positive(product.get("release_id")):
        _fail("source manifest product IDs must be positive")
    if not _hex(product.get("commit"), 40) or not _hex(product.get("tree"), 40):
        _fail("source manifest product coordinates are malformed")
    asset_ids = product.get("asset_ids")
    if not isinstance(asset_ids, Mapping) or not asset_ids or any(
        not isinstance(name, str) or not _positive(asset_id) for name, asset_id in asset_ids.items()
    ):
        _fail("source manifest asset IDs must be positive")
    native = value.get("native_evidence")
    if not isinstance(native, Mapping) or set(native) != {
        "schema", "archive", "inventory", "relay_asset_ids", "relay_release_id", "relay_tag",
    } or native.get("schema") != EVIDENCE_SCHEMA:
        _fail("native evidence manifest is not closed")
    if native.get("relay_release_id") != EVIDENCE_RELAY_RELEASE_ID or native.get("relay_tag") != EVIDENCE_RELAY_TAG:
        _fail("native evidence manifest release identity is not bound")
    relay_ids = native.get("relay_asset_ids")
    if (
        not isinstance(relay_ids, Mapping)
        or set(relay_ids) != {"archive", "inventory"}
        or any(relay_ids[key] != EVIDENCE_RELAY_ASSET_IDS[key] for key in relay_ids)
    ):
        _fail("native relay IDs are not bound to the public evidence release")
    for key, expected in (("archive", (EVIDENCE_ARCHIVE_NAME, EVIDENCE_ARCHIVE_BYTES, EVIDENCE_ARCHIVE_SHA256)),
                          ("inventory", (EVIDENCE_INVENTORY_NAME, EVIDENCE_INVENTORY_BYTES, EVIDENCE_INVENTORY_SHA256))):
        row = native.get(key)
        expected_keys = {"name", "bytes", "sha256", "sha512"} if key == "archive" else {
            "name", "bytes", "sha256",
        }
        if not isinstance(row, Mapping) or set(row) != expected_keys:
            _fail("native evidence manifest is not closed")
        if row.get("name") != expected[0] or row.get("bytes") != expected[1] or row.get("sha256") != expected[2]:
            _fail("native evidence manifest does not bind the held bytes")
        if key == "archive" and row.get("sha512") != EVIDENCE_ARCHIVE_SHA512:
            _fail("native evidence archive digest is not bound")
    return json.loads(canonical(value))


def resolve_clean_source_identity(
    repository: str | Path,
    *,
    commit: str,
    resolver: Any = None,
) -> dict[str, str]:
    """Obtain and normalize identity from the clean-checkout source owner."""
    from rs9.current_generation import CURRENT_GENERATION
    from rs9.nebular080_public_input_manifest import validate_runtime_source_identity

    if resolver is None:
        from rs9.hosted_custody import source_identity as resolver
    if not callable(resolver):
        _fail("clean source identity resolver is unavailable")
    try:
        value = resolver(repository, commit, generation=CURRENT_GENERATION)
    except ContractError:
        raise
    except Exception:
        _fail("clean source identity could not be obtained")
    try:
        return validate_runtime_source_identity(value)
    except (TypeError, ValueError, KeyError):
        _fail("clean source identity is not bound to the expected repository")


def _validate_tracked080_runtime(
    source_manifest: Mapping[str, Any],
    release_binding: Mapping[str, Any],
    repository: Path,
    source_identity: Mapping[str, Any] | None,
) -> dict[str, Any]:
    """Validate held rows, then bind a clean checkout identity in memory."""
    from rs9.nebular080_public_input_manifest import (
        bind_runtime_source_identity,
        validate_release_binding,
        validate_tracked080_manifest,
        validate_tracked_repository_rows,
    )

    try:
        checked_manifest = validate_tracked080_manifest(source_manifest)
        checked_binding = validate_release_binding(release_binding, checked_manifest)
        tracked_rows = validate_tracked_repository_rows(repository, checked_manifest)
    except (TypeError, ValueError, KeyError):
        _fail("tracked 0.8 manifest or release binding is not closed")
    if source_identity is None:
        _fail("clean source identity is required for tracked 0.8 inputs")
    try:
        bound = bind_runtime_source_identity(checked_manifest, checked_binding, source_identity)
    except (TypeError, ValueError, KeyError):
        _fail("clean source identity is not bound to tracked 0.8 inputs")
    product = bound["manifest"]["product_evidence"]
    return {
        **bound,
        "tracked_rows": tracked_rows,
        "product_manifest": {
            "repository": product["repository"],
            "tag": product["tag"],
            "version": "0.8.0",
            "release_id": product["release_id"],
            "commit": product["commit"],
            "tree": product["tree"],
        },
        "transport_spec": {
            "relay_asset_ids": {
                "archive": product["relay_archive_asset_id"],
                "inventory": product["relay_inventory_asset_id"],
            },
        },
    }


def _validate_native_transport(spec: Mapping[str, Any]) -> dict[str, Any]:
    if not isinstance(spec, Mapping) or set(spec) != {"archive", "inventory", "scope"}:
        _fail("native evidence transport shape is not closed")
    if spec.get("scope") not in {"local-fixture-only", "local-fixture-for-public-relay", "public-relay"}:
        _fail("native evidence transport scope is not closed")
    result: dict[str, Any] = {}
    for key, expected in (("archive", (EVIDENCE_ARCHIVE_NAME, EVIDENCE_ARCHIVE_BYTES, EVIDENCE_ARCHIVE_SHA256)),
                          ("inventory", (EVIDENCE_INVENTORY_NAME, EVIDENCE_INVENTORY_BYTES, EVIDENCE_INVENTORY_SHA256))):
        row = spec.get(key)
        required = {"name", "asset_id", "bytes", "sha256"} | ({"sha512"} if key == "archive" else set())
        if not isinstance(row, Mapping) or set(row) != required:
            _fail("native evidence transport shape is not closed")
        if (
            row.get("name") != expected[0]
            or row.get("bytes") != expected[1]
            or row.get("sha256") != expected[2]
            or not _positive(row.get("asset_id"))
        ):
            _fail("native evidence transport IDs or digests are invalid")
        if key == "archive" and row.get("sha512") != EVIDENCE_ARCHIVE_SHA512:
            _fail("native evidence archive digest is invalid")
        result[key] = dict(row)
    return result


class PublicRelayNativeEvidenceTransport:
    """Fetch the two fixed NativeRC evidence assets from the public relay.

    The caller supplies only the existing read-only public client; release tag,
    asset names, IDs, and digests are closed constants rather than URL options.
    """

    def __init__(self, client: Any) -> None:
        if not callable(getattr(client, "get", None)) or not callable(getattr(client, "json", None)):
            _fail("public relay client has no bounded GET method")
        self._client = client
        self._verified_release = False
        self.spec = MappingProxyType({
            "scope": "public-relay",
            "archive": MappingProxyType({
                "name": EVIDENCE_ARCHIVE_NAME,
                "asset_id": EVIDENCE_RELAY_ASSET_IDS["archive"],
                "bytes": EVIDENCE_ARCHIVE_BYTES,
                "sha256": EVIDENCE_ARCHIVE_SHA256,
                "sha512": EVIDENCE_ARCHIVE_SHA512,
            }),
            "inventory": MappingProxyType({
                "name": EVIDENCE_INVENTORY_NAME,
                "asset_id": EVIDENCE_RELAY_ASSET_IDS["inventory"],
                "bytes": EVIDENCE_INVENTORY_BYTES,
                "sha256": EVIDENCE_INVENTORY_SHA256,
            }),
        })

    def _verify_release(self) -> None:
        if self._verified_release:
            return
        url = f"https://api.github.com/repos/{PRODUCT_REPOSITORY}/releases/tags/{EVIDENCE_RELAY_TAG}"
        try:
            release = self._client.json(url, request_class="github-api", limit=2 * 1024 * 1024)
        except Exception:
            _fail("public relay release metadata transport failed")
        assets = release.get("assets") if isinstance(release, Mapping) else None
        if (
            not isinstance(release, Mapping)
            or release.get("id") != EVIDENCE_RELAY_RELEASE_ID
            or release.get("tag_name") != EVIDENCE_RELAY_TAG
            or release.get("draft") is not False
            or release.get("prerelease") is not True
            or not isinstance(assets, list)
        ):
            _fail("public relay release metadata disagrees")
        rows: dict[str, Mapping[str, Any]] = {}
        for asset in assets:
            if not isinstance(asset, Mapping) or not isinstance(asset.get("name"), str) or asset["name"] in rows:
                _fail("public relay release assets are malformed")
            rows[asset["name"]] = asset
        if set(rows) != {EVIDENCE_ARCHIVE_NAME, EVIDENCE_INVENTORY_NAME}:
            _fail("public relay release asset set disagrees")
        for key, row in (("archive", rows[EVIDENCE_ARCHIVE_NAME]), ("inventory", rows[EVIDENCE_INVENTORY_NAME])):
            expected = self.spec[key]
            if (
                row.get("id") != expected["asset_id"]
                or row.get("size") != expected["bytes"]
                or row.get("digest") != "sha256:" + expected["sha256"]
            ):
                _fail("public relay release asset metadata disagrees")
        self._verified_release = True

    def fetch(self, *, name: str, asset_id: int, expected_size: int, expected_sha256: str) -> bytes:
        self._verify_release()
        rows = {self.spec["archive"]["name"]: self.spec["archive"], self.spec["inventory"]["name"]: self.spec["inventory"]}
        row = rows.get(name)
        if row is None or asset_id != row["asset_id"] or expected_size != row["bytes"] or expected_sha256 != row["sha256"]:
            _fail("public relay asset identity disagrees")
        url = (
            f"https://github.com/{PRODUCT_REPOSITORY}/releases/download/"
            f"{EVIDENCE_RELAY_TAG}/{name}"
        )
        try:
            body = self._client.get(
                url, request_class="github-asset", limit=EVIDENCE_ARCHIVE_BYTES,
                expected_size=expected_size,
            )
        except Exception:
            _fail("public relay asset transport failed")
        if not isinstance(body, bytes) or sha256(body) != expected_sha256:
            _fail("public relay asset digest disagrees")
        if "sha512" in row and hashlib.sha512(body).hexdigest() != row["sha512"]:
            _fail("public relay archive digest disagrees")
        return body


def _fetch_native(transport: Any, row: Mapping[str, Any]) -> bytes:
    fetch = getattr(transport, "fetch", None)
    if not callable(fetch):
        _fail("native evidence transport has no bounded fetch method")
    try:
        data = fetch(
            name=row["name"], asset_id=row["asset_id"],
            expected_size=row["bytes"], expected_sha256=row["sha256"],
        )
    except Exception:
        _fail("native evidence transport failed")
    if not isinstance(data, bytes) or len(data) != row["bytes"] or sha256(data) != row["sha256"]:
        _fail("native evidence transport bytes disagree")
    if "sha512" in row and hashlib.sha512(data).hexdigest() != row["sha512"]:
        _fail("native evidence archive digest disagrees")
    return data


def _inventory_rows(inventory_data: bytes) -> dict[str, Mapping[str, Any]]:
    if len(inventory_data) != EVIDENCE_INVENTORY_BYTES or sha256(inventory_data) != EVIDENCE_INVENTORY_SHA256:
        _fail("native evidence inventory digest disagrees")
    try:
        value = json.loads(inventory_data)
    except (TypeError, ValueError, UnicodeError):
        _fail("native evidence inventory is malformed")
    if not isinstance(value, Mapping) or value.get("schema") != EVIDENCE_SCHEMA:
        _fail("native evidence inventory is malformed")
    archive = value.get("archive")
    if (
        not isinstance(archive, Mapping)
        or archive.get("archive_bytes") != EVIDENCE_ARCHIVE_BYTES
        or archive.get("file_count") != 68
        or archive.get("source_bytes") != EVIDENCE_SOURCE_BYTES
        or archive.get("sha256") != EVIDENCE_ARCHIVE_SHA256
        or archive.get("sha512") != EVIDENCE_ARCHIVE_SHA512
    ):
        _fail("native evidence inventory archive binding is malformed")
    files = value.get("files")
    if not isinstance(files, list) or len(files) != 68:
        _fail("native evidence inventory row count is not fixed")
    rows: dict[str, Mapping[str, Any]] = {}
    total = 0
    for row in files:
        if not isinstance(row, Mapping) or set(row) != {"bytes", "path", "role", "sha256"}:
            _fail("native evidence inventory row is malformed")
        path = _safe_rel(row.get("path"))
        if path in rows or type(row.get("bytes")) is not int or row["bytes"] <= 0 or not _hex(row.get("sha256")):
            _fail("native evidence inventory row is malformed")
        rows[path] = dict(row)
        total += row["bytes"]
    if total != EVIDENCE_SOURCE_BYTES:
        _fail("native evidence inventory byte total disagrees")
    return rows


def _archive_rows(archive_data: bytes, inventory: Mapping[str, Mapping[str, Any]]) -> dict[str, bytes]:
    if len(archive_data) != EVIDENCE_ARCHIVE_BYTES or sha256(archive_data) != EVIDENCE_ARCHIVE_SHA256:
        _fail("native evidence archive digest disagrees")
    extracted: dict[str, bytes] = {}
    try:
        with tarfile.open(fileobj=io.BytesIO(archive_data), mode="r:gz") as archive:
            members = archive.getmembers()
            if len(members) != len(inventory):
                _fail("native evidence archive member count disagrees")
            for member in members:
                path = _safe_rel(member.name)
                if path in extracted or path not in inventory or not member.isreg() or member.pax_headers:
                    _fail("native evidence archive member is not fixed")
                stream = archive.extractfile(member)
                if stream is None:
                    _fail("native evidence archive member is unreadable")
                body = stream.read(int(inventory[path]["bytes"]) + 1)
                if len(body) != inventory[path]["bytes"] or sha256(body) != inventory[path]["sha256"]:
                    _fail("native evidence archive row digest disagrees")
                extracted[path] = body
    except (OSError, EOFError, tarfile.TarError, ValueError):
        _fail("native evidence archive is malformed")
    if set(extracted) != set(inventory):
        _fail("native evidence archive row set disagrees")
    return extracted


def _smoke_spec(
    target: str,
    source: Mapping[str, str],
    archive_data: bytes,
    authority_data: bytes,
    source_members: Mapping[str, tuple[int, str, str, int]],
    evidence_files: dict[str, dict[str, Any]],
    raw_root: Path,
) -> dict[str, Any]:
    from rs9.nebular080_smoke_support import _closure_digest, _verify_source_authority

    _verify_source_authority(
        authority_data,
        expected_size=len(authority_data),
        expected_sha256=sha256(authority_data),
        expected_identity=source["authority_identity"],
    )
    root = f"smoke-support/{target}"
    archive_name = Path(EVIDENCE_ARCHIVE_NAME.replace("native-evidence-run-42418673472-attempt-1", "source")).name
    authority_name = "nebular-compiled-public-build-source-authority-v0.8.0.json"
    archive_path = f"source/{EVIDENCE_ARCHIVE_NAME.replace('nebular-v0.8.0-native-evidence-run-42418673472-attempt-1.tar.gz', 'theme-forge-nebular-fusion-v0.8.0-source.tar.gz')}"
    authority_path = f"source/{authority_name}"
    archive_evidence_path = "source/theme-forge-nebular-fusion-v0.8.0-source.tar.gz"
    authority_evidence_path = "source/nebular-compiled-public-build-source-authority-v0.8.0.json"
    _stage_raw(raw_root / root / archive_path, archive_data)
    _stage_raw(raw_root / root / authority_path, authority_data)
    evidence_files[archive_evidence_path] = _stage_evidence(evidence_files, archive_evidence_path, archive_data)
    evidence_files[authority_evidence_path] = _stage_evidence(evidence_files, authority_evidence_path, authority_data)
    files: list[dict[str, Any]] = []
    selected_paths = {f"tools/{name}" for name in _SOURCE_TOOLS} | set(_SOURCE_FIXTURES)
    for path in sorted(selected_paths):
        size, digest, blob, mode = source_members[path]
        body = _source_member_bytes(archive_data, path, size)
        if len(body) != size or sha256(body) != digest:
            _fail("source closure member changed")
        raw_path = raw_root / root / path
        _stage_raw(raw_path, body)
        evidence_path = f"smoke-source/{path}"
        evidence_files[evidence_path] = _stage_evidence(evidence_files, evidence_path, body)
        role = "application-smoke" if path == "tools/native-rc-smoke.mjs" else (
            "fixture" if path in _SOURCE_FIXTURES else "verifier-module"
        )
        files.append({
            "path": path, "size": size, "sha256": digest, "blob": blob,
            "role": role, "evidence_path": evidence_path,
        })
    spec = {
        "schema": "rs9.nebular080-smoke-support.v1",
        "target": target,
        "source": dict(source),
        "root": root,
        "tool_root": "tools",
        "fixture_root": "docs/examples/v0.4/brand-system/core-minimal",
        "files": files,
        "source_binding": {
            "archive": {"path": archive_path, "size": len(archive_data), "sha256": sha256(archive_data), "evidence_path": archive_evidence_path},
            "authority": {"path": authority_path, "size": len(authority_data), "sha256": sha256(authority_data), "evidence_path": authority_evidence_path},
        },
    }
    spec["closure_sha256"] = _closure_digest(spec)
    return spec


def _source_member_bytes(archive_data: bytes, path: str, size: int) -> bytes:
    try:
        with tarfile.open(fileobj=io.BytesIO(archive_data), mode="r:gz") as archive:
            member = archive.getmember(path)
            stream = archive.extractfile(member)
            if stream is None:
                _fail("source closure member is unavailable")
            body = stream.read(size + 1)
            if len(body) != size:
                _fail("source closure member size disagrees")
            return body
    except (KeyError, OSError, EOFError, tarfile.TarError):
        _fail("source closure member is unavailable")
    raise AssertionError("unreachable")


def _stage_raw(path: Path, data: bytes) -> None:
    _write(path, data)


def _stage_evidence(existing: Mapping[str, Any], path: str, data: bytes) -> dict[str, Any]:
    # The caller has already chosen the fresh evidence root; this helper only
    # returns the descriptor.  Actual bytes are written by _stage_evidence_at.
    return _file_entry(path, data)


def _stage_evidence_at(root: Path, existing: dict[str, dict[str, Any]], path: str, data: bytes) -> None:
    path = _safe_rel(path)
    prior = existing.get(path)
    entry = _file_entry(path, data)
    if prior is not None:
        if prior != entry:
            _fail("evidence path was assigned two byte identities")
        destination = root / path
        if destination.is_file() and not destination.is_symlink():
            current = _regular(destination, limit=max(1, entry["size"]))
            if _file_entry(path, current) != entry:
                _fail("evidence path changed after staging")
            return
    _write(root / path, data)
    existing[path] = entry


def _binding(value: Mapping[str, Any], source: Mapping[str, str]) -> dict[str, Any]:
    required = {
        "schema", "release", "application_version", "distribution_version", "repository", "tag",
        "bootstrap_path", "expectations_path", "profile_path", "status", "lineage", "provenance", "expected",
    }
    if not isinstance(value, Mapping) or set(value) != required:
        _fail("release binding is not closed")
    if (
        value.get("schema") != "rs9.nebular080-release-binding.v1alpha1"
        or value.get("release") != PRODUCT_VERSION
        or value.get("application_version") != PRODUCT_VERSION
        or value.get("distribution_version") != PRODUCT_VERSION
        or value.get("repository") != source["repository"]
        or value.get("tag") != PRODUCT_TAG
        or value.get("status") != "ready"
        or value.get("lineage") != {"mode": "direct-tag-provenance-equality", "requires_historical_author_rewrite": False}
    ):
        _fail("release binding does not match source")
    for field in ("bootstrap_path", "expectations_path", "profile_path"):
        _safe_rel(value.get(field))
    if value["profile_path"] != "operators/tf-pypi/theme-forge-nebular-fusion-0.8.0-gate1.json":
        _fail("release binding profile path is not fixed")
    provenance = value.get("provenance")
    if not isinstance(provenance, Mapping) or set(provenance) != {"path", "commit_field", "tree_field"}:
        _fail("release binding provenance is malformed")
    expected = value.get("expected")
    if (
        not isinstance(expected, Mapping)
        or set(expected) != {"repository_id", "release_id", "tag_commit", "tag_tree", "bootstrap_sha256", "expectations_sha256"}
        or not _positive(expected.get("repository_id"))
        or not _positive(expected.get("release_id"))
        or expected.get("tag_commit") != source["commit"]
        or expected.get("tag_tree") != source["tree"]
        or not _hex(expected.get("bootstrap_sha256"))
        or not _hex(expected.get("expectations_sha256"))
    ):
        _fail("release binding expected identities are malformed")
    return json.loads(canonical(value))


def _binding_from_capture(
    capture: Any,
    source: Mapping[str, str],
    release: Mapping[str, Any],
    tracked_rows: Mapping[str, Mapping[str, Any]],
) -> dict[str, Any]:
    """Project authenticated product facts into the legacy descriptor ABI."""
    record = getattr(capture, "record", None)
    repository = record.get("repository") if isinstance(record, Mapping) else None
    if (
        not isinstance(repository, Mapping)
        or not _positive(repository.get("id"))
        or not isinstance(tracked_rows, Mapping)
    ):
        _fail("authenticated product repository identity is unavailable")
    try:
        value = {
            "schema": "rs9.nebular080-release-binding.v1alpha1",
            "release": PRODUCT_VERSION,
            "application_version": PRODUCT_VERSION,
            "distribution_version": PRODUCT_VERSION,
            "repository": source["repository"],
            "tag": PRODUCT_TAG,
            "bootstrap_path": tracked_rows["bootstrap"]["path"],
            "expectations_path": tracked_rows["expectations"]["path"],
            "profile_path": "operators/tf-pypi/theme-forge-nebular-fusion-0.8.0-gate1.json",
            "status": "ready",
            "lineage": {
                "mode": "direct-tag-provenance-equality",
                "requires_historical_author_rewrite": False,
            },
            "provenance": {
                "path": "PROVENANCE.json",
                "commit_field": "tagCommit",
                "tree_field": "tagTree",
            },
            "expected": {
                "repository_id": repository["id"],
                "release_id": release["release_id"],
                "tag_commit": source["commit"],
                "tag_tree": source["tree"],
                "bootstrap_sha256": tracked_rows["bootstrap"]["sha256"],
                "expectations_sha256": tracked_rows["expectations"]["sha256"],
            },
        }
    except (KeyError, TypeError):
        _fail("authenticated product binding inputs are unavailable")
    return _binding(value, source)


def _source_files(source_archive: bytes) -> dict[str, bytes]:
    result: dict[str, bytes] = {}
    try:
        with tarfile.open(fileobj=io.BytesIO(source_archive), mode="r:gz") as archive:
            for name in ("README.md", "LICENSE", "NOTICE", "COMMERCIAL-LICENSE.md"):
                member = archive.getmember(name)
                stream = archive.extractfile(member)
                if stream is None:
                    _fail("source legal/readme member is unavailable")
                result[name] = stream.read(2 * 1024 * 1024 + 1)
                if len(result[name]) > 2 * 1024 * 1024:
                    _fail("source legal/readme member exceeds bound")
    except (KeyError, OSError, EOFError, tarfile.TarError):
        _fail("source legal/readme member is unavailable")
    return result


def acquire_public_inputs_080(
    output: str | Path,
    *,
    repository: str | Path,
    source_manifest: Mapping[str, Any],
    release_client: Any,
    native_transport: Any,
    release_binding: Mapping[str, Any],
    source_identity: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Acquire and stage a complete held 0.8 descriptor in a fresh root.

    ``release_client`` must expose the existing read-only ``json``/``get``
    interface.  ``native_transport`` exposes only ``fetch`` and is passed
    positive fixture or future relay IDs by the caller; missing, zero, and
    ``None`` IDs are rejected before any evidence bytes are accepted.
    """
    repository_path = Path(repository)
    tracked_context: dict[str, Any] | None = None
    if (
        isinstance(source_manifest, Mapping)
        and source_manifest.get("schema") == "rs9.tracked080-public-input-manifest.v1"
    ):
        tracked_context = _validate_tracked080_runtime(
            source_manifest,
            release_binding,
            repository_path,
            source_identity,
        )

    from rs9.nebular080_product_capture import capture_product_release, load_held_product_capture
    from rs9.nebular080_product_native import _descriptor_names, replay_descriptor_native
    from rs9.nebular080_smoke_support import _source_archive_members
    from rs9.nebular080_universal_consumer import authenticated_product_release, authenticated_product_source
    from rs9.nebular080_public_inputs import stage_native_ci_evidence, validate_qualification_inputs_descriptor
    from rs9.nebular080_publication_coordinates import (
        QUALIFICATION_INPUT_PHASE_PREP, QUALIFICATION_INPUTS_SCHEMA, SYSTEM_WEBKIT_INPUT_SCHEMA,
        SYSTEM_WEBKIT_PROFILE_ID, WORKFLOW,
    )

    if tracked_context is not None:
        manifest = tracked_context["manifest"]
        transport_spec = tracked_context["transport_spec"]
        product_manifest = tracked_context["product_manifest"]
        binding: dict[str, Any] | None = None
    else:
        manifest = _validate_source_manifest(source_manifest)
        transport_spec = manifest["native_evidence"]
        product_manifest = manifest["product"]
        binding = _binding(release_binding, {
            "repository": product_manifest["repository"],
            "commit": product_manifest["commit"],
            "tree": product_manifest["tree"],
        })
    transport_rows = _validate_native_transport(native_transport.spec)
    for key in ("archive", "inventory"):
        if transport_rows[key]["asset_id"] != transport_spec["relay_asset_ids"][key]:
            _fail("native transport asset ID disagrees with the source manifest")
    output_path = Path(output)
    if not output_path.is_absolute() or output_path.exists() or output_path.is_symlink():
        _fail("acquisition output must be a fresh absolute path")
    validate_ancestry_not_symlink(repository_path)
    _mkdir(output_path)
    identity = os.lstat(output_path)
    try:
        capture_product_release(output_path, client=release_client)
        capture = load_held_product_capture(output_path)
        source = authenticated_product_source(capture)
        release = authenticated_product_release(capture)
        if (
            source["repository"] != product_manifest["repository"]
            or source["commit"] != product_manifest["commit"]
            or source["tree"] != product_manifest["tree"]
            or release["release_id"] != product_manifest["release_id"]
            or release["tag"] != product_manifest["tag"]
        ):
            _fail("authenticated product capture disagrees with source manifest")
        if binding is None:
            binding = _binding_from_capture(
                capture,
                source,
                release,
                tracked_context["tracked_rows"],
            )
        if release["release_id"] != binding["expected"]["release_id"]:
            _fail("release binding disagrees with authenticated capture")
        if source["commit"] != binding["expected"]["tag_commit"] or source["tree"] != binding["expected"]["tag_tree"]:
            _fail("release binding disagrees with authenticated source")

        capture_api_root = output_path / "product-capture" / "evidence" / "api"
        release_document = json.loads(_regular(capture_api_root / "release.json", limit=4 * 1024 * 1024))
        asset_rows = _asset_rows(release_document)
        npm_name = "knowledge-forge-ai-theme-forge-nebular-fusion-0.8.0.tgz"
        npm_row = asset_rows.get(npm_name)
        if not isinstance(npm_row, Mapping) or not _positive(npm_row.get("id")) or not _positive(npm_row.get("size")):
            _fail("product npm asset metadata is unavailable")
        npm_digest = npm_row.get("digest")
        if not isinstance(npm_digest, str) or not npm_digest.startswith("sha256:") or not _hex(npm_digest[7:]):
            _fail("product npm asset digest is unavailable")
        try:
            npm_body = release_client.get(
                str(npm_row.get("browser_download_url")), request_class="github-asset",
                limit=int(npm_row["size"]), expected_size=int(npm_row["size"]),
            )
        except Exception:
            _fail("product npm asset transport failed")
        if not isinstance(npm_body, bytes) or len(npm_body) != npm_row["size"] or sha256(npm_body) != npm_digest[7:]:
            _fail("product npm asset digest disagrees")

        archive_data = _fetch_native(native_transport, transport_rows["archive"])
        inventory_data = _fetch_native(native_transport, transport_rows["inventory"])
        inventory = _inventory_rows(inventory_data)
        rows = _archive_rows(archive_data, inventory)
        if set(rows) != set(_descriptor_names()):
            _fail("native evidence rows do not equal the fixed descriptor set")

        evidence_root = output_path / "evidence" / "public-release"
        _mkdir(evidence_root)
        evidence_files: dict[str, dict[str, Any]] = {}
        for api_name in ("release.json", "repository.json", "ref.json", "commit.json", "tree.json"):
            body = _regular(capture_api_root / api_name, limit=4 * 1024 * 1024)
            _stage_evidence_at(evidence_root, evidence_files, f"api/{api_name}", body)
        checksums = _regular(output_path / "product-capture/evidence/assets/SHA256SUMS", limit=4 * 1024 * 1024)
        provenance = _regular(output_path / "product-capture/evidence/assets/nebular-v0.8.0-native-ci-provenance.json", limit=2 * 1024 * 1024)
        source_archive = _regular(output_path / "product-capture/evidence/assets/theme-forge-nebular-fusion-v0.8.0-source.tar.gz", limit=2 * 1024 * 1024 * 1024)
        authority = _regular(output_path / "product-capture/evidence/assets/nebular-compiled-public-build-source-authority-v0.8.0.json", limit=2 * 1024 * 1024)
        source_files = _source_files(source_archive)
        _stage_evidence_at(evidence_root, evidence_files, "assets/SHA256SUMS", checksums)
        _stage_evidence_at(evidence_root, evidence_files, "assets/PROVENANCE.json", provenance)
        _stage_evidence_at(evidence_root, evidence_files, "source/theme-forge-nebular-fusion-v0.8.0-source.tar.gz", source_archive)
        _stage_evidence_at(evidence_root, evidence_files, "source/nebular-compiled-public-build-source-authority-v0.8.0.json", authority)
        _stage_evidence_at(evidence_root, evidence_files, "source/LICENSE", source_files["LICENSE"])
        _stage_evidence_at(evidence_root, evidence_files, "source/NOTICE", source_files["NOTICE"])
        npm_meta = canonical({
            "id": npm_row["id"], "name": npm_row["name"], "size": npm_row["size"],
            "digest": npm_row["digest"], "browser_download_url": npm_row["browser_download_url"],
        })
        _stage_evidence_at(evidence_root, evidence_files, "npm/metadata.json", npm_meta)
        _stage_evidence_at(evidence_root, evidence_files, "npm/package.tgz", npm_body)
        for path, body in sorted(rows.items()):
            evidence_files[f"native-ci/{path}"] = _file_entry(f"native-ci/{path}", body)

        source_members = _source_archive_members(
            source_archive, expected_size=len(source_archive), expected_sha256=sha256(source_archive),
        )
        if set(source_members) & {"tools/"}:
            _fail("source archive identity is malformed")
        raw_root = output_path / "raw-release"
        _mkdir(raw_root)
        support_specs: dict[str, dict[str, Any]] = {}
        for target in TARGETS:
            support_specs[target] = _smoke_spec(
                target, source, source_archive, authority, source_members,
                evidence_files, raw_root,
            )
        # _smoke_spec returns descriptors; its evidence writes are performed
        # explicitly here after the descriptor paths have been chosen.
        for target, support in support_specs.items():
            for ref in support["source_binding"].values():
                _stage_evidence_at(evidence_root, evidence_files, ref["evidence_path"], source_archive if ref["path"].endswith(".tar.gz") else authority)
            for item in support["files"]:
                body = _source_member_bytes(source_archive, item["path"], item["size"])
                _stage_evidence_at(evidence_root, evidence_files, item["evidence_path"], body)

        binding_paths = (binding["bootstrap_path"], binding["expectations_path"], binding["profile_path"])
        for path in binding_paths:
            validate_ancestry_not_symlink(repository_path / path)
        payload_root = raw_root / "payloads"
        _mkdir(payload_root)
        targets: dict[str, Any] = {}
        payload_rows = {row["name"]: row for row in capture.record["assets"] if row.get("role") == "payload"}
        readme_path = "source/README.md"
        provenance_path = "source/PROVENANCE.json"
        for name, body in source_files.items():
            _stage_raw(raw_root / "source" / name, body)
        _stage_raw(raw_root / provenance_path, provenance)
        for target in TARGETS:
            lane = _LANE_BY_TARGET[target]
            payload = next((row for row in payload_rows.values() if row["name"].endswith({
                "darwin-arm64": "aarch64-apple-darwin.app.tar.gz",
                "linux-arm64-gnu": "aarch64-unknown-linux-gnu.tar.gz",
                "linux-x64-gnu": "x86_64-unknown-linux-gnu.tar.gz",
            }[target])), None)
            if payload is None:
                _fail("product payload asset is missing")
            payload_name = str(payload["name"])
            payload_path = f"payloads/{payload_name}"
            _copy_file(capture.archives[target], raw_root / payload_path, expected_size=int(payload["size"]), expected_sha256=str(payload["sha256"]))
            _stage_evidence_at(evidence_root, evidence_files, payload_path, _regular(raw_root / payload_path, limit=2 * 1024 * 1024 * 1024))
            record_body = rows[f"{lane}/package-record.json"]
            manifest_body = canonical(capture.manifests[target])
            manifest_path = f"manifests/{target}.json"
            _stage_raw(raw_root / manifest_path, manifest_body)
            _stage_evidence_at(evidence_root, evidence_files, manifest_path, manifest_body)
            record_path = f"native-ci/{lane}/package-record.json"
            _stage_raw(raw_root / record_path, record_body)
            targets[target] = {
                "schema": "rs9.tf-pypi-nebular080-raw-release-handoff.v1",
                "target": target,
                "record": _file_entry(record_path, record_body),
                "readme": _file_entry(readme_path, source_files["README.md"]),
                "legal_files": {
                    name: _file_entry(f"source/{name}", source_files[name])
                    for name in ("LICENSE", "NOTICE", "COMMERCIAL-LICENSE.md")
                },
                "payload": _file_entry(payload_path, _regular(raw_root / payload_path, limit=2 * 1024 * 1024 * 1024)),
                "manifest": _file_entry(manifest_path, manifest_body),
                "provenance": _file_entry(provenance_path, provenance),
                "native_consumer": {target: {"smoke_support": support_specs[target]}},
                "product_source": source,
            }
            _stage_evidence_at(evidence_root, evidence_files, readme_path, source_files["README.md"])
            _stage_evidence_at(evidence_root, evidence_files, provenance_path, provenance)
            _stage_evidence_at(evidence_root, evidence_files, f"source/COMMERCIAL-LICENSE.md", source_files["COMMERCIAL-LICENSE.md"])
        descriptor = {
            "schema": QUALIFICATION_INPUTS_SCHEMA,
            "project": "theme-forge-nebular-fusion",
            "version": PRODUCT_VERSION,
            "distribution_version": PRODUCT_VERSION,
            "workflow": WORKFLOW,
            "status": "ready",
            "system_webkit": {
                "schema": SYSTEM_WEBKIT_INPUT_SCHEMA,
                "origin_kind": "public-in-run",
                "profile_id": SYSTEM_WEBKIT_PROFILE_ID,
            },
            "upstream_origin": {
                "repository": PRODUCT_REPOSITORY,
                "tag": PRODUCT_TAG,
                "release_url": f"https://github.com/{PRODUCT_REPOSITORY}/releases/tag/{PRODUCT_TAG}",
                "api_release_url": f"https://api.github.com/repos/{PRODUCT_REPOSITORY}/releases/tags/{PRODUCT_TAG}",
            },
            "release_binding": binding,
            "release_binding_sha256": sha256(canonical(binding)),
            "evidence": {"source_root": "evidence/public-release", "files": evidence_files},
            "raw_release": {"source_root": "raw-release", "targets": targets},
        }
        with tempfile.TemporaryDirectory(
            dir=str(output_path.parent), prefix="nebular080-native-capsule-",
        ) as capsule_dir:
            capsule_root = Path(capsule_dir)
            for relative, body in sorted(rows.items()):
                _write(capsule_root / relative, body)
            stage_native_ci_evidence(capsule_root, output_path, descriptor)
        checked = validate_qualification_inputs_descriptor(
            descriptor, repository=repository_path, phase=QUALIFICATION_INPUT_PHASE_PREP,
            inrun_root=output_path, product_capture=capture,
        )
        descriptor_bytes = canonical(checked)
        descriptor_path = output_path / "qualification-inputs-prep.json"
        _write(descriptor_path, descriptor_bytes)
        replay_descriptor_native(descriptor, output_path, capture, repository=repository_path)
        receipt = {
            "schema": "rs9.tf-pypi-nebular080-public-inputs-preparation.v2",
            "status": "held",
            "source_manifest": {"schema": manifest["schema"], "sha256": sha256(canonical(manifest))},
            "product_capture": {"release_id": release["release_id"], "commit": source["commit"], "tree": source["tree"]},
            "descriptor": {"path": "qualification-inputs-prep.json", "bytes": len(descriptor_bytes), "sha256": sha256(descriptor_bytes)},
            "native_evidence": {"archive_sha256": sha256(archive_data), "inventory_sha256": sha256(inventory_data), "file_count": len(rows), "bytes": sum(len(body) for body in rows.values())},
            "limits": {
                "native_execution": False,
                "network_acquisition": native_transport.spec["scope"] == "public-relay",
                "publication": False,
            },
        }
        if tracked_context is not None:
            receipt["rs9_source"] = tracked_context["source"]
            receipt["tracked_inputs"] = tracked_context["tracked_rows"]
        _write(output_path / "public-inputs-preparation.json", canonical(receipt))
        return receipt
    except Exception:
        try:
            current = os.lstat(output_path)
            if (current.st_dev, current.st_ino, current.st_uid) == (identity.st_dev, identity.st_ino, identity.st_uid):
                shutil.rmtree(output_path)
        except OSError:
            pass
        raise


__all__ = [
    "PublicRelayNativeEvidenceTransport", "acquire_public_inputs_080",
    "resolve_clean_source_identity",
]
