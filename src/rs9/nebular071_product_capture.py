"""Producer and held-custody loader for the 0.7.1 product release capture.

``prepare-public-inputs-071`` materializes ``<output>/product-capture`` in the
same ``tfnf-071-public-inputs`` root as ``qualification-inputs.json``.
Downstream qualification and publication commands load and re-authenticate the
held capture from that single artifact root without a ninth workflow artifact
or out-of-band ``--product-selection`` / ``--product-evidence`` flags.
"""

from __future__ import annotations

from collections.abc import Mapping
import hashlib
import os
from pathlib import Path
import shutil
import stat
from typing import Any

from rs9.tf_pypi_archive import AdmissionError
from rs9.errors import ContractError
from rs9.github import PublicClient
from rs9.release_core import (
    ReleaseCapture,
    authenticate_release,
    authenticated_record_hash,
    capture_release,
)
from rs9.scratch import canonical
from rs9.materialize import validate_ancestry_not_symlink


CAPTURE_DIR = "product-capture"
SELECTION_NAME = "selection.json"
EVIDENCE_DIR = "evidence"
PRODUCT_REPOSITORY = "Knowledge-Forge-AI/theme-forge-nebular-fusion"
PRODUCT_VERSION = "0.7.1"
PRODUCT_TAG = "v0.7.1"
PRODUCT_ASSET_LIMIT_BYTES = 300 * 1024 * 1024

RAW_PAYLOAD_TRIPLES = {
    "darwin-arm64": "aarch64-apple-darwin.app",
    "linux-arm64-gnu": "aarch64-unknown-linux-gnu",
    "linux-x64-gnu": "x86_64-unknown-linux-gnu",
}

API_FILE_NAMES = frozenset({
    "repository.json",
    "release.json",
    "ref.json",
    "tags.json",
    "commit.json",
    "tree.json",
})

EVIDENCE_ASSETS = (
    ("source-archive", "theme-forge-nebular-fusion-v0.7.1-source.tar.gz"),
    ("source-authority", "nebular-compiled-public-build-source-authority-v0.7.1.json"),
    ("native-provenance", "nebular-v0.7.1-native-ci-provenance.json"),
)


def _fail(message: str = "Held product release capture is missing or invalid") -> None:
    raise ContractError("NEBULAR_UNIVERSAL_PRODUCT_CAPTURE", message)


def product_selection() -> dict[str, Any]:
    """Return the closed v0.7.1 product release-selection contract."""
    return {
        "schema": "rs9.release-selection.v1alpha1",
        "repository": PRODUCT_REPOSITORY,
        "tag": PRODUCT_TAG,
        "prerelease": "reject",
        "checksums": "SHA256SUMS",
        "source_paths": [],
        "limits": {"asset_bytes": PRODUCT_ASSET_LIMIT_BYTES},
        "payload_assets": [
            {
                "id": target,
                "name": f"theme-forge-nebular-fusion-v0.7.1-{triple}.tar.gz",
                "format": "tar.gz",
                "commands": {},
                "launchers": {},
                "platforms": [target],
                "checksum_covered": True,
            }
            for target, triple in sorted(RAW_PAYLOAD_TRIPLES.items())
        ],
        "evidence_assets": [
            {
                "role": role,
                "name": name,
                "checksum_covered": False,
            }
            for role, name in EVIDENCE_ASSETS
        ],
    }


def expected_asset_names() -> frozenset[str]:
    """Return the exact 7 asset filenames materialized in product-capture."""
    payload_names = {
        f"theme-forge-nebular-fusion-v0.7.1-{triple}.tar.gz"
        for triple in RAW_PAYLOAD_TRIPLES.values()
    }
    evidence_names = {name for _role, name in EVIDENCE_ASSETS}
    return frozenset({*payload_names, *evidence_names, "SHA256SUMS"})


def public_client(
    *,
    opener: Any = None,
    environ: Mapping[str, str] | None = None,
) -> PublicClient:
    """Construct a read-only GitHub client honoring RS9_GITHUB_READ_TOKEN."""
    env = os.environ if environ is None else environ
    raw_token = env.get("RS9_GITHUB_READ_TOKEN")
    token = raw_token.strip() if isinstance(raw_token, str) and raw_token.strip() else None
    return PublicClient(opener=opener, api_token=token)


def _read_regular_nofollow(path: Path, limit: int) -> bytes:
    validate_ancestry_not_symlink(path)
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    except OSError:
        _fail()
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_size <= 0 or info.st_size > limit:
            _fail()
        chunks: list[bytes] = []
        remaining = info.st_size + 1
        while remaining > 0:
            chunk = os.read(fd, min(1024 * 1024, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        data = b"".join(chunks)
        if len(data) != info.st_size:
            _fail()
        return data
    except OSError:
        _fail()
    finally:
        os.close(fd)


def _require_real_dir(path: Path) -> Path:
    validate_ancestry_not_symlink(path)
    try:
        info = os.lstat(path)
    except OSError:
        _fail()
    if not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode):
        _fail()
    return path


def _require_exact_entries(directory: Path, expected: set[str] | frozenset[str]) -> None:
    _require_real_dir(directory)
    try:
        names = {item.name for item in directory.iterdir()}
    except OSError:
        _fail()
    if names != set(expected):
        _fail()


def _require_regular_children(directory: Path, expected: set[str] | frozenset[str]) -> None:
    _require_exact_entries(directory, expected)
    for name in sorted(expected):
        child = directory / name
        validate_ancestry_not_symlink(child)
        try:
            info = os.lstat(child)
        except OSError:
            _fail()
        if not stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode) or info.st_size <= 0:
            _fail()


def _write_exclusive(path: Path, data: bytes) -> None:
    validate_ancestry_not_symlink(path)
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
    except OSError:
        _fail("Could not write held product release selection")


def _cleanup_dir(path: Path, identity: tuple[int, int, int]) -> None:
    try:
        info = os.lstat(path)
        if (
            stat.S_ISDIR(info.st_mode)
            and not stat.S_ISLNK(info.st_mode)
            and (info.st_dev, info.st_ino, info.st_uid) == identity
        ):
            shutil.rmtree(path)
    except OSError:
        pass


class _TransportReuseClient:
    """Reuse digest-verified payload bytes already materialized in the output root."""

    def __init__(
        self,
        client: Any,
        base: Path,
        transport: Mapping[str, Any] | None,
    ) -> None:
        self._client = client
        self._base = base
        client_receipts = getattr(client, "receipts", None)
        self.receipts: list[dict[str, Any]] = (
            client_receipts if isinstance(client_receipts, list) else []
        )
        self._reusable: dict[str, Mapping[str, Any]] = {}
        payloads = transport.get("payloads") if isinstance(transport, Mapping) else None
        if isinstance(payloads, list):
            for row in payloads:
                if (
                    isinstance(row, Mapping)
                    and isinstance(row.get("name"), str)
                    and row["name"].endswith(".tar.gz")
                    and isinstance(row.get("path"), str)
                    and type(row.get("bytes")) is int
                    and isinstance(row.get("sha256"), str)
                ):
                    url = (
                        f"https://github.com/{PRODUCT_REPOSITORY}"
                        f"/releases/download/{PRODUCT_TAG}/{row['name']}"
                    )
                    self._reusable[url] = row

    def json(self, url: str, **kwargs: Any) -> Any:
        return self._client.json(url, **kwargs)

    def get(
        self,
        url: str,
        *,
        request_class: str = "github-asset",
        limit: int = PRODUCT_ASSET_LIMIT_BYTES,
        expected_size: int | None = None,
        **kwargs: Any,
    ) -> bytes:
        row = self._reusable.get(url)
        if row is not None:
            if expected_size is not None and row["bytes"] != expected_size:
                _fail("Transport payload size disagrees with release asset metadata")
            data = _read_regular_nofollow(self._base / str(row["path"]), limit)
            if (
                len(data) != row["bytes"]
                or hashlib.sha256(data).hexdigest() != row["sha256"]
            ):
                _fail("Transport payload bytes disagree with transport receipt")
            self.receipts.append({
                "url": url,
                "final_url": url,
                "status": 200,
                "operation": request_class,
                "size": len(data),
                "sha256": row["sha256"],
                "reused_transport_path": row["path"],
            })
            return data
        return self._client.get(
            url,
            request_class=request_class,
            limit=limit,
            expected_size=expected_size,
            **kwargs,
        )


def capture_product_release(
    root: str | Path,
    *,
    client: PublicClient | None = None,
    transport: Mapping[str, Any] | None = None,
) -> ReleaseCapture:
    """Materialize and re-authenticate ``<root>/product-capture``."""
    try:
        base = _require_real_dir(Path(root))
        capture_root = base / CAPTURE_DIR
        validate_ancestry_not_symlink(capture_root)
        if capture_root.exists() or capture_root.is_symlink():
            _fail("Held product capture root already exists")
        capture_root.mkdir(mode=0o700)
        info = os.lstat(capture_root)
        if not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode):
            _fail("Held product capture root is not a real directory")
        identity = (info.st_dev, info.st_ino, info.st_uid)
    except ContractError as exc:
        if exc.code == "NEBULAR_UNIVERSAL_PRODUCT_CAPTURE":
            raise
        _fail("Held product capture root is invalid")

    try:
        selection = product_selection()
        _write_exclusive(capture_root / SELECTION_NAME, canonical(selection))
        evidence_root = capture_root / EVIDENCE_DIR
        evidence_root.mkdir(mode=0o700)
        _require_real_dir(evidence_root)
        base_client = client if client is not None else public_client()
        active_client = (
            _TransportReuseClient(base_client, base, transport)
            if transport is not None
            else base_client
        )
        capture_release(selection, evidence_root, client=active_client)
        return load_held_product_capture(base)
    except Exception as exc:
        _cleanup_dir(capture_root, identity)
        if isinstance(exc, ContractError) and exc.code == "NEBULAR_UNIVERSAL_PRODUCT_CAPTURE":
            raise
        _fail("Held product release capture failed")


def load_held_product_capture(root: str | Path) -> ReleaseCapture:
    """Validate and authenticate the held ``<root>/product-capture`` tree."""
    from rs9.nebular071_universal_consumer import (
        authenticated_product_release,
        authenticated_product_source,
    )

    try:
        base = _require_real_dir(Path(root))
        capture_root = base / CAPTURE_DIR
        _require_exact_entries(capture_root, {SELECTION_NAME, EVIDENCE_DIR})
        selection_bytes = _read_regular_nofollow(capture_root / SELECTION_NAME, 65536)
        expected_selection = product_selection()
        if selection_bytes != canonical(expected_selection):
            _fail("Held product selection.json differs from the pinned v0.7.1 selection")
        evidence_root = capture_root / EVIDENCE_DIR
        _require_exact_entries(evidence_root, {"api", "assets", "fetch-receipt.json"})
        _read_regular_nofollow(evidence_root / "fetch-receipt.json", 1024 * 1024)
        _require_regular_children(evidence_root / "api", API_FILE_NAMES)
        _require_regular_children(evidence_root / "assets", expected_asset_names())
        capture = authenticate_release(expected_selection, evidence_root)
        authenticated_product_source(capture)
        authenticated_product_release(capture)
        return capture
    except ContractError as exc:
        if exc.code == "NEBULAR_UNIVERSAL_PRODUCT_CAPTURE":
            raise
        _fail()
    except (AdmissionError, OSError, ValueError, TypeError, KeyError):
        _fail()
    raise AssertionError("unreachable")


def product_capture_receipt(
    root: str | Path,
    capture: ReleaseCapture | None = None,
) -> dict[str, str]:
    """Return the digest summary recorded in public-inputs-preparation.json."""
    active = load_held_product_capture(root) if capture is None else capture
    if not isinstance(active, ReleaseCapture):
        _fail()
    base = _require_real_dir(Path(root))
    capture_root = base / CAPTURE_DIR
    selection_bytes = _read_regular_nofollow(capture_root / SELECTION_NAME, 65536)
    receipt_bytes = _read_regular_nofollow(
        capture_root / EVIDENCE_DIR / "fetch-receipt.json",
        1024 * 1024,
    )
    return {
        "path": CAPTURE_DIR,
        "selection_sha256": hashlib.sha256(selection_bytes).hexdigest(),
        "record_sha256": authenticated_record_hash(active),
        "fetch_receipt_sha256": hashlib.sha256(receipt_bytes).hexdigest(),
    }
