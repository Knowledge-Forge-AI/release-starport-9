"""Public Pages tree scanner.

Scans and verifies public Pages trees (such as GitHub Pages or package repository mirrors).
Fail-closed security:
- Rejects private keys and secrets (credential tokens, private key blocks).
- Rejects unmanifested files and private payloads.
- Allows only candidate public assets, index files, public keys, docs, and CNAME.
- Enforces safe POSIX relative paths and rejects all symlinks.
- Enforces mandatory manifest for production candidate scanner.
"""

from __future__ import annotations

import base64
import hashlib
import os
from pathlib import Path
import re
import stat
from typing import Any

from rs9.errors import ContractError
from rs9.records import Record, closed, record_sha256, snapshot, validate_bounded_int, validate_sha256
from rs9.scratch import canonical, physical_directory
from rs9.security import PRIVATE_BLOCK_RE, scan_for_credentials, validate_safe_relative_posix_path

SCHEMA_PAGES_MANIFEST = "rs9.pages-manifest.v1alpha1"

CATEGORY_CNAME = "cname"
CATEGORY_INDEX = "index"
CATEGORY_PUBLIC_KEY = "public_key"
CATEGORY_DOCS = "docs"
CATEGORY_CANDIDATE_ASSET = "candidate_public_asset"

ALLOWED_CATEGORIES = {
    CATEGORY_CNAME,
    CATEGORY_INDEX,
    CATEGORY_PUBLIC_KEY,
    CATEGORY_DOCS,
    CATEGORY_CANDIDATE_ASSET,
}

# Sensitive filename patterns that must immediately fail
SENSITIVE_FILENAME_RE = re.compile(
    r"(?i)(^|\b|_|-)(id_rsa|id_ecdsa|id_ed25519|id_dsa|privkey|private_key|private-key|private|secret|credential|passwd|password|api_key|token)($|\b|_|-|\.)"
)

# Allowed extensions for documentation files
DOC_EXTENSIONS = frozenset(
    {
        ".html",
        ".htm",
        ".md",
        ".markdown",
        ".css",
        ".js",
        ".mjs",
        ".json",
        ".txt",
        ".png",
        ".jpg",
        ".jpeg",
        ".gif",
        ".svg",
        ".ico",
        ".webp",
        ".woff",
        ".woff2",
        ".ttf",
        ".eot",
    }
)

ROOT_DOC_FILES = frozenset(
    {
        "README.md",
        "LICENSE",
        "NOTICE",
        "CHANGELOG.md",
        "favicon.ico",
        "robots.txt",
        "404.html",
    }
)

INDEX_FILENAMES = frozenset(
    {
        "index.html",
        "index.htm",
        "index.txt",
        "index.json",
        "index.xml",
    }
)

PUBLIC_KEY_EXTENSIONS = frozenset(
    {
        ".pub",
        ".gpg",
        ".asc",
    }
)

PUBLIC_KEY_NAMES = frozenset(
    {
        "public.key",
        "pubkey.gpg",
        "Release.gpg",
        "key.asc",
        "repo.pub",
    }
)

ASSET_EXTENSIONS = frozenset(
    {
        ".deb",
        ".tar.gz",
        ".tar.xz",
        ".tgz",
        ".rpm",
        ".pkg.tar.zst",
        ".sig",
        ".db",
        ".files",
        ".sha256",
        ".gz",
        ".xz",
    }
)

APT_METADATA_FILES = frozenset(
    {
        "Packages",
        "Packages.gz",
        "Packages.xz",
        "Release",
        "InRelease",
        "Release.gpg",
    }
)

PACKAGE_EXTENSIONS = (".deb", ".rpm", ".pkg.tar.zst", ".tar.gz", ".tar.xz", ".tgz")


def _digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _check_no_symlinks(path: Path) -> None:
    if path.is_symlink():
        raise ContractError("SYMLINK_REJECTED", "Path is a symlink")
    for parent in (path, *path.parents):
        if parent.is_symlink():
            raise ContractError("SYMLINK_REJECTED", "Path ancestry contains a symlink")


OPENPGP_PUBLIC_KEY_ALLOWED_TAGS = frozenset({2, 6, 12, 13, 14, 17})
OPENPGP_SECRET_TAGS = frozenset({5, 7})


def parse_openpgp_packets(data: bytes, *, strict: bool = False) -> list[tuple[int, bytes]]:
    """Read bounded, definite-length public-key packets without ignoring trailers.

    Discovery of arbitrary binary assets is tolerant. Key validation rejects
    malformed, partial-length and indeterminate packets rather than guessing.
    """
    packets, offset = [], 0
    try:
        while offset < len(data):
            header = data[offset]
            offset += 1
            if not header & 0x80:
                raise ValueError
            new_format = bool(header & 0x40)
            tag = header & 0x3f if new_format else (header >> 2) & 0x0f
            if tag in OPENPGP_SECRET_TAGS:
                raise ContractError("CREDENTIAL_DETECTED", "OpenPGP secret key packet detected")
            if new_format:
                first = data[offset]
                offset += 1
                if first < 192:
                    length = first
                elif first < 224:
                    length = ((first - 192) << 8) + data[offset] + 192
                    offset += 1
                elif first == 255:
                    if offset + 4 > len(data): raise ValueError
                    length = int.from_bytes(data[offset:offset + 4], "big")
                    offset += 4
                else:
                    raise ValueError
            else:
                length_type = header & 3
                if length_type == 3: raise ValueError
                width = (1, 2, 4)[length_type]
                if offset + width > len(data): raise ValueError
                length = int.from_bytes(data[offset:offset + width], "big")
                offset += width
            if offset + length > len(data): raise ValueError
            packets.append((tag, data[offset:offset + length]))
            offset += length
    except (ValueError, IndexError):
        if strict:
            raise ContractError("INVALID_PUBLIC_KEY", "Malformed or unsupported public key packet framing") from None
    return packets


def check_no_secret_key_packets(data: bytes) -> None:
    """Reject any binary OpenPGP data containing secret key or secret subkey packets."""
    if len(data) >= 2 and (data[0] & 0x80):
        try:
            packets = parse_openpgp_packets(data)
            if any(tag in OPENPGP_SECRET_TAGS for tag, _ in packets):
                raise ContractError("CREDENTIAL_DETECTED", "OpenPGP binary secret key packet detected")
        except ContractError:
            raise
        except Exception:
            pass


def validate_openpgp_public_key(data: bytes) -> None:
    """Validate that data contains truthful public OpenPGP key material and no secret keys."""
    stripped = data.strip()
    if stripped.startswith(b"-----BEGIN PGP"):
        text = stripped.decode("utf-8", errors="replace")
        if "PRIVATE KEY" in text or "SECRET KEY" in text:
            if "BEGIN PGP SECRET KEY BLOCK" in text or "BEGIN PGP PRIVATE KEY BLOCK" in text:
                raise ContractError("CREDENTIAL_DETECTED", "Secret key block detected")
            raise ContractError("CREDENTIAL_DETECTED", "Private or secret key detected in key file")
        if not (text.startswith("-----BEGIN PGP PUBLIC KEY BLOCK-----") and "-----END PGP PUBLIC KEY BLOCK-----" in text):
            raise ContractError("INVALID_PUBLIC_KEY", "Public key must be a valid PGP public key block")

        lines = text.splitlines()
        start_idx = -1
        end_idx = -1
        for i, line in enumerate(lines):
            if line.strip() == "-----BEGIN PGP PUBLIC KEY BLOCK-----":
                start_idx = i
            elif line.strip() == "-----END PGP PUBLIC KEY BLOCK-----":
                end_idx = i
                break
        if start_idx == -1 or end_idx == -1 or end_idx <= start_idx:
            raise ContractError("INVALID_PUBLIC_KEY", "Malformed PGP public key armor headers")

        b64_lines = []
        in_body = False
        for line in lines[start_idx + 1:end_idx]:
            sline = line.strip()
            if not in_body:
                if not sline or ":" not in sline:
                    in_body = True
                else:
                    continue
            if not sline or sline.startswith("="):
                continue
            b64_lines.append(sline)

        try:
            decoded = base64.b64decode("".join(b64_lines), validate=True)
        except Exception:
            raise ContractError("INVALID_PUBLIC_KEY", "Malformed base64 in PGP public key armor") from None

        packets = parse_openpgp_packets(decoded, strict=True)
        if any(tag in OPENPGP_SECRET_TAGS for tag, _ in packets):
            raise ContractError("CREDENTIAL_DETECTED", "Secret key packet detected inside public key armor")
        if not any(tag == 6 for tag, _ in packets):
            raise ContractError("INVALID_PUBLIC_KEY", "Public key armor contains no public key packet")
        if any(tag not in OPENPGP_PUBLIC_KEY_ALLOWED_TAGS for tag, _ in packets):
            raise ContractError("INVALID_PUBLIC_KEY", "Disallowed packet in public key block")
    else:
        # Binary OpenPGP public key
        if not (len(data) >= 2 and (data[0] & 0x80)):
            raise ContractError("INVALID_PUBLIC_KEY", "Public key file must contain OpenPGP key material")
        packets = parse_openpgp_packets(data, strict=True)
        if any(tag in OPENPGP_SECRET_TAGS for tag, _ in packets):
            raise ContractError("CREDENTIAL_DETECTED", "Secret key packet detected in binary public key")
        if not any(tag == 6 for tag, _ in packets):
            raise ContractError("INVALID_PUBLIC_KEY", "Binary public key contains no public key packet")
        if any(tag not in OPENPGP_PUBLIC_KEY_ALLOWED_TAGS for tag, _ in packets):
            raise ContractError("INVALID_PUBLIC_KEY", "Disallowed packet in binary public key")


def classify_pages_path(rel_path: str) -> tuple[bool, str]:
    """Classify a relative POSIX path into allowed pages categories.

    Returns (is_allowed, category_name).
    """
    validate_safe_relative_posix_path(rel_path)
    parts = rel_path.split("/")
    filename = parts[-1]

    # Reject hidden files or hidden directory segments
    for part in parts:
        if part.startswith("."):
            return False, ""

    # Sensitive filename keywords rejected across all segments - NO exemption for .gpg/.asc
    for part in parts:
        if SENSITIVE_FILENAME_RE.search(part):
            return False, ""

    # 1. CNAME (root only)
    if rel_path == "CNAME":
        return True, CATEGORY_CNAME

    # 2. Index files
    if filename in INDEX_FILENAMES:
        if (
            len(parts) == 1
            or parts[0] in ("docs", "assets", "dists", "pool", "repodata", "rpm", "pacman", "arch", "archlinux")
            or (len(parts) == 4 and parts[1] == "os")
        ):
            return True, CATEGORY_INDEX
        return False, ""

    # 3. Public keys (documented root only)
    ext = Path(filename).suffix.lower()
    if len(parts) == 1 and (filename in PUBLIC_KEY_NAMES or ext in PUBLIC_KEY_EXTENSIONS):
        return True, CATEGORY_PUBLIC_KEY

    # 4. Docs
    if parts[0] == "docs" and ext in DOC_EXTENSIONS:
        return True, CATEGORY_DOCS
    if len(parts) == 1 and (filename in ROOT_DOC_FILES or (filename.endswith(".md") and not SENSITIVE_FILENAME_RE.search(filename))):
        return True, CATEGORY_DOCS

    # 5. Candidate public assets in documented directory structures only:
    # No broad suffix allowlist bypassing directory rules.

    # 5a. APT repository: dists/, pool/, by-hash/
    if parts[0] == "dists":
        if filename in APT_METADATA_FILES:
            return True, CATEGORY_CANDIDATE_ASSET
        if len(parts) >= 3 and parts[-3] == "by-hash" and parts[-2] == "SHA256":
            if re.fullmatch(r"[0-9a-f]{64}", filename):
                return True, CATEGORY_CANDIDATE_ASSET
        return False, ""

    if parts[0] == "pool":
        if filename.endswith(".deb"):
            return True, CATEGORY_CANDIDATE_ASSET
        return False, ""

    if parts[0] == "by-hash":
        if len(parts) == 3 and parts[1] == "SHA256" and re.fullmatch(r"[0-9a-f]{64}", filename):
            return True, CATEGORY_CANDIDATE_ASSET
        return False, ""

    # 5b. RPM repository: repodata/, rpm/, packages/
    if parts[0] == "repodata" or (len(parts) >= 2 and parts[-2] == "repodata"):
        if filename == "repomd.xml" or filename.startswith("repomd.") or filename.endswith((".xml", ".xml.gz", ".xml.asc")):
            return True, CATEGORY_CANDIDATE_ASSET
        return False, ""

    if parts[0] in ("rpm", "packages"):
        if filename.endswith(".rpm"):
            return True, CATEGORY_CANDIDATE_ASSET
        return False, ""

    # 5c. Pacman / Arch repository: arch/, pacman/, archlinux/, or <repo>/os/<arch>/
    if parts[0] in ("arch", "pacman", "archlinux"):
        if filename.endswith((".pkg.tar.zst", ".pkg.tar.zst.sig", ".db", ".db.tar.gz", ".files", ".files.tar.gz")):
            return True, CATEGORY_CANDIDATE_ASSET
        return False, ""

    if len(parts) == 4 and parts[1] == "os" and parts[2] in ("x86_64", "aarch64", "any", "i686", "armv7h"):
        if filename.endswith((".pkg.tar.zst", ".pkg.tar.zst.sig", ".db", ".db.tar.gz", ".files", ".files.tar.gz")):
            return True, CATEGORY_CANDIDATE_ASSET
        return False, ""

    # 5d. General release assets and root checksums
    if parts[0] == "assets":
        if filename.endswith((".tar.gz", ".tar.xz", ".tgz", ".zip")) or filename in ("SHA256SUMS", "hashes.txt"):
            return True, CATEGORY_CANDIDATE_ASSET
        return False, ""

    if len(parts) == 1 and filename in ("SHA256SUMS", "hashes.txt"):
        return True, CATEGORY_CANDIDATE_ASSET

    return False, ""


def _scan_file_content(path: Path, rel_path: str, category: str, max_size: int = 512 * 1024 * 1024) -> tuple[str, int]:
    """Scan file bytes safely: no symlink, check size, scan credentials/keys."""
    _check_no_symlinks(path)
    try:
        descriptor = os.open(str(path), os.O_RDONLY | os.O_NOFOLLOW)
        with os.fdopen(descriptor, "rb") as stream:
            info = os.fstat(stream.fileno())
            if not stat.S_ISREG(info.st_mode):
                raise ContractError("INVALID_FILE", "Regular file required")
            if info.st_size > max_size:
                raise ContractError("PAGES_LIMIT", "File size exceeds limit")
            data = stream.read(max_size + 1)
            if len(data) > max_size:
                raise ContractError("PAGES_LIMIT", "File size exceeds limit")
    except OSError as err:
        if isinstance(err, ContractError):
            raise
        raise ContractError("IO_ERROR", "Failed reading file") from None

    file_size = len(data)
    sha256 = _digest(data)

    # Check for private or secret key blocks across all files
    if b"PRIVATE KEY" in data or b"SECRET KEY" in data:
        text_preview = data.decode("utf-8", errors="replace")
        if PRIVATE_BLOCK_RE.search(text_preview) or "BEGIN PGP SECRET KEY BLOCK" in text_preview:
            raise ContractError("CREDENTIAL_DETECTED", "Private or secret key block detected")

    # Reject binary OpenPGP secret key packets across all files
    check_no_secret_key_packets(data)

    # Validate public key material if categorized as public key
    if category == CATEGORY_PUBLIC_KEY:
        validate_openpgp_public_key(data)

    # Scan for credentials in text files
    if category in (CATEGORY_CNAME, CATEGORY_DOCS, CATEGORY_INDEX, CATEGORY_PUBLIC_KEY) or rel_path.endswith(
        (".txt", ".md", ".json", ".xml", ".html", ".css", ".js")
    ):
        text = data.decode("utf-8", errors="replace")
        try:
            scan_for_credentials(text)
        except ContractError as err:
            raise ContractError(err.code, "Credential detected in pages file") from None

    return sha256, file_size


def scan_pages_tree(
    root: str | Path,
    manifest: dict[str, str] | set[str] | list[str] | None = None,
    *,
    require_manifest: bool = False,
    max_total_bytes: int = 2 * 1024 * 1024 * 1024,
    max_files: int = 20000,
) -> Record:
    """Scan and validate a public Pages tree fail-closed.

    When manifest is provided, validates exact manifest inventory and hashes.
    When manifest is omitted, operates as non-authoritative discovery helper.
    """
    if require_manifest and manifest is None:
        raise ContractError("MANIFEST_REQUIRED", "Manifest is mandatory for candidate validation")

    root_path = physical_directory(root)
    _check_no_symlinks(root_path)

    found_files: dict[str, dict[str, Any]] = {}
    category_counts: dict[str, int] = {cat: 0 for cat in ALLOWED_CATEGORIES}
    total_bytes = 0

    expected_hashes: dict[str, str] = {}
    manifest_paths: set[str] | None = None
    if manifest is not None:
        if isinstance(manifest, dict):
            expected_hashes = manifest
            manifest_paths = set(manifest.keys())
        elif isinstance(manifest, (set, list)):
            manifest_paths = set(manifest)
        else:
            raise ContractError("INVALID_TYPE", "Manifest must be dict, set, or list")

    for current_dir_str, dirnames, filenames in os.walk(str(root_path)):
        current_dir = Path(current_dir_str)
        _check_no_symlinks(current_dir)

        for d in dirnames:
            dir_path = current_dir / d
            if dir_path.is_symlink():
                raise ContractError("SYMLINK_REJECTED", "Directory symlink detected")
            if d.startswith("."):
                raise ContractError("DISALLOWED_FILE", "Hidden directory detected")

        for f in filenames:
            file_path = current_dir / f
            if file_path.is_symlink():
                raise ContractError("SYMLINK_REJECTED", "File symlink detected")

            rel_path = file_path.relative_to(root_path).as_posix()
            validate_safe_relative_posix_path(rel_path)

            parts = rel_path.split("/")
            if any(SENSITIVE_FILENAME_RE.search(part) for part in parts):
                raise ContractError("PRIVATE_PAYLOAD_DETECTED", "Sensitive path detected")

            if manifest_paths is not None and rel_path not in manifest_paths:
                raise ContractError("UNMANIFESTED_FILE", "Unmanifested file found in pages tree")

            is_allowed, category = classify_pages_path(rel_path)
            if not is_allowed:
                raise ContractError("DISALLOWED_FILE", "Disallowed file or private payload detected")

            sha256, file_size = _scan_file_content(file_path, rel_path, category)

            if rel_path in expected_hashes:
                expected_sha = expected_hashes[rel_path]
                validate_sha256(expected_sha)
                if sha256 != expected_sha:
                    raise ContractError("TAMPER_DETECTED", "Hash mismatch for manifested file")

            total_bytes += file_size
            if total_bytes > max_total_bytes:
                raise ContractError("PAGES_LIMIT", "Pages aggregate byte limit exceeded")

            if len(found_files) >= max_files:
                raise ContractError("PAGES_LIMIT", "Pages file count limit exceeded")

            found_files[rel_path] = {
                "sha256": sha256,
                "size": file_size,
                "category": category,
            }
            category_counts[category] += 1

    if manifest_paths is not None:
        missing = manifest_paths - set(found_files.keys())
        if missing:
            raise ContractError("MISSING_MANIFESTED_FILE", "Declared manifested file is missing")

    # Binary manifest required for all package files in production candidate scan
    package_files = [p for p in found_files if any(p.endswith(pext) for pext in PACKAGE_EXTENSIONS)]
    if package_files:
        if require_manifest or manifest is not None:
            for pkg in package_files:
                if expected_hashes and pkg not in expected_hashes:
                    raise ContractError("UNMANIFESTED_PACKAGE", "Binary package manifest required for package")

        has_repo_index = any(
            Path(p).name in APT_METADATA_FILES
            or any(p.endswith(meta) for meta in (".db", ".files", "repomd.xml"))
            or "repodata" in p
            for p in found_files
        )
        if not has_repo_index:
            raise ContractError("MISSING_PACKAGE_INDEX", "Package repository index missing for packages")

    is_authoritative = bool(manifest is not None)
    result_data = {
        "schema": SCHEMA_PAGES_MANIFEST,
        "authoritative": is_authoritative,
        "file_count": len(found_files),
        "total_bytes": total_bytes,
        "categories": category_counts,
        "files": dict(sorted(found_files.items())),
    }
    return Record(snapshot(result_data))


def validate_pages_tree(root: str | Path, manifest: Any = None) -> Record:
    """Validate a public Pages tree for production candidate.

    Manifest is mandatory for production candidate validation.
    """
    if manifest is None:
        raise ContractError("MANIFEST_REQUIRED", "Manifest is mandatory for production candidate scanner")
    return scan_pages_tree(root, manifest=manifest, require_manifest=True)
