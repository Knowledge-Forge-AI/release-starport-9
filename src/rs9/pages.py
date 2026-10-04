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
import gzip
import hashlib
import importlib
import io
import lzma
import os
from pathlib import Path
import re
import shutil
import stat
import struct
import subprocess
import tarfile
import threading
from typing import Any
import zlib

from rs9.errors import ContractError
from rs9.records import Record, closed, record_sha256, snapshot, validate_bounded_int, validate_sha256
from rs9.scratch import canonical, physical_directory
from rs9.security import (
    PRIVATE_BLOCK_RE,
    scan_bytes_for_credentials,
    scan_for_credentials,
    validate_safe_relative_posix_path,
)

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


RPM_MAGIC = b"\xed\xab\xee\xdb"
RPM_HEADER_MAGIC = b"\x8e\xad\xe8\x01"
AR_MAGIC = b"!<arch>\n"
XZ_MAGIC = b"\xfd7zXZ\x00"
ZSTD_MAGIC = b"\x28\xb5\x2f\xfd"
GZIP_MAGIC = b"\x1f\x8b"
CPIO_MAGICS = (b"070701", b"070702")
KEY_MEMBER_SUFFIXES = (".gpg", ".pgp", ".asc", ".kbx", ".key", ".sig")
MAX_SCAN_DECODED_BYTES = 1024 ** 3
MAX_SCAN_MEMBERS = 200_000
MAX_SCAN_DEPTH = 6


class _NotProven(Exception):
    """The claimed container structure could not be proven; caller keeps raw scanning."""


class _ScanBudget:
    def __init__(self) -> None:
        self.bytes_left = MAX_SCAN_DECODED_BYTES
        self.members = 0
        self.formats: set[str] = set()
        self.unscanned: set[str] = set()

    def take(self, count: int) -> None:
        self.bytes_left -= count
        if self.bytes_left < 0:
            raise ContractError("PAGES_LIMIT", "Decoded artifact byte limit exceeded during privacy scan")

    def member(self) -> None:
        self.members += 1
        if self.members > MAX_SCAN_MEMBERS:
            raise ContractError("PAGES_LIMIT", "Artifact member limit exceeded during privacy scan")


def detect_binary_format(data: bytes) -> str | None:
    """Identify a container by magic only; structure is proven separately."""
    if data.startswith(RPM_MAGIC):
        return "rpm"
    if data.startswith(AR_MAGIC):
        return "ar"
    if data.startswith(XZ_MAGIC):
        return "xz"
    if data.startswith(ZSTD_MAGIC):
        return "zstd"
    if data.startswith(GZIP_MAGIC):
        return "gzip"
    if data[257:262] == b"ustar":
        return "tar"
    if data.startswith(CPIO_MAGICS):
        return "cpio"
    return None


def clean_openpgp_framing(data: bytes) -> list[int] | None:
    """Tags of data that is, byte for byte, a definite-length OpenPGP packet sequence.

    Returns None for anything else, so random binary content does not pretend to be
    key material the way a tolerant prefix parse can.
    """
    if len(data) < 3 or not data[0] & 0x80:
        return None
    tags, offset = [], 0
    try:
        while offset < len(data):
            header = data[offset]
            offset += 1
            if not header & 0x80:
                return None
            if header & 0x40:
                tag = header & 0x3f
                first = data[offset]
                offset += 1
                if first < 192:
                    length = first
                elif first < 224:
                    length = ((first - 192) << 8) + data[offset] + 192
                    offset += 1
                elif first == 255:
                    length = int.from_bytes(data[offset:offset + 4], "big")
                    offset += 4
                else:
                    return None
            else:
                tag = (header >> 2) & 0x0f
                length_type = header & 3
                if length_type == 3:
                    return None
                width = (1, 2, 4)[length_type]
                if offset + width > len(data):
                    return None
                length = int.from_bytes(data[offset:offset + width], "big")
                offset += width
            if tag < 1 or tag > 21 or offset + length > len(data):
                return None
            tags.append(tag)
            offset += length
    except IndexError:
        return None
    return tags


def _zstd_frames_valid(data: bytes) -> bool:
    """Walk zstd frame and block headers; the whole input must be consumed."""
    offset, frames = 0, 0
    while offset < len(data):
        if offset + 4 > len(data):
            return False
        magic = data[offset:offset + 4]
        if magic[0] & 0xf0 == 0x50 and magic[1:] == b"\x2a\x4d\x18":
            if offset + 8 > len(data):
                return False
            offset += 8 + int.from_bytes(data[offset + 4:offset + 8], "little")
            if offset > len(data):
                return False
            continue
        if magic != ZSTD_MAGIC or offset + 5 > len(data):
            return False
        descriptor = data[offset + 4]
        offset += 5
        single, checksum = bool(descriptor & 0x20), bool(descriptor & 0x04)
        if descriptor & 0x08:
            return False
        fcs_size = (1 if single else 0, 2, 4, 8)[descriptor >> 6]
        offset += (0 if single else 1) + (0, 1, 2, 4)[descriptor & 3] + fcs_size
        while True:
            if offset + 3 > len(data):
                return False
            block = int.from_bytes(data[offset:offset + 3], "little")
            offset += 3
            block_type, size = (block >> 1) & 3, block >> 3
            if block_type == 3:
                return False
            offset += 1 if block_type == 1 else size
            if offset > len(data):
                return False
            if block & 1:
                break
        if checksum:
            offset += 4
            if offset > len(data):
                return False
        frames += 1
    return frames > 0


def _zstd_decode(data: bytes, limit: int) -> bytes | None:
    """Bounded zstd decode through whichever reviewed decoder exists; None if none does."""
    try:
        native = importlib.import_module("compression.zstd")  # Python 3.14+; absent elsewhere

        out, rest = bytearray(), data
        while rest:
            decoder = native.ZstdDecompressor()
            out += decoder.decompress(rest, max_length=limit + 1 - len(out))
            if len(out) > limit or not decoder.eof:
                break
            rest = decoder.unused_data
        if len(out) <= limit and not rest:
            return bytes(out)
    except Exception:
        pass
    tool = shutil.which("zstd")
    if tool is None:
        return None

    def _feed(stdin):
        try:
            stdin.write(data)
        except (BrokenPipeError, OSError):
            pass
        finally:
            try:
                stdin.close()
            except (BrokenPipeError, OSError):
                pass

    try:
        with subprocess.Popen(
            [tool, "-dc", "-q"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
        ) as child:
            feeder = threading.Thread(target=_feed, args=(child.stdin,), daemon=True)
            feeder.start()
            out = bytearray()
            limit_exceeded = False
            read_complete = False
            try:
                while True:
                    chunk = child.stdout.read(1024 * 1024)
                    if not chunk:
                        read_complete = True
                        break
                    out += chunk
                    if len(out) > limit:
                        limit_exceeded = True
                        break
            finally:
                if not read_complete:
                    child.kill()
                feeder.join(timeout=30)
                if feeder.is_alive():
                    child.kill()
                    feeder.join()
                try:
                    child.wait(timeout=30)
                except subprocess.TimeoutExpired:
                    # EOF does not establish process exit. Reap before the
                    # context manager performs its otherwise unbounded wait.
                    child.kill()
                    child.wait()
                    raise

            if limit_exceeded:
                raise ContractError("PAGES_LIMIT", "Decoded artifact byte limit exceeded during privacy scan")

            return bytes(out) if child.returncode == 0 else None
    except (OSError, subprocess.SubprocessError):
        return None


def _inflate(kind: str, data: bytes, budget: _ScanBudget) -> bytes | None:
    limit = budget.bytes_left
    try:
        if kind == "gzip":
            with gzip.GzipFile(fileobj=io.BytesIO(data)) as stream:
                out = stream.read(limit + 1)
        elif kind == "xz":
            with lzma.LZMAFile(io.BytesIO(data)) as stream:
                out = stream.read(limit + 1)
        else:
            if not _zstd_frames_valid(data):
                raise _NotProven
            out = _zstd_decode(data, limit)
            if out is None:
                return None
    except (OSError, EOFError, lzma.LZMAError, zlib.error):
        raise _NotProven from None
    budget.take(len(out))
    return out


def _scan_opaque(content: bytes, name: str, budget: _ScanBudget) -> None:
    """Content that is not a recognised container: key material is rejected, bytes are not guessed at."""
    scan_bytes_for_credentials(content)
    tags = clean_openpgp_framing(content)
    if tags is not None and any(tag in OPENPGP_SECRET_TAGS for tag in tags):
        raise ContractError("CREDENTIAL_DETECTED", "OpenPGP secret key packet detected in artifact member")
    if name.lower().endswith(KEY_MEMBER_SUFFIXES) or "keyring" in name.lower():
        if content and content[0] & 0x80:
            check_no_secret_key_packets(content)
        elif b"-----BEGIN PGP PUBLIC KEY BLOCK-----" in content:
            try:
                validate_openpgp_public_key(content)
            except ContractError as err:
                if err.code == "CREDENTIAL_DETECTED":
                    raise


def _scan_member(content: bytes, name: str, budget: _ScanBudget, depth: int) -> None:
    kind = detect_binary_format(content)
    if kind is not None and depth < MAX_SCAN_DEPTH:
        try:
            _scan_stream(kind, content, name, budget, depth + 1)
            return
        except _NotProven:
            pass
    _scan_opaque(content, name, budget)


def _strip_compression_suffix(name: str) -> str:
    for suffix in (".gz", ".xz", ".zst"):
        if name.endswith(suffix):
            return name[: -len(suffix)]
    return name


def _scan_tar(data: bytes, budget: _ScanBudget, depth: int) -> None:
    try:
        with tarfile.open(fileobj=io.BytesIO(data), mode="r:") as archive:
            for member in archive:
                budget.member()
                if member.isreg():
                    stream = archive.extractfile(member)
                    content = stream.read(member.size) if stream is not None else b""
                    budget.take(len(content))
                    _scan_member(content, member.name, budget, depth)
    except (tarfile.TarError, EOFError, UnicodeError):
        raise _NotProven from None


def _scan_cpio(data: bytes, budget: _ScanBudget, depth: int) -> None:
    offset = 0
    while True:
        if offset + 110 > len(data) or data[offset:offset + 6] not in CPIO_MAGICS:
            raise _NotProven
        try:
            mode = int(data[offset + 14:offset + 22], 16)
            size = int(data[offset + 54:offset + 62], 16)
            name_size = int(data[offset + 94:offset + 102], 16)
        except ValueError:
            raise _NotProven from None
        name_end = offset + 110 + name_size
        body = (name_end + 3) & ~3
        if name_size < 1 or body + size > len(data):
            raise _NotProven
        name = data[offset + 110:name_end - 1].decode("utf-8", errors="replace")
        offset = (body + size + 3) & ~3
        if name == "TRAILER!!!":
            break
        budget.member()
        if mode & 0o170000 == 0o100000:
            _scan_member(data[body:body + size], name, budget, depth)
    if data[offset:].strip(b"\x00"):
        raise _NotProven


def _rpm_header(data: bytes, offset: int) -> tuple[int, bytes]:
    if data[offset:offset + 4] != RPM_HEADER_MAGIC or offset + 16 > len(data):
        raise _NotProven
    count, store = struct.unpack(">II", data[offset + 8:offset + 16])
    end = offset + 16 + 16 * count + store
    if count > 0xFFFF or store > 256 * 1024 * 1024 or end > len(data):
        raise _NotProven
    for index in range(count):
        _, kind, where, _ = struct.unpack(">IIII", data[offset + 16 + 16 * index:offset + 32 + 16 * index])
        if kind > 9 or where > store:
            raise _NotProven
    return end, data[end - store:end]


def _scan_rpm(data: bytes, budget: _ScanBudget, depth: int) -> None:
    if len(data) < 112 or data[4] not in (3, 4, 6) or struct.unpack(">H", data[78:80])[0] != 5:
        raise _NotProven
    offset, signature_store = _rpm_header(data, 96)
    offset, header_store = _rpm_header(data, (offset + 7) & ~7)
    for store in (signature_store, header_store):
        scan_bytes_for_credentials(store, token_scan=True)
    payload = data[offset:]
    kind = detect_binary_format(payload)
    budget.formats.update(item for item in (kind, "cpio") if item)
    try:
        if kind in {"gzip", "xz", "zstd"}:
            inflated = _inflate(kind, payload, budget)
            if inflated is None:
                budget.unscanned.add("rpm-payload-zstd-decoder-unavailable")
                return
        elif kind == "cpio":
            inflated = payload
        else:
            raise _NotProven
        _scan_cpio(inflated, budget, depth)
    except _NotProven:
        # The rpm lead/signature/header structure is proven; the payload is not decodable here.
        budget.unscanned.add("rpm-payload")


def _scan_ar(data: bytes, budget: _ScanBudget, depth: int) -> None:
    offset, first = 8, True
    while offset < len(data):
        header = data[offset:offset + 60]
        if len(header) < 60 or header[58:60] != b"`\n":
            raise _NotProven
        name = header[:16].decode("ascii", errors="replace").strip().rstrip("/")
        try:
            size = int(header[48:58].decode("ascii").strip())
        except ValueError:
            raise _NotProven from None
        offset += 60
        if size < 0 or offset + size > len(data) or name.startswith(("#1/", "/")):
            raise _NotProven
        body = data[offset:offset + size]
        offset += size
        if size % 2 and offset < len(data):
            if data[offset:offset + 1] != b"\n":
                raise _NotProven
            offset += 1
        budget.member()
        if first and name == "debian-binary" and body != b"2.0\n":
            raise _NotProven
        first = False
        budget.take(len(body))
        _scan_member(body, name, budget, depth)


def _scan_stream(kind: str, data: bytes, name: str, budget: _ScanBudget, depth: int) -> None:
    budget.formats.add(kind)
    if kind == "rpm":
        _scan_rpm(data, budget, depth)
    elif kind == "ar":
        _scan_ar(data, budget, depth)
    elif kind == "tar":
        _scan_tar(data, budget, depth)
    elif kind == "cpio":
        _scan_cpio(data, budget, depth)
    else:
        inflated = _inflate(kind, data, budget)
        if inflated is None:
            budget.unscanned.add(f"{kind}-decoder-unavailable")
            return
        _scan_member(inflated, _strip_compression_suffix(name), budget, depth)


def scan_binary_artifact(data: bytes, rel_path: str = "") -> dict[str, Any] | None:
    """Format-aware privacy scan of rpm, ar/deb, xz, zstd, gzip, tar and cpio artifacts.

    Container structure is parsed and every decoded member is scanned for private key
    armor, OpenPGP secret packets in key material and (for text) credential tokens.
    The raw prefix packet scan is deliberately not applied to container bytes, because
    compressed or header bytes can parse as a secret packet by chance. Returns None when
    the container structure is not proven, so the caller keeps the conservative raw scan.
    """
    kind = detect_binary_format(data)
    if kind is None:
        return None
    budget = _ScanBudget()
    try:
        _scan_stream(kind, data, rel_path, budget, 0)
    except _NotProven:
        return None
    return {
        "format": kind,
        "formats_seen": sorted(budget.formats),
        "members_scanned": budget.members,
        "decoded_bytes": MAX_SCAN_DECODED_BYTES - budget.bytes_left,
        "complete": not budget.unscanned,
        "unscanned_streams": sorted(budget.unscanned),
    }


MERKLE_ALGORITHM = "rs9-merkle-sha256-v1"


def merkle_inventory(inventory: dict[str, str]) -> dict[str, Any]:
    """Exact Merkle commitment over a {path: sha256} inventory.

    Leaves are domain-separated (0x00, path length, path, content digest) and sorted by
    path bytes; interior nodes use 0x01. An odd node is promoted unchanged, never
    duplicated, so no two inventories share a root.
    """
    if not inventory:
        raise ContractError("EMPTY_INVENTORY", "Merkle inventory requires at least one file")
    leaves: list[tuple[bytes, str, bytes]] = []
    for path, sha in inventory.items():
        validate_safe_relative_posix_path(path)
        validate_sha256(sha)
        raw = path.encode("utf-8")
        leaves.append((raw, path, hashlib.sha256(b"\x00" + len(raw).to_bytes(4, "big") + raw + bytes.fromhex(sha)).digest()))
    leaves.sort(key=lambda row: row[0])
    level = [row[2] for row in leaves]
    while len(level) > 1:
        nxt = [hashlib.sha256(b"\x01" + level[i] + level[i + 1]).digest() for i in range(0, len(level) - 1, 2)]
        if len(level) % 2:
            nxt.append(level[-1])
        level = nxt
    return {
        "algorithm": MERKLE_ALGORITHM,
        "leaf_count": len(leaves),
        "root": level[0].hex(),
        "leaves": [{"path": path, "sha256": inventory[path], "leaf": leaf.hex()} for _, path, leaf in leaves],
    }


def verify_merkle_inventory(document: Any, inventory: dict[str, str]) -> None:
    """Fail closed unless the committed Merkle document equals the exact inventory."""
    if not isinstance(document, dict) or document.get("algorithm") != MERKLE_ALGORITHM:
        raise ContractError("MERKLE_MISMATCH", "Unsupported or missing Merkle inventory document")
    if merkle_inventory(inventory) != document:
        raise ContractError("MERKLE_MISMATCH", "Merkle inventory differs from exact file inventory")


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
        if parts[0] in {"apt", "rpm", "pacman", "keys"}:
            valid_parent = parts[:-1] in (["apt"], ["rpm"], ["pacman"], ["pacman", "x86_64"])
            if len(parts) == 5 and parts[:3] == ["rpm", "fedora", "43"] and parts[3] in {"x86_64", "aarch64"}:
                valid_parent = True
            return (True, CATEGORY_INDEX) if valid_parent else (False, "")
        if (
            len(parts) == 1
            or parts[0] == "docs"
        ):
            return True, CATEGORY_INDEX
        return False, ""

    # 3. Public keys: keys/{rs9.asc,rs9-archive-keyring.gpg} or documented root keys
    ext = Path(filename).suffix.lower()
    if rel_path == "keys/KEY-METADATA.json":
        return True, CATEGORY_DOCS
    if parts[0] == "keys":
        if len(parts) == 2 and filename in ("rs9.asc", "rs9-archive-keyring.gpg", "rs9-candidate-fixture-NONPRODUCTION.asc", "rs9-candidate-fixture-NONPRODUCTION.gpg"):
            return True, CATEGORY_PUBLIC_KEY
        return False, ""

    # 4. Docs: docs/, docs/install, root doc files
    if parts[0] == "docs":
        if ext in DOC_EXTENSIONS or filename in ROOT_DOC_FILES or (len(parts) == 2 and parts[1] == "install"):
            return True, CATEGORY_DOCS
        return False, ""
    if len(parts) == 1 and filename in ROOT_DOC_FILES:
        return True, CATEGORY_DOCS

    # 5. Candidate public assets in documented directory structures only:
    # No broad suffix allowlist bypassing directory rules.

    # 5a. APT repository within the reviewed apt/ namespace only.
    apt_parts = parts[1:] if (parts[0] == "apt" and len(parts) > 1) else None
    if apt_parts is not None:
        if apt_parts[0] == "dists":
            if filename in APT_METADATA_FILES:
                return True, CATEGORY_CANDIDATE_ASSET
            if len(apt_parts) >= 3 and apt_parts[-3] == "by-hash" and apt_parts[-2] == "SHA256":
                if re.fullmatch(r"[0-9a-f]{64}", filename):
                    return True, CATEGORY_CANDIDATE_ASSET
            return False, ""

        if apt_parts[0] == "pool":
            if filename.endswith(".deb"):
                return True, CATEGORY_CANDIDATE_ASSET
            return False, ""

        if apt_parts[0] == "by-hash":
            if len(apt_parts) == 3 and apt_parts[1] == "SHA256" and re.fullmatch(r"[0-9a-f]{64}", filename):
                return True, CATEGORY_CANDIDATE_ASSET
            return False, ""

    # 5b. RPM repository:
    # Required prefix: rpm/fedora/43/{x86_64,aarch64}/{Packages,repodata} plus rpm/rs9.repo
    if rel_path == "rpm/rs9.repo":
        return True, CATEGORY_CANDIDATE_ASSET

    if parts[0] == "rpm" and len(parts) >= 5 and parts[1] == "fedora" and parts[2] == "43" and parts[3] in ("x86_64", "aarch64"):
        if len(parts) != 6:
            return False, ""
        sub_dir = parts[4]
        if sub_dir == "Packages":
            if filename.endswith(".rpm"):
                return True, CATEGORY_CANDIDATE_ASSET
            return False, ""
        if sub_dir == "repodata":
            if filename in {"repomd.xml", "repomd.xml.asc"} or filename.endswith((".xml", ".xml.gz")):
                return True, CATEGORY_CANDIDATE_ASSET
            return False, ""
        return False, ""

    # 5c. Pacman / Arch repository:
    # Required prefix: pacman/x86_64 packages/db/files and exact signatures
    PACMAN_EXTENSIONS = (
        ".pkg.tar.zst",
        ".pkg.tar.zst.sig",
        ".db",
        ".db.tar.gz",
        ".db.sig",
        ".db.tar.gz.sig",
        ".files",
        ".files.tar.gz",
        ".files.sig",
        ".files.tar.gz.sig",
    )
    if parts[0] == "pacman":
        if len(parts) == 3 and parts[1] == "x86_64" and filename.endswith(PACMAN_EXTENSIONS):
            return True, CATEGORY_CANDIDATE_ASSET
        return False, ""

    return False, ""


def _scan_file_content(
    path: Path, rel_path: str, category: str, max_size: int = 512 * 1024 * 1024
) -> tuple[str, int, dict[str, Any] | None]:
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
    filename = Path(rel_path).name

    # Check for private or secret key blocks across all files
    if b"PRIVATE KEY" in data or b"SECRET KEY" in data:
        text_preview = data.decode("utf-8", errors="replace")
        if PRIVATE_BLOCK_RE.search(text_preview) or "BEGIN PGP SECRET KEY BLOCK" in text_preview:
            raise ContractError("CREDENTIAL_DETECTED", "Private or secret key block detected")

    # Proven rpm/ar/deb/xz/zstd/gzip/tar containers are scanned member by member; the
    # raw prefix packet scan only stays for data whose container structure is not proven,
    # so a suffix or magic prefix alone can never exempt a file.
    format_scan = scan_binary_artifact(data, rel_path) if category == CATEGORY_CANDIDATE_ASSET else None
    if format_scan is None:
        check_no_secret_key_packets(data)
    if category == CATEGORY_PUBLIC_KEY:
        validate_openpgp_public_key(data)

    # Scan for credentials in text files
    if category in (CATEGORY_CNAME, CATEGORY_DOCS, CATEGORY_INDEX, CATEGORY_PUBLIC_KEY) or rel_path.endswith(
        (".txt", ".md", ".json", ".xml", ".html", ".css", ".js", ".repo")
    ):
        text = data.decode("utf-8", errors="replace")
        try:
            scan_for_credentials(text)
        except ContractError as err:
            raise ContractError(err.code, "Credential detected in pages file") from None

    return sha256, file_size, format_scan


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

            sha256, file_size, format_scan = _scan_file_content(file_path, rel_path, category)

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
            if format_scan is not None:
                found_files[rel_path]["format_scan"] = format_scan
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
