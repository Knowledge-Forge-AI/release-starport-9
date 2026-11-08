"""Product hygiene without reading operator metadata or credentials."""

import ast
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import struct
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import patch
import warnings
import zipfile

from rs9.security import PRIVATE_BLOCK_RE, TOKEN_PATTERNS
from rs9.pages import parse_openpgp_packets, validate_openpgp_public_key
from rs9.errors import ContractError

ROOT = Path(__file__).resolve().parents[1]
LIMIT = 512 * 1024
HISTORICAL = {row["path"]: row for row in json.loads(
    (ROOT / "tests/fixtures/historical-binary-evidence.json").read_text())["files"]}
PUBLIC_TRUST_INPUTS = {
    "src/rs9/_archarm_support/pins/archlinuxarm-builder-public.gpg": {
        "size": 3857,
        "sha256": "4e4202772328674af68f90f675e077d192337fc8ced15cddcd35875a9de5b5f9",
        "fingerprint": "68B3537F39A313B3E574D06777193F152BDBE6A6",
        "mode": "100644",
    },
}

# This closed exception covers one pinned public NativeRC fixture.  It
# is deliberately a complete byte/layout pin, rather than a suffix or archive
# type exemption.  The maintained hygiene scanner remains the authority for
# every decoded string.
NATIVE_ARCHIVE_RELATIVE = (
    "tests/fixtures/nebular-v0.8.0-native-evidence-run-42418673472-attempt-1.tar.gz"
)
NATIVE_INVENTORY_RELATIVE = NATIVE_ARCHIVE_RELATIVE.removesuffix(
    ".tar.gz"
) + "-inventory.json"
NATIVE_ARCHIVE_BYTES = 216591
NATIVE_ARCHIVE_SHA256 = "20f5aaf0dacad5437185981ab95448fb2f13f26001b19ac31fd83ac324795640"
NATIVE_INVENTORY_BYTES = 17681
NATIVE_INVENTORY_SHA256 = "89067774cbdf7b4ce931e3df6b08029bdee97873b8083460fd5b249ee4f5ec72"
NATIVE_MEMBER_COUNT = 68
NATIVE_SOURCE_BYTES = 1514913
NATIVE_INDEX_MEMBER = "rc-index-original.zip"
NATIVE_INDEX_BYTES = 3076
NATIVE_INDEX_SHA256 = "1c5ce07befdb8907a36e808f55d7c43f9f5efef7ba33a3f1371d227e5a853d26"
NATIVE_INDEX_JSON_MEMBER = "rc-index.json"
NATIVE_INDEX_JSON_BYTES = 13991

# The five values are exact public hosted-runner executable paths.  A value is
# admissible only when its containing member, inventory row hash, JSON key path,
# and value hash all match this table.  The value itself is still scanned by the
# original credential and path scanners; only its exact path-match count is
# accounted for.
NATIVE_PUBLIC_PATH_FIELDS = frozenset({
    (
        "macos-arm64/smoke/darwin-arm64-A-npm-package.receipt.json",
        "9a05282c75b8b2c7970bc78a51d19eb6a36f2b012b484bf8cd29797f9e6fbfad",
        "executable.path",
        "55da0ae0a9a9db7f08a9cf83e3153137d53fc1769a9b797d80f97e31a0d4d3e1",
    ),
    (
        "macos-arm64/smoke/darwin-arm64-A-raw-archive.receipt.json",
        "78b3724ad8880a87812b78c3d037f6b7bebcc3c1434559fa9345efd66942d13e",
        "executable.path",
        "1f5c9adb7c5b6f7767fdaa52e160edb25b9634233ab46144055659e6ebb816b4",
    ),
    (
        "macos-arm64/smoke/darwin-arm64-appearance-pair-raw.phases/darwin-arm64-P-restart-raw.receipt.json",
        "1b7f67f30ff340a5bdb145519bfe87f870ce3375d62fbe17ab2b684970c8ed68",
        "executable.path",
        "1f5c9adb7c5b6f7767fdaa52e160edb25b9634233ab46144055659e6ebb816b4",
    ),
    (
        "macos-arm64/smoke/darwin-arm64-appearance-pair-raw.phases/darwin-arm64-P-save-raw.receipt.json",
        "297981808fc283207c35d763c853743658aec1f9d1305488be2078753f0c8756",
        "executable.path",
        "1f5c9adb7c5b6f7767fdaa52e160edb25b9634233ab46144055659e6ebb816b4",
    ),
    (
        "macos-arm64/smoke/darwin-arm64-paired-v2-raw-archive.receipt.json",
        "5eaab40d6fd42e1f73e1cfac16b5523f09eccdeea687a4c900363dcc862f8079",
        "executable.path",
        "1f5c9adb7c5b6f7767fdaa52e160edb25b9634233ab46144055659e6ebb816b4",
    ),
})
_NATIVE_ROW_HASHES = {
    member: row_hash for member, row_hash, _keypath, _value_hash in NATIVE_PUBLIC_PATH_FIELDS
}


def product_files(root=ROOT):
    names = ("README.md", "LICENSE", "COMMERCIAL-LICENSE.md", "CLA.md", "NOTICE", "CONTRIBUTING.md", ".gitignore")
    files = {root / name for name in names}
    for directory in (".github", "docs", "examples", "src", "tests", "bootstrap", "nix", "operators", "evidence"):
        files.update(path for path in (root / directory).rglob("*") if path.is_file() or path.is_symlink())
    files.add(root / ".gitignore")
    files.update(p for p in (root/"flake.nix", root/"flake.lock") if p.is_file())
    return sorted(files)


def bounded_text(data):
    if len(data) > LIMIT or b"\x00" in data or data.startswith(
            (b"\x7fELF", b"\x1f\x8b", b"\x89PNG", b"\xcf\xfa\xed\xfe")):
        raise ValueError("Expected bounded text")
    return data.decode("utf-8")


def zip_texts(data):
    """Inspect members without extraction; bound actual decompression, not just headers."""
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        members = archive.infolist()
        if not 1 <= len(members) <= 64 or archive.comment:
            raise ValueError("ZIP count or comment")
        # These historical ZIPs use neither ZIP64 nor data descriptors. Require a
        # complete, contiguous local/central directory with no prefix or trailer.
        end = data.rfind(b"PK\x05\x06")
        if end < 0 or end + 22 != len(data):
            raise ValueError("ZIP trailer")
        disk, central_disk, count, total_count, size, offset, comment = struct.unpack_from("<4H2LH", data, end + 4)
        if (disk or central_disk or count != len(members) or total_count != count
                or comment or offset != archive.start_dir or offset + size != end):
            raise ValueError("ZIP directory")
        seen = set()
        total = 0
        next_offset = 0
        for member in members:
            name = member.filename
            parts = name.split("/")
            if (not name or member.orig_filename != name or PurePosixPath(name).is_absolute() or "\\" in name or ":" in name
                    or any(p in ("", ".", "..") for p in parts)
                    or any(ord(c) < 32 or ord(c) == 127 for c in name) or name in seen):
                raise ValueError("Unsafe ZIP member name")
            seen.add(name)
            kind = stat.S_IFMT(member.external_attr >> 16)
            if (kind not in (0, stat.S_IFREG) or member.is_dir() or member.extra or member.comment
                    or member.flag_bits & ~0x800
                    or member.compress_type not in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED)
                    or member.file_size > LIMIT or member.header_offset != next_offset):
                raise ValueError("Unsafe ZIP member metadata")
            if data[next_offset:next_offset + 4] != b"PK\x03\x04":
                raise ValueError("ZIP local header")
            name_size, extra_size = struct.unpack_from("<HH", data, next_offset + 26)
            if extra_size:
                raise ValueError("ZIP local extra data")
            next_offset += 30 + name_size + extra_size + member.compress_size
            with archive.open(member) as stream:
                body = stream.read(LIMIT + 1)
            total += len(body)
            if total > 2 * 1024 * 1024 or len(body) != member.file_size:
                raise ValueError("ZIP decompressed size")
            yield name, bounded_text(body)
        if next_offset != archive.start_dir:
            raise ValueError("ZIP extra local data")


def _native_safe_member(name):
    parts = name.split("/")
    return bool(name) and PurePosixPath(name).as_posix() == name and not (
        PurePosixPath(name).is_absolute()
        or "\\" in name
        or ":" in name
        or any(part in ("", ".", "..") for part in parts)
        or any(ord(char) < 32 or ord(char) == 127 for char in name)
    )


def _native_exact_file(path, size, sha256):
    try:
        if any(item.is_symlink() for item in (path, *path.parents)):
            raise ValueError("Physical NativeRC fixture required")
        with path.open("rb") as stream:
            data = stream.read(LIMIT + 1)
    except OSError as error:
        raise ValueError("NativeRC fixture unreadable") from error
    if len(data) != size or hashlib.sha256(data).hexdigest() != sha256:
        raise ValueError("NativeRC fixture pin mismatch")
    try:
        metadata_bad = stat.S_IMODE(path.stat().st_mode) != 0o644 or os.access(path, os.X_OK)
    except OSError as error:
        raise ValueError("NativeRC fixture unreadable") from error
    if metadata_bad:
        raise ValueError("NativeRC fixture metadata mismatch")
    return data


def _native_inventory(root):
    data = _native_exact_file(root / NATIVE_INVENTORY_RELATIVE,
                              NATIVE_INVENTORY_BYTES, NATIVE_INVENTORY_SHA256)
    try:
        inventory = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError("NativeRC inventory JSON required") from error
    rows = inventory.get("files")
    archive = inventory.get("archive")
    if not isinstance(rows, list) or len(rows) != NATIVE_MEMBER_COUNT or not isinstance(archive, dict):
        raise ValueError("NativeRC inventory shape mismatch")
    if (archive.get("archive_bytes") != NATIVE_ARCHIVE_BYTES
            or archive.get("file_count") != NATIVE_MEMBER_COUNT
            or archive.get("filename") != NATIVE_ARCHIVE_RELATIVE.rsplit("/", 1)[-1]
            or archive.get("sha256") != NATIVE_ARCHIVE_SHA256
            or archive.get("source_bytes") != NATIVE_SOURCE_BYTES):
        raise ValueError("NativeRC inventory archive pin mismatch")
    seen = set()
    total = 0
    normalized = []
    for row in rows:
        if set(row) != {"bytes", "path", "role", "sha256"}:
            raise ValueError("NativeRC inventory row shape mismatch")
        path = row["path"]
        if (not isinstance(path, str) or not _native_safe_member(path) or path in seen
                or not isinstance(row["role"], str) or not row["role"]
                or type(row["bytes"]) is not int or row["bytes"] < 0
                or row["bytes"] > LIMIT
                or not isinstance(row["sha256"], str)
                or not re.fullmatch(r"[0-9a-f]{64}", row["sha256"])):
            raise ValueError("NativeRC inventory row value mismatch")
        seen.add(path)
        total += row["bytes"]
        normalized.append((path, row["bytes"], row["sha256"], row["role"]))
    if total != NATIVE_SOURCE_BYTES:
        raise ValueError("NativeRC inventory source size mismatch")
    return normalized


def _native_index_text(data):
    if len(data) != NATIVE_INDEX_BYTES or hashlib.sha256(data).hexdigest() != NATIVE_INDEX_SHA256:
        raise ValueError("NativeRC nested index pin mismatch")
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            members = archive.infolist()
            if archive.comment or len(members) != 1:
                raise ValueError("NativeRC nested index shape mismatch")
            member = members[0]
            if (member.filename != NATIVE_INDEX_JSON_MEMBER
                    or member.orig_filename != NATIVE_INDEX_JSON_MEMBER
                    or member.flag_bits != 8
                    or member.compress_type != zipfile.ZIP_DEFLATED
                    or member.extra or member.comment
                    or member.file_size != NATIVE_INDEX_JSON_BYTES
                    or member.compress_size > member.file_size
                    or member.header_offset != 0
                    or stat.S_IFMT(member.external_attr >> 16) != stat.S_IFREG
                    or (member.external_attr >> 16) & 0o777 != 0o644):
                raise ValueError("NativeRC nested index metadata mismatch")
            if data[:4] != b"PK\x03\x04":
                raise ValueError("NativeRC nested index local header mismatch")
            name_size, extra_size = struct.unpack_from("<HH", data, 26)
            data_start = 30 + name_size + extra_size
            descriptor_start = data_start + member.compress_size
            descriptor_end = descriptor_start + 16
            if (extra_size or name_size != len(NATIVE_INDEX_JSON_MEMBER)
                    or data[30:30 + name_size].decode("utf-8") != NATIVE_INDEX_JSON_MEMBER
                    or archive.start_dir != descriptor_end
                    or data[descriptor_start:descriptor_end][:4] != b"PK\x07\x08"
                    or struct.unpack_from("<3L", data, descriptor_start + 4)
                    != (member.CRC, member.compress_size, member.file_size)
                    or archive.start_dir + 46 + name_size + 22 != len(data)):
                raise ValueError("NativeRC nested index directory mismatch")
            with archive.open(member) as stream:
                body = stream.read(LIMIT + 1)
            if len(body) != NATIVE_INDEX_JSON_BYTES:
                raise ValueError("NativeRC nested index size mismatch")
            return bounded_text(body)
    except (OSError, ValueError, zipfile.BadZipFile, struct.error, UnicodeDecodeError) as error:
        if isinstance(error, ValueError) and str(error).startswith("NativeRC"):
            raise
        raise ValueError("NativeRC nested index unreadable") from error


def _native_json_strings(value, keypath=""):
    if isinstance(value, dict):
        for key, child in value.items():
            path = f"{keypath}.{key}" if keypath else str(key)
            yield from _native_json_strings(child, path)
    elif isinstance(value, list):
        for index, child in enumerate(value):
            yield from _native_json_strings(child, f"{keypath}[{index}]")
    elif isinstance(value, str):
        yield keypath, value


def _native_public_path_allowance(name, text, private_path):
    prefix = NATIVE_ARCHIVE_RELATIVE + ":"
    if not name.startswith(prefix):
        return 0
    member = name[len(prefix):]
    if ":" in member or member not in _NATIVE_ROW_HASHES:
        return 0
    if hashlib.sha256(text.encode("utf-8")).hexdigest() != _NATIVE_ROW_HASHES[member]:
        raise ValueError("NativeRC public path member pin mismatch")
    try:
        value = json.loads(text)
    except json.JSONDecodeError:
        return 0
    allowance = 0
    for keypath, string in _native_json_strings(value):
        candidate = (member, _NATIVE_ROW_HASHES[member], keypath,
                     hashlib.sha256(string.encode("utf-8")).hexdigest())
        if candidate in NATIVE_PUBLIC_PATH_FIELDS:
            matches = private_path.findall(string)
            if not matches:
                raise ValueError("NativeRC public path classification mismatch")
            allowance += len(matches)
    return allowance


def native_evidence_texts(relative, data, root):
    """Decode only the exact public capsule with bounded in-memory reads."""
    if (relative != NATIVE_ARCHIVE_RELATIVE or len(data) != NATIVE_ARCHIVE_BYTES
            or hashlib.sha256(data).hexdigest() != NATIVE_ARCHIVE_SHA256):
        raise ValueError("NativeRC archive pin mismatch")
    archive_path = root / NATIVE_ARCHIVE_RELATIVE
    try:
        archive_metadata_bad = (
            any(item.is_symlink() for item in (archive_path, *archive_path.parents))
            or stat.S_IMODE(archive_path.stat().st_mode) != 0o644
            or os.access(archive_path, os.X_OK)
        )
    except OSError as error:
        raise ValueError("NativeRC archive unreadable") from error
    if archive_metadata_bad:
        raise ValueError("NativeRC archive metadata mismatch")
    rows = _native_inventory(root)
    if len(rows) != NATIVE_MEMBER_COUNT:
        raise ValueError("NativeRC member count mismatch")
    row_names = [row[0] for row in rows]
    texts = []
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as archive:
        members = archive.getmembers()
        if len(members) != NATIVE_MEMBER_COUNT or [member.name for member in members] != row_names:
            raise ValueError("NativeRC TAR layout mismatch")
        for member, (name, expected_bytes, expected_sha256, _role) in zip(members, rows):
            if (member.name != name or member.type != tarfile.REGTYPE or member.mode != 0o644
                    or member.uid != 0 or member.gid != 0 or member.mtime != 0
                    or member.uname or member.gname or member.pax_headers
                    or member.size != expected_bytes):
                raise ValueError("NativeRC TAR metadata mismatch")
            stream = archive.extractfile(member)
            if stream is None:
                raise ValueError("NativeRC TAR regular file required")
            body = stream.read(LIMIT + 1)
            if (len(body) != expected_bytes
                    or hashlib.sha256(body).hexdigest() != expected_sha256):
                raise ValueError("NativeRC TAR row pin mismatch")
            if name == NATIVE_INDEX_MEMBER:
                texts.append((relative + ":" + name + ":" + NATIVE_INDEX_JSON_MEMBER,
                              _native_index_text(body)))
            else:
                texts.append((relative + ":" + name, bounded_text(body)))
    if sum(row[1] for row in rows) != NATIVE_SOURCE_BYTES:
        raise ValueError("NativeRC source size mismatch")
    return texts


def public_trust_texts(relative, data, record):
    """Inspect one pinned public certificate with the existing strict parser."""
    if (set(record) != {"size", "sha256", "fingerprint", "mode"}
            or record["mode"] != "100644" or len(data) > LIMIT
            or len(data) != record["size"]
            or hashlib.sha256(data).hexdigest() != record["sha256"]):
        raise ValueError("Public trust input pin mismatch")
    validate_openpgp_public_key(data)
    scan_text(data.decode("latin-1"))
    packets = parse_openpgp_packets(data, strict=True)
    primary = [body for tag, body in packets if tag == 6]
    if len(primary) != 1 or not primary[0] or primary[0][0] != 4 or len(primary[0]) > 65535:
        raise ValueError("Pinned public primary identity required")
    fingerprint = hashlib.sha1(b"\x99" + len(primary[0]).to_bytes(2, "big") + primary[0]).hexdigest().upper()
    if fingerprint != record["fingerprint"]:
        raise ValueError("Public trust input fingerprint mismatch")
    texts = [(relative + ":public-identity", json.dumps(record, sort_keys=True))]
    texts.extend((relative + ":uid-" + str(i), bounded_text(body))
                 for i, (tag, body) in enumerate(packets) if tag == 13)
    return texts


def file_texts(path, root=ROOT, historical=HISTORICAL, *, public_inputs=PUBLIC_TRUST_INPUTS):
    if any(p.is_symlink() for p in (path, *path.parents)):
        raise ValueError("Physical product file required")
    with path.open("rb") as stream:
        data = stream.read(LIMIT + 1)
    relative = path.relative_to(root).as_posix()
    if relative in public_inputs:
        if (relative in historical or stat.S_IMODE(path.stat().st_mode) != 0o644
                or os.access(path, os.X_OK)):
            raise ValueError("Public trust input file metadata mismatch")
        return public_trust_texts(relative, data, public_inputs[relative])
    if relative == NATIVE_ARCHIVE_RELATIVE:
        return native_evidence_texts(relative, data, root)
    record = historical.get(relative)
    if record is None:
        return [(relative, bounded_text(data))]
    if (len(data) != record["size"] or hashlib.sha256(data).hexdigest() != record["sha256"]
            or record["mode"] != "100644" or os.access(path, os.X_OK) or len(data) > LIMIT):
        raise ValueError("Historical evidence pin mismatch")
    return [(relative + ":" + name, text) for name, text in zip_texts(data)]


def scan_text(text, *, private_path=None, allow_pattern_source=False,
              allowed_private_match_count=0):
    if private_path is None:
        private_path = re.compile(r"/" + r"Users/|/" + r"home/[^/\s]+/|[A-Z]:\\" + r"Users\\")
    if PRIVATE_BLOCK_RE.search(text) or any(p.search(text) for p in TOKEN_PATTERNS):
        raise ValueError("Credential-shaped content")
    if not allow_pattern_source:
        matches = private_path.findall(text)
        if len(matches) != allowed_private_match_count:
            raise ValueError("Private path")


def scan_file_text(name, text, *, private_path=None, allow_pattern_source=False):
    if private_path is None:
        private_path = re.compile(r"/" + r"Users/|/" + r"home/[^/\s]+/|[A-Z]:\\" + r"Users\\")
    allowance = _native_public_path_allowance(name, text, private_path)
    scan_text(text, private_path=private_path,
              allow_pattern_source=allow_pattern_source,
              allowed_private_match_count=allowance)


def import_roots(node):
    if isinstance(node, ast.Import):
        return [alias.name.split(".", 1)[0] for alias in node.names]
    if isinstance(node, ast.ImportFrom):
        if node.level:
            return ["rs9"]
        return [node.module.split(".", 1)[0]] if node.module else []
    return []


class HygieneTests(unittest.TestCase):
    root = ROOT

    def test_product_contains_only_bounded_text(self):
        for path in product_files(self.root):
            if "__pycache__" in path.parts:
                continue
            with self.subTest(file=path.relative_to(self.root).as_posix()):
                file_texts(path, self.root)
    def test_no_private_keys_tokens_or_private_paths_in_product(self):
        private_path = re.compile(r"/Users/|/home/[^/\s]+/|[A-Z]:\\Users\\")
        for path in product_files(self.root):
            if "__pycache__" in path.parts:
                continue
            with self.subTest(file=str(path.relative_to(self.root))):
                for name, text in file_texts(path, self.root):
                    with self.subTest(member=name):
                        scan_file_text(name, text, private_path=private_path,
                                       allow_pattern_source=path.name == "test_hygiene.py" and ":" not in name)

    def test_license_boundary_documented(self):
        self.assertIn("It does not relicense", (ROOT / "README.md").read_text())

    def test_source_uses_only_standard_library_and_rs9(self):
        for path in (ROOT / "src/rs9").glob("*.py"):
            tree = ast.parse(path.read_text())
            for node in ast.walk(tree):
                for module in import_roots(node):
                    self.assertIn(module, sys.stdlib_module_names | {"rs9"})
        self.assertFalse((ROOT / "src/rs9/__main__.py").exists())

    def test_relative_import_roots_are_package_local(self):
        cases = (
            ("from . import X", ["rs9"]),
            ("from .name import X", ["rs9"]),
            ("from ..name import X", ["rs9"]),
            ("import json", ["json"]),
            ("from tf_pypi_model import X", ["tf_pypi_model"]),
        )
        for text, expected in cases:
            with self.subTest(source=text):
                node = ast.parse(text).body[0]
                self.assertEqual(import_roots(node), expected)
        allowed = sys.stdlib_module_names | {"rs9"}
        self.assertFalse(set(import_roots(ast.parse("from tf_pypi_model import X").body[0])).issubset(allowed))


class PublicTrustInputTests(unittest.TestCase):
    relative = next(iter(PUBLIC_TRUST_INPUTS))

    def key(self):
        return (ROOT / self.relative).read_bytes()

    def check(self, data, *, relative=None, mode=0o644, record=None):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            path = root / (relative or self.relative)
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)
            path.chmod(mode)
            inputs = PUBLIC_TRUST_INPUTS if record is None else {self.relative: record}
            texts = file_texts(path, root, {}, public_inputs=inputs)
            for _, text in texts:
                scan_text(text)
            return texts

    def repinned(self, data):
        return {**PUBLIC_TRUST_INPUTS[self.relative], "size": len(data),
                "sha256": hashlib.sha256(data).hexdigest()}

    def test_exact_existing_public_key_has_expected_identity_and_scanned_uids(self):
        texts = self.check(self.key())
        self.assertEqual(json.loads(texts[0][1])["fingerprint"], PUBLIC_TRUST_INPUTS[self.relative]["fingerprint"])
        self.assertTrue(any(":uid-" in name for name, _ in texts))

    def test_changed_unlisted_executable_and_wrong_identity_refuse(self):
        data = self.key()
        for body, kwargs in ((data + b"x", {}), (data, {"relative": "other.gpg"}),
                             (data, {"mode": 0o755}),
                             (data, {"record": {**PUBLIC_TRUST_INPUTS[self.relative], "fingerprint": "0" * 40}})):
            with self.subTest(kwargs=tuple(kwargs)), self.assertRaises((ValueError, ContractError)):
                self.check(body, **kwargs)

    def test_secret_packets_malformed_packets_and_trailers_never_bypass_parser(self):
        for suffix in (b"\xc5\x00", b"\xc7\x00", b"\xc6\xe0", b"\xfc\x00", b"\x00"):
            body = self.key() + suffix
            with self.subTest(suffix=suffix.hex()), self.assertRaises((ValueError, ContractError)):
                self.check(body, record=self.repinned(body))

    def test_public_uid_text_still_receives_existing_credential_and_path_scan(self):
        for text in (("/" + "Users/" + "synthetic/fixture").encode(),
                     ("ghp" + "_" + "a" * 36).encode()):
            for tag in (2, 13, 17):
                body = self.key() + bytes([0xc0 | tag, len(text)]) + text
                with self.subTest(size=len(text), packet=tag), self.assertRaises(ValueError):
                    self.check(body, record=self.repinned(body))


class HistoricalEvidenceTests(unittest.TestCase):
    def archive(self, rows, *, trailer=b"", extra=b"", comment=b""):
        stream = io.BytesIO()
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", UserWarning)
            with zipfile.ZipFile(stream, "w", compression=zipfile.ZIP_DEFLATED) as archive:
                archive.comment = comment
                for name, body, mode in rows:
                    member = zipfile.ZipInfo(name)
                    member.external_attr = mode << 16
                    member.extra = extra
                    archive.writestr(member, body)
        return stream.getvalue() + trailer

    def check(self, data, *, listed=True, changed=False):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            path = root / "fixture.zip"
            record = {"path": path.name, "size": len(data), "sha256": hashlib.sha256(data).hexdigest(), "mode": "100644"}
            path.write_bytes(data + b"x" if changed else data)
            for _, text in file_texts(path, root, {path.name: record} if listed else {}):
                scan_text(text)

    def test_exact_pins_and_unlisted_binary_refusal(self):
        data = self.archive([("safe.txt", b"bounded text\n", stat.S_IFREG | 0o644)])
        self.check(data)
        for options in ({"changed": True}, {"listed": False}):
            with self.subTest(options=options), self.assertRaises(ValueError):
                self.check(data, **options)

    def test_member_safety_and_content_negatives(self):
        secret_path = ("/" + "Users/" + "synthetic/fixture").encode()
        token = ("ghp" + "_" + "a" * 36).encode()
        key = ("-----" + "BEGIN " + "PRIVATE KEY-----").encode()
        cases = [
            [("link", b"target", stat.S_IFLNK | 0o777)],
            [("text", b"\xff", stat.S_IFREG | 0o644)],
            [("text", secret_path, stat.S_IFREG | 0o644)],
            [("text", token, stat.S_IFREG | 0o644)],
            [("text", key, stat.S_IFREG | 0o644)],
            [("../outside", b"text", stat.S_IFREG | 0o644)],
            [("same", b"a", 0o600), ("same", b"b", 0o600)],
            [("large", b"x" * (LIMIT + 1), 0o600)],
            [("text", b"\x00", 0o600)],
        ]
        for index, rows in enumerate(cases):
            with self.subTest(case=index), self.assertRaises(ValueError):
                self.check(self.archive(rows))
        for options in ({"trailer": b"extra"}, {"extra": b"\x01\x00\x00\x00"}, {"comment": b"extra"}):
            with self.subTest(options=sorted(options)), self.assertRaises(ValueError):
                self.check(self.archive([("text", b"safe", 0o600)], **options))

    def test_symlink_file_and_directory_are_never_exempt(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            (root / "tests").mkdir()
            target = root / "target"; target.mkdir()
            (target / "text").write_text("safe")
            for name, destination in (("link", target / "text"), ("directory", target)):
                link = root / "tests" / name
                link.symlink_to(destination)
                self.assertIn(link, product_files(root))
                with self.assertRaises(ValueError):
                    file_texts(link, root, {})

    def test_encryption_compression_and_actual_decompression_limits(self):
        original = self.archive([("text", b"safe", 0o600)])
        with zipfile.ZipFile(io.BytesIO(original)) as archive:
            central = archive.start_dir
        for local_offset, central_offset, value in ((6, central + 8, 1), (8, central + 10, 99)):
            data = bytearray(original)
            struct.pack_into("<H", data, local_offset, value)
            struct.pack_into("<H", data, central_offset, value)
            with self.subTest(value=value), self.assertRaises(ValueError):
                self.check(bytes(data))
        with patch("zipfile.ZipExtFile.read", return_value=b"x" * (LIMIT + 1)), self.assertRaises(ValueError):
            self.check(original)

    def test_bad_file_does_not_abort_later_scans(self):
        secret_path = ("/" + "Users/" + "synthetic/fixture").encode()
        for method, later in (("test_product_contains_only_bounded_text", b"\x00"),
                              ("test_no_private_keys_tokens_or_private_paths_in_product", secret_path)):
            with self.subTest(method=method), tempfile.TemporaryDirectory() as directory:
                root = Path(directory).resolve()
                for path in product_files(root):
                    path.parent.mkdir(parents=True, exist_ok=True)
                    path.write_text("safe")
                for name, body in (("docs/first.bin", b"\xff"), ("tests/later.bin", later)):
                    path = root / name
                    path.parent.mkdir(parents=True, exist_ok=True)
                    path.write_bytes(body)
                case = HygieneTests(method)
                case.root = root
                result = unittest.TestResult()
                case.run(result)
                self.assertEqual(len(result.errors), 2)
                self.assertTrue(any("docs/first.bin" in test.id() for test, _ in result.errors))
                self.assertTrue(any("tests/later.bin" in test.id() for test, _ in result.errors))
