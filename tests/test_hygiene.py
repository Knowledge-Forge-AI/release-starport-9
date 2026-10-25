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
import tempfile
import unittest
from unittest.mock import patch
import warnings
import zipfile

from rs9.security import PRIVATE_BLOCK_RE, TOKEN_PATTERNS

ROOT = Path(__file__).resolve().parents[1]
LIMIT = 512 * 1024
HISTORICAL = {row["path"]: row for row in json.loads(
    (ROOT / "tests/fixtures/historical-binary-evidence.json").read_text())["files"]}


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


def file_texts(path, root=ROOT, historical=HISTORICAL):
    if any(p.is_symlink() for p in (path, *path.parents)):
        raise ValueError("Physical product file required")
    with path.open("rb") as stream:
        data = stream.read(LIMIT + 1)
    relative = path.relative_to(root).as_posix()
    record = historical.get(relative)
    if record is None:
        return [(relative, bounded_text(data))]
    if (len(data) != record["size"] or hashlib.sha256(data).hexdigest() != record["sha256"]
            or record["mode"] != "100644" or os.access(path, os.X_OK) or len(data) > LIMIT):
        raise ValueError("Historical evidence pin mismatch")
    return [(relative + ":" + name, text) for name, text in zip_texts(data)]


def scan_text(text, *, private_path=None, allow_pattern_source=False):
    if private_path is None:
        private_path = re.compile(r"/" + r"Users/|/" + r"home/[^/\s]+/|[A-Z]:\\" + r"Users\\")
    if PRIVATE_BLOCK_RE.search(text) or any(p.search(text) for p in TOKEN_PATTERNS):
        raise ValueError("Credential-shaped content")
    if not allow_pattern_source and private_path.search(text):
        raise ValueError("Private path")


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
                        scan_text(text, private_path=private_path,
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
