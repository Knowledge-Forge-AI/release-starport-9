"""Product hygiene without reading operator metadata or credentials."""

import ast
from pathlib import Path
import re
import sys
import unittest

from rs9.security import PRIVATE_BLOCK_RE, TOKEN_PATTERNS

ROOT = Path(__file__).resolve().parents[1]


def product_files():
    names = ("README.md", "LICENSE", "COMMERCIAL-LICENSE.md", "CLA.md", "NOTICE", "CONTRIBUTING.md", ".gitignore")
    files = {ROOT / name for name in names}
    for directory in (".github", "docs", "examples", "src", "tests"):
        files.update(path for path in (ROOT / directory).rglob("*") if path.is_file())
    files.add(ROOT / ".gitignore")
    return sorted(files)


class HygieneTests(unittest.TestCase):
    def test_product_contains_only_bounded_text(self):
        for path in product_files():
            if "__pycache__" in path.parts:
                continue
            self.assertFalse(path.is_symlink())
            data = path.read_bytes()
            self.assertLessEqual(len(data), 512 * 1024)
            self.assertFalse(data.startswith((b"\x7fELF", b"\x1f\x8b", b"\x89PNG", b"\xcf\xfa\xed\xfe")))
            self.assertNotIn(b"\x00", data)
            data.decode("utf-8")
    def test_no_private_keys_tokens_or_private_paths_in_product(self):
        private_path = re.compile(r"/Users/|/home/[^/\s]+/|[A-Z]:\\Users\\")
        for path in product_files():
            if "__pycache__" in path.parts:
                continue
            text = path.read_text(encoding="utf-8")
            with self.subTest(file=str(path.relative_to(ROOT))):
                self.assertIsNone(PRIVATE_BLOCK_RE.search(text), "Private key marker")
                for pattern in TOKEN_PATTERNS:
                    self.assertIsNone(pattern.search(text), "Token-shaped content")
                # Pattern source itself is intentionally piecewise below.
                if path.name != "test_hygiene.py":
                    self.assertIsNone(private_path.search(text), "Private path")

    def test_license_boundary_documented(self):
        self.assertIn("It does not relicense", (ROOT / "README.md").read_text())

    def test_source_uses_only_standard_library_and_rs9(self):
        for path in (ROOT / "src/rs9").glob("*.py"):
            tree = ast.parse(path.read_text())
            for node in ast.walk(tree):
                modules = [a.name for a in node.names] if isinstance(node, ast.Import) else [node.module] if isinstance(node, ast.ImportFrom) else []
                for module in modules:
                    self.assertIn(module.split(".")[0], sys.stdlib_module_names | {"rs9"})
        self.assertFalse((ROOT / "src/rs9/__main__.py").exists())
