"""Causal Pages path diagnostics preserve rejection codes without private names."""
import hashlib
import tempfile
from pathlib import Path
import unittest

from rs9.errors import ContractError
from rs9.pages import pages_path_details, scan_pages_tree
from rs9.pages_candidate import REQUIRED_PAGES_FILES, verify_pages_completeness


class PagesFailureDetailsTests(unittest.TestCase):
    def test_rejected_zstd_path_has_public_cause(self):
        relative = "rpm/fedora/43/x86_64/repodata/primary.xml.zst"
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            path = root / relative
            path.parent.mkdir(parents=True)
            path.write_bytes(bytes.fromhex("28b52ffd"))
            with self.assertRaises(ContractError) as caught:
                scan_pages_tree(root)
        self.assertEqual(caught.exception.code, "DISALLOWED_FILE")
        self.assertEqual(caught.exception.details, {"substage": "pages-path-classification", "path": relative})

    def test_unsafe_display_names_only_retain_hash(self):
        for path in ("docs/private-key.pem", "docs/name\ncredential.txt", "/tmp/operator/file",
                     "docs/../../outside", "unknown/operator-file", "docs/" + "a" * 256):
            with self.subTest(path=path):
                details = pages_path_details("pages-path-classification", path)
                self.assertEqual(details, {"substage": "pages-path-classification",
                                          "path_sha256": hashlib.sha256(path.encode()).hexdigest()})

    def test_hidden_directory_and_unreviewed_root_keep_original_codes(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            (root / ".hidden").mkdir()
            with self.assertRaises(ContractError) as caught:
                scan_pages_tree(root)
            self.assertEqual(caught.exception.code, "DISALLOWED_FILE")
            self.assertEqual(caught.exception.details["substage"], "hidden-directory")
            self.assertIn("path_sha256", caught.exception.details)
        inventory = dict.fromkeys(REQUIRED_PAGES_FILES, "a" * 64)
        inventory["unreviewed/file"] = "a" * 64
        with self.assertRaises(ContractError) as caught:
            verify_pages_completeness(inventory, families=())
        self.assertEqual(caught.exception.code, "DISALLOWED_FILE")
        self.assertEqual(caught.exception.details["substage"], "top-level")
        self.assertIn("path_sha256", caught.exception.details)
