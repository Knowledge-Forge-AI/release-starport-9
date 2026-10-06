"""Tests for read-only product delta and parent verification."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import Mock, patch

from rs9.candidate_inventory import MANIFEST, candidate_paths, file_inventory, product_delta, verify_inventory
from rs9.errors import ContractError

PARENT = "a09fcc21c68c292cd526033bb2ecebccf3167b90"


class CandidateInventoryTests(unittest.TestCase):
    def test_product_delta_requires_explicit_parent(self):
        root = Path(__file__).resolve().parents[1]
        for bad_parent in (None, "", "not-a-sha", "1" * 39, "1" * 41, 12345):
            with self.subTest(parent=bad_parent), self.assertRaises(ContractError) as caught:
                product_delta(root, bad_parent)
            self.assertEqual(caught.exception.code, "CANDIDATE_PARENT")

    def test_product_delta_read_only_git_diff_plus_untracked_minus_operational(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp).resolve()
            subprocess.run(["git", "init", "-b", "main"], cwd=repo, capture_output=True, check=True)
            subprocess.run(["git", "config", "user.name", "Test"], cwd=repo, capture_output=True, check=True)
            subprocess.run(["git", "config", "user.email", "test@example.com"], cwd=repo, capture_output=True, check=True)

            # Initial commit
            (repo / "tracked.txt").write_bytes(b"initial")
            (repo / "unchanged.txt").write_bytes(b"unchanged")
            subprocess.run(["git", "add", "-A"], cwd=repo, capture_output=True, check=True)
            subprocess.run(["git", "commit", "-m", "initial commit"], cwd=repo, capture_output=True, check=True)
            parent = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=repo).decode().strip()

            # Modifications, additions, and operational files
            (repo / "tracked.txt").write_bytes(b"modified")
            (repo / "src").mkdir()
            (repo / "src/new_file.py").write_bytes(b"print('new')")

            # Operational files to ignore
            (repo / ".serena").mkdir()
            (repo / ".serena/state.json").write_bytes(b"{}")
            (repo / ".pytest_cache").mkdir()
            (repo / ".pytest_cache/cache.json").write_bytes(b"{}")
            (repo / "src/__pycache__").mkdir()
            (repo / "src/__pycache__/compiled.pyc").write_bytes(b"\x00")
            (repo / "src/old.pyc").write_bytes(b"\x00")

            delta = product_delta(repo, parent)
            self.assertEqual(delta, ["src/new_file.py", "tracked.txt"])
            self.assertNotIn(".serena/state.json", delta)
            self.assertNotIn(".pytest_cache/cache.json", delta)
            self.assertNotIn("src/__pycache__/compiled.pyc", delta)
            self.assertNotIn("src/old.pyc", delta)

    def test_verify_inventory_explicit_parent_and_manifest_matching(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp).resolve()
            (repo / MANIFEST).parent.mkdir(parents=True)
            (repo / MANIFEST).write_bytes(b"{}")
            (repo / "file.txt").write_bytes(b"hello")

            manifest = {
                "parent": "1" * 40,
                "changed_paths": ["file.txt"],
                "files": file_inventory(repo, ["file.txt"]),
            }

            # Matching parent succeeds
            with patch("rs9.candidate_inventory.candidate_paths", return_value=["file.txt", MANIFEST]), patch("rs9.candidate_inventory.product_delta", return_value=["file.txt"]):
                tree = verify_inventory(repo, manifest, parent="1" * 40)
                self.assertRegex(tree, r"^[0-9a-f]{40}$")

            # Mismatched parent raises CANDIDATE_PARENT
            with self.assertRaises(ContractError) as caught:
                verify_inventory(repo, manifest, parent="2" * 40)
            self.assertEqual(caught.exception.code, "CANDIDATE_PARENT")

            # Missing parent argument when manifest has parent raises CANDIDATE_PARENT
            with self.assertRaises(ContractError) as caught:
                verify_inventory(repo, manifest)
            self.assertEqual(caught.exception.code, "CANDIDATE_PARENT")

            # Bad parent SHA raises CANDIDATE_PARENT
            with self.assertRaises(ContractError) as caught:
                verify_inventory(repo, manifest, parent="short")
            self.assertEqual(caught.exception.code, "CANDIDATE_PARENT")

    def test_manifest_matches_full_live_product_delta(self):
        root = Path(__file__).resolve().parents[1]
        if subprocess.run(["git", "-C", str(root), "cat-file", "-e", PARENT + "^{commit}"],
                          stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode:
            self.skipTest("public parent object absent in shallow checkout")
        manifest = json.loads((root / MANIFEST).read_bytes())
        self.assertEqual(manifest["parent"], PARENT)
        self.assertEqual(manifest["changed_paths"], product_delta(root, PARENT))
        self.assertIn("operators/live1/targets.json", manifest["changed_paths"])
        target = next(r for r in manifest["files"] if r["path"] == "operators/live1/targets.json")
        parent_target = subprocess.check_output(["git", "-C", str(root), "show", PARENT + ":operators/live1/targets.json"])
        self.assertNotEqual(target["sha256"], hashlib.sha256(parent_target).hexdigest())
        self.assertEqual(json.loads((root / target["path"]).read_bytes())["maintainer"],
                         "Knowledge Forge AI <nonproduction@knowledge-forge.invalid>")
        self.assertRegex(verify_inventory(root, manifest, parent=PARENT), r"^[0-9a-f]{40}$")

    def test_inventory_rejects_incomplete_changed_path_set(self):
        root = Path(__file__).resolve().parents[1]
        manifest = {"parent": PARENT, "changed_paths": [MANIFEST], "files": []}
        with patch("rs9.candidate_inventory.product_delta", return_value=[MANIFEST, "src/new.py"]):
            with self.assertRaises(ContractError) as caught:
                verify_inventory(root, manifest, parent=PARENT)
        self.assertEqual(caught.exception.code, "CANDIDATE_CHANGED")
