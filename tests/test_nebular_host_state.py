"""Unit tests for bounded non-enumerating Nebular Darwin host-state observer."""
from __future__ import annotations

import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from rs9.nebular_host_state import (
    APPLICATION_IDENTIFIER,
    BASES,
    HostStateError,
    NAMES,
    SUFFIXES,
    compare_snapshots,
    public_summary,
    snapshot,
    target_relatives,
    verify_harness_targets,
)
from rs9.tf_pypi_archive import AdmissionError


class NebularHostStateTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name).resolve()
        self.fake_home = self.root / "operator_home"
        self.fake_home.mkdir()
        for base in BASES:
            (self.fake_home / base).mkdir(parents=True, exist_ok=True)

    def test_exact_63_target_set_and_clean_pass(self) -> None:
        self.assertEqual(len(BASES), 7)
        self.assertEqual(len(NAMES), 3)
        self.assertEqual(len(SUFFIXES), 3)
        rels = target_relatives()
        self.assertEqual(len(rels), 63)

        before = snapshot(self.fake_home)
        self.assertEqual(before["target_count"], 63)
        self.assertEqual(before["existing_targets"], 0)
        self.assertEqual(before["inventory_entries"], 63)

        after = snapshot(self.fake_home)
        comp = compare_snapshots(before, after)
        self.assertTrue(comp["unchanged"])
        self.assertEqual(comp["changed_target_indices"], [])
        self.assertEqual(comp["sha256"], comp["after_sha256"])

        summary = public_summary(before)
        raw = json.dumps(summary)
        self.assertNotIn(str(self.fake_home), raw)

    def test_never_enumerates_shared_library_parent_directories(self) -> None:
        (self.fake_home / "Library/Preferences/com.apple.Finder.plist").write_bytes(b"unrelated")
        (self.fake_home / "Library/Caches/com.apple.Safari").mkdir()
        (self.fake_home / "Library/Application Support/UnrelatedApp").mkdir()

        real_scandir = os.scandir
        forbidden_parents = {(self.fake_home / base).resolve() for base in BASES}

        def guarded_scandir(path=None):
            if isinstance(path, (str, os.PathLike)):
                resolved = Path(path).resolve()
                if resolved in forbidden_parents:
                    raise AssertionError(f"Forbidden parent directory enumeration: {resolved}")
            return real_scandir(path)

        with patch("os.scandir", side_effect=guarded_scandir), patch(
            "os.listdir", side_effect=AssertionError("os.listdir must not be used on parent dirs")
        ):
            snap = snapshot(self.fake_home)
        self.assertEqual(snap["target_count"], 63)
        self.assertEqual(snap["existing_targets"], 0)

    def test_preexisting_unchanged_targets_pass_and_mutations_fail_closed(self) -> None:
        app_dir = self.fake_home / f"Library/Application Support/{APPLICATION_IDENTIFIER}"
        app_dir.mkdir(parents=True)
        state_file = app_dir / "settings.json"
        state_file.write_bytes(b'{"theme":"nebular"}\n')
        webkit_dir = self.fake_home / f"Library/WebKit/{APPLICATION_IDENTIFIER}/secret-origin.example.com"
        webkit_dir.mkdir(parents=True)
        (webkit_dir / "localstorage.sqlite3").write_bytes(b"sqlite")
        pref_file = self.fake_home / f"Library/Preferences/{APPLICATION_IDENTIFIER}.plist"
        pref_file.write_bytes(b"plist-v1")

        before = snapshot(self.fake_home)
        self.assertEqual(before["existing_targets"], 3)
        serialized_entries = json.dumps(before["entries"])
        self.assertNotIn("settings.json", serialized_entries)
        self.assertNotIn("secret-origin.example.com", serialized_entries)
        self.assertNotIn("localstorage.sqlite3", serialized_entries)
        self.assertTrue(
            any("/sha256:" in k for k in before["entries"]),
            "Descendant keys must use sha256:... hashing",
        )

        # Unchanged pass
        unchanged = snapshot(self.fake_home)
        comp = compare_snapshots(before, unchanged)
        self.assertTrue(comp["unchanged"])

        # Content mutation fails closed
        state_file.write_bytes(b'{"theme":"mutated"}\n')
        after_mod = snapshot(self.fake_home)
        with self.assertRaises(HostStateError) as ctx:
            compare_snapshots(before, after_mod)
        self.assertEqual(ctx.exception.code, "TF_PYPI_HOST_STATE_DRIFT")
        self.assertIsNotNone(ctx.exception.target_index)
        self.assertNotIn(str(self.fake_home), json.dumps(ctx.exception.public_details()))

        # Restore and test new target creation failure
        state_file.write_bytes(b'{"theme":"nebular"}\n')
        new_cache = self.fake_home / "Library/Caches/theme-forge-nebular-fusion"
        new_cache.mkdir()
        after_new = snapshot(self.fake_home)
        with self.assertRaises(HostStateError) as ctx2:
            compare_snapshots(before, after_new)
        self.assertEqual(ctx2.exception.code, "TF_PYPI_HOST_STATE_DRIFT")

    def test_rejects_symlinks_in_home_ancestry_or_parent_and_hashes_target_symlinks(self) -> None:
        # 1. Symlinked home root rejected
        sym_home = self.root / "sym_home"
        sym_home.symlink_to(self.fake_home, target_is_directory=True)
        with self.assertRaises(HostStateError) as ctx:
            snapshot(sym_home)
        self.assertEqual(ctx.exception.code, "TF_PYPI_HOST_STATE_SYMLINK_ANCESTOR")

        # 2. Symlinked Library/Caches parent rejected
        caches_dir = self.fake_home / "Library/Caches"
        caches_dir.rmdir()
        real_caches = self.root / "real_caches"
        real_caches.mkdir()
        caches_dir.symlink_to(real_caches, target_is_directory=True)
        with self.assertRaises(HostStateError) as ctx2:
            snapshot(self.fake_home)
        self.assertEqual(ctx2.exception.code, "TF_PYPI_HOST_STATE_SYMLINK_ANCESTOR")
        caches_dir.unlink()
        caches_dir.mkdir()

        # 3. Symlink at target path is recorded by link_target_sha256 without following
        sym_target = self.fake_home / "Library/Caches/theme-forge-nebular-fusion"
        sym_target.symlink_to("/nonexistent/target")
        snap_sym = snapshot(self.fake_home)
        self.assertEqual(
            snap_sym["entries"]["Library/Caches/theme-forge-nebular-fusion"]["kind"],
            "symlink",
        )

    def test_verify_harness_targets_validates_smoke_mjs_63_target_contract(self) -> None:
        smoke_mjs = self.root / "native-rc-smoke.mjs"
        smoke_mjs.write_text(
            'export const APPLICATION_IDENTIFIER = "ai.knowledgeforge.themeforge.nebularfusion";\n'
            "export function persistentStateLocations(platform, home = homedir()) {\n"
            '  const names = [APPLICATION_IDENTIFIER, "Theme Forge Nebular Fusion", "theme-forge-nebular-fusion"];\n'
            '  const bases = platform.startsWith("darwin") ? [\n'
            '    "Library/Caches",\n'
            '    "Library/Application Support",\n'
            '    "Library/WebKit",\n'
            '    "Library/Logs",\n'
            '    "Library/HTTPStorages",\n'
            '    "Library/Saved Application State",\n'
            '    "Library/Preferences"\n'
            "  ] : [];\n"
            "  return bases.flatMap((base) => names.flatMap((name) => [\n"
            "    join(home, base, name),\n"
            "    join(home, base, `${name}.plist`),\n"
            "    join(home, base, `${name}.savedState`)\n"
            "  ]));\n"
            "}\n",
            encoding="utf-8",
        )
        res = verify_harness_targets(smoke_mjs)
        self.assertTrue(res["verified"])
        self.assertEqual(res["target_count"], 63)

        # Drift in APPLICATION_IDENTIFIER fails closed
        smoke_mjs.write_text(
            smoke_mjs.read_text(encoding="utf-8").replace(
                "ai.knowledgeforge.themeforge.nebularfusion", "ai.wrong.id"
            ),
            encoding="utf-8",
        )
        with self.assertRaises(AdmissionError) as ctx:
            verify_harness_targets(smoke_mjs)
        self.assertEqual(ctx.exception.code, "TF_PYPI_HOST_STATE_HARNESS_MISMATCH")


if __name__ == "__main__":
    unittest.main()
