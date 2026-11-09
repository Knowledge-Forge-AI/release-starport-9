"""Connected source19 tests for declared-root real-user-state accounting."""
from __future__ import annotations

import hashlib
from pathlib import Path
import os
import sys
import tempfile
import unittest
from unittest.mock import patch


SOURCE_ROOT = Path(__file__).resolve().parents[1]
TMP_ROOT = Path(tempfile.gettempdir()).resolve()
sys.path.insert(0, str(SOURCE_ROOT / "src"))

from rs9 import nebular080_consumer_core as core  # noqa: E402
from rs9 import tf_pypi_universal_support as support  # noqa: E402
from rs9.tf_pypi_archive import AdmissionError, canonical  # noqa: E402


TARGETS = ("darwin-arm64", "linux-arm64-gnu", "linux-x64-gnu")
CORE_GUARD_CODE = "TF_PYPI_NEBULAR_USER_STATE_GUARD"
SUPPORT_GUARD_CODE = "TF_PYPI_NEBULAR080_NEBULAR_USER_STATE_GUARD"


class RealUserStateAccountingTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls._created_tmp_root = not TMP_ROOT.exists()
        if TMP_ROOT.exists() and (TMP_ROOT.is_symlink() or not TMP_ROOT.is_dir()):
            raise RuntimeError("frontend temporary root is not a regular directory")
        TMP_ROOT.mkdir(mode=0o700, parents=True, exist_ok=True)

    @classmethod
    def tearDownClass(cls) -> None:
        if cls._created_tmp_root:
            try:
                TMP_ROOT.rmdir()
            except OSError:
                pass

    def _home(self, prefix: str) -> tempfile.TemporaryDirectory:
        return tempfile.TemporaryDirectory(prefix=prefix, dir=TMP_ROOT)

    def _assert_guard_accepts(self, value: dict, target: str, phase: str) -> None:
        checked = core._nebular_real_user_state(value, target=target, phase=phase)
        self.assertEqual(checked["locations"], value["locations"])

    def _assert_guard_refuses(self, value: dict, target: str, phase: str) -> None:
        with self.assertRaises(AdmissionError) as caught:
            core._nebular_real_user_state(value, target=target, phase=phase)
        self.assertEqual(caught.exception.code, CORE_GUARD_CODE)

    @staticmethod
    def _known_app_file(home: Path) -> Path:
        path = home / ".cache" / "theme-forge-nebular-fusion" / "state.bin"
        path.parent.mkdir(parents=True, mode=0o700)
        return path

    def test_fresh_homes_keep_all_declared_roots_and_guard_accepts(self) -> None:
        expected_counts = {
            "darwin-arm64": 63,
            "linux-arm64-gnu": 36,
            "linux-x64-gnu": 36,
        }
        for target in TARGETS:
            with self.subTest(target=target), self._home("state-empty-") as home_name:
                home = Path(home_name)
                relatives = support._state_targets(target)
                self.assertEqual(len(relatives), expected_counts[target])
                snapshot = support.make_real_user_state_snapshotter(target, home_dir=home)
                before = snapshot("before", target)
                after = snapshot("after", target)
                rows, digest = support._snapshot_state(home, relatives)
                self.assertEqual(before["locations"], expected_counts[target])
                self.assertEqual(after["locations"], expected_counts[target])
                self.assertEqual(before["changed"], [])
                self.assertEqual(after["changed"], [])
                self.assertEqual(before["snapshot_sha256"], after["snapshot_sha256"])
                self.assertEqual(before["snapshot_sha256"], digest)
                self.assertEqual(set(rows), set(relatives))
                self.assertTrue(all(value is None for value in rows.values()))
                self._assert_guard_accepts(before, target, "before")
                self._assert_guard_accepts(after, target, "after")

    def test_present_root_descendants_do_not_inflate_location_count(self) -> None:
        target = "linux-x64-gnu"
        with self._home("state-present-") as home_name:
            home = Path(home_name)
            file_path = self._known_app_file(home)
            file_path.write_bytes(b"stable-state")
            nested = file_path.parent / "nested" / "child.bin"
            nested.parent.mkdir(mode=0o700)
            nested.write_bytes(b"nested-state")
            snapshot = support.make_real_user_state_snapshotter(target, home_dir=home)
            before = snapshot("before", target)
            after = snapshot("after", target)
            rows, _ = support._snapshot_state(home, support._state_targets(target))
            self.assertGreater(len(rows), before["locations"])
            self.assertEqual(before["locations"], len(support._state_targets(target)))
            self.assertEqual(after["locations"], before["locations"])
            self.assertEqual(before["snapshot_sha256"], after["snapshot_sha256"])
            self._assert_guard_accepts(before, target, "before")
            self._assert_guard_accepts(after, target, "after")

    def test_created_monitored_root_is_reported_and_refused(self) -> None:
        target = "linux-x64-gnu"
        with self._home("state-created-") as home_name:
            home = Path(home_name)
            snapshot = support.make_real_user_state_snapshotter(target, home_dir=home)
            before = snapshot("before", target)
            self._assert_guard_accepts(before, target, "before")
            file_path = self._known_app_file(home)
            file_path.write_bytes(b"created-after-before")
            after = snapshot("after", target)
            self.assertGreater(after["changed"], [])
            self._assert_guard_refuses(after, target, "after")

    def test_changed_file_and_deleted_root_are_reported_and_refused(self) -> None:
        target = "linux-x64-gnu"
        with self._home("state-changed-") as home_name:
            home = Path(home_name)
            file_path = self._known_app_file(home)
            file_path.write_bytes(b"before")
            snapshot = support.make_real_user_state_snapshotter(target, home_dir=home)
            before = snapshot("before", target)
            file_path.write_bytes(b"after")
            changed = snapshot("after", target)
            self.assertGreater(changed["changed"], [])
            self._assert_guard_refuses(changed, target, "after")
            self.assertNotEqual(before["snapshot_sha256"], changed["snapshot_sha256"])

        with self._home("state-deleted-") as home_name:
            home = Path(home_name)
            file_path = self._known_app_file(home)
            file_path.write_bytes(b"before-delete")
            snapshot = support.make_real_user_state_snapshotter(target, home_dir=home)
            before = snapshot("before", target)
            file_path.unlink()
            file_path.parent.rmdir()
            deleted = snapshot("after", target)
            self.assertGreater(deleted["changed"], [])
            self._assert_guard_refuses(deleted, target, "after")
            self.assertNotEqual(before["snapshot_sha256"], deleted["snapshot_sha256"])

    def test_unreadable_path_is_guard_error_not_absence(self) -> None:
        target = "linux-x64-gnu"
        with self._home("state-unreadable-") as home_name:
            home = Path(home_name)
            unreadable = home / support._state_targets(target)[0]
            snapshot = support.make_real_user_state_snapshotter(target, home_dir=home)
            original = os.lstat

            def denied(path, *args, **kwargs):
                if Path(path) == unreadable:
                    raise PermissionError("controlled lstat refusal")
                return original(path, *args, **kwargs)

            with patch.object(support.os, "lstat", side_effect=denied):
                with self.assertRaises(AdmissionError) as caught:
                    snapshot("before", target)
                self.assertEqual(caught.exception.code, SUPPORT_GUARD_CODE)

    def test_absent_roots_count_toward_entry_cap(self) -> None:
        target = "linux-x64-gnu"
        with self._home("state-cap-") as home_name:
            home = Path(home_name)
            relatives = support._state_targets(target)
            with patch.object(support, "MAX_SNAPSHOT_ENTRIES", len(relatives) - 1):
                with self.assertRaises(AdmissionError) as caught:
                    support._snapshot_state(home, relatives)
            self.assertEqual(caught.exception.code, SUPPORT_GUARD_CODE)

    def test_zero_location_receipt_still_refused(self) -> None:
        value = {
            "schema": "nebular.native-rc-persistent-user-state-v1",
            "method": "native-rc-smoke.persistentStateLocations+snapshotLocations",
            "scope": "real-user-state",
            "target": "linux-x64-gnu",
            "phase": "before",
            "locations": 0,
            "snapshot_sha256": hashlib.sha256(canonical([])).hexdigest(),
            "changed": [],
        }
        self._assert_guard_refuses(value, "linux-x64-gnu", "before")


if __name__ == "__main__":
    unittest.main()
