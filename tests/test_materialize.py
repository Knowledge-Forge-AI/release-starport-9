"""Tests for safe runtime materializer and staged Nix candidate definitions."""

import concurrent.futures
import errno
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tarfile
import tempfile
import unittest
from unittest import mock

from rs9.errors import ContractError
from rs9.materialize import (
    MaterializeLock,
    copy_store_to_payload,
    extract_archive_to_payload,
    materialize_payload,
    parse_manifest_members,
    resolve_launcher,
    safe_rmtree,
    validate_ancestry_not_symlink,
    verify_payload_directory,
)
from tests.shadow_fixtures import tar_bytes

ROOT = Path(__file__).resolve().parents[1]


class MaterializeTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp_dir.cleanup)
        # Use Path.resolve() so that macOS /var -> /private/var is handled cleanly
        self.scratch = Path(self.temp_dir.name).resolve()
        self.cache_dir = self.scratch / "cache"
        self.cache_dir.mkdir()

    def build_test_archive(self, entries):
        archive_path = self.scratch / "test-payload.tar.gz"
        archive_path.write_bytes(tar_bytes(entries))
        return archive_path

    def make_members_and_archive(self):
        root = "test-app"
        bin_app_bytes = b"#!/bin/sh\necho test\n"
        data_txt_bytes = b"payload content bytes\n"
        entries = [
            (root, b"", 0o755, tarfile.DIRTYPE, ""),
            (f"{root}/bin", b"", 0o755, tarfile.DIRTYPE, ""),
            (f"{root}/bin/app", bin_app_bytes, 0o755, tarfile.REGTYPE, ""),
            (f"{root}/lib", b"", 0o755, tarfile.DIRTYPE, ""),
            (f"{root}/lib/data.txt", data_txt_bytes, 0o644, tarfile.REGTYPE, ""),
            (f"{root}/link-app", b"", 0o777, tarfile.SYMTYPE, "bin/app"),
        ]
        archive_path = self.build_test_archive(entries)

        manifest = [
            {"path": root, "type": "directory", "mode": 0o755, "size": 0},
            {"path": f"{root}/bin", "type": "directory", "mode": 0o755, "size": 0},
            {
                "path": f"{root}/bin/app",
                "type": "file",
                "mode": 0o755,
                "size": len(bin_app_bytes),
                "sha256": hashlib.sha256(bin_app_bytes).hexdigest(),
            },
            {"path": f"{root}/lib", "type": "directory", "mode": 0o755, "size": 0},
            {
                "path": f"{root}/lib/data.txt",
                "type": "file",
                "mode": 0o644,
                "size": len(data_txt_bytes),
                "sha256": hashlib.sha256(data_txt_bytes).hexdigest(),
            },
            {"path": f"{root}/link-app", "type": "symlink", "mode": 0o777, "size": 0, "target": "bin/app"},
        ]
        return archive_path, manifest

    def test_safe_materialize_restores_archive_modes_and_bytes(self):
        archive_path, manifest = self.make_members_and_archive()
        payload_root = materialize_payload(archive_path, self.cache_dir, manifest)

        self.assertTrue(payload_root.is_dir())
        self.assertEqual(payload_root.name, "test-app")

        # Verify executable file mode is 0o755 (archive mode preserved)
        exe_path = payload_root / "bin/app"
        self.assertTrue(exe_path.is_file())
        self.assertEqual(exe_path.stat().st_mode & 0o777, 0o755)
        self.assertEqual(exe_path.read_bytes(), b"#!/bin/sh\necho test\n")

        # Verify regular data file mode is 0o644 (write bit preserved)
        data_path = payload_root / "lib/data.txt"
        self.assertTrue(data_path.is_file())
        self.assertEqual(data_path.stat().st_mode & 0o777, 0o644)
        self.assertEqual(data_path.read_bytes(), b"payload content bytes\n")

        # Verify symlink
        link_path = payload_root / "link-app"
        self.assertTrue(link_path.is_symlink())
        self.assertEqual(os.readlink(link_path), "bin/app")

        # Verify NO marker or extra files placed inside payload
        all_files = [str(p.relative_to(payload_root.parent)) for p in payload_root.rglob("*")]
        expected = ["test-app/bin", "test-app/bin/app", "test-app/lib", "test-app/lib/data.txt", "test-app/link-app"]
        self.assertEqual(sorted(all_files), sorted(expected))

        # Check metadata was stored outside the payload tree
        entry_dir = payload_root.parent.parent
        self.assertTrue((entry_dir / "meta.json").is_file())
        self.assertTrue((entry_dir / "manifest.json").is_file())

    def test_materialize_from_store_restores_stripped_write_bits(self):
        archive_path, manifest = self.make_members_and_archive()

        # Simulate read-only Nix store directory (write bits stripped: 0o555 for exe/dir, 0o444 for file)
        store_sim = self.scratch / "nix-store-sim"
        store_app = store_sim / "test-app"
        store_app.mkdir(parents=True)
        (store_app / "bin").mkdir()
        (store_app / "bin/app").write_bytes(b"#!/bin/sh\necho test\n")
        (store_app / "lib").mkdir()
        (store_app / "lib/data.txt").write_bytes(b"payload content bytes\n")
        os.symlink("bin/app", store_app / "link-app")

        # Strip write bits as Nix store does
        os.chmod(store_app / "bin/app", 0o555)
        os.chmod(store_app / "lib/data.txt", 0o444)
        os.chmod(store_app / "bin", 0o555)
        os.chmod(store_app / "lib", 0o555)
        os.chmod(store_app, 0o555)

        # Materialize from store simulation
        payload_root = materialize_payload(store_sim, self.cache_dir, manifest, source_is_store=True)

        # Original archive modes must be restored (0o755 executable, 0o644 regular file)
        self.assertEqual((payload_root / "bin/app").stat().st_mode & 0o777, 0o755)
        self.assertEqual((payload_root / "lib/data.txt").stat().st_mode & 0o777, 0o644)
        self.assertEqual(os.readlink(payload_root / "link-app"), "bin/app")

    def test_materialize_without_manifest_inspects_actual_archive(self):
        archive_path, _ = self.make_members_and_archive()
        # Call materialize without manifest; it inspects actual archive directly
        payload_root = materialize_payload(archive_path, self.cache_dir)
        self.assertTrue(payload_root.is_dir())
        self.assertEqual(payload_root.name, "test-app")
        self.assertEqual((payload_root / "bin/app").stat().st_mode & 0o777, 0o755)

    def test_strict_ancestry_rejects_symlinks_without_os_exemption(self):
        # Path under resolved temp directory passes
        valid_dest = self.scratch / "valid-dest"
        valid_dest.mkdir()
        validated = validate_ancestry_not_symlink(valid_dest)
        self.assertEqual(validated, valid_dest)

        # Symlink anywhere in directory ancestry must fail with NO OS exemptions
        symlink_sub = self.scratch / "symlink-sub"
        real_target = self.scratch / "real-target"
        real_target.mkdir()
        os.symlink(real_target, symlink_sub)

        nested_dest = symlink_sub / "nested"
        with self.assertRaises(ContractError) as caught:
            validate_ancestry_not_symlink(nested_dest)
        self.assertEqual(caught.exception.code, "SYMLINK_REJECTED")
        # Never echo private paths in ContractError
        self.assertNotIn(str(nested_dest), str(caught.exception))
        self.assertNotIn(str(self.scratch), str(caught.exception))

        # Raw /tmp or /var symlink fails strictly
        raw_tmp = Path("/tmp")
        if raw_tmp.is_symlink():
            with self.assertRaises(ContractError) as caught:
                validate_ancestry_not_symlink(raw_tmp / "some-sub")
            self.assertEqual(caught.exception.code, "SYMLINK_REJECTED")

    def test_sidecar_ancestry_rejects_all_symlinks(self):
        root = "test-app"
        entries = [
            {"path": root, "type": "directory", "mode": 0o755, "size": 0},
            {"path": f"{root}/lib", "type": "directory", "mode": 0o755, "size": 0},
            {"path": f"{root}/lib/sidecar-link", "type": "symlink", "mode": 0o777, "size": 0, "target": "other"},
        ]
        with self.assertRaises(ContractError) as caught:
            parse_manifest_members(entries)
        self.assertEqual(caught.exception.code, "UNSAFE_LINK")

    def test_launch_ancestry_rejects_symlinks(self):
        archive_path, manifest = self.make_members_and_archive()
        payload_root = materialize_payload(archive_path, self.cache_dir, manifest)

        # Create a symlink in launch ancestry
        fake_launcher_link = payload_root / "bin/link-launcher"
        os.symlink("app", fake_launcher_link)

        with self.assertRaises(ContractError) as caught:
            resolve_launcher(payload_root, "bin/link-launcher")
        self.assertEqual(caught.exception.code, "UNSAFE_LINK")

    def test_empty_manifest_fails(self):
        for empty_val in [[], {}, {"members": []}]:
            with self.assertRaises(ContractError) as caught:
                parse_manifest_members(empty_val)
            self.assertEqual(caught.exception.code, "INVALID_MANIFEST")

    def test_invalid_modes_rejected(self):
        for bad_mode in [-1, 0o100755, 0o4755, 0o2755, 0o1000, 0o100000, "0755", True]:
            manifest = [
                {"path": "test-app", "type": "directory", "mode": bad_mode, "size": 0},
            ]
            with self.subTest(bad_mode=bad_mode), self.assertRaises(ContractError) as caught:
                parse_manifest_members(manifest)
            self.assertEqual(caught.exception.code, "UNSAFE_MODE")

    def test_invalid_nonhex_digests_and_sizes_rejected(self):
        manifest_bad_hash = [
            {"path": "test-app", "type": "directory", "mode": 0o755, "size": 0},
            {"path": "test-app/file", "type": "file", "mode": 0o644, "size": 1, "sha256": "not-a-valid-hex-hash"},
        ]
        with self.assertRaises(ContractError) as caught:
            parse_manifest_members(manifest_bad_hash)
        self.assertEqual(caught.exception.code, "INVALID_MANIFEST")

        manifest_bad_size = [
            {"path": "test-app", "type": "directory", "mode": 0o755, "size": 0},
            {"path": "test-app/file", "type": "file", "mode": 0o644, "size": -10, "sha256": "0" * 64},
        ]
        with self.assertRaises(ContractError) as caught:
            parse_manifest_members(manifest_bad_size)
        self.assertEqual(caught.exception.code, "INVALID_MANIFEST")

    def test_missing_root_mode_in_manifest_fails(self):
        # Manifest without root directory entry
        manifest = [
            {"path": "test-app/bin", "type": "directory", "mode": 0o755, "size": 0},
            {"path": "test-app/bin/app", "type": "file", "mode": 0o755, "size": 1, "sha256": "0" * 64},
        ]
        with self.assertRaises(ContractError) as caught:
            parse_manifest_members(manifest)
        self.assertEqual(caught.exception.code, "INVALID_MANIFEST")

    def test_bounded_static_error_messages_never_echo_private_paths(self):
        archive_path, manifest = self.make_members_and_archive()
        # Test nonexistent launcher
        payload_root = materialize_payload(archive_path, self.cache_dir, manifest)
        with self.assertRaises(ContractError) as caught:
            resolve_launcher(payload_root, "bin/nonexistent")
        self.assertEqual(caught.exception.code, "COMMAND_PATH")
        self.assertNotIn("nonexistent", str(caught.exception))
        self.assertNotIn(str(payload_root), str(caught.exception))

        # Test invalid store path
        with self.assertRaises(ContractError) as caught:
            copy_store_to_payload(self.scratch / "missing-store-path", payload_root, manifest)
        self.assertEqual(caught.exception.code, "INVALID_STORE_PATH")
        self.assertNotIn("missing-store-path", str(caught.exception))
        self.assertNotIn(str(self.scratch), str(caught.exception))

    def test_malicious_paths_rejected(self):
        for bad_path in [
            "../escape",
            "test-app/../../outside",
            "/test-app/abs",
            "test-app/\\backslash",
            "test-app/invalid\x00path",
            "test-app/control\nline",
            "other-root/file",
        ]:
            entries = [("test-app", b"", 0o755, tarfile.DIRTYPE, ""), (bad_path, b"x", 0o644, tarfile.REGTYPE, "")]
            archive = self.build_test_archive(entries)
            manifest = [
                {"path": "test-app", "type": "directory", "mode": 0o755, "size": 0},
                {"path": bad_path, "type": "file", "mode": 0o644, "size": 1, "sha256": "0" * 64},
            ]
            with self.subTest(bad_path=bad_path), self.assertRaises(ContractError):
                materialize_payload(archive, self.cache_dir, manifest)

    def test_unsafe_symlinks_and_loops_rejected(self):
        for bad_symlink in [
            ("../../outside", "escapes root"),
            ("/etc/passwd", "absolute path"),
            ("a/../../outside", "relative escape"),
            ("bad\\backslash", "contains backslash"),
        ]:
            target, desc = bad_symlink
            manifest = [
                {"path": "test-app", "type": "directory", "mode": 0o755, "size": 0},
                {"path": "test-app/bad-link", "type": "symlink", "mode": 0o777, "size": 0, "target": target},
            ]
            with self.subTest(desc=desc), self.assertRaises(ContractError):
                parse_manifest_members(manifest)

        # Loop detection: link1 -> link2 -> link1
        loop_manifest = [
            {"path": "test-app", "type": "directory", "mode": 0o755, "size": 0},
            {"path": "test-app/link1", "type": "symlink", "mode": 0o777, "size": 0, "target": "link2"},
            {"path": "test-app/link2", "type": "symlink", "mode": 0o777, "size": 0, "target": "link1"},
        ]
        with self.assertRaises(ContractError) as caught:
            parse_manifest_members(loop_manifest)
        self.assertEqual(caught.exception.code, "UNSAFE_LINK")

    def test_tamper_detection(self):
        archive_path, manifest = self.make_members_and_archive()
        payload_root = materialize_payload(archive_path, self.cache_dir, manifest)

        # 1. Modify file content
        (payload_root / "lib/data.txt").write_bytes(b"tampered content")
        with self.assertRaises(ContractError) as caught:
            verify_payload_directory(payload_root.parent, manifest)
        self.assertEqual(caught.exception.code, "PAYLOAD_TAMPERED")
        (payload_root / "lib/data.txt").write_bytes(b"payload content bytes\n")

        # 2. Alter mode (e.g. remove executable bit)
        os.chmod(payload_root / "bin/app", 0o644)
        with self.assertRaises(ContractError) as caught:
            verify_payload_directory(payload_root.parent, manifest)
        self.assertEqual(caught.exception.code, "PAYLOAD_TAMPERED")
        os.chmod(payload_root / "bin/app", 0o755)

        # 3. Inject extra file or marker inside payload
        extra_marker = payload_root / ".extra_marker"
        extra_marker.write_bytes(b"forbidden marker inside payload")
        with self.assertRaises(ContractError) as caught:
            verify_payload_directory(payload_root.parent, manifest)
        self.assertEqual(caught.exception.code, "EXTRA_PAYLOAD_ENTRY")
        extra_marker.unlink()

        # 4. Remove file
        (payload_root / "lib/data.txt").unlink()
        with self.assertRaises(ContractError) as caught:
            verify_payload_directory(payload_root.parent, manifest)
        self.assertEqual(caught.exception.code, "PAYLOAD_TAMPERED")

    def test_manifest_sha256_mismatch_fails_closed(self):
        archive_path, manifest = self.make_members_and_archive()
        forged_manifest_hash = "0" * 64
        with self.assertRaises(ContractError) as caught:
            materialize_payload(
                archive_path, self.cache_dir, manifest, expected_manifest_sha256=forged_manifest_hash
            )
        self.assertEqual(caught.exception.code, "MANIFEST_TAMPERED")

    def test_repeated_use_and_tampered_cache_recovery(self):
        archive_path, manifest = self.make_members_and_archive()

        # First call: materializes
        path1 = materialize_payload(archive_path, self.cache_dir, manifest)
        # Second call: cache hit, reused without re-extracting
        path2 = materialize_payload(archive_path, self.cache_dir, manifest)
        self.assertEqual(path1, path2)

        # Simulate tampering existing cache entry
        (path2 / "lib/data.txt").write_bytes(b"corrupted in cache")
        # Third call: detects tamper, purges invalid cache, re-materializes cleanly
        path3 = materialize_payload(archive_path, self.cache_dir, manifest)
        self.assertEqual(path3, path1)
        self.assertEqual((path3 / "lib/data.txt").read_bytes(), b"payload content bytes\n")

    def test_concurrency_handling_and_lock_privacy(self):
        archive_path, manifest = self.make_members_and_archive()

        def worker():
            return materialize_payload(archive_path, self.cache_dir, manifest)

        with concurrent.futures.ThreadPoolExecutor(max_workers=6) as executor:
            futures = [executor.submit(worker) for _ in range(12)]
            results = [f.result() for f in futures]

        for res in results:
            self.assertEqual(res, results[0])
            self.assertTrue(res.is_dir())
        verify_payload_directory(results[0].parent, manifest)

        # Check lock file directory permissions (0o700)
        lock_dir = self.cache_dir / ".locks"
        if lock_dir.exists():
            self.assertEqual(lock_dir.stat().st_mode & 0o777, 0o700)

    def test_launcher_resolution(self):
        archive_path, manifest = self.make_members_and_archive()
        payload_root = materialize_payload(archive_path, self.cache_dir, manifest)

        launcher_path = resolve_launcher(payload_root, "bin/app")
        self.assertTrue(launcher_path.is_file())
        self.assertTrue(launcher_path.stat().st_mode & 0o111)

        with self.assertRaises(ContractError) as caught:
            resolve_launcher(payload_root, "bin/nonexistent")
        self.assertEqual(caught.exception.code, "COMMAND_PATH")

        with self.assertRaises(ContractError) as caught:
            resolve_launcher(payload_root, "lib/data.txt")
        self.assertEqual(caught.exception.code, "COMMAND_PATH")

    def test_nebular_materialization_and_parity(self):
        root = "Theme Forge Nebular Fusion.app"
        macho_bytes = b"fake macho\n"
        launcher_bytes = b"#!/bin/sh\nexit 0\n"
        entries = [
            (root, b"", 0o755, tarfile.DIRTYPE, ""),
            (f"{root}/Contents", b"", 0o755, tarfile.DIRTYPE, ""),
            (f"{root}/Contents/MacOS", b"", 0o755, tarfile.DIRTYPE, ""),
            (f"{root}/Contents/MacOS/tfnf", macho_bytes, 0o755, tarfile.REGTYPE, ""),
            (f"{root}/Contents/Resources", b"", 0o755, tarfile.DIRTYPE, ""),
            (f"{root}/Contents/Resources/bin", b"", 0o755, tarfile.DIRTYPE, ""),
            (f"{root}/Contents/Resources/bin/tfnf", launcher_bytes, 0o755, tarfile.REGTYPE, ""),
        ]
        archive = self.build_test_archive(entries)
        manifest = [
            {"path": root, "type": "directory", "mode": 0o755, "size": 0},
            {"path": f"{root}/Contents", "type": "directory", "mode": 0o755, "size": 0},
            {"path": f"{root}/Contents/MacOS", "type": "directory", "mode": 0o755, "size": 0},
            {
                "path": f"{root}/Contents/MacOS/tfnf",
                "type": "file",
                "mode": 0o755,
                "size": len(macho_bytes),
                "sha256": hashlib.sha256(macho_bytes).hexdigest(),
            },
            {"path": f"{root}/Contents/Resources", "type": "directory", "mode": 0o755, "size": 0},
            {"path": f"{root}/Contents/Resources/bin", "type": "directory", "mode": 0o755, "size": 0},
            {
                "path": f"{root}/Contents/Resources/bin/tfnf",
                "type": "file",
                "mode": 0o755,
                "size": len(launcher_bytes),
                "sha256": hashlib.sha256(launcher_bytes).hexdigest(),
            },
        ]
        payload = materialize_payload(archive, self.cache_dir, manifest)
        launcher = resolve_launcher(payload, "Contents/Resources/bin/tfnf")
        self.assertTrue(launcher.is_file())
        self.assertTrue(launcher.stat().st_mode & 0o111)

    # Defect 7: Malicious archive symlink/type/target tests

    def test_archive_member_type_mismatch_directory_expected_rejected(self):
        root = "test-app"
        outside_target = self.scratch / "outside_leak"
        outside_target.mkdir()
        entries = [
            (root, b"", 0o755, tarfile.DIRTYPE, ""),
            (f"{root}/data", b"", 0o777, tarfile.SYMTYPE, str(outside_target)),
            (f"{root}/data/exploit.txt", b"evil bytes", 0o644, tarfile.REGTYPE, ""),
        ]
        archive = self.build_test_archive(entries)
        manifest = [
            {"path": root, "type": "directory", "mode": 0o755, "size": 0},
            {"path": f"{root}/data", "type": "directory", "mode": 0o755, "size": 0},
            {
                "path": f"{root}/data/exploit.txt",
                "type": "file",
                "mode": 0o644,
                "size": 10,
                "sha256": hashlib.sha256(b"evil bytes").hexdigest(),
            },
        ]
        with self.assertRaises(ContractError) as caught:
            materialize_payload(archive, self.cache_dir, manifest)
        self.assertIn(caught.exception.code, ("PAYLOAD_TAMPERED", "UNSAFE_LINK"))
        # Unsafe archive cannot write outside staging!
        self.assertFalse((outside_target / "exploit.txt").exists())

    def test_archive_member_type_mismatch_file_expected_rejected(self):
        root = "test-app"
        file_bytes = b"real content"
        entries = [
            (root, b"", 0o755, tarfile.DIRTYPE, ""),
            (f"{root}/file.txt", b"", 0o777, tarfile.SYMTYPE, "other"),
        ]
        archive = self.build_test_archive(entries)
        manifest = [
            {"path": root, "type": "directory", "mode": 0o755, "size": 0},
            {
                "path": f"{root}/file.txt",
                "type": "file",
                "mode": 0o644,
                "size": len(file_bytes),
                "sha256": hashlib.sha256(file_bytes).hexdigest(),
            },
        ]
        with self.assertRaises(ContractError) as caught:
            materialize_payload(archive, self.cache_dir, manifest)
        self.assertEqual(caught.exception.code, "PAYLOAD_TAMPERED")

    def test_archive_symlink_target_mismatch_rejected(self):
        root = "test-app"
        entries = [
            (root, b"", 0o755, tarfile.DIRTYPE, ""),
            (f"{root}/link", b"", 0o777, tarfile.SYMTYPE, "wrong_target"),
        ]
        archive = self.build_test_archive(entries)
        manifest = [
            {"path": root, "type": "directory", "mode": 0o755, "size": 0},
            {"path": f"{root}/link", "type": "symlink", "mode": 0o777, "size": 0, "target": "expected_target"},
        ]
        with self.assertRaises(ContractError) as caught:
            materialize_payload(archive, self.cache_dir, manifest)
        self.assertEqual(caught.exception.code, "PAYLOAD_TAMPERED")

    def test_archive_symlink_target_escape_rejected(self):
        root = "test-app"
        for bad_target in ["../../outside", "/etc/passwd", "sub/../../../escape"]:
            entries = [
                (root, b"", 0o755, tarfile.DIRTYPE, ""),
                (f"{root}/badlink", b"", 0o777, tarfile.SYMTYPE, bad_target),
            ]
            archive = self.build_test_archive(entries)
            manifest = [
                {"path": root, "type": "directory", "mode": 0o755, "size": 0},
                {"path": f"{root}/badlink", "type": "symlink", "mode": 0o777, "size": 0, "target": bad_target},
            ]
            with self.subTest(bad_target=bad_target), self.assertRaises(ContractError) as caught:
                materialize_payload(archive, self.cache_dir, manifest)
            self.assertEqual(caught.exception.code, "UNSAFE_LINK")

    def test_archive_cannot_write_outside_staging_through_symlink_parent(self):
        outside_dir = self.scratch / "outside_dir"
        outside_dir.mkdir()
        root = "test-app"
        file_bytes = b"should never be written outside"
        entries = [
            (root, b"", 0o755, tarfile.DIRTYPE, ""),
            (f"{root}/sym_escape", b"", 0o777, tarfile.SYMTYPE, str(outside_dir)),
            (f"{root}/sym_escape/hacked.txt", file_bytes, 0o644, tarfile.REGTYPE, ""),
        ]
        archive = self.build_test_archive(entries)
        manifest = [
            {"path": root, "type": "directory", "mode": 0o755, "size": 0},
            {"path": f"{root}/sym_escape", "type": "symlink", "mode": 0o777, "size": 0, "target": str(outside_dir)},
            {
                "path": f"{root}/sym_escape/hacked.txt",
                "type": "file",
                "mode": 0o644,
                "size": len(file_bytes),
                "sha256": hashlib.sha256(file_bytes).hexdigest(),
            },
        ]
        with self.assertRaises(ContractError) as caught:
            materialize_payload(archive, self.cache_dir, manifest)
        self.assertIn(caught.exception.code, ("UNSAFE_LINK", "PAYLOAD_TAMPERED"))
        self.assertFalse((outside_dir / "hacked.txt").exists())

    # Defect 7: Lock failure tests

    def test_materialize_lock_flock_failure_not_swallowed(self):
        lock_file = self.cache_dir / ".locks" / "test.lock"
        with mock.patch("fcntl.flock", side_effect=OSError(errno.EACCES, "Permission denied")):
            with self.assertRaises(ContractError) as caught:
                with MaterializeLock(lock_file):
                    pass
            self.assertEqual(caught.exception.code, "LOCK_FAILED")

    def test_materialize_payload_fails_closed_on_lock_acquisition_failure(self):
        archive_path, manifest = self.make_members_and_archive()
        with mock.patch("fcntl.flock", side_effect=OSError(errno.ENOLCK, "No locks available")):
            with self.assertRaises(ContractError) as caught:
                materialize_payload(archive_path, self.cache_dir, manifest)
            self.assertEqual(caught.exception.code, "LOCK_FAILED")

    # Defect 7: Invalid digest tests

    def test_expected_manifest_sha256_pending_cannot_bypass(self):
        archive_path, manifest = self.make_members_and_archive()
        with self.assertRaises(ContractError) as caught:
            materialize_payload(
                archive_path, self.cache_dir, manifest, expected_manifest_sha256="pending"
            )
        self.assertEqual(caught.exception.code, "INVALID_DIGEST")

    def test_expected_manifest_sha256_invalid_format_rejected(self):
        archive_path, manifest = self.make_members_and_archive()
        for bad_digest in [
            "not-a-valid-hex-hash",
            "0" * 63,
            "0" * 65,
            "g" * 64,
            "",
            "   ",
            "A" * 64,  # uppercase rejected
            12345,
        ]:
            with self.subTest(bad_digest=bad_digest), self.assertRaises(ContractError) as caught:
                materialize_payload(
                    archive_path, self.cache_dir, manifest, expected_manifest_sha256=bad_digest
                )
            self.assertEqual(caught.exception.code, "INVALID_DIGEST")

    def test_manifest_dict_invalid_digest_rejected(self):
        for bad_digest in ["pending", "invalid", "0" * 63, "g" * 64]:
            manifest = {
                "manifest_sha256": bad_digest,
                "members": [
                    {"path": "test-app", "type": "directory", "mode": 0o755, "size": 0},
                ],
            }
            with self.subTest(bad_digest=bad_digest), self.assertRaises(ContractError) as caught:
                parse_manifest_members(manifest)
            self.assertEqual(caught.exception.code, "INVALID_DIGEST")

    # Defect 7: Failed-cache cleanup tests

    def test_read_only_failed_cache_recovers_cleanly(self):
        archive_path, manifest = self.make_members_and_archive()
        # 1. Materialize initial payload
        payload_root1 = materialize_payload(archive_path, self.cache_dir, manifest)
        self.assertTrue(payload_root1.is_dir())

        # 2. Make cache entry directories read-only (0o555 / 0o500) and files read-only (0o444)
        entry_dir = payload_root1.parent.parent
        for dirpath, dirnames, filenames in os.walk(entry_dir):
            for f in filenames:
                os.chmod(os.path.join(dirpath, f), 0o444)
            for d in dirnames:
                os.chmod(os.path.join(dirpath, d), 0o555)
        os.chmod(entry_dir, 0o555)

        # 3. Simulate corruption inside the read-only cache entry
        # Make parent writable temporarily just to corrupt
        data_file = payload_root1 / "lib/data.txt"
        os.chmod(data_file.parent, 0o700)
        os.chmod(data_file, 0o600)
        data_file.write_bytes(b"tampered bytes in cache")
        os.chmod(data_file, 0o444)
        os.chmod(data_file.parent, 0o555)

        # 4. Materialize payload again: must safely clean read-only cache and re-materialize cleanly
        payload_root2 = materialize_payload(archive_path, self.cache_dir, manifest)
        self.assertTrue(payload_root2.is_dir())
        self.assertEqual(
            (payload_root2 / "lib/data.txt").read_bytes(),
            b"payload content bytes\n",
        )

    def test_read_only_stale_staging_dir_cleans_cleanly(self):
        archive_path, manifest = self.make_members_and_archive()
        _, _, manifest_sha256 = parse_manifest_members(manifest)

        # Create simulated stale staging directory with read-only files and directories
        stale_staging = self.cache_dir / ".staging" / f"{manifest_sha256}.{os.getpid()}"
        stale_payload = stale_staging / "payload/test-app/sub"
        stale_payload.mkdir(parents=True)
        stale_file = stale_payload / "read_only.txt"
        stale_file.write_bytes(b"old staging data")
        stale_file.chmod(0o444)
        stale_payload.chmod(0o555)
        stale_payload.parent.chmod(0o555)
        (stale_staging / "payload").chmod(0o555)
        stale_staging.chmod(0o555)

        # Calling materialize_payload must safely clean stale staging and succeed
        payload_root = materialize_payload(archive_path, self.cache_dir, manifest)
        self.assertTrue(payload_root.is_dir())
        self.assertFalse(stale_staging.exists())

    def test_safe_rmtree_root_confinement_and_symlink_safety(self):
        # 1. Test safe_rmtree removes read-only directories cleanly
        target_dir = self.cache_dir / "test_ro_tree"
        sub_dir = target_dir / "sub"
        sub_dir.mkdir(parents=True)
        ro_file = sub_dir / "data.bin"
        ro_file.write_bytes(b"bytes")
        ro_file.chmod(0o444)
        sub_dir.chmod(0o555)
        target_dir.chmod(0o555)

        safe_rmtree(target_dir, confinement_root=self.cache_dir)
        self.assertFalse(target_dir.exists())

        # 2. Test safe_rmtree does NOT delete symlink target outside confinement root
        outside_file = self.scratch / "outside_secret.txt"
        outside_file.write_bytes(b"secret payload")

        target_dir2 = self.cache_dir / "test_sym_tree"
        target_dir2.mkdir()
        sym = target_dir2 / "outside_link"
        os.symlink(str(outside_file), str(sym))

        safe_rmtree(target_dir2, confinement_root=self.cache_dir)
        self.assertFalse(target_dir2.exists())
        self.assertTrue(outside_file.exists())
        self.assertEqual(outside_file.read_bytes(), b"secret payload")

        # 3. Test safe_rmtree rejects targets outside confinement root
        with self.assertRaises(ContractError) as caught:
            safe_rmtree(self.scratch / "outside_dir", confinement_root=self.cache_dir)
        self.assertEqual(caught.exception.code, "UNSAFE_PATH")

        # 4. Test safe_rmtree rejects deleting the confinement root itself
        with self.assertRaises(ContractError) as caught:
            safe_rmtree(self.cache_dir, confinement_root=self.cache_dir)
        self.assertEqual(caught.exception.code, "UNSAFE_PATH")


class NixCandidateContractTests(unittest.TestCase):
    """Verify staged Nix candidate contracts, unexposed publication outputs, and qualification status."""

    def test_root_flake_does_not_expose_unqualified_outputs(self):
        flake_text = (ROOT / "flake.nix").read_text()
        self.assertIn("outputs = { self }:", flake_text)

        # Must NOT expose root publication outputs
        for forbidden in ["packages = ", "apps = ", "overlay = ", "overlays = "]:
            self.assertNotIn(forbidden, flake_text)

    @unittest.skipUnless(__import__("shutil").which("nix-instantiate"), "Nix pure evaluator unavailable")
    def test_pure_flake_evaluation_has_no_publication_outputs(self):
        proc = subprocess.run(
            ["nix-instantiate", "--eval", "--strict", "--expr",
             f'let flake = import {ROOT}/flake.nix; f = flake.outputs {{ self = {{}}; }}; in {{ hasPackages = f ? packages; hasApps = f ? apps; hasOverlay = f ? overlay; hasOverlays = f ? overlays; }}'],
            capture_output=True,
            text=True,
        )
        self.assertEqual(proc.returncode, 0)
        self.assertIn("hasPackages = false;", proc.stdout)
        self.assertIn("hasApps = false;", proc.stdout)
        self.assertIn("hasOverlay = false;", proc.stdout)
        self.assertIn("hasOverlays = false;", proc.stdout)

    @unittest.skipUnless(__import__("shutil").which("nix-instantiate"), "Nix pure evaluator unavailable")
    def test_candidate_definitions_under_nix_fail_closed_without_pinned_nixpkgs(self):
        proc = subprocess.run(
            ["nix-instantiate", "--eval", "--strict", "--expr", f'(import {ROOT}/nix/default.nix {{}}).candidatePackages'],
            capture_output=True,
            text=True,
        )
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn("RS9 Nix Candidate Fail-Closed", proc.stderr)
        self.assertIn("requiring authenticated generated inputs and pinned lock", proc.stderr)

    def test_four_candidate_products_exact_assets_and_metadata(self):
        config_path = ROOT / "nix/candidate-products.json"
        self.assertTrue(config_path.is_file())
        config = json.loads(config_path.read_bytes())
        products = config["products"]

        expected_keys = {
            "theme-forge-stellar-burst",
            "theme-forge-stellar-loom",
            "theme-forge-solar-sail",
            "theme-forge-nebular-fusion",
        }
        self.assertEqual(set(products.keys()), expected_keys)

        # Candidate config template must be explicitly pending with no authenticated true flags
        self.assertEqual(config.get("status"), "pending")
        self.assertFalse(config.get("authenticated", True))

        # Check no true authenticated flags anywhere
        def check_no_authenticated_true(obj):
            if isinstance(obj, dict):
                for k, v in obj.items():
                    if k == "authenticated":
                        self.assertFalse(v)
                    check_no_authenticated_true(v)
            elif isinstance(obj, list):
                for elem in obj:
                    check_no_authenticated_true(elem)
        check_no_authenticated_true(config)

        # Stellar Burst (Node 22 CLI)
        sb = products["theme-forge-stellar-burst"]
        self.assertEqual(sb["version"], "0.6.1")
        self.assertEqual(sb["kind"], "node-cli")
        self.assertEqual(sb["commands"], ["tfsb", "tfsb-studio-service"])
        self.assertEqual(sb["asset"]["sha256"], "53ef41a3de3335e042f2c4b1d299b1155b64bfc6556a84baf6a62cb28bcca209")

        # Stellar Loom (Node 22 CLI)
        sl = products["theme-forge-stellar-loom"]
        self.assertEqual(sl["version"], "0.4.0")
        self.assertEqual(sl["kind"], "node-cli")
        self.assertEqual(sl["commands"], ["tfsl", "tfsl-batch"])
        self.assertEqual(sl["asset"]["sha256"], "4550314d9a6eb9a016c8637eb2a0a98e9a410210ad6546642dfce31c7402c9ec")

        # Solar Sail (Node 22 CLI)
        ss = products["theme-forge-solar-sail"]
        self.assertEqual(ss["version"], "0.2.1")
        self.assertEqual(ss["kind"], "node-cli")
        self.assertEqual(ss["commands"], ["tfss"])
        self.assertEqual(ss["asset"]["sha256"], "ebc4f21d1e61dbc0ac4e87ce81f7ecec4f97d7c15562356e429d4c1a4e9aa5a0")

        # Nebular Fusion (Materialized Desktop)
        nf = products["theme-forge-nebular-fusion"]
        self.assertEqual(nf["version"], "0.6.1")
        self.assertEqual(nf["kind"], "materialized-desktop")
        self.assertEqual(nf["commands"], ["tfnf"])
        self.assertEqual(
            nf["assets"]["aarch64-darwin"]["sha256"],
            "e5ab9c5ce5dd7fb02274b11b223db9db7ac1f3b2167334ee2f322abd3c8ec4be",
        )
        self.assertEqual(
            nf["assets"]["aarch64-linux"]["sha256"],
            "5d59a1dfb6b5cec5edced1b098eba7b79e4f77a0dd2a0ab815caa8992b17497f",
        )
        self.assertEqual(
            nf["assets"]["x86_64-linux"]["sha256"],
            "d6060f74d6e55ec3a096ac01a1ebadc8b8b1d89a9a51475cd52207b465ca434d",
        )

        # Removed fixture-derived hashes (payload manifest and executable SHA)
        fixture_hashes = {
            "41d9eaa1b7930efe1edaa33a600491bd9073da42f27445983fd4da88596995ba",
            "4c23d945757dadb74d9cadd7af1c3b3d6ef117b74a6e69883ad0cd17bcf1a729",
            "2ea9768f45528fd8513faab24383635e0d1ffcc86ff60a9df3c908335c32b563",
            "663c60a675165287e3157a279988bcd4bce556cf3c2a69d4bfd5ab937f60d867",
            "5c182d28c02f2d6ea09ed130625ef899a8d0fe4ca080df775d72cdd6cd43b743",
            "6efc9c12ff9148f9e20763c620b7abb1712c614fc796b1577e01913488c658e0",
        }
        for asset in nf["assets"].values():
            self.assertNotIn(asset.get("payload_manifest_sha256"), fixture_hashes)
            self.assertNotIn(asset.get("executable_sha256"), fixture_hashes)
            self.assertEqual(asset.get("payload_manifest_sha256"), "pending")
            self.assertEqual(asset.get("executable_sha256"), "pending")

        # Guessed library lists must not become qualification evidence.
        for asset in nf["assets"].values():
            self.assertNotIn("closure_evidence", asset)

        # Explicit qualification pending status
        self.assertEqual(nf["closure_qualification"]["status"], "not-run")
        self.assertEqual(nf["closure_qualification"]["native_proof_status"], "pending")
        self.assertFalse(nf["closure_qualification"].get("authenticated", True))

    def test_candidate_derivations_source_only_own_builder_files(self):
        for nix_file in [ROOT / "nix/node-cli.nix", ROOT / "nix/nebular.nix"]:
            text = nix_file.read_text()
            self.assertNotIn("src = ./.", text)
            self.assertNotIn("src = ../.", text)
            self.assertNotIn("src = .;", text)

    @unittest.skipUnless(__import__("shutil").which("nix-instantiate"), "Nix pure evaluator unavailable")
    def test_qualification_proof_pending_status(self):
        proc = subprocess.run(
            ["nix-instantiate", "--eval", "--strict", "--expr", f'(import {ROOT}/nix/default.nix {{}}).qualification'],
            capture_output=True,
            text=True,
        )
        self.assertEqual(proc.returncode, 0)
        self.assertIn('status = "pending";', proc.stdout)
        self.assertIn("crossPlatformGatesPending = true;", proc.stdout)
        self.assertIn("nativeProofPending = true;", proc.stdout)
        self.assertIn('nebularLinuxClosure = "not-run";', proc.stdout)
        self.assertIn("publicationOutputsExposed = false;", proc.stdout)
        self.assertIn("authenticated = false;", proc.stdout)
