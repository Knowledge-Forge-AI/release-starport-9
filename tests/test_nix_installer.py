"""Adverse tests for authenticated Nix-only extraction and source pin custody."""
import io
import json
import os
from pathlib import Path
import stat
import tarfile
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from rs9.errors import ContractError
from rs9.nix_installer import extract_installer_archive, get_installer_pin, install, verify_physical_executable
from rs9.release_core import digest

SYSTEM = "x86_64-linux"
VERSION = "2.31.2"
TOP = "nix-" + VERSION + "-" + SYSTEM
STORE = "4j6p91af1bfgnn31agg1c9ijr0kyg6gi-gcc-14.3.0-libgcc"
INSTALL = (TOP + "/install", tarfile.REGTYPE, b"#!/bin/sh\nexit 0\n", 0o755, "")


def archive_bytes(entries):
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode="w") as tar:
        for name, kind, data, mode, target in entries:
            item = tarfile.TarInfo(name)
            item.type, item.mode, item.linkname = kind, mode, target
            item.size = len(data) if kind == tarfile.REGTYPE else 0
            tar.addfile(item, io.BytesIO(data) if kind == tarfile.REGTYPE else None)
    return stream.getvalue()


class InstallerExtractionTests(unittest.TestCase):
    def extract(self, entries, *, bad_pin=False):
        raw = archive_bytes(entries)
        archive = self.root / "installer.tar"
        archive.write_bytes(raw)
        return extract_installer_archive(archive, self.output, expected_sha256="0" * 64 if bad_pin else digest(raw),
                                         version=VERSION, system=SYSTEM)

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.output = self.root / "output"
        self.output.mkdir()

    def reject(self, entries):
        with self.assertRaises(ContractError) as caught:
            self.extract([INSTALL, *entries])
        self.assertEqual(caught.exception.code, "NIX_INSTALLER_UNSAFE")
        self.assertEqual(list(self.output.iterdir()), [])

    def test_authentic_absolute_store_link_and_implicit_directories(self):
        target = "/nix/store/" + STORE + "/lib/libgcc_s.so.1"
        evidence = self.extract([INSTALL,
            (TOP + "/store/" + STORE + "/lib/libgcc_s.so", tarfile.SYMTYPE, b"", 0o777, target),
            (TOP + "/store/" + STORE + "/lib/libgcc_s.so.1", tarfile.REGTYPE, b"library", 0o755, "")])
        link = self.output / TOP / "store" / STORE / "lib/libgcc_s.so"
        self.assertEqual(os.readlink(link), target)
        self.assertEqual(evidence["absolute_store_symlinks"], 1)
        self.assertEqual(evidence["member_count"], 3)
        self.assertTrue((self.output / TOP / "install").stat().st_mode & 0o111)
        self.assertEqual(stat.S_IMODE((link.parent).stat().st_mode), 0o755)

    def test_absolute_store_target_must_exist_in_archive(self):
        self.reject([(TOP + "/link", tarfile.SYMTYPE, b"", 0o777, "/nix/store/" + STORE + "/missing")])

    def test_forbidden_absolute_links(self):
        for target in ("/etc/passwd", "/bin/sh", "/nix/store/foo/lib", "/nix/store/" + STORE + "/../bad",
                       "/nix/store/" + STORE + "//lib", "/nix/store/" + STORE + "/./lib"):
            with self.subTest(target=target):
                self.reject([(TOP + "/link", tarfile.SYMTYPE, b"", 0o777, target)])

    def test_member_path_traversal_and_wrong_top_level(self):
        for name in ("../outside", "/etc/file", TOP + "/../outside", TOP + "/./file", TOP + "//file",
                     "other/file", TOP + "/back\\slash"):
            with self.subTest(name=name):
                self.reject([(name, tarfile.REGTYPE, b"bad", 0o644, "")])

    def test_forward_and_backward_symlink_ancestors_rejected_before_writes(self):
        link = (TOP + "/dir", tarfile.SYMTYPE, b"", 0o777, "real")
        child = (TOP + "/dir/child", tarfile.REGTYPE, b"bad", 0o644, "")
        for entries in ([link, child], [child, link]):
            with self.subTest(order=entries[0][1]):
                self.reject(entries)

    def test_file_ancestor_rejected(self):
        self.reject([(TOP + "/dir/child", tarfile.REGTYPE, b"bad", 0o644, ""),
                     (TOP + "/dir", tarfile.REGTYPE, b"file", 0o644, "")])

    def test_hardlink_escape_and_all_special_types_rejected(self):
        for kind in (tarfile.LNKTYPE, tarfile.CHRTYPE, tarfile.BLKTYPE, tarfile.FIFOTYPE, tarfile.CONTTYPE, b"s"):
            with self.subTest(kind=kind):
                self.reject([(TOP + "/bad", kind, b"", 0o644, "../../etc/passwd")])

    def test_relative_parent_links_allowed_only_inside_expected_top(self):
        self.extract([INSTALL, (TOP + "/lib/link", tarfile.SYMTYPE, b"", 0o777, "../install")])
        self.assertEqual(os.readlink(self.output / TOP / "lib/link"), "../install")
        with tempfile.TemporaryDirectory() as tmp:
            self.output = Path(tmp).resolve()
            self.reject([(TOP + "/escape", tarfile.SYMTYPE, b"", 0o777, "../outside")])

    def test_duplicates_and_privilege_modes_rejected(self):
        self.reject([INSTALL])
        for mode in (0o4755, 0o2755, 0o1755):
            self.reject([(TOP + "/bad", tarfile.REGTYPE, b"bad", mode, "")])

    def test_sha_checked_before_archive_parsing(self):
        archive = self.root / "not-a-tar"
        archive.write_bytes(b"not a tar")
        with patch("rs9.nix_installer.tarfile.open") as parse:
            with self.assertRaises(ContractError) as caught:
                extract_installer_archive(archive, self.output, expected_sha256="0" * 64,
                                         version=VERSION, system=SYSTEM)
            parse.assert_not_called()
        self.assertEqual(caught.exception.code, "NIX_INSTALLER_CHECKSUM")
        self.assertEqual(list(self.output.iterdir()), [])

    def test_nonempty_and_symlink_roots_rejected(self):
        (self.output / "sentinel").write_bytes(b"unchanged")
        with self.assertRaises(ContractError):
            self.extract([INSTALL])
        self.assertEqual((self.output / "sentinel").read_bytes(), b"unchanged")
        linked = self.root / "linked"
        linked.symlink_to(self.output)
        self.output = linked
        with self.assertRaises(ContractError) as caught:
            self.extract([INSTALL])
        self.assertEqual(caught.exception.code, "SYMLINK_REJECTED")

    def test_only_physical_executable_installer_allowed(self):
        self.extract([INSTALL])
        path = self.output / TOP / "install"
        verify_physical_executable(path)
        path.chmod(0o644)
        with self.assertRaises(ContractError):
            verify_physical_executable(path)
        path.unlink()
        path.symlink_to("/bin/sh")
        with self.assertRaises(ContractError):
            verify_physical_executable(path)

    def test_symlink_aware_parent_resolution_and_loops(self):
        self.reject([(TOP + "/d/up", tarfile.SYMTYPE, b"", 0o777, ".."),
                     (TOP + "/x", tarfile.SYMTYPE, b"", 0o777, "d/up/../..")])
        self.reject([(TOP + "/a", tarfile.SYMTYPE, b"", 0o777, "b"),
                     (TOP + "/b", tarfile.SYMTYPE, b"", 0o777, "a")])

    def test_explicit_directories_after_implicit_parents_are_created_once(self):
        self.extract([INSTALL, (TOP, tarfile.DIRTYPE, b"", 0o755, "")])
        self.assertEqual(sorted(p.name for p in (self.output / TOP).iterdir()), ["install"])

    def test_missing_member_data_is_closed_and_cleans_partial_output(self):
        with patch("rs9.nix_installer.tarfile.TarFile.extractfile", return_value=None):
            with self.assertRaises(ContractError) as caught:
                self.extract([INSTALL])
        self.assertEqual(caught.exception.code, "NIX_INSTALLER_UNSAFE")
        self.assertEqual(caught.exception.details["cleanup"], "complete")
        self.assertEqual(list(self.output.iterdir()), [])

    def test_corrupt_authenticated_compressed_bytes_give_stable_error(self):
        import lzma
        raw = lzma.compress(archive_bytes([INSTALL]))[:20]
        archive = self.root / "corrupt.tar.xz"
        archive.write_bytes(raw)
        with self.assertRaises(ContractError) as caught:
            extract_installer_archive(archive, self.output, expected_sha256=digest(raw), version=VERSION, system=SYSTEM)
        self.assertEqual(caught.exception.code, "NIX_INSTALLER_EXTRACTION")
        self.assertEqual(list(self.output.iterdir()), [])

    def test_mid_write_failure_is_cleaned_without_following_links(self):
        original, calls = os.fchmod, 0
        def fail_once(fd, mode):
            nonlocal calls
            calls += 1
            if calls == 1:
                raise OSError("injected disk failure")
            return original(fd, mode)
        with patch("rs9.nix_installer.os.fchmod", side_effect=fail_once):
            with self.assertRaises(ContractError) as caught:
                self.extract([INSTALL])
        self.assertEqual(caught.exception.code, "NIX_INSTALLER_EXTRACTION")
        self.assertEqual(caught.exception.details["cleanup"], "complete")
        self.assertEqual(list(self.output.iterdir()), [])

    def test_readonly_directories_are_removed_after_readback_failure(self):
        with patch("rs9.nix_installer.verify_physical_inventory", side_effect=OSError("injected readback failure")):
            with self.assertRaises(ContractError) as caught:
                self.extract([INSTALL, (TOP, tarfile.DIRTYPE, b"", 0o555, "")])
        self.assertEqual(caught.exception.details["cleanup"], "complete")
        self.assertEqual(list(self.output.iterdir()), [])

    def test_archive_change_after_authentication_does_not_change_parsed_bytes(self):
        original = tarfile.open
        def mutate_before_parse(*args, **kwargs):
            (self.root / "installer.tar").write_bytes(b"changed after authentication")
            return original(*args, **kwargs)
        raw = archive_bytes([INSTALL])
        archive = self.root / "installer.tar"
        archive.write_bytes(raw)
        with patch("rs9.nix_installer.tarfile.open", side_effect=mutate_before_parse):
            evidence = extract_installer_archive(archive, self.output, expected_sha256=digest(raw), version=VERSION, system=SYSTEM)
        self.assertEqual(evidence["install_sha256"], digest(INSTALL[2]))

    def test_physical_readback_rejects_changed_install_bytes(self):
        from rs9.nix_installer import verify_physical_inventory
        def tamper(fd, expected):
            (self.output / TOP / "install").write_bytes(b"tampered")
            return verify_physical_inventory(fd, expected)
        with patch("rs9.nix_installer.verify_physical_inventory", side_effect=tamper):
            with self.assertRaises(ContractError) as caught:
                self.extract([INSTALL])
        self.assertEqual(caught.exception.details["reason"], "physical-inventory-mismatch")
        self.assertEqual(caught.exception.details["cleanup"], "complete")
        self.assertEqual(list(self.output.iterdir()), [])


    def test_absolute_store_symlink_upward_traversal_fails_closed(self):
        entries = [
            (TOP + "/store/" + STORE + "/lib/libgcc_s.so", tarfile.SYMTYPE, b"", 0o777, "/nix/store/" + STORE + "/lib/inner"),
            (TOP + "/store/" + STORE + "/lib/inner", tarfile.SYMTYPE, b"", 0o777, "../libgcc_s.so.1"),
            (TOP + "/store/" + STORE + "/libgcc_s.so.1", tarfile.REGTYPE, b"lib", 0o755, ""),
        ]
        with self.assertRaises(ContractError) as caught:
            self.extract([INSTALL, *entries])
        self.assertEqual(caught.exception.code, "NIX_INSTALLER_UNSAFE")
        self.assertEqual(caught.exception.details.get("reason"), "ambiguous-upward-traversal")

    def test_cleanup_failure_restores_caller_original_physical_root_mode(self):
        initial_mode = 0o755
        self.output.chmod(initial_mode)
        def fail_cleanup(fd):
            raise OSError("disk error during cleanup")
        with patch("rs9.nix_installer.verify_physical_inventory", side_effect=OSError("force fail before readback")), \
             patch("rs9.nix_installer._cleanup_directory", side_effect=fail_cleanup):
            with self.assertRaises(ContractError) as caught:
                self.extract([INSTALL])
            self.assertEqual(caught.exception.details.get("cleanup"), "failed")
        self.assertEqual(stat.S_IMODE(self.output.stat().st_mode), initial_mode)


def find_official_nix_archives():
    candidates = []
    if os.environ.get("RS9_OFFICIAL_NIX_ARCHIVES"):
        candidates.append(Path(os.environ["RS9_OFFICIAL_NIX_ARCHIVES"]).resolve())
    candidates.extend([
        Path("/tmp/rs9-scratch/official-nix-archives").resolve(),
        Path("/private/tmp/rs9-scratch/official-nix-archives").resolve(),
    ])
    for candidate in candidates:
        if candidate.is_dir():
            required = [candidate / f"nix-{VERSION}-{sys}.tar.xz" for sys in ("aarch64-darwin", "x86_64-linux", "aarch64-linux")]
            if all(p.is_file() for p in required):
                return candidate
    return None


OFFICIAL_ARCHIVES = find_official_nix_archives()


@unittest.skipUnless(OFFICIAL_ARCHIVES, "official archive directory not locatable")
class OfficialArchiveTests(unittest.TestCase):
    def verify_system(self, system):
        repository = Path(__file__).resolve().parents[1]
        targets = json.loads((repository / "operators/live1/targets.json").read_bytes())["nix"]
        historical = json.loads((repository / "evidence/live1/hosted4-pins-readback.json").read_bytes())["parent_closed_extractor_validation"][system]
        archive = OFFICIAL_ARCHIVES / ("nix-" + VERSION + "-" + system + ".tar.xz")
        with tempfile.TemporaryDirectory() as tmp:
            evidence = extract_installer_archive(archive, Path(tmp).resolve(), expected_sha256=get_installer_pin(targets, system),
                                                 version=VERSION, system=system)
        for field in ("member_count", "regular_files", "directories", "symlinks", "absolute_store_symlinks", "uncompressed_bytes", "extraction_manifest_sha256"):
            self.assertEqual(evidence[field], historical[field], (system, field))
        self.assertRegex(evidence["physical_manifest_sha256"], r"^[0-9a-f]{64}$")
        self.assertRegex(evidence["install_sha256"], r"^[0-9a-f]{64}$")
        print("NIX_ARCHIVE=" + json.dumps({"system": system, "archive_sha256": get_installer_pin(targets, system), **evidence}, sort_keys=True))

    def test_aarch64_darwin(self):
        self.verify_system("aarch64-darwin")

    def test_x86_64_linux(self):
        self.verify_system("x86_64-linux")

    def test_aarch64_linux(self):
        self.verify_system("aarch64-linux")


class InstallerPinCustodyTests(unittest.TestCase):
    def test_exact_per_system_pin_map(self):
        targets = json.loads((Path(__file__).resolve().parents[1] / "operators/live1/targets.json").read_bytes())["nix"]
        for system in ("aarch64-darwin", SYSTEM, "aarch64-linux"):
            self.assertEqual(get_installer_pin(targets, system), targets["installer_sha256_by_system"][system])
        for pins in ({SYSTEM: "a" * 64}, {"installer_sha256": "a" * 64},
                     {**targets["installer_sha256_by_system"], "other": "a" * 64}):
            cfg = {"installer_sha256_by_system": pins}
            with self.assertRaises(ContractError):
                get_installer_pin(cfg, SYSTEM)

    def test_installer_download_binds_system_pin_and_safe_failure(self):
        raw = archive_bytes([INSTALL])
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            (root / "operators/live1").mkdir(parents=True)
            targets = {"nix": {"installer_version": VERSION, "installer_sha256_by_system": {
                system: digest(raw) for system in ("aarch64-darwin", SYSTEM, "aarch64-linux")}}}
            (root / "operators/live1/targets.json").write_text(json.dumps(targets))
            client = Mock()
            client.get.return_value = raw
            runner = Mock(return_value=SimpleNamespace(returncode=1, stdout=b"private stdout", stderr=b"private stderr"))
            with patch("rs9.nix_installer.get_current_system", return_value=SYSTEM):
                with self.assertRaises(ContractError) as caught:
                    install(root, root / "work", client=client, runner=runner)
            self.assertEqual(caught.exception.code, "NIX_INSTALLER_EXECUTION")
            self.assertIn("nix-2.31.2-x86_64-linux.tar.xz", client.get.call_args.args[0])
            failure = json.loads((root / "work/installer-failure.json").read_bytes())
            self.assertEqual(failure["sha256"], digest(raw))
            self.assertEqual(failure["error"], "NIX_INSTALLER_EXECUTION")
            self.assertNotIn("private", json.dumps(failure))

    def test_sha_failure_never_executes_installer(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            (root / "operators/live1").mkdir(parents=True)
            (root / "operators/live1/targets.json").write_text(json.dumps({"nix": {
                "installer_version": VERSION, "installer_sha256_by_system": {
                    s: "a" * 64 for s in ("aarch64-darwin", SYSTEM, "aarch64-linux")}}}))
            client, runner = Mock(), Mock()
            client.get.return_value = b"invalid tar"
            with patch("rs9.nix_installer.get_current_system", return_value=SYSTEM):
                with self.assertRaises(ContractError):
                    install(root, root / "work", client=client, runner=runner)
            runner.assert_not_called()
            self.assertEqual(json.loads((root / "work/installer-failure.json").read_bytes())["error"], "NIX_INSTALLER_CHECKSUM")
