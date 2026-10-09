"""Tests for RPM repository ownership audit, safe public tree helpers, and metadata signing."""

import errno
import os
from pathlib import Path
import stat
import tempfile
import unittest
from unittest.mock import MagicMock, patch

from rs9.build_native import CommandReceipt
from rs9.errors import ContractError
from rs9.hosted_deb import ContainerRunner, _user
from rs9.rpm_repository import (
    audit_owned_tree,
    prepare_public_directory,
    sign_metadata,
    write_public_file,
)
from rs9.signing_fixture import SigningFixture
from tests.test_hosted_deb import usable_gpg
from tests.test_repo_apt import FixtureSigner


class PreparePublicDirectoryTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name).resolve()
        os.chmod(self.root, 0o755)

    def tearDown(self):
        self.tmp.cleanup()

    def test_prepare_explicit_levels_creates_expected_modes_independent_of_umask(self):
        old_umask = os.umask(0o077)
        try:
            target = self.root / "fedora" / "43" / "x86_64" / "Packages"
            prepared = prepare_public_directory(target, self.root)
            self.assertEqual(prepared, target)
            self.assertTrue(target.is_dir())

            for d in (self.root, self.root / "fedora", self.root / "fedora" / "43",
                      self.root / "fedora" / "43" / "x86_64", target):
                mode = stat.S_IMODE(d.stat().st_mode)
                self.assertEqual(mode, 0o755, f"Directory {d} mode was {oct(mode)}, expected 0o755")
        finally:
            os.umask(old_umask)

    def test_prepare_directory_leaves_ancestor_and_siblings_untouched(self):
        parent_dir = self.root / "outside"
        parent_dir.mkdir(mode=0o700)
        os.chmod(parent_dir, 0o700)
        repo_root = parent_dir / "repo"
        sibling_dir = parent_dir / "sibling"
        sibling_dir.mkdir(mode=0o700)
        os.chmod(sibling_dir, 0o700)

        target = repo_root / "repodata"
        prepare_public_directory(target, repo_root)

        self.assertEqual(stat.S_IMODE(parent_dir.stat().st_mode), 0o700)
        self.assertEqual(stat.S_IMODE(sibling_dir.stat().st_mode), 0o700)
        self.assertEqual(stat.S_IMODE(repo_root.stat().st_mode), 0o755)
        self.assertEqual(stat.S_IMODE(target.stat().st_mode), 0o755)

    def test_prepare_directory_rejects_escape_outside_root(self):
        outside = self.root.parent / "escape"
        with self.assertRaises(ContractError) as caught:
            prepare_public_directory(outside, self.root)
        self.assertEqual(caught.exception.code, "RPM_REPOSITORY_OPERATION")
        self.assertEqual(caught.exception.details.get("causal_code"), "ESCAPE_DETECTED")
        self.assertEqual(caught.exception.details.get("substage"), "directory-preparation")

    def test_prepare_directory_rejects_symlink_in_path(self):
        sub = self.root / "sub"
        sub.mkdir()
        link = self.root / "symlink_dir"
        link.symlink_to(sub)
        with self.assertRaises(ContractError) as caught:
            prepare_public_directory(link / "target", self.root)
        self.assertEqual(caught.exception.code, "RPM_REPOSITORY_OPERATION")
        self.assertEqual(caught.exception.details.get("causal_code"), "SYMLINK_REJECTED")

    def test_prepare_directory_rejects_symlink_root(self):
        real_root = self.root / "real_root"
        real_root.mkdir()
        link_root = self.root / "link_root"
        link_root.symlink_to(real_root)
        with self.assertRaises(ContractError) as caught:
            prepare_public_directory(link_root / "subdir", link_root)
        self.assertEqual(caught.exception.code, "RPM_REPOSITORY_OPERATION")
        self.assertEqual(caught.exception.details.get("causal_code"), "SYMLINK_REJECTED")

    def test_prepare_directory_rejects_file_component(self):
        blocking_file = self.root / "fedora"
        blocking_file.write_text("not a dir")
        with self.assertRaises(ContractError) as caught:
            prepare_public_directory(self.root / "fedora" / "Packages", self.root)
        self.assertEqual(caught.exception.code, "RPM_REPOSITORY_OPERATION")
        self.assertEqual(caught.exception.details.get("causal_code"), "NOT_A_DIRECTORY")


class WritePublicFileTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name).resolve()
        os.chmod(self.root, 0o755)

    def tearDown(self):
        self.tmp.cleanup()

    def test_write_public_file_sets_mode_0644_independent_of_umask(self):
        old_umask = os.umask(0o077)
        try:
            target = self.root / "repomd.xml.asc"
            written = write_public_file(target, b"test-signature-data")
            self.assertEqual(written, target)
            self.assertEqual(target.read_bytes(), b"test-signature-data")
            mode = stat.S_IMODE(target.stat().st_mode)
            self.assertEqual(mode, 0o644, f"File mode was {oct(mode)}, expected 0o644")
        finally:
            os.umask(old_umask)

    def test_write_public_file_rejects_non_bytes(self):
        target = self.root / "bad.txt"
        with self.assertRaises(ContractError) as caught:
            write_public_file(target, "not bytes")  # type: ignore
        self.assertEqual(caught.exception.code, "RPM_REPOSITORY_OPERATION")
        self.assertEqual(caught.exception.details.get("causal_code"), "INVALID_DATA")

    def test_write_public_file_rejects_symlink_target(self):
        real_file = self.root / "real.xml"
        real_file.write_bytes(b"original")
        link_file = self.root / "link.xml"
        link_file.symlink_to(real_file)
        with self.assertRaises(ContractError) as caught:
            write_public_file(link_file, b"replacement")
        self.assertEqual(caught.exception.code, "RPM_REPOSITORY_OPERATION")
        self.assertEqual(caught.exception.details.get("causal_code"), "SYMLINK_REJECTED")

    def test_write_public_file_rejects_symlink_parent(self):
        real_dir = self.root / "real_dir"
        real_dir.mkdir()
        link_dir = self.root / "link_dir"
        link_dir.symlink_to(real_dir)
        with self.assertRaises(ContractError) as caught:
            write_public_file(link_dir / "file.txt", b"data")
        self.assertEqual(caught.exception.code, "RPM_REPOSITORY_OPERATION")
        self.assertEqual(caught.exception.details.get("causal_code"), "SYMLINK_REJECTED")

    def test_write_public_file_diagnostics_on_permission_error(self):
        read_only_dir = self.root / "readonly"
        read_only_dir.mkdir()
        target = read_only_dir / "file.xml"
        os.chmod(read_only_dir, 0o555)
        try:
            with self.assertRaises(ContractError) as caught:
                write_public_file(target, b"data")
            self.assertEqual(caught.exception.code, "RPM_REPOSITORY_OPERATION")
            self.assertEqual(caught.exception.details.get("substage"), "file-write")
            self.assertEqual(caught.exception.details.get("errno"), "EACCES")
        finally:
            os.chmod(read_only_dir, 0o755)


class AuditOwnedTreeTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name).resolve()
        os.chmod(self.root, 0o755)

    def tearDown(self):
        self.tmp.cleanup()

    def test_audit_passes_for_standard_tree_no_abs_paths_no_numeric_ids(self):
        sub = self.root / "repodata"
        sub.mkdir(mode=0o755)
        os.chmod(sub, 0o755)
        f1 = sub / "repomd.xml"
        f1.write_bytes(b"<xml/>")
        os.chmod(f1, 0o644)
        f2 = sub / "repomd.xml.asc"
        f2.write_bytes(b"sig")
        os.chmod(f2, 0o644)

        audit = audit_owned_tree(self.root)
        self.assertEqual(audit["status"], "pass")
        self.assertTrue(audit["compatible"])
        self.assertEqual(audit["total_files"], 2)
        self.assertEqual(audit["total_directories"], 2)
        self.assertEqual(audit["violations"], [])
        self.assertIn("self", audit["owner_summary"])

        def assert_no_leak(obj):
            if isinstance(obj, str):
                self.assertFalse(obj.startswith("/"), f"Leaked absolute path: {obj}")
            elif isinstance(obj, dict):
                for k, v in obj.items():
                    self.assertNotIn("uid", k.lower())
                    self.assertNotIn("gid", k.lower())
                    assert_no_leak(k)
                    assert_no_leak(v)
            elif isinstance(obj, list):
                for item in obj:
                    assert_no_leak(item)

        assert_no_leak(audit)

    def test_audit_detects_bad_file_mode(self):
        f = self.root / "bad_file.txt"
        f.write_bytes(b"content")
        os.chmod(f, 0o600)

        audit = audit_owned_tree(self.root)
        self.assertEqual(audit["status"], "fail")
        self.assertEqual(len(audit["violations"]), 1)
        self.assertEqual(audit["violations"][0]["issue"], "file-mode-mismatch")
        self.assertEqual(audit["violations"][0]["path"], "bad_file.txt")

    def test_audit_detects_bad_dir_mode(self):
        d = self.root / "bad_dir"
        d.mkdir(mode=0o700)
        os.chmod(d, 0o700)

        audit = audit_owned_tree(self.root)
        self.assertEqual(audit["status"], "fail")
        self.assertTrue(any(v["issue"] == "directory-mode-mismatch" for v in audit["violations"]))

    def test_audit_detects_symlink(self):
        f = self.root / "target.txt"
        f.write_bytes(b"data")
        os.chmod(f, 0o644)
        link = self.root / "link.txt"
        link.symlink_to(f)

        audit = audit_owned_tree(self.root)
        self.assertEqual(audit["status"], "fail")
        self.assertTrue(any(v["issue"] == "symlink-rejected" for v in audit["violations"]))

    def test_audit_root_guard_and_distinct_owner_controls(self):
        f = self.root / "test.txt"
        f.write_bytes(b"data")
        os.chmod(f, 0o644)

        orig_lstat = os.lstat

        def mock_lstat_root(path):
            st = orig_lstat(path)
            return os.stat_result((
                st.st_mode, st.st_ino, st.st_dev, st.st_nlink,
                0, 0,  # root UID and GID
                st.st_size, st.st_atime, st.st_mtime, st.st_ctime
            ))

        def mock_lstat_other(path):
            st = orig_lstat(path)
            return os.stat_result((
                st.st_mode, st.st_ino, st.st_dev, st.st_nlink,
                9999, 9999,  # other UID and GID
                st.st_size, st.st_atime, st.st_mtime, st.st_ctime
            ))

        with patch("rs9.rpm_repository.os.getuid", return_value=1000):
            with patch("rs9.rpm_repository.os.lstat", side_effect=mock_lstat_root):
                audit_root = audit_owned_tree(self.root)
                self.assertEqual(audit_root["status"], "fail")
                self.assertFalse(audit_root["compatible"])
                self.assertEqual(audit_root["owner_summary"]["root"], 2)  # root dir + file
                self.assertTrue(any("incompatible-owner:root" in v["issue"] for v in audit_root["violations"]))

            with patch("rs9.rpm_repository.os.lstat", side_effect=mock_lstat_other):
                audit_other = audit_owned_tree(self.root)
                self.assertEqual(audit_other["status"], "fail")
                self.assertFalse(audit_other["compatible"])
                self.assertEqual(audit_other["owner_summary"]["other"], 2)
                self.assertTrue(any("incompatible-owner:other" in v["issue"] for v in audit_other["violations"]))


class SignMetadataTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name).resolve()
        self.repodata = self.root / "repodata"
        self.repodata.mkdir(mode=0o755)
        os.chmod(self.repodata, 0o755)
        os.chmod(self.root, 0o755)
        self.repomd = self.repodata / "repomd.xml"
        self.repomd.write_bytes(b"<repomd><revision>1</revision></repomd>\n")
        os.chmod(self.repomd, 0o644)
        self.signer = FixtureSigner()
        self.receipt = CommandReceipt(
            ["createrepo_c", "--no-database", str(self.root)],
            0,
            b"createrepo_c complete\n",
            b"",
            tool_name="createrepo_c",
        )

    def tearDown(self):
        self.tmp.cleanup()

    def test_sign_metadata_full_sequence_with_fixture_signer(self):
        report = sign_metadata(self.signer, self.root, receipt=self.receipt)
        self.assertEqual(report["status"], "pass")
        self.assertEqual(report["index_path"], "repodata/repomd.xml")
        self.assertEqual(report["signature_path"], "repodata/repomd.xml.asc")
        self.assertEqual(report["verified_issuer"], self.signer.primary_fingerprint)
        self.assertEqual(report["receipt_stdout_sha256"], self.receipt.stdout_sha256)
        self.assertEqual(report["receipt_stderr_sha256"], self.receipt.stderr_sha256)
        self.assertEqual(report["receipt_exit_code"], 0)

        sig_path = self.repodata / "repomd.xml.asc"
        self.assertTrue(sig_path.is_file())
        self.assertEqual(stat.S_IMODE(sig_path.stat().st_mode), 0o644)

        # Verification passes
        verified = self.signer.verify(self.repomd.read_bytes(), sig_path.read_bytes())
        self.assertEqual(verified["verified_issuer"], self.signer.primary_fingerprint)

    def test_sign_metadata_with_real_gpg_when_available(self):
        binary = usable_gpg()
        if not binary:
            self.skipTest("Real GnuPG binary not available on this host")

        with SigningFixture(gpg_binary=binary) as fixture:
            report = sign_metadata(fixture, self.root, receipt=self.receipt)
            self.assertEqual(report["status"], "pass")
            self.assertEqual(report["verified_issuer"], fixture.primary_fingerprint)
            sig_path = self.repodata / "repomd.xml.asc"
            self.assertTrue(sig_path.is_file())
            self.assertEqual(stat.S_IMODE(sig_path.stat().st_mode), 0o644)

    def test_sign_metadata_substage_read_failure_diagnostics(self):
        self.repomd.unlink()
        with self.assertRaises(ContractError) as caught:
            sign_metadata(self.signer, self.root, receipt=self.receipt)
        self.assertEqual(caught.exception.code, "RPM_REPOSITORY_OPERATION")
        details = caught.exception.details
        self.assertEqual(details["operation"], "repodata-index-read")
        self.assertEqual(details["substage"], "index-read")
        self.assertEqual(details["target"], "repodata/repomd.xml")
        self.assertEqual(details["causal_code"], "FileNotFoundError")
        self.assertEqual(details["errno"], "ENOENT")
        self.assertEqual(details["stdout_sha256"], self.receipt.stdout_sha256)
        self.assertEqual(details["stderr_sha256"], self.receipt.stderr_sha256)

    def test_sign_metadata_substage_sign_failure_diagnostics(self):
        broken_signer = MagicMock()
        broken_signer.detach_sign.side_effect = RuntimeError("GPG agent disconnected")
        with self.assertRaises(ContractError) as caught:
            sign_metadata(broken_signer, self.root, receipt=self.receipt)
        self.assertEqual(caught.exception.code, "RPM_REPOSITORY_OPERATION")
        details = caught.exception.details
        self.assertEqual(details["operation"], "repodata-fixture-sign")
        self.assertEqual(details["substage"], "fixture-sign")
        self.assertEqual(details["target"], "repodata/repomd.xml.asc")
        self.assertEqual(details["stdout_sha256"], self.receipt.stdout_sha256)

    def test_sign_metadata_substage_write_failure_diagnostics(self):
        os.chmod(self.repodata, 0o555)
        try:
            with self.assertRaises(ContractError) as caught:
                sign_metadata(self.signer, self.root, receipt=self.receipt)
            self.assertEqual(caught.exception.code, "RPM_REPOSITORY_OPERATION")
            details = caught.exception.details
            self.assertEqual(details["operation"], "repodata-signature-write")
            self.assertEqual(details["substage"], "signature-write")
            self.assertEqual(details["target"], "repodata/repomd.xml.asc")
            self.assertEqual(details["errno"], "EACCES")
            self.assertEqual(details["stdout_sha256"], self.receipt.stdout_sha256)
        finally:
            os.chmod(self.repodata, 0o755)

    def test_sign_metadata_substage_verify_failure_diagnostics(self):
        wrong_signer = FixtureSigner(fingerprint="B" * 40)
        mock_signer = MagicMock()
        mock_signer.detach_sign.side_effect = lambda data, armor=True: wrong_signer.detach_sign(data, armor=armor)
        mock_signer.verify.side_effect = lambda data, sig: self.signer.verify(data, sig)

        with self.assertRaises(ContractError) as caught:
            sign_metadata(mock_signer, self.root, receipt=self.receipt)
        self.assertEqual(caught.exception.code, "RPM_REPOSITORY_OPERATION")
        details = caught.exception.details
        self.assertEqual(details["operation"], "repodata-signature-verify")
        self.assertEqual(details["substage"], "signature-verify")
        self.assertEqual(details["target"], "repodata/repomd.xml.asc")
        self.assertEqual(details["causal_code"], "UNPINNED_TRUST")
        self.assertEqual(details["stdout_sha256"], self.receipt.stdout_sha256)

    def test_sign_metadata_substage_audit_failure_diagnostics(self):
        bad_file = self.root / "bad_perm.rpm"
        bad_file.write_bytes(b"content")
        os.chmod(bad_file, 0o777)

        with self.assertRaises(ContractError) as caught:
            sign_metadata(self.signer, self.root, receipt=self.receipt)
        self.assertEqual(caught.exception.code, "RPM_REPOSITORY_OPERATION")
        details = caught.exception.details
        self.assertEqual(details["operation"], "repodata-public-modes")
        self.assertEqual(details["substage"], "public-modes")
        self.assertEqual(details["causal_code"], "AUDIT_FAILED")
        self.assertEqual(details["stdout_sha256"], self.receipt.stdout_sha256)


class ContainerRunnerArgvTests(unittest.TestCase):
    def test_container_runner_docker_argv_nonroot_user_and_shared_mounts(self):
        host = MagicMock()
        stage = "/path/to/stage"
        homedir = "/path/to/fixture_home"
        runner = ContainerRunner(
            host,
            "rs9-pages-fedora:test",
            platform="linux/amd64",
            mounts=[(stage, stage, True), (homedir, homedir, False)],
            user="1000:1000",
        )
        argv = runner.docker_argv(["rpmsign", "--addsign", "/path/to/pkg.rpm"])

        self.assertIn("--user", argv)
        self.assertIn("1000:1000", argv)
        self.assertIn("-e", argv)
        self.assertIn("HOME=/tmp", argv)
        self.assertIn("-v", argv)
        self.assertIn(f"{stage}:{stage}", argv)
        self.assertIn(f"{homedir}:{homedir}:ro", argv)
        self.assertIn("--network", argv)
        self.assertIn("none", argv)
        self.assertEqual(argv[-4:], ["rs9-pages-fedora:test", "rpmsign", "--addsign", "/path/to/pkg.rpm"])

    def test_container_runner_docker_argv_root_omits_user_flag(self):
        host = MagicMock()
        runner = ContainerRunner(
            host,
            "rs9-deb-builder:test",
            platform="linux/amd64",
            user=None,
        )
        argv = runner.docker_argv(["dpkg-deb", "-b", "/dir", "/out.deb"])
        self.assertNotIn("--user", argv)
        self.assertNotIn("HOME=/tmp", argv)

    def test_user_helper_returns_uid_gid_for_nonroot_and_none_for_root(self):
        with patch("rs9.hosted_deb.os.getuid", return_value=1001), patch("rs9.hosted_deb.os.getgid", return_value=1002):
            self.assertEqual(_user(), "1001:1002")

        with patch("rs9.hosted_deb.os.getuid", return_value=0), patch("rs9.hosted_deb.os.getgid", return_value=0):
            self.assertIsNone(_user())


if __name__ == "__main__":
    unittest.main()
