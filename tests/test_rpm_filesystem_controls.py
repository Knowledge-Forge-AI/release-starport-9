"""Real filesystem writer controls; these do not claim Docker or RPM execution."""
import errno
import json
import os
from pathlib import Path
import stat
import tempfile
import unittest

from rs9.build_native import CommandReceipt
from rs9.errors import ContractError
from rs9.rpm_repository import prepare_public_directory, sign_metadata, write_public_file
from tests.test_repo_apt import FixtureSigner


class RpmFilesystemControls(unittest.TestCase):
    def make_repository(self, root, mask):
        old = os.umask(mask)
        try:
            repository = root / "rpm"
            directory = prepare_public_directory(repository / "fedora/43/noarch/repodata", repository)
            from tests.rpm_metadata_fixtures import create_valid_repodata
            create_valid_repodata(directory.parent)
            return directory.parent
        finally:
            os.umask(old)

    def test_host_write_verify_and_public_modes_under_both_umasks(self):
        for mask in (0o022, 0o077):
            with self.subTest(umask=oct(mask)), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp).resolve()
                directory = self.make_repository(root, mask)
                index = directory / "repodata/repomd.xml"
                before = index.read_bytes()
                old = os.umask(mask)
                try:
                    report = sign_metadata(FixtureSigner(), directory)
                finally:
                    os.umask(old)
                self.assertEqual(report["status"], "pass")
                self.assertEqual(index.read_bytes(), before)
                for p in (root / "rpm", *(root / "rpm").rglob("*")):
                    self.assertEqual(stat.S_IMODE(p.stat().st_mode), 0o755 if p.is_dir() else 0o644)

    @unittest.skipIf(os.geteuid() == 0, "root bypasses DAC; use the distinct unprivileged writer control")
    def test_signature_write_failure_retains_errno_relations_and_original_index(self):
        for mask in (0o022, 0o077):
            with self.subTest(umask=oct(mask)), tempfile.TemporaryDirectory() as tmp:
                directory = self.make_repository(Path(tmp).resolve(), mask)
                index = directory / "repodata/repomd.xml"
                before = index.read_bytes()
                parent = index.parent
                parent.chmod(0o555)
                receipt = CommandReceipt(["createrepo_c", "fixture-repository"], 0, b"created", b"")
                try:
                    with self.assertRaises(ContractError) as caught:
                        sign_metadata(FixtureSigner(), directory, receipt)
                    detail = caught.exception.details
                    self.assertEqual(detail["operation"], "repodata-signature-write")
                    self.assertEqual(detail["target"], "repodata/repomd.xml.asc")
                    self.assertEqual(detail["errno"], errno.errorcode[errno.EACCES])
                    self.assertEqual(detail["causal_code"], "PermissionError")
                    self.assertIs(detail["writer_is_owner"], True)
                    self.assertIs(detail["target_exists"], False)
                    self.assertEqual(detail["parent_mode"], "0555")
                    self.assertEqual(detail["stdout_sha256"], receipt.stdout_sha256)
                    self.assertEqual(detail["stderr_sha256"], receipt.stderr_sha256)
                    self.assertNotIn(str(directory), json.dumps(detail))
                    self.assertEqual(index.read_bytes(), before)
                finally:
                    parent.chmod(0o755)

    @unittest.skipUnless(os.geteuid() == 0 and hasattr(os, "fork"),
                         "distinct real writer ownership needs root and POSIX fork")
    def test_distinct_unprivileged_writer_negative_and_owner_aligned_positive(self):
        for mask in (0o022, 0o077):
            with self.subTest(umask=oct(mask)), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp).resolve()
                root.chmod(0o755)
                directory = self.make_repository(root, mask)
                index = directory / "repodata/repomd.xml"
                before = index.read_bytes()
                for aligned in (False, True):
                    if aligned:
                        # Confined disposable fixture tree only; no host or checkout ownership changes.
                        for p in (root / "rpm", *(root / "rpm").rglob("*")):
                            os.chown(p, 65534, 65534)
                    read_fd, write_fd = os.pipe()
                    pid = os.fork()
                    if pid == 0:
                        os.close(read_fd)
                        try:
                            os.setgroups([])
                            os.setgid(65534)
                            os.setuid(65534)
                            os.umask(mask)
                            try:
                                sign_metadata(FixtureSigner(), directory)
                                outcome = {"status": "pass"}
                            except ContractError as error:
                                outcome = {"status": "fail", "code": error.code, "details": error.details}
                            os.write(write_fd, json.dumps(outcome).encode())
                        finally:
                            os.close(write_fd)
                            os._exit(0)
                    os.close(write_fd)
                    with os.fdopen(read_fd, "rb") as stream:
                        outcome = json.loads(stream.read(8192))
                    _, child_status = os.waitpid(pid, 0)
                    self.assertEqual(child_status, 0)
                    self.assertEqual(outcome["status"], "pass" if aligned else "fail")
                    if not aligned:
                        self.assertEqual(outcome["details"]["errno"], "EACCES")
                        self.assertIs(outcome["details"]["writer_is_owner"], False)
                        self.assertIs(outcome["details"]["owner_is_root"], True)
                    self.assertEqual(index.read_bytes(), before)

    @unittest.skipIf(os.geteuid() == 0, "root bypasses read DAC")
    def test_actual_index_read_denial_is_separate_from_signature_write(self):
        with tempfile.TemporaryDirectory() as tmp:
            directory = self.make_repository(Path(tmp).resolve(), 0o077)
            index = directory / "repodata/repomd.xml"
            index.chmod(0)
            try:
                with self.assertRaises(ContractError) as caught:
                    sign_metadata(FixtureSigner(), directory)
                self.assertEqual(caught.exception.details["operation"], "repodata-index-read")
                self.assertEqual(caught.exception.details["target"], "repodata/repomd.xml")
                self.assertEqual(caught.exception.details["errno"], "EACCES")
                self.assertEqual(caught.exception.details["causal_code"], "PermissionError")
            finally:
                index.chmod(0o644)
            self.assertFalse((index.parent / "repomd.xml.asc").exists())

    def test_traversal_reentry_cannot_chmod_a_repository_ancestor(self):
        with tempfile.TemporaryDirectory() as tmp:
            parent = Path(tmp).resolve()
            root = parent / "rpm"
            root.mkdir()
            parent.chmod(0o700)
            with self.assertRaises(ContractError):
                prepare_public_directory(root / ".." / "rpm" / "child", root)
            self.assertEqual(parent.stat().st_mode & 0o777, 0o700)
