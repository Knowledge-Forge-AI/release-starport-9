"""Repository operation diagnostics retain safe filesystem relationships."""
import unittest

from pathlib import Path
import tempfile

from rs9.build_native import CommandReceipt, CommandRunner
from rs9.errors import ContractError, safe_details
from rs9.hosted_deb import _run_tool_container
from rs9.release_core import digest
from rs9.rpm_repository import metadata_command


class RepositoryOperationDetailsTests(unittest.TestCase):
    def test_safe_operation_identity_survives_contract_error(self):
        details = dict(operation="repodata-signature-write", target="repodata/repomd.xml.asc",
                       errno="EACCES", causal_code="PermissionError", substage="repository-metadata",
                       writer_is_owner=False, owner_is_root=True, group_matches=False,
                       target_exists=False, parent_mode="0755", stdout_sha256="a" * 64,
                       stderr_sha256="b" * 64)
        error = ContractError("RPM_REPOSITORY_OPERATION", "Repository write failed", details=details)
        self.assertEqual(error.details, details)

    def test_relationships_cannot_include_private_or_untyped_values(self):
        for field, value in (("target", "/" + "home/operator/repodata.xml"),
                             ("writer_is_owner", 1), ("owner_is_root", "root"),
                             ("parent_mode", "07777-extra"), ("target_mode", 644),
                             ("errno", "permission denied")):
            with self.subTest(field=field):
                self.assertEqual(safe_details({field: value}), {"details_truncated": True})

    def test_untrusted_operations_and_numeric_owner_ids_are_withheld(self):
        self.assertEqual(safe_details({"operation": "arbitrary-write", "writer_uid": 501}),
                         {"details_truncated": True})

    def test_client_image_causal_substage_retained(self):
        self.assertEqual(safe_details({"causal_substage": "client-image-verification"}),
                         {"causal_substage": "client-image-verification"})

    def test_pages_metadata_failure_names_tool_with_real_container_receipt(self):
        inner = metadata_command("fixture-repository", sha256=True)
        case = self
        class FailureTransport(CommandRunner):
            def run(self, argv, *, cwd=None, env=None):
                case.assertEqual(argv[:2], ["docker", "run"])
                case.assertEqual(argv[-len(inner):], inner)
                return CommandReceipt(argv, 2, b"", b"controlled metadata error\n", executed=True)
        with tempfile.TemporaryDirectory() as tmp, self.assertRaises(ContractError) as caught:
            _run_tool_container(FailureTransport(), "fixture-image", "linux/amd64", Path(tmp), inner)
        self.assertEqual(caught.exception.code, "METADATA_BUILD_FAILED")
        self.assertEqual(caught.exception.details["tool"], "createrepo_c")
        self.assertEqual(caught.exception.details["exit_code"], 2)
        self.assertEqual(caught.exception.details["stderr_sha256"], digest(b"controlled metadata error\n"))
