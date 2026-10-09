"""Real runner/receipt contracts across fixture repository and late-failure seams.

The container transport models native tools; this is not Docker/DNF/RPM proof.
Filesystem access failures use actual permissions. Hosted native proof remains required.
"""
from contextlib import ExitStack
import errno
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from rs9.build_native import CommandReceipt, CommandRunner
from rs9.errors import ContractError
from rs9.hosted_deb import _user
from rs9 import hosted_packaging as hosted
from rs9.hosted_custody import retain, provenance
from rs9.hosted_summary import validate_rpm_policy_custody
from rs9.release_core import digest
from rs9.rpm_repository import metadata_command
from tests.rpm_summary_fixtures import witnessed_build_double
import tests.test_rpm_late_failure_reporting as fixtures


class ContainerTransport(CommandRunner):
    def __init__(self, failure=None):
        self.calls = []
        self.failure = failure
        self.index_bytes = b"<repomd/>\n"
        self.repodata = None

    def which(self, name):
        return "/fixture/bin/" + name

    def run(self, argv, *, cwd=None, env=None):
        self.calls.append(list(argv))
        def receipt(code=0, out=b"", err=b""):
            return CommandReceipt(list(argv), code, out, err, executed=True)
        if argv[:2] == ["docker", "rmi"]:
            if self.failure == "cleanup-not-executed":
                return CommandReceipt(argv, 0, b"", b"", executed=False)
            return receipt(3 if self.failure == "cleanup" else 0)
        if argv[:2] != ["docker", "run"]:
            raise AssertionError("unexpected transport command")
        image_index = next(i for i, arg in enumerate(argv) if arg.startswith("rs9-rpm-builder:"))
        inner = argv[image_index + 1:]
        if inner == ["true"]:
            return receipt()
        if "createrepo_c" in inner:
            assert inner == metadata_command(inner[-1])
            if self.failure == "metadata-command":
                return receipt(1, b"", b"controlled createrepo failure\n")
            self.repodata = Path(inner[-1]) / "repodata"
            self.repodata.mkdir()
            self.repodata.chmod(0o755)
            index = self.repodata / "repomd.xml"
            index.write_bytes(self.index_bytes)
            index.chmod(0o644)
            if self.failure == "metadata-write":
                self.repodata.chmod(0o555)
            return receipt(out=b"created public metadata\n")
        command = inner[0]
        if command == "rpmsign":
            path = Path(inner[-1])
            path.write_bytes(path.read_bytes() + b"-fixture-signed")
            if self.failure == "custody-mutation":
                scratch = next(p for p in path.parents if (p / "unsigned-custody").is_dir())
                (scratch / "unsigned-custody/files" / path.name).write_bytes(b"controlled mutation")
            return receipt()
        if command == "rpmkeys":
            if "--checksig" in inner:
                negative = any("wrong-rpmdb" in a or "empty-rpmdb" in a or ".tampered" in a for a in inner)
                if self.failure == "signing-positive" and not negative:
                    return receipt(1, b"fixture.rpm: digests signatures NOT OK\n", b"checksig failed\n")
                return receipt(1 if negative else 0, b"fixture.rpm: digests signatures NOT OK\n" if negative
                               else b"fixture.rpm: digests signatures OK\n")
            return receipt()
        if command == "rpm":
            if "--version" in inner:
                return receipt(out=b"RPM version 6.0.2\n")
            if "--querytags" in inner:
                return receipt(out=b"PAYLOADSHA256\nPAYLOADSHA256ALGO\n")
            if "--eval" in inner:
                macros = dict(inner[i + 1].split(" ", 1) for i, a in enumerate(inner) if a == "--define")
                return receipt(out=("|".join(macros[k] for k in ("_keyring", "_keyringpath", "_dbpath")) + "\n").encode())
            query = inner[inner.index("--queryformat") + 1]
            if "%{PAYLOAD" in query:
                return receipt(out=("0" * 64 + "|8\n").encode())
            name = Path(inner[-1]).name
            product = next(p for p in fixtures.PRODUCTS if name.startswith(p + "-"))
            arch = "noarch" if ".noarch.rpm" in name else "x86_64"
            return receipt(out=f"{product}|1.0.0|1.fc43|{arch}\n".encode())
        raise AssertionError("unexpected inner tool")


class RepositorySequenceTests(unittest.TestCase):
    def execute_lane(self, root, *, failure=None, client_error=None, fixture_type=None, image_drift=False):
        harness = fixtures.RpmLateFailureReportingTests()
        harness.setUp()
        context, environment, build = harness._setup_lane(root)
        transport = ContainerTransport(failure)
        context["runner"] = transport
        image_reads = []
        def verify_image(*a, **kw):
            image_reads.append(True)
            if image_drift and len(image_reads) == 2:
                raise ContractError("CLIENT_IMAGE_DRIFT", "Controlled client image drift")
            return "fixture-client"
        client_rows = [{"name": "rpm-client.dnf", "status": "pass"},
                       {"name": "burst-native-addon-target", "status": "pass"},
                       {"name": "burst-native-addon-load", "status": "pass"}]
        def client(*a, **kw):
            index = transport.repodata / "repomd.xml"
            self.assertEqual(index.read_bytes(), transport.index_bytes)
            self.assertTrue((transport.repodata / "repomd.xml.asc").is_file())
            self.assertEqual(transport.repodata.stat().st_mode & 0o777, 0o755)
            for path in transport.repodata.iterdir():
                self.assertEqual(path.stat().st_mode & 0o777, 0o644)
            if client_error:
                raise client_error
            return client_rows, {}
        with ExitStack() as stack:
            replacements = {
                "rs9.hosted_packaging.provision": {"return_value": environment},
                "rs9.hosted_deb.provision_image": {},
                "rs9.hosted_packaging.prepare_client": {"return_value": {"status": "pass", "reason": "ok"}},
                "rs9.rpm_client_runtime.bind_engine_floors": {"side_effect": lambda ev, caps: ev},
                "rs9.hosted_packaging.verify_client_image": {"side_effect": verify_image},
                "rs9.hosted_packaging.container_tool_facts": {"return_value": {"rpm": "6.0.2"}},
                "rs9.hosted_packaging._resolve_offline_npm_archives": {"return_value": None},
                "rs9.hosted_packaging.build_rpm_candidate": {"autospec": True, "side_effect": witnessed_build_double(build)},
                "rs9.hosted_smoke.prepare_smoke": {"return_value": {}},
                "rs9.hosted_deb._burst_release_record": {"return_value": {}},
                "rs9.hosted_deb.client_cycle": {"side_effect": client},
                "rs9.hosted_deb.tamper_cycle": {"return_value": [
                    {"name": "rpm-trust.tamper." + k, "status": "pass"} for k in
                    ("package", "index", "signature", "wrongkey")]},
            }
            for name, kwargs in replacements.items():
                stack.enter_context(patch(name, **kwargs))
            stack.enter_context(patch("rs9.hosted_packaging.SigningFixture", fixture_type or fixtures.MockSigningFixture))
            try:
                result = hosted.execute(context)
            except Exception as error:
                result = error.partial_result
                self.assertIs(error, client_error)
            finally:
                if transport.repodata:
                    transport.repodata.chmod(0o755)
        return context, transport, result

    def assert_custody_and_completed_signing(self, root, context, result):
        root = root.resolve()
        details = result["details"]
        signing = details["completed_operations"]["package_signing"]
        self.assertEqual(len(signing["identities"]), 4)
        self.assertEqual(len(signing["probes"]), 4)
        self.assertEqual(details["completed_operations"]["unsigned_custody_unchanged"], "pass")
        self.assertTrue(details["completed_operations"]["unsigned_custody"]["merkle"]["root"])
        retained = root / "retained"
        record = {"lane": "rpm", "system": "x86_64-linux", "gates": result["gates"],
                  "details": details, "runner": {}, "provenance": provenance(Path('.').resolve(), "1" * 64)}
        manifest = retain(context["scratch"], retained, result["artifacts"], record)
        self.assertEqual(set(validate_rpm_policy_custody(retained, manifest, record)), set(fixtures.PRODUCTS))
        self.assertEqual(details["rpm_lint_raw"]["theme-forge-nebular-fusion"]["status"], "fail")
        self.assertTrue(details["rpm_lint_policy"]["theme-forge-nebular-fusion"]["accepted"])

    def test_actual_receipts_container_argv_and_public_sequence_both_umasks(self):
        for mask in (0o022, 0o077):
            with self.subTest(umask=oct(mask)), tempfile.TemporaryDirectory() as tmp:
                previous = os.umask(mask)
                try:
                    context, transport, result = self.execute_lane(Path(tmp).resolve())
                finally:
                    os.umask(previous)
                self.assertEqual(next(g for g in result["gates"] if g["name"] == "rpm-repository-indexing")["status"], "pass")
                self.assert_custody_and_completed_signing(Path(tmp), context, result)
                tools = [a for a in transport.calls if any(t in a for t in ("rpmsign", "rpmkeys", "createrepo_c"))]
                self.assertTrue(tools)
                for command in tools:
                    if _user() is None:
                        self.assertNotIn("--user", command)
                    else:
                        self.assertEqual(command[command.index("--user") + 1], _user())
                        self.assertIn("HOME=/tmp", command)
                    self.assertIn(str(context["scratch"]) + ":" + str(context["scratch"]), command)

    @unittest.skipIf(os.geteuid() == 0, "DAC permission denial requires an unprivileged writer")
    def test_real_metadata_permission_failure_keeps_raw_chunks_and_signing_probes(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            context, transport, result = self.execute_lane(root, failure="metadata-write")
            self.assert_custody_and_completed_signing(root, context, result)
            detail = result["details"]["repository_failure"]
            self.assertEqual(detail["operation"], "repodata-signature-write")
            self.assertEqual(detail["target"], "repodata/repomd.xml.asc")
            self.assertEqual(detail["errno"], errno.errorcode[errno.EACCES])
            self.assertEqual(detail["causal_code"], "PermissionError")
            self.assertEqual(detail["tool"], "createrepo_c")
            self.assertEqual((transport.repodata / "repomd.xml").read_bytes(), transport.index_bytes)
            self.assertFalse((transport.repodata / "repomd.xml.asc").exists())
            rows = {g["name"]: g for g in result["gates"]}
            self.assertEqual(rows["rpm-repository-indexing"]["status"], "fail")
            self.assertEqual(rows["rpm-client-qualification"]["status"], "not-run")

    def test_failed_bundle_creation_leaves_custody_verification_not_run(self):
        with tempfile.TemporaryDirectory() as tmp, patch("rs9.pages_candidate.write_custody_bundle",
                side_effect=OSError(errno.ENOSPC, "controlled bundle write failure")):
            _, _, result = self.execute_lane(Path(tmp).resolve())
            detail = result["details"]
            self.assertEqual(detail["repository_failure"]["causal_substage"], "custody-bundle")
            self.assertEqual(detail["completed_operations"]["unsigned_custody_unchanged"], "not-run")
            self.assertNotIn("unsigned_custody", detail["completed_operations"])
            self.assertIn({"operation": "custody-verification", "code": "FileNotFoundError"},
                          detail["secondary_diagnostics"])
            rows = {g["name"]: g for g in result["gates"]}
            self.assertEqual(rows["rpm-repository-indexing"]["status"], "fail")
            self.assertEqual(rows["rpm-package-build"]["status"], "pass")
            self.assertEqual(rows["rpm-client-qualification"]["status"], "not-run")

    def test_observed_custody_mutation_remains_failed(self):
        with tempfile.TemporaryDirectory() as tmp:
            _, _, result = self.execute_lane(Path(tmp).resolve(), failure="custody-mutation")
            detail = result["details"]
            self.assertEqual(detail["repository_failure"]["code"], "CUSTODY_HASH")
            self.assertEqual(detail["completed_operations"]["unsigned_custody_unchanged"], "fail")
            rows = {g["name"]: g for g in result["gates"]}
            self.assertEqual(rows["rpm-repository-indexing"]["status"], "fail")
            self.assertEqual(rows["rpm-client-qualification"]["status"], "not-run")

    @unittest.skipIf(os.geteuid() == 0, "DAC permission denial requires an unprivileged writer")
    def test_unreadable_custody_bundle_does_not_claim_mutation(self):
        from rs9.pages_candidate import write_custody_bundle
        unreadable = []
        def write_then_deny(directory, **kwargs):
            result = write_custody_bundle(directory, **kwargs)
            path = next((directory / "files").iterdir())
            path.chmod(0o000)
            unreadable.append(path)
            return result
        with tempfile.TemporaryDirectory() as tmp, patch("rs9.pages_candidate.write_custody_bundle",
                side_effect=write_then_deny):
            try:
                _, _, result = self.execute_lane(Path(tmp).resolve())
            finally:
                for path in unreadable:
                    path.chmod(0o644)
            detail = result["details"]
            self.assertEqual(detail["repository_failure"]["code"], "PermissionError")
            self.assertEqual(detail["completed_operations"]["unsigned_custody_unchanged"], "not-run")
            self.assertIn({"operation": "custody-verification", "code": "PermissionError"},
                          detail["secondary_diagnostics"])

    def test_metadata_command_failure_names_createrepo_and_retains_receipt_hashes(self):
        with tempfile.TemporaryDirectory() as tmp:
            _, _, result = self.execute_lane(Path(tmp).resolve(), failure="metadata-command")
            detail = result["details"]["repository_failure"]
            self.assertEqual(detail["tool"], "createrepo_c")
            self.assertEqual(detail["causal_substage"], "repository-metadata")
            self.assertEqual(detail["stderr_sha256"], digest(b"controlled createrepo failure\n"))
            self.assertEqual(detail["exit_code"], 1)

    def test_late_client_errors_preserve_indexing_and_cleanup_secondary(self):
        for cause in (ContractError("NATIVE_TOOL", "Controlled client failure"), RuntimeError("controlled unexpected error")):
            with self.subTest(cause=type(cause).__name__), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp).resolve()
                context, _, result = self.execute_lane(root, failure="cleanup", client_error=cause)
                self.assert_custody_and_completed_signing(root, context, result)
                rows = {g["name"]: g for g in result["gates"]}
                self.assertEqual(rows["rpm-repository-indexing"]["status"], "pass")
                self.assertEqual(rows["rpm-client-qualification"]["status"], "fail")
                self.assertEqual(result["details"]["repository_failure"]["causal_substage"], "client-cycle")
                self.assertEqual(result["details"]["cleanup_evidence"]["status"], "fail")
                self.assertTrue(all(rows["rpm-trust.tamper." + k]["status"] == "not-run" for k in
                                    ("package", "index", "signature", "wrongkey")))

    def test_fixture_cleanup_error_retains_original_permission_cause(self):
        class BadCleanup(fixtures.MockSigningFixture):
            def __exit__(self, *args):
                super().__exit__(*args)
                raise OSError(errno.EIO, "controlled fixture cleanup failure")
        with tempfile.TemporaryDirectory() as tmp:
            _, _, result = self.execute_lane(Path(tmp).resolve(), client_error=ContractError("NATIVE_TOOL", "Client failed"), fixture_type=BadCleanup)
            self.assertEqual(result["details"]["repository_failure"]["code"], "NATIVE_TOOL")
            self.assertTrue(result["details"]["secondary_diagnostics"])
            self.assertTrue(all(r["operation"] == "fixture-cleanup" for r in result["details"]["secondary_diagnostics"]))

    def test_late_client_image_drift_keeps_preparation_mapping_and_completed_metadata(self):
        with tempfile.TemporaryDirectory() as tmp:
            context, _, result = self.execute_lane(Path(tmp).resolve(), image_drift=True)
            self.assert_custody_and_completed_signing(Path(tmp), context, result)
            rows = {g["name"]: g for g in result["gates"]}
            self.assertEqual(rows["rpm-repository-indexing"]["status"], "pass")
            self.assertEqual(rows["rpm-client-preparation"]["status"], "fail")
            self.assertEqual(rows["rpm-client-preparation"]["causal_substage"], "client-image-verification")
            self.assertEqual(rows["rpm-client-qualification"]["status"], "not-run")

    def test_probe_write_secondary_failure_preserves_original_checksig_receipt(self):
        with tempfile.TemporaryDirectory() as tmp, patch("rs9.hosted_packaging._write_probe_diagnostic",
                side_effect=OSError(errno.ENOSPC, "controlled diagnostic storage failure")):
            _, _, result = self.execute_lane(Path(tmp).resolve(), failure="signing-positive")
            detail = result["details"]
            self.assertEqual(detail["repository_failure"]["code"], "RPM_SIGNING")
            self.assertEqual(detail["repository_failure"]["substage"], "rpm-checksig")
            self.assertEqual(detail["repository_failure"]["stderr_sha256"], digest(b"checksig failed\n"))
            self.assertEqual(detail["completed_operations"]["unwritten_signing_probe"]["status"], "fail")
            self.assertIn({"operation": "signing-probe-write", "code": "OSError"}, detail["secondary_diagnostics"])

    def test_cleanup_zero_exit_without_execution_is_not_reported_as_pass(self):
        with tempfile.TemporaryDirectory() as tmp:
            _, _, result = self.execute_lane(Path(tmp).resolve(), failure="cleanup-not-executed")
            self.assertEqual(result["details"]["cleanup_evidence"]["status"], "not-run")

    def test_unreadable_probe_keeps_completed_signing_and_independent_custody_check(self):
        read = Path.read_bytes
        def read_with_probe_failure(path):
            if path.name.startswith("rpm-signed-query-probe-"):
                raise PermissionError(errno.EACCES, "controlled secondary probe read failure")
            return read(path)
        with tempfile.TemporaryDirectory() as tmp, patch.object(Path, "read_bytes", read_with_probe_failure):
            _, _, result = self.execute_lane(Path(tmp).resolve())
            detail = result["details"]
            self.assertEqual(len(detail["completed_operations"]["package_signing"]["identities"]), 4)
            self.assertEqual(detail["completed_operations"]["unsigned_custody_unchanged"], "pass")
            self.assertTrue(all(row["operation"] == "signing-probe-read" for row in detail["secondary_diagnostics"]))
            self.assertFalse(any(p.name.startswith("rpm-signed-query-probe-") for p in result["artifacts"]))


if __name__ == "__main__":
    unittest.main()
