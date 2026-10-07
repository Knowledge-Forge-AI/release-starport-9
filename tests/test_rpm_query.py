"""Tests for rs9.rpm_query: Option B RPM query, capabilities, identity, payload digest, and failure modes."""

import os
from pathlib import Path
import tempfile
import unittest

from rs9.build_native import CommandReceipt, MockCommandRunner
from rs9.errors import ContractError
from rs9.release_core import digest
from rs9.rpm_query import (
    IDENTITY_QUERYFORMAT,
    PGPHASHALGO_SHA256,
    RPM_CLOSED_QUERYTAGS,
    RPM_EXPECTED_ARCHITECTURES,
    UPLOADED_PAYLOADDIGEST_ERROR_SHA256,
    UPLOADED_PAYLOADDIGEST_ERROR_STDERR,
    _safe_observed_token,
    check_query_receipt,
    query_rpm_identity,
    query_rpm_package,
    query_rpm_payload_digest,
    read_rpm_identity,
    read_rpm_payload_digest,
    rpm_isolation_args,
    select_payload_capability,
    verify_primary_rpm_source_algorithm,
)


class RpmQueryTests(unittest.TestCase):
    def test_discovery_selects_only_complete_supported_pairs(self):
        class Runner:
            def __init__(self, tags): self.tags = tags
            def run(self, argv, **kwargs):
                self.assertion = argv == ["rpm", "--querytags"]
                return CommandReceipt(argv, 0, self.tags, b"")
        for tags, chosen in ((b"NAME\nPAYLOADSHA256\nPAYLOADSHA256ALGO\n", "rpm6"),
                             (b"PAYLOADDIGEST\nPAYLOADDIGESTALGO\n", "legacy")):
            runner = Runner(tags)
            self.assertEqual(select_payload_capability(runner)[0], chosen)
            self.assertTrue(runner.assertion)
        for tags in (b"NAME\n", b"PAYLOADSHA256ALT\nPAYLOADSHA256ALGO\n", b"PAYLOADDIGEST\n",
                     b"NAME\nNAME\n", b"chatter with spaces\n"):
            with self.subTest(tags=tags), self.assertRaises(ContractError):
                select_payload_capability(Runner(tags))

    def test_digest_value_algorithm_and_requested_source_fail_closed(self):
        for value, algorithm in (("a"*63, "8"), ("A"*64, "8"), ("a"*64, "sha256"),
                                 ("a"*64, "08"), ("a"*64, "10")):
            with self.subTest(value=value, algorithm=algorithm), self.assertRaises(ContractError):
                read_rpm_payload_digest(CommandReceipt(["rpm"], 0, f"{value}|{algorithm}\n".encode(), b""))
        class Runner:
            def run(self, argv, **kwargs):
                return CommandReceipt(argv, 0, b"PAYLOADSHA256\nPAYLOADSHA256ALGO\n", b"")
        with self.assertRaises(ContractError):
            query_rpm_payload_digest(Runner(), "fixture.rpm", capability="legacy")

    def test_signed_nokey_warning_rejected_and_strict_empty_stderr_required(self):
        warning = b"warning: fixture.rpm: Header V4 RSA/SHA256 Signature, key ID abcdef01: NOKEY\n"
        receipt_with_warning = CommandReceipt(["rpm"], 0, b"product|1.0.0|1.fc43|noarch\n", warning)
        with self.assertRaises(ContractError) as caught:
            read_rpm_identity(receipt_with_warning, "product", "1.0.0", "noarch")
        self.assertEqual(caught.exception.code, "RPM_QUERY_FAILED")
        self.assertEqual(caught.exception.details["stderr_sha256"], digest(warning))

        clean_receipt = CommandReceipt(["rpm"], 0, b"product|1.0.0|1.fc43|noarch\n", b"")
        self.assertEqual(read_rpm_identity(clean_receipt, "product", "1.0.0", "noarch")["arch"], "noarch")
        for raw in (b"product|1.0.0|1.fc43|noarch", b"product|1.0.0|1.fc43|(none)\n",
                    b"product|1.0.0|1.fc43|noarch\n\n"):
            with self.subTest(raw=raw), self.assertRaises(ContractError):
                read_rpm_identity(CommandReceipt(["rpm"], 0, raw, b""))
        with self.assertRaises(ContractError):
            read_rpm_identity(clean_receipt, expected_release="1.fc44")
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name).resolve()

    def test_uploaded_exit0_empty_stdout_unknown_tag_stderr(self):
        """Exact uploaded exit0 empty stdout stderr unknown tag failure with custody diagnostic hashes."""
        stderr_bytes = UPLOADED_PAYLOADDIGEST_ERROR_STDERR.encode("utf-8")
        stderr_sha = digest(stderr_bytes)
        self.assertEqual(stderr_sha, UPLOADED_PAYLOADDIGEST_ERROR_SHA256)
        self.assertEqual(stderr_sha, "7d9d1aa567137d6c38111fd189312572c041a32da954bfa55fa8bf8b3f36ddd8")

        receipt = CommandReceipt(
            ["rpm", "-qp", "--queryformat", "%{PAYLOADDIGEST}|%{PAYLOADDIGESTALGO}\n", "/path/to/pkg.rpm"],
            0,
            b"",
            stderr_bytes,
            executed=True,
        )

        with self.assertRaises(ContractError) as caught:
            check_query_receipt(receipt, substage="rpm-query", tool="rpm", product="test-prod")

        err = caught.exception
        self.assertEqual(err.code, "RPM_QUERY_FAILED")
        self.assertEqual(err.details["exit_code"], 0)
        self.assertEqual(err.details["stdout_sha256"], digest(b""))
        self.assertEqual(err.details["stderr_sha256"], "7d9d1aa567137d6c38111fd189312572c041a32da954bfa55fa8bf8b3f36ddd8")
        self.assertEqual(err.details["product"], "test-prod")
        self.assertEqual(err.details["substage"], "rpm-query")
        self.assertEqual(err.details["tool"], "rpm")

        # Also verify read_rpm_payload_digest fails with the exact diagnostic
        with self.assertRaises(ContractError) as caught2:
            read_rpm_payload_digest(receipt, capability="legacy", product="test-prod")
        self.assertEqual(caught2.exception.code, "RPM_QUERY_FAILED")
        self.assertEqual(caught2.exception.details["stderr_sha256"], UPLOADED_PAYLOADDIGEST_ERROR_SHA256)

    def test_all_three_architectures_supported(self):
        """All three architectures (noarch, x86_64, aarch64) are valid and recognized."""
        for arch in ("noarch", "x86_64", "aarch64"):
            with self.subTest(arch=arch):
                receipt = CommandReceipt(
                    ["rpm"], 0, f"product|1.0.0|1.fc43|{arch}\n".encode(), b"", executed=True
                )
                ident = read_rpm_identity(receipt, "product", "1.0.0", arch, revision=1, dist="fc43")
                self.assertEqual(ident["name"], "product")
                self.assertEqual(ident["version"], "1.0.0")
                self.assertEqual(ident["release"], "1.fc43")
                self.assertEqual(ident["arch"], arch)

    def test_unexpected_architecture_rejected(self):
        """Architectures outside vocabulary (i686, armv7hl, amd64) are rejected."""
        for bad_arch in ("i686", "armv7hl", "amd64", "universal"):
            with self.subTest(arch=bad_arch):
                receipt = CommandReceipt(
                    ["rpm"], 0, f"product|1.0.0|1.fc43|{bad_arch}\n".encode(), b"", executed=True
                )
                with self.assertRaises(ContractError) as caught:
                    read_rpm_identity(receipt, "product", "1.0.0", bad_arch)
                self.assertEqual(caught.exception.code, "INVALID_ARCHITECTURE")
                self.assertEqual(caught.exception.details.get("diagnostic_token"), bad_arch)

    def test_architecture_mismatch_rejected(self):
        """Architecture differing from expected product architecture is rejected."""
        receipt = CommandReceipt(
            ["rpm"], 0, b"product|1.0.0|1.fc43|x86_64\n", b"", executed=True
        )
        with self.assertRaises(ContractError) as caught:
            read_rpm_identity(receipt, "product", "1.0.0", "noarch")
        self.assertEqual(caught.exception.code, "INVALID_ARCHITECTURE")
        self.assertEqual(caught.exception.details.get("diagnostic_token"), "x86_64")

    def test_release_validation_plain_fc43_and_wrong_suffix(self):
        """Release revision validation supports plain revision and .fc43, rejecting wrong suffixes."""
        # 1. Plain revision (e.g. "1")
        receipt_plain = CommandReceipt(["rpm"], 0, b"product|1.0.0|1|noarch\n", b"", executed=True)
        ident_plain = read_rpm_identity(receipt_plain, "product", "1.0.0", "noarch", revision=1, dist="fc43")
        self.assertEqual(ident_plain["release"], "1")

        # 2. Builder-expanded dist (e.g. "1.fc43")
        receipt_dist = CommandReceipt(["rpm"], 0, b"product|1.0.0|1.fc43|noarch\n", b"", executed=True)
        ident_dist = read_rpm_identity(receipt_dist, "product", "1.0.0", "noarch", revision=1, dist="fc43")
        self.assertEqual(ident_dist["release"], "1.fc43")

        # 3. Wrong suffix (e.g. "1.wrong", "1.el8", "1.fc42")
        for bad_rel in ("1.wrong", "1.el8", "1.fc42", "1.fc43.extra"):
            with self.subTest(bad_rel=bad_rel):
                receipt_bad = CommandReceipt(["rpm"], 0, f"product|1.0.0|{bad_rel}|noarch\n".encode(), b"", executed=True)
                with self.assertRaises(ContractError) as caught:
                    read_rpm_identity(receipt_bad, "product", "1.0.0", "noarch", revision=1, dist="fc43")
                self.assertEqual(caught.exception.code, "INVALID_RELEASE")
                self.assertEqual(caught.exception.details.get("diagnostic_token"), bad_rel)

        # 4. Wrong revision (e.g. revision 2 when 1 was expected)
        receipt_wrong_rev = CommandReceipt(["rpm"], 0, b"product|1.0.0|2.fc43|noarch\n", b"", executed=True)
        with self.assertRaises(ContractError) as caught:
            read_rpm_identity(receipt_wrong_rev, "product", "1.0.0", "noarch", revision=1, dist="fc43")
        self.assertEqual(caught.exception.code, "INVALID_RELEASE")

    def test_name_and_version_mismatches(self):
        """Mismatched name or version raises specific INVALID_NAME or INVALID_VERSION."""
        receipt_name = CommandReceipt(["rpm"], 0, b"other|1.0.0|1.fc43|noarch\n", b"", executed=True)
        with self.assertRaises(ContractError) as caught:
            read_rpm_identity(receipt_name, "expected-name", "1.0.0", "noarch")
        self.assertEqual(caught.exception.code, "INVALID_NAME")
        self.assertEqual(caught.exception.details.get("diagnostic_token"), "other")

        receipt_ver = CommandReceipt(["rpm"], 0, b"expected-name|2.0.0|1.fc43|noarch\n", b"", executed=True)
        with self.assertRaises(ContractError) as caught:
            read_rpm_identity(receipt_ver, "expected-name", "1.0.0", "noarch")
        self.assertEqual(caught.exception.code, "INVALID_VERSION")
        self.assertEqual(caught.exception.details.get("diagnostic_token"), "2.0.0")

    def test_capabilities_closed_table_rpm6_and_legacy(self):
        """Closed querytags table accepts rpm6 and legacy; excludes ALT unconditionally."""
        sha_hex = "a" * 64

        # RPM6 capability
        receipt_rpm6 = CommandReceipt(["rpm"], 0, f"{sha_hex}|8\n".encode(), b"", executed=True)
        res_rpm6 = read_rpm_payload_digest(receipt_rpm6, capability="rpm6")
        self.assertEqual(res_rpm6["digest"], sha_hex)
        self.assertEqual(res_rpm6["algorithm_numeric"], 8)
        self.assertEqual(res_rpm6["capability"], "rpm6")

        # Legacy capability
        receipt_legacy = CommandReceipt(["rpm"], 0, f"{sha_hex}|8\n".encode(), b"", executed=True)
        res_legacy = read_rpm_payload_digest(receipt_legacy, capability="legacy")
        self.assertEqual(res_legacy["digest"], sha_hex)
        self.assertEqual(res_legacy["algorithm_numeric"], 8)
        self.assertEqual(res_legacy["capability"], "legacy")

        # ALT excluded
        for alt_cap in ("alt", "ALT", "payloadsha256alt", "payloaddigestalt"):
            with self.subTest(alt=alt_cap):
                with self.assertRaises(ContractError) as caught:
                    read_rpm_payload_digest(receipt_rpm6, capability=alt_cap)
                self.assertEqual(caught.exception.code, "UNSUPPORTED_CAPABILITY")

        # Arbitrary unknown capability rejected
        with self.assertRaises(ContractError) as caught:
            read_rpm_payload_digest(receipt_rpm6, capability="unregistered_cap")
        self.assertEqual(caught.exception.code, "UNSUPPORTED_CAPABILITY")

    def test_source_and_algorithm_mismatch(self):
        """Verifies algorithm numeric 8 from source or query; fails closed on mismatch."""
        sha_hex = "b" * 64

        # Algorithm mismatch in query output (e.g. 1 for MD5 or 2 for SHA1)
        for bad_algo in ("1", "2", "sha1", "md5", "unknown"):
            with self.subTest(bad_algo=bad_algo):
                receipt_bad_algo = CommandReceipt(["rpm"], 0, f"{sha_hex}|{bad_algo}\n".encode(), b"", executed=True)
                with self.assertRaises(ContractError) as caught:
                    read_rpm_payload_digest(receipt_bad_algo, capability="rpm6")
                self.assertEqual(caught.exception.code, "INVALID_ALGORITHM")

        # Primary RPM source verification
        # 1. Matching source defines PGPHASHALGO_SHA256 = 8
        header_ok = self.root / "rpmpgp_ok.h"
        header_ok.write_text("/* RPM PGP header */\n#define PGPHASHALGO_SHA256 8\n")
        self.assertTrue(verify_primary_rpm_source_algorithm(header_ok))

        # 2. Source mismatch defines PGPHASHALGO_SHA256 = 9 -> fails closed!
        header_bad = self.root / "rpmpgp_bad.h"
        header_bad.write_text("/* RPM PGP header mismatch */\n#define PGPHASHALGO_SHA256 9\n")
        with self.assertRaises(ContractError) as caught:
            verify_primary_rpm_source_algorithm(header_bad)
        self.assertEqual(caught.exception.code, "ALGORITHM_MISMATCH")

        # 3. Source missing PGPHASHALGO_SHA256 -> fails closed
        header_empty = self.root / "rpmpgp_empty.h"
        header_empty.write_text("/* Empty header */\n")
        with self.assertRaises(ContractError) as caught:
            verify_primary_rpm_source_algorithm(header_empty)
        self.assertEqual(caught.exception.code, "ALGORITHM_MISMATCH")

        # 4. Inaccessible source path returns False
        self.assertFalse(verify_primary_rpm_source_algorithm(self.root / "nonexistent.h"))

    def test_malformed_and_bounded_query_diagnostics(self):
        """Malformed identity lines produce bounded diagnostics without leaking unsafe tokens."""
        unsafe = "/private/rpm/path"
        raw = f"{unsafe}|1.0.0|1.fc43|noarch|extra|tags\n".encode()
        receipt = CommandReceipt(["rpm"], 0, raw, b"", executed=True)
        with self.assertRaises(ContractError) as caught:
            read_rpm_identity(receipt, "prod", "1.0.0", "noarch")
        err = caught.exception
        self.assertEqual(err.code, "RPM_QUERY_FAILED")
        self.assertEqual(err.details["observed_field_count"], 6)
        self.assertEqual(err.details["observed_field_tokens"][0], digest(unsafe.encode()))
        self.assertNotIn(unsafe, str(err.details))

    def test_end_to_end_query_rpm_package_with_runner(self):
        """query_rpm_package executes both identity and payload queries cleanly."""
        class MockRpmRunner(MockCommandRunner):
            def __init__(self):
                super().__init__(
                    available_tools={"rpm": "/usr/bin/rpm"},
                    handlers={"rpm": self._handle_rpm},
                )
                self.calls = []

            def _handle_rpm(self, argv, **kwargs):
                self.calls.append(argv)
                if "--querytags" in argv:
                    return CommandReceipt(argv, 0, b"PAYLOADSHA256\nPAYLOADSHA256ALGO\n", b"", executed=True)
                if "--eval" in argv:
                    return CommandReceipt(argv, 0, b"1.fc43\n", b"", executed=True)
                qf = argv[argv.index("--queryformat") + 1]
                if "%{NAME}" in qf:
                    return CommandReceipt(argv, 0, b"my-prod|0.5.0|1.fc43|x86_64\n", b"", executed=True)
                if "%{PAYLOAD" in qf:
                    return CommandReceipt(argv, 0, b"c" * 64 + b"|8\n", b"", executed=True)
                return CommandReceipt(argv, 1, b"", b"unknown queryformat", executed=True)

        runner = MockRpmRunner()
        identity, payload_digest, receipts = query_rpm_package(
            runner,
            self.root / "pkg.rpm",
            product="my-prod",
            version="0.5.0",
            architecture="x86_64",
            revision=1,
            dist="fc43",
        )
        self.assertEqual(identity["name"], "my-prod")
        self.assertEqual(identity["version"], "0.5.0")
        self.assertEqual(identity["release"], "1.fc43")
        self.assertEqual(identity["arch"], "x86_64")
        self.assertEqual(payload_digest["digest"], "c" * 64)
        self.assertEqual(payload_digest["algorithm_numeric"], 8)
        self.assertEqual(payload_digest["algorithm"], "sha256")
        self.assertEqual(len(receipts), 4)

    def test_supplied_exit0_unsupported_tags_fail_closed(self):
        """Hermetic tests for supplied exit0 unsupported tags failing closed."""
        class Exit0Runner:
            def __init__(self, tag_output):
                self.tag_output = tag_output

            def run(self, argv, **kwargs):
                return CommandReceipt(argv, 0, self.tag_output, b"", executed=True)

        # 1. Valid exit 0 tag list but missing PAYLOADSHA256 and PAYLOADDIGEST
        tag_list_unsupported = b"NAME\nVERSION\nRELEASE\nARCH\nSUMMARY\nDESCRIPTION\nLICENSE\n"
        runner_unsupported = Exit0Runner(tag_list_unsupported)
        with self.assertRaises(ContractError) as caught:
            select_payload_capability(runner_unsupported)
        self.assertEqual(caught.exception.code, "RPM_PAYLOAD_DIGEST_UNSUPPORTED")

        with self.assertRaises(ContractError) as caught:
            query_rpm_payload_digest(runner_unsupported, self.root / "pkg.rpm")
        self.assertEqual(caught.exception.code, "RPM_PAYLOAD_DIGEST_UNSUPPORTED")

        # 2. Supplied exit 0 with ALT uncompressed tags (PAYLOADSHA256ALT)
        tag_list_alt = b"NAME\nPAYLOADSHA256ALT\nPAYLOADSHA256ALGO\n"
        with self.assertRaises(ContractError) as caught:
            select_payload_capability(Exit0Runner(tag_list_alt))
        self.assertEqual(caught.exception.code, "RPM_PAYLOAD_DIGEST_UNSUPPORTED")

        # 3. Supplied exit 0 with legacy ALT tags (PAYLOADDIGESTALT)
        tag_list_legacy_alt = b"NAME\nPAYLOADDIGESTALT\nPAYLOADDIGESTALGO\n"
        with self.assertRaises(ContractError) as caught:
            select_payload_capability(Exit0Runner(tag_list_legacy_alt))
        self.assertEqual(caught.exception.code, "RPM_PAYLOAD_DIGEST_UNSUPPORTED")

    def test_rpm_isolation_args_builder(self):
        """rpm_isolation_args builds correct --dbpath and %_keyring/%_keyringpath macros."""
        # Empty when none specified
        self.assertEqual(rpm_isolation_args(), [])

        # Fully populated isolation arguments
        args = rpm_isolation_args(
            dbpath="/tmp/scratch/db",
            keyring="rpmdb",
            keyringpath="/tmp/scratch/keyring",
        )
        self.assertEqual(args, [
            "--dbpath", "/tmp/scratch/db",
            "--define", "_dbpath /tmp/scratch/db",
            "--define", "_keyring rpmdb",
            "--define", "_pkgverify_flags 0",
            "--define", "_vsflags_query 0",
            "--define", "_keyringpath /tmp/scratch/keyring",
        ])

    def test_query_rpm_package_passes_isolation_arguments(self):
        """query_rpm_package passes --dbpath and %_keyring/%_keyringpath on all rpm invocations."""
        calls = []

        class MockIsolationRunner:
            def run(self, argv, **kwargs):
                calls.append(argv)
                if "--querytags" in argv:
                    return CommandReceipt(argv, 0, b"PAYLOADSHA256\nPAYLOADSHA256ALGO\n", b"", executed=True)
                if "--eval" in argv:
                    return CommandReceipt(argv, 0, b"1.fc43\n", b"", executed=True)
                qf = argv[argv.index("--queryformat") + 1]
                if "%{NAME}" in qf:
                    return CommandReceipt(argv, 0, b"isolated-prod|1.0.0|1.fc43|x86_64\n", b"", executed=True)
                if "%{PAYLOAD" in qf:
                    return CommandReceipt(argv, 0, b"d" * 64 + b"|8\n", b"", executed=True)
                return CommandReceipt(argv, 1, b"", b"unknown query", executed=True)

        runner = MockIsolationRunner()
        db_path = self.root / "fixture-rpmdb"
        keyring_dir = self.root / "fixture-keyring"

        identity, payload_digest, receipts = query_rpm_package(
            runner,
            self.root / "pkg.rpm",
            product="isolated-prod",
            version="1.0.0",
            architecture="x86_64",
            revision=1,
            dist="fc43",
            dbpath=db_path,
            keyring="rpmdb",
            keyringpath=keyring_dir,
        )
        self.assertEqual(identity["name"], "isolated-prod")
        self.assertEqual(payload_digest["digest"], "d" * 64)
        self.assertEqual(len(receipts), 4)

        # Verify every invocation of rpm contained the isolation parameters
        for call in calls:
            self.assertIn("--dbpath", call)
            self.assertIn(str(db_path), call)
            self.assertIn("--define", call)
            self.assertIn("_keyring rpmdb", call)
            self.assertIn(f"_keyringpath {keyring_dir}", call)


if __name__ == "__main__":
    unittest.main()
