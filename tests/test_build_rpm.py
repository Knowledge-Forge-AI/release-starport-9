"""Strict RPM architecture, name, version evidence, query parsing, and derivation tests."""
from pathlib import Path
import re
import tempfile
import unittest

from rs9.build_native import CommandReceipt, MockCommandRunner
from rs9.build_rpm import (
    RPM_EXPECTED_ARCHITECTURES,
    _safe_observed_token,
    build_rpm_candidate,
    read_rpm_identity,
)
from rs9.errors import ContractError, safe_details
from rs9.release_core import digest
from tests.test_build_native import create_cli_fixture


class BuildRpmTests(unittest.TestCase):
    def test_exact_query_architecture_vocabulary_and_rejection_of_banners_and_filenames(self):
        from rs9.build_native import CommandReceipt
        for arch in ("noarch", "x86_64", "aarch64"):
            with self.subTest(arch=arch):
                receipt = CommandReceipt(["rpm"], 0, f"product|0.6.1|1.fc43|{arch}\n".encode(), b"")
                self.assertEqual(read_rpm_identity(receipt, "product", "0.6.1", arch)["arch"], arch)
        for raw in (b"", b"\n", b"product-0.6.1-1.fc43.noarch.rpm\n", b"product-0.6.1-1.fc43.src.rpm\n",
                    b"RPM query\nproduct|0.6.1|1.fc43|noarch\n",
                    b"product|0.6.1|1.fc43|noarch|extra\n",
                    b"product\n0.6.1\n1.fc43\nnoarch\n"):
            with self.subTest(raw=raw), self.assertRaises(ContractError) as caught:
                read_rpm_identity(CommandReceipt(["rpm"], 0, raw, b""), "product", "0.6.1", "noarch")
            self.assertEqual(caught.exception.code, "RPM_QUERY_FAILED")

    def test_malformed_query_retains_bounded_field_and_architecture_evidence(self):
        for raw, count, arch in (
            (b"product|0.6.1|1.fc43|noarch|extra\n", 5, "noarch"),
            (b"RPM query\nproduct|0.6.1|1.fc43|x86_64\n", 4, "x86_64"),
            (b"product\r|0.6.1|1.fc43|aarch64\n", 4, "aarch64"),
            (b"product|0.6.1|1.fc43\n", 3, ""),
            (b"product|0.6.1||noarch\n", 4, "noarch"),
        ):
            with self.subTest(raw=raw), self.assertRaises(ContractError) as caught:
                read_rpm_identity(CommandReceipt(["rpm"], 0, raw, b""), "product", "0.6.1", "noarch")
            error = caught.exception
            self.assertEqual(error.code, "RPM_QUERY_FAILED")
            self.assertEqual(error.details["observed_field_count"], count)
            self.assertEqual(error.details.get("observed_architecture", ""), arch)
            self.assertEqual(len(error.details["observed_field_tokens"]), min(count, 4))
            self.assertEqual(error.details["observed_fields_truncated"], count > 4)
            self.assertEqual(error.details["stdout_sha256"], digest(raw))
            self.assertEqual(error.details["product"], "product")

    def test_malformed_query_hashes_unsafe_fields_without_disclosing_paths(self):
        unsafe = "/private-query/path"
        raw = f"{unsafe}|0.6.1|1.fc43|noarch|extra\n".encode()
        with self.assertRaises(ContractError) as caught:
            read_rpm_identity(CommandReceipt(["rpm"], 0, raw, b""), "product", "0.6.1", "noarch")
        details = caught.exception.details
        self.assertEqual(details["observed_field_tokens"][0], digest(unsafe.encode()))
        self.assertEqual(details["observed_architecture"], "noarch")
        self.assertNotIn(unsafe, str(details))

    def test_oversized_query_diagnostics_cap_tokens_and_preserve_field_count(self):
        raw = ("product|0.6.1|1.fc43|aarch64|" + "a" * 5000).encode()
        with self.assertRaises(ContractError) as caught:
            read_rpm_identity(CommandReceipt(["rpm"], 0, raw, b""), "product", "0.6.1", "aarch64")
        details = caught.exception.details
        self.assertEqual(caught.exception.code, "RPM_QUERY_FAILED")
        self.assertEqual(details["observed_field_count"], raw.count(b"|") + 1)
        self.assertEqual(details["observed_architecture"], "aarch64")
        self.assertEqual(len(details["observed_field_tokens"]), 4)
        self.assertTrue(details["observed_fields_truncated"])
        self.assertTrue(all(len(token) <= 64 for token in details["observed_field_tokens"]))

    def test_query_diagnostic_schema_rejects_unbounded_or_private_values(self):
        valid = {"observed_field_count": 4, "observed_field_tokens": ["product", "0.6.1", "1", "noarch"],
                 "observed_fields_truncated": False}
        self.assertEqual(safe_details(valid), valid)
        for key, values in (
            ("observed_field_count", (True, -1, 2 ** 40)),
            ("observed_fields_truncated", ("true", 1)),
            ("observed_field_tokens", ("noarch", [], ["a"] * 7, ["a" * 65], ["/private-query/path"],
                                       [".."], ["ghp_" + "A" * 36])),
        ):
            for value in values:
                with self.subTest(key=key):
                    self.assertEqual(safe_details({key: value}), {"details_truncated": True})

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name).resolve()
        self.scratch = self.root / "scratch"
        self.scratch.mkdir()

    def _setup_runner(
        self,
        arch="noarch",
        name="theme-forge-stellar-loom",
        version="0.4.0",
        query_out=None,
        release_expansion="1.fc43",
        query_exit=0,
        rpmlint_exit=0,
        createrepo_exit=0,
    ):
        def rpmbuild_handler(argv, cwd=None, env=None):
            rpm_dir = Path(cwd) / "RPMS" / arch
            rpm_dir.mkdir(parents=True, exist_ok=True)
            (rpm_dir / f"{name}-{version}-1.fc43.{arch}.rpm").write_bytes(b"rpm-payload")
            return CommandReceipt(argv, 0, b"built\n", b"")

        def rpm_query_handler(argv, cwd=None, env=None):
            if "--requires" in argv:
                return CommandReceipt(argv, 0, b"nodejs >= 22\nrpmlib(CompressedFileNames) <= 3.0.4-1\n", b"")
            if query_exit:
                return CommandReceipt(argv, query_exit, b"", b"error\n")
            if "--querytags" in argv:
                return CommandReceipt(argv, 0, b"PAYLOADSHA256\nPAYLOADSHA256ALGO\n", b"")
            if "--eval" in argv:
                return CommandReceipt(argv, 0, (release_expansion + "\n").encode(), b"")
            qf = argv[argv.index("--queryformat") + 1] if "--queryformat" in argv else ""
            if "%{PAYLOAD" in qf:
                return CommandReceipt(argv, 0, b"abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789|8\n", b"")
            if query_out is not None:
                return CommandReceipt(argv, 0, query_out, b"")
            return CommandReceipt(argv, 0, f"{name}|{version}|1.fc43|{arch}\n".encode(), b"")

        def rpmlint_handler(argv, cwd=None, env=None):
            return CommandReceipt(argv, rpmlint_exit, b"rpmlint\n", b"error\n" if rpmlint_exit else b"")

        def createrepo_handler(argv, cwd=None, env=None):
            repodata = Path(argv[-1]) / "repodata"
            repodata.mkdir(parents=True, exist_ok=True)
            (repodata / "repomd.xml").write_bytes(b"<repomd/>")
            return CommandReceipt(argv, createrepo_exit, b"created\n", b"error\n" if createrepo_exit else b"")

        return MockCommandRunner(
            available_tools={
                "rpmbuild": "/usr/bin/rpmbuild",
                "rpm": "/usr/bin/rpm",
                "rpmlint": "/usr/bin/rpmlint",
                "createrepo_c": "/usr/bin/createrepo_c",
            },
            handlers={
                "rpmbuild": rpmbuild_handler,
                "rpm": rpm_query_handler,
                "rpmlint": rpmlint_handler,
                "createrepo_c": createrepo_handler,
            },
        )

    def test_safe_observed_token_helper(self):
        # Bounded safe token returned verbatim
        self.assertEqual(_safe_observed_token("noarch"), "noarch")
        self.assertEqual(_safe_observed_token("theme-forge-stellar-loom"), "theme-forge-stellar-loom")
        self.assertEqual(_safe_observed_token("0.4.0-1.fc43"), "0.4.0-1.fc43")

        # None or empty returns empty string
        self.assertEqual(_safe_observed_token(None), "")
        self.assertEqual(_safe_observed_token(""), "")

        # Unsafe characters (newlines, null bytes, special symbols) hashed
        unsafe_val = "token\ninjected"
        hashed = _safe_observed_token(unsafe_val)
        self.assertEqual(hashed, digest(unsafe_val.encode("utf-8")))
        self.assertTrue(re.fullmatch(r"[0-9a-f]{64}", hashed))

        # Windows drive path prefix hashed
        win_path = "C:/secret/path"
        self.assertEqual(_safe_observed_token(win_path), digest(win_path.encode("utf-8")))

        # Long token exceeding 256 chars hashed
        long_val = "a" * 300
        self.assertEqual(_safe_observed_token(long_val), digest(long_val.encode("utf-8")))

    def test_rpm_build_proves_noarch_query_evidence(self):
        capture, intent, offline_npm = create_cli_fixture(self.root / "loom_input", product="theme-forge-stellar-loom")
        runner = self._setup_runner(arch="noarch")
        result = build_rpm_candidate(
            capture, intent, "noarch", self.scratch,
            offline_npm_archives=offline_npm, runner=runner,
        )
        manifest = result["manifest"]
        self.assertEqual(manifest["architecture"], "noarch")
        self.assertEqual(manifest["rpm_identity"]["name"], "theme-forge-stellar-loom")
        self.assertEqual(manifest["rpm_identity"]["version"], "0.4.0")
        self.assertEqual(manifest["rpm_identity"]["release"], "1.fc43")
        self.assertEqual(manifest["rpm_identity"]["arch"], "noarch")
        self.assertEqual(manifest["rpm_payload_digest"]["payload_digest_algo"], "sha256")
        self.assertEqual(manifest["rpm_payload_digest"]["payload_digest"], "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789")
        self.assertEqual(manifest["schema"], "rs9.rpm-candidate.v1alpha2")

    def test_native_requires_exit_zero_with_stderr_fails(self):
        capture, intent, offline_npm = self._make_burst_fixture("requires-stderr")
        runner = self._setup_runner(arch="x86_64", name="theme-forge-stellar-burst", version="0.6.1")
        original = runner.handlers["rpm"]
        def noisy_requires(argv, **kwargs):
            receipt = original(argv, **kwargs)
            if "--requires" in argv:
                return CommandReceipt(argv, 0, receipt.stdout_bytes, b"error: unsupported query\n")
            return receipt
        runner.handlers["rpm"] = noisy_requires
        with self.assertRaises(ContractError) as caught:
            build_rpm_candidate(capture, intent, "x86_64", self.scratch,
                                offline_npm_archives=offline_npm, runner=runner)
        self.assertEqual(caught.exception.code, "DEPENDENCY_DERIVATION")

    def test_rpm_query_unexpected_arch_outside_lane_vocabulary_rejected(self):
        capture, intent, offline_npm = create_cli_fixture(self.root / "loom_input", product="theme-forge-stellar-loom")
        for bad_arch in ("i686", "armv7hl", "amd64", "universal"):
            with self.subTest(arch=bad_arch):
                sub_scratch = self.scratch / f"scratch_{bad_arch}"
                sub_scratch.mkdir()
                bad_query = f"theme-forge-stellar-loom|0.4.0|1.fc43|{bad_arch}\n".encode()
                runner = self._setup_runner(arch="noarch", query_out=bad_query)
                with self.assertRaises(ContractError) as caught:
                    build_rpm_candidate(
                        capture, intent, "noarch", sub_scratch,
                        offline_npm_archives=offline_npm, runner=runner,
                    )
                self.assertEqual(caught.exception.code, "INVALID_ARCHITECTURE")
                self.assertEqual(caught.exception.details.get("diagnostic_token"), bad_arch)
                self.assertEqual(caught.exception.details["observed_architecture"], bad_arch)

    def test_rpm_query_arch_mismatch_rejected(self):
        capture, intent, offline_npm = create_cli_fixture(self.root / "loom_input", product="theme-forge-stellar-loom")
        # Observed x86_64 when noarch was expected
        mismatched_query = b"theme-forge-stellar-loom|0.4.0|1.fc43|x86_64\n"
        runner = self._setup_runner(arch="noarch", query_out=mismatched_query)
        with self.assertRaises(ContractError) as caught:
            build_rpm_candidate(
                capture, intent, "noarch", self.scratch,
                offline_npm_archives=offline_npm, runner=runner,
            )
        self.assertEqual(caught.exception.code, "INVALID_ARCHITECTURE")
        self.assertEqual(caught.exception.details.get("diagnostic_token"), "x86_64")

    def test_rpm_query_name_mismatch_raises_separate_invalid_name_code(self):
        capture, intent, offline_npm = create_cli_fixture(self.root / "loom_input", product="theme-forge-stellar-loom")
        wrong_name_query = b"wrong-product-name|0.4.0|1.fc43|noarch\n"
        runner = self._setup_runner(arch="noarch", query_out=wrong_name_query)
        with self.assertRaises(ContractError) as caught:
            build_rpm_candidate(
                capture, intent, "noarch", self.scratch,
                offline_npm_archives=offline_npm, runner=runner,
            )
        self.assertEqual(caught.exception.code, "INVALID_NAME")
        self.assertEqual(caught.exception.details.get("diagnostic_token"), "wrong-product-name")
        self.assertEqual(caught.exception.details.get("product"), "theme-forge-stellar-loom")

    def test_rpm_query_version_mismatch_raises_separate_invalid_version_code(self):
        capture, intent, offline_npm = create_cli_fixture(self.root / "loom_input", product="theme-forge-stellar-loom")
        wrong_version_query = b"theme-forge-stellar-loom|9.9.9|1.fc43|noarch\n"
        runner = self._setup_runner(arch="noarch", query_out=wrong_version_query)
        with self.assertRaises(ContractError) as caught:
            build_rpm_candidate(
                capture, intent, "noarch", self.scratch,
                offline_npm_archives=offline_npm, runner=runner,
            )
        self.assertEqual(caught.exception.code, "INVALID_VERSION")
        self.assertEqual(caught.exception.details.get("diagnostic_token"), "9.9.9")
        self.assertEqual(caught.exception.details.get("product"), "theme-forge-stellar-loom")

    def test_rpm_query_unsafe_observed_token_is_safely_hashed(self):
        capture, intent, offline_npm = create_cli_fixture(self.root / "loom_input", product="theme-forge-stellar-loom")
        unsafe_name = "injected/name;rm -rf /"
        unsafe_query = f"{unsafe_name}|0.4.0|1.fc43|noarch\n".encode()
        runner = self._setup_runner(arch="noarch", query_out=unsafe_query)
        with self.assertRaises(ContractError) as caught:
            build_rpm_candidate(
                capture, intent, "noarch", self.scratch,
                offline_npm_archives=offline_npm, runner=runner,
            )
        self.assertEqual(caught.exception.code, "INVALID_NAME")
        token = caught.exception.details.get("diagnostic_token")
        self.assertNotIn("\n", token)
        self.assertEqual(token, digest(unsafe_name.encode("utf-8")))

    def test_rpm_query_release_distro_validation_plain_fc43_and_wrong_suffix(self):
        capture, intent, offline_npm = create_cli_fixture(self.root / "loom_input", product="theme-forge-stellar-loom")

        # 1. Plain revision "1" passes
        s_plain = self.scratch / "s_plain"
        s_plain.mkdir()
        runner_plain = self._setup_runner(arch="noarch", release_expansion="1", query_out=b"theme-forge-stellar-loom|0.4.0|1|noarch\n")
        res_plain = build_rpm_candidate(capture, intent, "noarch", s_plain,
                                        offline_npm_archives=offline_npm, runner=runner_plain)
        self.assertEqual(res_plain["manifest"]["rpm_identity"]["release"], "1")

        # 2. Builder-expanded dist "1.fc43" passes
        s_dist = self.scratch / "s_dist"
        s_dist.mkdir()
        runner_dist = self._setup_runner(arch="noarch", query_out=b"theme-forge-stellar-loom|0.4.0|1.fc43|noarch\n")
        res_dist = build_rpm_candidate(capture, intent, "noarch", s_dist,
                                       offline_npm_archives=offline_npm, runner=runner_dist)
        self.assertEqual(res_dist["manifest"]["rpm_identity"]["release"], "1.fc43")

        # 3. Wrong suffix (e.g. "1.wrong", "1.el8", "1.fc42") raises INVALID_RELEASE
        for bad_rel in ("1.wrong", "1.el8", "1.fc42"):
            with self.subTest(bad_rel=bad_rel):
                s_bad = self.scratch / f"s_{bad_rel}"
                s_bad.mkdir()
                runner_bad = self._setup_runner(arch="noarch", query_out=f"theme-forge-stellar-loom|0.4.0|{bad_rel}|noarch\n".encode())
                with self.assertRaises(ContractError) as caught:
                    build_rpm_candidate(capture, intent, "noarch", s_bad,
                                        offline_npm_archives=offline_npm, runner=runner_bad)
                self.assertEqual(caught.exception.code, "INVALID_RELEASE")
                self.assertEqual(caught.exception.details.get("diagnostic_token"), bad_rel)

    def test_rpm_query_command_failure_raises_rpm_query_failed(self):
        capture, intent, offline_npm = create_cli_fixture(self.root / "loom_input", product="theme-forge-stellar-loom")
        runner = self._setup_runner(arch="noarch", query_exit=1)
        with self.assertRaises(ContractError) as caught:
            build_rpm_candidate(
                capture, intent, "noarch", self.scratch,
                offline_npm_archives=offline_npm, runner=runner,
            )
        self.assertEqual(caught.exception.code, "RPM_QUERY_FAILED")

    def test_rpm_query_empty_output_raises_rpm_query_failed(self):
        capture, intent, offline_npm = create_cli_fixture(self.root / "loom_input", product="theme-forge-stellar-loom")
        runner = self._setup_runner(arch="noarch", query_out=b"  \n")
        with self.assertRaises(ContractError) as caught:
            build_rpm_candidate(
                capture, intent, "noarch", self.scratch,
                offline_npm_archives=offline_npm, runner=runner,
            )
        self.assertEqual(caught.exception.code, "RPM_QUERY_FAILED")

    def test_rpm_query_unparseable_output_raises_rpm_query_failed(self):
        capture, intent, offline_npm = create_cli_fixture(self.root / "loom_input", product="theme-forge-stellar-loom")
        runner = self._setup_runner(arch="noarch", query_out=b"corrupted\n")
        with self.assertRaises(ContractError) as caught:
            build_rpm_candidate(
                capture, intent, "noarch", self.scratch,
                offline_npm_archives=offline_npm, runner=runner,
            )
        self.assertEqual(caught.exception.code, "RPM_QUERY_FAILED")

    def test_rpmlint_failure_raises_rpmlint_failed(self):
        capture, intent, offline_npm = create_cli_fixture(self.root / "loom_input", product="theme-forge-stellar-loom")
        runner = self._setup_runner(arch="noarch", rpmlint_exit=1)
        with self.assertRaises(ContractError) as caught:
            build_rpm_candidate(
                capture, intent, "noarch", self.scratch,
                offline_npm_archives=offline_npm, runner=runner,
            )
        self.assertEqual(caught.exception.code, "RPMLINT_FAILED")

    def test_createrepo_failure_raises_build_failed(self):
        capture, intent, offline_npm = create_cli_fixture(self.root / "loom_input", product="theme-forge-stellar-loom")
        runner = self._setup_runner(arch="noarch", createrepo_exit=1)
        with self.assertRaises(ContractError) as caught:
            build_rpm_candidate(
                capture, intent, "noarch", self.scratch,
                offline_npm_archives=offline_npm, runner=runner,
            )
        self.assertEqual(caught.exception.code, "BUILD_FAILED")

    def _make_burst_fixture(self, sub_name="burst"):
        from rs9.burst_native import BURST_CLOSED_PREBUILDS
        from tests.test_burst_platform_wheel import make_synthetic_elf, make_synthetic_macho

        prebuild_binaries = {
            "darwin-arm64": make_synthetic_macho("arm64", 13, 0),
            "darwin-x64": make_synthetic_macho("x86_64", 15, 0),
            "linux-arm64-gnu": make_synthetic_elf("aarch64"),
            "linux-x64-gnu": make_synthetic_elf("x86_64"),
        }
        extra_entries = [
            (path.removeprefix("package/"), prebuild_binaries[key])
            for key, path in BURST_CLOSED_PREBUILDS.items()
        ]
        burst_input = self.root / f"burst_input_{sub_name}"
        return create_cli_fixture(
            burst_input,
            product="theme-forge-stellar-burst",
            extra_asset_entries=extra_entries,
        )

    def test_rpm_build_proves_x86_64_native_evidence(self):
        capture, intent, offline_npm = self._make_burst_fixture("x86_64")
        sub_scratch = self.scratch / "scratch_x86_64"
        sub_scratch.mkdir()
        runner = self._setup_runner(arch="x86_64", name="theme-forge-stellar-burst", version="0.6.1")
        result = build_rpm_candidate(
            capture, intent, "x86_64", sub_scratch,
            offline_npm_archives=offline_npm, runner=runner,
        )
        manifest = result["manifest"]
        self.assertEqual(manifest["architecture"], "x86_64")
        self.assertEqual(manifest["rpm_identity"]["name"], "theme-forge-stellar-burst")
        self.assertEqual(manifest["rpm_identity"]["version"], "0.6.1")
        self.assertEqual(manifest["rpm_identity"]["arch"], "x86_64")
        self.assertEqual(manifest["rpm_payload_digest"]["payload_digest_algo"], "sha256")
        self.assertEqual(manifest["schema"], "rs9.rpm-candidate.v1alpha2")

    def test_rpm_build_proves_aarch64_native_evidence(self):
        capture, intent, offline_npm = self._make_burst_fixture("aarch64")
        sub_scratch = self.scratch / "scratch_aarch64"
        sub_scratch.mkdir()
        runner = self._setup_runner(arch="aarch64", name="theme-forge-stellar-burst", version="0.6.1")
        result = build_rpm_candidate(
            capture, intent, "aarch64", sub_scratch,
            offline_npm_archives=offline_npm, runner=runner,
        )
        manifest = result["manifest"]
        self.assertEqual(manifest["architecture"], "aarch64")
        self.assertEqual(manifest["rpm_identity"]["name"], "theme-forge-stellar-burst")
        self.assertEqual(manifest["rpm_identity"]["version"], "0.6.1")
        self.assertEqual(manifest["rpm_identity"]["arch"], "aarch64")
        self.assertEqual(manifest["rpm_payload_digest"]["payload_digest_algo"], "sha256")
        self.assertEqual(manifest["schema"], "rs9.rpm-candidate.v1alpha2")


if __name__ == "__main__":
    unittest.main()
