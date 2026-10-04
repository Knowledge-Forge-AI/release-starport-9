"""Unit tests for rs9.hosted_packaging."""

from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest

from rs9.build_native import CommandReceipt, MockCommandRunner
from rs9.errors import ContractError
from rs9.hosted_native import container_tool_facts
from rs9.hosted_packaging import (
    FIXTURE_ARMOR,
    FIXTURE_KEYRING,
    checked,
    sign_rpm,
    write_keys,
)
from rs9.pages_candidate import _fixture_public_armor
from rs9.release_core import digest


class HostedPackagingTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name).resolve()

    def test_fixture_public_armor_preferred_bytes_rule(self):
        # Preferred bytes rule: public_key_bytes takes precedence over public_key_armor
        with_both = SimpleNamespace(
            public_key_bytes=b"preferred-bytes",
            public_key_armor="fallback-str",
        )
        self.assertEqual(_fixture_public_armor(with_both), b"preferred-bytes")

        # String armor is converted to UTF-8 bytes when public_key_bytes is None or absent
        str_only = SimpleNamespace(
            public_key_bytes=None,
            public_key_armor="armor-as-str",
        )
        self.assertEqual(_fixture_public_armor(str_only), b"armor-as-str")

    def test_write_keys_with_str_and_bytes_armor(self):
        dest1 = self.root / "keys1"
        fixture_str = SimpleNamespace(
            primary_fingerprint="A" * 40,
            public_key_armor="-----BEGIN PGP PUBLIC KEY BLOCK-----\narmor\n-----END PGP PUBLIC KEY BLOCK-----\n",
            public_key_binary=b"\x99\x00keyring",
        )
        write_keys(dest1, fixture_str)
        self.assertEqual((dest1 / FIXTURE_ARMOR).read_bytes(), fixture_str.public_key_armor.encode("utf-8"))
        self.assertEqual((dest1 / FIXTURE_KEYRING).read_bytes(), fixture_str.public_key_binary)
        self.assertTrue((dest1 / "KEY-METADATA.json").is_file())

        dest2 = self.root / "keys2"
        fixture_bytes = SimpleNamespace(
            primary_fingerprint="B" * 40,
            public_key_bytes=b"bytes-armor",
            public_key_armor="str-armor",
            public_key_binary=b"\x99\x01keyring",
        )
        write_keys(dest2, fixture_bytes)
        self.assertEqual((dest2 / FIXTURE_ARMOR).read_bytes(), b"bytes-armor")
        self.assertEqual((dest2 / FIXTURE_KEYRING).read_bytes(), fixture_bytes.public_key_binary)

    def test_checked_executed_and_synthetic_runner_distinction(self):
        class DistinctionRunner:
            def __init__(self, receipt):
                self.receipt = receipt

            def run(self, argv, **kwargs):
                return self.receipt

        # Executed runner passes
        executed_receipt = CommandReceipt(["tool"], 0, b"ok", b"", executed=True)
        res = checked(DistinctionRunner(executed_receipt), ["tool"])
        self.assertEqual(res, executed_receipt)

        # Synthetic runner (executed=False) fails with NATIVE_TOOL even with exit_code=0
        synthetic_receipt = CommandReceipt(["tool"], 0, b"ok", b"", executed=False)
        with self.assertRaises(ContractError) as caught:
            checked(DistinctionRunner(synthetic_receipt), ["tool"])
        self.assertEqual(caught.exception.code, "NATIVE_TOOL")
        self.assertIn("failed: tool", caught.exception.message)

        # Failure exit code raises NATIVE_TOOL
        failed_receipt = CommandReceipt(["tool"], 1, b"", b"err", executed=True)
        with self.assertRaises(ContractError) as caught:
            checked(DistinctionRunner(failed_receipt), ["tool"])
        self.assertEqual(caught.exception.code, "NATIVE_TOOL")

    def test_sign_rpm_with_str_armor_and_executed_runner(self):
        rpm_file = self.root / "sample.rpm"
        rpm_file.write_bytes(b"initial-rpm-content")

        fixture_home = self.root / "fixture-home"
        fixture_home.mkdir()
        fixture = SimpleNamespace(
            primary_fingerprint="C" * 40,
            homedir=fixture_home,
            gpg="gpg",
            public_key_armor="-----BEGIN PGP PUBLIC KEY BLOCK-----\narmor\n-----END PGP PUBLIC KEY BLOCK-----\n",
            public_key_binary=b"\x99\x02keyring",
        )

        class ExecutedRpmRunner:
            def __init__(self):
                self.calls = []

            def run(self, argv, **kwargs):
                self.calls.append(argv)
                cmd = argv[0]
                if cmd == "rpmsign":
                    # simulate signing by mutating the target file
                    target = Path(argv[-1])
                    target.write_bytes(target.read_bytes() + b"-signed")
                    return CommandReceipt(argv, 0, b"", b"", executed=True)
                if cmd == "rpmkeys":
                    return CommandReceipt(argv, 0, b"sample.rpm: digests signatures OK\n", b"", executed=True)
                return CommandReceipt(argv, 0, b"", b"", executed=True)

        runner = ExecutedRpmRunner()
        result = sign_rpm(runner, rpm_file, fixture)
        self.assertEqual(result["unsigned_sha256"], digest(b"initial-rpm-content"))
        self.assertEqual(result["fixture_signed_sha256"], digest(b"initial-rpm-content-signed"))
        self.assertEqual(result["fixture_fingerprint"], "C" * 40)
        self.assertFalse(result["production"])
        self.assertEqual((fixture_home / FIXTURE_ARMOR).read_bytes(), fixture.public_key_armor.encode("utf-8"))

    def test_sign_rpm_rejects_synthetic_runner(self):
        rpm_file = self.root / "sample.rpm"
        rpm_file.write_bytes(b"initial-rpm-content")
        fixture_home = self.root / "fixture-home"
        fixture_home.mkdir()
        fixture = SimpleNamespace(
            primary_fingerprint="C" * 40,
            homedir=fixture_home,
            gpg="gpg",
            public_key_armor="armor",
        )

        class SyntheticRunner:
            def run(self, argv, **kwargs):
                return CommandReceipt(argv, 0, b"", b"", executed=False)

        with self.assertRaises(ContractError) as caught:
            sign_rpm(SyntheticRunner(), rpm_file, fixture)
        self.assertEqual(caught.exception.code, "NATIVE_TOOL")

    def test_tool_unavailable_unit_regression_uses_runner_available_tools(self):
        # Regression: tool availability is governed by runner available_tools, not global shutil.which
        empty_runner = MockCommandRunner(available_tools={})
        facts = container_tool_facts(empty_runner, ["rpm", "createrepo_c", "rpmsign"])
        self.assertEqual(facts, {
            "rpm": "unavailable",
            "createrepo_c": "unavailable",
            "rpmsign": "unavailable",
        })

        partial_runner = MockCommandRunner(
            available_tools={"rpm": "/usr/bin/rpm"},
            handlers={"rpm": lambda argv, **kw: CommandReceipt(argv, 0, b"RPM version 4.19\n", b"", executed=True)},
        )
        facts_partial = container_tool_facts(partial_runner, ["rpm", "createrepo_c"])
        self.assertEqual(facts_partial["rpm"], "RPM version 4.19")
        self.assertEqual(facts_partial["createrepo_c"], "unavailable")


if __name__ == "__main__":
    unittest.main()
