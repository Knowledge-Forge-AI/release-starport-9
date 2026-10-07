"""Unit tests for rs9.hosted_packaging."""

import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

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


def wrong_fixture(fixture):
    return SimpleNamespace(primary_fingerprint=('F' if fixture.primary_fingerprint != 'F' * 40 else 'E') * 40,
                           public_key_armor='synthetic distinct wrong-key armor')


class HostedPackagingTests(unittest.TestCase):
    def setUp(self):
        # These orchestration fixtures contain synthetic captures; released loader
        # authentication and execution are exercised in the Burst-specific tests.
        loader_record = patch("rs9.hosted_deb._burst_release_record", return_value={"synthetic": True})
        loader_record.start()
        self.addCleanup(loader_record.stop)
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

        failed_receipt = CommandReceipt(["tool"], 1, b"", b"err", executed=True)
        with self.assertRaises(ContractError) as caught:
            checked(DistinctionRunner(failed_receipt), ["tool"])
        self.assertEqual(caught.exception.code, "NATIVE_TOOL")

    def test_real_pacman_and_rpm_hosted_calls_preserve_safe_failure_codes(self):
        from unittest.mock import patch
        import json
        from rs9.hosted_packaging import execute
        for family in ("pacman", "rpm"):
            for index, error in enumerate((ContractError("TOOL_TIMEOUT", "timeout"),
                                           ContractError("TOOL_EXECUTION", "missing"),
                                           ContractError("INVALID_ARCHITECTURE", "native bytes in universal package"),
                                           OSError("private failure"))):
                with self.subTest(family=family, code=type(error).__name__):
                    scratch = self.root / (family + str(index))
                    scratch.mkdir()
                    context = {"family": family, "system": "x86_64-linux", "repository": self.root,
                               "scratch": scratch, "pins": {}, "client": None,
                               "captures": [(SimpleNamespace(), {"project": {"id": "theme-forge-stellar-burst"}}, {})]}
                    environment = {"platform": "linux/amd64", "image_ref": "fixture@sha256:" + "a" * 64,
                                   "preprovisioned_packages": [], "tools": {}}
                    name = "rs9.hosted_packaging.build_" + family + "_candidate"
                    with patch("rs9.hosted_packaging.provision", return_value=environment), \
                         patch("rs9.hosted_deb.provision_image"), \
                         patch("rs9.hosted_packaging.checked"), \
                         patch("rs9.hosted_packaging.container_tool_facts", return_value={}), \
                         patch("rs9.hosted_packaging._resolve_offline_npm_archives", return_value=None), \
                         patch(name, autospec=True, side_effect=error) as builder:
                        with self.assertRaises(ContractError) as caught:
                            execute(context)
                    self.assertEqual(caught.exception.code, "NATIVE_BUILD")
                    builder.assert_called_once()
                    self.assertNotIn("maintainer", builder.call_args.kwargs)
                    diagnostic = json.loads((scratch / "diagnostics/build-errors.json").read_bytes())
                    expected = error.code if isinstance(error, ContractError) else "PACKAGE_FILESYSTEM"
                    self.assertEqual(diagnostic["errors"]["theme-forge-stellar-burst"], expected)
                    self.assertNotIn("private failure", json.dumps(diagnostic))
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
                if cmd == "rpm":
                    if "--version" in argv:
                        return CommandReceipt(argv, 0, b"RPM version 6.0.0\n", b"", executed=True)
                    if "--querytags" in argv:
                        return CommandReceipt(argv, 0, b"PAYLOADSHA256\nPAYLOADSHA256ALGO\n", b"", executed=True)
                    if "--eval" in argv and "_keyring" in argv[-1]:
                        definitions = dict(a.split(" ", 1) for a in argv if a.startswith(("_keyring ", "_keyringpath ", "_dbpath ")))
                        raw = "|".join(definitions[k] for k in ("_keyring", "_keyringpath", "_dbpath")) + "\n"
                        return CommandReceipt(argv, 0, raw.encode(), b"", executed=True)
                    if "--eval" in argv:
                        return CommandReceipt(argv, 0, b"1.fc43\n", b"", executed=True)
                    qf = argv[argv.index("--queryformat") + 1] if "--queryformat" in argv else ""
                    if "%{PAYLOAD" in qf:
                        return CommandReceipt(argv, 0, b"abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789|8\n", b"", executed=True)
                    return CommandReceipt(argv, 0, b"sample|1.0.0|1.fc43|x86_64\n", b"", executed=True)
                if cmd == "rpmsign":
                    # simulate signing by mutating the target file
                    target = Path(argv[-1])
                    target.write_bytes(target.read_bytes() + b"-signed")
                    return CommandReceipt(argv, 0, b"", b"", executed=True)
                if cmd == "rpmkeys":
                    if "--checksig" in argv:
                        if any("wrong-rpmdb" in a or "empty-rpmdb" in a or ".tampered" in a for a in argv):
                            return CommandReceipt(argv, 1, b"sample.rpm: digests signatures NOT OK\n", b"", executed=True)
                        return CommandReceipt(argv, 0, b"sample.rpm: digests signatures OK\n", b"", executed=True)
                    return CommandReceipt(argv, 0, b"", b"", executed=True)
                return CommandReceipt(argv, 0, b"", b"", executed=True)

        runner = ExecutedRpmRunner()
        from rs9.rpm_query import query_rpm_identity, query_rpm_payload_digest
        identity, _ = query_rpm_identity(runner, rpm_file)
        payload, _ = query_rpm_payload_digest(runner, rpm_file)
        expected = {"package_sha256": digest(rpm_file.read_bytes()),
                    "rpm_identity": identity, "rpm_payload_digest": payload}
        for bad in ({**expected, "package_sha256": "0" * 64},
                    {**expected, "rpm_identity": {**identity, "name": "wrong"}},
                    {**expected, "rpm_payload_digest": {**payload, "scope": "uncompressed-payload"}}):
            with self.subTest(expected=bad), self.assertRaises(ContractError) as caught:
                sign_rpm(runner, rpm_file, fixture, expected=bad, wrong_fixture=wrong_fixture(fixture))
            self.assertEqual(caught.exception.code, "RPM_SIGNING")
            self.assertEqual(rpm_file.read_bytes(), b"initial-rpm-content")
        result = sign_rpm(runner, rpm_file, fixture, expected=expected, wrong_fixture=wrong_fixture(fixture))
        self.assertEqual(result["unsigned_sha256"], digest(b"initial-rpm-content"))
        self.assertEqual(result["fixture_signed_sha256"], digest(b"initial-rpm-content-signed"))
        self.assertNotEqual(result["unsigned_sha256"], result["fixture_signed_sha256"])
        self.assertEqual(result["fixture_fingerprint"], "C" * 40)
        self.assertFalse(result["production"])
        self.assertEqual(result["rpm_identity"]["name"], "sample")
        self.assertEqual(result["rpm_identity"]["version"], "1.0.0")
        self.assertEqual(result["rpm_identity"]["release"], "1.fc43")
        self.assertEqual(result["rpm_identity"]["arch"], "x86_64")
        self.assertEqual(result["rpm_payload_digest"]["payload_digest"], "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789")
        self.assertEqual(result["rpm_payload_digest"]["algorithm_numeric"], 8)
        self.assertTrue(result["identity_preserved"])
        self.assertTrue(result["payload_digest_preserved"])
        self.assertEqual((fixture_home / FIXTURE_ARMOR).read_bytes(), fixture.public_key_armor.encode("utf-8"))

        # Verify probe record and lane diagnostics retention
        self.assertIn("probe", result)
        self.assertEqual(result["probe"]["status"], "pass")
        self.assertEqual(result["probe"]["checks"]["real_checksig"], "pass")
        self.assertEqual(result["probe"]["checks"]["wrong_key_rejection"], "pass")
        self.assertEqual(result["probe"]["checks"]["empty_trust_rejection"], "pass")
        self.assertEqual(result["probe"]["checks"]["tamper_rejection"], "pass")
        self.assertTrue(result["probe"]["checks"]["supported_tags"])
        self.assertTrue(result["probe"]["checks"]["algo8"])
        self.assertTrue(result["probe"]["checks"]["whole_file_sha_changed"])
        self.assertTrue(next((fixture_home / "diagnostics").glob("rpm-signed-query-probe-*.json")).is_file())

    def test_sign_rpm_rejects_identity_mutation_after_signing(self):
        rpm_file = self.root / "sample_mutate_id.rpm"
        rpm_file.write_bytes(b"initial-rpm-content")
        fixture_home = self.root / "fixture-home-id"
        fixture_home.mkdir()
        fixture = SimpleNamespace(
            primary_fingerprint="C" * 40,
            homedir=fixture_home,
            gpg="gpg",
            public_key_armor="-----BEGIN PGP PUBLIC KEY BLOCK-----\narmor\n-----END PGP PUBLIC KEY BLOCK-----\n",
            public_key_binary=b"\x99\x02keyring",
        )
        signed_counter = [0]

        class MutatingIdRunner:
            def run(self, argv, **kwargs):
                cmd = argv[0]
                if cmd == "rpm":
                    if "--version" in argv:
                        return CommandReceipt(argv, 0, b"RPM version 6.0.0\n", b"", executed=True)
                    if "--querytags" in argv:
                        return CommandReceipt(argv, 0, b"PAYLOADSHA256\nPAYLOADSHA256ALGO\n", b"", executed=True)
                    if "--eval" in argv and "_keyring" in argv[-1]:
                        definitions = dict(a.split(" ", 1) for a in argv if a.startswith(("_keyring ", "_keyringpath ", "_dbpath ")))
                        raw = "|".join(definitions[k] for k in ("_keyring", "_keyringpath", "_dbpath")) + "\n"
                        return CommandReceipt(argv, 0, raw.encode(), b"", executed=True)
                    if "--eval" in argv:
                        return CommandReceipt(argv, 0, b"1.fc43\n", b"", executed=True)
                    qf = argv[argv.index("--queryformat") + 1] if "--queryformat" in argv else ""
                    if "%{PAYLOAD" in qf:
                        return CommandReceipt(argv, 0, b"abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789|8\n", b"", executed=True)
                    if signed_counter[0] > 0 and not any("empty-rpmdb" in a for a in argv):
                        return CommandReceipt(argv, 0, b"mutated-name|1.0.0|1.fc43|x86_64\n", b"", executed=True)
                    return CommandReceipt(argv, 0, b"sample|1.0.0|1.fc43|x86_64\n", b"", executed=True)
                if cmd == "rpmsign":
                    signed_counter[0] += 1
                    target = Path(argv[-1])
                    target.write_bytes(target.read_bytes() + b"-signed")
                    return CommandReceipt(argv, 0, b"", b"", executed=True)
                if cmd == "rpmkeys":
                    if "--checksig" in argv:
                        if any("wrong-rpmdb" in a or "empty-rpmdb" in a or ".tampered" in a for a in argv):
                            return CommandReceipt(argv, 1, b"sample.rpm: digests signatures NOT OK\n", b"", executed=True)
                        return CommandReceipt(argv, 0, b"sample.rpm: digests signatures OK\n", b"", executed=True)
                    return CommandReceipt(argv, 0, b"", b"", executed=True)
                return CommandReceipt(argv, 0, b"", b"", executed=True)

        with self.assertRaises(ContractError) as caught:
            sign_rpm(MutatingIdRunner(), rpm_file, fixture, wrong_fixture=wrong_fixture(fixture))
        self.assertEqual(caught.exception.code, "RPM_SIGNING")
        self.assertIn("identity changed", caught.exception.message)
        self.assertTrue(next((fixture_home / "diagnostics").glob("rpm-signed-query-probe-*.json")).is_file())

    def test_sign_rpm_rejects_payload_digest_mutation_after_signing(self):
        rpm_file = self.root / "sample_mutate_pd.rpm"
        rpm_file.write_bytes(b"initial-rpm-content")
        fixture_home = self.root / "fixture-home-pd"
        fixture_home.mkdir()
        fixture = SimpleNamespace(
            primary_fingerprint="C" * 40,
            homedir=fixture_home,
            gpg="gpg",
            public_key_armor="-----BEGIN PGP PUBLIC KEY BLOCK-----\narmor\n-----END PGP PUBLIC KEY BLOCK-----\n",
            public_key_binary=b"\x99\x02keyring",
        )
        signed_counter = [0]

        class MutatingPdRunner:
            def run(self, argv, **kwargs):
                cmd = argv[0]
                if cmd == "rpm":
                    if "--version" in argv:
                        return CommandReceipt(argv, 0, b"RPM version 6.0.0\n", b"", executed=True)
                    if "--querytags" in argv:
                        return CommandReceipt(argv, 0, b"PAYLOADSHA256\nPAYLOADSHA256ALGO\n", b"", executed=True)
                    if "--eval" in argv and "_keyring" in argv[-1]:
                        definitions = dict(a.split(" ", 1) for a in argv if a.startswith(("_keyring ", "_keyringpath ", "_dbpath ")))
                        raw = "|".join(definitions[k] for k in ("_keyring", "_keyringpath", "_dbpath")) + "\n"
                        return CommandReceipt(argv, 0, raw.encode(), b"", executed=True)
                    if "--eval" in argv:
                        return CommandReceipt(argv, 0, b"1.fc43\n", b"", executed=True)
                    qf = argv[argv.index("--queryformat") + 1] if "--queryformat" in argv else ""
                    if "%{PAYLOAD" in qf:
                        if signed_counter[0] > 0 and not any("empty-rpmdb" in a for a in argv):
                            return CommandReceipt(argv, 0, b"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb|8\n", b"", executed=True)
                        return CommandReceipt(argv, 0, b"abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789|8\n", b"", executed=True)
                    return CommandReceipt(argv, 0, b"sample|1.0.0|1.fc43|x86_64\n", b"", executed=True)
                if cmd == "rpmsign":
                    signed_counter[0] += 1
                    target = Path(argv[-1])
                    target.write_bytes(target.read_bytes() + b"-signed")
                    return CommandReceipt(argv, 0, b"", b"", executed=True)
                if cmd == "rpmkeys":
                    if "--checksig" in argv:
                        if any("wrong-rpmdb" in a or "empty-rpmdb" in a or ".tampered" in a for a in argv):
                            return CommandReceipt(argv, 1, b"sample.rpm: digests signatures NOT OK\n", b"", executed=True)
                        return CommandReceipt(argv, 0, b"sample.rpm: digests signatures OK\n", b"", executed=True)
                    return CommandReceipt(argv, 0, b"", b"", executed=True)
                return CommandReceipt(argv, 0, b"", b"", executed=True)

        with self.assertRaises(ContractError) as caught:
            sign_rpm(MutatingPdRunner(), rpm_file, fixture, wrong_fixture=wrong_fixture(fixture))
        self.assertEqual(caught.exception.code, "RPM_SIGNING")
        self.assertIn("payload digest changed", caught.exception.message)
        self.assertTrue(next((fixture_home / "diagnostics").glob("rpm-signed-query-probe-*.json")).is_file())

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
            sign_rpm(SyntheticRunner(), rpm_file, fixture, wrong_fixture=wrong_fixture(fixture))
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

    def test_checked_native_tool_contract_error_details_safe_boundaries(self):
        from rs9.errors import safe_details

        class FailingRunner:
            def run(self, argv, **kwargs):
                return CommandReceipt(argv, 2, b"stdout bytes", b"stderr error", executed=True)

        with self.assertRaises(ContractError) as caught:
            checked(FailingRunner(), ["/usr/bin/createrepo_c", "--no-database", "repodir"], substage="repo-index")

        err = caught.exception
        self.assertEqual(err.code, "NATIVE_TOOL")
        self.assertEqual(err.details.get("tool"), "createrepo_c")
        self.assertEqual(err.details.get("substage"), "repo-index")
        self.assertEqual(err.details.get("exit_code"), 2)
        self.assertEqual(err.details.get("stdout_sha256"), digest(b"stdout bytes"))
        self.assertEqual(err.details.get("stderr_sha256"), digest(b"stderr error"))

        # Verify safe_details boundary accepts and preserves all fields without truncation
        safe = safe_details(err.details)
        self.assertEqual(safe.get("tool"), "createrepo_c")
        self.assertEqual(safe.get("substage"), "repo-index")
        self.assertEqual(safe.get("exit_code"), 2)
        self.assertNotIn("details_truncated", safe)

    def test_real_signature_builder_autospec_regression(self):
        import inspect
        from unittest.mock import patch
        from rs9.build_pacman import build_pacman_candidate
        from rs9.build_rpm import build_rpm_candidate
        from rs9.hosted_packaging import execute

        # Prove that real builder signatures do not accept maintainer parameter
        pacman_sig = inspect.signature(build_pacman_candidate)
        self.assertNotIn("maintainer", pacman_sig.parameters)
        rpm_sig = inspect.signature(build_rpm_candidate)
        self.assertNotIn("maintainer", rpm_sig.parameters)
        from unittest.mock import create_autospec
        for build in (build_pacman_candidate, build_rpm_candidate):
            with self.assertRaises(TypeError):
                create_autospec(build)(None, None, "any", self.root, maintainer="fixture")

        # Build context with lane-work scratch and orchestration paths
        outer = self.root / "orchestration"
        outer.mkdir()
        (outer / "capture").mkdir()
        (outer / "authentication.json").write_bytes(b"auth")
        lane_scratch = outer / "lane-work"
        lane_scratch.mkdir()

        captures = []
        for pid in ("theme-forge-stellar-burst", "theme-forge-stellar-loom",
                    "theme-forge-solar-sail", "theme-forge-nebular-fusion"):
            captures.append((
                SimpleNamespace(root=outer / "capture" / pid),
                {"project": {"id": pid}},
                {},
            ))

        context = {
            "family": "pacman",
            "system": "x86_64-linux",
            "repository": self.root,
            "scratch": lane_scratch,
            "pins": {"maintainer": "Lead <lead@example.com>"},
            "captures": captures,
            "client": None,
            "binding": {"source_commit": "0" * 40},
            "authentication_sha256": "1" * 64,
        }

        # Mock build_pacman_candidate with autospec=True
        # If maintainer keyword is passed, autospec=True raises TypeError!
        def mock_build(capture, intent, arch, scratch_dir, **kwargs):
            pkg_path = Path(scratch_dir) / f"{intent['project']['id']}-1.0.0-1-any.pkg.tar.zst"
            pkg_path.write_bytes(b"package-data")
            (Path(scratch_dir) / "pacman-manifest.json").write_bytes(b"{}")
            return {"package_path": pkg_path}

        class MockRunner:
            def run(self, argv, **kw):
                return CommandReceipt(argv, 0, b"ok\n", b"", executed=True)

        env = {
            "family": "pacman", "system": "x86_64-linux", "image_ref": "arch@sha256:" + "0"*64,
            "platform": "linux/amd64", "preprovisioned_packages": [], "tools": {},
        }
        class MockSigningFixture:
            def __init__(self, scratch_dir=None, **kw):
                self.primary_fingerprint = "A" * 40
                self.homedir = Path(tempfile.mkdtemp())
                self.gpg = "gpg"
                self.public_key_armor = "-----BEGIN PGP PUBLIC KEY BLOCK-----\narmor\n-----END PGP PUBLIC KEY BLOCK-----\n"
                self.public_key_binary = b"keyring"

            def __enter__(self):
                return self

            def __exit__(self, *args):
                pass

            def detach_sign(self, data, armor=False):
                return b"sig"

            def verify(self, data, sig):
                return True

        def mock_checked(runner, argv, **kwargs):
            if argv and argv[0] == "repo-add" and len(argv) > 1:
                db_path = Path(argv[1])
                db_path.parent.mkdir(parents=True, exist_ok=True)
                db_path.write_bytes(b"db-data")
                db_path.with_name("rs9.files.tar.gz").write_bytes(b"files-data")
            return CommandReceipt(argv, 0, b"", b"", executed=True)

        with patch("rs9.hosted_packaging.provision", return_value=env), \
             patch("rs9.hosted_deb.provision_image"), \
             patch("rs9.hosted_packaging.checked", side_effect=mock_checked), \
             patch("rs9.hosted_packaging.container_tool_facts", return_value={"pacman": "v1"}), \
             patch("rs9.hosted_packaging._resolve_offline_npm_archives", return_value=None), \
             patch("rs9.hosted_packaging.build_pacman_candidate", autospec=True, side_effect=mock_build) as builder_mock, \
             patch("rs9.pages_candidate.write_custody_bundle"), \
             patch("rs9.hosted_deb.client_cycle", return_value=([], {})), \
             patch("rs9.hosted_deb.tamper_cycle", return_value=[]), \
             patch("rs9.hosted_smoke.prepare_smoke", return_value={}), \
             patch("rs9.hosted_packaging.SigningFixture", MockSigningFixture):
            # This must run without TypeError: got an unexpected keyword argument 'maintainer'
            res = execute(context)
            self.assertTrue(builder_mock.called)
            for call in builder_mock.call_args_list:
                self.assertNotIn("maintainer", call.kwargs)

    def test_build_errors_diagnostics_emitted_and_empty_custody_guarded(self):
        from unittest.mock import patch
        from rs9.hosted_packaging import execute

        outer = self.root / "orchestration-err"
        outer.mkdir()
        lane_scratch = outer / "lane-work"
        lane_scratch.mkdir()

        captures = [(
            SimpleNamespace(root=outer / "capture" / "theme-forge-stellar-burst"),
            {"project": {"id": "theme-forge-stellar-burst"}},
            {},
        )]

        context = {
            "family": "pacman",
            "system": "x86_64-linux",
            "repository": self.root,
            "scratch": lane_scratch,
            "pins": {"maintainer": "Lead <lead@example.com>"},
            "captures": captures,
            "client": None,
            "binding": {"source_commit": "0" * 40},
            "authentication_sha256": "1" * 64,
        }

        env = {
            "family": "pacman", "system": "x86_64-linux", "image_ref": "arch@sha256:" + "0"*64,
            "platform": "linux/amd64", "preprovisioned_packages": [], "tools": {},
        }

        with patch("rs9.hosted_packaging.provision", return_value=env), \
             patch("rs9.hosted_deb.provision_image"), \
             patch("rs9.hosted_packaging.checked", return_value=CommandReceipt(["tool"], 0, b"", b"", executed=True)), \
             patch("rs9.hosted_packaging.container_tool_facts", return_value={"pacman": "v1"}), \
             patch("rs9.hosted_packaging._resolve_offline_npm_archives", return_value=None), \
             patch("rs9.hosted_packaging.build_pacman_candidate", autospec=True, side_effect=ContractError("BUILD_FAIL", "failed build")):
            with self.assertRaises(ContractError) as caught:
                execute(context)
            self.assertEqual(caught.exception.code, "NATIVE_BUILD")
            self.assertEqual(caught.exception.details.get("substage"), "package-build")
            self.assertEqual(caught.exception.details.get("family"), "pacman")
            self.assertEqual(caught.exception.details.get("product"), "theme-forge-stellar-burst")

            # Diagnostics must be emitted
            diag_file = lane_scratch / "diagnostics" / "build-errors.json"
            self.assertTrue(diag_file.is_file())
            # Empty unsigned-custody bundle must not have been created
            self.assertFalse((lane_scratch / "unsigned-custody").exists())

    def test_container_commands_mount_lane_work_only(self):
        from unittest.mock import patch
        from rs9.hosted_packaging import execute

        outer = self.root / "orchestration-mounts"
        outer.mkdir()
        capture_dir = outer / "capture"
        capture_dir.mkdir()
        auth_file = outer / "authentication.json"
        auth_file.write_bytes(b"auth-secret")
        inputs_dir = outer / "inputs"
        inputs_dir.mkdir()
        lane_scratch = outer / "lane-work"
        lane_scratch.mkdir()

        captures = []
        for pid in ("theme-forge-stellar-burst", "theme-forge-stellar-loom",
                    "theme-forge-solar-sail", "theme-forge-nebular-fusion"):
            captures.append((
                SimpleNamespace(root=capture_dir / pid),
                {"project": {"id": pid}},
                {},
            ))

        context = {
            "family": "pacman",
            "system": "x86_64-linux",
            "repository": self.root,
            "scratch": lane_scratch,
            "pins": {"maintainer": "Lead <lead@example.com>"},
            "captures": captures,
            "client": None,
            "binding": {"source_commit": "0" * 40},
            "authentication_sha256": "1" * 64,
        }

        observed_mounts = []

        def fake_container_init(self_cr, host, image, platform="linux/amd64", mounts=(), user="0:0", network=True):
            self_cr.mounts = list(mounts)
            self_cr.host = host
            self_cr.image = image
            self_cr.platform = platform
            self_cr.user = user
            self_cr.network = network
            observed_mounts.extend(list(mounts))

        def mock_build(capture, intent, arch, scratch_dir, **kwargs):
            pkg_path = Path(scratch_dir) / f"{intent['project']['id']}-1.0.0-1-any.pkg.tar.zst"
            pkg_path.write_bytes(b"package-data")
            (Path(scratch_dir) / "pacman-manifest.json").write_bytes(b"{}")
            return {"package_path": pkg_path}

        env = {
            "family": "pacman", "system": "x86_64-linux", "image_ref": "arch@sha256:" + "0"*64,
            "platform": "linux/amd64", "preprovisioned_packages": [], "tools": {},
        }

        class MockSigningFixture:
            def __init__(self, scratch_dir=None, **kw):
                self.primary_fingerprint = "A" * 40
                self.homedir = Path(tempfile.mkdtemp())
                self.gpg = "gpg"
                self.public_key_armor = "-----BEGIN PGP PUBLIC KEY BLOCK-----\narmor\n-----END PGP PUBLIC KEY BLOCK-----\n"
                self.public_key_binary = b"keyring"

            def __enter__(self):
                return self

            def __exit__(self, *args):
                pass

            def detach_sign(self, data, armor=False):
                return b"sig"

            def verify(self, data, sig):
                return True

        def mock_checked(runner, argv, **kwargs):
            if argv and argv[0] == "repo-add" and len(argv) > 1:
                db_path = Path(argv[1])
                db_path.parent.mkdir(parents=True, exist_ok=True)
                db_path.write_bytes(b"db-data")
                db_path.with_name("rs9.files.tar.gz").write_bytes(b"files-data")
            return CommandReceipt(argv, 0, b"", b"", executed=True)

        with patch("rs9.hosted_packaging.provision", return_value=env), \
             patch("rs9.hosted_deb.provision_image"), \
             patch("rs9.hosted_packaging.checked", side_effect=mock_checked), \
             patch("rs9.hosted_deb.ContainerRunner.__init__", fake_container_init), \
             patch("rs9.hosted_deb.ContainerRunner.which", return_value="/usr/bin/pacman"), \
             patch("rs9.hosted_deb.ContainerRunner.run", return_value=CommandReceipt(["tool"], 0, b"", b"", executed=True)), \
             patch("rs9.hosted_packaging.container_tool_facts", return_value={"pacman": "v1"}), \
             patch("rs9.hosted_packaging._resolve_offline_npm_archives", return_value=None), \
             patch("rs9.hosted_packaging.build_pacman_candidate", autospec=True, side_effect=mock_build), \
             patch("rs9.pages_candidate.write_custody_bundle"), \
             patch("rs9.hosted_deb.client_cycle", return_value=([], {})), \
             patch("rs9.hosted_deb.tamper_cycle", return_value=[]), \
             patch("rs9.hosted_smoke.prepare_smoke", return_value={}), \
             patch("rs9.hosted_packaging.SigningFixture", MockSigningFixture):
            execute(context)

        self.assertTrue(observed_mounts)
        for source, target, writable in observed_mounts:
            src_path = Path(source).resolve()
            # Every mount source must be within lane_scratch (lane-work)
            self.assertTrue(
                src_path == lane_scratch.resolve() or lane_scratch.resolve() in src_path.parents,
                f"Mount source {src_path} is outside lane_scratch {lane_scratch.resolve()}"
            )
            # Never mount outer orchestration paths
            self.assertNotEqual(src_path, outer.resolve())
            self.assertNotEqual(src_path, capture_dir.resolve())
            self.assertNotEqual(src_path, inputs_dir.resolve())
            self.assertNotEqual(src_path, auth_file.resolve())

    def test_hosted_packaging_uses_shared_npm_deps_helper(self):
        from rs9.hosted_packaging import _resolve_offline_npm_archives, resolve_offline_npm_archives
        from rs9.npm_deps import resolve_offline_npm_archives as npm_helper
        self.assertIs(_resolve_offline_npm_archives, npm_helper)
        self.assertIs(resolve_offline_npm_archives, npm_helper)

        scratch = self.root / "pkg_helper_scratch"
        scratch.mkdir()
        neb_capture = SimpleNamespace(source={"package.json": json.dumps({"dependencies": {"vue": "3.0"}})})
        self.assertIsNone(_resolve_offline_npm_archives(neb_capture, "theme-forge-nebular-fusion", scratch, None, None))

    def _base_probe_runner(self):
        class BaseRpmRunner:
            def __init__(self):
                self.calls = []

            def run(self, argv, **kwargs):
                self.calls.append(argv)
                cmd = argv[0]
                if cmd == "rpm":
                    if "--version" in argv:
                        return CommandReceipt(argv, 0, b"RPM version 6.0.0\n", b"", executed=True)
                    if "--querytags" in argv:
                        return CommandReceipt(argv, 0, b"PAYLOADSHA256\nPAYLOADSHA256ALGO\n", b"", executed=True)
                    if "--eval" in argv and "_keyring" in argv[-1]:
                        definitions = dict(a.split(" ", 1) for a in argv if a.startswith(("_keyring ", "_keyringpath ", "_dbpath ")))
                        raw = "|".join(definitions[k] for k in ("_keyring", "_keyringpath", "_dbpath")) + "\n"
                        return CommandReceipt(argv, 0, raw.encode(), b"", executed=True)
                    if "--eval" in argv:
                        return CommandReceipt(argv, 0, b"1.fc43\n", b"", executed=True)
                    qf = argv[argv.index("--queryformat") + 1] if "--queryformat" in argv else ""
                    if "%{PAYLOAD" in qf:
                        return CommandReceipt(argv, 0, b"abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789|8\n", b"", executed=True)
                    return CommandReceipt(argv, 0, b"sample|1.0.0|1.fc43|x86_64\n", b"", executed=True)
                if cmd == "rpmsign":
                    target = Path(argv[-1])
                    target.write_bytes(target.read_bytes() + b"-signed")
                    return CommandReceipt(argv, 0, b"", b"", executed=True)
                if cmd == "rpmkeys":
                    if "--checksig" in argv:
                        if any("wrong-rpmdb" in a or "empty-rpmdb" in a or ".tampered" in a for a in argv):
                            return CommandReceipt(argv, 1, b"sample.rpm: digests signatures NOT OK\n", b"", executed=True)
                        return CommandReceipt(argv, 0, b"sample.rpm: digests signatures OK\n", b"", executed=True)
                    return CommandReceipt(argv, 0, b"", b"", executed=True)
                return CommandReceipt(argv, 0, b"", b"", executed=True)
        return BaseRpmRunner()

    def test_probe_streams_are_bounded_path_redacted_and_ascii_only(self):
        from rs9.hosted_custody import diagnostic_bytes
        from rs9.hosted_packaging import _receipt_summary
        raw = ("warning: /tmp/space bearing path.rpm: Header RSA/SHA256 NOKEY\n" + "x" * 8000).encode()
        row = _receipt_summary(CommandReceipt(["rpm", str(self.root)], 0, b"identity\n", raw, executed=True))
        self.assertNotIn("argv", row)
        self.assertNotIn("/tmp/", json.dumps(row))
        self.assertLessEqual(len(row["stderr_text"]), 1024)
        self.assertEqual(row["stderr_sha256"], digest(raw))
        nonascii = _receipt_summary(CommandReceipt(["rpm"], 0, b"\xff", b"", executed=True))
        self.assertEqual(nonascii["stdout_text"], "non-printable-stream-withheld")
        target = self.root / "diagnostic.json"
        target.write_text(json.dumps(row))
        diagnostic_bytes(target)

    def test_unsigned_query_and_bad_macros_retain_native_probe_before_failure(self):
        for cause in ("unsigned-stderr", "macros"):
            with self.subTest(cause=cause):
                work = self.root / cause; work.mkdir()
                path = work / "sample.rpm"; path.write_bytes(b"fixture-package")
                fixture = SimpleNamespace(homedir=work, primary_fingerprint="A" * 40,
                                          public_key_armor="synthetic armor", gpg="gpg")
                runner = self._base_probe_runner(); actual = runner.run
                def failure(argv, **kw):
                    row = actual(argv, **kw)
                    if cause == "unsigned-stderr" and "-qp" in argv:
                        return CommandReceipt(argv, 0, row.stdout_bytes, b"error: unknown tag\n", executed=True)
                    if cause == "macros" and "--eval" in argv and "_keyring" in argv[-1]:
                        return CommandReceipt(argv, 0, b"openpgp|ambient|ambient\n", b"", executed=True)
                    return row
                runner.run = failure
                with self.assertRaises(ContractError):
                    sign_rpm(runner, path, fixture, wrong_fixture=wrong_fixture(fixture))
                record = json.loads(next((work / "diagnostics").glob("rpm-signed-query-probe-*.json")).read_bytes())
                self.assertEqual(record["status"], "fail")
                self.assertIn("unsigned_preflight_identity", record["transcripts"])

    def test_sign_rpm_probe_retained_on_checksig_failure(self):
        """Host probe is written to lane diagnostics even when signature validation fails."""
        rpm_file = self.root / "sample_probe_fail.rpm"
        rpm_file.write_bytes(b"initial-rpm-content")
        fixture_home = self.root / "fixture-home-probe-fail"
        fixture_home.mkdir()
        fixture = SimpleNamespace(
            primary_fingerprint="D" * 40,
            homedir=fixture_home,
            gpg="gpg",
            public_key_armor="-----BEGIN PGP PUBLIC KEY BLOCK-----\narmor\n-----END PGP PUBLIC KEY BLOCK-----\n",
            public_key_binary=b"\x99\x03keyring",
        )
        runner = self._base_probe_runner()
        # Override rpmkeys to fail checksig on the primary signed path
        orig_run = runner.run
        def failing_run(argv, **kw):
            if argv[0] == "rpmkeys" and "--checksig" in argv and not any("wrong-rpmdb" in a or "empty-rpmdb" in a or ".tampered" in a for a in argv):
                return CommandReceipt(argv, 1, b"sample.rpm: digests signatures NOT OK\n", b"", executed=True)
            return orig_run(argv, **kw)
        runner.run = failing_run

        with self.assertRaises(ContractError) as caught:
            sign_rpm(runner, rpm_file, fixture, wrong_fixture=wrong_fixture(fixture))
        self.assertEqual(caught.exception.code, "RPM_SIGNING")
        self.assertIn("signature validation failed", caught.exception.message)

        # Probe diagnostic must be retained on failure
        probe_file = next((fixture_home / "diagnostics").glob("rpm-signed-query-probe-*.json"))
        self.assertTrue(probe_file.is_file())
        probe_data = json.loads(probe_file.read_bytes())
        self.assertEqual(probe_data["status"], "fail")
        self.assertEqual(probe_data["error_code"], "RPM_SIGNING")

    def test_sign_rpm_requires_distinct_wrong_key_before_signing(self):
        path = self.root / "required-wrong-key.rpm"; path.write_bytes(b"unsigned")
        fixture = SimpleNamespace(homedir=self.root, primary_fingerprint="A" * 40,
                                  public_key_armor="synthetic armor", gpg="gpg")
        for wrong in (None, fixture):
            runner = self._base_probe_runner()
            with self.subTest(wrong=wrong is None), self.assertRaises(ContractError) as caught:
                sign_rpm(runner, path, fixture, wrong_fixture=wrong)
            self.assertEqual(caught.exception.code, "RPM_SIGNING")
            self.assertEqual(path.read_bytes(), b"unsigned")
            self.assertFalse(any(argv[0] == "rpmsign" for argv in runner.calls))
            record = json.loads(next((self.root / "diagnostics").glob("rpm-signed-query-probe-*.json")).read_bytes())
            self.assertEqual(record["status"], "fail")

    def test_sign_rpm_wrong_key_acceptance_fails_closed(self):
        """Signed RPM accepted by wrong key fails closed and records failure in probe."""
        rpm_file = self.root / "sample_wrong_accept.rpm"
        rpm_file.write_bytes(b"initial-rpm-content")
        fixture_home = self.root / "fixture-home-wrong-accept"
        fixture_home.mkdir()
        fixture = SimpleNamespace(
            primary_fingerprint="E" * 40,
            homedir=fixture_home,
            gpg="gpg",
            public_key_armor="-----BEGIN PGP PUBLIC KEY BLOCK-----\narmor\n-----END PGP PUBLIC KEY BLOCK-----\n",
            public_key_binary=b"\x99\x04keyring",
        )
        runner = self._base_probe_runner()
        orig_run = runner.run
        def buggy_wrong_key_run(argv, **kw):
            if argv[0] == "rpmkeys" and "--checksig" in argv and any("wrong-rpmdb" in a for a in argv):
                return CommandReceipt(argv, 0, b"sample.rpm: digests signatures OK\n", b"", executed=True)
            return orig_run(argv, **kw)
        runner.run = buggy_wrong_key_run

        with self.assertRaises(ContractError) as caught:
            sign_rpm(runner, rpm_file, fixture, wrong_fixture=SimpleNamespace(
                primary_fingerprint="F" * 40, public_key_armor=fixture.public_key_armor))
        self.assertEqual(caught.exception.code, "RPM_SIGNING")
        self.assertIn("wrong key", caught.exception.message)

        probe_file = next((fixture_home / "diagnostics").glob("rpm-signed-query-probe-*.json"))
        self.assertTrue(probe_file.is_file())
        probe_data = json.loads(probe_file.read_bytes())
        self.assertEqual(probe_data["status"], "fail")

    def test_sign_rpm_empty_trust_acceptance_fails_closed(self):
        """Signed RPM accepted by empty trust db fails closed and records failure in probe."""
        rpm_file = self.root / "sample_empty_accept.rpm"
        rpm_file.write_bytes(b"initial-rpm-content")
        fixture_home = self.root / "fixture-home-empty-accept"
        fixture_home.mkdir()
        fixture = SimpleNamespace(
            primary_fingerprint="E" * 40,
            homedir=fixture_home,
            gpg="gpg",
            public_key_armor="-----BEGIN PGP PUBLIC KEY BLOCK-----\narmor\n-----END PGP PUBLIC KEY BLOCK-----\n",
            public_key_binary=b"\x99\x04keyring",
        )
        runner = self._base_probe_runner()
        orig_run = runner.run
        def buggy_empty_run(argv, **kw):
            if argv[0] == "rpmkeys" and "--checksig" in argv and any("empty-rpmdb" in a for a in argv):
                return CommandReceipt(argv, 0, b"sample.rpm: digests signatures OK\n", b"", executed=True)
            return orig_run(argv, **kw)
        runner.run = buggy_empty_run

        with self.assertRaises(ContractError) as caught:
            sign_rpm(runner, rpm_file, fixture, wrong_fixture=wrong_fixture(fixture))
        self.assertEqual(caught.exception.code, "RPM_SIGNING")
        self.assertIn("empty trust", caught.exception.message)

        probe_file = next((fixture_home / "diagnostics").glob("rpm-signed-query-probe-*.json"))
        self.assertTrue(probe_file.is_file())
        probe_data = json.loads(probe_file.read_bytes())
        self.assertEqual(probe_data["status"], "fail")

    def test_sign_rpm_tamper_acceptance_fails_closed(self):
        """Tampered RPM accepted by checksig fails closed and records failure in probe."""
        rpm_file = self.root / "sample_tamper_accept.rpm"
        rpm_file.write_bytes(b"initial-rpm-content")
        fixture_home = self.root / "fixture-home-tamper-accept"
        fixture_home.mkdir()
        fixture = SimpleNamespace(
            primary_fingerprint="F" * 40,
            homedir=fixture_home,
            gpg="gpg",
            public_key_armor="-----BEGIN PGP PUBLIC KEY BLOCK-----\narmor\n-----END PGP PUBLIC KEY BLOCK-----\n",
            public_key_binary=b"\x99\x05keyring",
        )
        runner = self._base_probe_runner()
        orig_run = runner.run
        def buggy_tamper_run(argv, **kw):
            if argv[0] == "rpmkeys" and "--checksig" in argv and any(".tampered" in a for a in argv):
                return CommandReceipt(argv, 0, b"sample.rpm: digests signatures OK\n", b"", executed=True)
            return orig_run(argv, **kw)
        runner.run = buggy_tamper_run

        with self.assertRaises(ContractError) as caught:
            sign_rpm(runner, rpm_file, fixture, wrong_fixture=wrong_fixture(fixture))
        self.assertEqual(caught.exception.code, "RPM_SIGNING")
        self.assertIn("Tampered RPM accepted", caught.exception.message)

        probe_file = next((fixture_home / "diagnostics").glob("rpm-signed-query-probe-*.json"))
        self.assertTrue(probe_file.is_file())
        probe_data = json.loads(probe_file.read_bytes())
        self.assertEqual(probe_data["status"], "fail")

    def test_sign_rpm_strict_empty_stderr_query_rejection(self):
        """Any stderr (such as NOKEY warning) on signed query fails closed."""
        rpm_file = self.root / "sample_stderr_fail.rpm"
        rpm_file.write_bytes(b"initial-rpm-content")
        fixture_home = self.root / "fixture-home-stderr-fail"
        fixture_home.mkdir()
        fixture = SimpleNamespace(
            primary_fingerprint="G" * 40,
            homedir=fixture_home,
            gpg="gpg",
            public_key_armor="-----BEGIN PGP PUBLIC KEY BLOCK-----\narmor\n-----END PGP PUBLIC KEY BLOCK-----\n",
            public_key_binary=b"\x99\x06keyring",
        )
        runner = self._base_probe_runner()
        orig_run = runner.run
        def stderr_warning_run(argv, **kw):
            receipt = orig_run(argv, **kw)
            # If gating query on signed package with dbpath fixture-rpmdb
            if argv[0] == "rpm" and "-qp" in argv and any("fixture-rpmdb" in a for a in argv):
                return CommandReceipt(argv, 0, receipt.stdout_bytes,
                                      b"warning: Header V4 RSA/SHA256 Signature, key ID abcdef01: NOKEY\n",
                                      executed=True)
            return receipt
        runner.run = stderr_warning_run

        with self.assertRaises(ContractError) as caught:
            sign_rpm(runner, rpm_file, fixture, wrong_fixture=wrong_fixture(fixture))
        self.assertEqual(caught.exception.code, "RPM_QUERY_FAILED")

    def test_sign_rpm_isolates_dbpath_and_keyringpath_on_unsigned_and_signed(self):
        """sign_rpm isolates dbpath and %_keyring/%_keyringpath on both unsigned and signed queries."""
        rpm_file = self.root / "sample_isolation_verify.rpm"
        rpm_file.write_bytes(b"initial-rpm-content")
        fixture_home = self.root / "fixture-home-isolation"
        fixture_home.mkdir()
        fixture = SimpleNamespace(
            primary_fingerprint="H" * 40,
            homedir=fixture_home,
            gpg="gpg",
            public_key_armor="-----BEGIN PGP PUBLIC KEY BLOCK-----\narmor\n-----END PGP PUBLIC KEY BLOCK-----\n",
            public_key_binary=b"\x99\x07keyring",
        )
        runner = self._base_probe_runner()
        res = sign_rpm(runner, rpm_file, fixture, wrong_fixture=wrong_fixture(fixture))
        self.assertTrue(res["identity_preserved"])

        # Inspect all calls to 'rpm' and 'rpmkeys'
        rpm_queries = [call for call in runner.calls if call[0] == "rpm" and "-qp" in call]
        self.assertGreaterEqual(len(rpm_queries), 4)
        for call in rpm_queries:
            self.assertIn("--dbpath", call)
            self.assertIn("--define", call)
            self.assertTrue(any("_keyring" in a for a in call))
            self.assertTrue(any("_keyringpath" in a for a in call))

    def test_rpm_gate_split_and_quarantine_when_rpmlint_fails(self):
        """When RPM builds succeed but rpmlint fails: gate split passes package-build, fails rpmlint-clean, blocks custody, quarantines bytes."""
        outer = self.root / "orchestration-rpm-gate-split"
        outer.mkdir()
        lane_scratch = outer / "lane-work"
        lane_scratch.mkdir()

        product_ids = [
            "theme-forge-stellar-burst",
            "theme-forge-stellar-loom",
            "theme-forge-solar-sail",
            "theme-forge-nebular-fusion",
        ]
        captures = [
            (
                SimpleNamespace(root=outer / "capture" / pid),
                {"project": {"id": pid}},
                {},
            )
            for pid in product_ids
        ]

        context = {
            "family": "rpm",
            "system": "x86_64-linux",
            "repository": self.root,
            "scratch": lane_scratch,
            "pins": {"maintainer": "Lead <lead@example.com>"},
            "captures": captures,
            "client": None,
            "binding": {"source_commit": "0" * 40},
            "authentication_sha256": "1" * 64,
        }

        env = {
            "family": "rpm",
            "system": "x86_64-linux",
            "image_ref": "fedora@sha256:" + "0" * 64,
            "platform": "linux/amd64",
            "preprovisioned_packages": [],
            "tools": {},
        }

        def mock_build(capture, intent, arch, scratch_dir, **kwargs):
            pid = intent["project"]["id"]
            pkg_name = f"{pid}-1.0.0-1.fc43.{arch}.rpm"
            pkg_path = Path(scratch_dir) / pkg_name
            pkg_path.write_bytes(f"rpm-content-{pid}".encode())
            spec_path = Path(scratch_dir) / "rpmbuild" / "SPECS" / f"{pid}.spec"
            spec_path.parent.mkdir(parents=True, exist_ok=True)
            spec_path.write_bytes(f"Name: {pid}\n".encode())

            if pid == "theme-forge-nebular-fusion":
                ev_data = {
                    "schema": "rs9.rpmlint-evidence.v1alpha1",
                    "product": pid,
                    "clean": False,
                    "status": "fail",
                    "findings": [{"target": pkg_name, "level": "E", "check": "explicit-lib-dependency", "message": "nodejs"}],
                    "findings_summary": {"packages": 1, "specfiles": 1, "errors": 1, "warnings": 0, "filtered": 0},
                }
                lint_err = ContractError(
                    "RPMLINT_FAILED",
                    "Candidate RPM did not pass rpmlint: explicit-lib-dependency",
                    details={
                        "substage": "rpmlint",
                        "tool": "rpmlint",
                        "exit_code": 1,
                        "stdout_sha256": digest(b"stdout"),
                        "stderr_sha256": digest(b"stderr"),
                        "product": pid,
                        "diagnostic_token": "explicit-lib-dependency",
                        "reason_token": "lint-errors",
                        "observed_field_tokens": ["explicit-lib-dependency"],
                        "observed_field_count": 1,
                    },
                )
                lint_err.package_path = str(pkg_path)
                lint_err.spec_path = str(spec_path)
                lint_err.evidence = ev_data
                raise lint_err

            (Path(scratch_dir) / "rpm-manifest.json").write_bytes(b"{}")
            return {
                "rpm_path": pkg_path,
                "manifest": {
                    "rpm_identity": {"name": pid, "version": "1.0.0", "release": "1.fc43", "arch": arch},
                    "rpm_payload_digest": {"tag": "PAYLOADSHA256", "algo_tag": "PAYLOADSHA256ALGO", "payload_digest": "0" * 64},
                },
            }

        with patch("rs9.hosted_packaging.provision", return_value=env), \
             patch("rs9.hosted_deb.provision_image"), \
             patch("rs9.hosted_packaging.checked", return_value=CommandReceipt(["tool"], 0, b"", b"", executed=True)), \
             patch("rs9.hosted_packaging.container_tool_facts", return_value={"rpm": "v6"}), \
             patch("rs9.hosted_packaging._resolve_offline_npm_archives", return_value=None), \
             patch("rs9.hosted_packaging.build_rpm_candidate", autospec=True, side_effect=mock_build):
            from rs9.hosted_packaging import execute
            result = execute(context)
            details = result["details"]["product_failures"]["theme-forge-nebular-fusion"]
            self.assertEqual(details["code"], "RPMLINT_FAILED")
            self.assertEqual(details["diagnostic_token"], "explicit-lib-dependency")
            self.assertEqual(details["reason_token"], "lint-errors")
            self.assertIn("explicit-lib-dependency", details["observed_field_tokens"])
            gates_by_name = {g["name"]:g["status"] for g in result["gates"]}
            self.assertEqual(gates_by_name["rpm-package-build"],"pass")
            self.assertEqual(gates_by_name["rpm-rpmlint-clean"],"fail")
            self.assertEqual(gates_by_name["rpm-client-qualification"],"not-run")

            # 1. Gate split verified in build-errors.json
            diag_file = lane_scratch / "diagnostics" / "build-errors.json"
            self.assertTrue(diag_file.is_file())
            diag_data = json.loads(diag_file.read_bytes())
            gates_by_name = {g["name"]: g["status"] for g in diag_data.get("gates", [])}
            self.assertEqual(gates_by_name.get("rpm-package-build"), "pass")
            self.assertEqual(gates_by_name.get("rpm-rpmlint-clean"), "fail")

            # 2. Custody blocked verified: unsigned-custody was NEVER created
            self.assertFalse((lane_scratch / "unsigned-custody").exists())

            # 3. Quarantine verified: failed RPM bytes are in quarantine only
            quarantine_rpm = lane_scratch / "quarantine" / "theme-forge-nebular-fusion-1.0.0-1.fc43.x86_64.rpm"
            self.assertTrue(quarantine_rpm.is_file())
            self.assertEqual(quarantine_rpm.read_bytes(), b"rpm-content-theme-forge-nebular-fusion")

            # 4. Diagnostics records and spec retained
            retained_spec = lane_scratch / "diagnostics" / "theme-forge-nebular-fusion.spec.json"
            self.assertTrue(retained_spec.is_file())
            spec_record = json.loads(retained_spec.read_bytes())
            self.assertEqual(spec_record["spec_sha256"], digest(spec_record["spec"].encode()))
            retained_ev = lane_scratch / "diagnostics" / "rpmlint-theme-forge-nebular-fusion.json"
            self.assertTrue(retained_ev.is_file())
            ev_data = json.loads(retained_ev.read_bytes())
            self.assertEqual(ev_data["product"], "theme-forge-nebular-fusion")
            self.assertFalse(ev_data["clean"])
            from rs9.hosted_custody import retain
            record = {"lane": "rpm", "system": "x86_64-linux", "provenance": {},
                      "runner": {}, "execution_error": "required-gates-unsatisfied"}
            output = outer / "retained"
            retain(lane_scratch, output, result["artifacts"], record)
            self.assertNotIn("diagnostic_scan_failures", record)
            uploaded = output / "objects/diagnostics" / retained_spec.name
            self.assertEqual(uploaded.read_bytes(), retained_spec.read_bytes())

    def test_rpm_gate_split_build_fails_when_rpmbuild_fails(self):
        """When an actual build failure occurs (BUILD_FAILED): package-build gate fails, rpmlint-clean gate fails."""
        outer = self.root / "orchestration-rpm-build-fail"
        outer.mkdir()
        lane_scratch = outer / "lane-work"
        lane_scratch.mkdir()

        captures = [
            (
                SimpleNamespace(root=outer / "capture" / "theme-forge-stellar-burst"),
                {"project": {"id": "theme-forge-stellar-burst"}},
                {},
            )
        ]

        context = {
            "family": "rpm",
            "system": "x86_64-linux",
            "repository": self.root,
            "scratch": lane_scratch,
            "pins": {"maintainer": "Lead <lead@example.com>"},
            "captures": captures,
            "client": None,
            "binding": {"source_commit": "0" * 40},
            "authentication_sha256": "1" * 64,
        }

        env = {
            "family": "rpm",
            "system": "x86_64-linux",
            "image_ref": "fedora@sha256:" + "0" * 64,
            "platform": "linux/amd64",
            "preprovisioned_packages": [],
            "tools": {},
        }

        with patch("rs9.hosted_packaging.provision", return_value=env), \
             patch("rs9.hosted_deb.provision_image"), \
             patch("rs9.hosted_packaging.checked", return_value=CommandReceipt(["tool"], 0, b"", b"", executed=True)), \
             patch("rs9.hosted_packaging.container_tool_facts", return_value={"rpm": "v6"}), \
             patch("rs9.hosted_packaging._resolve_offline_npm_archives", return_value=None), \
             patch("rs9.hosted_packaging.build_rpm_candidate", autospec=True, side_effect=ContractError("BUILD_FAILED", "rpmbuild failed")):
            with self.assertRaises(ContractError) as caught:
                from rs9.hosted_packaging import execute
                execute(context)

            self.assertEqual(caught.exception.code, "NATIVE_BUILD")
            diag_file = lane_scratch / "diagnostics" / "build-errors.json"
            self.assertTrue(diag_file.is_file())
            diag_data = json.loads(diag_file.read_bytes())
            gates_by_name = {g["name"]: g["status"] for g in diag_data.get("gates", [])}
            self.assertEqual(gates_by_name.get("rpm-package-build"), "fail")
            self.assertEqual(gates_by_name.get("rpm-rpmlint-clean"), "fail")
            self.assertFalse((lane_scratch / "unsigned-custody").exists())


if __name__ == "__main__":
    unittest.main()
