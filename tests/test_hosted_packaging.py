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


if __name__ == "__main__":
    unittest.main()
