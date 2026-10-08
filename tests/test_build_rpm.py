"""Strict RPM architecture, name, version evidence, query parsing, and derivation tests."""
from pathlib import Path
from unittest.mock import patch
from tests.rpm_fixtures import inventory_response, fixture_policy
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
    def test_complete_capability_readback_and_bounded_coverage_diagnostic(self):
        from rs9.build_rpm import _capability_records, _coverage_diagnostic, RPM_CAPABILITY_MAX_BYTES
        from rs9.hosted_custody import diagnostic_bytes
        from rs9.scratch import canonical
        rows = ['rpmlib(CompressedFileNames) <= 3.0.4-1'] * 2000 + [' nodejs >= 22 ']
        raw = ('\n'.join(rows) + '\n').encode('ascii')
        receipt = CommandReceipt(['rpm', '--requires'], 0, raw, b'')
        self.assertGreater(len(raw), 65536)
        self.assertEqual(len(receipt.stdout_text), 65536)
        expected = [row.strip() for row in rows]
        self.assertEqual(_capability_records(receipt, 'rpm-requires'), expected)
        self.assertEqual(receipt.stdout_sha256, digest(raw))
        report = _coverage_diagnostic(['libmissing.so.1'], ['libmissing.so.1'], expected, expected,
                                      'theme-forge-stellar-loom')
        self.assertEqual(report['actual_requires_count'], len(expected))
        self.assertEqual(report['actual_requires_sha256'], digest(canonical(expected)))
        self.assertEqual(len(report['actual_requires']), 32)
        path = self.root / 'coverage.json'; path.write_bytes(canonical(report))
        self.assertEqual(diagnostic_bytes(path), canonical(report))
        for bad in (raw + b'bad\x00record\n', raw[:-1], raw + b'\xff\n', raw + b'\n',
                    b'x' * (RPM_CAPABILITY_MAX_BYTES + 1)):
            causal = CommandReceipt(['rpm', '--provides'], 0, bad, b'')
            with self.subTest(size=len(bad)), self.assertRaises(ContractError) as caught:
                _capability_records(causal, 'rpm-provides')
            self.assertIs(caught.exception.receipt, causal)

    def test_builder_uses_full_capability_stream_and_preserves_late_failure(self):
        capture, intent, npm = create_cli_fixture(self.root / 'capability-stream')
        runner = self._setup_runner()
        original = runner.handlers['rpm']
        rows = ['rpmlib(CompressedFileNames) <= 3.0.4-1'] * 2000 + ['nodejs >= 22']
        raw = ('\n'.join(rows) + '\n').encode()
        mode = ['valid']
        seen = []
        def query(argv, **kwargs):
            if '--requires' in argv:
                r = CommandReceipt(argv, 0, raw if mode[0] == 'valid' else raw + b'bad\xff\n', b'')
                seen.append(r)
                return r
            return original(argv, **kwargs)
        runner.handlers['rpm'] = query
        result = build_rpm_candidate(capture, intent, 'noarch', self.scratch,
                                     offline_npm_archives=npm, runner=runner)
        self.assertEqual(result['derivation_record']['evidence']['rpm_query_evidence']['requires'], rows)
        mode[0] = 'invalid'; scratch = self.root / 'capability-invalid'; scratch.mkdir()
        with self.assertRaises(ContractError) as caught:
            build_rpm_candidate(capture, intent, 'noarch', scratch, offline_npm_archives=npm, runner=runner)
        self.assertEqual(caught.exception.code, 'DEPENDENCY_DERIVATION')
        self.assertIs(caught.exception.receipt, seen[-1])

    def test_late_inventory_corruption_retains_raw_lint_and_causal_query(self):
        capture, intent, npm = create_cli_fixture(self.root / 'large-inventory',
            extra_asset_entries=[(f'data/member-{i:04d}.txt', f'row-{i}'.encode()) for i in range(1200)])
        runner = self._setup_runner()
        original = runner.handlers['rpm']
        seen = []
        def query(argv, **kwargs):
            receipt = original(argv, **kwargs)
            if '--dump' in argv:
                self.assertGreater(len(receipt.stdout_bytes), 65536)
                receipt = CommandReceipt(argv, 0, receipt.stdout_bytes + b'corrupt trailing record\n', b'')
                seen.append(receipt)
            return receipt
        runner.handlers['rpm'] = query
        name = intent['project']['id']
        raw_lint = (name + '.noarch: E: env-script-interpreter /usr/lib/' + name +
                    '/bin/run.js /usr/bin/env node\n1 packages and 1 specfiles checked; 1 errors, 0 warnings, 0 filtered.\n').encode()
        runner.handlers['rpmlint'] = lambda argv, **kw: CommandReceipt(argv,
            0 if '--version' in argv else 64, b'2.8.0\n' if '--version' in argv else raw_lint, b'')
        with self.assertRaises(ContractError) as caught:
            build_rpm_candidate(capture, intent, 'noarch', self.scratch, offline_npm_archives=npm, runner=runner)
        error = caught.exception
        self.assertEqual(error.code, 'RPM_INVENTORY_FAILED')
        self.assertIs(error.receipt, seen[0])
        self.assertEqual(error.details['tool'], 'rpm')
        self.assertEqual(error.details['stdout_sha256'], seen[0].stdout_sha256)
        self.assertEqual(error.rpmlint_evidence['tool_receipt']['stdout_sha256'], digest(raw_lint))
        self.assertEqual(error.rpmlint_policy['raw_exit_code'], 64)
        self.assertFalse(error.rpmlint_policy['accepted'])
        self.assertIsNotNone(error.inventory_diagnostic)

    def test_inventory_runner_failure_keeps_original_code_and_stream_hashes(self):
        capture, intent, npm = create_cli_fixture(self.root / 'query-execution')
        for code in ('TOOL_TIMEOUT', 'TOOL_EXECUTION'):
            with self.subTest(code=code):
                runner = self._setup_runner()
                original = runner.handlers['rpm']
                cause = ContractError(code, 'Controlled inventory runner failure', details={
                    'tool':'rpm', 'substage':'tool-execution',
                    'stdout_sha256':digest(b'partial query'), 'stderr_sha256':digest(b'query stderr')})
                def query(argv, **kwargs):
                    if '--dump' in argv: raise cause
                    return original(argv, **kwargs)
                runner.handlers['rpm'] = query
                work = self.scratch / code; work.mkdir()
                with self.assertRaises(ContractError) as caught:
                    build_rpm_candidate(capture, intent, 'noarch', work, offline_npm_archives=npm, runner=runner)
                error = caught.exception
                self.assertEqual(error.code, 'RPM_INVENTORY_FAILED')
                self.assertEqual(error.details['underlying_code'], code)
                self.assertEqual(error.details['reason_token'], 'query-execution-failed')
                self.assertEqual(error.details['diagnostic_token'], 'dump')
                self.assertEqual(error.details['tool'], 'rpm')
                self.assertEqual(error.details['stdout_sha256'], digest(b'partial query'))
                self.assertEqual(error.details['stderr_sha256'], digest(b'query stderr'))
                self.assertIsNone(error.receipt)
                self.assertIsNotNone(error.rpmlint_receipt)
                self.assertFalse(error.rpmlint_policy['accepted'])
                self.assertEqual(error.inventory_diagnostic['queries'][0]['status'], 'fail')

    def test_invalid_attribute_path_is_attributed_to_attribute_query(self):
        capture, intent, npm = create_cli_fixture(self.root / 'attribute-path')
        runner = self._setup_runner()
        original = runner.handlers['rpm']
        seen = []
        def query(argv, **kwargs):
            receipt = original(argv, **kwargs)
            if '--queryformat' in argv and '%{FILENAMES}' in argv[argv.index('--queryformat') + 1]:
                receipt = CommandReceipt(argv, 0, receipt.stdout_bytes + b'/usr/../invalid|1|0|0\n', b'')
                seen.append(receipt)
            return receipt
        runner.handlers['rpm'] = query
        with self.assertRaises(ContractError) as caught:
            build_rpm_candidate(capture, intent, 'noarch', self.scratch, offline_npm_archives=npm, runner=runner)
        error = caught.exception
        self.assertEqual(error.details['reason_token'], 'malformed-attrs-path')
        self.assertEqual(error.details['diagnostic_token'], 'stdout')
        self.assertEqual(error.details['underlying_code'], 'RPM_INVENTORY_FAILED')
        self.assertEqual(error.details['stdout_sha256'], seen[0].stdout_sha256)
        self.assertIs(error.receipt, seen[0])
        self.assertEqual(error.inventory_diagnostic['queries'][-1]['query'], 'attrs')
        self.assertIsNotNone(error.rpmlint_evidence)

    def test_changelog_is_deterministic_authenticated_utc_and_matches_spec_evr(self):
        from rs9.build_rpm import _format_rpm_changelog, _get_rpm_maintainer
        identity = _get_rpm_maintainer()
        for timestamp, expected in (("2026-09-29T23:59:59Z", "Tue Sep 29 2026"),
                                    ("2026-09-30T00:00:00Z", "Wed Sep 30 2026")):
            entry = _format_rpm_changelog(timestamp, "0.6.1", 1, identity)
            self.assertIn(expected, entry)
            self.assertIn("nonproduction@knowledge-forge.invalid", entry)
            self.assertIn("0.6.1-1\n", entry)
            self.assertNotIn("%{", entry)
            self.assertEqual(entry, _format_rpm_changelog(timestamp, "0.6.1", 1, identity))
        for value in (None, "invalidZ", "2026-09-30", "2026-09-30Z", "2026-09-30T12:00:00-04:00"):
            with self.assertRaises(ContractError) as caught:
                _format_rpm_changelog(value, "0.6.1", 1, identity)
            self.assertEqual(caught.exception.code, "CHANGELOG_DATE")

    def test_generated_soname_requires_and_self_provides_cover_only_exact_names(self):
        from rs9.build_rpm import is_soname_covered, REDUNDANT_NEBULAR_REQUIRES
        self.assertEqual(REDUNDANT_NEBULAR_REQUIRES,
                         {"dbus-libs", "glib2", "libgcc", "libstdc++", "libsoup3"})
        self.assertTrue(is_soname_covered("liblocal.so.1", [], ["liblocal.so.1()(64bit)"]))
        self.assertTrue(is_soname_covered("libc.so.6", ["libc.so.6(GLIBC_2.34)(64bit)"], []))
        self.assertFalse(is_soname_covered("liblocal.so.1", ["liblocal.so.10()(64bit)", "named-library"], []))

    def test_nebular_removal_targets_match_retained_specs_and_generated_capabilities(self):
        import json
        from rs9.build_rpm import REDUNDANT_NEBULAR_REQUIRES, is_soname_covered
        from rs9.dependencies import LIBRARIES
        sonames = ("libdbus-1.so.3", "libglib-2.0.so.0", "libgobject-2.0.so.0", "libgio-2.0.so.0",
                   "libgcc_s.so.1", "libstdc++.so.6", "libsoup-3.0.so.0")
        self.assertEqual({LIBRARIES[s][1] for s in sonames}, REDUNDANT_NEBULAR_REQUIRES)
        for arch in ("x86_64-linux", "aarch64-linux"):
            path = Path(__file__).parent / "fixtures/run9/rpm" / arch / "theme-forge-nebular-fusion.spec.json"
            spec = json.loads(path.read_bytes())["spec"]
            requires = set(re.findall(r"^Requires: (.+)$", spec, re.M))
            self.assertTrue(REDUNDANT_NEBULAR_REQUIRES <= requires)
            for soname in sonames:
                self.assertFalse(is_soname_covered(soname, list(requires), []))
                self.assertTrue(is_soname_covered(soname, [soname + "()(64bit)"], []))

    def test_raw_exit64_and_actual_preservation_policy_pass_remain_distinct_in_builder(self):
        capture, intent, npm = create_cli_fixture(self.root / "preservation")
        runner = self._setup_runner()
        name = intent['project']['id']
        def lint(argv, **kwargs):
            if '--version' in argv:
                return CommandReceipt(argv,0,b'2.8.0\n',b'')
            return CommandReceipt(argv,64,(name+'.noarch: E: env-script-interpreter /usr/lib/'+name+
                '/bin/run.js /usr/bin/env node\n1 packages and 1 specfiles checked; 1 errors, 0 warnings, 0 filtered.\n').encode(),b'',executed=True)
        runner.handlers['rpmlint'] = lint
        def policy():
            result = fixture_policy(self.root)
            result['projects'][name]['exceptions'] = {'env-script-interpreter': {
                '/usr/lib/'+name+'/bin/run.js': {'launcher':'/usr/bin/tfsl'}}}
            return result
        with patch('rs9.rpm_lint_policy.load_policy',side_effect=policy):
            result = build_rpm_candidate(capture,intent,'noarch',self.scratch,offline_npm_archives=npm,runner=runner,
                                         builder_system='aarch64-linux')
        self.assertEqual(result['manifest']['rpmlint']['status'],'fail')
        self.assertEqual(result['manifest']['rpmlint']['tool_receipt']['exit_code'],64)
        self.assertTrue(result['manifest']['rpmlint_policy']['accepted'])
        self.assertEqual(result['manifest']['rpmlint_policy']['inputs']['system'],'aarch64-linux')
        self.assertFalse(result['manifest']['can_publish'])

    def test_inventory_or_absent_policy_failure_preserves_raw_and_stops_before_createrepo(self):
        for cause in ('inventory','policy'):
            capture,intent,npm=create_cli_fixture(self.root/cause)
            scratch=self.root/(cause+'-work');scratch.mkdir()
            runner=self._setup_runner()
            original=runner.handlers['rpm']
            if cause=='inventory':
                runner.handlers['rpm']=lambda argv,**kw: CommandReceipt(argv,1,b'',b'failed') if '--dump' in argv else original(argv,**kw)
                manager=patch('rs9.rpm_lint_policy.load_policy',side_effect=lambda:fixture_policy(self.root))
            else:
                manager=patch('rs9.rpm_lint_policy.load_policy',side_effect=ContractError('INVALID_POLICY','Missing policy'))
            with manager, self.assertRaises(ContractError) as caught:
                build_rpm_candidate(capture,intent,'noarch',scratch,offline_npm_archives=npm,runner=runner)
            self.assertEqual(caught.exception.rpmlint_evidence['status'],'pass')
            self.assertFalse(caught.exception.rpmlint_policy['accepted'])
            self.assertFalse(any(c['argv'][0].startswith('createrepo') for c in runner.calls))

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
        policy_patch = patch("rs9.rpm_lint_policy.load_policy", side_effect=lambda *a, **kw: fixture_policy(self.root))
        policy_patch.start()
        self.addCleanup(policy_patch.stop)

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
            return CommandReceipt(argv, 0, b"built\n", b"", executed=True)

        def rpm_query_handler(argv, cwd=None, env=None):
            response = inventory_response(argv,cwd)
            if response is not None: return response
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
            if "--version" in argv:
                return CommandReceipt(argv, 0, b"2.8.0\n", b"", executed=True)
            if rpmlint_exit:
                return CommandReceipt(
                    argv,
                    rpmlint_exit,
                    f"{name}.{arch}: E: explicit-lib-dependency nodejs\n1 packages and 1 specfiles checked; 1 errors, 0 warnings, 0 filtered.\n".encode(),
                    b"error\n", executed=True,
                )
            return CommandReceipt(
                argv,
                0,
                b"1 packages and 1 specfiles checked; 0 errors, 0 warnings, 0 filtered.\n",
                b"", executed=True,
            )

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
        self.assertEqual(caught.exception.details.get("diagnostic_token"), "explicit-lib-dependency")
        self.assertTrue(caught.exception.spec_sha256)
        self.assertTrue(caught.exception.package_sha256)
        self.assertEqual(caught.exception.details.get("sha256"), caught.exception.package_sha256)

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

    def test_burst_native_accepted_with_empty_messages_x86_64_and_aarch64(self):
        from rs9.scratch import canonical
        for arch in ("x86_64", "aarch64"):
            with self.subTest(arch=arch):
                capture, intent, offline_npm = self._make_burst_fixture(arch)
                scratch = self.scratch / f"burst_empty_msg_{arch}"
                scratch.mkdir()
                runner = self._setup_runner(arch=arch, name="theme-forge-stellar-burst", version="0.6.1")

                # Realistic raw lint with empty message findings
                lint_stdout = (
                    f"theme-forge-stellar-burst.spec: W: no-%check-section\n"
                    f"theme-forge-stellar-burst.{arch}: W: no-documentation\n"
                    f"1 packages and 1 specfiles checked; 0 errors, 2 warnings, 0 filtered.\n"
                ).encode("ascii")

                def custom_lint(argv, cwd=None, env=None):
                    if "--version" in argv:
                        return CommandReceipt(argv, 0, b"2.8.0\n", b"", executed=True)
                    return CommandReceipt(argv, 0, lint_stdout, b"", executed=True)

                runner.handlers["rpmlint"] = custom_lint

                result = build_rpm_candidate(
                    capture, intent, arch, scratch,
                    offline_npm_archives=offline_npm, runner=runner,
                )

                manifest = result["manifest"]
                derivation = result["derivation_record"]

                # 1. Manifest rpmlint retains raw lint with empty message strings intact
                raw_lint = manifest["rpmlint"]
                self.assertEqual(raw_lint["findings"][0]["check"], "no-%check-section")
                self.assertEqual(raw_lint["findings"][0]["message"], "")
                self.assertEqual(raw_lint["findings"][1]["check"], "no-documentation")
                self.assertEqual(raw_lint["findings"][1]["message"], "")
                self.assertTrue(raw_lint["clean"])
                self.assertEqual(raw_lint["status"], "pass")

                # 2. Derivation rpmlint contains durable projection where empty messages are None
                durable_lint = derivation["evidence"]["rpmlint"]
                self.assertEqual(durable_lint["schema"], "rs9.durable-lint-projection.v1")
                self.assertNotIn("findings", durable_lint)
                self.assertEqual(durable_lint["raw_evidence"]["sha256"], digest(canonical(raw_lint)))

                # 3. Derivation rpmlint_policy contains compact summary
                summary = derivation["evidence"]["rpmlint_policy"]
                self.assertEqual(summary["schema"], "rs9.rpm-lint-policy-summary.v1")
                self.assertEqual(summary["product"], "theme-forge-stellar-burst")
                self.assertGreater(summary["chunk_count"], 0)

                # 4. Derivation passes records.sanitized
                from rs9.records import sanitized
                sanitized(derivation)

    def test_loom_and_solar_sail_noarch_accepted_with_empty_messages(self):
        for product in ("theme-forge-stellar-loom", "theme-forge-solar-sail"):
            with self.subTest(product=product):
                fixture_dir = self.root / f"fixture_empty_msg_{product}"
                capture, intent, npm = create_cli_fixture(fixture_dir, product=product)
                scratch = self.scratch / f"scratch_empty_msg_{product}"
                scratch.mkdir()
                version = intent["version"]
                runner = self._setup_runner(arch="noarch", name=product, version=version)

                lint_stdout = (
                    f"{product}.spec: W: no-%check-section\n"
                    f"{product}.noarch: W: no-documentation\n"
                    f"1 packages and 1 specfiles checked; 0 errors, 2 warnings, 0 filtered.\n"
                ).encode("ascii")

                def custom_lint(argv, cwd=None, env=None):
                    if "--version" in argv:
                        return CommandReceipt(argv, 0, b"2.8.0\n", b"", executed=True)
                    return CommandReceipt(argv, 0, lint_stdout, b"", executed=True)

                runner.handlers["rpmlint"] = custom_lint

                result = build_rpm_candidate(
                    capture, intent, "noarch", scratch,
                    offline_npm_archives=npm, runner=runner,
                )

                manifest = result["manifest"]
                derivation = result["derivation_record"]

                # Raw retains empty message strings
                self.assertEqual(manifest["rpmlint"]["findings"][0]["message"], "")
                self.assertEqual(manifest["rpmlint"]["findings"][1]["message"], "")

                # Durable projection has None
                self.assertNotIn("findings", derivation["evidence"]["rpmlint"])

                from rs9.records import sanitized
                sanitized(derivation)

    def test_createrepo_failure_has_distinct_substage_and_receipt(self):
        fixture_dir = self.root / "fixture_createrepo"
        capture, intent, npm = create_cli_fixture(fixture_dir)
        scratch = self.scratch / "scratch_createrepo"
        scratch.mkdir()
        runner = self._setup_runner(createrepo_exit=1)

        with self.assertRaises(ContractError) as caught:
            build_rpm_candidate(
                capture, intent, "noarch", scratch,
                offline_npm_archives=npm, runner=runner,
            )
        err = caught.exception
        self.assertEqual(err.code, "BUILD_FAILED")
        self.assertEqual(err.details.get("substage"), "createrepo")
        self.assertEqual(err.details.get("tool"), "createrepo")
        self.assertIsNotNone(err.receipt)
        self.assertEqual(err.receipt.exit_code, 1)
        self.assertIs(err.causal_receipt, err.receipt)
        self.assertIsNotNone(getattr(err, "construction_witness", None))
        self.assertEqual(err.construction_witness["schema"], "rs9.rpm-construction-witness.v1")
        self.assertEqual(err.package_artifact, err.package_path)
        self.assertEqual(err.details.get("construction_witness")["schema"], "rs9.rpm-construction-witness.v1")

    def test_record_boundary_failure_wrapped_preserving_field_rule_and_no_receipt(self):
        fixture_dir = self.root / "fixture_boundary"
        capture, intent, npm = create_cli_fixture(fixture_dir)
        scratch = self.scratch / "scratch_boundary"
        scratch.mkdir()
        runner = self._setup_runner()

        # Mock create_derivation_record to simulate an adverse field error
        from rs9.records import ContractError as RecContractError
        def fail_derivation(**kwargs):
            e = RecContractError("INVALID_STRING", "A bounded nonempty string is required")
            e.field_path = "$.evidence.custom_field"
            e.rule = "INVALID_STRING"
            raise e

        with patch("rs9.build_rpm.create_derivation_record", side_effect=fail_derivation):
            with self.assertRaises(ContractError) as caught:
                build_rpm_candidate(
                    capture, intent, "noarch", scratch,
                    offline_npm_archives=npm, runner=runner,
                )
            err = caught.exception
            self.assertEqual(err.code, "RPM_DERIVATION_RECORD")
            self.assertIsNone(err.receipt)
            self.assertIsNone(err.causal_receipt)
            self.assertEqual(getattr(err, "field_path", None), "$.evidence.custom_field")
            self.assertEqual(getattr(err, "rule", None), "INVALID_STRING")
            self.assertEqual(getattr(err, "substage", None), "rpm-derivation-record")
            self.assertIsNotNone(getattr(err, "rpmlint_evidence", None))
            self.assertIsNotNone(getattr(err, "rpmlint_policy", None))
            self.assertTrue(Path(err.package_path).is_file())
            self.assertEqual(err.package_sha256, digest(Path(err.package_path).read_bytes()))
            self.assertIsNotNone(getattr(err, "construction_witness", None))
            self.assertEqual(err.construction_witness["schema"], "rs9.rpm-construction-witness.v1")
            self.assertEqual(err.package_artifact, err.package_path)

    def test_construction_witness_attached_on_success_and_failure(self):
        fixture_dir = self.root / "fixture_witness"
        capture, intent, npm = create_cli_fixture(fixture_dir)
        scratch = self.scratch / "scratch_witness_ok"
        scratch.mkdir()
        runner = self._setup_runner()

        result = build_rpm_candidate(
            capture, intent, "noarch", scratch,
            offline_npm_archives=npm, runner=runner,
        )
        witness = result["construction_witness"]
        self.assertEqual(witness["schema"], "rs9.rpm-construction-witness.v1")
        self.assertTrue(witness["rpmbuild_receipt"]["executed"])
        self.assertEqual(witness["rpmbuild_receipt"]["exit_code"], 0)
        self.assertEqual(witness["rpmbuild_receipt"]["tool"], "rpmbuild")
        self.assertEqual(witness["rpm_identity"]["name"], intent["project"]["id"])
        self.assertEqual(witness["package_sha256"], digest(result["rpm_path"].read_bytes()))
        self.assertEqual(witness["package_size"], len(result["rpm_path"].read_bytes()))
        self.assertEqual(result["manifest"]["construction_witness"], witness)

        # On failure (rpmlint exit = 1)
        fail_scratch = self.scratch / "scratch_witness_fail"
        fail_scratch.mkdir()
        fail_runner = self._setup_runner(rpmlint_exit=1)
        with self.assertRaises(ContractError) as caught:
            build_rpm_candidate(
                capture, intent, "noarch", fail_scratch,
                offline_npm_archives=npm, runner=fail_runner,
            )
        err = caught.exception
        self.assertIsNotNone(err.construction_witness)
        self.assertEqual(err.construction_witness["schema"], "rs9.rpm-construction-witness.v1")
        self.assertEqual(err.package_artifact, err.package_path)
        self.assertEqual(err.package_sha256, digest(Path(err.package_path).read_bytes()))
        self.assertIn("construction_witness", err.details)


if __name__ == "__main__":
    unittest.main()
